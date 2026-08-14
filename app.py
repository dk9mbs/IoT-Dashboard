#!/usr/bin/env python3
"""
Kleines Flask-Dashboard zur Anzeige der IoT-Geräte, die
IotDeviceClient.fetch_devices() zurückliefert.
"""

import json
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
import requests

load_dotenv()

from iot_device_query import IotDeviceClient
from iot_sensor_query import IotSensorClient
from shelly_update import trigger_shelly_update
from telegram_notify import send_telegram_message

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

HOST = "0.0.0.0"
PORT = 5000

# Spalten, die im Dashboard angezeigt werden sollen.
# Jeder Eintrag: (Feldname in der API-Antwort, Spaltentitel)
COLUMNS = [
    ("id", "ID"),
    ("name", "Name"),
    ("address", "Adresse"),
    ("network_ssid", "WLAN (SSID)"),
    ("network_rssi", "RSSI"),
    ("last_scan_on", "Letzter Scan"),
]

SENSOR_COLUMNS = [
    ("id", "ID"),
    ("alias", "Alias"),
    ("description", "Beschreibung"),
    ("last_value", "Letzter Wert"),
    ("unit", "Einheit"),
    ("last_value_on", "Letzte Meldung"),
]

VERSION_COLUMNS = [
    ("id", "ID"),
    ("name", "Name"),
    ("version", "Version"),
    ("version_available", "Verfügbare Version"),
]

SENSOR_MINMAX_COLUMNS = [
    ("id", "ID"),
    ("alias", "Alias"),
    ("description", "Beschreibung"),
    ("last_value", "Letzter Wert"),
    ("min_value", "Min."),
    ("max_value", "Max."),
    ("unit", "Einheit"),
    ("last_value_on", "Letzte Meldung"),
]

SENSOR_MINMAX_DISPLAY_COLUMNS = SENSOR_MINMAX_COLUMNS + [("_direction", "Abweichung")]

# Merkt sich pro Geräte-ID, wann zuletzt ein Update ausgelöst wurde.
# Wird in einer JSON-Datei neben app.py gespeichert, damit der Zustand
# auch einen Server-Neustart übersteht (nicht nur einen Seiten-Reload).
PENDING_UPDATES_FILE = BASE_DIR / "pending_updates.json"
UPDATE_PENDING_TTL_SECONDS = 5 * 60  # Nach 5 Min. gilt ein Update als "hängengeblieben"


def _load_pending_updates() -> dict:
    try:
        with open(PENDING_UPDATES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_pending_updates(data: dict) -> None:
    with open(PENDING_UPDATES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def mark_update_pending(device_id: str) -> None:
    data = _load_pending_updates()
    data[device_id] = time.time()
    _save_pending_updates(data)


def get_pending_seconds(device_id: str) -> Optional[int]:
    """
    Gibt zurück, seit wie vielen Sekunden ein Update für dieses Gerät
    läuft, oder None, wenn kein (noch gültiges) Update anliegt.
    Räumt dabei automatisch abgelaufene Einträge aus der Datei auf.
    """
    data = _load_pending_updates()
    started_at = data.get(device_id)
    if started_at is None:
        return None

    elapsed = time.time() - started_at
    if elapsed > UPDATE_PENDING_TTL_SECONDS:
        data.pop(device_id, None)
        _save_pending_updates(data)
        return None

    return int(elapsed)


# Merkt sich als {id: label}, fuer welche Geraete/Sensoren bereits eine
# Meldung per Telegram verschickt wurde, damit jedes Ereignis nur einmalig
# meldet. Sobald ein Eintrag wieder verschwindet (online / neuer Sensorwert
# / nicht mehr 'neu'), wird eine Erholungs-Meldung verschickt und der
# Eintrag entfernt - erst dann kann ein erneutes Ereignis wieder eine neue
# Meldung ausloesen. Das gespeicherte label (Name/Alias) wird gebraucht,
# damit die Erholungs-Meldung lesbar bleibt, auch wenn das Geraet/der
# Sensor zu diesem Zeitpunkt nicht mehr in der API-Antwort auftaucht.
DEVICE_STATUS_STATE_FILE = BASE_DIR / "device_status_state.json"
OFFLINE_POLL_INTERVAL_SECONDS = 120


def _load_notified_offline() -> dict:
    try:
        with open(DEVICE_STATUS_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    for key in ("devices", "new_devices", "sensors", "minmax_sensors"):
        value = data.get(key)
        if isinstance(value, list):
            # Altes Format (nur IDs, kein Label) migrieren.
            data[key] = {item_id: item_id for item_id in value}
        elif not isinstance(value, dict):
            data[key] = {}
    return data


def _notify_state_changes(notified: dict, current: dict, label_for, alert_text, recovery_text) -> dict:
    """
    Vergleicht den zuletzt gemeldeten Zustand (notified: {id: label}) mit dem
    aktuell auffaelligen Zustand (current: {id: row}) und verschickt fuer
    jede Aenderung genau eine Telegram-Nachricht: einmalig bei neuem
    Auftreten (alert_text) und einmalig bei Wegfall/Erholung (recovery_text).
    Gibt den aktualisierten notified-Zustand zurueck.
    """
    for item_id in set(notified) - set(current):
        label = notified[item_id]
        ok, message = send_telegram_message(recovery_text(item_id, label))
        if ok:
            del notified[item_id]
        else:
            print(f"[offline-check] Telegram-Versand fehlgeschlagen: {message}")

    for item_id, row in current.items():
        if item_id not in notified:
            ok, message = send_telegram_message(alert_text(item_id, row))
            if ok:
                notified[item_id] = label_for(row)
            else:
                print(f"[offline-check] Telegram-Versand fehlgeschlagen: {message}")

    return notified


def _save_notified_offline(data: dict) -> None:
    with open(DEVICE_STATUS_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


# Farbliche Markierung je nach status_id.
# Unbekannte/neue Status-Werte fallen automatisch auf "status-unknown" zurück.
STATUS_STYLES = {
    "new": ("Neu", "status-new"),
    "active": ("Aktiv", "status-active"),
    "online": ("Online", "status-active"),
    "inactive": ("Inaktiv", "status-disabled"),
    "disabled": ("Deaktiviert", "status-disabled"),
    "error": ("Fehler", "status-error"),
    "offline": ("Offline", "status-offline"),
}


def resolve_status(raw_status_id: str):
    """Liefert (Anzeigetext, CSS-Klasse) für einen status_id-Wert."""
    key = (raw_status_id or "").strip().lower()
    if key in STATUS_STYLES:
        return STATUS_STYLES[key]
    # Unbekannter Status: Rohwert trotzdem anzeigen, aber neutral einfärben.
    return (raw_status_id or "unbekannt", "status-unknown")


def extract_fields(device: dict, columns: list) -> dict:
    """Holt aus jedem Feld den formatted_value für die angegebenen Spalten."""
    row = {}
    for field, _ in columns:
        field_data = device.get(field) or {}
        if isinstance(field_data, dict):
            row[field] = field_data.get("formatted_value", "")
        else:
            # Falls die API das Feld doch als einfachen Wert liefert
            row[field] = field_data
    return row


def extract_row(device: dict) -> dict:
    """Holt die iot_device-Spalten und ergänzt die Status-Markierung."""
    row = extract_fields(device, COLUMNS)

    # status_id wird nicht als eigene Spalte angezeigt, sondern nur
    # zur farblichen Markierung der Zeile verwendet.
    status_data = device.get("status_id") or {}
    raw_status = (
        status_data.get("formatted_value", "")
        if isinstance(status_data, dict)
        else status_data
    )
    status_label, status_class = resolve_status(raw_status)
    row["_status_label"] = status_label
    row["_status_class"] = status_class
    row["_status_raw"] = (raw_status or "").strip().lower()

    return row


def extract_sensor_row(sensor: dict) -> dict:
    """Holt die iot_sensor-Spalten für die Anzeige."""
    return extract_fields(sensor, SENSOR_COLUMNS)


def extract_version_row(device: dict) -> Optional[dict]:
    """
    Holt die Versions-Spalten eines Geräts. Gibt None zurück, wenn
    version und version_available identisch sind oder version_available
    leer ist (dann liegt kein Update vor / wurde nicht geprüft).
    """
    row = extract_fields(device, VERSION_COLUMNS)
    version = (row.get("version") or "").strip()
    version_available = (row.get("version_available") or "").strip()

    if not version_available or version == version_available:
        return None

    # Adresse wird nicht als Spalte angezeigt, aber für den Update-Button gebraucht.
    address_data = device.get("address") or {}
    row["_address"] = (
        address_data.get("formatted_value", "")
        if isinstance(address_data, dict)
        else address_data
    )

    return row


def extract_out_of_range_sensor(sensor: dict) -> Optional[dict]:
    """
    Liefert die Sensor-Zeile zurück, wenn last_value außerhalb von
    [min_value, max_value] liegt, sonst None (auch bei min_value ==
    max_value, z.B. 0/0 - das gilt als exakter Grenzwert, jede Abweichung
    zählt). Sensoren ohne (numerischen) last_value werden ignoriert.
    """
    row = extract_fields(sensor, SENSOR_MINMAX_COLUMNS)

    try:
        last_value = float(row.get("last_value"))
        min_value = float(row.get("min_value"))
        max_value = float(row.get("max_value"))
    except (TypeError, ValueError):
        return None

    if last_value < min_value:
        row["_direction"] = f"< Min. ({row['min_value']})"
    elif last_value > max_value:
        row["_direction"] = f"> Max. ({row['max_value']})"
    else:
        return None

    return row


def check_offline_devices_and_sensors() -> None:
    """
    Prueft Geraete und Sensoren auf "offline"/"neu" und verschickt fuer jedes
    NEU aufgetretene Ereignis genau eine Telegram-Nachricht.

    fetch_devices() liefert Geraete, bei denen last_scan_on aelter als 10 Min.
    ist UND notify=-1 gesetzt ist, ODER der Status 'new' ist (dieselbe
    server-seitig gefilterte Logik wie fuer die Tabelle "auffaellige
    Geraete"). Die 'new'-Faelle werden separat als "neues Geraet" gemeldet,
    der Rest als "offline" - status_id wird von diesem Backend naemlich
    nicht zuverlaessig auf 'offline' gesetzt, wenn ein Geraet nicht mehr
    scannt, es bleibt z.B. auf 'active' stehen, waehrend last_scan_on
    veraltet.

    Ein Sensor gilt als offline/"still", wenn er in fetch_sensors() auftaucht
    (notify=-1 & last_value_on > 15 Min, server-seitig gefiltert).

    Ein Sensor gilt als Min/Max-Grenzwertverletzung, wenn last_value bei
    einem notify=-1-Sensor außerhalb von [min_value, max_value] liegt
    (siehe extract_out_of_range_sensor).
    """
    state = _load_notified_offline()
    notified_devices = state["devices"]
    notified_new_devices = state["new_devices"]
    notified_sensors = state["sensors"]
    notified_minmax_sensors = state["minmax_sensors"]

    try:
        device_client = IotDeviceClient()
        conspicuous_devices = device_client.fetch_devices()
        conspicuous_rows = list(map(extract_row, conspicuous_devices))
        new_now = {
            row["id"]: row for row in conspicuous_rows if row.get("_status_raw") == "new"
        }
        offline_now = {
            row["id"]: row for row in conspicuous_rows if row.get("_status_raw") != "new"
        }
    except (RuntimeError, requests.exceptions.RequestException) as exc:
        print(f"[offline-check] Geraete-Abfrage fehlgeschlagen: {exc}")
        new_now = None
        offline_now = None

    device_label = lambda row: row.get("name") or row["id"]

    if new_now is not None:
        notified_new_devices = _notify_state_changes(
            notified_new_devices,
            new_now,
            label_for=device_label,
            alert_text=lambda device_id, row: (
                f"\U0001F195 Neues Geraet erkannt: {row.get('name') or device_id} "
                f"(ID {device_id}, {row.get('address') or 'keine Adresse'})"
            ),
            recovery_text=lambda device_id, label: (
                f"✅ Geraet nicht mehr neu: {label} (ID {device_id})"
            ),
        )

    if offline_now is not None:
        notified_devices = _notify_state_changes(
            notified_devices,
            offline_now,
            label_for=device_label,
            alert_text=lambda device_id, row: (
                f"\U0001F534 Geraet offline: {row.get('name') or device_id} "
                f"(ID {device_id}, {row.get('address') or 'keine Adresse'})"
            ),
            recovery_text=lambda device_id, label: (
                f"✅ Geraet wieder online: {label} (ID {device_id})"
            ),
        )

    try:
        sensor_client = IotSensorClient()
        stale_sensors = sensor_client.fetch_sensors()
        stale_rows = {row["id"]: row for row in map(extract_sensor_row, stale_sensors)}
    except (RuntimeError, requests.exceptions.RequestException) as exc:
        print(f"[offline-check] Sensor-Abfrage fehlgeschlagen: {exc}")
        stale_rows = None

    if stale_rows is not None:
        notified_sensors = _notify_state_changes(
            notified_sensors,
            stale_rows,
            label_for=lambda row: row.get("alias") or row["id"],
            alert_text=lambda sensor_id, row: (
                f"\U0001F507 Sensor still: {row.get('alias') or sensor_id}"
                f"{' - ' + row['description'] if row.get('description') else ''} "
                f"(seit {row.get('last_value_on') or 'unbekannt'})"
            ),
            recovery_text=lambda sensor_id, label: (
                f"✅ Sensor meldet wieder Werte: {label} (ID {sensor_id})"
            ),
        )

    try:
        minmax_sensor_client = IotSensorClient()
        notify_sensors = minmax_sensor_client.fetch_notify_sensors()
        minmax_rows = {
            row["id"]: row
            for sensor in notify_sensors
            if (row := extract_out_of_range_sensor(sensor)) is not None
        }
    except (RuntimeError, requests.exceptions.RequestException) as exc:
        print(f"[offline-check] Sensor-Abfrage (Min/Max) fehlgeschlagen: {exc}")
        minmax_rows = None

    if minmax_rows is not None:
        notified_minmax_sensors = _notify_state_changes(
            notified_minmax_sensors,
            minmax_rows,
            label_for=lambda row: row.get("alias") or row["id"],
            alert_text=lambda sensor_id, row: (
                f"\U000026A0\U0000FE0F Sensor außerhalb Min/Max: {row.get('alias') or sensor_id}"
                f"{' - ' + row['description'] if row.get('description') else ''} "
                f"(aktuell {row.get('last_value') or 'unbekannt'} {row.get('unit') or ''}, "
                f"{row.get('_direction') or ''})"
            ),
            recovery_text=lambda sensor_id, label: (
                f"✅ Sensor wieder im Toleranzbereich: {label} (ID {sensor_id})"
            ),
        )

    _save_notified_offline(
        {
            "devices": notified_devices,
            "new_devices": notified_new_devices,
            "sensors": notified_sensors,
            "minmax_sensors": notified_minmax_sensors,
        }
    )


def offline_poll_loop() -> None:
    """
    Prueft in Dauerschleife auf Offline-Ereignisse, unabhaengig davon, ob
    gerade jemand das Dashboard im Browser geoeffnet hat.
    """
    while True:
        try:
            check_offline_devices_and_sensors()
        except Exception as exc:  # Hintergrundthread darf nicht abbrechen
            print(f"[offline-check] Unerwarteter Fehler: {exc}")
        time.sleep(OFFLINE_POLL_INTERVAL_SECONDS)


@app.route("/")
def dashboard():
    error = None
    rows = []
    sensor_error = None
    sensor_rows = []
    version_error = None
    version_rows = []

    try:
        client = IotDeviceClient()
        devices = client.fetch_devices()
        rows = [extract_row(device) for device in devices]
    except RuntimeError as exc:
        # Fehlende Zugangsdaten (RESTAPI_USERNAME / RESTAPI_PASSWORD)
        error = str(exc)
    except requests.exceptions.RequestException as exc:
        error = f"Fehler bei der Abfrage des REST-Service: {exc}"

    try:
        sensor_client = IotSensorClient()
        sensors = sensor_client.fetch_sensors()
        sensor_rows = [extract_sensor_row(sensor) for sensor in sensors]
    except RuntimeError as exc:
        sensor_error = str(exc)
    except requests.exceptions.RequestException as exc:
        sensor_error = f"Fehler bei der Abfrage des REST-Service: {exc}"

    minmax_error = None
    minmax_rows = []

    try:
        minmax_sensor_client = IotSensorClient()
        notify_sensors = minmax_sensor_client.fetch_notify_sensors()
        minmax_rows = [
            row
            for sensor in notify_sensors
            if (row := extract_out_of_range_sensor(sensor)) is not None
        ]
    except RuntimeError as exc:
        minmax_error = str(exc)
    except requests.exceptions.RequestException as exc:
        minmax_error = f"Fehler bei der Abfrage des REST-Service: {exc}"

    try:
        version_client = IotDeviceClient()
        all_shelly_devices = version_client.fetch_all_shelly_devices()
        version_rows = [
            row
            for device in all_shelly_devices
            if (row := extract_version_row(device)) is not None
        ]
        for row in version_rows:
            row["_pending_seconds"] = get_pending_seconds(row["id"])
    except RuntimeError as exc:
        version_error = str(exc)
    except requests.exceptions.RequestException as exc:
        version_error = f"Fehler bei der Abfrage des REST-Service: {exc}"

    new_count = sum(1 for row in rows if row.get("_status_raw") == "new")
    active_count = sum(1 for row in rows if row.get("_status_raw") == "active")
    sensor_stale_count = len(sensor_rows)
    minmax_count = len(minmax_rows)
    version_outdated_count = len(version_rows)

    return render_template(
        "dashboard.html",
        columns=COLUMNS,
        rows=rows,
        error=error,
        new_count=new_count,
        active_count=active_count,
        sensor_columns=SENSOR_COLUMNS,
        sensor_rows=sensor_rows,
        sensor_error=sensor_error,
        sensor_stale_count=sensor_stale_count,
        sensor_minmax_columns=SENSOR_MINMAX_DISPLAY_COLUMNS,
        sensor_minmax_rows=minmax_rows,
        minmax_error=minmax_error,
        minmax_count=minmax_count,
        version_columns=VERSION_COLUMNS,
        version_rows=version_rows,
        version_error=version_error,
        version_outdated_count=version_outdated_count,
    )


@app.route("/device/<device_id>/update-firmware", methods=["POST"])
def update_firmware(device_id):
    """
    Löst ein Firmware-Update für ein einzelnes Gerät aus.
    Die Adresse kommt aus dem Formularfeld 'address' (vom Dashboard
    mitgeliefert), NICHT aus einer erneuten REST-Abfrage - das hält
    den Endpunkt schnell und unabhängig vom REST-Service.
    """
    address = request.form.get("address", "").strip()

    if not address:
        return jsonify({"success": False, "message": "Keine Adresse übermittelt."}), 400

    success, message = trigger_shelly_update(address)
    if success:
        mark_update_pending(device_id)
    return jsonify({"success": success, "message": message})


def open_chrome():
    """Öffnet das Dashboard automatisch in Chrome, sobald der Server läuft."""
    url = f"http://{HOST}:{PORT}/"

    # Übliche Chrome-Kandidaten je nach Betriebssystem.
    chrome_candidates = [
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "/usr/bin/google-chrome",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "C:/Program Files/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    ]

    for candidate in chrome_candidates:
        try:
            browser = webbrowser.get(f'"{candidate}" %s')
            browser.open(url)
            return
        except webbrowser.Error:
            continue

    # Fallback: Standardbrowser, falls Chrome nicht gefunden wurde.
    webbrowser.open(url)


if __name__ == "__main__":
    # Chrome erst öffnen, nachdem der Server kurz Zeit hatte hochzufahren.
    #threading.Timer(1.0, open_chrome).start()
    threading.Thread(target=offline_poll_loop, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=True, use_reloader=False)
