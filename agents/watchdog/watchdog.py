#!/usr/bin/env python3
"""
watchdog.py - Erkennt auffaellige Geraete und Sensoren und stellt dafuer
Benachrichtigungen in die Warteschlange iot_notification. Verschickt werden
sie vom Agenten notify (frueher hat notify beides gemacht).

Ein Aufruf = eine Pruefung; den Takt gibt der Agenten-Runner vor.
Gemeldet wird jedes Ereignis genau einmal beim Auftreten und einmal bei
der Erholung:
  - Geraet neu (status 'new')
  - Geraet offline (notify=-1 & last_scan_on > 10 Min., serverseitig gefiltert)
  - Sensor still (notify=-1 & letzte Meldung aelter als watchdog_warning_sec des Sensors)
  - Sensorwert ausserhalb [min_value, max_value]

Ausgabetyp 1 (No Action): die Meldungen gehen als JSON {"notify": [...]} auf
stdout, der Runner stellt sie in iot_notification ein; Log-Meldungen auf stderr.
Der Zustand gilt mit der Ausgabe als gemeldet - der Agent erfaehrt nicht, ob
der Runner die Meldungen einstellen konnte.

Aufruf:
    python3 watchdog.py [--dry-run]

Exit-Code 1, wenn eine REST-Abfrage fehlschlug.
"""

import argparse
import json
import sys
from pathlib import Path

import requests
from dk9mbs_iot.agent import dry_run_from_env, log, rest_from_env, write_output
from dk9mbs_iot.query.device import IotDeviceClient
from dk9mbs_iot.query.sensor import IotSensorClient
from dk9mbs_iot.rows import extract_out_of_range_sensor, extract_row, extract_stale_sensor

AGENT_DIR = Path(__file__).resolve().parent

# Merkt sich als {id: label}, fuer welche Geraete/Sensoren bereits eine
# Meldung erzeugt wurde, damit jedes Ereignis nur einmalig meldet.
# Sobald ein Eintrag wieder verschwindet (online / neuer Sensorwert /
# nicht mehr 'neu'), wird eine Erholungs-Meldung erzeugt und der Eintrag
# entfernt - erst dann kann ein erneutes Ereignis wieder eine neue Meldung
# ausloesen. Das gespeicherte label (Name/Alias) wird gebraucht, damit die
# Erholungs-Meldung lesbar bleibt, auch wenn das Geraet/der Sensor zu
# diesem Zeitpunkt nicht mehr in der API-Antwort auftaucht.
STATE_FILE = AGENT_DIR / "device_status_state.json"
# Zustand aus der Zeit, als notify selbst geprueft hat (einmalige Uebernahme)
LEGACY_STATE_FILE = AGENT_DIR.parent / "notify" / "device_status_state.json"

STATE_KEYS = ("devices", "new_devices", "sensors", "minmax_sensors")


def state_changes(notified: dict, current: dict, label_for, alert_text, recovery_text,
                  messages: list) -> dict:
    """
    Vergleicht den zuletzt gemeldeten Zustand (notified: {id: label}) mit dem
    aktuell auffaelligen Zustand (current: {id: row}) und haengt fuer jede
    Aenderung genau eine Meldung an messages an: einmalig bei neuem Auftreten
    (alert_text) und einmalig bei Wegfall/Erholung (recovery_text).
    Gibt den aktualisierten notified-Zustand zurueck.
    """
    for item_id in sorted(set(notified) - set(current)):
        messages.append(recovery_text(item_id, notified.pop(item_id)))

    for item_id, row in current.items():
        if item_id not in notified:
            messages.append(alert_text(item_id, row))
            notified[item_id] = label_for(row)

    return notified


def load_state() -> dict:
    path = STATE_FILE if STATE_FILE.exists() else LEGACY_STATE_FILE
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    for key in STATE_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            # Altes Format (nur IDs, kein Label) migrieren.
            data[key] = {item_id: item_id for item_id in value}
        elif not isinstance(value, dict):
            data[key] = {}
    return data


def save_state(data: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def check(state: dict, messages: list) -> bool:
    """
    Prueft Geraete und Sensoren, aktualisiert state und sammelt die Meldungen.
    Rueckgabe: False, wenn eine Abfrage fehlschlug.

    fetch_devices() liefert Shellys, bei denen last_scan_on aelter als 10 Min.
    ist UND notify=-1 gesetzt ist, ODER Geraete jedes Herstellers mit Status
    'new' (dieselbe server-seitig gefilterte Logik wie fuer die Tabelle
    "auffaellige Geraete" im Dashboard). Die 'new'-Faelle werden separat als
    "neues Geraet" gemeldet, der Rest als "offline" - status_id wird vom
    Backend naemlich nicht zuverlaessig auf 'offline' gesetzt, wenn ein Geraet
    nicht mehr scannt, es bleibt z.B. auf 'active' stehen, waehrend
    last_scan_on veraltet.

    Schlaegt eine Abfrage fehl, bleibt der Zustand der betroffenen Kategorie
    unveraendert (keine falschen Erholungs-Meldungen).
    """
    ok = True
    try:
        rest = rest_from_env()
    except (RuntimeError, OSError, ValueError) as exc:
        log(f"REST-Zugang nicht konfiguriert: {exc}")
        return False
    clients = {"apikey": rest["apikey"], "base_url": rest["base_url"]}

    try:
        conspicuous_rows = list(map(extract_row, IotDeviceClient(**clients).fetch_devices()))
        new_now = {row["id"]: row for row in conspicuous_rows if row.get("_status_raw") == "new"}
        offline_now = {row["id"]: row for row in conspicuous_rows if row.get("_status_raw") != "new"}
    except (RuntimeError, requests.exceptions.RequestException) as exc:
        log(f"Geraete-Abfrage fehlgeschlagen: {exc}")
        ok = False
        new_now = offline_now = None

    device_label = lambda row: row.get("name") or row["id"]  # noqa: E731

    if new_now is not None:
        state["new_devices"] = state_changes(
            state["new_devices"],
            new_now,
            label_for=device_label,
            alert_text=lambda device_id, row: (
                f"\U0001F195 Neues Geraet erkannt: {row.get('name') or device_id} "
                f"(ID {device_id}, {row.get('address') or 'keine Adresse'})"
            ),
            recovery_text=lambda device_id, label: (
                f"✅ Geraet nicht mehr neu: {label} (ID {device_id})"
            ),
            messages=messages,
        )

    if offline_now is not None:
        state["devices"] = state_changes(
            state["devices"],
            offline_now,
            label_for=device_label,
            alert_text=lambda device_id, row: (
                f"\U0001F534 Geraet offline: {row.get('name') or device_id} "
                f"(ID {device_id}, {row.get('address') or 'keine Adresse'})"
            ),
            recovery_text=lambda device_id, label: (
                f"✅ Geraet wieder online: {label} (ID {device_id})"
            ),
            messages=messages,
        )

    # Eine Abfrage fuer "still" (Watchdog je Sensor) und "ausserhalb Min/Max"
    try:
        notify_sensors = IotSensorClient(**clients).fetch_notify_sensors()
        stale_rows = {
            row["id"]: row
            for sensor in notify_sensors
            if (row := extract_stale_sensor(sensor)) is not None
        }
        minmax_rows = {
            row["id"]: row
            for sensor in notify_sensors
            if (row := extract_out_of_range_sensor(sensor)) is not None
        }
    except (RuntimeError, requests.exceptions.RequestException) as exc:
        log(f"Sensor-Abfrage fehlgeschlagen: {exc}")
        ok = False
        stale_rows = minmax_rows = None

    if stale_rows is not None:
        state["sensors"] = state_changes(
            state["sensors"],
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
            messages=messages,
        )

    if minmax_rows is not None:
        state["minmax_sensors"] = state_changes(
            state["minmax_sensors"],
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
            messages=messages,
        )

    return ok


def main():
    ap = argparse.ArgumentParser(
        description="Erkennt auffaellige Geraete/Sensoren; Meldungen als JSON fuer den Runner")
    ap.add_argument("--dry-run", action="store_true",
                    help="Meldungen nur anzeigen, Zustand nicht speichern")
    args = ap.parse_args()
    dry_run = args.dry_run or dry_run_from_env()

    state = load_state()
    messages = []
    ok = check(state, messages)
    for text in messages:
        log(text)

    if not dry_run:
        save_state(state)
    summary = f"{len(messages)} neue Meldung(en)" + ("" if ok else ", Abfrage fehlgeschlagen")
    if args.dry_run:
        log(f"[dry-run] {summary}")
    else:
        write_output([], summary, messages)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
