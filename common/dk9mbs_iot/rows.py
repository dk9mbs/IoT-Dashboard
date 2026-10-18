"""
Aufbereitung der REST-Antworten (iot_device / iot_sensor) zu einfachen
Zeilen. Gemeinsam genutzt vom Dashboard (Anzeige) und vom Notify-Agenten
(Benachrichtigungen), damit beide dieselben Regeln fuer "offline", "neu",
"still" und "ausserhalb Min/Max" anwenden.
"""

from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

# Zeitzone der Zeitstempel im REST-Service (last_value_on, last_scan_on)
SERVER_TZ = ZoneInfo("Europe/Berlin")

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
    ("watchdog_warning_sec", "Watchdog (Sek.)"),
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


def _raw(record: dict, field: str):
    """Rohwert eines Feldes (die API liefert ihn direkt oder als {"value": ...})."""
    value = record.get(field)
    if isinstance(value, dict):
        value = value.get("value", value.get("formatted_value"))
    return value


def extract_stale_sensor(sensor: dict, now: Optional[datetime] = None) -> Optional[dict]:
    """
    Liefert die Sensor-Zeile zurück, wenn der Sensor "still" ist: seine letzte
    Meldung (last_value_on) liegt länger zurück als sein eigener Watchdog
    (watchdog_warning_sec). Das lässt sich im FetchXML nicht formulieren, weil
    zwei Felder derselben Zeile verglichen werden.
    Keine Warnung (None), wenn der Sensor keinen Watchdog hat (leer oder 0)
    oder noch nie einen Wert gemeldet hat.
    """
    try:
        watchdog = int(_raw(sensor, "watchdog_warning_sec"))
        last = datetime.fromisoformat(str(_raw(sensor, "last_value_on")))
    except (TypeError, ValueError):
        return None
    if watchdog <= 0:
        return None

    if last.tzinfo is None:
        last = last.replace(tzinfo=SERVER_TZ)
    now = now or datetime.now(SERVER_TZ)
    silent = (now - last).total_seconds()
    if silent <= watchdog:
        return None

    row = extract_sensor_row(sensor)
    row["_silent_seconds"] = int(silent)
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
