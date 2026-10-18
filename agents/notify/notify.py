#!/usr/bin/env python3
"""
notify.py - Benachrichtigt per Nextcloud Talk und/oder Telegram ueber
auffaellige Geraete und Sensoren (frueher Hintergrund-Thread im Dashboard).

Ein Aufruf = eine Pruefung; den Takt gibt der Agenten-Runner vor.
Gemeldet wird jedes Ereignis genau einmal beim Auftreten und einmal bei
der Erholung:
  - Geraet neu (status 'new')
  - Geraet offline (notify=-1 & last_scan_on > 10 Min., serverseitig gefiltert)
  - Sensor still (notify=-1 & letzte Meldung aelter als watchdog_warning_sec des Sensors)
  - Sensorwert ausserhalb [min_value, max_value]

REST-Zugang (IOT_REST_*) und Einstellungen (IOT_AGENT_SETTINGS) gibt der
Agenten-Runner mit. Die Einstellungen sind die Kanaele, mit denselben Namen
wie frueher in config.env (Vorlage: settings.json.skelet), z.B.
{"NEXTCLOUD_TALK_ENABLED": true, "NEXTCLOUD_URL": "...", "TELEGRAM_ENABLED": false}.

Aufruf:
    python3 notify.py [--dry-run] [--test "Text"]

Exit-Code 1, wenn eine REST-Abfrage oder eine Benachrichtigung fehlschlug.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Tuple

import requests
from dk9mbs_iot.agent import rest_from_env, settings_from_env
from dk9mbs_iot.query.device import IotDeviceClient
from dk9mbs_iot.query.sensor import IotSensorClient
from dk9mbs_iot.rows import extract_out_of_range_sensor, extract_row, extract_stale_sensor

from nextcloud_talk_notify import send_nextcloud_talk_message
from telegram_notify import send_telegram_message

AGENT_DIR = Path(__file__).resolve().parent

# Kanal-Einstellungen in die Umgebung, dort lesen sie die beiden Sender
for _key, _value in settings_from_env().items():
    os.environ[_key] = str(_value).lower() if isinstance(_value, bool) else str(_value)

# Merkt sich als {id: label}, fuer welche Geraete/Sensoren bereits eine
# Meldung verschickt wurde, damit jedes Ereignis nur einmalig meldet.
# Sobald ein Eintrag wieder verschwindet (online / neuer Sensorwert /
# nicht mehr 'neu'), wird eine Erholungs-Meldung verschickt und der Eintrag
# entfernt - erst dann kann ein erneutes Ereignis wieder eine neue Meldung
# ausloesen. Das gespeicherte label (Name/Alias) wird gebraucht, damit die
# Erholungs-Meldung lesbar bleibt, auch wenn das Geraet/der Sensor zu
# diesem Zeitpunkt nicht mehr in der API-Antwort auftaucht.
STATE_FILE = AGENT_DIR / "device_status_state.json"


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


TELEGRAM_ENABLED = _env_flag("TELEGRAM_ENABLED", False)
NEXTCLOUD_TALK_ENABLED = _env_flag("NEXTCLOUD_TALK_ENABLED", True)


class Notifier:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.failed = False  # fuer den Exit-Code

    def send(self, text: str) -> Tuple[bool, str]:
        """
        Verschickt eine Nachricht ueber alle aktivierten Kanaele. Gilt als
        erfolgreich, sobald mindestens ein aktivierter Kanal erfolgreich war,
        damit ein einzelner ausgefallener Kanal keine Endlos-Wiederholung
        der Meldung bei jedem Lauf ausloest.
        """
        if self.dry_run:
            print(f"[dry-run] {text}")
            return True, "dry-run"

        channels = []
        if TELEGRAM_ENABLED:
            channels.append(("Telegram", send_telegram_message))
        if NEXTCLOUD_TALK_ENABLED:
            channels.append(("Nextcloud Talk", send_nextcloud_talk_message))

        if not channels:
            return False, "Keine Benachrichtigungskanaele aktiviert."

        results = []
        any_ok = False
        for name, sender in channels:
            ok, message = sender(text)
            results.append(f"{name}: {message}")
            any_ok = any_ok or ok

        return any_ok, "; ".join(results)

    def state_changes(self, notified: dict, current: dict, label_for, alert_text, recovery_text) -> dict:
        """
        Vergleicht den zuletzt gemeldeten Zustand (notified: {id: label}) mit dem
        aktuell auffaelligen Zustand (current: {id: row}) und verschickt fuer
        jede Aenderung genau eine Benachrichtigung: einmalig bei neuem Auftreten
        (alert_text) und einmalig bei Wegfall/Erholung (recovery_text).
        Gibt den aktualisierten notified-Zustand zurueck.
        """
        for item_id in set(notified) - set(current):
            label = notified[item_id]
            ok, message = self.send(recovery_text(item_id, label))
            if ok:
                del notified[item_id]
            else:
                self.failed = True
                print(f"[notify] Benachrichtigung fehlgeschlagen: {message}")

        for item_id, row in current.items():
            if item_id not in notified:
                ok, message = self.send(alert_text(item_id, row))
                if ok:
                    notified[item_id] = label_for(row)
                else:
                    self.failed = True
                    print(f"[notify] Benachrichtigung fehlgeschlagen: {message}")

        return notified


def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
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


def save_state(data: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def check(notifier: Notifier) -> None:
    """
    Prueft Geraete und Sensoren und meldet jede Aenderung genau einmal.

    fetch_devices() liefert Geraete, bei denen last_scan_on aelter als 10 Min.
    ist UND notify=-1 gesetzt ist, ODER der Status 'new' ist (dieselbe
    server-seitig gefilterte Logik wie fuer die Tabelle "auffaellige
    Geraete" im Dashboard). Die 'new'-Faelle werden separat als "neues
    Geraet" gemeldet, der Rest als "offline" - status_id wird vom Backend
    naemlich nicht zuverlaessig auf 'offline' gesetzt, wenn ein Geraet nicht
    mehr scannt, es bleibt z.B. auf 'active' stehen, waehrend last_scan_on
    veraltet.

    Schlaegt eine Abfrage fehl, bleibt der Zustand der betroffenen Kategorie
    unveraendert (keine falschen Erholungs-Meldungen).
    """
    try:
        rest = rest_from_env()
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"[notify] REST-Zugang nicht konfiguriert: {exc}")
        notifier.failed = True
        return
    clients = {"apikey": rest["apikey"], "base_url": rest["base_url"]}

    state = load_state()

    try:
        conspicuous_rows = list(map(extract_row, IotDeviceClient(**clients).fetch_devices()))
        new_now = {row["id"]: row for row in conspicuous_rows if row.get("_status_raw") == "new"}
        offline_now = {row["id"]: row for row in conspicuous_rows if row.get("_status_raw") != "new"}
    except (RuntimeError, requests.exceptions.RequestException) as exc:
        print(f"[notify] Geraete-Abfrage fehlgeschlagen: {exc}")
        notifier.failed = True
        new_now = offline_now = None

    device_label = lambda row: row.get("name") or row["id"]  # noqa: E731

    if new_now is not None:
        state["new_devices"] = notifier.state_changes(
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
        )

    if offline_now is not None:
        state["devices"] = notifier.state_changes(
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
        print(f"[notify] Sensor-Abfrage fehlgeschlagen: {exc}")
        notifier.failed = True
        stale_rows = minmax_rows = None

    if stale_rows is not None:
        state["sensors"] = notifier.state_changes(
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
        )

    if minmax_rows is not None:
        state["minmax_sensors"] = notifier.state_changes(
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
        )

    if not notifier.dry_run:
        save_state(state)


def main():
    ap = argparse.ArgumentParser(description="Benachrichtigungen fuer auffaellige Geraete/Sensoren")
    ap.add_argument("--dry-run", action="store_true",
                    help="nur anzeigen, was gemeldet wuerde (nichts senden, Zustand nicht speichern)")
    ap.add_argument("--test", metavar="TEXT", help="nur eine Testnachricht ueber die Kanaele senden")
    args = ap.parse_args()

    notifier = Notifier(dry_run=args.dry_run)
    if args.test:
        ok, message = notifier.send(args.test)
        print(message)
        sys.exit(0 if ok else 1)

    check(notifier)
    sys.exit(1 if notifier.failed else 0)


if __name__ == "__main__":
    main()
