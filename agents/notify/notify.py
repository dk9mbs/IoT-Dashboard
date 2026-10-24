#!/usr/bin/env python3
"""
notify.py - Verschickt die offenen Benachrichtigungen aus der Warteschlange
iot_notification per Nextcloud Talk und/oder Telegram.

Was gemeldet wird, entscheidet notify nicht selbst: jeder Agent kann ueber
"notify" in seiner JSON-Ausgabe Meldungen einstellen (z.B. watchdog fuer
auffaellige Geraete und Sensoren), der Runner legt sie mit status 'new' an.

Ein Aufruf = ein Versanddurchgang; den Takt gibt der Agenten-Runner vor.
Offen sind Meldungen mit status 'new' oder 'failed' und weniger als
max_attempts Versuchen, verschickt in der Reihenfolge ihres Eintrags.
Eine Meldung gilt als gesendet, sobald mindestens ein aktivierter Kanal
erfolgreich war.

Ausgabetyp 5 (Update Notification): das Ergebnis je Meldung geht als JSON
{"data": [{"id", "status_id", "attempts", "last_error", "sent_on"}]} auf
stdout, der Runner setzt die Meldungen damit auf 'sent' bzw. 'failed';
Log-Meldungen auf stderr. Gelesen wird die Warteschlange selbst.

REST-Zugang (IOT_REST_*) und Einstellungen (IOT_AGENT_SETTINGS) gibt der
Agenten-Runner mit. Die Einstellungen sind die Kanaele, mit denselben Namen
wie frueher in config.env (Vorlage: settings.json.skelet), z.B.
{"NEXTCLOUD_TALK_ENABLED": true, "NEXTCLOUD_URL": "...", "TELEGRAM_ENABLED": false},
dazu optional "max_attempts" (Standard 5).

Aufruf:
    python3 notify.py [--dry-run] [--test "Text"]

Exit-Code 1, wenn die Warteschlange nicht gelesen werden konnte oder eine
Meldung nicht verschickt wurde.
"""

import argparse
import os
import sys
from datetime import datetime
from typing import Tuple
from zoneinfo import ZoneInfo

import requests
from dk9mbs_iot.agent import dry_run_from_env, log, rest_from_env, settings_from_env, write_output
from dk9mbs_iot.query.auth import rest_headers

from nextcloud_talk_notify import send_nextcloud_talk_message
from telegram_notify import send_telegram_message

MITTELEUROPA = ZoneInfo("Europe/Berlin")
DEFAULT_MAX_ATTEMPTS = 5

SETTINGS = settings_from_env()
# Kanal-Einstellungen in die Umgebung, dort lesen sie die beiden Sender
for _key, _value in SETTINGS.items():
    os.environ[_key] = str(_value).lower() if isinstance(_value, bool) else str(_value)


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


TELEGRAM_ENABLED = _env_flag("TELEGRAM_ENABLED", False)
NEXTCLOUD_TALK_ENABLED = _env_flag("NEXTCLOUD_TALK_ENABLED", True)


def send(text: str) -> Tuple[bool, str]:
    """
    Verschickt eine Nachricht ueber alle aktivierten Kanaele. Gilt als
    erfolgreich, sobald mindestens ein aktivierter Kanal erfolgreich war,
    damit ein einzelner ausgefallener Kanal keine Endlos-Wiederholung
    der Meldung bei jedem Lauf ausloest.
    """
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


def _value(row: dict, field: str):
    """Rohwert eines Feldes aus der REST-Antwort ({'value': ..., 'formatted_value': ...})."""
    data = row.get(field)
    return data.get("value") if isinstance(data, dict) else data


def fetch_queue(max_attempts: int) -> list:
    """Offene Meldungen (nicht 'sent', weniger als max_attempts Versuche), aelteste zuerst."""
    rest = rest_from_env()
    xml = f"""<restapi type="select">
    <table name="iot_notification" alias="n"/>
    <filter type="and">
        <condition field="status_id" alias="n" value="sent" operator="neq" />
        <condition field="attempts" alias="n" value="{max_attempts - 1}" operator="leq" />
    </filter>
    <orderby>
        <field name="id" alias="n" sort="ASC"/>
    </orderby>
</restapi>"""
    response = requests.post(f"{rest['base_url']}/data", headers=rest_headers(apikey=rest["apikey"]),
                             data=xml.encode("utf-8"), timeout=rest["timeout"])
    response.raise_for_status()
    rows = response.json()
    if not isinstance(rows, list):
        raise RuntimeError(f"unerwartete Antwort: {str(rows)[:200]}")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Verschickt die Meldungen aus iot_notification")
    ap.add_argument("--dry-run", action="store_true",
                    help="nur anzeigen, was verschickt wuerde (nichts senden, nichts ausgeben)")
    ap.add_argument("--test", metavar="TEXT", help="nur eine Testnachricht ueber die Kanaele senden")
    args = ap.parse_args()

    if args.test:
        ok, message = send(args.test)
        log(message)
        sys.exit(0 if ok else 1)

    max_attempts = max(1, int(SETTINGS.get("max_attempts", DEFAULT_MAX_ATTEMPTS)))
    try:
        queue = fetch_queue(max_attempts)
    except (RuntimeError, ValueError, requests.exceptions.RequestException) as exc:
        log(f"Warteschlange nicht lesbar: {exc}")
        if not args.dry_run:
            write_output([], "Warteschlange nicht lesbar")
        sys.exit(1)

    dry_run = args.dry_run or dry_run_from_env()
    output = []
    sent = failed = 0
    for row in queue:
        notification_id, text = _value(row, "id"), str(_value(row, "message") or "")
        attempts = int(_value(row, "attempts") or 0) + 1
        if dry_run:
            log(f"[dry-run] {notification_id}: {text}")
            continue
        ok, result = send(text)
        item = {"id": notification_id, "attempts": attempts}
        if ok:
            sent += 1
            item.update(status_id="sent", last_error=None,
                        sent_on=datetime.now(MITTELEUROPA).strftime("%Y-%m-%d %H:%M:%S"))
        else:
            failed += 1
            item.update(status_id="failed", last_error=result)
            log(f"{notification_id}: nicht verschickt (Versuch {attempts}/{max_attempts}): {result}")
        output.append(item)

    summary = (f"{len(queue)} offen (dry-run)" if dry_run else
               f"{sent} gesendet, {failed} fehlgeschlagen" if queue else "keine offenen Meldungen")
    log(summary)
    if not args.dry_run:
        write_output(output, summary)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
