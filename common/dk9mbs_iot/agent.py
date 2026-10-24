"""
Umgebung eines Agenten. Der Agenten-Runner (agents/run_agents.py) setzt:

    IOT_REST_BASE_URL, IOT_REST_APIKEY, IOT_REST_TIMEOUT   REST-Zugang
    IOT_AGENT_SETTINGS                                     Einstellungen (JSON)
    IOT_DRY_RUN                                            "1" bei run_agents.py --dry-run

Die Einstellungen kommen zentral aus iot_agent_config.settings.

Agenten mit Ausgabetyp > 1 (iot_agent.output_type_id) geben ihr Ergebnis mit
write_output() als JSON auf stdout aus (optional mit einer kurzen Meldung) und
melden alles andere mit log() auf stderr; der Runner schreibt die Daten dann
per REST (agents/agent_output.py).
"""

import json
import os
import sys


def log(*args) -> None:
    """Log-Meldung nach stderr (stdout ist dem JSON-Ergebnis vorbehalten)."""
    print(*args, file=sys.stderr, flush=True)


def write_output(items: list, message: str = None, notify=None) -> None:
    """
    Ergebnis für den Runner: {"data": [...], "message": "...", "notify": [...]}
    als einzige Ausgabe auf stdout. message ist eine kurze Meldung zum Lauf
    (z.B. "30/32 erreichbar"), der Runner speichert sie in iot_agent_status.
    notify (Text oder Liste von Texten) stellt der Runner als Benachrichtigungen
    in die Warteschlange iot_notification, verschickt vom Agenten notify.
    """
    document = {"data": items}
    if message:
        document["message"] = message
    if notify:
        document["notify"] = notify
    json.dump(document, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stdout.flush()


def dry_run_from_env() -> bool:
    """True, wenn der Runner mit --dry-run läuft: nichts senden, keinen Zustand speichern."""
    return os.environ.get("IOT_DRY_RUN") == "1"


def rest_from_env() -> dict:
    """REST-Zugang des Agenten: {"base_url", "apikey", "timeout"}."""
    base_url = os.environ.get("IOT_REST_BASE_URL")
    apikey = os.environ.get("IOT_REST_APIKEY")
    if not base_url or not apikey:
        raise RuntimeError("IOT_REST_BASE_URL / IOT_REST_APIKEY fehlen - "
                           "Agenten ueber run_agents.py starten (z.B. --run <name>)")
    return {
        "base_url": base_url.rstrip("/"),
        "apikey": apikey,
        "timeout": float(os.environ.get("IOT_REST_TIMEOUT") or 10),
    }


def settings_from_env() -> dict:
    """Einstellungen des Agenten; leer, wenn der Runner keine mitgegeben hat."""
    raw = os.environ.get("IOT_AGENT_SETTINGS")
    if not raw:
        return {}
    settings = json.loads(raw)
    if not isinstance(settings, dict):
        raise ValueError("IOT_AGENT_SETTINGS muss ein JSON-Objekt sein")
    return settings
