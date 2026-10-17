"""
Umgebung eines Agenten. Der Agenten-Runner (agents/run_agents.py) setzt:

    IOT_REST_BASE_URL, IOT_REST_APIKEY, IOT_REST_TIMEOUT   REST-Zugang
    IOT_AGENT_SETTINGS                                     Einstellungen (JSON)

Die Einstellungen kommen zentral aus iot_agent_config.settings.
"""

import json
import os


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
