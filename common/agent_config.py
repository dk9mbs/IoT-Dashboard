"""
Zentrale REST-Zugangsdaten der Agenten aus agents/agents.json:

    "rest": { "base_url": "https://dk9mbs.de/api/v1.0", "apikey": "...", "timeout": 10 }

Der Runner setzt IOT_AGENTS_CONFIG auf seine Konfiguration, damit Agenten
dieselbe Datei lesen; beim Aufruf von Hand gilt agents/agents.json.
"""

import json
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_AGENTS_CONFIG = ROOT_DIR / "agents" / "agents.json"


def agents_config_path() -> Path:
    return Path(os.environ.get("IOT_AGENTS_CONFIG") or DEFAULT_AGENTS_CONFIG)


def rest_settings(cfg: dict = None) -> dict:
    """Liefert {"base_url", "apikey", "timeout"}; RuntimeError, wenn etwas fehlt."""
    path = agents_config_path()
    if cfg is None:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    rest = cfg.get("rest") or {}
    base_url = rest.get("base_url")
    if not base_url and rest.get("url"):
        # altes Format: "url" zeigte direkt auf .../data/iot_sensor_data
        base_url = rest["url"].split("/data/")[0]
    if not base_url or not rest.get("apikey"):
        raise RuntimeError(f"rest.base_url und rest.apikey in {path} eintragen")
    return {
        "base_url": base_url.rstrip("/"),
        "apikey": rest["apikey"],
        "timeout": rest.get("timeout", 10),
    }
