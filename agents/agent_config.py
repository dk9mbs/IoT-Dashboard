"""
REST-Zugangsdaten der Agenten aus agents.json (genutzt vom Runner):

    "rest": { "base_url": "https://dk9mbs.de/api/v1.0", "apikey": "...", "timeout": 10 }

Der Runner gibt sie jedem Agenten als Umgebungsvariablen mit (rest_env),
die Agenten lesen sie mit dk9mbs_iot.query.auth.rest_from_env().
"""


def rest_settings(cfg: dict) -> dict:
    """Liefert {"base_url", "apikey", "timeout"}; RuntimeError, wenn etwas fehlt."""
    rest = cfg.get("rest") or {}
    base_url = rest.get("base_url")
    if not base_url and rest.get("url"):
        # altes Format: "url" zeigte direkt auf .../data/iot_sensor_data
        base_url = rest["url"].split("/data/")[0]
    if not base_url or not rest.get("apikey"):
        raise RuntimeError("rest.base_url und rest.apikey in agents.json eintragen")
    return {
        "base_url": base_url.rstrip("/"),
        "apikey": rest["apikey"],
        "timeout": rest.get("timeout", 10),
    }


def rest_env(cfg: dict) -> dict:
    """Umgebungsvariablen fuer einen Agenten; leer, wenn kein REST-Zugang konfiguriert ist."""
    try:
        rest = rest_settings(cfg)
    except RuntimeError:
        return {}
    return {
        "IOT_REST_BASE_URL": rest["base_url"],
        "IOT_REST_APIKEY": rest["apikey"],
        "IOT_REST_TIMEOUT": str(rest["timeout"]),
    }
