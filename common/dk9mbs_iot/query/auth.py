"""Anmeldung am REST-Service: Header und Zugangsdaten aus der Umgebung."""

import os
from typing import Optional


def rest_headers(username: Optional[str] = None, password: Optional[str] = None,
                 apikey: Optional[str] = None) -> dict:
    """
    Bevorzugt den API-Key (Parameter oder RESTAPI_APIKEY), sonst
    Benutzer/Passwort (Parameter oder RESTAPI_USERNAME / RESTAPI_PASSWORD).
    """
    apikey = apikey or os.environ.get("RESTAPI_APIKEY")
    if apikey:
        return {"Content-Type": "application/xml", "apikey": apikey}

    username = username or os.environ.get("RESTAPI_USERNAME")
    password = password or os.environ.get("RESTAPI_PASSWORD")
    if not username or not password:
        raise RuntimeError(
            "Bitte RESTAPI_APIKEY oder RESTAPI_USERNAME und RESTAPI_PASSWORD "
            "setzen, oder Zugangsdaten übergeben."
        )
    return {
        "Content-Type": "application/xml",
        "restapi_username": username,
        "restapi_password": password,
    }


def rest_from_env() -> dict:
    """
    REST-Zugang eines Agenten: {"base_url", "apikey", "timeout"}.
    Der Agenten-Runner setzt dafuer IOT_REST_BASE_URL, IOT_REST_APIKEY und
    IOT_REST_TIMEOUT aus dem rest-Block seiner agents.json.
    """
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
