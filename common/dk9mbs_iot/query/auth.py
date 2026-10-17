"""Anmelde-Header fuer den REST-Service: API-Key oder Benutzer/Passwort."""

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

