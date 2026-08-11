#!/usr/bin/env python3
"""
Löst ein Firmware-Update auf einem Shelly-Gerät aus.

Probiert zuerst die Gen2+/Gen3-RPC-Methode (POST /rpc/Shelly.Update).
Schlägt das aus Verbindungsgründen fehl (z.B. weil es ein Gen1-Gerät
ist, das /rpc nicht kennt), wird auf die klassische Gen1-Methode
(GET /ota?update=true) zurückgefallen.

WICHTIG: Ein fehlgeschlagenes OTA-Update kann ein Gerät im schlimmsten
Fall unbrauchbar machen. Diese Funktion sollte nur gezielt für einzelne,
vom Nutzer bestätigte Geräte aufgerufen werden - nie automatisiert oder
in Schleife über mehrere Geräte ohne Bestätigung.
"""

from typing import Tuple

import requests


def trigger_shelly_update(address: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """
    Löst ein Firmware-Update aus. Gibt (success, message) zurück.
    """
    if not address:
        return False, "Keine Adresse für dieses Gerät bekannt."

    base = address if address.startswith("http") else f"http://{address}"

    # --- Gen2+/Gen3: RPC-Methode Shelly.Update ---
    try:
        response = requests.post(
            f"{base}/rpc/Shelly.Update",
            json={"id": 1, "method": "Shelly.Update", "params": {"stage": "stable"}},
            timeout=timeout,
        )
        try:
            data = response.json()
        except ValueError:
            data = {}

        if not isinstance(data, dict):
            data = {}

        if response.status_code == 200 and "error" not in data:
            return True, "Update ausgelöst (Gen2+/RPC). Gerät startet in Kürze neu."

        if "error" in data:
            return False, f"Gerät meldete Fehler: {data['error']}"

        # Unerwarteter Status ohne klaren Fehler -> Gen1-Fallback versuchen
    except requests.exceptions.RequestException:
        # Verbindung zu /rpc fehlgeschlagen -> vermutlich Gen1-Gerät, Fallback versuchen
        pass

    # --- Gen1: klassischer /ota-Endpunkt ---
    try:
        response = requests.get(
            f"{base}/ota", params={"update": "true"}, timeout=timeout
        )
        if response.status_code == 200:
            return True, "Update ausgelöst (Gen1). Gerät startet in Kürze neu."
        return False, f"Gerät antwortete mit Status {response.status_code}."
    except requests.exceptions.RequestException as exc:
        return False, f"Gerät nicht erreichbar: {exc}"
