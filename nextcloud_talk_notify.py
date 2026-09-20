#!/usr/bin/env python3
"""
Verschickt Benachrichtigungen ueber die Nextcloud Talk Chat-API (OCS).

Benoetigt NEXTCLOUD_URL, NEXTCLOUD_USERNAME, NEXTCLOUD_APP_PASSWORD und
NEXTCLOUD_TALK_ROOM_TOKEN als Umgebungsvariablen (siehe .env). Die
Anmeldung erfolgt ueber ein App-Passwort (Nextcloud-Einstellungen >
Sicherheit > Geraete & Sitzungen), NICHT ueber das normale Passwort.
Der Room-Token steht im Talk-Link der Unterhaltung
(https://<host>/call/<token>).
"""

import os
from typing import Tuple

import requests

CHAT_PATH = "/ocs/v2.php/apps/spreed/api/v1/chat/{token}"


def send_nextcloud_talk_message(text: str, timeout: float = 10.0) -> Tuple[bool, str]:
    """Sendet eine Textnachricht in den konfigurierten Nextcloud-Talk-Raum."""
    base_url = (os.environ.get("NEXTCLOUD_URL") or "").strip().rstrip("/")
    if base_url and not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"
    username = os.environ.get("NEXTCLOUD_USERNAME")
    app_password = os.environ.get("NEXTCLOUD_APP_PASSWORD")
    room_token = os.environ.get("NEXTCLOUD_TALK_ROOM_TOKEN")

    if not base_url or not username or not app_password or not room_token:
        return False, (
            "NEXTCLOUD_URL/NEXTCLOUD_USERNAME/NEXTCLOUD_APP_PASSWORD/"
            "NEXTCLOUD_TALK_ROOM_TOKEN nicht (vollstaendig) gesetzt."
        )

    url = base_url + CHAT_PATH.format(token=room_token)

    try:
        response = requests.post(
            url,
            auth=(username, app_password),
            headers={"OCS-APIRequest": "true", "Accept": "application/json"},
            data={"message": text},
            timeout=timeout,
        )
        if response.status_code in (200, 201):
            return True, "gesendet"
        return False, (
            f"Nextcloud Talk antwortete mit Status {response.status_code}: "
            f"{response.text}"
        )
    except requests.exceptions.RequestException as exc:
        return False, f"Nextcloud Talk nicht erreichbar: {exc}"
