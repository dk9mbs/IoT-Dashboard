#!/usr/bin/env python3
"""
Verschickt Benachrichtigungen ueber die Telegram Bot API.

Benoetigt TELEGRAM_BOT_TOKEN und TELEGRAM_CHAT_ID als Umgebungsvariablen
(siehe .env).
"""

import os
from typing import Tuple

import requests

API_URL = "https://api.telegram.org/bot{token}/sendMessage"


def send_telegram_message(text: str, timeout: float = 10.0) -> Tuple[bool, str]:
    """Sendet eine Textnachricht an den konfigurierten Telegram-Chat."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        return False, "TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID nicht gesetzt."

    try:
        response = requests.post(
            API_URL.format(token=token),
            data={"chat_id": chat_id, "text": text},
            timeout=timeout,
        )
        if response.status_code == 200:
            return True, "gesendet"
        return False, f"Telegram antwortete mit Status {response.status_code}: {response.text}"
    except requests.exceptions.RequestException as exc:
        return False, f"Telegram nicht erreichbar: {exc}"
