#!/bin/bash
# Prueft Geraete/Sensoren und verschickt Benachrichtigungen (Nextcloud Talk,
# Telegram). Einstellungen und Zugangsdaten kommen aus config.env im selben
# Ordner (Vorlage: config.env.skelet).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/../../.venv/bin/python3" "$SCRIPT_DIR/notify.py" "$@"
