#!/bin/bash
# Prueft Geraete/Sensoren und stellt Benachrichtigungen in die Warteschlange
# iot_notification (verschickt vom Agenten notify). REST-Zugang gibt der Agenten-Runner als
# Umgebungsvariablen mit.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Python des Runners (IOT_PYTHON), sonst gemeinsames .venv im Repo-Root
PYTHON="${IOT_PYTHON:-$SCRIPT_DIR/../../.venv/bin/python3}"
exec "$PYTHON" "$SCRIPT_DIR/watchdog.py" "$@"
