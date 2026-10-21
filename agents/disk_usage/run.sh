#!/bin/bash
# Ermittelt die Festplattenbelegung des Rechners und schreibt sie nach iot_sensor_data.
# REST-Zugang und Einstellungen gibt der Agenten-Runner als Umgebungsvariablen mit.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Python des Runners (IOT_PYTHON), sonst gemeinsames .venv im Repo-Root
PYTHON="${IOT_PYTHON:-$SCRIPT_DIR/../../.venv/bin/python3}"
exec "$PYTHON" "$SCRIPT_DIR/disk_usage.py" "$@"
