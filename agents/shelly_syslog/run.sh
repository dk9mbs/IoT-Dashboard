#!/bin/bash
# Wertet die Shelly-Syslogs aus (wer hat zugegriffen, wie auffaellig?); die Kennzahlen
# gibt er als JSON fuer den Runner aus, auffaellige Zugriffe als Benachrichtigung.
# REST-Zugang und Einstellungen gibt der Agenten-Runner als Umgebungsvariablen mit.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Python des Runners (IOT_PYTHON), sonst gemeinsames .venv im Repo-Root
PYTHON="${IOT_PYTHON:-$SCRIPT_DIR/../../.venv/bin/python3}"
exec "$PYTHON" "$SCRIPT_DIR/shelly_syslog.py" "$@"
