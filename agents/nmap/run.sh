#!/bin/bash
# Startet den nmap-Netzwerkscan. REST-Zugang und Einstellungen (Netz, nmap-
# Argumente) gibt der Agenten-Runner als Umgebungsvariablen mit.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Python des Runners (IOT_PYTHON), sonst gemeinsames .venv im Repo-Root
PYTHON="${IOT_PYTHON:-$SCRIPT_DIR/../../.venv/bin/python3}"
exec "$PYTHON" "$SCRIPT_DIR/iptest_v2.py" "$@"
