#!/bin/bash
# Berechnet den WLAN-Score und schreibt die Kennzahlen per REST weg.
# REST-Zugang und Einstellungen (APs, Muster, Bewertung) gibt der
# Agenten-Runner als Umgebungsvariablen mit.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Python des Runners (IOT_PYTHON), sonst gemeinsames .venv im Repo-Root
PYTHON="${IOT_PYTHON:-$SCRIPT_DIR/../../.venv/bin/python3}"
exec "$PYTHON" "$SCRIPT_DIR/wlan_score.py" --push "$@"
