#!/bin/bash
# Berechnet den WLAN-Score und schreibt die Kennzahlen per REST weg.
# Einstellungen und API-Key kommen aus config.json im selben Ordner.
# Python aus dem gemeinsamen .venv im Repo-Root, sonst System-Python.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/../../.venv/bin/python3"
[ -x "$PYTHON" ] || PYTHON=python3
exec "$PYTHON" "$SCRIPT_DIR/wlan_score.py" --config "$SCRIPT_DIR/config.json" --push "$@"
