#!/bin/bash
# Berechnet den WLAN-Score und schreibt die Kennzahlen per REST weg.
# Einstellungen kommen aus config.json im selben Ordner, der REST-Zugang
# aus agents/agents.json. Python aus dem gemeinsamen .venv im Repo-Root
# (dort ist dk9mbs_iot installiert, siehe install/install.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/../../.venv/bin/python3" "$SCRIPT_DIR/wlan_score.py" --config "$SCRIPT_DIR/config.json" --push "$@"
