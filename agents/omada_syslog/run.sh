#!/bin/bash
# Berechnet den WLAN-Score und schreibt die Kennzahlen per REST weg.
# Einstellungen und API-Key kommen aus config.json im selben Ordner.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/wlan_score.py" --config "$SCRIPT_DIR/config.json" --push "$@"
