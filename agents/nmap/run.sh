#!/bin/bash
# Startet den nmap-Netzwerkscan. Einstellungen und Zugangsdaten kommen aus
# config.env im selben Ordner (Vorlage: config.env.skelet).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"
source "$VENV/bin/activate"
exec python3 "$SCRIPT_DIR/iptest_v2.py" \
  --netz "$NMAP_NETZ" \
  --rest-url "$REST_URL" \
  --rest-user "$REST_USER" \
  --rest-pass "$REST_PASS" \
  "$@"
