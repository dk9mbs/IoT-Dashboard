#!/bin/bash
# Startet den nmap-Netzwerkscan. Netz und venv kommen aus config.env im selben
# Ordner (Vorlage: config.env.skelet), der REST-Zugang aus agents/agents.json.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"
# ohne VENV in config.env: gemeinsames .venv im Repo-Root
VENV="${VENV:-$SCRIPT_DIR/../../.venv}"
exec "$VENV/bin/python3" "$SCRIPT_DIR/iptest_v2.py" --netz "$NMAP_NETZ" "$@"
