#!/bin/bash
# Installiert das IoT-Dashboard als systemd-Dienst.
#
# Erzeugt aus iot-dashboard.service.skelet die Unit mit den Pfaden dieses
# Repos, installiert sie nach /etc/systemd/system und startet den Dienst.
#
# Aufruf (als root):
#   ./install.sh [--venv PFAD] [--user BENUTZER] [--print]
#
#   --venv PFAD      venv mit Flask & Co. (Standard: aktives venv, sonst ./dash)
#   --user BENUTZER  Benutzer fuer den Dienst (Standard: Aufrufer, bei sudo SUDO_USER)
#   --print          Unit nur ausgeben, nichts installieren (kein root noetig)
set -euo pipefail

SERVICE=iot-dashboard
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$REPO_DIR/$SERVICE.service.skelet"
TARGET="/etc/systemd/system/$SERVICE.service"

VENV="${VIRTUAL_ENV:-}"
[ -z "$VENV" ] && [ -d "$REPO_DIR/dash" ] && VENV="$REPO_DIR/dash"
RUN_USER="${SUDO_USER:-$(id -un)}"
PRINT_ONLY=false

while [ $# -gt 0 ]; do
  case "$1" in
    --venv)  VENV="$2"; shift 2 ;;
    --user)  RUN_USER="$2"; shift 2 ;;
    --print) PRINT_ONLY=true; shift ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
done

fail() { echo "Fehler: $*" >&2; exit 1; }

[ -n "$VENV" ] || fail "kein venv gefunden - bitte mit --venv PFAD angeben"
PYTHON="$VENV/bin/python3"
[ -x "$PYTHON" ] || fail "$PYTHON nicht gefunden"
"$PYTHON" -c "import flask, requests, dotenv" 2>/dev/null \
  || fail "im venv $VENV fehlen Pakete: $PYTHON -m pip install -r $REPO_DIR/requirements.txt"
id "$RUN_USER" >/dev/null 2>&1 || fail "Benutzer $RUN_USER existiert nicht"
[ -f "$REPO_DIR/.env" ] || echo "Warnung: $REPO_DIR/.env fehlt (Vorlage: .env.skelet)" >&2

UNIT="$(sed -e "s|@REPO_DIR@|$REPO_DIR|g" \
            -e "s|@PYTHON@|$PYTHON|g" \
            -e "s|@USER@|$RUN_USER|g" \
            -e '1,/^\[Unit\]/{/^\[Unit\]/!d}' "$TEMPLATE")"  # Kopfkommentar entfernen

if $PRINT_ONLY; then
  echo "$UNIT"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || fail "bitte als root bzw. mit sudo ausfuehren (oder --print)"

echo "$UNIT" > "$TARGET"
echo "Unit geschrieben: $TARGET (Benutzer $RUN_USER, Python $PYTHON)"
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 2
systemctl --no-pager --lines=5 status "$SERVICE" || true
echo
echo "Logs:    journalctl -u $SERVICE -f"
echo "Stoppen: systemctl stop $SERVICE"
