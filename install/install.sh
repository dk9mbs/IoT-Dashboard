#!/bin/bash
# Richtet das gemeinsame venv ein und installiert das IoT-Dashboard als
# systemd-Dienst.
#
# 1. Legt das venv an, falls es fehlt (Standard: .venv im Repo-Root), und
#    installiert per pip dashboard/requirements.txt sowie die
#    requirements.txt aller Agenten (agents/*/requirements.txt).
# 2. Erzeugt aus iot-dashboard.service.skelet die Unit mit den Pfaden des
#    Dashboards (dashboard/), installiert sie nach /etc/systemd/system und
#    startet den Dienst.
#
# Aufruf:
#   install/install.sh [--venv PFAD] [--user BENUTZER] [--deps | --print]
#
#   --venv PFAD      venv fuer Dashboard und Agenten
#                    (Standard: aktives venv, sonst .venv im Repo-Root)
#   --user BENUTZER  Benutzer fuer den Dienst (Standard: Aufrufer, bei sudo SUDO_USER)
#   --deps           nur venv anlegen und Pakete installieren, kein Dienst (kein root noetig)
#   --print          Unit nur ausgeben, nichts installieren (kein root noetig)
set -euo pipefail

SERVICE=iot-dashboard
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$INSTALL_DIR/.." && pwd)"
APP_DIR="$ROOT_DIR/dashboard"
TEMPLATE="$INSTALL_DIR/$SERVICE.service.skelet"
TARGET="/etc/systemd/system/$SERVICE.service"

VENV="${VIRTUAL_ENV:-$ROOT_DIR/.venv}"
RUN_USER="${SUDO_USER:-$(id -un)}"
MODE=install

while [ $# -gt 0 ]; do
  case "$1" in
    --venv)  VENV="$2"; shift 2 ;;
    --user)  RUN_USER="$2"; shift 2 ;;
    --deps)  MODE=deps; shift ;;
    --print) MODE=print; shift ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
done

fail() { echo "Fehler: $*" >&2; exit 1; }

id "$RUN_USER" >/dev/null 2>&1 || fail "Benutzer $RUN_USER existiert nicht"
[ "$MODE" != install ] || [ "$(id -u)" -eq 0 ] \
  || fail "bitte als root bzw. mit sudo ausfuehren (oder --deps / --print)"
PYTHON="$VENV/bin/python3"

# Als root das venv nicht root gehoeren lassen: anlegen als Dienst-Benutzer,
# pip als Eigentuemer des venv ausfuehren
as_user() {
  local user="$1"; shift
  if [ "$(id -u)" -eq 0 ] && [ "$user" != root ]; then
    sudo -u "$user" "$@"
  else
    "$@"
  fi
}

if [ "$MODE" != print ]; then
  if [ ! -x "$PYTHON" ]; then
    echo "Lege venv an: $VENV"
    as_user "$RUN_USER" python3 -m venv "$VENV"
  fi
  OWNER="$(stat -c %U "$VENV")"
  as_user "$OWNER" "$PYTHON" -m pip install --quiet --upgrade pip
  for req in "$APP_DIR/requirements.txt" "$ROOT_DIR"/agents/*/requirements.txt; do
    [ -f "$req" ] || continue
    echo "Installiere ${req#"$ROOT_DIR"/}"
    as_user "$OWNER" "$PYTHON" -m pip install --quiet -r "$req"
  done
  [ "$MODE" = deps ] && { echo "Pakete installiert in $VENV"; exit 0; }
  "$PYTHON" -c "import flask, requests, dotenv" 2>/dev/null \
    || fail "im venv $VENV fehlen Pakete fuer das Dashboard"
  [ -f "$APP_DIR/.env" ] || echo "Warnung: $APP_DIR/.env fehlt (Vorlage: .env.skelet)" >&2
fi

UNIT="$(sed -e "s|@APP_DIR@|$APP_DIR|g" \
            -e "s|@PYTHON@|$PYTHON|g" \
            -e "s|@USER@|$RUN_USER|g" \
            -e '1,/^\[Unit\]/{/^\[Unit\]/!d}' "$TEMPLATE")"  # Kopfkommentar entfernen

if [ "$MODE" = print ]; then
  echo "$UNIT"
  exit 0
fi

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
