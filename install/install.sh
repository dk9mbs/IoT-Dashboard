#!/bin/bash
# Richtet das gemeinsame venv ein und installiert die gewaehlten Dienste.
#
# 1. Legt das venv an, falls es fehlt (Standard: .venv im Repo-Root), und
#    installiert per pip den gemeinsamen Code (common/, dk9mbs-iot),
#    dashboard/requirements.txt sowie die
#    requirements.txt aller Agenten (agents/*/requirements.txt).
# 2. Installiert nur die angegebenen Dienste als systemd-Units:
#      --dashboard  iot-dashboard.service  (Weboberflaeche, dashboard/app.py)
#      --agents     iot-agents.service     (Runner, startet die Agenten aus
#                                           agents/agents.json; ersetzt Cron)
#    Welche Agenten laufen, steht allein in agents/agents.json des Rechners.
#
# Aufruf:
#   install/install.sh [--dashboard] [--agents] [--venv PFAD] [--user BENUTZER]
#                      [--deps | --print | --remove]
#
#   --venv PFAD      venv fuer Dashboard und Agenten
#                    (Standard: aktives venv, sonst .venv im Repo-Root)
#   --user BENUTZER  Benutzer fuer die Dienste (Standard: Aufrufer, bei sudo SUDO_USER)
#   --deps           nur venv anlegen und Pakete installieren (kein root noetig)
#   --print          Units nur ausgeben, nichts installieren (kein root noetig)
#   --remove         gewaehlte Dienste stoppen, abschalten und Units loeschen
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$INSTALL_DIR/.." && pwd)"
APP_DIR="$ROOT_DIR/dashboard"
UNIT_DIR=/etc/systemd/system

VENV="${VIRTUAL_ENV:-$ROOT_DIR/.venv}"
RUN_USER="${SUDO_USER:-$(id -un)}"
MODE=install
SERVICES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --dashboard) SERVICES+=(iot-dashboard); shift ;;
    --agents)    SERVICES+=(iot-agents); shift ;;
    --venv)      VENV="$2"; shift 2 ;;
    --user)      RUN_USER="$2"; shift 2 ;;
    --deps)      MODE=deps; shift ;;
    --print)     MODE=print; shift ;;
    --remove)    MODE=remove; shift ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 1 ;;
  esac
done

fail() { echo "Fehler: $*" >&2; exit 1; }

[ "$MODE" = deps ] || [ ${#SERVICES[@]} -gt 0 ] \
  || fail "bitte --dashboard und/oder --agents angeben (oder --deps), siehe --help"
id "$RUN_USER" >/dev/null 2>&1 || fail "Benutzer $RUN_USER existiert nicht"
case "$MODE" in install|remove)
  [ "$(id -u)" -eq 0 ] || fail "bitte als root bzw. mit sudo ausfuehren (oder --deps / --print)" ;;
esac
PYTHON="$VENV/bin/python3"

if [ "$MODE" = remove ]; then
  for svc in "${SERVICES[@]}"; do
    systemctl disable --now "$svc" 2>/dev/null || true
    rm -f "$UNIT_DIR/$svc.service"
    echo "Entfernt: $svc"
  done
  systemctl daemon-reload
  exit 0
fi

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
  # gemeinsamer Code zuerst, editierbar: Aenderungen in common/ gelten sofort.
  # Bewusst nicht in den requirements.txt, sonst wuerde pip ihn ggf. auf PyPI suchen.
  echo "Installiere common/ (dk9mbs-iot)"
  as_user "$OWNER" "$PYTHON" -m pip install --quiet -e "$ROOT_DIR/common"
  for req in "$APP_DIR/requirements.txt" "$ROOT_DIR"/agents/*/requirements.txt; do
    [ -f "$req" ] || continue
    echo "Installiere ${req#"$ROOT_DIR"/}"
    as_user "$OWNER" "$PYTHON" -m pip install --quiet -r "$req"
  done
  [ "$MODE" = deps ] && { echo "Pakete installiert in $VENV"; exit 0; }
fi

render_unit() {  # $1 = Dienstname; Kopfkommentar der Vorlage entfernen
  sed -e "s|@APP_DIR@|$APP_DIR|g" \
      -e "s|@ROOT_DIR@|$ROOT_DIR|g" \
      -e "s|@PYTHON@|$PYTHON|g" \
      -e "s|@USER@|$RUN_USER|g" \
      -e '1,/^\[Unit\]/{/^\[Unit\]/!d}' "$INSTALL_DIR/$1.service.skelet"
}

for svc in "${SERVICES[@]}"; do
  if [ "$MODE" = print ]; then
    echo "# --- $UNIT_DIR/$svc.service"
    render_unit "$svc"
    echo
    continue
  fi

  case "$svc" in
    iot-dashboard)
      "$PYTHON" -c "import flask, requests, dotenv" 2>/dev/null \
        || fail "im venv $VENV fehlen Pakete fuer das Dashboard"
      [ -f "$APP_DIR/.env" ] || echo "Warnung: $APP_DIR/.env fehlt (Vorlage: .env.skelet)" >&2
      ;;
    iot-agents)
      [ -f "$ROOT_DIR/agents/agents.json" ] \
        || echo "Warnung: agents/agents.json fehlt (Vorlage: agents.json.skelet)" >&2
      if crontab -l -u "$RUN_USER" 2>/dev/null | grep -q "run_agents.py"; then
        echo "Warnung: crontab von $RUN_USER startet run_agents.py noch - Eintrag entfernen (crontab -e -u $RUN_USER)" >&2
      fi
      [ "$RUN_USER" = root ] || echo "Warnung: Agenten laufen als $RUN_USER - nmap liefert ohne root keine MAC-Adressen/Hersteller (dafuer --user root)" >&2
      # Laufzeit- und Einstellungsdateien dem Dienst-Benutzer geben, damit ein
      # frueherer Lauf als anderer Benutzer (z.B. root) den Dienst nicht aussperrt
      mkdir -p "$ROOT_DIR/agents/logs"
      chown -R "$RUN_USER:" "$ROOT_DIR/agents/logs"
      for f in "$ROOT_DIR"/agents/agents.json "$ROOT_DIR"/agents/*/config.env "$ROOT_DIR"/agents/*/config.json \
               "$ROOT_DIR"/agents/*/known_macs.json "$ROOT_DIR"/agents/*/vendor_cache.json \
               "$ROOT_DIR"/agents/*/device_status_state.json; do
        [ -e "$f" ] && chown "$RUN_USER:" "$f"
      done
      echo "Laufzeit- und Einstellungsdateien der Agenten gehoeren jetzt $RUN_USER"
      ;;
  esac

  render_unit "$svc" > "$UNIT_DIR/$svc.service"
  echo "Unit geschrieben: $UNIT_DIR/$svc.service (Benutzer $RUN_USER, Python $PYTHON)"
done

[ "$MODE" = print ] && exit 0

systemctl daemon-reload
for svc in "${SERVICES[@]}"; do
  systemctl enable "$svc"
  systemctl restart "$svc"
done
sleep 2
for svc in "${SERVICES[@]}"; do
  systemctl --no-pager --lines=5 status "$svc" || true
  echo
done
echo "Logs:    journalctl -u <dienst> -f    (Dienste: ${SERVICES[*]})"
echo "Stoppen: systemctl stop <dienst>"
