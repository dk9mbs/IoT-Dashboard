#!/usr/bin/env python3
"""
shelly_syslog.py - Agent für den Runner (agents/run_agents.py): wertet die
Syslogs der Shellys aus und meldet, ob fremde IP-Adressen auf die Shellys
zugreifen. Die Auswertung der Logs steckt in shelly_access_report.py
(eigenständig nutzbar, nur Standardbibliothek).

Aufruf:
    python3 shelly_syslog.py [--config settings.json] [--pretty]

Die Einstellungen kommen zentral aus iot_agent_config.settings und werden vom
Runner als IOT_AGENT_SETTINGS mitgegeben (Vorlage: settings.json.skelet);
--config liest sie stattdessen aus einer Datei.

Fremd ist eine IP, die nicht mit Status 'active' in iot_device steht und auch
nicht unter "allowed_ips" der Einstellungen (einzelne IPs oder Netze wie
"35.205.0.0/16", z. B. für die Shelly Cloud). Zugriffe ohne IP (MQTT,
Skripte auf dem Shelly selbst) zählen nicht.

Ausgabetyp 2 (Add Sensor Value): eine Kennzahl als JSON {"data": [...]} auf
stdout, der Runner schreibt sie nach iot_sensor_data:
    <sensor_prefix>_foreign_ips   Anzahl verschiedener fremder IPs im Zeitfenster
                                  (0 = alles in Ordnung)
Der Sensor muss vorher in iot_sensor angelegt sein; mit max_value 0 meldet
watchdog jeden Wert ab 1. Zusätzlich kommt je fremder IP eine Benachrichtigung
als "notify" (nur beim ersten Auftreten; erneut erst, wenn die IP
baseline_days lang nicht mehr zugegriffen hat). "message" und "notify" sind
deutsch, der vollständige Bericht (englisch, alle Zugriffe mit Score) steht im
Log (stderr).

Die IP der Shellys selbst (Ziel) kommt aus iot_device (id bzw. host_name =
Hostname im Log).

Bei --dry-run des Runners (IOT_DRY_RUN) werden Historie und
Benachrichtigungs-Zustand nicht gespeichert.
"""

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

from dk9mbs_iot.agent import dry_run_from_env, log, rest_from_env, settings_from_env, write_output  # vom Agenten-Runner
from dk9mbs_iot.query.device import IotDeviceClient

from shelly_access_report import (AccessReport, AnomalyScorer, HistoryStore, PatternDescriber, RpcParser,
                                  ScoringConfig, ShellyAccessAnalyzer, StaticKnownDeviceProvider)

AGENT_DIR = Path(__file__).resolve().parent

# Nur Geräte mit diesem Status zählen als bekannt (iot_device_status.id)
KNOWN_DEVICE_STATUS = "active"

# Höchstens so viele Aktionen je fremder IP in der Meldung
MAX_ACTIONS_IN_TEXT = 3

DEFAULTS = {
    "log_dir": "/var/log/shelly",
    "window_minutes": 60,
    "namespace": "shelly.syslog",
    "sensor_prefix": "shelly_syslog",
    "allowed_ips": [],
    "notify": {"enabled": True, "max_per_run": 10},
    "state_file": "notify_state.json",
}


def value(row: dict, field: str):
    """Feldwert einer REST-Zeile (auch Antworten mit Formatter: {"value": ...})."""
    v = row.get(field)
    if isinstance(v, dict):
        v = v.get("value", v.get("formatted_value"))
    return v


def parse_ip(address):
    """IP-Objekt oder None (z. B. für leere oder ungültige Adressen)."""
    try:
        return ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None


def allowed_networks(entries: list) -> list:
    """'allowed_ips' als Netze; einzelne IPs werden zu /32 bzw. /128."""
    networks = []
    for entry in entries or []:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError as exc:
            raise RuntimeError(f"invalid entry in allowed_ips: {entry!r}") from exc
    return networks


# --------------------------------------------------------------------------
# Geräte aus iot_device
# --------------------------------------------------------------------------

def known_devices(client: IotDeviceClient) -> list:
    """Bekannte Geräte aus iot_device (nur Status 'active'), Name = host_name."""
    devices = []
    for row in client.fetch_all_devices(status_id=KNOWN_DEVICE_STATUS):
        address = value(row, "address")
        if address:
            name = value(row, "host_name") or value(row, "name") or value(row, "id")
            devices.append({"address": address, "name": name})
    return devices


def shelly_addresses(client: IotDeviceClient) -> dict:
    """Hostname des Shellys (wie im Log) -> IP aus iot_device (id und host_name)."""
    addresses = {}
    for row in client.fetch_all_shelly_devices():
        address = value(row, "address")
        if not address:
            continue
        for field in ("id", "host_name"):
            if value(row, field):
                addresses[str(value(row, field)).lower()] = address
    return addresses


# --------------------------------------------------------------------------
# Fremde IPs, Kennzahl und Benachrichtigungen
# --------------------------------------------------------------------------

def foreign_ips(access_rows: list, known: set, allowed: list) -> dict:
    """
    Zugriffe fremder IPs, je IP zusammengefasst:
    {ip: {"targets": {host: anzahl}, "actions": {methode: anzahl}, "channels": set, "last": iso}}
    """
    result = {}
    for a in access_rows:
        source = a["source"]
        if source.get("type") != "IP":
            continue
        ip = parse_ip(source.get("address"))
        if ip is None or ip in known or any(ip in net for net in allowed):
            continue
        entry = result.setdefault(str(ip), {"targets": {}, "actions": {}, "channels": set(), "last": ""})
        host = a["target"]["host"]
        entry["targets"][host] = entry["targets"].get(host, 0) + a["count"]
        entry["actions"][a["action"]] = entry["actions"].get(a["action"], 0) + a["count"]
        entry["channels"].add(a["channel"])
        entry["last"] = max(entry["last"], a["period"]["to"] or "")
    return result


class NotificationState:
    """Merkt sich je gemeldeter fremder IP den Zeitpunkt des letzten Zugriffs."""

    def __init__(self, path: Path, keep_days: int = 7):
        self.path = path
        self.keep_days = keep_days
        self.notified = {}
        if path.exists():
            try:
                self.notified = json.loads(path.read_text(encoding="utf-8")).get("notified", {})
            except (ValueError, OSError):
                self.notified = {}

    def is_new(self, key: str) -> bool:
        return key not in self.notified

    def mark(self, key: str, last_access: str) -> None:
        self.notified[key] = max(self.notified.get(key) or "", last_access or "")

    def save(self) -> None:
        # IPs, die keep_days lang nicht mehr zugegriffen haben, werden wieder gemeldet
        limit = (datetime.now().astimezone() - timedelta(days=self.keep_days)).isoformat()
        self.notified = {k: v for k, v in self.notified.items() if v and v >= limit}
        self.path.write_text(json.dumps({"notified": self.notified}, indent=1), encoding="utf-8")


def foreign_ip_text(ip: str, entry: dict) -> str:
    targets = ", ".join(f"{host} ({count}×)" for host, count in
                        sorted(entry["targets"].items(), key=lambda t: -t[1]))
    actions = sorted(entry["actions"], key=lambda m: -entry["actions"][m])
    action_text = ", ".join(actions[:MAX_ACTIONS_IN_TEXT]) + (", …" if len(actions) > MAX_ACTIONS_IN_TEXT else "")
    return (f"Fremde IP {ip} greift auf Shellys zu: {targets} - {action_text} "
            f"über {', '.join(sorted(entry['channels']))}")


def notification_texts(foreign: dict, state: NotificationState, max_per_run: int) -> list:
    """Texte (deutsch) für erstmals gesehene fremde IPs; aktualisiert den Zustand."""
    texts, skipped = [], 0
    for ip, entry in sorted(foreign.items()):
        new = state.is_new(ip)
        state.mark(ip, entry["last"])
        if not new:
            continue
        if len(texts) >= max_per_run:
            skipped += 1
            continue
        texts.append(foreign_ip_text(ip, entry))
    if skipped:
        texts.append(f"Shelly-Syslog: {skipped} weitere fremde IP(s), siehe Agenten-Log")
    return texts


# --------------------------------------------------------------------------
# Ablauf
# --------------------------------------------------------------------------

def load_settings(config_file):
    """Einstellungen + Basisordner für relative Pfade."""
    if config_file:
        path = Path(config_file).resolve()
        return json.loads(path.read_text(encoding="utf-8")), path.parent
    settings = settings_from_env()  # zentral aus iot_agent_config.settings, vom Runner mitgegeben
    if not settings:
        raise RuntimeError("no settings - start via run_agents.py or use --config")
    return settings, AGENT_DIR


def run(settings: dict, base_dir: Path, rest: dict, dry_run: bool) -> tuple:
    """Rückgabe: (Bericht als Dict, Einträge für den Runner, Meldung, Benachrichtigungen)."""
    settings = {**DEFAULTS, **settings, "notify": {**DEFAULTS["notify"], **settings.get("notify", {})}}
    log_dir = Path(settings["log_dir"])
    if not log_dir.is_absolute():
        log_dir = base_dir / log_dir
    if not log_dir.is_dir():
        raise RuntimeError(f"log directory {log_dir} not found")
    allowed = allowed_networks(settings["allowed_ips"])

    config = ScoringConfig.from_dict(settings, base_dir)
    window = timedelta(minutes=int(settings["window_minutes"]))
    since = datetime.now().astimezone() - window

    client = IotDeviceClient(apikey=rest["apikey"], base_url=rest["base_url"])
    devices = known_devices(client)
    known = {ip for ip in (parse_ip(d["address"]) for d in devices) if ip is not None}

    history = None
    if config.history_enabled:
        history = HistoryStore(config.history_file or base_dir / "shelly_access_history.json",
                               config.baseline_days)

    describer = PatternDescriber()
    scorer = AnomalyScorer(config, StaticKnownDeviceProvider(devices), history, describer)
    parser = RpcParser(host_addresses=shelly_addresses(client))
    analyzer = ShellyAccessAnalyzer(parser=parser, since=since).add_directory(log_dir)
    report = AccessReport(analyzer.groups(), analyzer.files, log_dir, describer, scorer,
                          sort_by_score=True, window_hours=window.total_seconds() / 3600)
    data = report.to_dict()

    foreign = foreign_ips(report.accesses(), known, allowed)
    for ip, entry in sorted(foreign.items()):
        log(foreign_ip_text(ip, entry))

    notify = []
    state = None
    if settings["notify"].get("enabled"):
        state_file = Path(settings["state_file"])
        state = NotificationState(state_file if state_file.is_absolute() else base_dir / state_file,
                                  config.baseline_days)
        notify = notification_texts(foreign, state, int(settings["notify"]["max_per_run"]))

    if not dry_run:
        report.update_history()
        if state:
            state.save()

    items = [{"id": f"{settings['sensor_prefix']}_foreign_ips", "value": len(foreign),
              "namespace": settings["namespace"]}]
    s = data["summary"]
    # Kurzmeldung für iot_agent_status (deutsch wie bei den anderen Agenten)
    message = (f"{len(foreign)} fremde IP(s), {s['total_accesses']} Zugriffe auf "
               f"{len(s['targets'])} Shelly(s) in {settings['window_minutes']} min")
    return data, items, message, notify


def main() -> int:
    ap = argparse.ArgumentParser(description="Shelly syslog access report as runner agent")
    ap.add_argument("--config", default=None,
                    help="read settings from this JSON file instead of the runner (IOT_AGENT_SETTINGS)")
    ap.add_argument("--pretty", action="store_true", help="indent the full report in the log")
    args = ap.parse_args()

    try:
        settings, base_dir = load_settings(args.config)
        rest = rest_from_env()  # REST-Zugang vom Runner: bekannte Geräte aus iot_device
        data, items, message, notify = run(settings, base_dir, rest, dry_run_from_env())
    except Exception as exc:  # noqa: BLE001
        log(json.dumps({"error": str(exc)}))
        return 1

    log(json.dumps(data, ensure_ascii=False, indent=2 if args.pretty else None))
    write_output(items, message, notify)
    return 0


if __name__ == "__main__":
    sys.exit(main())
