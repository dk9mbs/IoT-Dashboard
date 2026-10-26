#!/usr/bin/env python3
"""
shelly_syslog.py - Agent für den Runner (agents/run_agents.py): wertet die
Syslogs der Shellys aus (wer hat zugegriffen?) und bewertet jede Zugriffsgruppe
mit einem Auffälligkeits-Score. Die Auswertung selbst steckt in
shelly_access_report.py (eigenständig nutzbar, nur Standardbibliothek).

Aufruf:
    python3 shelly_syslog.py [--config settings.json] [--pretty]

Die Einstellungen kommen zentral aus iot_agent_config.settings und werden vom
Runner als IOT_AGENT_SETTINGS mitgegeben (Vorlage: settings.json.skelet);
--config liest sie stattdessen aus einer Datei.

Ausgabetyp 2 (Add Sensor Value): die Kennzahlen gehen als JSON {"data": [...]}
auf stdout (sensor_id = <sensor_prefix>_<kennzahl>, Namespace aus den
Einstellungen); der Runner schreibt sie nach iot_sensor_data. Die Sensoren
müssen vorher in iot_sensor angelegt sein. Auffällige Zugriffe kommen als
"notify" mit (je Zugriffsgruppe nur einmal, bis neue Zugriffe dazukommen).
"message" und "notify" sind deutsch (wie bei den anderen Agenten), der
Bericht im Log ist englisch (Ausgabeformat des Kernmoduls).
Der vollständige Bericht (alle Zugriffe mit Score) steht im Log (stderr).

Bekannte Geräte: alle Geräte aus iot_device mit Status 'active' (Name =
host_name), dazu "known_devices" aus den Einstellungen (z. B. MQTT-Clients
wie ioBroker, die nicht in iot_device stehen). Die IP der Shellys selbst
(Ziel) kommt ebenfalls aus iot_device (id bzw. host_name = Hostname im Log).

Bei --dry-run des Runners (IOT_DRY_RUN) werden Historie und
Benachrichtigungs-Zustand nicht gespeichert.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from dk9mbs_iot.agent import dry_run_from_env, log, rest_from_env, settings_from_env, write_output  # vom Agenten-Runner
from dk9mbs_iot.query.device import IotDeviceClient

from shelly_access_report import (AccessReport, AnomalyScorer, CombinedKnownDeviceProvider, HistoryStore,
                                  KnownDeviceProvider, PatternDescriber, RpcParser, ScoringConfig,
                                  ShellyAccessAnalyzer, StaticKnownDeviceProvider)

AGENT_DIR = Path(__file__).resolve().parent

# Nur Geräte mit diesem Status zählen als bekannt (iot_device_status.id)
KNOWN_DEVICE_STATUS = "active"

DEFAULTS = {
    "log_dir": "/var/log/shelly",
    "window_minutes": 60,
    "namespace": "shelly.syslog",
    "sensor_prefix": "shelly_syslog",
    "per_target_metrics": False,
    "notify": {"enabled": True, "max_per_run": 10},
    "state_file": "notify_state.json",
}


def value(row: dict, field: str):
    """Feldwert einer REST-Zeile (auch Antworten mit Formatter: {"value": ...})."""
    v = row.get(field)
    if isinstance(v, dict):
        v = v.get("value", v.get("formatted_value"))
    return v


def sensor_part(text: str) -> str:
    """Teil einer Sensor-ID: 'shellypro2-aabbccddeeff' -> 'shellypro2_aabbccddeeff'."""
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_") or "unknown"


# --------------------------------------------------------------------------
# Geräte aus iot_device
# --------------------------------------------------------------------------

class RestKnownDeviceProvider(KnownDeviceProvider):
    """Bekannte Geräte aus iot_device (nur Status 'active'), Name = host_name."""

    def __init__(self, client: IotDeviceClient):
        super().__init__()
        self.client = client

    def load_devices(self) -> list:
        devices = []
        for row in self.client.fetch_all_devices(status_id=KNOWN_DEVICE_STATUS):
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
# Kennzahlen und Benachrichtigungen
# --------------------------------------------------------------------------

def metric_items(settings: dict, report: dict) -> list:
    """Kennzahlen als Einträge für den Runner (Ausgabetyp Add Sensor Value)."""
    prefix = settings["sensor_prefix"]
    namespace = settings["namespace"]
    accesses = report["accesses"]

    def sources(predicate) -> int:
        return len({json.dumps(a["source"], sort_keys=True) for a in accesses if predicate(a)})

    metrics = {
        "max_score": report["summary"]["max_score"],
        "suspicious": report["summary"]["suspicious_entries"],
        "accesses": report["summary"]["total_accesses"],
        "write_accesses": report["summary"]["write_accesses"],
        "sources": sources(lambda a: True),
        "unknown_sources": sources(lambda a: "unknown source" in a["anomaly"]["reasons"]),
        "external_sources": sources(lambda a: "external (public) address" in a["anomaly"]["reasons"]),
    }
    items = [{"id": f"{prefix}_{name}", "value": v, "namespace": namespace} for name, v in metrics.items()]

    if settings.get("per_target_metrics"):
        per_target = {}
        for a in accesses:
            t = per_target.setdefault(a["target"]["host"], {"max_score": 0, "accesses": 0})
            t["max_score"] = max(t["max_score"], a["anomaly"]["score"])
            t["accesses"] += a["count"]
        for host, values in sorted(per_target.items()):
            for name, v in values.items():
                items.append({"id": f"{prefix}_{sensor_part(host)}_{name}", "value": v, "namespace": namespace})
    return items


class NotificationState:
    """Merkt sich je Zugriffsgruppe den Zeitpunkt des zuletzt gemeldeten Zugriffs."""

    def __init__(self, path: Path, keep_days: int = 7):
        self.path = path
        self.keep_days = keep_days
        self.notified = {}
        if path.exists():
            try:
                self.notified = json.loads(path.read_text(encoding="utf-8")).get("notified", {})
            except (ValueError, OSError):
                self.notified = {}

    def is_new(self, key: str, last_access: str) -> bool:
        previous = self.notified.get(key)
        return previous is None or (last_access and last_access > previous)

    def mark(self, key: str, last_access: str) -> None:
        self.notified[key] = last_access

    def save(self) -> None:
        limit = (datetime.now().astimezone() - timedelta(days=self.keep_days)).isoformat()
        self.notified = {k: v for k, v in self.notified.items() if v and v >= limit}
        self.path.write_text(json.dumps({"notified": self.notified}, indent=1), encoding="utf-8")


# Begründungen des Kernmoduls (englisch) für Meldungen auf Deutsch
REASON_TRANSLATIONS = [
    (re.compile(r"^unknown source$"), "unbekannte Quelle"),
    (re.compile(r"^external \(public\) address$"), "öffentliche Adresse"),
    (re.compile(r"^write access$"), "schreibender Zugriff"),
    (re.compile(r"^sensitive action: (.+)$"), r"sensible Aktion \1"),
    (re.compile(r"^(\d+)× at night \((.+)\)$"), r"\1× nachts (\2)"),
    (re.compile(r"^irregular timing$"), "unregelmäßig"),
    (re.compile(r"^high rate: (\d+) calls/min$"), r"hohe Rate: \1 Aufrufe/min"),
    (re.compile(r"^internal call \(loopback\)$"), "interner Aufruf"),
    (re.compile(r"^read access by Shelly Cloud$"), "Lesezugriff der Shelly Cloud"),
    (re.compile(r"^new source \(not seen before\)$"), "neue Quelle"),
    (re.compile(r"^rate ([\d.]+)× higher than usual$"), r"Rate \1× höher als üblich"),
]


def reason_de(reason: str) -> str:
    for pattern, replacement in REASON_TRANSLATIONS:
        if pattern.match(reason):
            return pattern.sub(replacement, reason)
    return reason  # unbekannte Begründung unverändert lassen


def source_text(source: dict) -> str:
    label = source.get("address") or source.get("client_id") or source.get("transport") or source["type"]
    if source.get("type") == "MQTT":
        label = f"MQTT-Client {label}"
    return f"{label} ({source['name']})" if source.get("name") else label


def notification_texts(access_rows: list, state: NotificationState, max_per_run: int) -> list:
    """Texte (deutsch) für neue auffällige Zugriffe; markiert sie im Zustand."""
    texts, skipped = [], 0
    for a in access_rows:
        if not a["anomaly"]["suspicious"]:
            continue
        last = a["period"]["to"]
        if not state.is_new(a["_key"], last):
            continue
        state.mark(a["_key"], last)
        if len(texts) >= max_per_run:
            skipped += 1
            continue
        texts.append(
            f"Shelly {a['target']['host']}: auffälliger Zugriff von {source_text(a['source'])} - "
            f"{a['action']} {a['count']}× über {a['channel']} "
            f"(Score {a['anomaly']['score']}: {', '.join(reason_de(r) for r in a['anomaly']['reasons'])})")
    if skipped:
        texts.append(f"Shelly-Syslog: {skipped} weitere auffällige Zugriffsgruppe(n), siehe Agenten-Log")
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

    config = ScoringConfig.from_dict(settings, base_dir)
    window = timedelta(minutes=int(settings["window_minutes"]))
    since = datetime.now().astimezone() - window

    client = IotDeviceClient(apikey=rest["apikey"], base_url=rest["base_url"])
    providers = [RestKnownDeviceProvider(client)]
    if settings.get("known_devices"):
        providers.append(StaticKnownDeviceProvider(settings["known_devices"]))
    devices = CombinedKnownDeviceProvider(providers)

    history = None
    if config.history_enabled:
        history = HistoryStore(config.history_file or base_dir / "shelly_access_history.json",
                               config.baseline_days)

    describer = PatternDescriber()
    scorer = AnomalyScorer(config, devices, history, describer)
    parser = RpcParser(host_addresses=shelly_addresses(client))
    analyzer = ShellyAccessAnalyzer(parser=parser, since=since).add_directory(log_dir)
    groups = analyzer.groups()
    report = AccessReport(groups, analyzer.files, log_dir, describer, scorer,
                          sort_by_score=True, window_hours=window.total_seconds() / 3600)
    data = report.to_dict()

    notify = []
    state = None
    if settings["notify"].get("enabled"):
        state_file = Path(settings["state_file"])
        state = NotificationState(state_file if state_file.is_absolute() else base_dir / state_file,
                                  config.baseline_days)
        notify = notification_texts(report.accesses(), state, int(settings["notify"]["max_per_run"]))

    if not dry_run:
        report.update_history()
        if state:
            state.save()

    s = data["summary"]
    # Kurzmeldung für iot_agent_status (deutsch wie bei den anderen Agenten)
    message = (f"max. Score {s['max_score']}, {s['suspicious_entries']} auffällig, "
               f"{s['total_accesses']} Zugriffe auf {len(s['targets'])} Shelly(s) "
               f"in {settings['window_minutes']} min")
    return data, metric_items(settings, data), message, notify


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
