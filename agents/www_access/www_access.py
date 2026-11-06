#!/usr/bin/env python3
"""
www_access.py - Agent für den Runner (agents/run_agents.py): wertet das
Access-Log des Webservers (Apache, Format "combined", optional mit
vorangestelltem vhost wie bei "vhost_combined") aus und meldet auffällige
externe IP-Adressen.

Aufruf:
    python3 www_access.py [--config settings.json] [--pretty]

Die Einstellungen kommen zentral aus iot_agent_config.settings und werden vom
Runner als IOT_AGENT_SETTINGS mitgegeben (Vorlage: settings.json.skelet);
--config liest sie stattdessen aus einer Datei.

Bewertet werden nur externe IPs (keine privaten Netze, nicht in
"allowed_ips"). Eine IP ist auffällig, wenn im Zeitfenster mindestens eine
Regel greift:
    enumeration  ein Pfad wird mit vielen verschiedenen Zahlen-IDs abgerufen
                 (?documentid=1000104, /document/1000104), ab enum_min_values;
                 Anfragen bekannter Clients ("known_agents") zählen hier nicht
    rate         Spitze ab max_per_minute Anfragen pro Minute
    probe        ab probe_min Zugriffe auf typische Prüfpfade (/.env, /.git/ ...)
    errors       ab min_requests Anfragen und Anteil 4xx ab error_ratio
                 (z. B. Passwort-Raten mit 401)
Der User-Agent wird nur in der Meldung genannt, er ist keine eigene Regel.

Ausgabetyp 2 (Add Sensor Value): zwei Kennzahlen als JSON {"data": [...]}:
    <sensor_prefix>_suspicious_ips   Anzahl auffälliger IPs im Zeitfenster
                                     (0 = alles in Ordnung)
    <sensor_prefix>_max_rate         höchste Anfragen pro Minute einer
                                     einzelnen externen IP
Die Sensoren müssen vorher in iot_sensor angelegt sein. Je auffälliger IP
kommt eine Benachrichtigung als "notify" (nur beim ersten Auftreten; erneut
erst, wenn die IP renotify_days lang nicht mehr auffällig war). Der Bericht
(alle auffälligen IPs mit Details) steht im Log (stderr).

Bei --dry-run des Runners (IOT_DRY_RUN) wird der Benachrichtigungs-Zustand
nicht gespeichert. Benötigt nur die Python-Standardbibliothek.
"""

import argparse
import gzip
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from dk9mbs_iot.agent import dry_run_from_env, log, settings_from_env, write_output  # vom Agenten-Runner

AGENT_DIR = Path(__file__).resolve().parent

DEFAULTS = {
    "log_files": ["/var/log/apache2/access.log"],
    "window_minutes": 60,
    "namespace": "www.access",
    "sensor_prefix": "www_access",
    "allowed_ips": [],
    # User-Agents eigener Clients (Teiltext): zählen nicht für die Regel enumeration
    "known_agents": ["Nextcloud", "mirall"],
    "rules": {},
    "notify": {"enabled": True, "max_per_run": 10},
    "renotify_days": 7,
    "state_file": "notify_state.json",
}

DEFAULT_RULES = {
    "enum_min_values": 20,
    "max_per_minute": 120,
    "probe_min": 3,
    "probe_paths": ["/.env", "/.git/", "wp-login.php", "xmlrpc.php", "phpmyadmin",
                    "/cgi-bin/", "/vendor/phpunit", "/.aws/", "/actuator", "/boaform"],
    "min_requests": 20,
    "error_ratio": 0.5,
}

# Höchstens so viele Beispiele/User-Agents im Bericht bzw. in der Meldung
MAX_EXAMPLES = 3

# vhost (optional), IP, ident, user, [Zeit], "Anfrage", Status, Bytes, "Referer", "User-Agent"
LINE_RE = re.compile(
    r'^(?:\S+:\d+ )?(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) \S+(?: "(?:[^"\\]|\\.)*" "(?P<agent>(?:[^"\\]|\\.)*)")?')
TIME_RE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
NUMBER_RE = re.compile(r"^\d+$")


# --------------------------------------------------------------------------
# Log lesen
# --------------------------------------------------------------------------

def parse_time(text: str):
    """Apache-Zeit '06/Nov/2026:03:18:35 +0100' als datetime mit Zeitzone (ohne locale)."""
    m = TIME_RE.match(text)
    if not m or m.group(2) not in MONTHS:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    offset = timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
    return datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                    tzinfo=timezone(offset))


def log_files(patterns: list, base_dir: Path, since: datetime) -> list:
    """Logdateien samt rotierter Dateien (access.log.1, access.log.2.gz), ältere als since entfallen."""
    files = []
    for entry in patterns:
        path = Path(entry)
        if not path.is_absolute():
            path = base_dir / path
        for candidate in sorted(path.parent.glob(path.name + "*")):
            name = candidate.name[len(path.name):]
            if name and not re.fullmatch(r"\.\d+(\.gz)?|\.gz", name):
                continue
            try:
                mtime = datetime.fromtimestamp(candidate.stat().st_mtime, timezone.utc)
            except OSError:
                continue
            if candidate.is_file() and mtime >= since:
                files.append(candidate)
    if not files and not any(Path(p).exists() or (base_dir / p).exists() for p in patterns):
        raise RuntimeError(f"log file(s) not found: {', '.join(patterns)}")
    return files


def read_lines(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as file:
        yield from file


# --------------------------------------------------------------------------
# Auswertung je IP
# --------------------------------------------------------------------------

def networks(entries: list) -> list:
    """'allowed_ips' als Netze; einzelne IPs werden zu /32 bzw. /128."""
    result = []
    for entry in entries or []:
        try:
            result.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError as exc:
            raise RuntimeError(f"invalid entry in allowed_ips: {entry!r}") from exc
    return result


def is_external(address: str, allowed: list) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    return not any(ip in net for net in allowed)


def id_templates(target: str) -> list:
    """
    Zahlen-IDs einer URL als (Vorlage, Wert):
    '/a/getdoc.php?documentid=17&x=1' -> [('/a/getdoc.php?documentid=', 17), ('/a/getdoc.php?x=', 1)]
    '/doc/17/view'                     -> [('/doc/{n}/view', 17)]
    """
    parts = urlsplit(target)
    result = []
    segments = parts.path.split("/")
    for i, segment in enumerate(segments):
        if NUMBER_RE.match(segment):
            template = "/".join(segments[:i] + ["{n}"] + segments[i + 1:])
            result.append((template, int(segment)))
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        if NUMBER_RE.match(val):
            result.append((f"{parts.path}?{key}=", int(val)))
    return result


class IpStats:
    """Alle Anfragen einer IP im Zeitfenster."""

    def __init__(self, ip: str):
        self.ip = ip
        self.requests = 0
        self.per_minute = Counter()
        self.status = Counter()
        self.agents = Counter()
        self.ids = {}          # Vorlage -> {"values": set, "ok": Anzahl 2xx}
        self.probes = Counter()
        self.first = None
        self.last = None

    def add(self, when: datetime, target: str, status: int, agent: str, probe_paths: list,
            known_agent: bool = False) -> None:
        self.requests += 1
        self.per_minute[when.replace(second=0)] += 1
        self.status[status // 100 * 100] += 1
        self.agents[agent or "-"] += 1
        self.first = min(self.first or when, when)
        self.last = max(self.last or when, when)
        for template, number in ([] if known_agent else id_templates(target)):
            entry = self.ids.setdefault(template, {"values": set(), "ok": 0})
            entry["values"].add(number)
            entry["ok"] += 200 <= status < 300
        lower = target.lower()
        for probe in probe_paths:
            if probe.lower() in lower:
                self.probes[probe] += 1

    @property
    def peak_per_minute(self) -> int:
        return max(self.per_minute.values(), default=0)

    @property
    def error_share(self) -> float:
        return self.status[400] / self.requests if self.requests else 0.0

    def enumerations(self, min_values: int) -> list:
        found = []
        for template, entry in self.ids.items():
            values = entry["values"]
            if len(values) >= min_values:
                found.append({"template": template, "values": len(values), "min": min(values),
                              "max": max(values), "ok": entry["ok"]})
        return sorted(found, key=lambda e: -e["values"])

    def reasons(self, rules: dict) -> list:
        """Gegriffene Regeln als Liste von (Regel, Details)."""
        reasons = []
        enums = self.enumerations(int(rules["enum_min_values"]))
        if enums:
            reasons.append(("enumeration", enums))
        if self.peak_per_minute >= int(rules["max_per_minute"]):
            reasons.append(("rate", self.peak_per_minute))
        if sum(self.probes.values()) >= int(rules["probe_min"]):
            reasons.append(("probe", dict(self.probes)))
        if self.requests >= int(rules["min_requests"]) and self.error_share >= float(rules["error_ratio"]):
            reasons.append(("errors", round(self.error_share, 2)))
        return reasons

    def to_dict(self, reasons: list) -> dict:
        return {
            "ip": self.ip,
            "requests": self.requests,
            "peak_per_minute": self.peak_per_minute,
            "status": {f"{k // 100}xx": v for k, v in sorted(self.status.items())},
            "user_agents": [a for a, _ in self.agents.most_common(MAX_EXAMPLES)],
            "first": self.first.isoformat() if self.first else None,
            "last": self.last.isoformat() if self.last else None,
            "reasons": {name: detail for name, detail in reasons},
        }


def analyse(files: list, since: datetime, allowed: list, rules: dict, known_agents: list) -> tuple:
    """Rückgabe: ({ip: IpStats} externer IPs, Anzahl gelesener Zeilen, Anzahl unlesbarer Zeilen)."""
    stats, lines, invalid = {}, 0, 0
    for path in files:
        for line in read_lines(path):
            m = LINE_RE.match(line)
            if not m:
                invalid += bool(line.strip())
                continue
            when = parse_time(m.group("time"))
            if when is None:
                invalid += 1
                continue
            if when < since:
                continue
            lines += 1
            ip = m.group("ip")
            if not is_external(ip, allowed):
                continue
            request = m.group("request").split(" ")
            target = request[1] if len(request) > 1 else request[0]
            agent = m.group("agent") or ""
            entry = stats.get(ip) or stats.setdefault(ip, IpStats(ip))
            entry.add(when, target, int(m.group("status")), agent, rules["probe_paths"],
                      any(k.lower() in agent.lower() for k in known_agents))
    return stats, lines, invalid


# --------------------------------------------------------------------------
# Benachrichtigungen
# --------------------------------------------------------------------------

class NotificationState:
    """Merkt sich je gemeldeter IP den Zeitpunkt der letzten auffälligen Anfrage."""

    def __init__(self, path: Path, keep_days: int):
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

    def mark(self, key: str, last: str) -> None:
        # als datetime vergleichen: die Zeitstempel können verschiedene Offsets haben (Sommerzeit)
        old = self.notified.get(key)
        if not old or (last and datetime.fromisoformat(last) > datetime.fromisoformat(old)):
            self.notified[key] = last

    def save(self) -> None:
        # IPs, die keep_days lang nicht mehr auffällig waren, werden wieder gemeldet
        limit = datetime.now(timezone.utc) - timedelta(days=self.keep_days)
        self.notified = {k: v for k, v in self.notified.items()
                         if v and datetime.fromisoformat(v) >= limit}
        self.path.write_text(json.dumps({"notified": self.notified}, indent=1), encoding="utf-8")


def reason_text(name: str, detail) -> str:
    if name == "enumeration":
        e = detail[0]
        more = f" (+{len(detail) - 1} weitere)" if len(detail) > 1 else ""
        return (f"Enumeration {e['template']} ({e['values']} IDs {e['min']}–{e['max']}, "
                f"{e['ok']}× 2xx){more}")
    if name == "rate":
        return f"{detail}/min"
    if name == "probe":
        return "Prüfpfade " + ", ".join(sorted(detail)[:MAX_EXAMPLES])
    if name == "errors":
        return f"{round(detail * 100)} % 4xx"
    return name


def suspicious_text(report: dict) -> str:
    reasons = "; ".join(reason_text(n, d) for n, d in report["reasons"].items())
    agent = report["user_agents"][0] if report["user_agents"] else "-"
    return (f"Webserver: auffällige IP {report['ip']} – {reasons}; "
            f"{report['requests']} Anfragen, UA {agent}")


def notification_texts(suspicious: list, state: NotificationState, max_per_run: int) -> list:
    """Texte (deutsch) für erstmals auffällige IPs; aktualisiert den Zustand."""
    texts, skipped = [], 0
    for report in suspicious:
        new = state.is_new(report["ip"])
        state.mark(report["ip"], report["last"])
        if not new:
            continue
        if len(texts) >= max_per_run:
            skipped += 1
            continue
        texts.append(suspicious_text(report))
    if skipped:
        texts.append(f"Webserver: {skipped} weitere auffällige IP(s), siehe Agenten-Log")
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


def run(settings: dict, base_dir: Path, dry_run: bool, now: datetime = None) -> tuple:
    """Rückgabe: (Bericht als Dict, Einträge für den Runner, Meldung, Benachrichtigungen)."""
    settings = {**DEFAULTS, **settings, "notify": {**DEFAULTS["notify"], **settings.get("notify", {})}}
    rules = {**DEFAULT_RULES, **settings["rules"]}
    allowed = networks(settings["allowed_ips"])
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(minutes=int(settings["window_minutes"]))

    files = log_files(settings["log_files"], base_dir, since)
    stats, lines, invalid = analyse(files, since, allowed, rules, settings["known_agents"])

    suspicious = []
    for entry in stats.values():
        reasons = entry.reasons(rules)
        if reasons:
            suspicious.append(entry.to_dict(reasons))
    suspicious.sort(key=lambda r: -r["requests"])
    max_rate = max((s.peak_per_minute for s in stats.values()), default=0)

    for report in suspicious:
        log(suspicious_text(report))

    notify, state = [], None
    if settings["notify"].get("enabled"):
        state_file = Path(settings["state_file"])
        state = NotificationState(state_file if state_file.is_absolute() else base_dir / state_file,
                                  int(settings["renotify_days"]))
        notify = notification_texts(suspicious, state, int(settings["notify"]["max_per_run"]))
    if state and not dry_run:
        state.save()

    prefix, namespace = settings["sensor_prefix"], settings["namespace"]
    items = [
        {"id": f"{prefix}_suspicious_ips", "value": len(suspicious), "namespace": namespace},
        {"id": f"{prefix}_max_rate", "value": max_rate, "namespace": namespace},
    ]
    data = {
        "created": now.isoformat(),
        "window_minutes": int(settings["window_minutes"]),
        "files": [str(f) for f in files],
        "lines": lines,
        "invalid_lines": invalid,
        "external_ips": len(stats),
        "max_rate": max_rate,
        "suspicious": suspicious,
    }
    # Kurzmeldung für iot_agent_status
    message = (f"{len(suspicious)} auffällige IP(s), {len(stats)} externe IPs, "
               f"{lines} Anfragen in {settings['window_minutes']} min")
    if invalid:
        message += f", {invalid} Zeilen unlesbar"
    return data, items, message, notify


def main() -> int:
    ap = argparse.ArgumentParser(description="Web server access log analysis as runner agent")
    ap.add_argument("--config", default=None,
                    help="read settings from this JSON file instead of the runner (IOT_AGENT_SETTINGS)")
    ap.add_argument("--pretty", action="store_true", help="indent the full report in the log")
    args = ap.parse_args()

    try:
        settings, base_dir = load_settings(args.config)
        data, items, message, notify = run(settings, base_dir, dry_run_from_env())
    except Exception as exc:  # noqa: BLE001
        log(json.dumps({"error": str(exc)}))
        return 1

    log(json.dumps(data, ensure_ascii=False, indent=2 if args.pretty else None))
    write_output(items, message, notify)
    return 0


if __name__ == "__main__":
    sys.exit(main())
