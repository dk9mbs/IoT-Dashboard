#!/usr/bin/env python3
"""
shelly_access_report.py

Liest alle Logdateien eines Verzeichnisses (Standard: /var/log/shelly),
wertet die RPC-Zugriffe der Shelly-Geräte aus (Zeilen von shos_rpc_inst.c)
und gibt ein JSON aus, das zeigt, wer auf welchen Shelly zugegriffen hat.

Ausgewertet werden *.log sowie rotierte Dateien (*.log.1, *.log.2.gz, *.log.gz).

Pro Kombination aus Quelle, Ziel, Aktion und Kanal entsteht ein Objekt mit:
  source, target, action, count, period, pattern, access_type, channel,
  rate_per_hour, peak_per_minute, anomaly (score 0–100, suspicious, reasons)

Bewertung:
  shelly_access_config.json  Gewichte, Schwellwert, Nachtzeit, sensible Aktionen, Historie
  known_devices.json         bekannte Geräte (später ersetzbar durch einen REST-Server,
                             dazu eine Unterklasse von KnownDeviceProvider schreiben)
  shelly_access_history.json wird automatisch geführt (Vergleich mit früheren Läufen)

Aufruf:
  python3 shelly_access_report.py                       # JSON auf stdout
  python3 shelly_access_report.py -d /var/log/shelly -o report.json
  python3 shelly_access_report.py --write-only

Wiederverwendung als Modul:
  from shelly_access_report import ShellyAccessAnalyzer, AccessReport
  analyzer = ShellyAccessAnalyzer().add_directory("/var/log/shelly")
  report = AccessReport(analyzer.groups(), analyzer.files)
  print(report.to_json())

Bausteine:
  ShellyLogReader      liest Logdateien (auch .gz) und liefert einzelne Einträge (LogRecord)
  RpcParser            erkennt RPC-Aufrufe in Einträgen und erzeugt RpcAccess-Objekte
  TransportParser      zerlegt den "via ..."-Teil in Kanal und Quelle (IP oder MQTT)
  PatternDescriber     beschreibt das zeitliche Muster einer Zugriffsreihe
  ScoringConfig        Einstellungen für Score und Historie
  KnownDeviceProvider  Liste bekannter Geräte (JsonKnownDeviceProvider liest sie aus JSON)
  HistoryStore         speichert Raten und Quellen früherer Läufe
  AnomalyScorer        berechnet den Auffälligkeits-Score mit Begründungen
  ShellyAccessAnalyzer gruppiert Zugriffe nach Quelle, Ziel, Aktion und Kanal
  AccessReport         baut Zusammenfassung und JSON

Benötigt nur die Python-Standardbibliothek (ab Python 3.9).
"""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import re
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional


# ---------------------------------------------------------------------------
# Datenobjekte
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogRecord:
    """Ein einzelner Shelly-Logeintrag (eine Zeile kann mehrere enthalten)."""
    timestamp: Optional[datetime]
    host: str
    source_file: str      # z. B. "shos_rpc_inst.c"
    message: str
    log_file: Path


@dataclass(frozen=True)
class Source:
    """Wer hat zugegriffen: IP-Adresse oder MQTT-Client."""
    kind: str                         # "IP", "MQTT", "internal" oder "unknown"
    address: Optional[str] = None
    interface: Optional[str] = None
    client_id: Optional[str] = None
    transport: Optional[str] = None
    rpc_source: Optional[str] = None
    hint: Optional[str] = None

    def to_dict(self) -> dict:
        if self.kind == "MQTT":
            return {"type": "MQTT", "client_id": self.client_id,
                    "transport": self.transport, "hint": self.hint}
        if self.kind != "IP":
            d = {"type": self.kind, "address": None, "transport": self.transport}
            if self.rpc_source:
                d["rpc_source"] = self.rpc_source
            if self.hint:
                d["hint"] = self.hint
            return d
        d = {"type": self.kind, "address": self.address}
        if self.interface:
            d["interface"] = self.interface
        if self.rpc_source:
            d["rpc_source"] = self.rpc_source
        return d

    @property
    def label(self) -> str:
        if self.kind == "MQTT":
            return f"MQTT:{self.client_id}"
        if self.kind == "internal":
            return "internal (loopback)"
        if self.kind == "unknown":
            return f"unknown ({self.transport})"
        return self.address


@dataclass(frozen=True)
class Target:
    """Auf welchen Shelly wurde zugegriffen."""
    host: str
    address: Optional[str] = None

    def to_dict(self) -> dict:
        return {"host": self.host, "address": self.address}


@dataclass(frozen=True)
class RpcAccess:
    """Ein einzelner RPC-Zugriff."""
    timestamp: Optional[datetime]
    source: Source
    target: Target
    method: str
    channel: str
    log_file: str

    @property
    def access_type(self) -> str:
        return RpcParser.access_type(self.method)


@dataclass
class AccessGroup:
    """Alle Zugriffe mit gleicher Quelle, Ziel, Aktion und Kanal."""
    source: Source
    target: Target
    method: str
    channel: str
    times: list = field(default_factory=list)
    files: set = field(default_factory=set)

    def add(self, access: RpcAccess) -> None:
        self.times.append(access.timestamp)
        self.files.add(access.log_file)

    @property
    def count(self) -> int:
        return len(self.times)

    @property
    def access_type(self) -> str:
        return RpcParser.access_type(self.method)

    @property
    def key(self) -> str:
        """Eindeutiger Schlüssel der Gruppe (u. a. für die Historie)."""
        return f"{self.source.label}|{self.target.host}|{self.method.lower()}|{self.channel}"

    def valid_times(self) -> list:
        return sorted(t for t in self.times if t is not None)

    def to_dict(self, describer: "PatternDescriber") -> dict:
        times = self.valid_times()
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "action": self.method,
            "count": self.count,
            "period": {
                "from": times[0].isoformat() if times else None,
                "to": times[-1].isoformat() if times else None,
            },
            "pattern": describer.describe(self.times),
            "access_type": self.access_type,
            "channel": self.channel,
            "files": sorted(self.files),
        }


# ---------------------------------------------------------------------------
# Lesen der Logdateien
# ---------------------------------------------------------------------------

class ShellyLogReader:
    """Liest Shelly-Syslogs (auch rotiert/gzip) und liefert einzelne LogRecord-Objekte."""

    # *.log, *.log.1, *.log.2.gz, *.log.gz
    RE_LOG_FILE = re.compile(r"\.log(?:\.\d+)?(?:\.gz)?$")
    # Zeitstempel am Zeilenanfang (RFC 5424 / ISO 8601)
    RE_TS = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+")
    # <host> <seq> <uptime> <lvl> <x>|<quelldatei>:<zeile> <nachricht>
    RE_RECORD = re.compile(
        r"(?P<host>\S+)\s+\d+\s+[\d.]+\s+\d+\s+\d+\|(?P<srcfile>[^\s:|]+):\d+\s+(?P<msg>.*)$"
    )
    # Einträge, die rsyslog in einer Zeile zusammengefasst hat
    RE_SPLIT = re.compile(r"#000|\x00")

    def __init__(self, encoding: str = "utf-8"):
        self.encoding = encoding

    def files(self, directory) -> list:
        return sorted(p for p in Path(directory).iterdir()
                      if p.is_file() and self.RE_LOG_FILE.search(p.name))

    def open(self, path: Path):
        if path.suffix == ".gz":
            return gzip.open(path, "rt", encoding=self.encoding, errors="replace")
        return path.open("r", encoding=self.encoding, errors="replace")

    def read_file(self, path: Path) -> Iterator[LogRecord]:
        with self.open(path) as fh:
            for line in fh:
                yield from self.parse_line(line.rstrip("\n"), path)

    def parse_line(self, line: str, path: Path) -> Iterator[LogRecord]:
        if not line.strip():
            return
        m_ts = self.RE_TS.match(line)
        ts = self.parse_timestamp(m_ts.group(1)) if m_ts else None
        body = line[m_ts.end():] if m_ts else line
        for part in self.RE_SPLIT.split(body):
            rec = self.RE_RECORD.search(part.strip())
            if rec:
                yield LogRecord(ts, rec.group("host"), rec.group("srcfile"), rec.group("msg"), path)

    @staticmethod
    def parse_timestamp(text: str) -> Optional[datetime]:
        """ISO-Zeitstempel in ein datetime umwandeln (None, wenn nicht lesbar)."""
        if not text:
            return None
        t = text.replace("Z", "+00:00")
        t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)   # +0100 -> +01:00
        m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", t)
        if m:
            frac = m.group(2)[1:7].ljust(6, "0") if m.group(2) else ""
            t = m.group(1) + ("." + frac if frac else "") + m.group(3)
        try:
            return datetime.fromisoformat(t)
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Erkennen von RPC-Zugriffen
# ---------------------------------------------------------------------------

class TransportParser:
    """Zerlegt den Transport-Teil ("via ...") in Kanal und Quelle."""

    # Absender mit oder ohne "from" (Pro-Geräte: "GET from 1.2.3.4:5 via en0",
    # Plus-Geräte: "GET 1.2.3.4:5"), IPv4 oder IPv6 (auch [fe80::1%en0]:443)
    RE_ADDR = re.compile(
        r"(?:\bfrom\s+)?(?P<addr>(?:\d{1,3}\.){3}\d{1,3}"
        r"|\[[0-9a-fA-F:]+(?:%[^\]\s]+)?\]"
        r"|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F]*(?:%\S+)?)"
        r"(?::(?P<port>\d+))?(?:\s+via\s+(?P<iface>\S+))?"
    )
    MQTT_HINT = "Command was received via the MQTT broker; the sender IP is not in the Shelly log"
    INTERNAL_HINT = "Call on the device itself, e.g. Shelly.call() from a script"

    def parse(self, via: str, rpc_src: str) -> tuple:
        via = via.strip()
        words = via.split()
        head = words[0] if words else "unknown"
        head_up = head.upper()

        if head_up.startswith("MQTT"):
            return "MQTT", Source(kind="MQTT", client_id=rpc_src or None,
                                  transport=via, hint=self.MQTT_HINT)

        if head_up.startswith("LOOPBACK"):
            return "loopback", Source(kind="internal", transport=via,
                                      rpc_source=rpc_src or None, hint=self.INTERNAL_HINT)

        channel = self.channel_name(head_up, head, words)
        # nur hinter dem Kanalnamen nach der Adresse suchen
        m = self.RE_ADDR.search(via, len(head))
        rpc_source = None
        if rpc_src:
            # Web-Oberfläche meldet sich mit "web-<sessionid>"
            rpc_source = "web UI" if rpc_src.startswith("web-") else rpc_src
        if m:
            address = m.group("addr").strip("[]")
            return channel, Source(kind="IP", address=address,
                                   interface=m.group("iface"), rpc_source=rpc_source)
        # nichts erkannt: Original-Transporttext behalten, damit man es nachvollziehen kann
        return channel, Source(kind="unknown", transport=via, rpc_source=rpc_source)

    @staticmethod
    def channel_name(head_up: str, head: str, words: list) -> str:
        if head_up.startswith("HTTP"):
            verb = words[1] if len(words) > 1 and words[1].isalpha() else ""
            return f"HTTP {verb}".strip()
        if head_up.startswith("WS"):
            return "WebSocket"
        if head_up.startswith(("BLE", "GATT")):
            return "Bluetooth"
        if head_up.startswith("UDP"):
            return "UDP"
        if head_up == "SHC":
            return "Shelly Cloud"
        return head


class RpcParser:
    """Erkennt RPC-Aufrufe in LogRecords und erzeugt RpcAccess-Objekte."""

    RE_RPC = re.compile(
        r"^(?P<method>[A-Za-z0-9_]+\.[A-Za-z0-9_]+)\s+\[(?P<id>[^@\]]*)@(?P<rpcsrc>[^\]]*)\]\s+via\s+(?P<via>.*)$"
    )
    READ_PREFIXES = ("Get", "List", "Check", "Ping", "Echo")
    READ = "read"
    WRITE = "write"

    def __init__(self, transport_parser: Optional[TransportParser] = None,
                 host_addresses: Optional[dict] = None):
        self.transport = transport_parser or TransportParser()
        # Zuordnung Shelly-Hostname -> IP (z. B. aus iot_device), Schlüssel klein geschrieben
        self.host_addresses = {k.lower(): v for k, v in (host_addresses or {}).items() if v}

    def parse(self, record: LogRecord) -> Optional[RpcAccess]:
        if not record.source_file.startswith("shos_rpc_inst"):
            return None
        m = self.RE_RPC.match(record.message.strip())
        if not m:
            return None
        channel, source = self.transport.parse(m.group("via"), m.group("rpcsrc"))
        address = self.ip_from_filename(record.log_file) or self.host_addresses.get(record.host.lower())
        target = Target(host=record.host, address=address)
        return RpcAccess(record.timestamp, source, target,
                         self.normalize_method(m.group("method")), channel, record.log_file.name)

    @staticmethod
    def normalize_method(method: str) -> str:
        """'sys.SetConfig' -> 'Sys.SetConfig' (Shelly loggt die Komponente mal klein, mal groß)."""
        component, _, name = method.partition(".")
        return component[:1].upper() + component[1:] + "." + name

    @classmethod
    def access_type(cls, method: str) -> str:
        # Groß-/Kleinschreibung egal (Plus-Geräte loggen z. B. "sys.getconfig")
        name = method.partition(".")[2].lower()
        prefixes = tuple(p.lower() for p in cls.READ_PREFIXES)
        return cls.READ if name.startswith(prefixes) else cls.WRITE

    @staticmethod
    def ip_from_filename(path: Path) -> Optional[str]:
        """Liefert eine IP, wenn der Dateiname eine enthält (z. B. 192.168.0.50.log)."""
        for candidate in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", path.name):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
        return None


# ---------------------------------------------------------------------------
# Zeitliches Muster
# ---------------------------------------------------------------------------

class PatternDescriber:
    """Beschreibt das zeitliche Muster einer Reihe von Zeitstempeln."""

    def __init__(self, burst_gap_s: float = 2.0, min_regular_bursts: int = 4, tolerance: float = 0.25):
        self.burst_gap_s = burst_gap_s            # Abstand, unter dem Aufrufe als ein Block gelten
        self.min_regular_bursts = min_regular_bursts
        self.tolerance = tolerance                # erlaubte Abweichung vom Median-Intervall

    def describe(self, times: Iterable) -> str:
        times = list(times)
        missing = sum(1 for t in times if t is None)
        text = self._describe(sorted(t for t in times if t is not None))
        # Einträge ohne lesbaren Zeitstempel kenntlich machen
        if missing and text != "no timestamp":
            text += f" (+{missing} without timestamp)"
        return text

    def _describe(self, times: list) -> str:
        n = len(times)
        if n == 0:
            return "no timestamp"
        if n == 1:
            return f"once at {self.format_time(times[0])}"

        bursts = self.bursts(times)
        per_burst = statistics.median(len(b) for b in bursts)
        suffix = f", {int(per_burst)}× per request" if per_burst >= 2 else ""

        interval = self.regular_interval(bursts)
        if interval is not None:
            return f"regularly every ~{self.format_duration(interval)}{suffix}"
        if len(bursts) == 1:
            return f"{n}× in quick succession at {self.format_time(times[0])}"
        if len(bursts) <= 3:
            return f"{n}× at " + ", ".join(self.format_time(b[0]) for b in bursts)
        return (f"irregular, {n}× in {len(bursts)} bursts between "
                f"{self.format_time(times[0])} and {self.format_time(times[-1])}")

    def bursts(self, times: list) -> list:
        """Fasst dicht aufeinanderfolgende Aufrufe zu Blöcken zusammen."""
        result = [[times[0]]]
        for t in times[1:]:
            if (t - result[-1][-1]).total_seconds() < self.burst_gap_s:
                result[-1].append(t)
            else:
                result.append([t])
        return result

    def regular_interval(self, bursts: list) -> Optional[float]:
        """Median-Intervall in Sekunden, wenn die Blöcke regelmäßig kommen, sonst None."""
        if len(bursts) < self.min_regular_bursts:
            return None
        starts = [b[0] for b in bursts]
        gaps = [(b - a).total_seconds() for a, b in zip(starts, starts[1:])]
        median_gap = statistics.median(gaps)
        if median_gap > 0 and all(abs(g - median_gap) <= self.tolerance * median_gap for g in gaps):
            return median_gap
        return None

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Sekunden menschenlesbar (z. B. "15.6 s", "2 min")."""
        def num(x):
            return f"{x:.1f}".removesuffix(".0")
        if seconds < 120:
            return f"{num(seconds)} s"
        if seconds < 7200:
            return f"{num(seconds / 60)} min"
        return f"{num(seconds / 3600)} h"

    @staticmethod
    def format_time(dt: Optional[datetime]) -> str:
        return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "?"


# ---------------------------------------------------------------------------
# Bewertung: Konfiguration, bekannte Geräte, Historie, Score
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = Path(__file__).resolve().parent / "shelly_access_config.json"

DEFAULT_WEIGHTS = {
    "unknown_source": 35,     # Quelle nicht in der Liste bekannter Geräte
    "external_source": 25,    # öffentliche IP (außer Shelly Cloud)
    "write": 10,              # schreibender Zugriff
    "sensitive_action": 25,   # sicherheitsrelevante Aktion
    "night": 10,              # Zugriff in der Nacht
    "irregular": 5,           # unregelmäßiges Muster statt Polling
    "high_rate": 20,          # sehr viele Aufrufe pro Minute (z. B. HTTP-/RPC-Scan)
    "new_source": 30,         # Quelle bisher nie gesehen (Historie)
    "rate_deviation": 15,     # Rate deutlich höher als üblich (Historie)
    "internal": -20,          # interner Aufruf (loopback)
    "cloud_read": -10,        # Lesezugriff der Shelly Cloud
}

DEFAULT_SENSITIVE_ACTIONS = [
    "Sys.SetConfig", "WiFi.SetConfig", "Eth.SetConfig", "Mqtt.SetConfig", "Cloud.SetConfig",
    "Ws.SetConfig", "BLE.SetConfig", "Shelly.SetAuth", "User.SetConfig", "Shelly.Update",
    "Shelly.Reboot", "Shelly.FactoryReset", "Shelly.ResetWiFiConfig", "Script.PutCode",
    "Script.Create", "Script.Delete", "Script.SetConfig", "Schedule.Create", "Webhook.Create",
    "KVS.Set",
]


@dataclass
class ScoringConfig:
    """Einstellungen für Score und Historie (aus shelly_access_config.json)."""
    threshold: int = 50
    weights: dict = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    night_start: int = 0                  # Stunde, ab der "Nacht" gilt (inklusive)
    night_end: int = 5                    # Stunde, bis zu der "Nacht" gilt (exklusive)
    high_rate_per_minute: int = 60
    rate_deviation_factor: float = 5.0
    trust_shelly_cloud: bool = True
    sensitive_actions: list = field(default_factory=lambda: list(DEFAULT_SENSITIVE_ACTIONS))
    known_devices_file: Optional[str] = None
    history_enabled: bool = True
    history_file: Optional[str] = None
    baseline_days: int = 7

    @classmethod
    def load(cls, path) -> "ScoringConfig":
        """Lädt die Konfiguration; relative Pfade gelten relativ zur Konfigurationsdatei."""
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data, path.parent)

    @classmethod
    def from_dict(cls, data: dict, base_dir) -> "ScoringConfig":
        """
        Konfiguration aus einem Dict (z. B. IOT_AGENT_SETTINGS des Runners).
        Relative Pfade gelten relativ zu base_dir.
        """
        base_dir = Path(base_dir)
        cfg = cls()
        s = data.get("scoring", {})
        cfg.threshold = s.get("threshold", cfg.threshold)
        cfg.weights.update(s.get("weights", {}))
        night = s.get("night_hours", {})
        cfg.night_start = night.get("start", cfg.night_start)
        cfg.night_end = night.get("end", cfg.night_end)
        cfg.high_rate_per_minute = s.get("high_rate_per_minute", cfg.high_rate_per_minute)
        cfg.rate_deviation_factor = s.get("rate_deviation_factor", cfg.rate_deviation_factor)
        cfg.trust_shelly_cloud = s.get("trust_shelly_cloud", cfg.trust_shelly_cloud)
        cfg.sensitive_actions = s.get("sensitive_actions", cfg.sensitive_actions)

        def resolve(p):
            return str(p if Path(p).is_absolute() else base_dir / p) if p else None

        cfg.known_devices_file = resolve(data.get("known_devices_file"))
        h = data.get("history", {})
        cfg.history_enabled = h.get("enabled", cfg.history_enabled)
        cfg.history_file = resolve(h.get("file"))
        cfg.baseline_days = h.get("baseline_days", cfg.baseline_days)
        return cfg


class KnownDeviceProvider:
    """
    Basisklasse für die Liste bekannter Geräte.
    Später kann eine Unterklasse die Liste von einem REST-Server holen;
    sie muss nur load_devices() überschreiben.
    Erwartetes Format je Gerät: {"address": "192.168.0.10", "name": "..."}
    oder für MQTT-Clients: {"mqtt_client": "iobroker", "name": "..."}
    """

    def __init__(self):
        self._by_address = None
        self._by_mqtt = None

    def load_devices(self) -> Optional[list]:
        return None   # keine Liste konfiguriert

    def _ensure_loaded(self) -> None:
        if self._by_address is not None:
            return
        devices = self.load_devices()
        if devices is None:
            self._by_address, self._by_mqtt = {}, {}
            self.configured = False
            return
        self.configured = True
        self._by_address = {d["address"]: d.get("name", d["address"]) for d in devices if d.get("address")}
        self._by_mqtt = {d["mqtt_client"]: d.get("name", d["mqtt_client"]) for d in devices if d.get("mqtt_client")}

    @property
    def is_configured(self) -> bool:
        self._ensure_loaded()
        return self.configured

    def lookup(self, source: Source) -> Optional[str]:
        """Name des Geräts oder None, wenn unbekannt."""
        self._ensure_loaded()
        if source.kind == "MQTT":
            return self._by_mqtt.get(source.client_id)
        if source.address:
            return self._by_address.get(source.address)
        return None


class JsonKnownDeviceProvider(KnownDeviceProvider):
    """Liest die bekannten Geräte aus einer JSON-Datei ({"devices": [...]} oder direkt eine Liste)."""

    def __init__(self, path):
        super().__init__()
        self.path = Path(path)

    def load_devices(self) -> Optional[list]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return data.get("devices", []) if isinstance(data, dict) else data


class StaticKnownDeviceProvider(KnownDeviceProvider):
    """Bekannte Geräte aus einer fest übergebenen Liste (z. B. aus den Agenten-Einstellungen)."""

    def __init__(self, devices: list):
        super().__init__()
        self.devices = list(devices)

    def load_devices(self) -> Optional[list]:
        return self.devices


class CombinedKnownDeviceProvider(KnownDeviceProvider):
    """
    Fasst mehrere Quellen zusammen (z. B. REST-Server + Einträge aus den Einstellungen).
    Konfiguriert ist die Liste, sobald eine Quelle eine Liste liefert.
    """

    def __init__(self, providers: list):
        super().__init__()
        self.providers = providers

    def load_devices(self) -> Optional[list]:
        lists = [p.load_devices() for p in self.providers]
        if all(devices is None for devices in lists):
            return None
        return [d for devices in lists if devices for d in devices]


class HistoryStore:
    """
    Speichert pro Lauf die Raten je Zugriffsgruppe und die gesehenen Quellen.
    Dient als Vergleichsbasis für "neue Quelle" und "Rate höher als üblich".
    """

    def __init__(self, path, baseline_days: int = 7):
        self.path = Path(path)
        self.baseline_days = baseline_days
        self.runs = []
        if self.path.exists():
            try:
                self.runs = json.loads(self.path.read_text(encoding="utf-8")).get("runs", [])
            except (ValueError, OSError):
                self.runs = []   # kaputte Datei: neu anfangen
        self.runs = self._recent(self.runs)

    def _recent(self, runs: list) -> list:
        now = datetime.now().astimezone()
        result = []
        for r in runs:
            try:
                age_days = (now - datetime.fromisoformat(r["time"])).total_seconds() / 86400
            except (KeyError, ValueError):
                continue
            if age_days <= self.baseline_days:
                result.append(r)
        return result

    @property
    def has_runs(self) -> bool:
        return bool(self.runs)

    def known_sources(self) -> set:
        return {s for r in self.runs for s in r.get("sources", [])}

    def baseline_rate(self, key: str) -> Optional[float]:
        """Mittlere Rate pro Stunde dieser Gruppe in früheren Läufen (None, wenn nie gesehen)."""
        rates = [r["rates"][key] for r in self.runs if key in r.get("rates", {})]
        return statistics.mean(rates) if rates else None

    def add_run(self, rates: dict, sources: set) -> None:
        self.runs.append({
            "time": datetime.now().astimezone().isoformat(timespec="seconds"),
            "sources": sorted(sources),
            "rates": rates,
        })

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"runs": self.runs}, ensure_ascii=False, indent=1), encoding="utf-8")


class AnomalyScorer:
    """Berechnet je Zugriffsgruppe einen Auffälligkeits-Score (0–100) mit Begründungen."""

    def __init__(self, config: Optional[ScoringConfig] = None,
                 devices: Optional[KnownDeviceProvider] = None,
                 history: Optional[HistoryStore] = None,
                 describer: Optional[PatternDescriber] = None):
        self.config = config or ScoringConfig()
        self.devices = devices or KnownDeviceProvider()
        self.history = history
        self.describer = describer or PatternDescriber()
        self._sensitive = {a.lower() for a in self.config.sensitive_actions}
        self._known_sources = history.known_sources() if history and history.has_runs else None

    # --- Kennzahlen ---------------------------------------------------------

    @staticmethod
    def observation_window_hours(groups: list) -> float:
        """Gesamter beobachteter Zeitraum über alle Gruppen (mindestens 1 Minute)."""
        times = [t for g in groups for t in g.valid_times()]
        if len(times) < 2:
            return 1 / 60
        return max((max(times) - min(times)).total_seconds() / 3600, 1 / 60)

    @staticmethod
    def peak_per_minute(times: list) -> int:
        """Höchste Anzahl Aufrufe innerhalb eines beliebigen 60-Sekunden-Fensters."""
        peak, start = 0, 0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() >= 60:
                start += 1
            peak = max(peak, end - start + 1)
        return peak

    def is_night(self, dt: datetime) -> bool:
        s, e = self.config.night_start, self.config.night_end
        return s <= dt.hour < e if s <= e else (dt.hour >= s or dt.hour < e)

    def device_name(self, group: AccessGroup) -> Optional[str]:
        if group.source.kind == "internal":
            return "this device (script)"
        if group.channel == "Shelly Cloud" and self.config.trust_shelly_cloud:
            return self.devices.lookup(group.source) or "Shelly Cloud"
        return self.devices.lookup(group.source)

    # --- Score --------------------------------------------------------------

    def score(self, group: AccessGroup, rate_per_hour: float) -> dict:
        w = self.config.weights
        times = group.valid_times()
        points, reasons = 0, []

        def add(factor: str, reason: str):
            nonlocal points
            points += w.get(factor, 0)
            reasons.append(reason)

        name = self.device_name(group)
        if name is None and self.devices.is_configured:
            add("unknown_source", "unknown source")
        if self._is_external(group):
            add("external_source", "external (public) address")
        if group.access_type == RpcParser.WRITE:
            add("write", "write access")
        if group.method.lower() in self._sensitive:
            add("sensitive_action", f"sensitive action: {group.method}")

        night = sum(1 for t in times if self.is_night(t))
        if night:
            add("night", f"{night}× at night ({self.config.night_start:02d}–{self.config.night_end:02d} h)")

        if times:
            bursts = self.describer.bursts(times)
            if len(bursts) >= self.describer.min_regular_bursts and self.describer.regular_interval(bursts) is None:
                add("irregular", "irregular timing")
        peak = self.peak_per_minute(times) if times else 0
        if peak >= self.config.high_rate_per_minute:
            add("high_rate", f"high rate: {peak} calls/min")

        if group.source.kind == "internal":
            add("internal", "internal call (loopback)")
        if group.channel == "Shelly Cloud" and group.access_type == RpcParser.READ:
            add("cloud_read", "read access by Shelly Cloud")

        if self.history and self.history.has_runs:
            if group.source.label not in self._known_sources:
                add("new_source", "new source (not seen before)")
            baseline = self.history.baseline_rate(group.key)
            if baseline and rate_per_hour >= self.config.rate_deviation_factor * baseline:
                add("rate_deviation", f"rate {rate_per_hour / baseline:.1f}× higher than usual")

        score = max(0, min(100, points))
        return {
            "device_name": name,
            "peak_per_minute": peak,
            "anomaly": {
                "score": score,
                "suspicious": score >= self.config.threshold,
                "reasons": reasons,
            },
        }

    @staticmethod
    def _is_external(group: AccessGroup) -> bool:
        if group.source.kind != "IP" or not group.source.address or group.channel == "Shelly Cloud":
            return False
        try:
            return ipaddress.ip_address(group.source.address.split("%")[0]).is_global
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Auswertung und Bericht
# ---------------------------------------------------------------------------

class ShellyAccessAnalyzer:
    """Sammelt RPC-Zugriffe aus Logdateien und gruppiert sie."""

    def __init__(self, reader: Optional[ShellyLogReader] = None, parser: Optional[RpcParser] = None,
                 since: Optional[datetime] = None):
        self.reader = reader or ShellyLogReader()
        self.parser = parser or RpcParser()
        # nur Zugriffe ab diesem Zeitpunkt (Zeitfenster); Einträge ohne Zeitstempel fallen dann weg
        self.since = since
        self._groups: dict = {}
        self.files: list = []

    def add_directory(self, directory) -> "ShellyAccessAnalyzer":
        for path in self.reader.files(directory):
            # Dateien, die seit Fensterbeginn nicht geändert wurden, enthalten nichts Neues
            if self.since and path.stat().st_mtime < self.since.timestamp():
                continue
            self.add_file(path)
        return self

    def add_file(self, path) -> "ShellyAccessAnalyzer":
        path = Path(path)
        self.files.append(str(path))
        for record in self.reader.read_file(path):
            access = self.parser.parse(record)
            if access:
                self.add_access(access)
        return self

    def add_access(self, access: RpcAccess) -> None:
        if self.since and (access.timestamp is None or access.timestamp < self.since):
            return
        # "sys.getconfig" und "Sys.GetConfig" sind dieselbe Aktion
        key = (access.source, access.target, access.method.lower(), access.channel)
        group = self._groups.get(key)
        if group is None:
            group = self._groups[key] = AccessGroup(access.source, access.target,
                                                    access.method, access.channel)
        elif self._casing_score(access.method) > self._casing_score(group.method):
            group.method = access.method   # die CamelCase-Schreibweise bevorzugen
        group.add(access)

    @staticmethod
    def _casing_score(method: str) -> int:
        return sum(1 for c in method.partition(".")[2] if c.isupper())

    KIND_ORDER = {"IP": 0, "MQTT": 1, "internal": 2, "unknown": 3}

    def groups(self, write_only: bool = False, exclude_internal: bool = False) -> list:
        result = [g for g in self._groups.values()
                  if (not write_only or g.access_type == RpcParser.WRITE)
                  and (not exclude_internal or g.source.kind != "internal")]
        result.sort(key=lambda g: (self.KIND_ORDER.get(g.source.kind, 9),
                                   str(g.source.address or g.source.client_id or g.source.transport or ""),
                                   g.target.host, -g.count, g.method))
        return result


class AccessReport:
    """Baut aus gruppierten Zugriffen den JSON-Bericht."""

    def __init__(self, groups: list, files: list, directory=None,
                 describer: Optional[PatternDescriber] = None,
                 scorer: Optional[AnomalyScorer] = None,
                 sort_by_score: bool = False,
                 all_groups: Optional[list] = None,
                 window_hours: Optional[float] = None):
        self.groups = groups
        # feste Fensterlänge (z. B. window_minutes des Agenten); sonst aus den Daten ermittelt
        self.window_hours = window_hours
        # ungefilterte Gruppen: Basis für Beobachtungszeitraum und Historie
        self.all_groups = all_groups if all_groups is not None else groups
        self.files = files
        self.directory = directory
        self.describer = describer or PatternDescriber()
        self.scorer = scorer or AnomalyScorer(describer=self.describer)
        self.sort_by_score = sort_by_score
        self._accesses = None

    def accesses(self) -> list:
        """Zugriffe als Dicts inkl. Rate und Score (wird einmal berechnet)."""
        if self._accesses is None:
            window = self.observation_hours()
            result = []
            for g in self.groups:
                d = g.to_dict(self.describer)
                rate = round(g.count / window, 2)
                s = self.scorer.score(g, rate)
                if s["device_name"]:
                    d["source"]["name"] = s["device_name"]
                d["rate_per_hour"] = rate
                d["peak_per_minute"] = s["peak_per_minute"]
                d["anomaly"] = s["anomaly"]
                d["_key"] = g.key
                result.append(d)
            if self.sort_by_score:
                result.sort(key=lambda d: -d["anomaly"]["score"])
            self._accesses = result
        return self._accesses

    def summary(self) -> dict:
        per_source = defaultdict(int)
        for g in self.groups:
            per_source[g.source.label] += g.count
        acc = self.accesses()
        history = self.scorer.history
        return {
            "total_accesses": sum(g.count for g in self.groups),
            "write_accesses": sum(g.count for g in self.groups if g.access_type == RpcParser.WRITE),
            "per_source": dict(sorted(per_source.items(), key=lambda kv: -kv[1])),
            "targets": sorted({g.target.host for g in self.groups}),
            "observation_window_hours": round(self.observation_hours(), 2),
            "anomaly_threshold": self.scorer.config.threshold,
            "suspicious_entries": sum(1 for d in acc if d["anomaly"]["suspicious"]),
            "max_score": max((d["anomaly"]["score"] for d in acc), default=0),
            "known_devices_configured": self.scorer.devices.is_configured,
            "history_runs_used": len(history.runs) if history else 0,
        }

    def observation_hours(self) -> float:
        """Länge des Beobachtungszeitraums in Stunden (Basis für rate_per_hour)."""
        if self.window_hours:
            return self.window_hours
        return self.scorer.observation_window_hours(self.all_groups)

    def update_history(self) -> None:
        """
        Schreibt den aktuellen Lauf in die Historie (nach der Bewertung aufrufen).
        Nutzt die ungefilterten Gruppen, damit Filter wie --write-only die Historie nicht verfälschen.
        """
        history = self.scorer.history
        if not history:
            return
        groups = self.all_groups
        window = self.observation_hours()
        rates = {g.key: round(g.count / window, 2) for g in groups}
        history.add_run(rates, {g.source.label for g in groups})
        history.save()

    def to_dict(self) -> dict:
        summary = self.summary()
        accesses = [{k: v for k, v in d.items() if k != "_key"} for d in self.accesses()]
        return {
            "created": datetime.now().astimezone().isoformat(timespec="seconds"),
            "directory": str(Path(self.directory).resolve()) if self.directory else None,
            "files": self.files,
            "summary": summary,
            "accesses": accesses,
        }

    def to_json(self, compact: bool = False) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=None if compact else 2)


# ---------------------------------------------------------------------------
# Kommandozeile
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Analyzes Shelly syslogs and lists all accesses as JSON.")
    ap.add_argument("-d", "--dir", default="/var/log/shelly", help="log directory (default: /var/log/shelly)")
    ap.add_argument("-o", "--output", help="write JSON to this file instead of stdout")
    ap.add_argument("--write-only", action="store_true", help="only list write accesses")
    ap.add_argument("--exclude-internal", action="store_true",
                    help="omit internal calls (loopback, e.g. from scripts)")
    ap.add_argument("--compact", action="store_true", help="output JSON without indentation")
    ap.add_argument("-c", "--config", default=str(DEFAULT_CONFIG),
                    help=f"config file for scoring and history (default: {DEFAULT_CONFIG.name} next to the script)")
    ap.add_argument("--threshold", type=int, help="score from which an entry counts as suspicious (overrides config)")
    ap.add_argument("--suspicious-only", action="store_true", help="only list suspicious entries")
    ap.add_argument("--sort-by-score", action="store_true", help="sort entries by score, highest first")
    ap.add_argument("--no-history", action="store_true", help="do not read or update the history")
    args = ap.parse_args(argv)

    if not Path(args.dir).is_dir():
        print(f"Error: directory {args.dir} not found", file=sys.stderr)
        return 1

    # Konfiguration laden (ohne Datei: Standardwerte, keine Geräteliste, keine Historie)
    config_path = Path(args.config)
    if config_path.is_file():
        config = ScoringConfig.load(config_path)
    else:
        if args.config != str(DEFAULT_CONFIG):
            print(f"Error: config file {args.config} not found", file=sys.stderr)
            return 1
        config = ScoringConfig(history_enabled=False)
    if args.threshold is not None:
        config.threshold = args.threshold

    devices = KnownDeviceProvider()
    if config.known_devices_file:
        if not Path(config.known_devices_file).is_file():
            print(f"Error: known devices file {config.known_devices_file} not found", file=sys.stderr)
            return 1
        devices = JsonKnownDeviceProvider(config.known_devices_file)

    history = None
    if config.history_enabled and not args.no_history:
        history_file = config.history_file or str(config_path.parent / "shelly_access_history.json")
        history = HistoryStore(history_file, config.baseline_days)

    describer = PatternDescriber()
    scorer = AnomalyScorer(config, devices, history, describer)

    analyzer = ShellyAccessAnalyzer().add_directory(args.dir)
    groups = analyzer.groups(write_only=args.write_only, exclude_internal=args.exclude_internal)
    report = AccessReport(groups, analyzer.files, args.dir, describer, scorer,
                          sort_by_score=args.sort_by_score, all_groups=analyzer.groups())
    data = report.to_dict()
    if args.suspicious_only:
        data["accesses"] = [a for a in data["accesses"] if a["anomaly"]["suspicious"]]
    report.update_history()
    text = json.dumps(data, ensure_ascii=False, indent=None if args.compact else 2)
    groups = data["accesses"]

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"{len(groups)} entries written to {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
