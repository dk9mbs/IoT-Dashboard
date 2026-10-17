#!/usr/bin/env python3
"""
wlan_score.py - Ermittelt einen WLAN-Sicherheitsscore (0-100) aus den
Syslog-Dateien der Omada-Access-Points (eine Datei pro AP: <ip>.log).

Aufruf:
    python3 wlan_score.py --config config.json [--pretty] [--learn] [--push]

Ausgabe: JSON auf stdout (Score, Ampel, Einzelwerte, Abzuege).
Mit --push werden die Kennzahlen ("metrics") zusaetzlich als Datensaetze in
die REST-Tabelle iot_sensor_data geschrieben (sensor_id = wlan_<kennzahl>).
URL und API-Key kommen zentral aus agents/agents.json, der Namespace aus
dem rest-Block der config.json.
"""

import argparse
import gzip
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "common"))
from agent_config import rest_settings  # noqa: E402  (REST-Zugang zentral aus agents.json)

MAC_RE =re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")

# rsyslog-Zeilenformate: ISO (Debian-Standard) und klassisch ("Oct 15 12:00:00")
ISO_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(\S+)\s+(.*)$"
)
TRAD_LINE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")

# rsyslog maskiert CR/LF als #015/#012 - der AP packt mehrere Eintraege in eine Nachricht
ENTRY_SEP = "#012"
# Traffic-Eintrag der Omada-APs: [ts] AP MAC=.. MAC SRC=.. IP SRC=.. IP DST=.. ...
TRAFFIC_RE = re.compile(r"AP MAC=(\S+) MAC SRC=(\S+) IP SRC=(\S+) IP DST=(\S+)")


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------

def normalize_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def parse_line(line: str, now: datetime):
    """Liefert (zeitstempel, nachricht) oder None."""
    try:
        return _parse_line(line, now)
    except ValueError:  # kaputter Zeitstempel darf nicht den ganzen Lauf abbrechen
        return None


def _parse_line(line: str, now: datetime):
    m = ISO_LINE.match(line)
    if m:
        ts = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        return ts, m.group(3)
    m = TRAD_LINE.match(line)
    if m:
        ts = datetime.strptime(f"{now.year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        ts = ts.replace(tzinfo=now.tzinfo)
        if ts > now + timedelta(days=1):  # Jahreswechsel
            ts = ts.replace(year=now.year - 1)
        return ts, m.group(3)
    return None


def open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def read_ap_log(ap: dict, log_dir: Path, since: datetime, now: datetime):
    """Liest aktuelle + zuletzt rotierte Datei eines APs.
    Rueckgabe: (events im Zeitfenster, letzter Zeitstempel ueberhaupt, Datei gefunden?)"""
    base = log_dir / f"{ap['ip']}.log"
    candidates = [Path(f"{base}.1.gz"), Path(f"{base}.1"), base]
    events, last_seen, found = [], None, False

    for path in candidates:
        if not path.exists():
            continue
        found = True
        with open_log(path) as f:
            for line in f:
                parsed = parse_line(line.rstrip("\n"), now)
                if not parsed:
                    continue
                ts, msg = parsed
                if last_seen is None or ts > last_seen:
                    last_seen = ts
                if ts >= since:
                    for part in msg.split(ENTRY_SEP):
                        part = part.replace("#015", "").strip()
                        if part:
                            events.append((ts, part))
    return events, last_seen, found


def is_internet(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_known_macs(cfg: dict) -> dict:
    """Bekannte Geraete als {mac: eintrag}. Optional pro Geraet "internet": false.
    Spaeter hier durch Abruf vom REST-Server ersetzen."""
    path = Path(cfg["known_macs_file"])
    if not path.exists():  # Ersteinrichtung: --learn legt die Datei an
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("devices", [])
    macs = {}
    for item in data:
        entry = item if isinstance(item, dict) else {"mac": item}
        if entry.get("mac"):
            macs[normalize_mac(entry["mac"])] = entry
    return macs


def learn_unknown(cfg: dict, unknown: dict) -> int:
    """Haengt unbekannte MACs mit leerem Namen an die known_macs-Datei an."""
    path = Path(cfg["known_macs_file"])
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    devices = data.get("devices", []) if isinstance(data, dict) else data
    for mac, aps in sorted(unknown.items()):
        devices.append({"mac": mac, "name": "", "ap": ", ".join(aps), "internet": True})
    if isinstance(data, dict):
        data["devices"] = devices
    else:
        data = devices
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(unknown)


def push_metrics(cfg: dict, metrics: dict, rest: dict) -> list:
    """Schreibt jede Kennzahl als eigenen Datensatz nach iot_sensor_data.
    rest: zentrale Zugangsdaten (base_url, apikey, timeout) aus agents.json.
    Rueckgabe: Liste der Fehlermeldungen (leer = alles ok)."""
    url = f"{rest['base_url']}/data/iot_sensor_data"
    namespace = cfg.get("rest", {}).get("namespace", "wlan.score")
    headers = {"Content-Type": "application/json", "apikey": rest["apikey"]}
    errors = []
    for sensor_id, value in metrics.items():
        body = json.dumps({
            "sensor_id": sensor_id,
            "sensor_namespace": namespace,
            "sensor_value": value,
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=rest["timeout"]):
                pass
        except urllib.error.HTTPError as exc:
            errors.append(f"{sensor_id}: HTTP {exc.code} {exc.read()[:200].decode(errors='replace')}")
        except (urllib.error.URLError, OSError) as exc:
            errors.append(f"{sensor_id}: {exc}")
    return errors


def capped(value: int, cap) -> int:
    return min(value, cap) if cap is not None else value


# --------------------------------------------------------------------------
# Score-Berechnung
# --------------------------------------------------------------------------

def compute_score(cfg: dict) -> dict:
    now = datetime.now().astimezone()
    window = cfg.get("window_minutes", 60)
    since = now - timedelta(minutes=window)
    log_dir = Path(cfg["log_dir"])
    sc = cfg["scoring"]
    pat = {k: re.compile(v, re.IGNORECASE) for k, v in cfg["patterns"].items()}

    known = get_known_macs(cfg)
    ignore = {normalize_mac(m) for m in cfg.get("ignore_macs", [])}

    auth_fail_macs = Counter()
    auth_fail_total = 0
    deauth_per_minute = Counter()
    unknown_macs = {}
    rogue_lines = []
    mgmt_fail = 0
    silent_aps, warnings = [], []
    client_macs = set()
    internet_dst = {}  # mac -> Ziel-IPs im Internet
    per_ap = {}        # Diagnose pro AP
    # MACs der APs selbst (aus Config und Traffic-Eintraegen) sind keine Clients
    ap_macs = {normalize_mac(ap["mac"]) for ap in cfg["aps"] if ap.get("mac")}

    for ap in cfg["aps"]:
        events, last_seen, found = read_ap_log(ap, log_dir, since, now)
        if not found:
            warnings.append(f"Keine Logdatei fuer {ap['name']} ({ap['ip']})")

        stats = per_ap[ap["name"]] = {
            "ip": ap["ip"],
            "entries": len(events),
            "traffic_entries": 0,
            "clients": set(),
            "ap_macs": set(),
            "last_seen": last_seen.isoformat(timespec="seconds") if last_seen else None,
        }

        silent_limit = sc["ap_silent"]["minutes"]
        if last_seen is None or last_seen < now - timedelta(minutes=silent_limit):
            silent_aps.append(ap["name"])

        for ts, msg in events:
            t = TRAFFIC_RE.search(msg)
            if t:  # Traffic-Eintrag: aktiver Client + Ziel
                src_mac, dst_ip = normalize_mac(t.group(2)), t.group(4)
                client_macs.add(src_mac)
                stats["traffic_entries"] += 1
                stats["clients"].add(src_mac)
                stats["ap_macs"].add(normalize_mac(t.group(1)))
                ap_macs.add(normalize_mac(t.group(1)))
                if src_mac not in known and src_mac not in ignore:
                    unknown_macs.setdefault(src_mac, set()).add(ap["name"])
                if is_internet(dst_ip):
                    internet_dst.setdefault(src_mac, set()).add(dst_ip)
                continue

            macs = [normalize_mac(m) for m in MAC_RE.findall(msg)]

            if pat["auth_fail"].search(msg):
                auth_fail_total += 1
                for mac in macs:
                    auth_fail_macs[mac] += 1
            if pat["deauth"].search(msg):
                deauth_per_minute[ts.strftime("%Y-%m-%d %H:%M")] += 1
            if pat["rogue_ap"].search(msg):
                rogue_lines.append(f"{ap['name']}: {msg[:200]}")
            if pat["mgmt_login_fail"].search(msg):
                mgmt_fail += 1
            if pat["client_seen"].search(msg):
                for mac in macs:
                    if mac not in known and mac not in ignore:
                        unknown_macs.setdefault(mac, set()).add(ap["name"])

    # AP-MACs erst nach dem Lesen aller APs entfernen (Traffic kann spaeter kommen)
    for mac in ap_macs:
        unknown_macs.pop(mac, None)
        auth_fail_macs.pop(mac, None)

    # --- Abzuege ---------------------------------------------------------
    penalties = {}

    r = sc["auth_fail"]
    penalties["auth_fail"] = capped((auth_fail_total // r["per"]) * r["penalty"], r.get("cap"))

    r = sc["deauth_burst"]
    max_deauth = max(deauth_per_minute.values(), default=0)
    penalties["deauth_burst"] = r["penalty"] if max_deauth > r["per_minute"] else 0

    r = sc["unknown_mac"]
    penalties["unknown_mac"] = capped(len(unknown_macs) * r["penalty"], r.get("cap"))

    penalties["rogue_ap"] = sc["rogue_ap"]["penalty"] if rogue_lines else 0

    r = sc["mgmt_login_fail"]
    penalties["mgmt_login_fail"] = capped(mgmt_fail * r["penalty"], r.get("cap"))

    unexpected_inet = {
        mac: sorted(ips)[:5] for mac, ips in internet_dst.items()
        if known.get(mac, {}).get("internet") is False
    }
    r = sc.get("unexpected_internet", {"penalty": 0})
    penalties["unexpected_internet"] = capped(len(unexpected_inet) * r["penalty"], r.get("cap"))

    penalties["ap_silent"] = len(silent_aps) * sc["ap_silent"]["penalty"]

    b = cfg.get("baseline", {})
    missing = [k for k, ok in b.get("checks", {}).items() if not ok]
    penalties["baseline"] = len(missing) * b.get("points_each", 0)

    score = max(0, 100 - sum(penalties.values()))
    th = cfg["thresholds"]
    level = "gruen" if score >= th["green"] else "gelb" if score >= th["yellow"] else "rot"

    # Numerische Kennzahlen fuer iot_sensor_data (sensor_value ist decimal):
    # Listen/Dicts werden als Anzahl gemeldet, ueber die volle Menge statt Top-N
    metrics = {
        "wlan_score": score,
        "wlan_auth_fail_total": auth_fail_total,
        "wlan_auth_fail_top_macs": len(auth_fail_macs),
        "wlan_deauth_max_per_minute": max_deauth,
        "wlan_clients_seen": len(client_macs),
        "wlan_unknown_macs": len(unknown_macs),
        "wlan_internet_clients": len(internet_dst),
        "wlan_unexpected_internet": len(unexpected_inet),
        "wlan_rogue_ap_events": len(rogue_lines),
        "wlan_mgmt_login_fail": mgmt_fail,
        "wlan_silent_aps": len(silent_aps),
        "wlan_baseline_missing": len(missing),
    }

    return {
        "timestamp": now.isoformat(timespec="seconds"),
        "window_minutes": window,
        "score": score,
        "level": level,
        "penalties": penalties,
        "metrics": metrics,
        "details": {
            "auth_fail_total": auth_fail_total,
            "auth_fail_top_macs": auth_fail_macs.most_common(5),
            "deauth_max_per_minute": max_deauth,
            "clients_seen": len(client_macs),
            "unknown_macs": {m: sorted(a) for m, a in unknown_macs.items()},
            "internet_clients": len(internet_dst),
            "unexpected_internet": unexpected_inet,
            "rogue_ap_events": rogue_lines[:10],
            "mgmt_login_fail": mgmt_fail,
            "silent_aps": silent_aps,
            "baseline_missing": missing,
        },
        "per_ap": {
            name: {**st, "clients": len(st["clients"]), "ap_macs": sorted(st["ap_macs"])}
            for name, st in per_ap.items()
        },
        "warnings": warnings,
    }


def main():
    ap = argparse.ArgumentParser(description="WLAN-Sicherheitsscore aus Omada-Syslogs")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--pretty", action="store_true", help="JSON eingerueckt ausgeben")
    ap.add_argument("--learn", action="store_true",
                    help="unbekannte MACs in die known_macs-Datei uebernehmen")
    ap.add_argument("--push", action="store_true",
                    help="Kennzahlen per REST nach iot_sensor_data schreiben")
    args = ap.parse_args()
    push_errors = []

    try:
        cfg_path = Path(args.config).resolve()
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        # relative Pfade beziehen sich auf den Ordner der Config (wichtig fuer Cron)
        for key in ("log_dir", "known_macs_file"):
            if not Path(cfg[key]).is_absolute():
                cfg[key] = str(cfg_path.parent / cfg[key])
        result = compute_score(cfg)
        if args.learn:
            n = learn_unknown(cfg, result["details"]["unknown_macs"])
            print(f"{n} MAC(s) in {cfg['known_macs_file']} uebernommen", file=sys.stderr)
        if args.push:
            rest = rest_settings()
            push_errors = push_metrics(cfg, result["metrics"], rest)
            ok = len(result["metrics"]) - len(push_errors)
            print(f"{ok}/{len(result['metrics'])} Kennzahl(en) an {rest['base_url']} gesendet",
                  file=sys.stderr)
            for err in push_errors:
                print(f"  Fehler: {err}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None))
    if push_errors:
        sys.exit(2)


if __name__ == "__main__":
    main()

