"""
Konfiguration der Agenten fuer den Runner.

Lokal (agents/agents.json) steht nur der Zugang zum REST-Server:

    { "rest": { "base_url": "https://dk9mbs.de/api/v1.0", "apikey": "...", "timeout": 10 },
      "host": "nextcloud",          # optional, Standard: Rechnername
      "log_dir": "logs" }           # optional

Welche Agenten laufen und mit welchen Einstellungen, steht zentral in den
Tabellen iot_agent_host / iot_agent_config (Plugin IoTSensorNet), der
Ausgabetyp je Agent in iot_agent (im lokalen Block: "output_type").
Quellen in dieser Reihenfolge:
  1. zentral (wird als Kopie in <log_dir>/central_config.json gespeichert)
  2. die letzte Kopie, wenn der Server nicht erreichbar ist
  3. ein lokaler "agents"-Block in agents.json (Uebergang/Test); Agenten ohne
     "settings" bekommen dann ihre bisherigen Dateien (config.env/config.json)

Der Runner gibt jedem Agenten REST-Zugang und Einstellungen als
Umgebungsvariablen mit (agent_env).
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from xml.sax.saxutils import quoteattr

AGENTS_DIR = Path(__file__).resolve().parent
CACHE_NAME = "central_config.json"
LAST_SEEN_INTERVAL = 600  # last_seen_on hoechstens alle 10 Minuten setzen
DEFAULT_OUTPUT_TYPE = 1   # iot_agent_output_type "No Action" (siehe agent_output.py)


# --------------------------------------------------------------------------
# REST-Zugang
# --------------------------------------------------------------------------

def rest_settings(cfg: dict) -> dict:
    """Liefert {"base_url", "apikey", "timeout"}; RuntimeError, wenn etwas fehlt."""
    rest = cfg.get("rest") or {}
    base_url = rest.get("base_url")
    if not base_url and rest.get("url"):
        # altes Format: "url" zeigte direkt auf .../data/iot_sensor_data
        base_url = rest["url"].split("/data/")[0]
    if not base_url or not rest.get("apikey"):
        raise RuntimeError("rest.base_url und rest.apikey in agents.json eintragen")
    return {
        "base_url": base_url.rstrip("/"),
        "apikey": rest["apikey"],
        "timeout": rest.get("timeout", 10),
    }


def host_name(cfg: dict) -> str:
    return cfg.get("host") or socket.gethostname()


def _select(rest: dict, table: str, field: str = None, value: str = None) -> list:
    """XML-Select auf table; ohne field alle Datensaetze."""
    condition = (f'<filter type="and"><condition field={quoteattr(field)} value={quoteattr(value)} '
                 f'operator="eq" /></filter>' if field else "")
    xml = f'<restapi type="select"><table name={quoteattr(table)} alias="a"/>{condition}</restapi>'
    req = urllib.request.Request(
        f"{rest['base_url']}/data", data=xml.encode("utf-8"), method="POST",
        headers={"Content-Type": "application/xml", "apikey": rest["apikey"]})
    with urllib.request.urlopen(req, timeout=rest["timeout"]) as resp:
        return json.load(resp)


def _value(row: dict, field: str):
    value = row.get(field)
    if isinstance(value, dict):  # Antwort mit Formatter: {"value": ..., "formatted_value": ...}
        value = value.get("value", value.get("formatted_value"))
    return value


def _flag(value) -> bool:
    """smallint-Schalter der restapi: -1/1 = an, 0 = aus."""
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return bool(value)


# --------------------------------------------------------------------------
# Zentrale Konfiguration
# --------------------------------------------------------------------------

def fetch_central(cfg: dict):
    """
    Liest Rechner und Agenten vom REST-Server.
    Rueckgabe: {"host": ..., "enabled": bool, "agents": {...}} oder None, wenn
    der Rechner zentral nicht eingetragen ist. Fehler -> Exception.
    """
    rest = rest_settings(cfg)
    host = host_name(cfg)
    hosts = _select(rest, "iot_agent_host", "id", host)
    if not hosts:
        return None
    output_types = fetch_output_types(rest)
    agents = {}
    for row in _select(rest, "iot_agent_config", "host_id", host):
        name = _value(row, "agent")
        raw = _value(row, "settings") or "{}"
        try:
            settings = json.loads(raw)
        except ValueError as exc:
            print(f"[config] Einstellungen von {name} sind kein gueltiges JSON ({exc}) - Agent aus",
                  file=sys.stderr, flush=True)
            agents[name] = {"enabled": False, "settings_error": str(exc)}
            continue
        agents[name] = {
            "enabled": _flag(_value(row, "enabled")),
            "every_minutes": int(_value(row, "every_minutes") or 5),
            "timeout_seconds": int(_value(row, "timeout_seconds") or 300),
            "settings": settings,
            "output_type": output_types.get(name, DEFAULT_OUTPUT_TYPE),
        }
    return {"host": host, "enabled": _flag(_value(hosts[0], "enabled")), "agents": agents}


def fetch_output_types(rest: dict) -> dict:
    """
    Ausgabetyp je Agent aus iot_agent ({name: output_type_id}). Fehlt die
    Tabelle (Plugin noch nicht aktualisiert), gilt fuer alle "No Action", statt
    die ganze zentrale Konfiguration zu verwerfen.
    """
    try:
        rows = _select(rest, "iot_agent")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"[config] iot_agent nicht lesbar ({exc}) - Ausgabetyp 1 (No Action) fuer alle",
              file=sys.stderr, flush=True)
        return {}
    types = {}
    for row in rows:
        try:
            types[_value(row, "id")] = int(_value(row, "output_type_id") or DEFAULT_OUTPUT_TYPE)
        except (TypeError, ValueError):
            types[_value(row, "id")] = DEFAULT_OUTPUT_TYPE
    return types


def touch_host(cfg: dict) -> None:
    """Setzt iot_agent_host.last_seen_on (Fehler werden nur gemeldet)."""
    rest = rest_settings(cfg)
    host = host_name(cfg)
    body = json.dumps({"id": host, "last_seen_on": time.strftime("%Y-%m-%d %H:%M:%S")}).encode("utf-8")
    req = urllib.request.Request(
        f"{rest['base_url']}/data/iot_agent_host/{host}", data=body, method="PUT",
        headers={"Content-Type": "application/json", "apikey": rest["apikey"]})
    try:
        with urllib.request.urlopen(req, timeout=rest["timeout"]):
            pass
    except (urllib.error.URLError, OSError) as exc:
        print(f"[config] last_seen_on fuer {host} nicht gesetzt: {exc}", file=sys.stderr, flush=True)


def _read_cache(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_cache(path: Path, data: dict) -> None:
    # enthaelt Zugangsdaten der Agenten -> nur fuer den Eigentuemer lesbar
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def resolve_agents(cfg: dict, log_dir: Path):
    """
    Ermittelt die Agenten dieses Rechners.
    Rueckgabe: (agents, quelle) - quelle ist ein kurzer Text fuer --list/Journal.
    """
    cache_path = log_dir / CACHE_NAME
    try:
        central = fetch_central(cfg)
    except Exception as exc:  # Server/Tabellen nicht erreichbar
        cache = _read_cache(cache_path)
        if cache:
            return cache["agents"] if cache.get("enabled", True) else {}, \
                f"Kopie vom {time.strftime('%Y-%m-%d %H:%M', time.localtime(cache.get('fetched_on', 0)))} " \
                f"(zentral nicht erreichbar: {exc})"
        return _local_agents(cfg), f"lokal (zentral nicht erreichbar: {exc})"

    if central is None:
        return _local_agents(cfg), f"lokal (Rechner {host_name(cfg)} zentral nicht eingetragen)"

    cache = _read_cache(cache_path) or {}
    central["fetched_on"] = time.time()
    central["last_seen_put"] = cache.get("last_seen_put", 0)
    if time.time() - central["last_seen_put"] >= LAST_SEEN_INTERVAL:
        touch_host(cfg)
        central["last_seen_put"] = time.time()
    try:
        _write_cache(cache_path, central)
    except OSError as exc:
        print(f"[config] Kopie {cache_path} nicht geschrieben: {exc}", file=sys.stderr, flush=True)

    if not central["enabled"]:
        return {}, f"zentral (Rechner {central['host']} deaktiviert)"
    return central["agents"], f"zentral (Rechner {central['host']})"


# --------------------------------------------------------------------------
# Lokaler Block und bisherige Dateien (Uebergang)
# --------------------------------------------------------------------------

def _read_env_file(path: Path) -> dict:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip("'\"")
    return values


def legacy_settings(name: str) -> dict:
    """Einstellungen aus den bisherigen Dateien eines Agenten (vor der zentralen Konfiguration)."""
    agent_dir = AGENTS_DIR / name
    if name == "nmap" and (agent_dir / "config.env").exists():
        env = _read_env_file(agent_dir / "config.env")
        return {"netz": env["NMAP_NETZ"]} if env.get("NMAP_NETZ") else {}
    if name == "notify" and (agent_dir / "config.env").exists():
        env = _read_env_file(agent_dir / "config.env")
        return {k: v for k, v in env.items() if k.startswith(("NEXTCLOUD_", "TELEGRAM_"))}
    if name == "omada_syslog" and (agent_dir / "config.json").exists():
        return json.loads((agent_dir / "config.json").read_text(encoding="utf-8"))
    return {}


def _local_agents(cfg: dict) -> dict:
    agents = {}
    for name, agent in (cfg.get("agents") or {}).items():
        agent = dict(agent)
        if "settings" not in agent:
            try:
                agent["settings"] = legacy_settings(name)
            except (OSError, ValueError) as exc:
                print(f"[config] bisherige Einstellungen von {name} nicht lesbar: {exc}",
                      file=sys.stderr, flush=True)
                agent["settings"] = {}
        agents[name] = agent
    return agents


# --------------------------------------------------------------------------
# Uebergabe an die Agenten und Export
# --------------------------------------------------------------------------

def agent_env(cfg: dict, agent: dict) -> dict:
    """Umgebungsvariablen fuer einen Agenten: REST-Zugang, Einstellungen, Python."""
    env = {"IOT_AGENT_SETTINGS": json.dumps(agent.get("settings") or {}, ensure_ascii=False)}
    try:
        rest = rest_settings(cfg)
        env.update({
            "IOT_REST_BASE_URL": rest["base_url"],
            "IOT_REST_APIKEY": rest["apikey"],
            "IOT_REST_TIMEOUT": str(rest["timeout"]),
        })
    except RuntimeError:
        pass
    if sys.prefix != sys.base_prefix:
        # Runner laeuft im venv (z.B. als Dienst) -> Agenten mit demselben Python starten
        env["IOT_PYTHON"] = sys.executable
    return env


def _sql(value) -> str:
    if value is None:
        return "NULL"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def export_sql(cfg: dict) -> str:
    """INSERT-Befehle fuer iot_agent_host/iot_agent_config aus der lokalen Konfiguration."""
    host = host_name(cfg)
    lines = [
        f"-- Agenten-Konfiguration von {host} (aus agents.json und den bisherigen Dateien)",
        "-- ACHTUNG: enthaelt Zugangsdaten der Agenten",
        f"INSERT INTO iot_agent_host (id, description, enabled) VALUES ({_sql(host)}, NULL, -1)",
        "    ON DUPLICATE KEY UPDATE enabled=VALUES(enabled);",
    ]
    for name, agent in _local_agents(cfg).items():
        settings = json.dumps(agent.get("settings") or {}, ensure_ascii=False, indent=2)
        lines += [
            "INSERT INTO iot_agent_config (host_id, agent, enabled, every_minutes, timeout_seconds, settings)",
            f"    VALUES ({_sql(host)}, {_sql(name)}, {-1 if agent.get('enabled') else 0}, "
            f"{int(agent.get('every_minutes', 5))}, {int(agent.get('timeout_seconds', 300))}, {_sql(settings)})",
            "    ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), every_minutes=VALUES(every_minutes),",
            "        timeout_seconds=VALUES(timeout_seconds), settings=VALUES(settings);",
        ]
    return "\n".join(lines) + "\n"
