#!/usr/bin/env python3
"""
run_agents.py - Zentraler Runner fuer die Agenten unter agents/.

Fuehrt jeden aktiven Agenten aus agents.json aus, dessen Intervall
abgelaufen ist. Als Dienst (iot-agents.service, siehe install/install.sh)
laeuft er mit --daemon und prueft selbst jede Minute; alternativ per Cron
jede Minute ein einzelner Durchlauf:

    * * * * * python3 /pfad/zu/agents/run_agents.py

Jeder Agent ist ein Ordner unter agents/ mit einer run.sh, die gestartet
wird. Mit "command" in agents.json laesst sich ein anderer Befehl angeben.

Pro Agent:
  - Sperrdatei, damit ein noch laufender Agent nicht doppelt startet
  - Timeout, der die ganze Prozessgruppe beendet (auch Kindprozesse)
  - eigene Logdatei <log_dir>/<name>.log
  - optional Meldung von Exit-Code und Laufzeit nach iot_sensor_data
    (sensor_id agent_<name>_exit / agent_<name>_duration); eigene Codes:
    124 = Timeout, 125 = Runner-Fehler (z.B. keine Schreibrechte in log_dir),
    127 = Befehl nicht startbar

Weitere Aufrufe:
    python3 run_agents.py --list         Status aller Agenten anzeigen
    python3 run_agents.py --run nmap     Agenten sofort ausfuehren (auch wenn deaktiviert)
    python3 run_agents.py --all          alle aktiven Agenten sofort ausfuehren
    python3 run_agents.py --daemon       dauerhaft laufen, jede Minute faellige Agenten starten
"""

import argparse
import fcntl
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

from agent_config import rest_env, rest_settings  # noqa: E402  (agents/agent_config.py)

TIMEOUT_EXIT = 124       # wie timeout(1)
RUNNER_ERROR_EXIT = 125  # Runner konnte Sperr-/Log-/Statusdatei nicht schreiben
LOG_MAX_BYTES = 5 * 1024 * 1024


def now_str() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_config(path: Path) -> dict:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    log_dir = Path(cfg.get("log_dir", "logs"))
    if not log_dir.is_absolute():
        log_dir = path.parent / log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    cfg["log_dir"] = log_dir
    return cfg


def last_start(lock_path: Path) -> float:
    """Startzeit des letzten Laufs (steht in der Sperrdatei), 0 wenn nie gelaufen."""
    try:
        return float(lock_path.read_text().strip() or 0)
    except (OSError, ValueError):
        return 0.0


def is_due(agent: dict, lock_path: Path, now: float) -> bool:
    # 30 s Toleranz, weil Cron nicht sekundengenau startet
    return now - last_start(lock_path) >= agent.get("every_minutes", 60) * 60 - 30


def rotate_log(log_path: Path) -> None:
    if log_path.exists() and log_path.stat().st_size > LOG_MAX_BYTES:
        log_path.replace(log_path.with_suffix(".log.1"))


def push_status(cfg: dict, name: str, exit_code: int, duration: float) -> None:
    try:
        rest = rest_settings(cfg)
    except RuntimeError:
        return  # ohne REST-Zugang keine Status-Meldung
    url = f"{rest['base_url']}/data/iot_sensor_data"
    namespace = cfg["rest"].get("namespace", "agents")
    headers = {"Content-Type": "application/json", "apikey": rest["apikey"]}
    for sensor_id, value in ((f"agent_{name}_exit", exit_code),
                             (f"agent_{name}_duration", round(duration, 1))):
        body = json.dumps({
            "sensor_id": sensor_id,
            "sensor_namespace": namespace,
            "sensor_value": value,
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=rest["timeout"]):
                pass
        except (urllib.error.URLError, OSError) as exc:
            print(f"[{name}] Status-Meldung {sensor_id} fehlgeschlagen: {exc}", file=sys.stderr)


def run_agent(cfg: dict, name: str, agent: dict, results: dict) -> None:
    """Fuehrt einen Agenten aus, wenn er nicht schon laeuft. Ergebnis in results[name].
    Kann der Runner seine Dateien nicht schreiben (z.B. nach Wechsel zwischen
    root und normalem Benutzer), wird das als Exit 125 gemeldet statt still
    abzubrechen."""
    try:
        _run_agent(cfg, name, agent, results)
    except OSError as exc:
        print(f"[{name}] Runner-Fehler: {exc}", file=sys.stderr, flush=True)
        push_status(cfg, name, RUNNER_ERROR_EXIT, 0.0)
        results[name] = f"exit={RUNNER_ERROR_EXIT} Runner-Fehler: {exc}"


def _run_agent(cfg: dict, name: str, agent: dict, results: dict) -> None:
    log_dir = cfg["log_dir"]
    lock_path = log_dir / f"{name}.lock"
    log_path = log_dir / f"{name}.log"

    with open(lock_path, "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            results[name] = "laeuft noch"
            return
        lock.seek(0)
        lock.truncate()
        lock.write(str(time.time()))
        lock.flush()

        rotate_log(log_path)
        timeout = agent.get("timeout_seconds", 300)
        command = agent.get("command", [f"{name}/run.sh"])
        start = time.monotonic()
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"===== {now_str()} start: {' '.join(command)}\n")
            log.flush()
            try:
                # eigene Prozessgruppe, damit der Timeout auch Kindprozesse beendet
                # REST-Zugang aus agents.json als IOT_REST_* an den Agenten geben
                proc = subprocess.Popen(command, cwd=BASE_DIR, stdout=log,
                                        stderr=subprocess.STDOUT, start_new_session=True,
                                        env={**os.environ, **rest_env(cfg)})
                try:
                    exit_code = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    exit_code = TIMEOUT_EXIT
                    log.write(f"Timeout nach {timeout} s, abgebrochen\n")
            except OSError as exc:  # Befehl nicht gefunden o.ae.
                log.write(f"Start fehlgeschlagen: {exc}\n")
                exit_code = 127
            duration = time.monotonic() - start
            log.write(f"===== {now_str()} ende: exit={exit_code} dauer={duration:.1f}s\n")
        # Ergebnis des letzten Laufs fuer --list
        (log_dir / f"{name}.status").write_text(json.dumps(
            {"exit": exit_code, "duration": round(duration, 1), "end": time.time()}))

    push_status(cfg, name, exit_code, duration)
    results[name] = f"exit={exit_code} dauer={duration:.1f}s"


def is_running(lock_path: Path) -> bool:
    """True, wenn ein Runner die Sperre des Agenten gerade haelt."""
    if not lock_path.exists():
        return False
    with open(lock_path) as lock:
        try:
            # geteilte Sperre kollidiert nur mit der exklusiven eines laufenden Agenten
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(lock, fcntl.LOCK_UN)
    return False


def fmt_seconds(seconds: float) -> str:
    return f"{seconds:.0f} s" if seconds < 60 else f"{seconds / 60:.0f} min"


def list_agents(cfg: dict) -> None:
    now = time.time()
    for name, agent in cfg["agents"].items():
        lock_path = cfg["log_dir"] / f"{name}.lock"
        ts = last_start(lock_path)
        last = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "nie"
        state = "aktiv" if agent.get("enabled") else "aus"
        info = []
        if is_running(lock_path):
            info.append(f"laeuft seit {fmt_seconds(now - ts)}")
        else:
            try:
                st = json.loads((cfg["log_dir"] / f"{name}.status").read_text())
                info.append(f"exit={st['exit']} ({st['duration']}s)")
            except (OSError, ValueError, KeyError):
                pass
            if agent.get("enabled") and is_due(agent, lock_path, now):
                info.append("faellig")
        print(f"{name:15} {state:5} alle {agent.get('every_minutes', 60):>4} min  "
              f"letzter Start: {last}  {'  '.join(info)}".rstrip())


def due_agents(cfg: dict) -> list:
    now = time.time()
    return [n for n, a in cfg["agents"].items()
            if a.get("enabled") and is_due(a, cfg["log_dir"] / f"{n}.lock", now)]


def run_daemon(config_path: Path) -> None:
    """
    Dauerbetrieb: prueft zu jeder vollen Minute, welche Agenten faellig sind,
    und startet jeden in einem eigenen Thread - ein langer Scan haelt die
    anderen Agenten nicht auf. agents.json wird jedes Mal neu gelesen, damit
    Aenderungen ohne Neustart wirken.
    """
    running = {}  # name -> Thread

    def run_and_report(cfg, name, agent):
        results = {}
        try:
            run_agent(cfg, name, agent, results)
        except Exception as exc:  # Thread soll den Fehler nicht verschlucken
            results[name] = f"unerwarteter Fehler: {exc!r}"
        print(f"{name}: {results.get(name)}", flush=True)

    print(f"Runner gestartet ({config_path})", flush=True)
    while True:
        try:
            cfg = load_config(config_path)
            for name in due_agents(cfg):
                if name in running and running[name].is_alive():
                    continue  # laeuft noch aus einer frueheren Minute
                running[name] = threading.Thread(
                    target=run_and_report, args=(cfg, name, cfg["agents"][name]), daemon=True)
                running[name].start()
        except Exception as exc:  # z.B. agents.json gerade halb gespeichert
            print(f"Fehler im Runner: {exc}", file=sys.stderr, flush=True)
        time.sleep(60 - time.time() % 60)  # bis zur naechsten vollen Minute


def main():
    ap = argparse.ArgumentParser(description="Zentraler Runner fuer die IoT-Agenten")
    ap.add_argument("--config", default=str(BASE_DIR / "agents.json"))
    ap.add_argument("--run", metavar="NAME", help="Agenten sofort ausfuehren")
    ap.add_argument("--all", action="store_true",
                    help="alle aktiven Agenten sofort ausfuehren (Intervall egal)")
    ap.add_argument("--list", action="store_true", help="Status aller Agenten anzeigen")
    ap.add_argument("--daemon", action="store_true",
                    help="dauerhaft laufen und jede Minute faellige Agenten starten")
    args = ap.parse_args()

    config_path = Path(args.config).resolve()

    if args.daemon:
        run_daemon(config_path)
        return

    cfg = load_config(config_path)
    agents = cfg["agents"]

    if args.list:
        list_agents(cfg)
        return

    if args.run:
        if args.run not in agents:
            sys.exit(f"Unbekannter Agent: {args.run} (bekannt: {', '.join(agents)})")
        todo = [args.run]
    elif args.all:
        todo = [n for n, a in agents.items() if a.get("enabled")]
    else:
        todo = due_agents(cfg)

    # parallel, damit ein langer Scan die anderen Agenten nicht aufhaelt
    results = {}
    threads = [threading.Thread(target=run_agent, args=(cfg, n, agents[n], results))
               for n in todo]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for name in todo:
        print(f"{name}: {results.get(name)}")
    if any(not r.startswith("exit=0") for r in results.values() if r != "laeuft noch"):
        sys.exit(1)


if __name__ == "__main__":
    main()
