#!/usr/bin/env python3
"""
run_agents.py - Zentraler Runner fuer die Agenten unter agents/.

Wird per Cron jede Minute gestartet und fuehrt jeden aktiven Agenten aus
agents.json aus, dessen Intervall abgelaufen ist:

    * * * * * python3 /pfad/zu/agents/run_agents.py

Jeder Agent ist ein Ordner unter agents/ mit einer run.sh, die gestartet
wird. Mit "command" in agents.json laesst sich ein anderer Befehl angeben.

Pro Agent:
  - Sperrdatei, damit ein noch laufender Agent nicht doppelt startet
  - Timeout, der die ganze Prozessgruppe beendet (auch Kindprozesse)
  - eigene Logdatei <log_dir>/<name>.log
  - optional Meldung von Exit-Code und Laufzeit nach iot_sensor_data
    (sensor_id agent_<name>_exit / agent_<name>_duration)

Weitere Aufrufe:
    python3 run_agents.py --list         Status aller Agenten anzeigen
    python3 run_agents.py --run nmap     Agenten sofort ausfuehren (auch wenn deaktiviert)
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
TIMEOUT_EXIT = 124       # wie timeout(1)
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
    rest = cfg.get("rest")
    if not rest or not rest.get("apikey"):
        return
    headers = {"Content-Type": "application/json", "apikey": rest["apikey"]}
    for sensor_id, value in ((f"agent_{name}_exit", exit_code),
                             (f"agent_{name}_duration", round(duration, 1))):
        body = json.dumps({
            "sensor_id": sensor_id,
            "sensor_namespace": rest.get("namespace", "agents"),
            "sensor_value": value,
        }).encode("utf-8")
        req = urllib.request.Request(rest["url"].rstrip("/"), data=body,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=rest.get("timeout", 10)):
                pass
        except (urllib.error.URLError, OSError) as exc:
            print(f"[{name}] Status-Meldung {sensor_id} fehlgeschlagen: {exc}", file=sys.stderr)


def run_agent(cfg: dict, name: str, agent: dict, results: dict) -> None:
    """Fuehrt einen Agenten aus, wenn er nicht schon laeuft. Ergebnis in results[name]."""
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
                proc = subprocess.Popen(command, cwd=BASE_DIR, stdout=log,
                                        stderr=subprocess.STDOUT, start_new_session=True)
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

    push_status(cfg, name, exit_code, duration)
    results[name] = f"exit={exit_code} dauer={duration:.1f}s"


def list_agents(cfg: dict) -> None:
    now = time.time()
    for name, agent in cfg["agents"].items():
        lock_path = cfg["log_dir"] / f"{name}.lock"
        ts = last_start(lock_path)
        last = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "nie"
        state = "aktiv" if agent.get("enabled") else "aus"
        due = "faellig" if agent.get("enabled") and is_due(agent, lock_path, now) else ""
        print(f"{name:15} {state:5} alle {agent.get('every_minutes', 60):>4} min  "
              f"letzter Start: {last}  {due}")


def main():
    ap = argparse.ArgumentParser(description="Zentraler Runner fuer die IoT-Agenten")
    ap.add_argument("--config", default=str(BASE_DIR / "agents.json"))
    ap.add_argument("--run", metavar="NAME", help="Agenten sofort ausfuehren")
    ap.add_argument("--list", action="store_true", help="Status aller Agenten anzeigen")
    args = ap.parse_args()

    cfg = load_config(Path(args.config).resolve())
    agents = cfg["agents"]

    if args.list:
        list_agents(cfg)
        return

    if args.run:
        if args.run not in agents:
            sys.exit(f"Unbekannter Agent: {args.run} (bekannt: {', '.join(agents)})")
        todo = [args.run]
    else:
        now = time.time()
        todo = [n for n, a in agents.items()
                if a.get("enabled") and is_due(a, cfg["log_dir"] / f"{n}.lock", now)]

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
