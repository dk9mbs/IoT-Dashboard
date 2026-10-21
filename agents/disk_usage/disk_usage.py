#!/usr/bin/env python3
"""
Ermittelt die Festplattenbelegung des ausführenden Rechners und schreibt sie
als Messwerte nach iot_sensor_data (wie omada_syslog den WLAN-Score).

Sensor-ID je Mountpoint und Kennzahl:
    disk_<host>_<mount>[_<kennzahl>]
    z.B. disk_nextcloud_root (belegt in %), disk_nextcloud_var_free_gb

Die Sensoren müssen vorher in iot_sensor angelegt sein, sonst lehnt der
REST-Service den Messwert ab ("Sensor not registered").

Nutzung:
    python3 disk_usage.py              REST-Zugang und Einstellungen vom Agenten-Runner
    python3 disk_usage.py --no-rest    nur ermitteln und ausgeben, nichts senden

Einstellungen (IOT_AGENT_SETTINGS, siehe settings.json.skelet):
    host        Name in der Sensor-ID (Standard: Hostname ohne Domain)
    mounts      zu messende Mountpoints; leer = alle echten Dateisysteme
    metrics     Kennzahlen: used_percent, free_gb, used_gb, total_gb
                (Standard ["used_percent"])
    namespace   sensor_namespace der Messwerte (Standard "disk")
"""

import argparse
import re
import shutil
import socket
import sys

import requests

from dk9mbs_iot.agent import rest_from_env, settings_from_env  # vom Agenten-Runner

# Pseudo- und Netz-Dateisysteme, die bei automatischer Auswahl nicht zählen
IGNORED_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "securityfs", "cgroup", "cgroup2",
    "pstore", "bpf", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs",
    "autofs", "binfmt_misc", "rpc_pipefs", "nsfs", "efivarfs", "ramfs", "squashfs",
    "overlay", "fuse.gvfsd-fuse", "fuse.portal", "nfs", "nfs4", "cifs", "smbfs", "nfsd",
}

GB = 1024 ** 3

METRICS = {
    # Name: (Suffix der Sensor-ID, Berechnung aus shutil.disk_usage)
    "used_percent": ("", lambda u: round(u.used / u.total * 100, 1) if u.total else 0.0),
    "free_gb": ("_free_gb", lambda u: round(u.free / GB, 2)),
    "used_gb": ("_used_gb", lambda u: round(u.used / GB, 2)),
    "total_gb": ("_total_gb", lambda u: round(u.total / GB, 2)),
}


def real_mountpoints() -> list:
    """Mountpoints aus /proc/mounts ohne Pseudo-/Netz-Dateisysteme, je Gerät nur einmal."""
    mounts, devices = [], set()
    with open("/proc/mounts", encoding="utf-8") as file:
        for line in file:
            device, mountpoint, fs_type = line.split()[:3]
            mountpoint = mountpoint.replace("\\040", " ")
            if fs_type in IGNORED_FS or device in devices:
                continue
            try:
                if shutil.disk_usage(mountpoint).total == 0:
                    continue
            except OSError:
                continue
            devices.add(device)
            mounts.append(mountpoint)
    return mounts


def sensor_name(mountpoint: str) -> str:
    """'/' -> 'root', '/var/lib' -> 'var_lib'."""
    name = re.sub(r"[^a-z0-9]+", "_", mountpoint.lower()).strip("_")
    return name or "root"


def main() -> int:
    parser = argparse.ArgumentParser(description="Ermittelt die Festplattenbelegung.")
    parser.add_argument("--no-rest", action="store_true",
                        help="nur ermitteln und ausgeben, nichts an den REST-Service senden")
    args = parser.parse_args()

    settings = settings_from_env()
    host = sensor_name(settings.get("host") or socket.gethostname().split(".")[0])
    mounts = settings.get("mounts") or real_mountpoints()
    metric_names = settings.get("metrics") or ["used_percent"]
    namespace = settings.get("namespace", "disk")

    unknown = [m for m in metric_names if m not in METRICS]
    if unknown:
        print(f"Fehler: unbekannte Kennzahl(en) {unknown}, erlaubt: {list(METRICS)}")
        return 1

    rest = None
    if not args.no_rest:
        try:
            rest = rest_from_env()
        except RuntimeError as e:
            print(f"Fehler: {e}")
            return 1

    errors = 0
    for mountpoint in mounts:
        try:
            usage = shutil.disk_usage(mountpoint)
        except OSError as e:
            errors += 1
            print(f"{mountpoint}: nicht lesbar ({e})")
            continue
        print(f"{mountpoint}: {METRICS['used_percent'][1](usage)} % belegt, "
              f"{usage.free / GB:.1f} von {usage.total / GB:.1f} GB frei")
        if rest is None:
            continue
        for metric in metric_names:
            suffix, compute = METRICS[metric]
            sensor_id = f"disk_{host}_{sensor_name(mountpoint)}{suffix}"
            try:
                response = requests.post(
                    f"{rest['base_url']}/data/iot_sensor_data",
                    json={"sensor_id": sensor_id, "sensor_namespace": namespace,
                          "sensor_value": compute(usage)},
                    headers={"apikey": rest["apikey"]}, timeout=rest["timeout"])
                if not response.ok:
                    errors += 1
                    print(f"  -> {sensor_id}: Status {response.status_code} {response.text[:200]}")
            except requests.exceptions.RequestException as e:
                errors += 1
                print(f"  -> {sensor_id}: Fehler beim Senden: {e}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
