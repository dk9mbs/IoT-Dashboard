#!/usr/bin/env python3
"""
Ermittelt die Festplattenbelegung des ausführenden Rechners als Messwerte für
iot_sensor_data.

Ausgabetyp 2 (Add Sensor Value): das Ergebnis geht als JSON {"data": [...]} auf
stdout, der Runner schreibt es nach iot_sensor_data; Log-Meldungen auf stderr.

Sensor-ID je Mountpoint und Kennzahl:
    disk_<host>_<mount>[_<kennzahl>]
    z.B. disk_nextcloud_root (belegt in %), disk_nextcloud_var_free_gb

Die Sensoren müssen vorher in iot_sensor angelegt sein, sonst lehnt der
REST-Service den Messwert ab ("Sensor not registered").

Nutzung:
    python3 disk_usage.py                 Einstellungen vom Agenten-Runner
    python3 disk_usage.py 2>/dev/null     nur das JSON-Ergebnis anzeigen

Einstellungen (IOT_AGENT_SETTINGS, siehe settings.json.skelet):
    host        Name in der Sensor-ID (Standard: Hostname ohne Domain)
    mounts      zu messende Mountpoints; leer = alle echten Dateisysteme
    metrics     Kennzahlen: used_percent, free_gb, used_gb, total_gb
                (Standard ["used_percent"])
    namespace   sensor_namespace der Messwerte (Standard "disk")
"""

import re
import shutil
import socket
import sys

from dk9mbs_iot.agent import log, settings_from_env, write_output  # vom Agenten-Runner

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
    settings = settings_from_env()
    host = sensor_name(settings.get("host") or socket.gethostname().split(".")[0])
    mounts = settings.get("mounts") or real_mountpoints()
    metric_names = settings.get("metrics") or ["used_percent"]
    namespace = settings.get("namespace", "disk")

    unknown = [m for m in metric_names if m not in METRICS]
    if unknown:
        log(f"Fehler: unbekannte Kennzahl(en) {unknown}, erlaubt: {list(METRICS)}")
        return 1

    errors = 0
    output = []
    for mountpoint in mounts:
        try:
            usage = shutil.disk_usage(mountpoint)
        except OSError as e:
            errors += 1
            log(f"{mountpoint}: nicht lesbar ({e})")
            continue
        log(f"{mountpoint}: {METRICS['used_percent'][1](usage)} % belegt, "
            f"{usage.free / GB:.1f} von {usage.total / GB:.1f} GB frei")
        for metric in metric_names:
            suffix, compute = METRICS[metric]
            output.append({"id": f"disk_{host}_{sensor_name(mountpoint)}{suffix}",
                           "value": compute(usage), "namespace": namespace})

    write_output(output)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
