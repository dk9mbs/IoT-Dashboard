#!/usr/bin/env python3
"""
Netzwerk-Scanner mit dem python-nmap Modul.

Voraussetzungen:
    - nmap muss auf dem System installiert sein (z.B. `apt install nmap` auf Debian/Ubuntu)
    - python-nmap Modul: `pip install python-nmap`
    - requests Modul: `pip install requests`
    - Für einige Scan-Typen (z.B. -O für OS-Erkennung) werden Root-Rechte benötigt (sudo)

Nutzung:
    python3 iptest_v2.py
    python3 iptest_v2.py --netz 192.168.1.0/24
    python3 iptest_v2.py --netz 192.168.1.0/24 --args "-O -sV"
    python3 iptest_v2.py 2>/dev/null      nur das JSON-Ergebnis anzeigen

    Einstellungen (IOT_AGENT_SETTINGS, z.B. {"netz": "192.168.2.0/24",
    "args": "-sn"}) gibt der Agenten-Runner mit; mit --netz / --args lässt
    sich das überschreiben.

    Ausgabetyp 3 (Add/Update Device): jedes gefundene Gerät geht als Eintrag
    in {"data": [...]} auf stdout, der Runner legt es in iot_device an bzw.
    aktualisiert es (Suche über die MAC, sonst die ID); Log-Meldungen auf stderr.
    ID ist die MAC-Adresse, der Hostname steht in host_name. Shellys (Hostname
    beginnt mit "shelly") behalten den Hostnamen als ID und bekommen den
    Hersteller shelly, alle anderen den Hersteller dk9mbs (vendor_id und name
    setzt der Runner nur bei der Neuanlage, name = Hostname bzw. ID; danach
    wird er manuell gepflegt). WLAN-, Firmware- und Update-Daten der Shellys
    holt der Agent agents/shelly.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    import nmap
except ImportError:
    print("Fehler: Das Modul 'python-nmap' ist nicht installiert.", file=sys.stderr)
    print("Installation mit: pip install python-nmap", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Fehler: Das Modul 'requests' ist nicht installiert.", file=sys.stderr)
    print("Installation mit: pip install requests", file=sys.stderr)
    sys.exit(1)

from dk9mbs_iot.agent import log, settings_from_env, write_output  # vom Agenten-Runner

# Mitteleuropäische Zeitzone (berücksichtigt automatisch MEZ/MESZ-Umstellung)
MITTELEUROPA = ZoneInfo("Europe/Berlin")


def host_zu_dict(host: str, host_info) -> dict:
    """
    Wandelt die nmap-Ergebnisse eines einzelnen Hosts in ein serialisierbares
    Dictionary um, das per REST-POST verschickt werden kann.
    """
    daten = {
        "ip": host,
        "hostname": host_info.hostname() or None,
        "status": host_info.state(),
        "mac": None,
        "vendor": None,
        "ports": [],
        "zeitstempel": datetime.now(MITTELEUROPA).isoformat(),
    }

    if "mac" in host_info["addresses"]:
        mac = host_info["addresses"]["mac"]
        daten["mac"] = mac
        daten["vendor"] = host_info.get("vendor", {}).get(mac)

    for protokoll in host_info.all_protocols():
        for port in sorted(host_info[protokoll].keys()):
            port_info = host_info[protokoll][port]
            if port_info["state"] == "open":
                daten["ports"].append(
                    {
                        "port": port,
                        "protokoll": protokoll,
                        "dienst": port_info.get("name", "unbekannt"),
                    }
                )

    return daten


# Zeitstempel (float, time.time()) der letzten Anfrage an api.macvendors.com,
# um den Mindestabstand von 1 Sekunde zwischen Anfragen einzuhalten.
_letzte_macvendors_anfrage = 0.0

# Dauerhafter Cache der Hersteller pro OUI (erste 3 Bytes der MAC), damit
# api.macvendors.com (max. 1000 Anfragen/Tag) nur fuer neue Hersteller gefragt wird.
VENDOR_CACHE_DATEI = Path(__file__).resolve().parent / "vendor_cache.json"
_vendor_cache = None
# nach erschoepftem Rate-Limit die API fuer den Rest des Laufs nicht mehr fragen
_macvendors_gesperrt = False


def _lade_vendor_cache() -> dict:
    global _vendor_cache
    if _vendor_cache is None:
        try:
            _vendor_cache = json.loads(VENDOR_CACHE_DATEI.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _vendor_cache = {}
    return _vendor_cache


def _speichere_vendor_cache() -> None:
    try:
        VENDOR_CACHE_DATEI.write_text(json.dumps(_vendor_cache, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    except OSError as e:
        log(f"  -> Warnung: Hersteller-Cache konnte nicht gespeichert werden: {e}")


def hersteller_von_macvendors(mac: str, timeout: int = 5, max_versuche: int = 3) -> str:
    """
    Fragt bei api.macvendors.com den Hersteller zu einer MAC-Adresse ab.
    Bereits bekannte OUIs kommen aus dem Cache (vendor_cache.json), ohne Anfrage.
    Hält dabei automatisch einen Mindestabstand von 1 Sekunde zur vorherigen Anfrage ein
    (Rate-Limit der kostenlosen API) und versucht es bei Status 429 mit steigender
    Wartezeit erneut (bis zu max_versuche mal).
    Gibt den Herstellernamen als String zurück, oder None falls nicht ermittelbar.
    """
    global _letzte_macvendors_anfrage, _macvendors_gesperrt

    if not mac:
        return None

    oui = mac.upper().replace("-", ":")[:8]
    cache = _lade_vendor_cache()
    if oui in cache:
        return cache[oui]  # None = laut API unbekannter Hersteller
    if _macvendors_gesperrt:
        return None

    url = f"https://api.macvendors.com/{mac}"

    for versuch in range(1, max_versuche + 1):
        # Mindestabstand von 1 Sekunde zur letzten Anfrage einhalten
        vergangen = time.time() - _letzte_macvendors_anfrage
        if vergangen < 1.0:
            time.sleep(1.0 - vergangen)

        try:
            antwort = requests.get(url, timeout=timeout)
            _letzte_macvendors_anfrage = time.time()

            if antwort.status_code == 200:
                cache[oui] = antwort.text.strip()
                _speichere_vendor_cache()
                return cache[oui]
            elif antwort.status_code == 404:
                # Hersteller für diese MAC-Adresse nicht bekannt
                cache[oui] = None
                _speichere_vendor_cache()
                return None
            elif antwort.status_code == 429:
                wartezeit = versuch * 2  # 2s, 4s, 6s ...
                log(f"  -> Rate-Limit bei api.macvendors.com (MAC {mac}), warte {wartezeit}s und versuche erneut ({versuch}/{max_versuche})")
                time.sleep(wartezeit)
                continue
            else:
                log(f"  -> Warnung: api.macvendors.com lieferte Status {antwort.status_code} für MAC {mac}")
                return None
        except requests.exceptions.RequestException as e:
            _letzte_macvendors_anfrage = time.time()
            log(f"  -> Fehler bei Abfrage von api.macvendors.com für MAC {mac}: {e}")
            return None

    log(f"  -> Kein Hersteller ermittelt (Rate-Limit trotz {max_versuche} Versuchen) für MAC {mac}, "
          f"api.macvendors.com wird in diesem Lauf nicht mehr gefragt")
    _macvendors_gesperrt = True
    return None


# Hersteller (iot_device_vendor.id) fuer Geraete, die keine Shellys sind
HERSTELLER_SONSTIGE = "dk9mbs"


def ist_shelly(daten: dict) -> bool:
    return (daten.get("hostname") or "").lower().startswith("shelly")


def geraete_id(daten: dict):
    """
    ID in iot_device: bei Shellys der Hostname (enthält die MAC, daran hängen
    Dashboard und Sensoren), sonst die MAC-Adresse. None, wenn sie fehlt.
    """
    if ist_shelly(daten):
        return daten.get("hostname")
    return daten.get("mac")


def build_device_entry(daten: dict, product_id: str = None) -> dict:
    """
    Eintrag für den Runner (Ausgabetyp Add/Update Device): id (siehe geraete_id),
    address (IP-Adresse), last_scan_on (aktueller Zeitstempel, mitteleuropäische
    Zeit), vendor_id ('shelly' bzw. HERSTELLER_SONSTIGE, nur bei Neuanlage),
    dazu product_id (Hersteller laut api.macvendors.com bzw. nmap), mac und
    host_name, wenn bekannt - sonst bleiben die gespeicherten Werte erhalten.
    name ist nicht enthalten: den setzt der Runner bei der Neuanlage.
    """
    entry = {
        "id": geraete_id(daten),
        "address": daten.get("ip"),
        "last_scan_on": datetime.now(MITTELEUROPA).strftime("%Y-%m-%d %H:%M:%S"),
        "vendor_id": "shelly" if ist_shelly(daten) else HERSTELLER_SONSTIGE,
    }
    # ohne ermittelten Hersteller den gespeicherten Wert nicht mit null ueberschreiben
    if product_id:
        entry["product_id"] = product_id
    # MAC nur, wenn nmap sie ermitteln konnte (ohne root bzw. ausserhalb des
    # eigenen Netzsegments liefert nmap keine) - sonst bleibt der gespeicherte Wert
    if daten.get("mac"):
        entry["mac"] = daten["mac"]
    # Hostname ebenso nur, wenn bekannt (DNS/DHCP liefert nicht immer einen)
    if daten.get("hostname"):
        entry["host_name"] = daten["hostname"]
    return entry


def product_id_of(daten: dict):
    """Hersteller zur MAC: api.macvendors.com, sonst die Angabe von nmap."""
    product_id = hersteller_von_macvendors(daten.get("mac"))
    if product_id:
        log(f"  -> Hersteller laut macvendors.com: {product_id}")
    elif daten.get("vendor"):
        product_id = daten["vendor"]
        log(f"  -> Hersteller laut nmap: {product_id}")
    return product_id


def scan_netzwerk(netzwerk: str, scan_argumente: str = "-sn") -> list:
    """
    Führt einen nmap-Scan über das angegebene Netzwerk durch.

    :param netzwerk: Netzwerk in CIDR-Notation, z.B. '192.168.1.0/24'
    :param scan_argumente: nmap-Argumente. Standard '-sn' = Ping-Scan (nur Host-Discovery, kein Portscan)
    :return: Einträge für den Runner (siehe build_device_entry), je Gerät mit bekannter ID
    """
    scanner = nmap.PortScanner()

    log(f"Starte Scan von '{netzwerk}' mit Argumenten '{scan_argumente}' ...")
    start_zeit = datetime.now()

    try:
        scanner.scan(hosts=netzwerk, arguments=scan_argumente)
    except nmap.PortScannerError as e:
        log(f"Fehler beim Scannen: {e}")
        log("Hinweis: Manche Scan-Optionen (z.B. -O, SYN-Scan) benötigen Root-Rechte (sudo).")
        sys.exit(1)

    dauer = (datetime.now() - start_zeit).total_seconds()
    hosts_liste = scanner.all_hosts()

    log(f"\nScan abgeschlossen in {dauer:.2f} Sekunden.")
    log(f"Gefundene aktive Hosts: {len(hosts_liste)}\n")

    output = []
    if not hosts_liste:
        log("Keine aktiven Hosts gefunden.")
        return output

    for host in sorted(hosts_liste, key=lambda ip: [int(part) for part in ip.split(".")] if ip.count(".") == 3 else [0]):
        host_info = scanner[host]
        daten = host_zu_dict(host, host_info)

        log(f"IP-Adresse:  {daten['ip']}")
        log(f"Hostname:    {daten['hostname'] or '-'}")
        log(f"Status:      {daten['status']}")

        if daten["mac"]:
            log(f"MAC-Adresse: {daten['mac']}")
            if daten["vendor"]:
                log(f"Hersteller:  {daten['vendor']}")

        if daten["ports"]:
            log("Offene Ports:")
            for p in daten["ports"]:
                log(f"  {p['port']}/{p['protokoll']}  {p['dienst']}")

        # Jedes Gerät in iot_device eintragen bzw. aktualisieren - ID ist die MAC
        # (Shellys: Hostname); ohne sie lässt sich das Gerät nicht sicher zuordnen
        # (nmap sieht keine MAC ausserhalb des eigenen Netzsegments und fuer den
        # scannenden Rechner selbst)
        if geraete_id(daten):
            output.append(build_device_entry(daten, product_id_of(daten)))
        else:
            log("  -> Übersprungen: MAC-Adresse nicht bekannt")

        log("-" * 40)

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Führt einen IP-Scan über ein bestimmtes Netzwerk mit nmap durch."
    )
    parser.add_argument(
        "--netz",
        "-n",
        default=None,
        help="Zu scannendes Netzwerk in CIDR-Notation (Standard: Einstellung 'netz', sonst 192.168.1.0/24)",
    )
    parser.add_argument(
        "--args",
        "-a",
        dest="scan_argumente",
        default=None,
        help=(
            "nmap-Argumente (Standard: Einstellung 'args', sonst '-sn' = reiner Ping-Scan/Host-Discovery). "
            "Beispiele: '-sV' (Service-Erkennung), '-O' (OS-Erkennung, benötigt sudo), "
            "'-p 1-1000' (Portbereich)"
        ),
    )
    argumente = parser.parse_args()

    # Einstellungen zentral aus iot_agent_config (vom Runner), Kommandozeile hat Vorrang
    settings = settings_from_env()
    netz = argumente.netz or settings.get("netz") or "192.168.1.0/24"
    scan_argumente = argumente.scan_argumente or settings.get("args") or "-sn"

    output = scan_netzwerk(netz, scan_argumente)
    write_output(output, f"{len(output)} Geraet(e) in {netz}")


if __name__ == "__main__":
    main()
