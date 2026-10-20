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
    python3 iptest_v2.py --netz 192.168.1.0/24 --no-rest

    REST-Zugang (IOT_REST_*) und Einstellungen (IOT_AGENT_SETTINGS, z.B.
    {"netz": "192.168.2.0/24", "args": "-sn"}) gibt der Agenten-Runner mit;
    mit --netz / --args / --rest-url /
    --apikey lässt sich das überschreiben. Jedes gefundene Gerät wird in
    iot_device angelegt bzw. aktualisiert (ID: MAC-Adresse, Hostname in host_name).
    Shellys (Hostname beginnt mit "shelly") behalten den Hostnamen als ID und
    bekommen den Hersteller shelly, alle anderen den Hersteller dk9mbs. WLAN-,
    Firmware- und Update-Daten der Shellys holt der Agent agents/shelly. Den
    Namen (name) setzt nmap nur bei der Neuanlage, danach wird er manuell gepflegt.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote
from xml.sax.saxutils import quoteattr
from zoneinfo import ZoneInfo

try:
    import nmap
except ImportError:
    print("Fehler: Das Modul 'python-nmap' ist nicht installiert.")
    print("Installation mit: pip install python-nmap")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Fehler: Das Modul 'requests' ist nicht installiert.")
    print("Installation mit: pip install requests")
    sys.exit(1)

from dk9mbs_iot.agent import rest_from_env, settings_from_env  # vom Agenten-Runner

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
        print(f"  -> Warnung: Hersteller-Cache konnte nicht gespeichert werden: {e}")


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
                print(f"  -> Rate-Limit bei api.macvendors.com (MAC {mac}), warte {wartezeit}s und versuche erneut ({versuch}/{max_versuche})")
                time.sleep(wartezeit)
                continue
            else:
                print(f"  -> Warnung: api.macvendors.com lieferte Status {antwort.status_code} für MAC {mac}")
                return None
        except requests.exceptions.RequestException as e:
            _letzte_macvendors_anfrage = time.time()
            print(f"  -> Fehler bei Abfrage von api.macvendors.com für MAC {mac}: {e}")
            return None

    print(f"  -> Kein Hersteller ermittelt (Rate-Limit trotz {max_versuche} Versuchen) für MAC {mac}, "
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


def erstelle_rest_payload(daten: dict, product_id: str = None) -> dict:
    """
    Erstellt das JSON-Payload für den PUT-Aufruf (Aktualisierung) aus den vollständigen
    Host-Daten. Enthält: id (siehe geraete_id), address (IP-Adresse), last_scan_on
    (aktueller Zeitstempel, mitteleuropäische Zeit), product_id (Hersteller laut
    api.macvendors.com), mac und host_name, wenn nmap sie ermitteln konnte.
    name ist nicht enthalten - der wird manuell gepflegt.
    """
    payload = {
        "id": geraete_id(daten),
        "address": daten.get("ip"),
        "last_scan_on": datetime.now(MITTELEUROPA).strftime("%Y-%m-%d %H:%M:%S"),
    }
    # ohne ermittelten Hersteller den gespeicherten Wert nicht mit null ueberschreiben
    if product_id:
        payload["product_id"] = product_id
    # MAC nur, wenn nmap sie ermitteln konnte (ohne root bzw. ausserhalb des
    # eigenen Netzsegments liefert nmap keine) - sonst bleibt der gespeicherte Wert
    if daten.get("mac"):
        payload["mac"] = daten["mac"]
    # Hostname ebenso nur, wenn bekannt (DNS/DHCP liefert nicht immer einen)
    if daten.get("hostname"):
        payload["host_name"] = daten["hostname"]
    return payload


def erstelle_neuanlage_payload(daten: dict, product_id: str = None) -> dict:
    """
    Erstellt das JSON-Payload für den POST-Aufruf (Neuanlage): wie beim PUT, dazu
    name (Vorbelegung: Hostname, sonst ID) und vendor_id ('shelly' bzw.
    HERSTELLER_SONSTIGE).
    """
    payload = erstelle_rest_payload(daten, product_id)
    payload["name"] = daten.get("hostname") or geraete_id(daten)
    payload["vendor_id"] = "shelly" if ist_shelly(daten) else HERSTELLER_SONSTIGE
    return payload


def _rest_header(apikey: str) -> dict:
    return {"apikey": apikey or ""}


def finde_datensatz(rest_url: str, feld: str, wert: str, apikey: str, timeout: int = 5):
    """
    Sucht per XML-SELECT an '<.../data>' in der Tabelle (letzter Teil von rest_url,
    z.B. iot_device) einen Datensatz mit feld = wert.
    Ein GET auf '<rest_url>/<id>' braucht beim REST-Service zusätzlich Leserechte
    auf api_http_header, die der API-Key-Benutzer nicht hat.
    Gibt die ID des Datensatzes zurück, "" wenn es keinen gibt, oder None, wenn
    die Suche fehlschlug.
    """
    data_url, _, tabelle = rest_url.rstrip("/").rpartition("/")
    xml = (
        f'<restapi type="select"><table name={quoteattr(tabelle)} alias="a"/>'
        f'<filter type="and"><condition field={quoteattr(feld)} value={quoteattr(wert)} operator="eq" />'
        f"</filter></restapi>"
    )
    header = {**_rest_header(apikey), "Content-Type": "application/xml"}

    try:
        antwort = requests.post(data_url, data=xml.encode("utf-8"), headers=header, timeout=timeout)
        if not antwort.ok:
            print(f"  -> Suche {tabelle} {feld}={wert} fehlgeschlagen (Status {antwort.status_code}): {antwort.text[:200]}")
            return None
        treffer = antwort.json()
        return str(treffer[0]["id"]) if treffer else ""
    except (requests.exceptions.RequestException, ValueError, KeyError) as e:
        print(f"  -> Fehler bei der Suche {tabelle} {feld}={wert}: {e}")
        return None


def datensatz_id(rest_url: str, daten: dict, apikey: str, timeout: int = 5):
    """
    ID des vorhandenen Datensatzes: zuerst über die MAC (so entsteht kein zweiter
    Eintrag, wenn ein Gerät später einen Hostnamen bekommt), sonst über die ID.
    "" = nicht vorhanden, None = Suche fehlgeschlagen.
    """
    if daten.get("mac"):
        gefunden = finde_datensatz(rest_url, "mac", daten["mac"], apikey, timeout)
        if gefunden is None or gefunden:
            return gefunden
    return finde_datensatz(rest_url, "id", geraete_id(daten), apikey, timeout)


def sende_an_rest_service(daten: dict, rest_url: str, apikey: str, timeout: int = 5) -> None:
    """
    Trägt ein gefundenes Gerät in iot_device ein bzw. aktualisiert es.
    Fragt bei api.macvendors.com den Hersteller zur MAC-Adresse ab (Feld product_id).
    Danach:
    - Datensatz vorhanden (gesucht über MAC, sonst ID): PUT an '<Basis-URL>/<ID>'.
    - Nicht vorhanden: POST an die Basis-URL (ohne ID, ohne abschließenden '/'),
      zusätzlich mit name (Vorbelegung) und vendor_id ('shelly', sonst
      HERSTELLER_SONSTIGE).
    - Suche fehlgeschlagen: nichts senden (sonst drohen doppelte Datensätze).
    Angemeldet wird mit dem Header 'apikey'.
    """
    basis_url = rest_url.rstrip('/')

    hersteller = hersteller_von_macvendors(daten.get("mac"))
    if hersteller:
        print(f"  -> Hersteller laut macvendors.com: {hersteller}")
    elif daten.get("vendor"):
        hersteller = daten["vendor"]
        print(f"  -> Hersteller laut nmap: {hersteller}")

    header = _rest_header(apikey)

    vorhandene_id = datensatz_id(rest_url, daten, apikey, timeout)
    if vorhandene_id is None:
        print(f"  -> Übersprungen: {geraete_id(daten)} (Suche in iot_device fehlgeschlagen)")
        return

    try:
        if vorhandene_id:
            payload = erstelle_rest_payload(daten, hersteller)
            payload["id"] = vorhandene_id
            print(f"  -> Aktualisiere: {vorhandene_id}")
            methode, ziel_url = "PUT", f"{basis_url}/{quote(vorhandene_id, safe='')}"
        else:
            payload = erstelle_neuanlage_payload(daten, hersteller)
            print(f"  -> Lege neu an: {payload['id']} (Hersteller {payload['vendor_id']})")
            # Beim Anlegen (POST) wird die ID NICHT an die URL angehängt
            # und die Basis-URL darf nicht mit '/' enden.
            methode, ziel_url = "POST", basis_url
        antwort = requests.request(methode, ziel_url, json=payload, headers=header, timeout=timeout)

        if antwort.ok:
            print(f"  -> {methode} an {ziel_url} erfolgreich (Status {antwort.status_code})")
        else:
            print(f"  -> {methode} an {ziel_url} fehlgeschlagen (Status {antwort.status_code}): {antwort.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"  -> Fehler beim Senden an {rest_url}: {e}")


def scan_netzwerk(netzwerk: str, scan_argumente: str = "-sn", rest_url: str = None, apikey: str = None) -> None:
    """
    Führt einen nmap-Scan über das angegebene Netzwerk durch.

    :param netzwerk: Netzwerk in CIDR-Notation, z.B. '192.168.1.0/24'
    :param scan_argumente: nmap-Argumente. Standard '-sn' = Ping-Scan (nur Host-Discovery, kein Portscan)
    :param rest_url: Optionale URL der REST-Tabelle (z.B. https://host/api/v1.0/data/iot_device).
                      Jeder passende Host wird angelegt bzw. per PUT an '<rest_url>/<id>'
                      aktualisiert. Ohne rest_url wird nur gescannt.
    :param apikey: Wert für den Header 'apikey'
    """
    scanner = nmap.PortScanner()

    print(f"Starte Scan von '{netzwerk}' mit Argumenten '{scan_argumente}' ...")
    start_zeit = datetime.now()

    try:
        scanner.scan(hosts=netzwerk, arguments=scan_argumente)
    except nmap.PortScannerError as e:
        print(f"Fehler beim Scannen: {e}")
        print("Hinweis: Manche Scan-Optionen (z.B. -O, SYN-Scan) benötigen Root-Rechte (sudo).")
        sys.exit(1)

    dauer = (datetime.now() - start_zeit).total_seconds()
    hosts_liste = scanner.all_hosts()

    print(f"\nScan abgeschlossen in {dauer:.2f} Sekunden.")
    print(f"Gefundene aktive Hosts: {len(hosts_liste)}\n")

    if not hosts_liste:
        print("Keine aktiven Hosts gefunden.")
        return

    for host in sorted(hosts_liste, key=lambda ip: [int(part) for part in ip.split(".")] if ip.count(".") == 3 else [0]):
        host_info = scanner[host]
        daten = host_zu_dict(host, host_info)

        print(f"IP-Adresse:  {daten['ip']}")
        print(f"Hostname:    {daten['hostname'] or '-'}")
        print(f"Status:      {daten['status']}")

        if daten["mac"]:
            print(f"MAC-Adresse: {daten['mac']}")
            if daten["vendor"]:
                print(f"Hersteller:  {daten['vendor']}")

        if daten["ports"]:
            print("Offene Ports:")
            for p in daten["ports"]:
                print(f"  {p['port']}/{p['protokoll']}  {p['dienst']}")

        # Jedes Gerät in iot_device eintragen bzw. aktualisieren - ID ist die MAC
        # (Shellys: Hostname); ohne sie lässt sich das Gerät nicht sicher zuordnen
        # (nmap sieht keine MAC ausserhalb des eigenen Netzsegments und fuer den
        # scannenden Rechner selbst)
        if rest_url:
            if geraete_id(daten):
                sende_an_rest_service(daten, rest_url, apikey)
            else:
                print("  -> Übersprungen: MAC-Adresse nicht bekannt")

        print("-" * 40)


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
    parser.add_argument(
        "--rest-url",
        "-r",
        dest="rest_url",
        default=None,
        help="URL der REST-Tabelle (Standard: $IOT_REST_BASE_URL/data/iot_device vom Runner); "
             "alle gefundenen Geräte werden angelegt bzw. aktualisiert",
    )
    parser.add_argument(
        "--apikey",
        default=None,
        help="Wert für den Header 'apikey' (Standard: $IOT_REST_APIKEY vom Runner)",
    )
    parser.add_argument(
        "--no-rest",
        action="store_true",
        help="nur scannen, nichts an den REST-Service senden",
    )

    argumente = parser.parse_args()
    rest_url, apikey = argumente.rest_url, argumente.apikey
    if argumente.no_rest:
        rest_url = None
    elif not rest_url or not apikey:
        try:
            rest = rest_from_env()
            rest_url = rest_url or f"{rest['base_url']}/data/iot_device"
            apikey = apikey or rest["apikey"]
        except (RuntimeError, OSError, ValueError) as e:
            print(f"Warnung: kein REST-Zugang ({e}) - es wird nur gescannt.")
            rest_url = None

    # Einstellungen zentral aus iot_agent_config (vom Runner), Kommandozeile hat Vorrang
    settings = settings_from_env()
    netz = argumente.netz or settings.get("netz") or "192.168.1.0/24"
    scan_argumente = argumente.scan_argumente or settings.get("args") or "-sn"

    scan_netzwerk(netz, scan_argumente, rest_url, apikey)


if __name__ == "__main__":
    main()
