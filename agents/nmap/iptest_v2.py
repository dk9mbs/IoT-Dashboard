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
    --apikey lässt sich das überschreiben. Nur Hosts, deren Hostname mit
    "shelly" beginnt, werden angelegt bzw. per PUT an "<rest-url>/<hostname>"
    gesendet.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
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


def shelly_update_verfuegbar(ip: str, timeout: int = 3) -> str:
    """
    Prüft direkt beim Shelly-Gerät, ob eine neuere Firmware-Version verfügbar ist.
    Versucht zuerst die Gen2+ RPC-API (/rpc/Shelly.CheckForUpdate, aktive Prüfung),
    fällt bei Fehlschlag auf die ältere Gen1-API (/status, Feld 'update.new_version') zurück.
    Gibt die verfügbare Versions-Nummer zurück, oder None falls kein Update verfügbar
    bzw. nicht ermittelbar.
    """
    # Gen2+ Geräte: RPC-Endpunkt prüft aktiv beim Update-Server
    try:
        antwort = requests.get(f"http://{ip}/rpc/Shelly.CheckForUpdate", timeout=timeout)
        if antwort.ok:
            daten = antwort.json()
            return daten.get("stable", {}).get("version") or None
    except (requests.exceptions.RequestException, ValueError):
        pass

    # Gen1 Geräte: /status enthält bereits das Ergebnis der letzten automatischen Prüfung
    try:
        antwort = requests.get(f"http://{ip}/status", timeout=timeout)
        if antwort.ok:
            daten = antwort.json()
            return daten.get("update", {}).get("new_version") or None
    except (requests.exceptions.RequestException, ValueError):
        pass

    return None


def shelly_firmware_version(ip: str, timeout: int = 3) -> str:
    """
    Fragt direkt beim Shelly-Gerät (per HTTP) die aktuell installierte Firmware-Version ab.
    Versucht zuerst die Gen2+ RPC-API (/rpc/Shelly.GetDeviceInfo, Feld 'ver'), fällt bei
    Fehlschlag auf die ältere Gen1-API (/status, Feld 'update.old_version') zurück.
    Gibt die Versions-String zurück, oder None falls nicht ermittelbar.
    """
    # Gen2+ Geräte: RPC-Endpunkt liefert kurze Versionsnummer, z.B. "0.6.7"
    try:
        antwort = requests.get(f"http://{ip}/rpc/Shelly.GetDeviceInfo", timeout=timeout)
        if antwort.ok:
            daten = antwort.json()
            version = daten.get("ver")
            if version:
                return version
    except (requests.exceptions.RequestException, ValueError):
        pass

    # Gen1 Geräte: /status enthält unter 'update' die aktuell installierte Version
    try:
        antwort = requests.get(f"http://{ip}/status", timeout=timeout)
        if antwort.ok:
            daten = antwort.json()
            version = daten.get("update", {}).get("old_version")
            if version:
                return version
    except (requests.exceptions.RequestException, ValueError):
        pass

    return None


def shelly_wlan_daten(ip: str, timeout: int = 3) -> dict:
    """
    Fragt direkt beim Shelly-Gerät (per HTTP) die aktuellen WLAN-Daten ab.
    Versucht zuerst die Gen2+ RPC-API (/rpc/WiFi.GetStatus), fällt bei Fehlschlag
    auf die ältere Gen1-API (/status) zurück.
    Gibt ein Dict {'ssid': ..., 'rssi': ...} zurück, Werte sind None falls nicht ermittelbar.
    """
    ergebnis = {"ssid": None, "rssi": None}

    # Gen2+ Geräte: RPC-Endpunkt
    try:
        antwort = requests.get(f"http://{ip}/rpc/WiFi.GetStatus", timeout=timeout)
        if antwort.ok:
            daten = antwort.json()
            ergebnis["ssid"] = daten.get("ssid")
            ergebnis["rssi"] = daten.get("rssi")
            if ergebnis["ssid"] is not None:
                return ergebnis
    except (requests.exceptions.RequestException, ValueError):
        pass

    # Gen1 Geräte: klassischer /status-Endpunkt mit verschachteltem wifi_sta-Objekt
    try:
        antwort = requests.get(f"http://{ip}/status", timeout=timeout)
        if antwort.ok:
            daten = antwort.json()
            wifi_sta = daten.get("wifi_sta", {})
            ergebnis["ssid"] = wifi_sta.get("ssid")
            ergebnis["rssi"] = wifi_sta.get("rssi")
    except (requests.exceptions.RequestException, ValueError):
        pass

    return ergebnis


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


def erstelle_rest_payload(daten: dict, product_id: str = None, wlan: dict = None, firmware_version: str = None, version_available: str = None) -> dict:
    """
    Erstellt das JSON-Payload für den PUT-Aufruf (Aktualisierung) aus den vollständigen
    Host-Daten. Enthält: id (Hostname), address (IP-Adresse), last_scan_on
    (aktueller Zeitstempel, mitteleuropäische Zeit), product_id (Hersteller laut
    api.macvendors.com), network_ssid, network_rssi (direkt vom Gerät abgefragt),
    version (aktuell installierte Firmware-Version), version_available
    (verfügbare neuere Firmware-Version, falls vorhanden) sowie mac, wenn nmap
    die MAC-Adresse ermitteln konnte.
    """
    wlan = wlan or {}
    payload = {
        "id": daten.get("hostname"),
        "address": daten.get("ip"),
        "last_scan_on": datetime.now(MITTELEUROPA).strftime("%Y-%m-%d %H:%M:%S"),
        "network_ssid": wlan.get("ssid"),
        "network_rssi": wlan.get("rssi") if wlan.get("rssi") is not None else 0,
        "version": firmware_version,
        "version_available": version_available,
    }
    # ohne ermittelten Hersteller den gespeicherten Wert nicht mit null ueberschreiben
    if product_id:
        payload["product_id"] = product_id
    # MAC nur, wenn nmap sie ermitteln konnte (ohne root bzw. ausserhalb des
    # eigenen Netzsegments liefert nmap keine) - sonst bleibt der gespeicherte Wert
    if daten.get("mac"):
        payload["mac"] = daten["mac"]
    return payload


def erstelle_neuanlage_payload(daten: dict, product_id: str = None, wlan: dict = None, firmware_version: str = None, version_available: str = None) -> dict:
    """
    Erstellt das JSON-Payload für den POST-Aufruf (Neuanlage) aus den vollständigen
    Host-Daten. Enthält zusätzlich zu id, address, last_scan_on, product_id,
    network_ssid, network_rssi, version und version_available die Felder
    name (Hostname) und vendor_id.
    """
    payload = erstelle_rest_payload(daten, product_id, wlan, firmware_version, version_available)
    payload["name"] = daten.get("hostname")
    payload["vendor_id"] = "shelly"
    return payload


def _rest_header(apikey: str) -> dict:
    return {"apikey": apikey or ""}


def datensatz_existiert(rest_url: str, hostname: str, apikey: str, timeout: int = 5):
    """
    Prüft per XML-SELECT an '<.../data>', ob für den Hostname bereits ein Datensatz
    in der Tabelle (letzter Teil von rest_url, z.B. iot_device) existiert.
    Ein GET auf '<rest_url>/<hostname>' braucht beim REST-Service zusätzlich
    Leserechte auf api_http_header, die der API-Key-Benutzer nicht hat.
    Gibt True/False zurück, oder None, wenn die Prüfung fehlschlug.
    """
    data_url, _, tabelle = rest_url.rstrip("/").rpartition("/")
    xml = (
        f'<restapi type="select"><table name={quoteattr(tabelle)} alias="a"/>'
        f'<filter type="and"><condition field="id" value={quoteattr(hostname)} operator="eq" />'
        f"</filter></restapi>"
    )
    header = {**_rest_header(apikey), "Content-Type": "application/xml"}

    try:
        antwort = requests.post(data_url, data=xml.encode("utf-8"), headers=header, timeout=timeout)
        if not antwort.ok:
            print(f"  -> Prüfung {tabelle}/{hostname} fehlgeschlagen (Status {antwort.status_code}): {antwort.text[:200]}")
            return None
        vorhanden = len(antwort.json()) > 0
        print(f"  -> {tabelle}/{hostname}: {'Datensatz vorhanden' if vorhanden else 'Datensatz nicht vorhanden'}")
        return vorhanden
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"  -> Fehler bei der Prüfung {tabelle}/{hostname}: {e}")
        return None


def sende_an_rest_service(daten: dict, rest_url: str, apikey: str, timeout: int = 5) -> None:
    """
    Fragt zunächst bei api.macvendors.com den Hersteller zur MAC-Adresse des Hosts ab
    (Feld product_id), direkt beim Shelly-Gerät die aktuellen WLAN-Daten (SSID, RSSI;
    Felder network_ssid, network_rssi), die installierte Firmware-Version (Feld version)
    sowie eine ggf. verfügbare neuere Firmware-Version (Feld version_available). Prüft
    anschließend, ob der Datensatz bereits existiert:
    - Existiert er NICHT: Neuanlage per POST an die Basis-URL (ohne Hostname am Ende,
      ohne abschließenden '/'). Payload enthält zusätzlich name und vendor_id.
    - Existiert er bereits: Aktualisierung per PUT an '<Basis-URL>/<Hostname>'.
      Payload enthält: id, address, last_scan_on, product_id, network_ssid,
      network_rssi, version, version_available und mac (nur wenn ermittelt).
    - Schlägt die Prüfung fehl: nichts senden (sonst drohen doppelte Datensätze).
    Angemeldet wird mit dem Header 'apikey'.
    """
    hostname = daten.get("hostname") or ""
    basis_url = rest_url.rstrip('/')
    ziel_url_put = f"{basis_url}/{hostname}"

    hersteller = hersteller_von_macvendors(daten.get("mac"))
    if hersteller:
        print(f"  -> Hersteller laut macvendors.com: {hersteller}")
    elif daten.get("vendor"):
        hersteller = daten["vendor"]
        print(f"  -> Hersteller laut nmap: {hersteller}")

    wlan = shelly_wlan_daten(daten.get("ip"))
    if wlan.get("ssid"):
        print(f"  -> WLAN laut Gerät: SSID={wlan['ssid']}, RSSI={wlan['rssi']}")
    else:
        print(f"  -> WLAN-Daten konnten nicht vom Gerät abgefragt werden")

    firmware_version = shelly_firmware_version(daten.get("ip"))
    if firmware_version:
        print(f"  -> Firmware-Version laut Gerät: {firmware_version}")
    else:
        print(f"  -> Firmware-Version konnte nicht vom Gerät abgefragt werden")

    version_available = shelly_update_verfuegbar(daten.get("ip"))
    if version_available:
        print(f"  -> Update verfügbar: {version_available}")
    else:
        print(f"  -> Kein Update verfügbar bzw. nicht ermittelbar")

    payload_update = erstelle_rest_payload(daten, hersteller, wlan, firmware_version, version_available)
    payload_neuanlage = erstelle_neuanlage_payload(daten, hersteller, wlan, firmware_version, version_available)

    header = _rest_header(apikey)

    existiert_bereits = datensatz_existiert(rest_url, hostname, apikey, timeout)
    if existiert_bereits is None:
        print(f"  -> Übersprungen: {hostname} (Existenz-Prüfung fehlgeschlagen)")
        return

    try:
        if existiert_bereits:
            print(f"  -> Aktualisiere: {hostname}")
            methode, ziel_url, payload = "PUT", ziel_url_put, payload_update
        else:
            print(f"  -> Lege neu an: {hostname}")
            # Beim Anlegen (POST) wird der Hostname NICHT an die URL angehängt
            # und die Basis-URL darf nicht mit '/' enden.
            methode, ziel_url, payload = "POST", basis_url, payload_neuanlage
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
                      Jeder passende Host wird angelegt bzw. per PUT an '<rest_url>/<hostname>'
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

        # Host-Daten per PUT an den REST-Service senden, aber nur wenn der
        # Hostname mit "shelly" beginnt (Groß-/Kleinschreibung wird ignoriert)
        if rest_url and daten["hostname"] and daten["hostname"].lower().startswith("shelly"):
            sende_an_rest_service(daten, rest_url, apikey)

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
             "passende Hosts (Hostname beginnt mit 'shelly') werden angelegt bzw. aktualisiert",
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
