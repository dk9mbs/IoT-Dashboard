#!/usr/bin/env python3
"""
Netzwerk-Scanner mit dem python-nmap Modul.

Voraussetzungen:
    - nmap muss auf dem System installiert sein (z.B. `apt install nmap` auf Debian/Ubuntu)
    - python-nmap Modul: `pip install python-nmap`
    - requests Modul: `pip install requests`
    - Für einige Scan-Typen (z.B. -O für OS-Erkennung) werden Root-Rechte benötigt (sudo)

Nutzung:
    python3 netzwerk_scan.py
    python3 netzwerk_scan.py --netz 192.168.1.0/24
    python3 netzwerk_scan.py --netz 192.168.1.0/24 --args "-O -sV"
    python3 netzwerk_scan.py --netz 192.168.1.0/24 --rest-url http://localhost:5000/api/hosts

    Hinweis: Nur Hosts, deren Hostname mit "shelly" beginnt, werden per PUT an
    "<rest-url>/<hostname>" gesendet.
"""

import argparse
import sys
import time
from datetime import datetime
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
    Hält dabei automatisch einen Mindestabstand von 1 Sekunde zur vorherigen Anfrage ein
    (Rate-Limit der kostenlosen API) und versucht es bei Status 429 mit steigender
    Wartezeit erneut (bis zu max_versuche mal).
    Gibt den Herstellernamen als String zurück, oder None falls nicht ermittelbar.
    """
    global _letzte_macvendors_anfrage

    if not mac:
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
                return antwort.text.strip()
            elif antwort.status_code == 404:
                # Hersteller für diese MAC-Adresse nicht bekannt
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

    print(f"  -> Kein Hersteller ermittelt (Rate-Limit trotz {max_versuche} Versuchen) für MAC {mac}")
    return None


def erstelle_rest_payload(daten: dict, product_id: str = None, wlan: dict = None, firmware_version: str = None, version_available: str = None) -> dict:
    """
    Erstellt das JSON-Payload für den PUT-Aufruf (Aktualisierung) aus den vollständigen
    Host-Daten. Enthält: id (Hostname), address (IP-Adresse), last_scan_on
    (aktueller Zeitstempel, mitteleuropäische Zeit), product_id (Hersteller laut
    api.macvendors.com), network_ssid, network_rssi (direkt vom Gerät abgefragt),
    version (aktuell installierte Firmware-Version) sowie version_available
    (verfügbare neuere Firmware-Version, falls vorhanden).
    """
    wlan = wlan or {}
    return {
        "id": daten.get("hostname"),
        "address": daten.get("ip"),
        "last_scan_on": datetime.now(MITTELEUROPA).strftime("%Y-%m-%d %H:%M:%S"),
        "product_id": product_id,
        "network_ssid": wlan.get("ssid"),
        "network_rssi": wlan.get("rssi") if wlan.get("rssi") is not None else 0,
        "version": firmware_version,
        "version_available": version_available,
    }


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


def datensatz_existiert(rest_url: str, hostname: str, benutzername: str = None, passwort: str = None, timeout: int = 5) -> bool:
    """
    Prüft per GET-Request, ob für den angegebenen Hostname bereits ein Datensatz
    beim REST-Service existiert. Gibt True zurück bei Status 200, sonst False.
    """
    ziel_url = f"{rest_url.rstrip('/')}/{hostname}"
    header = {
        "restapi_username": benutzername or "",
        "restapi_password": passwort or "",
    }

    try:
        antwort = requests.get(ziel_url, headers=header, timeout=timeout)
        vorhanden = antwort.status_code == 200
        print(f"  -> GET an {ziel_url}: {'Datensatz vorhanden' if vorhanden else 'Datensatz nicht vorhanden'} (Status {antwort.status_code})")
        return vorhanden
    except requests.exceptions.RequestException as e:
        print(f"  -> Fehler bei GET an {ziel_url}: {e}")
        return False


def sende_an_rest_service(daten: dict, rest_url: str, benutzername: str = None, passwort: str = None, timeout: int = 5) -> None:
    """
    Fragt zunächst bei api.macvendors.com den Hersteller zur MAC-Adresse des Hosts ab
    (Feld product_id), direkt beim Shelly-Gerät die aktuellen WLAN-Daten (SSID, RSSI;
    Felder network_ssid, network_rssi), die installierte Firmware-Version (Feld version)
    sowie eine ggf. verfügbare neuere Firmware-Version (Feld version_available). Prüft
    anschließend per GET, ob der Datensatz bereits existiert:
    - Existiert er NICHT: Neuanlage per POST an die Basis-URL (ohne Hostname am Ende,
      ohne abschließenden '/'). Payload enthält zusätzlich name und vendor_id.
    - Existiert er bereits: Aktualisierung per PUT an '<Basis-URL>/<Hostname>'.
      Payload enthält: id, address, last_scan_on, product_id, network_ssid,
      network_rssi, version, version_available.
    Zusätzlich werden die Header 'restapi_username' und 'restapi_password' mitgesendet.
    """
    hostname = daten.get("hostname") or ""
    basis_url = rest_url.rstrip('/')
    ziel_url_put = f"{basis_url}/{hostname}"

    hersteller = hersteller_von_macvendors(daten.get("mac"))
    if hersteller:
        print(f"  -> Hersteller laut macvendors.com: {hersteller}")

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

    header = {
        "restapi_username": benutzername or "",
        "restapi_password": passwort or "",
    }

    existiert_bereits = datensatz_existiert(rest_url, hostname, benutzername, passwort, timeout)

    try:
        if existiert_bereits:
            print(f"  -> Aktualisiere: {hostname}")
            antwort = requests.put(ziel_url_put, json=payload_update, headers=header, timeout=timeout)
            methode = "PUT"
            ziel_url = ziel_url_put
        else:
            print(f"  -> Lege neu an: {hostname}")
            # Beim Anlegen (POST) wird der Hostname NICHT an die URL angehängt
            # und die Basis-URL darf nicht mit '/' enden.
            antwort = requests.post(basis_url, json=payload_neuanlage, headers=header, timeout=timeout)
            methode = "POST"
            ziel_url = basis_url

        if antwort.ok:
            print(f"  -> {methode} an {ziel_url} erfolgreich (Status {antwort.status_code})")
        else:
            print(f"  -> {methode} an {ziel_url} fehlgeschlagen (Status {antwort.status_code}): {antwort.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"  -> Fehler beim Senden an {rest_url}: {e}")


def scan_netzwerk(netzwerk: str, scan_argumente: str = "-sn", rest_url: str = None, rest_benutzername: str = None, rest_passwort: str = None) -> None:
    """
    Führt einen nmap-Scan über das angegebene Netzwerk durch.

    :param netzwerk: Netzwerk in CIDR-Notation, z.B. '192.168.1.0/24'
    :param scan_argumente: nmap-Argumente. Standard '-sn' = Ping-Scan (nur Host-Discovery, kein Portscan)
    :param rest_url: Optionale Basis-URL eines REST-Endpunkts. Jeder passende Host wird
                      per PUT gesendet, wobei der Hostname an die URL angehängt wird
                      (z.B. rest_url=http://host/api/hosts -> PUT http://host/api/hosts/shelly-plug1)
    :param rest_benutzername: Wert für den Header 'restapi_username'
    :param rest_passwort: Wert für den Header 'restapi_password'
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
            sende_an_rest_service(daten, rest_url, rest_benutzername, rest_passwort)

        print("-" * 40)


def main():
    parser = argparse.ArgumentParser(
        description="Führt einen IP-Scan über ein bestimmtes Netzwerk mit nmap durch."
    )
    parser.add_argument(
        "--netz",
        "-n",
        default="192.168.1.0/24",
        help="Zu scannendes Netzwerk in CIDR-Notation (Standard: 192.168.1.0/24)",
    )
    parser.add_argument(
        "--args",
        "-a",
        dest="scan_argumente",
        default="-sn",
        help=(
            "nmap-Argumente (Standard: '-sn' = reiner Ping-Scan/Host-Discovery). "
            "Beispiele: '-sV' (Service-Erkennung), '-O' (OS-Erkennung, benötigt sudo), "
            "'-p 1-1000' (Portbereich)"
        ),
    )
    parser.add_argument(
        "--rest-url",
        "-r",
        dest="rest_url",
        default=None,
        help="Basis-URL eines REST-Endpunkts; passende Hosts (Hostname beginnt mit 'shelly') werden per PUT (JSON) gesendet, Hostname wird an die URL angehängt",
    )

    parser.add_argument(
        "--rest-user",
        dest="rest_benutzername",
        default=None,
        help="Wert für den Header 'restapi_username'",
    )
    parser.add_argument(
        "--rest-pass",
        dest="rest_passwort",
        default=None,
        help="Wert für den Header 'restapi_password'",
    )

    argumente = parser.parse_args()
    scan_netzwerk(
        argumente.netz,
        argumente.scan_argumente,
        argumente.rest_url,
        argumente.rest_benutzername,
        argumente.rest_passwort,
    )


if __name__ == "__main__":
    main()
