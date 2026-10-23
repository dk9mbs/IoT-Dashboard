#!/usr/bin/env python3
"""
Fragt die Shellys aus iot_device gezielt per HTTP unter ihrer gespeicherten
Adresse ab (statt sie wie nmap per Ping-Sweep zu suchen) und aktualisiert:

    last_scan_on                 bei jeder Antwort (Grundlage der Offline-Warnung)
    network_ssid, network_rssi   WLAN-Daten vom Gerät
    version                      installierte Firmware
    version_available            verfügbare Firmware (Update-Prüfung nur alle
                                 'update_check_minutes', fragt den Update-Server)

Die Generation wird einmal über /shelly festgestellt (Gen2+ liefert 'gen'),
danach werden nur die passenden Endpunkte abgefragt:
    Gen2+: /shelly (Firmware), /rpc/WiFi.GetStatus, /rpc/Shelly.CheckForUpdate
    Gen1:  /shelly, /status (WLAN, Firmware und verfügbare Version)

Abgefragt werden alle Geräte mit vendor_id 'shelly' ausser Status 'disabled'.
Neue Shellys legt weiterhin der nmap-Agent an (dort steht auch die Adresse).

Ausgabetyp 4 (Update Device): das Ergebnis geht als JSON {"data": [...]} auf
stdout, der Runner schreibt es nach iot_device; Log-Meldungen auf stderr.
Gelesen wird weiterhin selbst (Shellys aus iot_device).

Nutzung:
    python3 shelly.py                  REST-Zugang und Einstellungen vom Agenten-Runner
    python3 shelly.py 2>/dev/null      nur das JSON-Ergebnis anzeigen

Einstellungen (IOT_AGENT_SETTINGS, siehe settings.json.skelet):
    timeout               Sekunden je HTTP-Anfrage an ein Gerät (Standard 3)
    retries               Versuche für /shelly, bevor ein Gerät als nicht
                          erreichbar gilt (Standard 3)
    parallel              gleichzeitig abgefragte Geräte (Standard 8)
    update_check_minutes  Abstand der Update-Prüfung je Gerät (Standard 60)
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

from dk9mbs_iot.agent import log, rest_from_env, settings_from_env, write_output  # vom Agenten-Runner
from dk9mbs_iot.query.device import IotDeviceClient

MITTELEUROPA = ZoneInfo("Europe/Berlin")

# Zeitpunkt der letzten Update-Prüfung je Geräte-ID (wird automatisch angelegt)
UPDATE_STATE_DATEI = Path(__file__).resolve().parent / "update_check_state.json"

STATUS_IGNORIERT = "disabled"


def _wert(datensatz: dict, feld: str):
    """Rohwert eines Feldes aus der REST-Antwort ({'value': ..., 'formatted_value': ...})."""
    daten = datensatz.get(feld)
    return daten.get("value") if isinstance(daten, dict) else daten


def _get_json(url: str, timeout: float, versuche: int = 1):
    """GET mit Wiederholungen; gibt das JSON zurück oder None."""
    for versuch in range(versuche):
        try:
            antwort = requests.get(url, timeout=timeout)
            if antwort.ok:
                return antwort.json()
            return None  # Gerät antwortet, kennt den Endpunkt aber nicht
        except (requests.exceptions.RequestException, ValueError):
            if versuch + 1 < versuche:
                time.sleep(1)
    return None


def frage_shelly_ab(ip: str, timeout: float, versuche: int, update_pruefen: bool) -> dict:
    """
    Fragt eine Shelly ab. Ergebnis: {'erreichbar', 'gen', 'ssid', 'rssi',
    'version', 'version_available', 'update_geprueft'}; nicht ermittelte Werte
    sind None.
    """
    ergebnis = {"erreichbar": False, "gen": None, "ssid": None, "rssi": None,
                "version": None, "version_available": None, "update_geprueft": False}

    info = _get_json(f"http://{ip}/shelly", timeout, versuche)
    if not isinstance(info, dict):
        return ergebnis
    ergebnis["erreichbar"] = True
    ergebnis["gen"] = info.get("gen") or 1

    if ergebnis["gen"] >= 2:
        ergebnis["version"] = info.get("ver")
        wlan = _get_json(f"http://{ip}/rpc/WiFi.GetStatus", timeout) or {}
        ergebnis["ssid"], ergebnis["rssi"] = wlan.get("ssid"), wlan.get("rssi")
        if update_pruefen:
            # prüft aktiv beim Update-Server; leer = kein Update verfügbar
            update = _get_json(f"http://{ip}/rpc/Shelly.CheckForUpdate", timeout)
            if isinstance(update, dict):
                ergebnis["version_available"] = (update.get("stable") or {}).get("version")
                ergebnis["update_geprueft"] = True
    else:
        # Gen1: /status enthält WLAN und das Ergebnis der letzten Update-Prüfung des Geräts
        status = _get_json(f"http://{ip}/status", timeout) or {}
        wlan = status.get("wifi_sta") or {}
        update = status.get("update") or {}
        ergebnis["ssid"], ergebnis["rssi"] = wlan.get("ssid"), wlan.get("rssi")
        ergebnis["version"] = update.get("old_version")
        if status:
            ergebnis["version_available"] = update.get("new_version") or None
            ergebnis["update_geprueft"] = True

    return ergebnis


def erstelle_payload(geraete_id: str, ergebnis: dict) -> dict:
    """PUT-Payload: last_scan_on immer, sonst nur ermittelte Werte (nichts mit null überschreiben)."""
    payload = {
        "id": geraete_id,
        "last_scan_on": datetime.now(MITTELEUROPA).strftime("%Y-%m-%d %H:%M:%S"),
    }
    if ergebnis["ssid"] is not None:
        payload["network_ssid"] = ergebnis["ssid"]
    if ergebnis["rssi"] is not None:
        payload["network_rssi"] = ergebnis["rssi"]
    if ergebnis["version"]:
        payload["version"] = ergebnis["version"]
    # nach einer Update-Prüfung auch "kein Update" (None) speichern
    if ergebnis["update_geprueft"]:
        payload["version_available"] = ergebnis["version_available"]
    return payload


def _lade_update_state() -> dict:
    try:
        return json.loads(UPDATE_STATE_DATEI.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _speichere_update_state(state: dict) -> None:
    try:
        UPDATE_STATE_DATEI.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as e:
        log(f"Warnung: {UPDATE_STATE_DATEI.name} konnte nicht gespeichert werden: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fragt die Shellys aus iot_device per HTTP ab; Ergebnis als JSON auf stdout.")
    parser.parse_args()

    settings = settings_from_env()
    timeout = float(settings.get("timeout", 3))
    versuche = max(1, int(settings.get("retries", 3)))
    parallel = max(1, int(settings.get("parallel", 8)))
    update_intervall = float(settings.get("update_check_minutes", 60)) * 60

    try:
        rest = rest_from_env()
    except RuntimeError as e:
        log(f"Fehler: {e}")
        return 1
    client = IotDeviceClient(apikey=rest["apikey"], base_url=rest["base_url"])
    try:
        geraete = [g for g in client.fetch_all_shelly_devices()
                   if _wert(g, "status_id") != STATUS_IGNORIERT and _wert(g, "address")]
    except requests.exceptions.RequestException as e:
        log(f"Fehler: Shellys konnten nicht aus iot_device gelesen werden: {e}")
        return 1

    update_state = _lade_update_state()
    jetzt = time.time()

    def pruefe(geraet: dict):
        geraete_id, ip = str(_wert(geraet, "id")), str(_wert(geraet, "address"))
        update_pruefen = jetzt - update_state.get(geraete_id, 0) >= update_intervall
        return geraete_id, ip, frage_shelly_ab(ip, timeout, versuche, update_pruefen)

    log(f"Frage {len(geraete)} Shelly(s) ab ({parallel} parallel, {versuche} Versuch(e), "
        f"Timeout {timeout:g}s) ...")
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        ergebnisse = sorted(pool.map(pruefe, geraete))

    # Geschrieben wird vom Runner (Ausgabetyp "Update Device") - der Agent erfährt
    # nicht, ob das gelingt; die Update-Prüfung gilt daher schon nach der Abfrage
    # als erledigt.
    output = []
    for geraete_id, ip, ergebnis in ergebnisse:
        if not ergebnis["erreichbar"]:
            log(f"{geraete_id} ({ip}): nicht erreichbar")
            continue
        update = (f", Update: {ergebnis['version_available'] or 'keins'}"
                  if ergebnis["update_geprueft"] else "")
        log(f"{geraete_id} ({ip}): Gen{ergebnis['gen']}, Firmware {ergebnis['version'] or '?'}, "
            f"WLAN {ergebnis['ssid'] or '?'} ({ergebnis['rssi'] if ergebnis['rssi'] is not None else '?'}){update}")
        output.append(erstelle_payload(geraete_id, ergebnis))
        if ergebnis["update_geprueft"]:
            update_state[geraete_id] = jetzt

    _speichere_update_state(update_state)
    log(f"\n{len(output)}/{len(ergebnisse)} erreichbar")
    write_output(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
