#!/usr/bin/env python3
"""
Fragt auffällige IoT-Geräte ab:
  - Shellys, deren letzter Scan älter als 10 Minuten ist UND notify=-1 gesetzt ist
    ("offline"; nur Shellys, sonst würde z.B. jedes Handy außer Haus gemeldet),
  - ODER Geräte jedes Herstellers mit Status 'new' (vom nmap-Agenten neu angelegt).

Endpunkt: https://dk9mbs.de/api/v1.0/data
Auth:     Header apikey oder restapi_username / restapi_password
"""

from typing import List, Optional
from xml.sax.saxutils import quoteattr

import requests

from .auth import rest_headers


class IotDeviceClient:
    """Client für die Abfrage von IoT-Geräten über den REST-Service."""

    API_URL = "https://dk9mbs.de/api/v1.0/data"

    XML_PAYLOAD = """<restapi type="select">
    <table name="iot_device" alias="a"/>

    <filter type="or">
        <filter type="and">
            <condition field="vendor_id" value="shelly" operator="eq" />
            <condition field="last_scan_on" value="10" operator="olderThenXMinutes" />
            <condition field="notify" value="-1" operator="eq" />
        </filter>
        <condition field="status_id" value="new" operator="eq" />
    </filter>
</restapi>"""

    # Alle Shelly-Geräte ohne Zeit-/Status-Filter. Wird für Auswertungen
    # gebraucht, die serverseitig nicht filterbar sind (z.B. Vergleich
    # zweier Felder wie version vs. version_available).
    XML_PAYLOAD_ALL_SHELLY = """<restapi type="select">
    <table name="iot_device" alias="a"/>

    <filter type="and">
        <condition field="vendor_id" value="shelly" operator="eq" />
    </filter>
</restapi>"""

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None,
                 apikey: Optional[str] = None, base_url: Optional[str] = None):
        self.api_url = f"{base_url.rstrip('/')}/data" if base_url else self.API_URL
        self._headers = rest_headers(username, password, apikey)

    def fetch_devices(self) -> List[dict]:
        """Fragt die Geräte ab und gibt die JSON-Antwort als Liste zurück."""
        response = requests.post(
            self.api_url, headers=self._headers, data=self.XML_PAYLOAD
        )
        response.raise_for_status()
        return response.json()

    def fetch_all_shelly_devices(self) -> List[dict]:
        """Fragt ALLE Shelly-Geräte ab, ohne last_scan_on-/status_id-Filter."""
        response = requests.post(
            self.api_url, headers=self._headers, data=self.XML_PAYLOAD_ALL_SHELLY
        )
        response.raise_for_status()
        return response.json()

    def fetch_all_devices(self, status_id: Optional[str] = None) -> List[dict]:
        """Fragt alle Geräte ab, unabhängig vom Hersteller (z.B. für die MAC-Adressen),
        optional nur mit diesem status_id (z.B. 'active')."""
        condition = (f'<filter type="and"><condition field="status_id" value={quoteattr(status_id)} '
                     f'operator="eq" /></filter>' if status_id else "")
        xml = f'<restapi type="select"><table name="iot_device" alias="a"/>{condition}</restapi>'
        response = requests.post(self.api_url, headers=self._headers, data=xml)
        response.raise_for_status()
        return response.json()

    def print_devices(self, devices: List[dict]) -> None:
        """Gibt alle Felder jedes Geräts formatiert auf der Konsole aus."""
        if not devices:
            print("Keine passenden Geräte gefunden.")
            return

        print(f"{len(devices)} Gerät(e) gefunden:\n")
        for device in devices:
            for field, value in device.items():
                print(f"  {field}: {value}")
            print()


def main():
    client = IotDeviceClient()
    try:
        devices = client.fetch_devices()
    except requests.exceptions.RequestException as exc:
        print(f"Fehler bei der Abfrage: {exc}")
        return

    client.print_devices(devices)


if __name__ == "__main__":
    main()
