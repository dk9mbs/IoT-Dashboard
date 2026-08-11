#!/usr/bin/env python3
"""
Fragt IoT-Geräte des Vendors 'shelly' ab, bei denen entweder der
letzte Scan älter als 10 Minuten ist UND notify=-1 gesetzt ist,
ODER der Status 'new' ist.

Endpunkt: https://dk9mbs.de/api/v1.0/data
Auth:     Header restapi_username / restapi_password
"""

import os
from typing import List, Optional

import requests


class IotDeviceClient:
    """Client für die Abfrage von IoT-Geräten über den REST-Service."""

    API_URL = "https://dk9mbs.de/api/v1.0/data"

    XML_PAYLOAD = """<restapi type="select">
    <table name="iot_device" alias="a"/>

    <filter type="and">
        <condition field="vendor_id" value="shelly" operator="eq" />
        <filter type="or">
            <filter type="and">
                <condition field="last_scan_on" value="10" operator="olderThenXMinutes" />
                <condition field="notify" value="-1" operator="eq" />
            </filter>
            <condition field="status_id" value="new" operator="eq" />
        </filter>
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

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None):
        self.username = username or os.environ.get("RESTAPI_USERNAME")
        self.password = password or os.environ.get("RESTAPI_PASSWORD")

        if not self.username or not self.password:
            raise RuntimeError(
                "Bitte die Umgebungsvariablen RESTAPI_USERNAME und "
                "RESTAPI_PASSWORD setzen, oder Zugangsdaten übergeben."
            )

        self._headers = {
            "Content-Type": "application/xml",
            "restapi_username": self.username,
            "restapi_password": self.password,
        }

    def fetch_devices(self) -> List[dict]:
        """Fragt die Geräte ab und gibt die JSON-Antwort als Liste zurück."""
        response = requests.post(
            self.API_URL, headers=self._headers, data=self.XML_PAYLOAD
        )
        response.raise_for_status()
        return response.json()

    def fetch_all_shelly_devices(self) -> List[dict]:
        """Fragt ALLE Shelly-Geräte ab, ohne last_scan_on-/status_id-Filter."""
        response = requests.post(
            self.API_URL, headers=self._headers, data=self.XML_PAYLOAD_ALL_SHELLY
        )
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
