#!/usr/bin/env python3
"""
Fragt iot_sensor-Datensätze ab, bei denen notify=-1 gesetzt ist und
last_value_on älter als 15 Minuten ist (Sensoren, die schon lange
keinen neuen Wert mehr gemeldet haben, obwohl Benachrichtigung aktiv ist).

Endpunkt: https://dk9mbs.de/api/v1.0/data
Auth:     Header apikey oder restapi_username / restapi_password
"""

from typing import List, Optional

import requests

from .auth import rest_headers


class IotSensorClient:
    """Client für die Abfrage von iot_sensor-Datensätzen über den REST-Service."""

    API_URL = "https://dk9mbs.de/api/v1.0/data"

    XML_PAYLOAD = """<restapi type="select">
    <table name="iot_sensor" alias="a"/>

    <filter type="and">
        <condition field="notify" value="-1" operator="eq" />
        <condition field="last_value_on" value="15" operator="olderThenXMinutes" />
    </filter>
</restapi>"""

    # Alle Sensoren mit notify=-1, ohne Zeitfilter. Wird gebraucht, um
    # last_value gegen min_value/max_value zu pruefen - das laesst sich
    # serverseitig nicht als Bedingung formulieren, da beide Werte aus
    # derselben Zeile kommen.
    XML_PAYLOAD_NOTIFY = """<restapi type="select">
    <table name="iot_sensor" alias="a"/>

    <filter type="and">
        <condition field="notify" value="-1" operator="eq" />
    </filter>
</restapi>"""

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None,
                 apikey: Optional[str] = None, base_url: Optional[str] = None):
        self.api_url = f"{base_url.rstrip('/')}/data" if base_url else self.API_URL
        self._headers = rest_headers(username, password, apikey)

    def fetch_sensors(self) -> List[dict]:
        """Fragt die Sensoren ab und gibt die JSON-Antwort als Liste zurück."""
        response = requests.post(
            self.api_url, headers=self._headers, data=self.XML_PAYLOAD
        )
        response.raise_for_status()
        return response.json()

    def fetch_notify_sensors(self) -> List[dict]:
        """Fragt Sensoren mit notify=-1 ab, ohne last_value_on-Filter."""
        response = requests.post(
            self.api_url, headers=self._headers, data=self.XML_PAYLOAD_NOTIFY
        )
        response.raise_for_status()
        return response.json()
