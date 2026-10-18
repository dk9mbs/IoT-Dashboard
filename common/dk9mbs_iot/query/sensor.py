#!/usr/bin/env python3
"""
Fragt iot_sensor-Datensätze ab, bei denen notify=-1 gesetzt ist.
Ob ein Sensor "still" ist (Watchdog) oder außerhalb Min/Max liegt,
entscheiden die Regeln in dk9mbs_iot.rows - beides vergleicht Felder
derselben Zeile und lässt sich im FetchXML nicht filtern.

Endpunkt: https://dk9mbs.de/api/v1.0/data
Auth:     Header apikey oder restapi_username / restapi_password
"""

from typing import List, Optional
from xml.sax.saxutils import quoteattr

import requests

from .auth import rest_headers


class IotSensorClient:
    """Client für die Abfrage von iot_sensor-Datensätzen über den REST-Service."""

    API_URL = "https://dk9mbs.de/api/v1.0/data"

    # Alle Sensoren mit notify=-1, ohne Zeitfilter (siehe Modulbeschreibung).
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

    def fetch_sensor(self, sensor_id: str) -> Optional[dict]:
        """Fragt einen einzelnen Sensor ab; None, wenn es ihn nicht gibt."""
        xml = (
            '<restapi type="select"><table name="iot_sensor" alias="a"/>'
            f'<filter type="and"><condition field="id" value={quoteattr(sensor_id)} operator="eq" />'
            "</filter></restapi>"
        )
        response = requests.post(self.api_url, headers=self._headers, data=xml.encode("utf-8"))
        response.raise_for_status()
        rows = response.json()
        return rows[0] if rows else None

    def fetch_notify_sensors(self) -> List[dict]:
        """Fragt Sensoren mit notify=-1 ab, ohne last_value_on-Filter."""
        response = requests.post(
            self.api_url, headers=self._headers, data=self.XML_PAYLOAD_NOTIFY
        )
        response.raise_for_status()
        return response.json()
