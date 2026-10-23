"""
Verarbeitung der Agenten-Ausgabe durch den Runner.

Ein Agent mit Ausgabetyp > 1 (iot_agent.output_type_id) gibt auf stdout nur
JSON aus, Log-Meldungen gehen nach stderr:

    {"data": [ {...}, {...} ], "message": "..."}
                                    (ein einzelnes Objekt statt Liste geht auch;
                                    "message" ist optional, siehe iot_agent_status)

Was mit den Einträgen geschieht, legt der Ausgabetyp fest
(Tabelle iot_agent_output_type):

    1  No Action          stdout wird wie bisher ins Log geschrieben
    2  Add Sensor Value   je Eintrag {"id", "value", optional "namespace"}
                          -> POST iot_sensor_data (Namespace Standard: Agentname)
    3  Add/Update Device  je Eintrag ein iot_device-Datensatz mit "id"; gesucht
                          wird über "mac" (falls angegeben), sonst über "id".
                          Vorhanden -> PUT, sonst POST. Die Felder in
                          INSERT_ONLY_FIELDS werden nur beim Anlegen gesendet,
                          "name" ist dann vorbelegt mit host_name bzw. id.
    4  Update Device      wie 3, legt aber nie an (nicht gefunden = übersprungen)
"""

import json
import urllib.error
import urllib.request
from urllib.parse import quote
from xml.sax.saxutils import quoteattr

OUTPUT_NONE = 1
OUTPUT_SENSOR_VALUE = 2
OUTPUT_DEVICE_UPSERT = 3
OUTPUT_DEVICE_UPDATE = 4

OUTPUT_TYPES = {
    OUTPUT_NONE: "No Action",
    OUTPUT_SENSOR_VALUE: "Add Sensor Value",
    OUTPUT_DEVICE_UPSERT: "Add/Update Device",
    OUTPUT_DEVICE_UPDATE: "Update Device",
}

# nur beim Anlegen senden - name wird danach manuell gepflegt
INSERT_ONLY_FIELDS = ("name", "vendor_id")

MESSAGE_MAX_LENGTH = 250  # iot_agent_status.message


class OutputError(ValueError):
    """Ausgabe des Agenten ist kein gültiges JSON im erwarteten Format."""


def short_message(text) -> str:
    """Meldung einzeilig und auf die Feldlänge gekürzt; leer -> None."""
    text = " ".join(str(text).split()) if text is not None else ""
    return text[:MESSAGE_MAX_LENGTH] or None


def parse_output(text: str) -> tuple:
    """
    stdout des Agenten -> (Liste der Einträge, Meldung oder None).
    Leere Ausgabe = keine Einträge.
    """
    if not text.strip():
        return [], None
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise OutputError(f"kein gültiges JSON: {exc}") from None
    if not isinstance(document, dict):
        raise OutputError('erwartet ein Objekt {"data": ...}')
    # Schlüssel ohne Rücksicht auf Gross-/Kleinschreibung ("data" / "Data")
    keys = {k.lower(): v for k, v in document.items()}
    data = keys.get("data")
    if data is None:
        raise OutputError('Schlüssel "data" fehlt')
    items = data if isinstance(data, list) else [data]
    if not all(isinstance(item, dict) for item in items):
        raise OutputError('"data" muss Objekte enthalten')
    return items, short_message(keys.get("message"))


class OutputWriter:
    """Schreibt die Einträge eines Agenten je nach Ausgabetyp per REST."""

    def __init__(self, rest: dict, agent_name: str, log, dry_run: bool = False):
        self.rest = rest
        self.agent_name = agent_name
        self.log = log          # Funktion(text) -> Log des Agenten
        self.dry_run = dry_run

    def write(self, output_type: int, items: list) -> int:
        """Verarbeitet alle Einträge; Rückgabe: Anzahl Fehler."""
        handler = {
            OUTPUT_SENSOR_VALUE: self._sensor_value,
            OUTPUT_DEVICE_UPSERT: lambda item: self._device(item, insert=True),
            OUTPUT_DEVICE_UPDATE: lambda item: self._device(item, insert=False),
        }.get(output_type)
        if handler is None:
            self.log(f"Ausgabetyp {output_type} unbekannt - {len(items)} Eintrag/Einträge verworfen")
            return 1
        errors = 0
        for item in items:
            try:
                handler(item)
            except (OutputError, OSError) as exc:  # OSError: auch urllib.error.URLError
                errors += 1
                self.log(f"Fehler: {exc} - Eintrag {json.dumps(item, ensure_ascii=False)[:200]}")
        return errors

    # -- Add Sensor Value --------------------------------------------------

    def _sensor_value(self, item: dict) -> None:
        if not item.get("id") or "value" not in item:
            raise OutputError('Sensorwert braucht "id" und "value"')
        body = {"sensor_id": item["id"],
                "sensor_namespace": item.get("namespace") or self.agent_name,
                "sensor_value": item["value"]}
        self._send("POST", "iot_sensor_data", body, f"Sensor {item['id']} = {item['value']}")

    # -- Add/Update Device, Update Device -----------------------------------

    def _device(self, item: dict, insert: bool) -> None:
        if not item.get("id"):
            raise OutputError('Gerät braucht "id"')
        existing_id = None
        if item.get("mac"):
            existing_id = self._find("iot_device", "mac", item["mac"])
        if not existing_id:
            existing_id = self._find("iot_device", "id", item["id"])

        if existing_id:
            body = {k: v for k, v in item.items() if k not in INSERT_ONLY_FIELDS}
            body["id"] = existing_id
            self._send("PUT", f"iot_device/{quote(existing_id, safe='')}", body,
                       f"Gerät {existing_id} aktualisiert")
        elif insert:
            body = dict(item)
            body.setdefault("name", item.get("host_name") or item["id"])
            self._send("POST", "iot_device", body, f"Gerät {item['id']} neu angelegt")
        else:
            self.log(f"Gerät {item['id']} nicht vorhanden - übersprungen")

    # -- Status des Laufs (iot_agent_status) --------------------------------

    def write_status(self, config_id: int, fields: dict) -> bool:
        """Schreibt den Status zum iot_agent_config-Datensatz (anlegen oder aktualisieren)."""
        try:
            existing_id = self._find("iot_agent_status", "config_id", config_id)
            body = {"config_id": config_id, **fields}
            if existing_id:
                body["id"] = int(existing_id)
                self._send("PUT", f"iot_agent_status/{existing_id}", body, "Status geschrieben")
            else:
                self._send("POST", "iot_agent_status", body, "Status angelegt")
            return True
        except (OutputError, OSError, ValueError) as exc:
            self.log(f"Status nicht geschrieben: {exc}")
            return False

    # -- REST --------------------------------------------------------------

    def _find(self, table: str, field: str, value: str):
        """ID des Datensatzes mit field = value, None wenn keiner; Fehler -> Exception."""
        xml = (f'<restapi type="select"><table name={quoteattr(table)} alias="a"/>'
               f'<filter type="and"><condition field={quoteattr(field)} value={quoteattr(str(value))} '
               f'operator="eq" /></filter></restapi>')
        rows = self._request("POST", "", xml.encode("utf-8"), "application/xml",
                             f"Suche {table} {field}={value}")
        # unklare Antwort nicht als "nicht vorhanden" werten, sonst droht ein Doppel-Eintrag
        if not isinstance(rows, list):
            raise OutputError(f"Suche {table} {field}={value}: unerwartete Antwort")
        if not rows:
            return None
        row_id = rows[0]["id"]
        if isinstance(row_id, dict):  # Antwort mit Formatter
            row_id = row_id.get("value")
        return str(row_id)

    def _send(self, method: str, path: str, body: dict, description: str) -> None:
        if self.dry_run:
            self.log(f"[dry-run] {method} {path} {json.dumps(body, ensure_ascii=False)}")
            return
        self._request(method, f"/{path}", json.dumps(body).encode("utf-8"), "application/json",
                      f"{method} {path}")
        self.log(description)

    def _request(self, method: str, path: str, data: bytes, content_type: str, what: str):
        """REST-Aufruf; Rückgabe: Antwort als JSON (None, wenn leer oder kein JSON)."""
        req = urllib.request.Request(
            f"{self.rest['base_url']}/data{path}", data=data, method=method,
            headers={"apikey": self.rest["apikey"], "Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=self.rest["timeout"]) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise OutputError(f"{what}: Status {exc.code} "
                              f"{exc.read()[:200].decode(errors='replace')}") from None
        try:
            return json.loads(raw) if raw.strip() else None
        except ValueError:
            return None
