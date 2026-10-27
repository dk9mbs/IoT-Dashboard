# IoT-Dashboard

Dashboard und Agenten für die IoT-Geräte/Sensoren von dk9mbs. Daten liegen im
REST-Backend `https://dk9mbs.de/api/v1.0` (Projekt restapi + Plugin
IoTSensorNet, MySQL-DB `tuxlog`).

## Aufbau

- `dashboard/` – Flask-App, **rein passive Anzeige** (einzige Aktion:
  Firmware-Update-Knopf). Benachrichtigungen erkennt `agents/watchdog`,
  verschickt `agents/notify` (Warteschlange `iot_notification`).
- `agents/` – ein Verzeichnis je Agent mit eigenem `run.sh`
  (nmap, notify, omada_syslog, …). Gestartet vom Runner `agents/run_agents.py`
  (`--run <name>`, `--all`, `--list`, `--daemon`, `--export-sql`).
- `agents/agent_config.py` – Konfiguration auflösen und als Umgebung an die
  Agenten geben (`IOT_REST_BASE_URL`, `IOT_REST_APIKEY`, `IOT_REST_TIMEOUT`,
  `IOT_AGENT_SETTINGS` (JSON), `IOT_PYTHON`).
- `common/` – gemeinsames Paket `dk9mbs-iot` (Import `dk9mbs_iot`,
  `dk9mbs_iot.query`), editierbar installiert (`pip install -e common`).
- `install/install.sh` – Installation (`--dashboard`, `--agents`, `--deps`,
  `--print`, `--remove`) inkl. systemd-Units aus `*.service.skelet`.
- Ein gemeinsames `.venv` im Repo-Root.

## Konfiguration

Reihenfolge: zentral per REST aus `iot_agent_host` / `iot_agent_config`
(IoTSensorNet) → Cache `agents/logs/central_config.json` → lokaler
`agents`-Block bzw. Legacy `config.env`/`config.json`.
REST-Zugang (apikey) steht zentral in `agents/agents.json`.
Echte Konfiguration und Zugangsdaten gehören **nicht** ins Repo – nur
`*.skelet`-Vorlagen mit Demo-Werten. Vor jedem Commit auf Passwörter,
API-Keys und MAC-Adressen prüfen.

## Hosts

- `heiligenhafen` – lokaler Rechner (Entwicklung, `/home/dk9mbs/src/IoT-Dashboard`).
- `nextcloud` – Server, `/usr/local/IoT-Dashboard`, venv `/var/local/iotdash`,
  läuft als root; systemd-Dienste `iot-dashboard` und `iot-agents`.
- `omada_syslog` gehört auf den Host, der die Omada-Syslogs empfängt.

## Fachliche Regeln

- nmap trägt **alle** gefundenen Geräte in `iot_device` ein: Shellys mit
  Hersteller `shelly`, alle anderen mit `dk9mbs`. ID = MAC, nur Shellys
  behalten den Hostnamen als ID; Geräte ohne bekannte MAC werden übersprungen.
  Der Hostname steht in `host_name`; `name` wird nur bei Neuanlage gesetzt
  (Hostname bzw. ID) und sonst manuell gepflegt. Bestehende Einträge zuerst
  über die MAC suchen.
- Shellys fragt der Agent `shelly` per HTTP ab (setzt ebenfalls
  `last_scan_on`, dazu WLAN, Firmware, Update); nmap legt sie nur an.
- Ausgabetypen: nmap 3 (Add/Update Device), shelly 4 (Update Device),
  omada_syslog, shelly_syslog und disk_usage 2 (Add Sensor Value), watchdog 1 (No Action),
  notify 5 (Update Notification – setzt nur Meldungen auf `sent`/`failed`).
  Geschrieben wird nur noch über den Runner; gelesen wird weiterhin im Agenten.
- `mac` nur senden, wenn bekannt – **immer ohne Fallback**.
- Als bekannt (z. B. WLAN-Score) zählen nur Geräte mit Status `active`.
- „Neu“ = Status `new` aller Hersteller; „Offline“ nur Shellys.
- „Sensor still“ nutzt je Sensor `watchdog_warning_sec` (leer/0 = keine Warnung).

## Fallstricke

- Nach Code- oder Template-Änderungen den Dienst neu starten
  (`systemctl restart iot-dashboard iot-agents`); Agenten selbst starten
  ohnehin als neue Prozesse.
- `pkill -f` / `pgrep -f` mit verankertem Muster (`'^python3 …'`), sonst trifft
  es die eigene Shell.
- Der XML-Select des REST-Service (`<restapi type="select">`) kann keine zwei
  Felder miteinander vergleichen – solche Auswertungen in Python machen.
- Runner-Exitcodes: 124 Timeout, 125 Runner-Fehler, 126 Ausgabe ungültig bzw.
  nicht vollständig geschrieben, 127 Befehl nicht gefunden.
- Agenten mit Ausgabetyp > 1 (`iot_agent.output_type_id`, siehe
  `agents/agent_output.py`) dürfen auf stdout **nur** das JSON
  `{"data": [...], "message": "..."}` ausgeben – Log-Meldungen nach stderr
  (`dk9mbs_iot.agent.log` / `write_output(items, message)`). Die kurze
  `message` (bzw. bei Fehlern die des Runners) landet mit Start, Exitcode und
  Dauer in `iot_agent_status` (`config_id` → `iot_agent_config`), nur bei
  zentraler Konfiguration.
- Benachrichtigungen: jeder Agent kann `"notify": ["Text", …]` mit ausgeben
  (`write_output(items, message, notify)`, auch bei Ausgabetyp 1); der Runner
  legt sie in `iot_notification` (status `new`) an. Erkennen gehört nicht in
  den Versand-Agenten – notify liest nur die Warteschlange und ist austauschbar.
  Agenten mit eigenem Zustand/Versand beachten `IOT_DRY_RUN` (`--dry-run`).

## Sprache

Kommunikation, Kommentare, Docstrings und Ausgaben auf Deutsch,
Commit-Messages auf Englisch. Bezeichner im Code (Funktionen, Variablen,
Konstanten, Klassen) auf Englisch – gilt für neuen Code; bestehende deutsche
Namen nur umbenennen, wenn danach gefragt wird.
