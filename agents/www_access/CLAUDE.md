# Agent www_access (Webserver-Access-Log)

Wertet das Access-Log des Webservers aus (Apache `combined`, optional mit vhost-Präfix wie `vhost_combined`) und meldet **auffällige externe IPs**. Läuft als Runner-Agent (Ausgabetyp 2, Add Sensor Value) auf dem Host mit dem Webserver-Log (Standard `/var/log/apache2/access.log`). Nur Python-Standardbibliothek, kein REST-Lesezugriff.

> Pfade in dieser Datei gelten relativ zu diesem Ordner (außer `agents/run_agents.py`).

## Dateien

| Datei | Zweck |
|---|---|
| `www_access.py` | Agent: Log lesen, Regeln je IP, Kennzahlen und `notify` |
| `run.sh` | Startskript für den Runner |
| `settings.json.skelet` | Vorlage der zentralen Einstellungen (`iot_agent_config.settings`) |
| `notify_state.json` | Wird automatisch geschrieben (bereits gemeldete IPs). Nicht einchecken |

## Befehle

```bash
python3 agents/run_agents.py --run www_access --dry-run   # nichts senden, keinen Zustand speichern
python3 www_access.py --config settings.json --pretty     # lokal mit eigener Einstellungsdatei
```

## Auswertung

- Gelesen werden die Dateien aus `log_files` samt rotierter Dateien (`.1`, `.N.gz`, `.gz`); Dateien mit älterer Änderungszeit als das Zeitfenster entfallen. Ausgewertet werden nur Zeilen der letzten `window_minutes`. Die Monatsnamen werden ohne locale gelesen.
- Nur **externe** IPs: keine privaten/reservierten Netze (laut `ipaddress`, also auch Doku-Netze wie `2001:db8::/32`), nicht in `allowed_ips` (IPs oder Netze).
- Regeln je IP (Schwellen unter `rules`), eine reicht für „auffällig“:
  - `enumeration`: ein Pfad mit ≥ `enum_min_values` verschiedenen Zahlen-IDs (Query-Parameter oder Pfadsegment). Anfragen mit User-Agent aus `known_agents` (Teiltext, z. B. Nextcloud-Clients mit `lastKnownMessageId`) zählen hier nicht.
  - `rate`: Spitze ≥ `max_per_minute` Anfragen pro Minute.
  - `probe`: ≥ `probe_min` Treffer auf `probe_paths` (Teiltext, ohne Rücksicht auf Groß-/Kleinschreibung).
  - `errors`: ≥ `min_requests` Anfragen und Anteil 4xx ≥ `error_ratio`.
- **Sensorwerte** (bewusst nur zwei, in `iot_sensor` anlegen):
  - `<sensor_prefix>_suspicious_ips`: Anzahl auffälliger IPs (mit `max_value` 0 meldet watchdog jeden Wert ab 1)
  - `<sensor_prefix>_max_rate`: höchste Anfragen/min einer einzelnen externen IP
- **Benachrichtigungen:** je auffälliger IP ein deutscher Text, nur beim ersten Auftreten; erneut, wenn die IP `renotify_days` lang nicht auffällig war. Höchstens `notify.max_per_run` pro Lauf.
- Der Bericht (JSON mit Details je auffälliger IP) geht nach stderr. Bei `IOT_DRY_RUN` wird `notify_state.json` nicht gespeichert.
- Der Agent erkennt und meldet nur; Sperren (z. B. fail2ban) gehört nicht hierher.
