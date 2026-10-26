# Agent shelly_syslog (Shelly Access Report)

Wertet die Syslogs der Shelly-Geräte aus: **wer hat auf welchen Shelly zugegriffen** und wie auffällig ist das? Jede Zugriffsgruppe bekommt einen Auffälligkeits-Score. Läuft als Runner-Agent (Ausgabetyp 2, Add Sensor Value) auf dem Host `nextcloud`, der die Shelly-Syslogs empfängt (`/var/log/shelly`). Das Kernmodul ist zusätzlich eigenständig als CLI nutzbar.

> Dieser Ordner liegt als **Unterordner** im Projekt IoT-Dashboard. Pfade in dieser Datei gelten **relativ zu diesem Ordner** (außer `agents/run_agents.py`).

## Dateien

| Datei | Zweck |
|---|---|
| `shelly_syslog.py` | Runner-Agent: liest Einstellungen/REST-Zugang vom Runner, gibt Sensorwerte und `notify` aus |
| `run.sh` | Startskript für den Runner (wie bei den anderen Agenten) |
| `SCORE.md` | Doku des Auffälligkeits-Scores mit Beispielen. **Bei Änderungen an Gewichten oder Faktoren mitpflegen** |
| `settings.json.skelet` | Vorlage der zentralen Einstellungen (`iot_agent_config.settings`) |
| `requirements.txt` | `requests` (für `dk9mbs_iot.query.device`) |
| `shelly_access_report.py` | Kernmodul: CLI und wiederverwendbare Klassen, nur Standardbibliothek |
| `shelly_access_config.json` | Score-Konfiguration für die eigenständige CLI |
| `known_devices.json` | Bekannte Geräte nur für die eigenständige CLI (der Agent nimmt `iot_device`). Enthält Netzwerkdaten, **nicht einchecken** |
| `known_devices.json.skelet` | Vorlage mit Demo-Werten (wird eingecheckt). Für eine neue Installation nach `known_devices.json` kopieren |
| `shelly_access_history.json` | Wird automatisch geschrieben (frühere Läufe). Nicht einchecken |
| `notify_state.json` | Wird automatisch geschrieben (bereits gemeldete auffällige Zugriffe). Nicht einchecken |

Ort im Projekt: `agents/shelly_syslog/` im Repo IoT-Dashboard (Namensschema wie `omada_syslog`). Für den Agenten gelten die Agenten-Regeln aus der Root-CLAUDE.md (stdout nur JSON über `write_output()`, Log auf stderr, `IOT_DRY_RUN` beachten).

## Befehle

Die CLI sucht ihre Konfiguration immer neben dem Skript, egal aus welchem Ordner sie gestartet wird.

```bash
# als Agent (vom Projekt-Root bzw. agents/ aus)
python3 agents/run_agents.py --run shelly_syslog --dry-run   # nichts senden, keinen Zustand speichern
python3 agents/run_agents.py --run shelly_syslog
python3 shelly_syslog.py --config settings.json --pretty     # lokal mit eigener Einstellungsdatei (braucht IOT_REST_*)

# eigenständige CLI
python3 shelly_access_report.py                          # liest /var/log/shelly, JSON auf stdout
python3 shelly_access_report.py -d ./testlogs -o report.json
python3 shelly_access_report.py --sort-by-score --suspicious-only
python3 shelly_access_report.py --threshold 30 --no-history
python3 shelly_access_report.py --write-only --exclude-internal --compact
python3 shelly_access_report.py --help
```

## Rahmenbedingungen

- **Kernmodul `shelly_access_report.py`: nur Python-Standardbibliothek** und Python ≥ 3.9, keine Imports aus dem Projekt. Projektabhängiges (`dk9mbs_iot`, REST) gehört nach `shelly_syslog.py`. Keine weiteren externen Pakete ohne Rückfrage.
- **Bezeichner auf Englisch** (Klassen, Funktionen, Variablen, CLI-Optionen, JSON-Schlüssel, Ausgabetexte, Hilfetexte). **Kommentare und Docstrings dürfen deutsch sein.**
- **Das JSON-Ausgabeformat ist eine Schnittstelle.** Schlüssel nicht umbenennen oder entfernen, ohne vorher zu fragen. Neue Felder hinzufügen ist in Ordnung.
- **Iterativ arbeiten.** Gezielte Änderungen und Erweiterungen statt kompletter Neuschreibungen.
- **Bei Rückfragen erst entwickeln und alle Fragen gesammelt am Ende stellen.**
- Mit dem Nutzer auf Deutsch kommunizieren.
- Regeln aus der CLAUDE.md im Projekt-Root gelten zusätzlich. Bei Widersprüchen gilt für dieses Modul diese Datei. Insbesondere sind hier auf Wunsch des Nutzers die Ausgabe- und Hilfetexte des Kernmoduls (Bericht-JSON, `pattern`, `reasons`, CLI) englisch, abweichend von der Root-Regel „Ausgaben auf Deutsch“. **Ausnahme:** `message` und `notify` des Agenten sind deutsch wie bei den anderen Agenten; die `reasons` übersetzt `reason_de()` in `shelly_syslog.py` (bei neuen Begründungen im Kernmodul dort ergänzen).
- Echte Netzwerkdaten (IPs, MACs) nur in nicht eingecheckten Dateien, im Repo nur `*.skelet` mit Demo-Werten.

## Agent (`shelly_syslog.py`)

- Einstellungen aus `IOT_AGENT_SETTINGS` (Vorlage `settings.json.skelet`): `log_dir`, `window_minutes` (nur Zugriffe der letzten N Minuten; ältere Dateien werden übersprungen), `namespace`, `sensor_prefix`, `per_target_metrics`, `notify`, `known_devices`, `scoring`, `history`, `state_file`.
- **Bekannte Geräte:** `iot_device` mit Status `active`, Name = `host_name` (`RestKnownDeviceProvider`), dazu `known_devices` aus den Einstellungen (z. B. MQTT-Client `iobroker`, der nicht in `iot_device` steht). Die IP des Shellys selbst (Ziel) kommt aus `iot_device` (`id` bzw. `host_name` = Hostname im Log).
- **Sensorwerte** (Ausgabetyp 2), `sensor_id` = `<sensor_prefix>_<kennzahl>`: `max_score`, `suspicious`, `accesses`, `write_accesses`, `sources`, `unknown_sources`, `external_sources`. Mit `per_target_metrics` zusätzlich `<prefix>_<host>_max_score` / `_accesses` je Shelly. Die Sensoren müssen in `iot_sensor` angelegt sein.
- **Benachrichtigungen:** auffällige Gruppen als `notify`, je Gruppe nur einmal, bis neuere Zugriffe dazukommen (`notify_state.json`), höchstens `max_per_run` pro Lauf.
- `rate_per_hour` bezieht sich im Agenten auf `window_minutes` (feste Fensterlänge).
- Bei `IOT_DRY_RUN` werden Historie und Benachrichtigungs-Zustand nicht gespeichert.

## Architektur Kernmodul (`shelly_access_report.py`)

Datenfluss: Logdatei → `LogRecord` → `RpcAccess` → `AccessGroup` → Score → JSON.

- `ShellyLogReader`: liest `*.log`, `*.log.N`, `*.log.gz` und `*.log.N.gz`. Trennt Einträge, die rsyslog mit `#000` in einer Zeile zusammengefasst hat. Zeitstempel sind im ISO-Format mit Offset, die Sommer-/Winterzeit ist zu beachten.
- `RpcParser`: wertet nur Zeilen aus `shos_rpc_inst.c` aus. Er vereinheitlicht die Schreibweise der Methode (`sys.setconfig` → `Sys.setconfig`) und unterscheidet `read` (Get/List/Check/Ping/Echo, ohne Rücksicht auf Groß- und Kleinschreibung) von `write`.
- `TransportParser`: zerlegt den Teil `via …` in Kanal und `Source`.
- `PatternDescriber`: erkennt Blöcke (Abstand < 2 s) und regelmäßiges Polling und erzeugt den Text für `pattern`.
- `ShellyAccessAnalyzer`: gruppiert nach (Quelle, Ziel, Methode ohne Rücksicht auf Groß- und Kleinschreibung, Kanal). Bei mehreren Schreibweisen gewinnt die CamelCase-Form.
- `ScoringConfig`: `load(path)` für die CLI, `from_dict(settings, base_dir)` für den Agenten. Relative Pfade gelten relativ zur Konfigurationsdatei bzw. `base_dir`.
- `KnownDeviceProvider` ist die Basisklasse (`load_devices()` liefert `{"address"|"mqtt_client": …, "name": …}`). Unterklassen: `JsonKnownDeviceProvider`, `StaticKnownDeviceProvider`, `CombinedKnownDeviceProvider`; `RestKnownDeviceProvider` steht im Agenten.
- `RpcParser(host_addresses=…)`: optionale Zuordnung Hostname → IP für das Ziel.
- `ShellyAccessAnalyzer(since=…)`: optionales Zeitfenster.
- `HistoryStore`: speichert pro Lauf die Raten je Gruppe und die gesehenen Quellen, maximal `baseline_days` Tage.
- `AnomalyScorer`: berechnet den Score. Er addiert gewichtete Faktoren, begrenzt auf 0–100, und liefert `reasons` mit.
- `AccessReport`: baut die Zusammenfassung und das JSON und schreibt die Historie fort. Grundlage dafür sind die ungefilterten Gruppen, damit CLI-Filter die Historie nicht verfälschen. `window_hours` legt die Fensterlänge für `rate_per_hour` fest.

## Logformate (wichtig beim Ändern der Regex)

Eintrag: `<host> <seq> <uptime> <lvl> <x>|<quelldatei>:<zeile> <nachricht>`

| Gerät / Fall | Beispiel für den Teil `via …` | Ergebnis |
|---|---|---|
| Pro-Geräte (HTTP) | `via HTTP_in GET from 192.168.0.10:46098 via en0` | IP plus Schnittstelle |
| Plus-Geräte (HTTP) | `via HTTP_in GET 192.168.0.10:33048` (**ohne `from`**) | IP |
| WebSocket | `via WS_in from 192.168.0.161:43510 via en0` / `via WS_in 192.168.0.123:59376` | IP, Kanal WebSocket |
| MQTT | `Switch.Set [3@iobroker] via MQTT` | `type: MQTT`, `client_id` aus `[id@client]`, **keine IP im Log** |
| Shelly Cloud | `via SHC 35.205.13.146:6022` | IP, Kanal `Shelly Cloud` |
| Script auf dem Gerät | `[586@RPC.LOCAL] via loopback` | `type: internal` |
| nicht erkannt | – | `type: unknown`, Originaltext in `transport` |

Die RPC-Quelle `web-<id>` steht für die Web-Oberfläche, eine UUID für einen Browser-Client.

## Score (Standard-Gewichte, einstellbar)

| Faktor | Punkte |
|---|---|
| unbekannte Quelle | +35 |
| öffentliche IP (außer Shelly Cloud) | +25 |
| schreibender Zugriff | +10 |
| sensible Aktion | +25 |
| nachts | +10 |
| unregelmäßiges Muster | +5 |
| hohe Rate pro Minute (z. B. HTTP-/RPC-Scan) | +20 |
| neue Quelle (Historie) | +30 |
| Ratenabweichung (Historie) | +15 |
| interner Aufruf | −20 |
| Lesezugriff der Cloud | −10 |

- „Unbekannte Quelle“ zählt nur, wenn eine Geräteliste konfiguriert ist.
- Die Historien-Faktoren greifen erst ab dem zweiten Lauf.
- `suspicious` ist true, wenn der Score den Schwellwert erreicht oder überschreitet.

## Testen

Es gibt noch keine automatisierten Tests. Nach jeder Änderung:

1. Das Skript gegen Beispiel-Logs laufen lassen, zum Beispiel aus einem Ordner `testlogs/` mit Pro- und Plus-Zeilen. Den Agenten mit `run_agents.py --run shelly_syslog --dry-run` prüfen; für Tests ohne Server `IotDeviceClient` durch eine Fake-Klasse ersetzen und die Ausgabe mit `agent_output.parse_output()` prüfen.
2. Das JSON mit einem gespeicherten Referenzlauf vergleichen, das Feld `created` vorher entfernen.
   Bei reinen Umbauten muss die Ausgabe identisch bleiben.
3. Grenzfälle prüfen: `.gz`-Dateien, Zeilen mit `#000`, fehlender Zeitstempel, IPv6 und Methodennamen in Kleinschreibung.

## Offene Ideen

- Flag `allow_night` pro Gerät, damit Automatisierungen wie nächtliche Schaltbefehle von ioBroker nicht als „nachts“ zählen.
- Automatisierte Tests mit `unittest` und Beispiel-Logs als Fixtures.
