# Auffälligkeits-Score des Agenten shelly_syslog

Der Agent fasst die Zugriffe auf jeden Shelly zu **Zugriffsgruppen** zusammen. Eine Gruppe besteht aus allen Zugriffen mit gleicher Quelle, gleichem Ziel-Shelly, gleicher Aktion (RPC-Methode) und gleichem Kanal, zum Beispiel „192.168.0.10 ruft auf shellypro2 `Shelly.GetStatus` per HTTP GET auf“.

Jede Gruppe bekommt einen **Score von 0 bis 100**. Je höher der Score, desto ungewöhnlicher ist der Zugriff. Zusätzlich gibt es eine Liste `reasons` mit den Gründen, die zum Score geführt haben.

## So wird gerechnet

Der Score ist eine **Summe von Punkten**. Für jedes zutreffende Merkmal kommen die Punkte des Faktors hinzu. Die Summe wird danach auf den Bereich 0 bis 100 begrenzt.

| Faktor | Punkte | Trifft zu, wenn … |
|---|---:|---|
| `unknown_source` | +35 | die Quelle nicht in der Liste bekannter Geräte steht |
| `external_source` | +25 | die Quelle eine öffentliche IP-Adresse hat (die Shelly Cloud ausgenommen) |
| `write` | +10 | der Zugriff schreibend ist, also nicht `Get…`, `List…`, `Check…`, `Ping` oder `Echo` |
| `sensitive_action` | +25 | die Aktion sicherheitsrelevant ist, z. B. `WiFi.SetConfig` oder `Shelly.Update` (Liste unten) |
| `night` | +10 | mindestens ein Zugriff nachts stattfand (Standard 00:00 bis 05:00 Uhr) |
| `irregular` | +5 | die Zugriffe unregelmäßig kommen statt in festem Takt (erst ab 4 Blöcken bewertet) |
| `high_rate` | +20 | in einer Minute mindestens 60 Aufrufe kamen, z. B. bei einem HTTP-/RPC-Scan |
| `new_source` | +30 | die Quelle in der Historie (Standard 7 Tage) noch nie vorkam |
| `rate_deviation` | +15 | die Rate mindestens 5× höher ist als im Schnitt der Historie |
| `internal` | −20 | der Aufruf vom Shelly selbst kommt (`loopback`, z. B. ein Script) |
| `cloud_read` | −10 | die Shelly Cloud nur lesend zugreift |

### Negative Werte (Abzüge)

Die beiden negativen Faktoren sind **Abzüge**. Sie gleichen Pluspunkte aus, die ein Zugriff nur wegen seiner Art bekommt, obwohl er erwartet ist:

- **`internal` (−20):** Ein Script auf dem Shelly darf schalten oder Einstellungen lesen, auch nachts. Der Abzug hebt „schreibend“ (+10) und „nachts“ (+10) wieder auf.
- **`cloud_read` (−10):** Die Shelly Cloud fragt den Shelly regelmäßig ab, auch nachts. Der Abzug hebt „nachts“ (+10) wieder auf.

Ein Abzug kann den Score nie unter 0 drücken. Hat ein Zugriff ohnehin 0 Punkte, bewirkt der Abzug nichts. Er wirkt nur, wenn gleichzeitig Pluspunkte anfallen.

Ein Abzug macht einen Zugriff aber nicht automatisch harmlos. Ändert ein Script nachts mit `Sys.SetConfig` die Systemeinstellungen, ergibt das 10 + 25 + 10 − 20 = **25** Punkte. Der Zugriff bleibt im Bericht sichtbar, liegt aber unter dem Schwellwert. Wer solche Zugriffe trotzdem gemeldet haben will, setzt das Gewicht `internal` auf 0.

Eine Gruppe gilt als **auffällig** (`suspicious: true`), wenn ihr Score den Schwellwert erreicht oder überschreitet. Der Standard-Schwellwert ist **50**. Nur auffällige Gruppen werden als Benachrichtigung gemeldet.

### Wichtige Regeln

- **Bekannte Geräte:** Als bekannt gelten alle Geräte aus `iot_device` mit Status `active`, angezeigt mit ihrem `host_name`. Dazu kommen die Einträge unter `known_devices` in den Einstellungen, z. B. MQTT-Clients wie `iobroker`, die nicht in `iot_device` stehen. Die Shelly Cloud gilt als bekannt, solange `trust_shelly_cloud` an ist.
- **„Unbekannte Quelle“** zählt nur, wenn überhaupt eine Geräteliste vorhanden ist. Ohne Liste wäre sonst jede Quelle unbekannt.
- **Historie:** „Neue Quelle“ und „Ratenabweichung“ greifen erst ab dem **zweiten Lauf**, wenn es eine Historie zum Vergleichen gibt.
- **Nachtzeit:** Sie wird nach der Ortszeit im Log geprüft. Die Sommer- und Winterzeit ist im Zeitstempel enthalten.
- **Nur RPC-Aufrufe zählen:** Der Score bewertet nur Aufrufe, die der Shelly protokolliert. Ein Ping-Scan oder ein reiner Port-Scan erscheint im Shelly-Log nicht und kann deshalb auch nicht bewertet werden.

### Sensible Aktionen (Standard)

`Sys.SetConfig`, `WiFi.SetConfig`, `Eth.SetConfig`, `Mqtt.SetConfig`, `Cloud.SetConfig`, `Ws.SetConfig`, `BLE.SetConfig`, `Shelly.SetAuth`, `User.SetConfig`, `Shelly.Update`, `Shelly.Reboot`, `Shelly.FactoryReset`, `Shelly.ResetWiFiConfig`, `Script.PutCode`, `Script.Create`, `Script.Delete`, `Script.SetConfig`, `Schedule.Create`, `Webhook.Create`, `KVS.Set`

Groß- und Kleinschreibung spielt keine Rolle. `sys.setconfig` von Plus-Geräten zählt also genauso.

## Beispiele

Die folgenden Werte hat der Agent selbst mit den Standard-Gewichten berechnet.

### Unauffällig

**1. Monitoring fragt regelmäßig den Status ab → Score 0**
Das bekannte Gerät 192.168.0.10 ruft alle ~15 s `Shelly.GetStatus` auf.

| Merkmal | Punkte |
|---|---:|
| bekannt, lesend, regelmäßig, tagsüber | 0 |
| **Summe** | **0** |

**2. Shelly Cloud liest nachts die Komponenten → Score 0**
`Shelly.GetComponents` um 03:00 Uhr über den Kanal `Shelly Cloud`.

| Merkmal | Punkte |
|---|---:|
| 1× nachts | +10 |
| Lesezugriff der Shelly Cloud | −10 |
| **Summe** | **0** |

Ohne den Abzug hätte die Cloud nachts 10 Punkte bekommen, obwohl das normales Verhalten ist.

**3. Script auf dem Shelly schaltet nachts → Score 0**
Ein Script ruft um 03:00 Uhr `Switch.Set` auf (`loopback`).

| Merkmal | Punkte |
|---|---:|
| schreibender Zugriff | +10 |
| 1× nachts | +10 |
| interner Aufruf | −20 |
| **Summe** | **0** |

Ohne den Abzug wären es 20 Punkte für eine ganz normale Automatik.

### Erwartet, aber mit Punkten

**4. ioBroker schaltet über MQTT, einmal davon nachts → Score 25**
Der MQTT-Client `iobroker` ist bekannt. Er schaltet mit `Switch.Set` unregelmäßig über den Tag verteilt, einmal um 03:00 Uhr.

| Merkmal | Punkte |
|---|---:|
| schreibender Zugriff | +10 |
| 1× nachts | +10 |
| unregelmäßig | +5 |
| **Summe** | **25** → nicht auffällig |

**5. Konfigurationsänderung über die Web-Oberfläche → Score 35**
Ein bekannter PC ändert mit `Sys.SetConfig` die Systemeinstellungen.

| Merkmal | Punkte |
|---|---:|
| schreibender Zugriff | +10 |
| sensible Aktion `Sys.SetConfig` | +25 |
| **Summe** | **35** → nicht auffällig |

Hier bleibt ein bekanntes Gerät bewusst unter dem Schwellwert. Die Änderung erscheint im Bericht, löst aber keine Meldung aus.

**6. Bekanntes Polling plötzlich 5× so häufig → Score 15**
192.168.0.10 fragt mit 200 Aufrufen pro Stunde ab statt wie bisher im Schnitt 40.

| Merkmal | Punkte |
|---|---:|
| Rate 5× höher als üblich | +15 |
| **Summe** | **15** → nicht auffällig, aber im Bericht sichtbar |

### Auffällig

**7. HTTP-Scan von unbekannter IP im LAN, tagsüber → Score 55**
192.168.0.77 steht nicht in der Geräteliste und ruft in einer Minute 70× `Shelly.GetStatus` auf.

| Merkmal | Punkte |
|---|---:|
| unbekannte Quelle | +35 |
| hohe Rate: 70 Aufrufe/min | +20 |
| **Summe** | **55** → **auffällig** |

Nachts kämen noch 10 Punkte für „nachts“ hinzu, das ergäbe **65**.

**8. Neues unbekanntes Gerät fragt einmal ab → Score 65**
192.168.0.99 ruft einmal `Shelly.GetDeviceInfo` auf und kam in den letzten 7 Tagen nie vor.

| Merkmal | Punkte |
|---|---:|
| unbekannte Quelle | +35 |
| neue Quelle | +30 |
| **Summe** | **65** → **auffällig** |

Beim nächsten Lauf ist die Quelle nicht mehr „neu“. Bleibt es bei einzelnen Lesezugriffen, sinkt der Score auf 35. Gemeldet wird die Gruppe ohnehin nur einmal, bis neue Zugriffe dazukommen.

**9. WLAN-Konfiguration von einer öffentlichen IP → Score 95 bzw. 100**
85.10.20.30 ändert mit `WiFi.SetConfig` die WLAN-Einstellungen.

| Merkmal | Punkte |
|---|---:|
| unbekannte Quelle | +35 |
| öffentliche Adresse | +25 |
| schreibender Zugriff | +10 |
| sensible Aktion `WiFi.SetConfig` | +25 |
| **Summe tagsüber** | **95** → **auffällig** |
| nachts zusätzlich | +10 → 105, **auf 100 begrenzt** |

Das ist der schlimmste Fall: Jemand von außen ändert die Netzwerkeinstellungen eines Shellys.

## Was der Agent mit dem Score macht

- **Bericht im Agenten-Log:** Jede Gruppe erscheint mit `anomaly.score`, `anomaly.suspicious` und `anomaly.reasons`, sortiert nach Score.
- **Sensorwerte** nach `iot_sensor_data` (Namespace `shelly.syslog`):
  - `shelly_syslog_max_score`: höchster Score im Zeitfenster
  - `shelly_syslog_suspicious`: Anzahl auffälliger Gruppen
  - außerdem `_accesses`, `_write_accesses`, `_sources`, `_unknown_sources` und `_external_sources`
- **Benachrichtigung** für jede auffällige Gruppe, auf Deutsch und mit den Gründen. Beispiel:
  > Shelly shellypro2-aabbccddeeff: auffälliger Zugriff von 192.168.0.77 - Shelly.GetStatus 70× über HTTP GET (Score 55: unbekannte Quelle, hohe Rate: 70 Aufrufe/min)

  Jede Gruppe wird nur einmal gemeldet. Erst wenn neue Zugriffe dazukommen, gibt es wieder eine Meldung.

## Einstellen

Alle Werte stehen im Block `scoring` der Agenten-Einstellungen. Zentral liegen sie in `iot_agent_config.settings`, die Vorlage ist `settings.json.skelet`.

```json
"scoring": {
  "threshold": 50,
  "weights": { "unknown_source": 35, "high_rate": 20, "...": "..." },
  "night_hours": { "start": 0, "end": 5 },
  "high_rate_per_minute": 60,
  "rate_deviation_factor": 5,
  "trust_shelly_cloud": true,
  "sensitive_actions": ["Sys.SetConfig", "..."]
}
```

- **Weniger Meldungen:** `threshold` erhöhen, z. B. auf 60.
- **Mehr Meldungen:** `threshold` senken. Bei 35 würde z. B. auch Beispiel 5 gemeldet, also jede Konfigurationsänderung über die Web-Oberfläche.
- **Faktor abschalten:** sein Gewicht auf `0` setzen.
- **Nachtzeit über Mitternacht:** z. B. `"start": 22, "end": 6`.
- Die Historie steuert der Block `history` (`enabled`, `baseline_days`).
