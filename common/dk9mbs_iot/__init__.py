"""
dk9mbs_iot - gemeinsamer Code von IoT-Dashboard und Agenten.

    dk9mbs_iot.query.device   REST-Abfragen der Geraete (iot_device)
    dk9mbs_iot.query.sensor   REST-Abfragen der Sensoren (iot_sensor)
    dk9mbs_iot.query.auth     Anmelde-Header (API-Key oder Benutzer/Passwort)
    dk9mbs_iot.rows           Regeln fuer offline / neu / still / Min-Max
    dk9mbs_iot.agent          REST-Zugang und Einstellungen eines Agenten (vom Runner)

Wird von install/install.sh editierbar ins venv installiert
(pip install -e common), Aenderungen im Repo gelten damit sofort.
"""
