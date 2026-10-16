#!/bin/bash
# /home/markus/netzwerk_scan/run_scan.sh
source /home/dk9mbs/src/restapi/venv/restapi/bin/activate
python3 /home/dk9mbs/iptest_v2.py \
  --netz 192.168.2.0/24 \
  --rest-url https://dk9mbs.de/api/v1.0/data/iot_device \
  --rest-user "root" \
  --rest-pass "password"
