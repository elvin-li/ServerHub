#!/bin/bash
# 3-hour stability/resource audit sampler
OUT="/Users/a0000/Services/serverhub/data/audit_3h.jsonl"
END=$(( $(date +%s) + 3*3600 ))
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin
while [ $(date +%s) -lt $END ]; do
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  load=$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}')
  mem=$(memory_pressure -Q 2>/dev/null | awk -F': ' '/free percentage/{gsub(/%/,"",$2); print $2; exit}')
  # top processes
  tops=$(ps -Arco pcpu,pmem,rss,comm | head -8 | tail -7 | awk '{printf "%s:%.1f%%/%sMB ", $4, $1, int($3/1024)}')
  # key services
  ha=$(pgrep -f 'venv/bin/hass' >/dev/null && echo up || echo down)
  hub=$(curl -sS -m 2 -o /dev/null -w '%{http_code}' http://localhost:8086/api/status 2>/dev/null || echo 0)
  hahttp=$(curl -sS -m 2 -o /dev/null -w '%{http_code}' http://localhost:8123/ 2>/dev/null || echo 0)
  # gravity stuck?
  gcnt=$(pgrep -f 'update_daily_incremental' | wc -l | tr -d ' ')
  # HA recent errors
  herr=$(grep -c 'ERROR' /Users/a0000/Services/homeassistant/config/home-assistant.log 2>/dev/null || echo 0)
  printf '{"t":"%s","load":"%s","mem_free_pct":"%s","ha":"%s","hub_http":"%s","ha_http":"%s","gravity_upd":%s,"ha_err_lines":%s,"tops":"%s"}\n' \
    "$ts" "$load" "$mem" "$ha" "$hub" "$hahttp" "$gcnt" "$herr" "$tops" >> "$OUT"
  sleep 300
done
echo "{\"t\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"done\":true}" >> "$OUT"
