#!/bin/bash
# Recover the ServerHub panel when launchd believes it is running but nothing
# is answering on its port.
#
# KeepAlive already covers the ordinary case: the panel exits, launchd starts a
# replacement.  It does not cover the failure this script exists for, which has
# been observed on this host -- `launchctl kickstart -k` tears the old process
# down, and the replacement wedges in xpcproxy: spinning on CPU, never exec'ing
# python, never listening, and never exiting.  launchd considers the job alive
# (state = running, a pid is assigned), so KeepAlive never fires and the panel
# stays down until someone kills the stuck process by hand.  That is the
# "panel does not come back after a reboot" symptom.
#
# Conservative by construction, because a watchdog that restarts too eagerly is
# worse than the fault it fixes:
#   * It only ever acts on a label that is currently loaded.  If you booted the
#     job out on purpose, this stays out of the way.
#   * It requires FAIL_THRESHOLD consecutive unreachable probes (~3 minutes at
#     the default 60s interval) before touching anything, so a slow boot, a
#     deliberate restart, or a long GC pause is never mistaken for a hang.
#   * Any HTTP response at all counts as healthy, including 401.  The panel
#     requires authentication, so "refused sign-in" still proves it is serving.
set -u

PORT="${SERVERHUB_PORT:-8086}"
FAIL_THRESHOLD="${SERVERHUB_WATCHDOG_THRESHOLD:-3}"
STATE_FILE="${TMPDIR:-/tmp}/serverhub-watchdog.state"
LOG="$HOME/Library/Logs/serverhub-watchdog.log"
DOMAIN="gui/$(id -u)"

# StartInterval + a slow probe can overlap. Two writers racing the fail
# counter reached the threshold in one second and kickstarted a live panel.
# launchd PATH is /usr/bin:/bin — no util-linux `flock` on macOS. mkdir is
# atomic on APFS and is held for the life of this process via EXIT trap.
LOCK_DIR="${STATE_FILE}.lck"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  # Stale leftover from a SIGKILL'd tick (trap never ran).
  age=$(( $(date +%s) - $(stat -f %m "$LOCK_DIR" 2>/dev/null || echo 0) ))
  if [ "$age" -le 180 ]; then
    exit 0
  fi
  rmdir "$LOCK_DIR" 2>/dev/null || rm -rf "$LOCK_DIR"
  mkdir "$LOCK_DIR" 2>/dev/null || exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT INT TERM

log() { printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$*" >> "$LOG"; }

# Keep the log from growing without bound; this runs every minute forever.
if [ -f "$LOG" ] && [ "$(stat -f%z "$LOG" 2>/dev/null || echo 0)" -gt 262144 ]; then
  tail -n 500 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
fi

# Prefer the lineage that actually owns this host (com.elvin.serverhub).
# The app still knows how to bootstrap local.serverhub; if that label is
# listed first, a kickstart restarts the loser of the bind race.
LABEL=""
for candidate in com.elvin.serverhub local.serverhub.panel local.serverhub; do
  if launchctl print "$DOMAIN/$candidate" >/dev/null 2>&1; then
    LABEL="$candidate"
    break
  fi
done

if [ -z "$LABEL" ]; then
  # Nothing loaded: the panel was intentionally removed or booted out.
  rm -f "$STATE_FILE"
  exit 0
fi

# A listener on the panel port is enough: do not kickstart a serving process
# just because /api/health was slow. curl -f treats 401 as failure, so use -sS.
if curl -sS -o /dev/null --max-time 3 "http://127.0.0.1:$PORT/api/health" 2>/dev/null \
   || lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if [ -f "$STATE_FILE" ]; then
    log "panel healthy again on port $PORT ($LABEL)"
    rm -f "$STATE_FILE"
  fi
  exit 0
fi

fails=0
[ -f "$STATE_FILE" ] && fails="$(cat "$STATE_FILE" 2>/dev/null || echo 0)"
case "$fails" in ''|*[!0-9]*) fails=0 ;; esac
fails=$((fails + 1))
printf '%s' "$fails" > "$STATE_FILE"
log "port $PORT unreachable ($fails/$FAIL_THRESHOLD) label=$LABEL"

[ "$fails" -lt "$FAIL_THRESHOLD" ] && exit 0

# Threshold reached.  Clear a wedged xpcproxy first: while it holds the job's
# pid, launchd reports the job as running and kickstart cannot make progress.
stuck="$(pgrep -f "xpcproxy $LABEL" 2>/dev/null | head -1)"
if [ -n "$stuck" ]; then
  log "killing wedged xpcproxy pid=$stuck"
  kill -9 "$stuck" 2>/dev/null
  sleep 2
fi

log "restarting $LABEL"
if launchctl kickstart -k "$DOMAIN/$LABEL" >/dev/null 2>&1; then
  log "kickstart issued for $LABEL"
else
  log "kickstart FAILED for $LABEL"
fi

# Reset the counter so the next run starts a fresh window rather than
# restarting again on the very next tick while the panel is still booting.
rm -f "$STATE_FILE"
exit 0
