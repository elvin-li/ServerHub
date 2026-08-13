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
# A port that is not a number cannot be probed, only miscounted: curl fails on
# the garbage URL, lsof matches nothing, and three ticks later the real panel
# gets kickstarted over an env typo.  Refuse to run instead (stderr lands in
# serverhub-watchdog.err.log, so the misconfiguration is visible).
case "$PORT" in ''|*[!0-9]*)
  printf 'panel-watchdog: SERVERHUB_PORT=%s is not a port; nothing probed\n' "$PORT" >&2
  exit 0 ;;
esac
FAIL_THRESHOLD="${SERVERHUB_WATCHDOG_THRESHOLD:-3}"
# The failure counter is scoped to the probed port.  It used to be one shared
# file, and on 2026-08-13 03:49 a manual test run with SERVERHUB_PORT=59999
# fed its misses into the same counter the production 8086 probe reads: the
# production 8086 tick jumped straight to 3/3 on counts it never took and
# kickstarted a healthy panel.  Per-port state keeps a test's arithmetic out
# of production's.
STATE_FILE="${TMPDIR:-/tmp}/serverhub-watchdog.${PORT}.state"
# One-shot migration: a counter left at the pre-scoping path would otherwise
# sit in /tmp unread forever, and a stale shared count is exactly what this
# change removes.
rm -f "${TMPDIR:-/tmp}/serverhub-watchdog.state"
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
  tmp="$LOG.$$.tmp"
  tail -n 500 "$LOG" > "$tmp" 2>/dev/null && mv "$tmp" "$LOG"
  rm -f "$tmp"
fi

# Backstop rotation for the panel's launchd logs.  launchd appends to
# StandardOut/ErrorPath forever and macOS rotates neither; on this host a
# daily agent (local.services-logrotate) truncates them at 1-8 MiB, but that
# automation is host infrastructure, not part of ServerHub -- an install
# without it grows these files without bound.  10 MiB sits above the daily
# job's thresholds, so wherever that job exists it acts first and this never
# fires.  Copy-then-truncate, never rename: launchd holds the files open with
# O_APPEND, so a rename would leave it writing to the unlinked inode until
# the next panel restart.  gzip first and truncate only on its success, so
# the tail that explains a crash always survives, in <log>.0.gz -- a name the
# logrotate agent's .1.gz..5.gz chain never touches.
PANEL_LOG_MAX=$((10 * 1024 * 1024))
for panel_log in "$HOME/Library/Logs/serverhub.out.log" \
                 "$HOME/Library/Logs/serverhub.err.log" \
                 "$HOME/Library/Logs/serverhub-watchdog.err.log"; do
  [ -f "$panel_log" ] || continue
  [ "$(stat -f%z "$panel_log" 2>/dev/null || echo 0)" -gt "$PANEL_LOG_MAX" ] || continue
  if gzip -c "$panel_log" > "$panel_log.0.gz" 2>/dev/null; then
    : > "$panel_log"
    log "rotated $(basename "$panel_log") past $PANEL_LOG_MAX bytes into $(basename "$panel_log").0.gz"
  else
    # Failed compress (full disk, most likely): keep the original intact and
    # drop the partial archive rather than truncating data away.
    rm -f "$panel_log.0.gz"
  fi
done

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

# Which port that label serves is recorded in its plist environment --
# install.sh, the native launcher and the legacy install all set
# SERVERHUB_PORT there.  A watchdog probing any *other* port has found a
# label, not its panel: the 2026-08-13 test run above also kickstarted the
# live panel on its own third miss, because three misses on 59999 said
# nothing about the panel serving 8086.  When no port can be read from the
# label, assume it matches (the pre-guard behaviour): keep covering an
# oddly-registered panel rather than letting this guard fail closed and
# never restart anything.
label_port="$(launchctl print "$DOMAIN/$LABEL" 2>/dev/null \
  | sed -n 's/.*SERVERHUB_PORT => *//p' | head -n 1)"
case "$label_port" in ''|*[!0-9]*) label_port="$PORT" ;; esac
if [ "$label_port" != "$PORT" ]; then
  log "label $LABEL serves port $label_port, not $PORT; leaving it alone"
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
