"""Artifact freshness watchdog for daily launchd jobs.

Why this exists: on the night of 2026-08-10 a batch of LaunchAgent plists was
corrupted in a way that left four daily jobs *loaded but with no working
trigger*.  ``launchctl`` still listed them, so the existing service sweep --
which alerts on "Not loaded" -- saw nothing wrong, and the jobs silently did
not run for three days.  The stall was only noticed when one of the plists was
later unloaded outright and the "Not loaded" alert finally fired.

Watching launchd state therefore cannot catch this failure class.  What every
daily job *does* have is an artifact: an archive it writes, or a log line it
appends, once per run.  This module watches the artifact instead of the
scheduler: if the newest matching file is older than the job's cadence allows,
the job did not run -- no matter what launchd claims about it.  It is the
second line of defense behind the plist/config archive kept by
``hub.backups`` (first line: the damage is recoverable; this line: the damage
is *noticed*).

Extending the table
-------------------
Add a :class:`Target` to :data:`TARGETS`.  Pick the one file the job itself
touches on **every** run (its product, or a log it appends), and set
``max_age_hours`` to the cadence plus enough slack for runtime drift -- a
daily job that can run for two hours needs ~27h, one that finishes in seconds
needs ~25h.  Patterns go through :func:`glob.glob`, so both literal paths and
wildcards work; the newest match wins.

The sweep itself is wired into :func:`hub.alerts.check_once`, runs on the
alerter thread at ``alert_interval``, and follows the same state-machine
rules as the SMART/UPS checks there: edge-triggered on the persisted state,
a resolve event on recovery, and first sight counts (a stale backup must
alert even when the state file is brand new -- being freshly restarted is
not a reason to stay silent about a job that is not running).
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    #: Stable id; becomes the state key / alert id ``freshness:<id>``.
    id: str
    #: The launchd label, used in alert prose so the operator knows what to fix.
    label: str
    #: Absolute glob for the artifacts this job produces; newest match counts.
    pattern: str
    #: Alert once the newest match is older than this.
    max_age_hours: float


#: Job -> artifact map.  Every entry states *which file* proves the job ran and
#: why that file, because the wrong probe here silently monitors nothing.
TARGETS: tuple[Target, ...] = (
    # backup-configs.sh (04:05) wraps hub.backups.backup_configs(), which writes
    # a timestamped configs_YYYYmmdd_HHMMSS.tgz into Services/backups.  Manual
    # archives (configs_preimmich_...) also match; they are rare, and a fresh
    # manual archive genuinely means a fresh config copy exists.
    Target(
        id="config-backup",
        label="local.config-backup",
        pattern="/Users/a0000/Services/backups/configs_*.tgz",
        max_age_hours=25.0,
    ),
    # backup-db.sh (03:37) gzips a pg_dump to immich_YYYYmmdd_HHMMSS.sql.gz in
    # the same directory.  Its immich_backup.err scratch file does not match
    # this suffix, so a run that only managed to write errors stays stale.
    Target(
        id="immich-backup",
        label="local.immich-backup",
        pattern="/Users/a0000/Services/backups/immich_*.sql.gz",
        max_age_hours=25.0,
    ),
    # regulations_update.py (03:30) has no single product file -- it upserts
    # into a sqlite DB that other backfill agents also write, so the DB mtime
    # cannot distinguish this job from its siblings.  Its launchd stdout log is
    # per-job and appended on every run.  The run may last up to 2h (perl
    # alarm 7200), so the last-append time drifts run to run; 27h keeps ~1h of
    # margin over the worst case (yesterday finished late, today early).
    Target(
        id="onedrive-share-regulations",
        label="local.onedrive-share-regulations",
        pattern="/Users/a0000/Library/Logs/onedrive-share-regulations.log",
        max_age_hours=27.0,
    ),
    # rotate_logs.sh (04:15) appends a completion marker to freshness.log as
    # its final line on every run.  Its launchd .out file is useless as a
    # probe: a clean run prints nothing, so the .out mtime never moves.
    Target(
        id="gravity-rotate-logs",
        label="com.gravity.rotate-logs",
        pattern="/Users/a0000/Services/gravity/logs/freshness.log",
        max_age_hours=25.0,
    ),
)

#: While a target stays stale, remind at most this often.  Deliberately not the
#: SMART ``cooldown_sec`` (30min): a missed daily backup stays missed for ~24h
#: until the next run, and a reminder every sweep-cooldown would be spam that
#: trains the operator to ignore exactly the alert this module exists to send.
REANNOUNCE_SEC = 24 * 3600


def newest_mtime(pattern: str) -> float | None:
    """mtime of the newest file matching *pattern*, or None when nothing does.

    A missing parent directory and an empty glob are the same answer on
    purpose: either way the job's product does not exist, which is exactly
    the condition worth alerting on.  Files that vanish between glob and stat
    (the jobs prune their own old archives) are skipped, not fatal.
    """
    best: float | None = None
    for path in glob.glob(pattern):
        try:
            mt = os.stat(path).st_mtime
        except OSError:
            continue
        if best is None or mt > best:
            best = mt
    return best


def check_freshness(prev: dict, new_state: dict, now: int,
                    targets: tuple[Target, ...] | None = None) -> list:
    """One freshness pass, in the ``(prev, new_state, now)`` shape of the
    other checks in :mod:`hub.alerts`.

    Emits ``down`` (not ``warn``) on staleness: a backup that is >25h overdue
    is a job that did not run, not a trend to watch -- and ``down`` is what
    passes the notify gate on installs that ship ``include_warn=False``, the
    same way the "Not loaded" service alert does.
    """
    from hub import alerts as _alerts

    last_fire = prev.get("_freshness_last")
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    emitted: list = []
    n = _alerts.notify_settings()

    for t in targets if targets is not None else TARGETS:
        key = f"freshness:{t.id}"
        limit_sec = t.max_age_hours * 3600
        mt = newest_mtime(t.pattern)
        age_h = (now - mt) / 3600 if mt is not None else None
        stale = mt is None or (now - mt) > limit_sec
        new_state[key] = "down" if stale else "ok"
        old = prev.get(key)
        last_t = int(last_fire.get(t.id) or 0)

        if stale:
            if mt is None:
                detail = f"no artifact matches {t.pattern}"
                message = (
                    f"{t.label} has produced nothing: no file matches "
                    f"{t.pattern} — the job may be loaded but never firing"
                )
            else:
                detail = f"newest artifact {age_h:.1f}h old (limit {t.max_age_hours:g}h)"
                message = (
                    f"{t.label} artifact is stale: newest match of {t.pattern} "
                    f"is {age_h:.1f}h old (limit {t.max_age_hours:g}h) — the "
                    f"job may be loaded but never firing"
                )
            # Edge-triggered plus a daily re-announce.  No `old is None: skip`:
            # first sight counts, same reasoning as the SMART check -- this
            # code only starts running after a restart, and a job that is
            # already stale at boot must not wait for a second failure.
            if old != "down" or (now - last_t) >= REANNOUNCE_SEC:
                alert = {
                    "t": now,
                    "id": key,
                    "name": f"Freshness · {t.label}",
                    "kind": "freshness",
                    "group": "scheduled",
                    "level": "down",
                    "event": "problem",
                    "detail": detail,
                    "message": message,
                }
                _alerts._append_alert(alert)
                emitted.append(alert)
                new_last[t.id] = now
                if n.get("enabled"):
                    _alerts.send_ha_notify(
                        "ServerHub freshness alert", message, level="down"
                    )
        elif old == "down":
            message = (
                f"{t.label} artifact is fresh again "
                f"({age_h:.1f}h old, limit {t.max_age_hours:g}h)"
            )
            alert = {
                "t": now,
                "id": key,
                "name": f"Freshness · {t.label}",
                "kind": "freshness",
                "group": "scheduled",
                "level": "ok",
                "event": "resolved",
                "detail": f"newest artifact {age_h:.1f}h old",
                "message": message,
            }
            _alerts._append_alert(alert)
            emitted.append(alert)
            # Drop the stamp with the episode so recovery-then-restale alerts
            # immediately instead of waiting out a day-old timer.
            new_last.pop(t.id, None)
            if n.get("enabled") and n.get("notify_resolve", True):
                _alerts.send_ha_notify(
                    "ServerHub freshness recovered", message,
                    level="ok", event="resolved",
                )

    new_state["_freshness_last"] = new_last
    return emitted
