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

Configuring targets
-------------------
Targets live in services.yaml under a top-level ``freshness_targets:`` list,
hot-reloaded like the rest of the config.  There are no built-in entries:
which artifact proves which job ran is install-specific by nature, and a
shipped default would watch files that exist on exactly one machine::

    freshness_targets:
      - id: config-backup           # state key / alert id `freshness:<id>`
        label: local.config-backup  # launchd label, shown in alert prose
        pattern: ~/Services/backups/configs_*.tgz
        max_age_hours: 25

Pick the one file the job itself touches on **every** run (its product, or a
log it appends), and set ``max_age_hours`` to the cadence plus enough slack
for runtime drift -- a daily job that can run for two hours needs ~27h, one
that finishes in seconds needs ~25h.  Patterns go through :func:`glob.glob`,
so both literal paths and wildcards work; the newest match wins.

The sweep itself is wired into :func:`hub.alerts.check_once`, runs on the
alerter thread at ``alert_interval``, and follows the same state-machine
rules as the SMART/UPS checks there: edge-triggered on the persisted state,
a resolve event on recovery, and first sight counts (a stale backup must
alert even when the state file is brand new -- being freshly restarted is
not a reason to stay silent about a job that is not running).
"""
from __future__ import annotations

import glob
import logging
import os
import re
import time
from dataclasses import dataclass

log = logging.getLogger("serverhub.freshness")


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


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


#: ids end up in state keys, alert ids and alert prose, so they keep the shape
#: the original hardcoded table used.
_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9-]{0,63}\Z")


def configured_targets(raw: list | None = None) -> tuple[Target, ...]:
    """The job -> artifact map from services.yaml (``freshness_targets:``).

    Malformed entries are skipped with a log line rather than raising: this
    runs on the alert thread, and one mistyped row must not silently disable
    the watchdog for every other job (check_once would swallow the exception,
    and a watchdog that stops watching is the incident all over again).
    Skipped means: id missing/duplicate/oddly shaped, pattern not absolute
    once ``~`` is expanded, or max_age_hours not a positive number.
    """
    if raw is None:
        from hub.config import cfg
        raw = cfg().get("freshness_targets")
    if not isinstance(raw, list):
        return ()
    out: list[Target] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            log.warning("freshness_targets: skipping non-mapping entry %r", entry)
            continue
        try:
            tid = str(entry.get("id") or "").strip()
        except Exception:
            log.warning("freshness_targets: skipping malformed entry %r", entry)
            continue
        try:
            pattern = os.path.expanduser(_utf8_text(entry.get("pattern") or "").strip())
        except (TypeError, ValueError, RuntimeError, OSError):
            # Path.home / expanduser RuntimeError when HOME is unset; leftover
            # NUL is ValueError. Either used to 500 POST /api/alerts/check.
            log.warning("freshness_targets: skipping malformed entry %r", entry)
            continue
        try:
            max_age = float(entry.get("max_age_hours") or 0)
        except (TypeError, ValueError, OverflowError):
            max_age = 0.0
        if max_age != max_age or max_age in (float("inf"), float("-inf")):
            max_age = 0.0
        if (not _ID_RE.fullmatch(tid) or tid in seen
                or not os.path.isabs(pattern) or max_age <= 0):
            log.warning("freshness_targets: skipping malformed entry %r", entry)
            continue
        seen.add(tid)
        out.append(Target(
            id=tid,
            label=_utf8_text(entry.get("label") or "").strip() or tid,
            pattern=_utf8_text(pattern),
            max_age_hours=max_age,
        ))
    return tuple(out)

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
    try:
        matches = glob.glob(pattern)
    except (TypeError, ValueError, OSError, RuntimeError):
        return None
    for path in matches:
        try:
            mt = float(os.stat(path).st_mtime)
        except (OSError, TypeError, ValueError, OverflowError):
            continue
        if mt != mt or mt in (float("inf"), float("-inf")):
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

    if not isinstance(prev, dict):
        prev = {}
    if not isinstance(new_state, dict):
        return []
    try:
        now = int(now)
    except (TypeError, ValueError, OverflowError):
        try:
            now = int(time.time())
        except (TypeError, ValueError, OverflowError):
            # Leftover ``time.time() = inf`` OverflowError'd POST /api/alerts/check.
            now = 0

    last_fire = prev.get("_freshness_last")
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    emitted: list = []
    n = _alerts.notify_settings()
    if not isinstance(n, dict):
        n = {}

    for t in targets if targets is not None else configured_targets():
        key = f"freshness:{t.id}"
        label = _utf8_text(t.label)
        pattern = _utf8_text(t.pattern)
        try:
            limit_sec = float(t.max_age_hours) * 3600
        except (TypeError, ValueError, OverflowError):
            continue
        if limit_sec != limit_sec or limit_sec in (float("inf"), float("-inf")) or limit_sec <= 0:
            continue
        mt = newest_mtime(pattern)
        try:
            mt = float(mt) if mt is not None else None
        except (TypeError, ValueError, OverflowError):
            mt = None
        if mt is not None and (mt != mt or mt in (float("inf"), float("-inf"))):
            mt = None
        age_h = (now - mt) / 3600 if mt is not None else None
        stale = mt is None or (now - mt) > limit_sec
        new_state[key] = "down" if stale else "ok"
        old = prev.get(key)
        last_t = _alerts._as_epoch(last_fire.get(t.id))

        if stale:
            if mt is None:
                detail = f"no artifact matches {pattern}"
                message = (
                    f"{label} has produced nothing: no file matches "
                    f"{pattern} — the job may be loaded but never firing"
                )
            else:
                detail = f"newest artifact {age_h:.1f}h old (limit {t.max_age_hours:g}h)"
                message = (
                    f"{label} artifact is stale: newest match of {pattern} "
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
                    "name": f"Freshness · {label}",
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
                f"{label} artifact is fresh again "
                f"({age_h:.1f}h old, limit {t.max_age_hours:g}h)"
            )
            alert = {
                "t": now,
                "id": key,
                "name": f"Freshness · {label}",
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
