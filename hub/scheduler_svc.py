"""User-defined scheduled jobs: cron matching, dispatch, history, alerts.

OMV-style "Scheduled Jobs" for the panel: operators define recurring jobs
(shell command / rsync backup / compose-stack backup / APFS snapshot), a
background thread fires them on a five-field cron expression, results are
journalled and repeated failures reach the alert pipeline.

Scheduling semantics — deliberate, and relied on by the tests:

* **Host local time.**  Cron fields are matched against ``time.localtime()``.
  A NAS lives where its owner lives; scheduling in UTC would make "03:30
  nightly" drift with DST, which is exactly what an operator does not expect
  from a cron field.
* **Missed triggers are not back-filled.**  The engine only ever evaluates the
  *current* minute.  If the panel was down or the machine slept over a match,
  that run is simply gone and the job fires at its next matching minute —
  the same contract as vixie cron, and the honest one: replaying a backlog of
  "nightly" backups at 9am is rarely what the schedule meant.  This includes
  the boot minute: a restart inside a matching minute does not re-fire, so a
  quick panel restart cannot double-run a job.
* **Overlap is skipped, not queued.**  When a job's previous run is still
  going at its next matching minute, the new trigger is recorded as
  ``skipped`` and dropped.  Two concurrent runs of one backup are never right,
  and a queue would let a wedged job pile up silently.
* **Backwards clock steps never replay.**  Minutes already evaluated stay
  evaluated when the wall clock steps back (NTP correction, DST fall-back);
  the engine waits out a small step and re-anchors after a large one — see
  :func:`_tick_once` for the exact rule.

Execution reuses the maintenance runner's watchdog executor
(:func:`hub.jobs.run_watchdog`): process-group kill on timeout, bounded output
capture.  Run history is journalled to ``data/schedule-runs.jsonl`` with a
hard line cap, mirroring the alerts trail.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta

from hub.config import cfg, mutate
from hub.jobs import run_watchdog
from hub.paths import DATA_DIR

RUNS_PATH = DATA_DIR / "schedule-runs.jsonl"

#: Journal line cap.  A minutely job writes 1440 lines a day; without a cap the
#: file grows forever on an appliance nobody logs into.
MAX_RUNS = 1000
#: Cheap size gate before the full read-and-trim, same idea as hub/audit.py.
_TRIM_SOFT_BYTES = MAX_RUNS * 600

#: How much of a run's output tail survives into the journal.
TAIL_CHARS = 2000

#: Consecutive failures before the alert pipeline is involved.  One failure is
#: routine (a target disk momentarily unmounted); two in a row is a pattern the
#: operator should hear about.
FAILURE_ALERT_AFTER = 2

JOB_TYPES = ("command", "rsync", "stack_backup", "snapshot")

#: Default / ceiling for per-run timeouts (seconds).
DEFAULT_TIMEOUT = 3600
MAX_TIMEOUT = 24 * 3600

_runs_lock = threading.Lock()
#: Full-file trim at most hourly, the same SSD-friendly time gate as
#: hub/metrics.py.  The previous every-20-appends rule meant a minute-level
#: job at the cap rewrote the whole journal every 20 minutes, forever —
#: write amplification measured in tens of MB per day for a file that only
#: ever holds MAX_RUNS lines.
_last_trim = 0.0
_TRIM_INTERVAL = 3600.0

_running_guard = threading.Lock()
_running: set[str] = set()

#: job id -> consecutive failure count.  In-memory on purpose: after a panel
#: restart the slate is clean and the next failure starts a fresh streak, which
#: errs on the quiet side rather than re-alerting on stale history.
_fail_counts: dict[str, int] = {}

_stop = threading.Event()
_thread: threading.Thread | None = None


# ── cron parsing / matching ──────────────────────────────────────────────────

_FIELD_RANGES = (
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("dom", 1, 31),
    ("month", 1, 12),
    ("dow", 0, 7),
)


def _parse_field(spec: str, lo: int, hi: int) -> tuple[frozenset[int], bool]:
    """One cron field -> (allowed values, was it a bare ``*``).

    Supports ``*``, numbers, lists (``a,b``), ranges (``a-b``) and steps
    (``*/n``, ``a-b/n``, and vixie's ``a/n`` meaning ``a-max/n``).  The star
    flag is true only for a bare ``*`` — ``*/1`` restricts the field for the
    day-of-month/day-of-week OR rule below, matching vixie cron.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("empty cron field")
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty list item in {spec!r}")
        rng, slash, step_s = part.partition("/")
        step = 1
        if slash:
            if not step_s.isdigit() or int(step_s) < 1:
                raise ValueError(f"bad step in {part!r}")
            step = int(step_s)
        if rng == "*":
            start, end = lo, hi
        elif "-" in rng:
            a, _, b = rng.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f"bad range in {part!r}")
            start, end = int(a), int(b)
            if start > end:
                raise ValueError(f"reversed range in {part!r}")
        elif rng.isdigit():
            start = int(rng)
            # vixie: "n/step" walks n..max; a bare "n" is just n.
            end = hi if slash else start
        else:
            raise ValueError(f"bad value in {part!r}")
        if start < lo or end > hi:
            raise ValueError(f"{part!r} outside {lo}-{hi}")
        values.update(range(start, end + 1, step))
    return frozenset(values), spec == "*"


def parse_cron(expr: str) -> dict:
    """Parse a five-field cron expression or raise ValueError.

    Day-of-week accepts both 0 and 7 as Sunday; values are normalised to 0-6.
    """
    fields = str(expr or "").split()
    if len(fields) != 5:
        raise ValueError("a cron expression has five fields: min hour dom month dow")
    parsed: dict = {}
    for (name, lo, hi), field in zip(_FIELD_RANGES, fields):
        values, star = _parse_field(field, lo, hi)
        if name == "dow":
            values = frozenset(v % 7 for v in values)
        parsed[name] = values
        parsed[f"{name}_star"] = star
    return parsed


def valid_cron(expr: str) -> bool:
    try:
        parse_cron(expr)
        return True
    except ValueError:
        return False


def _day_matches(parsed: dict, *, month: int, dom: int, dow: int) -> bool:
    """Vixie day rule: when *both* dom and dow are restricted, either may match."""
    if month not in parsed["month"]:
        return False
    dom_ok = dom in parsed["dom"]
    dow_ok = dow in parsed["dow"]
    if parsed["dom_star"] and parsed["dow_star"]:
        return True
    if parsed["dom_star"]:
        return dow_ok
    if parsed["dow_star"]:
        return dom_ok
    return dom_ok or dow_ok


def cron_matches(expr: str | dict, t: time.struct_time) -> bool:
    """Whether *t* (a local struct_time) is a matching minute for *expr*."""
    parsed = expr if isinstance(expr, dict) else parse_cron(expr)
    if t.tm_min not in parsed["minute"] or t.tm_hour not in parsed["hour"]:
        return False
    # struct_time: Monday=0..Sunday=6; cron: Sunday=0..Saturday=6.
    dow = (t.tm_wday + 1) % 7
    return _day_matches(parsed, month=t.tm_mon, dom=t.tm_mday, dow=dow)


def next_run_ts(expr: str, after_ts: float | None = None) -> int | None:
    """Epoch seconds of the next matching minute after *after_ts* (local time).

    Scans day-by-day (cheap day-level filter, then hours, then minutes) rather
    than minute-by-minute; the horizon of four years covers even a
    ``0 0 29 2 *`` leap-day schedule.  Returns None when nothing matches.
    """
    try:
        parsed = parse_cron(expr)
    except ValueError:
        return None
    base = datetime.fromtimestamp(after_ts if after_ts is not None else time.time())
    cur = base.replace(second=0, microsecond=0) + timedelta(minutes=1)
    first_day = cur.replace(hour=0, minute=0)
    hours = sorted(parsed["hour"])
    minutes = sorted(parsed["minute"])
    for offset in range(0, 366 * 4):
        day = first_day + timedelta(days=offset)
        dow = (day.weekday() + 1) % 7
        if not _day_matches(parsed, month=day.month, dom=day.day, dow=dow):
            continue
        same_day = day.date() == cur.date()
        for h in hours:
            if same_day and h < cur.hour:
                continue
            for m in minutes:
                if same_day and h == cur.hour and m < cur.minute:
                    continue
                return int(day.replace(hour=h, minute=m).timestamp())
    return None


# ── job storage (services.yaml → schedules:) ─────────────────────────────────

def list_jobs() -> list[dict]:
    return [dict(j) for j in (cfg().get("schedules") or []) if isinstance(j, dict)]


def get_job(job_id: str) -> dict | None:
    for j in list_jobs():
        if j.get("id") == job_id:
            return j
    return None


def new_job_id() -> str:
    return f"job-{uuid.uuid4().hex[:8]}"


def save_job(record: dict) -> None:
    """Insert or replace one job record under the cross-process config lock."""
    def apply(data: dict) -> None:
        jobs = data.setdefault("schedules", [])
        for i, j in enumerate(jobs):
            if isinstance(j, dict) and j.get("id") == record["id"]:
                jobs[i] = record
                return
        jobs.append(record)

    mutate(apply)


def delete_job(job_id: str) -> bool:
    found = {"hit": False}

    def apply(data: dict) -> None:
        jobs = data.get("schedules") or []
        kept = [j for j in jobs if not (isinstance(j, dict) and j.get("id") == job_id)]
        found["hit"] = len(kept) != len(jobs)
        data["schedules"] = kept

    mutate(apply)
    return found["hit"]


def set_enabled(job_id: str, enabled: bool) -> dict | None:
    job = get_job(job_id)
    if job is None:
        return None
    job["enabled"] = bool(enabled)
    save_job(job)
    return job


# ── run history journal ──────────────────────────────────────────────────────

def _record_run(entry: dict) -> None:
    """Append one run record, keeping the journal bounded.

    Same atomic-trim shape as alerts.jsonl (rewrite through a temp file so a
    crash mid-trim cannot empty the history), but time-gated like
    hub/metrics.py: the full read-and-rewrite runs at most once per
    :data:`_TRIM_INTERVAL`, whatever the append rate.
    """
    global _last_trim
    with _runs_lock:
        try:
            RUNS_PATH.parent.mkdir(parents=True, exist_ok=True)
            with RUNS_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError:
            return
        now = time.time()
        if now - _last_trim < _TRIM_INTERVAL:
            return
        _last_trim = now
        try:
            if RUNS_PATH.stat().st_size <= _TRIM_SOFT_BYTES:
                return
            lines = RUNS_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) <= MAX_RUNS:
                return
            payload = "\n".join(lines[-MAX_RUNS:]) + "\n"
            tmp = RUNS_PATH.with_name(f"{RUNS_PATH.name}.{os.getpid()}.tmp")
            try:
                tmp.write_text(payload)
                os.replace(tmp, RUNS_PATH)
            except Exception:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
        except OSError:
            pass


def runs(job_id: str | None = None, limit: int = 50) -> list[dict]:
    """Newest-first run records, optionally filtered to one job."""
    try:
        lines = RUNS_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for raw in reversed(lines):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if job_id and rec.get("job") != job_id:
            continue
        out.append(rec)
        if len(out) >= max(1, min(int(limit), MAX_RUNS)):
            break
    return out


def last_run(job_id: str) -> dict | None:
    hits = runs(job_id, limit=1)
    return hits[0] if hits else None


def last_runs_by_job() -> dict[str, dict]:
    """job id -> its newest run record, from a single journal read.

    ``GET /api/scheduler/jobs`` needs the last run of *every* job; calling
    :func:`last_run` per job re-read and re-parsed the whole journal once per
    row, so the list endpoint cost jobs × MAX_RUNS json loads.  One reversed
    pass keeps the first (newest) record per id and skips the rest.
    """
    try:
        lines = RUNS_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    out: dict[str, dict] = {}
    for raw in reversed(lines):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        jid = str(rec.get("job") or "")
        if jid and jid not in out:
            out[jid] = rec
    return out


# ── runners ──────────────────────────────────────────────────────────────────

def _job_env() -> dict:
    env = dict(os.environ)
    env.update({k: str(v) for k, v in
                ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()})
    return env


def _job_timeout(job: dict) -> int:
    try:
        t = int(job.get("timeout") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        t = DEFAULT_TIMEOUT
    return max(1, min(t, MAX_TIMEOUT))


def _run_command(job: dict, log: list[str]) -> int:
    command = str((job.get("params") or {}).get("command") or "")
    if not command.strip():
        log.append("!! no command configured")
        return -1
    log.append(f"$ {command}")
    return run_watchdog(["/bin/bash", "-c", command],
                        timeout=_job_timeout(job), log=log, env=_job_env())


def _run_rsync(job: dict, log: list[str]) -> int:
    from hub import rsync_svc
    return rsync_svc.run_job(job.get("params") or {}, log=log,
                             timeout=_job_timeout(job), job_id=str(job.get("id") or ""))


def _run_stack_backup(job: dict, log: list[str]) -> int:
    from hub import backups
    params = job.get("params") or {}
    stack_id = str(params.get("stack_id") or "")
    if not stack_id:
        log.append("!! no stack configured")
        return -1
    try:
        retain = int(params.get("retain") or backups.RETAIN)
    except (TypeError, ValueError):
        retain = backups.RETAIN
    result = backups.backup_stack(stack_id, retain=retain, log=log)
    return 0 if result.get("ok") else 1


def _run_snapshot(job: dict, log: list[str]) -> int:
    # tmutil localsnapshot needs no elevation, so it is safe headless; the
    # thinning/deletion paths in snapshots_svc need the authorization sheet and
    # are deliberately not schedulable.
    from hub import snapshots_svc
    result = snapshots_svc.create_snapshot()
    if result.get("message"):
        log.append(str(result["message"]))
    return 0 if result.get("ok") else 1


_RUNNERS = {
    "command": _run_command,
    "rsync": _run_rsync,
    "stack_backup": _run_stack_backup,
    "snapshot": _run_snapshot,
}


# ── execution ────────────────────────────────────────────────────────────────

def _alert_on_failure(job: dict, entry: dict) -> None:
    """Track consecutive failures; involve the alert pipeline on a streak.

    Imported lazily and wrapped: a broken alert path must not take the
    scheduler thread with it, mirroring how the alerter itself never lets a
    channel exception escape.
    """
    jid = str(job.get("id"))
    if entry.get("status") == "ok":
        _fail_counts.pop(jid, None)
        return
    if entry.get("status") == "skipped":
        return
    count = _fail_counts.get(jid, 0) + 1
    _fail_counts[jid] = count
    if count < FAILURE_ALERT_AFTER:
        return
    try:
        from hub import alerts
        alerts.emit_alert(
            kind="schedule",
            level="warn",
            alert_id=f"schedule:{jid}",
            message=(
                f"scheduled task '{job.get('name') or jid}' failed "
                f"{count} times in a row (last exit {entry.get('rc')})"
            ),
        )
    except Exception:
        pass


def _execute(job: dict, trigger: str) -> dict:
    """Run *job* to completion and journal the outcome.  Never raises."""
    jid = str(job.get("id"))
    started = time.time()
    with _running_guard:
        if jid in _running:
            entry = {
                "ts": int(started), "end": int(started), "job": jid,
                "name": job.get("name") or jid, "type": job.get("type"),
                "trigger": trigger, "status": "skipped", "rc": None,
                "tail": "previous run still in progress", "duration": 0,
            }
            _record_run(entry)
            return entry
        _running.add(jid)
    log: list[str] = []
    rc: int | None = -1
    try:
        runner = _RUNNERS.get(str(job.get("type") or ""))
        if runner is None:
            log.append(f"!! unknown job type: {job.get('type')}")
            rc = -1
        else:
            rc = runner(job, log)
    except Exception as e:  # a runner bug must not kill the engine thread
        log.append(f"!! error: {e}")
        rc = -1
    finally:
        with _running_guard:
            _running.discard(jid)
    ended = time.time()
    status = "ok" if rc == 0 else ("timeout" if rc == 124 else "failed")
    entry = {
        "ts": int(started), "end": int(ended), "job": jid,
        "name": job.get("name") or jid, "type": job.get("type"),
        "trigger": trigger, "status": status, "rc": rc,
        "tail": "\n".join(log)[-TAIL_CHARS:], "duration": round(ended - started, 1),
    }
    _record_run(entry)
    _alert_on_failure(job, entry)
    return entry


def is_running(job_id: str) -> bool:
    with _running_guard:
        return job_id in _running


def run_job_now(job_id: str, *, wait: bool = False) -> dict:
    """Manual trigger.  Fire-and-forget by default: an rsync run can take an
    hour, and an API request must not hold a connection open for it."""
    job = get_job(job_id)
    if job is None:
        return {"ok": False, "error": "not_found"}
    if wait:
        entry = _execute(job, "manual")
        return {"ok": entry.get("status") == "ok", "run": entry}
    threading.Thread(
        target=_execute, args=(job, "manual"), daemon=True,
        name=f"sched-run-{job_id}",
    ).start()
    return {"ok": True, "started": True}


# ── engine loop ──────────────────────────────────────────────────────────────

#: The last minute that was evaluated, as (y, mon, d, h, min).  Initialised to
#: the boot minute by start_scheduler so restarts never re-fire or back-fill.
_last_minute: tuple | None = None

#: A backwards wall-clock step larger than this is treated as a deliberate
#: clock change rather than a correction: the engine adopts the new timeline
#: (with boot semantics) instead of staying silent until the old high-water
#: mark is reached again.  Same 3-hour rule as vixie cron.
_BACKWARD_RESYNC = timedelta(hours=3)


def _minute_key(t: time.struct_time) -> tuple:
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min)


def _tick_once(now_ts: float | None = None) -> list[str]:
    """Evaluate the current local minute once; returns ids of jobs launched.

    Only the *current* minute is ever considered — see the module docstring
    for why missed minutes are dropped rather than replayed.

    ``_last_minute`` is a high-water mark, not just an equality latch.  When
    the wall clock steps *backwards* (NTP correction, DST fall-back on hosts
    that observe it, an operator fixing a fast clock), the minutes between the
    new time and the mark were already evaluated on their first pass;
    re-evaluating them would double-run every fixed-time job in the replayed
    window.  A small step therefore keeps the engine quiet until the clock
    passes the mark again — vixie cron's behaviour for jumps under three
    hours.  A step larger than :data:`_BACKWARD_RESYNC` is a deliberate clock
    change: the engine re-anchors on the new timeline with the same
    mark-evaluated-not-fired semantics as boot, so the stall is bounded.
    """
    global _last_minute
    now = time.localtime(now_ts if now_ts is not None else time.time())
    key = _minute_key(now)
    if key == _last_minute:
        return []
    if _last_minute is not None and key < _last_minute:
        # Naive datetimes on purpose: both keys came from time.localtime(),
        # so their difference is the wall-clock distance the operator sees.
        if datetime(*_last_minute) - datetime(*key) <= _BACKWARD_RESYNC:
            return []
        _last_minute = key
        return []
    _last_minute = key
    launched: list[str] = []
    for job in list_jobs():
        if not job.get("enabled"):
            continue
        try:
            if not cron_matches(str(job.get("cron") or ""), now):
                continue
        except ValueError:
            continue  # an unparsable expression can never fire
        launched.append(str(job.get("id")))
        threading.Thread(
            target=_execute, args=(job, "schedule"), daemon=True,
            name=f"sched-{job.get('id')}",
        ).start()
    return launched


def _loop() -> None:
    from hub import worker_health
    worker_health.register("panel-scheduler", 60)
    while not _stop.is_set():
        try:
            worker_health.beat("panel-scheduler")
            _tick_once()
        except Exception:
            # The engine thread must survive anything a tick throws.
            pass
        # Sleep to just past the next minute boundary rather than a flat 60s:
        # a flat wait drifts and eventually straddles a boundary, silently
        # skipping a minute for an every-minute job.
        delay = 60.0 - (time.time() % 60.0) + 0.5
        if _stop.wait(delay):
            return


def start_scheduler() -> None:
    global _thread, _last_minute
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    # The boot minute is marked evaluated, not fired: triggers missed while
    # the panel was down (including "right now") are not back-filled.
    _last_minute = _minute_key(time.localtime())
    _thread = threading.Thread(target=_loop, daemon=True, name="panel-scheduler")
    _thread.start()


def stop_scheduler() -> None:
    global _thread
    _stop.set()
    # A deliberately stopped worker must not be reported as a dead one.
    from hub import worker_health
    worker_health.unregister("panel-scheduler")
    _thread = None
