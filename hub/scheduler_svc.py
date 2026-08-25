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

from hub import secure_io
from hub.config import cfg, maintenance_env, mutate
from hub.jobs import run_watchdog
from hub.paths import DATA_DIR
from hub.util import safe_json_loads, tail_file_lines

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


def _cron_field_tokens(expr) -> list[str]:
    """Normalise a cron payload to five field strings, or raise ValueError.

    Hand-edited YAML often stores the five fields as a list
    (``[0, 4, "*", "*", "*"]``) rather than one string.  ``str(list).split()``
    produces five tokens that look the right *shape* and then fail as
    ``"['0',"` — the job silently never fires.  Non-string leftovers
    (``True``, a job mapping) used to stringify into garbage too.
    """
    if isinstance(expr, (list, tuple)):
        if len(expr) != 5:
            raise ValueError("a cron expression has five fields: min hour dom month dow")
        try:
            return [str(part).strip() for part in expr]
        except RecursionError as e:
            # Leftover cyclic YAML field used to RecursionError
            # GET /api/scheduler/jobs via next_run_ts (not ValueError).
            raise ValueError(
                "a cron expression has five fields: min hour dom month dow"
            ) from e
    if not isinstance(expr, str):
        raise ValueError("a cron expression has five fields: min hour dom month dow")
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError("a cron expression has five fields: min hour dom month dow")
    return fields


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


def parse_cron(expr: str | list | tuple) -> dict:
    """Parse a five-field cron expression or raise ValueError.

    Day-of-week accepts both 0 and 7 as Sunday; values are normalised to 0-6.
    *expr* may be the usual string or a five-item sequence (YAML list form).
    """
    fields = _cron_field_tokens(expr)
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


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Finite floats in dicts/lists were already walked; YAML ``!!binary`` names,
    ``!!set`` of ``.nan``, ``.inf`` keys, and tuple-inf still leaked into
    GET /api/scheduler/jobs and failed the encoder. A leftover ``\\ud800``
    job name still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    A >4300-digit ``timeout``/param int still passed through untouched:
    CPython's int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/scheduler/jobs.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


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


def cron_matches(expr: str | dict | list | tuple, t: time.struct_time) -> bool:
    """Whether *t* (a local struct_time) is a matching minute for *expr*."""
    # A parsed matcher carries frozensets; a job mapping also looks like a
    # dict and must go through parse_cron (ValueError) instead of
    # ``5 not in "*"`` TypeError, which used to abort the whole tick.
    if isinstance(expr, dict) and isinstance(expr.get("minute"), (set, frozenset)):
        parsed = expr
    else:
        parsed = parse_cron(expr)
    if t.tm_min not in parsed["minute"] or t.tm_hour not in parsed["hour"]:
        return False
    # struct_time: Monday=0..Sunday=6; cron: Sunday=0..Saturday=6.
    dow = (t.tm_wday + 1) % 7
    return _day_matches(parsed, month=t.tm_mon, dom=t.tm_mday, dow=dow)


def next_run_ts(expr: str | list | tuple, after_ts: float | None = None) -> int | None:
    """Epoch seconds of the next matching minute after *after_ts* (local time).

    Scans day-by-day (cheap day-level filter, then hours, then minutes) rather
    than minute-by-minute; the horizon of four years covers even a
    ``0 0 29 2 *`` leap-day schedule.  Returns None when nothing matches.
    """
    try:
        parsed = parse_cron(expr)
    except (ValueError, RecursionError):
        return None
    try:
        base = datetime.fromtimestamp(
            after_ts if after_ts is not None else time.time()
        )
    except (OSError, OverflowError, TypeError, ValueError):
        # Leftover ``after_ts: .inf`` / a 400-digit epoch OverflowError'd
        # ``fromtimestamp`` on GET /api/scheduler/jobs.
        return None
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
    raw = cfg().get("schedules")
    rows = raw if isinstance(raw, list) else []
    return [dict(j) for j in rows if isinstance(j, dict)]


def get_job(job_id: str) -> dict | None:
    for j in list_jobs():
        if j.get("id") == job_id:
            return j
    return None


def new_job_id() -> str:
    return f"job-{uuid.uuid4().hex[:8]}"


class _NoChange(Exception):
    """Raised inside a mutate() body to abort without rewriting the file."""


def save_job(record: dict, *, mode: str = "upsert") -> bool:
    """Insert or replace one job record under the cross-process config lock.

    ``mode`` decides what happens when the id's existence disagrees with the
    caller's intent, *checked under the same lock as the write*:

    * ``"upsert"`` — insert or replace, always succeeds (the historic shape).
    * ``"create"`` — insert only; returns False when the id already exists.
    * ``"update"`` — replace only; returns False when the id is gone.

    The create/update modes exist because the router used to pre-check with
    :func:`get_job` and then call this unconditionally: two concurrent creates
    with the same id both passed the check and the second silently overwrote
    the first, and an update racing a delete re-created the deleted job.
    """
    def apply(data: dict) -> None:
        jobs = data.get("schedules")
        if not isinstance(jobs, list):
            jobs = []
            data["schedules"] = jobs
        for i, j in enumerate(jobs):
            if isinstance(j, dict) and j.get("id") == record["id"]:
                if mode == "create":
                    raise _NoChange
                jobs[i] = record
                return
        if mode == "update":
            raise _NoChange
        jobs.append(record)

    try:
        mutate(apply)
    except _NoChange:
        return False
    return True


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
    """Flip one job's ``enabled`` flag in place, under the write lock.

    The read and the write must share one lock.  The previous
    ``get_job()`` → ``save_job()`` pair took its snapshot outside the
    cross-process lock and wrote the *whole* stale record back, so a
    concurrent PUT /api/scheduler/jobs/{id} landing in between was silently
    reverted by the toggle — the exact lost-update shape config.save_full's
    docstring warns about.
    """
    hit: dict = {}

    def apply(data: dict) -> None:
        jobs = data.get("schedules")
        rows = jobs if isinstance(jobs, list) else []
        for j in rows:
            if isinstance(j, dict) and j.get("id") == job_id:
                j["enabled"] = bool(enabled)
                hit.update(j)
                return
        raise _NoChange

    try:
        mutate(apply)
    except _NoChange:
        return None
    return dict(hit)


# ── run history journal ──────────────────────────────────────────────────────

def _record_run(entry: dict) -> None:
    """Append one run record, keeping the journal bounded.

    Same atomic-trim shape as alerts.jsonl (rewrite through a temp file so a
    crash mid-trim cannot empty the history), but time-gated like
    hub/metrics.py: the full read-and-rewrite runs at most once per
    :data:`_TRIM_INTERVAL`, whatever the append rate.
    """
    global _last_trim
    # file_lock as well as _runs_lock: two panel processes sharing data/ can
    # both journal runs, and a trim in one used to swap away a record the
    # other had just appended to the pre-replace inode.
    with _runs_lock, secure_io.file_lock(RUNS_PATH):
        try:
            RUNS_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = _jsonable(entry) if isinstance(entry, dict) else None
            if not isinstance(payload, dict):
                return
            secure_io.append_text(
                RUNS_PATH,
                json.dumps(payload, ensure_ascii=False, default=str, allow_nan=False) + "\n",
            )
        except (OSError, TypeError, ValueError, RecursionError):
            # RecursionError: leftover circular run record after _jsonable is not ValueError.
            return
        now = time.time()
        if now - _last_trim < _TRIM_INTERVAL:
            return
        _last_trim = now
        try:
            if RUNS_PATH.stat().st_size <= _TRIM_SOFT_BYTES:
                return
            lines = tail_file_lines(
                RUNS_PATH, MAX_RUNS, max_bytes=max(_TRIM_SOFT_BYTES * 2, 256 * 1024)
            )
            if not lines:
                return
            payload = "\n".join(lines) + "\n"
            secure_io.replace_bytes(RUNS_PATH, payload.encode("utf-8"))
        except OSError:
            pass


def _journal_lines() -> list[str]:
    """Last :data:`MAX_RUNS` journal rows without slurping the whole file."""
    try:
        return tail_file_lines(
            RUNS_PATH, MAX_RUNS, max_bytes=max(_TRIM_SOFT_BYTES, 256 * 1024)
        )
    except OSError:
        return []


def runs(job_id: str | None = None, limit: int = 50) -> list[dict]:
    """Newest-first run records, optionally filtered to one job."""
    try:
        cap = max(1, min(int(limit), MAX_RUNS))
    except (TypeError, ValueError, OverflowError):
        cap = 50
    out: list[dict] = []
    for raw in reversed(_journal_lines()):
        try:
            rec = safe_json_loads(raw)
        except (ValueError, RecursionError):
            continue
        rec = _jsonable(rec) if isinstance(rec, dict) else None
        if not isinstance(rec, dict):
            continue
        if job_id and rec.get("job") != job_id:
            continue
        out.append(rec)
        if len(out) >= cap:
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
    out: dict[str, dict] = {}
    for raw in reversed(_journal_lines()):
        try:
            rec = safe_json_loads(raw)
        except (ValueError, RecursionError):
            continue
        rec = _jsonable(rec) if isinstance(rec, dict) else None
        if not isinstance(rec, dict):
            continue
        jid = str(rec.get("job") or "")
        if jid and jid not in out:
            out[jid] = rec
    return out


# ── runners ──────────────────────────────────────────────────────────────────

def _job_env() -> dict:
    env = dict(os.environ)
    env.update(maintenance_env())
    return env


def _job_timeout(job: dict) -> int:
    try:
        t = int(job.get("timeout") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError, OverflowError):
        t = DEFAULT_TIMEOUT
    return max(1, min(t, MAX_TIMEOUT))


def _epoch_int(raw, default: int = 0) -> int:
    """Finite epoch seconds. Leftover ``time.time() = inf`` OverflowError'd ``int()``."""
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError):
        return default


def _finite_duration(ended, started) -> float:
    """Seconds between two clocks, or 0 when leftover inf/NaN would 500 JSON."""
    try:
        duration = round(float(ended) - float(started), 1)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if duration != duration or duration in (float("inf"), float("-inf")):
        return 0.0
    return duration


def _job_params(job: dict) -> dict:
    p = job.get("params")
    return p if isinstance(p, dict) else {}


def _job_id(job: dict) -> str:
    """Stable job identity.  A missing/bool/mapping id must not become ``'None'``."""
    raw = job.get("id")
    if isinstance(raw, bool) or raw is None:
        return ""
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, float):
        # YAML ``id: .inf``: ``float('inf').is_integer()`` is True and
        # ``int(inf)`` OverflowError used to 500 GET /api/scheduler/jobs.
        if raw != raw or raw in (float("inf"), float("-inf")) or not raw.is_integer():
            return ""
        try:
            return str(int(raw))
        except (OverflowError, ValueError):
            return ""
    if isinstance(raw, str):
        return raw.strip()
    return ""


def job_enabled(job: dict) -> bool:
    """Whether *job* should fire.  YAML ``"false"`` / ``"0"`` are off, not on."""
    raw = job.get("enabled")
    if isinstance(raw, str):
        return raw.strip().lower() not in {"", "0", "false", "no", "off", "n", "f"}
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        if raw != raw or raw in (float("inf"), float("-inf")):
            return False
        return raw != 0
    return False


def _command_text(raw) -> str:
    """Shell text for a scheduled command.  Leftover non-str is not argv.

    YAML ``!!binary`` is bytes under SafeLoader.  ``str(bytes)`` is the
    repr, not the payload, but leftover lists of non-str parts were still
    joined into ``bash -c`` and leftover mappings stringified.  Only real
    strings.
    """
    if isinstance(raw, (list, tuple)):
        parts: list[str] = []
        for part in raw:
            if not isinstance(part, str):
                return ""
            text = part.strip()
            if not text:
                continue
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
                return ""
            parts.append(text)
        return " ".join(parts)
    if not isinstance(raw, str):
        return ""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return ""
    return raw.strip()


def _run_command(job: dict, log: list[str]) -> int:
    command = _command_text(_job_params(job).get("command"))
    if not command.strip():
        log.append("!! no command configured")
        return -1
    log.append(f"$ {command}")
    return run_watchdog(["/bin/bash", "-c", command],
                        timeout=_job_timeout(job), log=log, env=_job_env())


def _run_rsync(job: dict, log: list[str]) -> int:
    from hub import rsync_svc
    return rsync_svc.run_job(_job_params(job), log=log,
                             timeout=_job_timeout(job), job_id=str(job.get("id") or ""))


def _run_stack_backup(job: dict, log: list[str]) -> int:
    from hub import backups
    params = _job_params(job)
    stack_id = str(params.get("stack_id") or "")
    if not stack_id:
        log.append("!! no stack configured")
        return -1
    try:
        retain = int(params.get("retain") or backups.RETAIN)
    except (TypeError, ValueError, OverflowError):
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
    jid = _job_id(job)
    if not jid:
        return
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
    jid = _job_id(job)
    if not jid:
        return {"ok": False, "error": "no_id"}
    started = time.time()
    with _running_guard:
        if jid in _running:
            entry = {
                "ts": _epoch_int(started), "end": _epoch_int(started), "job": jid,
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
        log.append(f"!! error: {_utf8_text(e)}")
        rc = -1
    finally:
        with _running_guard:
            _running.discard(jid)
    ended = time.time()
    status = "ok" if rc == 0 else ("timeout" if rc == 124 else "failed")
    entry = {
        "ts": _epoch_int(started), "end": _epoch_int(ended), "job": jid,
        "name": job.get("name") or jid, "type": job.get("type"),
        "trigger": trigger, "status": status, "rc": rc,
        "tail": "\n".join(log)[-TAIL_CHARS:],
        "duration": _finite_duration(ended, started),
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
    try:
        raw = now_ts if now_ts is not None else time.time()
        n = float(raw)
        if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
            return []
        now = time.localtime(n)
    except (OverflowError, OSError, ValueError, TypeError):
        # Leftover ``time.time() = inf`` OverflowError'd the scheduler tick.
        return []
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
        jid = _job_id(job)
        if not jid or not job_enabled(job):
            continue
        try:
            if not cron_matches(job.get("cron"), now):
                continue
        except (ValueError, TypeError):
            continue  # an unparsable expression can never fire
        launched.append(jid)
        threading.Thread(
            target=_execute, args=(job, "schedule"), daemon=True,
            name=f"sched-{job.get('id')}",
        ).start()
    return launched


def _delay_until_next_minute(now: float | None = None) -> float:
    """Seconds to wait until just past the next local minute.

    A flat 60s wait drifts and eventually straddles a boundary, silently
    skipping a minute for an every-minute job.  Leftover ``time.time() = inf``
    used to compute ``Event.wait(nan)`` *outside* ``_tick_once``'s try/except
    and kill the scheduler thread.  A huge finite remainder OverflowError's
    ``Event.wait`` the same way leftover ``metrics_interval: 1e308`` did.
    """
    fallback = 30.0
    try:
        raw = now if now is not None else time.time()
        n = float(raw)
        if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
            return fallback
        delay = 60.0 - (n % 60.0) + 0.5
        if delay != delay or delay <= 0.0 or delay > 61.0:
            return fallback
        return delay
    except (OverflowError, OSError, ValueError, TypeError):
        return fallback


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
        delay = _delay_until_next_minute()
        try:
            stopped = _stop.wait(delay)
        except (OverflowError, ValueError, TypeError, OSError):
            # Leftover nan/inf timeout still OverflowError's Event.wait.
            try:
                stopped = _stop.wait(30.0)
            except (OverflowError, ValueError, TypeError, OSError):
                stopped = _stop.is_set()
        if stopped:
            return


def start_scheduler() -> None:
    global _thread, _last_minute
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    # The boot minute is marked evaluated, not fired: triggers missed while
    # the panel was down (including "right now") are not back-filled.
    try:
        _last_minute = _minute_key(time.localtime())
    except (OverflowError, OSError, ValueError, TypeError):
        # Leftover ``time.localtime()`` OverflowError (inf clock) used to
        # abort start; the lifespan ``except Exception`` then skipped the
        # engine entirely.
        _last_minute = None
    _thread = threading.Thread(target=_loop, daemon=True, name="panel-scheduler")
    _thread.start()


def stop_scheduler(timeout: float = 3.0) -> None:
    global _thread
    _stop.set()
    # A deliberately stopped worker must not be reported as a dead one.
    from hub import worker_health
    worker_health.unregister("panel-scheduler")
    thread = _thread
    # Join before start_scheduler() clears ``_stop``: otherwise the old
    # loop wakes, sees the event clear, and ticks beside the new thread.
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _thread = None
