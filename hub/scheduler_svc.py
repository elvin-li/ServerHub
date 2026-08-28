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

def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a value whose ``__class__`` is a raising
    property blew every ``isinstance`` gate in this module — a job id, an
    ``enabled`` flag, a cron payload, a params value, a whole row — straight
    out of GET /api/scheduler/jobs, out of every mutation's get_job scan,
    and out of the engine tick (costing every *other* job its matching
    minute; the modules8 rule).  A lying ``__class__`` (answers ``int``) is
    *not* an error and still reports its claim here; the unbound base
    coercions downstream then drop the impostor, exactly as before.
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


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
    if _isinst(expr, (list, tuple)):
        try:
            # list() through the C storage, then len() on the plain copy: a
            # leftover list-subclass whose ``__iter__``/``__len__`` raised
            # used to escape next_run_ts's (ValueError, RecursionError) net
            # and 500 GET /api/scheduler/jobs.
            parts = list(expr)
        except Exception as e:
            raise ValueError(
                "a cron expression has five fields: min hour dom month dow"
            ) from e
        if len(parts) != 5:
            raise ValueError("a cron expression has five fields: min hour dom month dow")
        try:
            # Unbound str.strip on the str() result: ``str()`` of a subclass
            # whose ``__str__`` returns self keeps the subclass, so a bound
            # ``.strip()`` returning (or being) a bomb handed _parse_field a
            # token whose ``split``/``__len__`` raised past this except —
            # outside every caller's ValueError net — and 500'd the same
            # route.  The unbound view also yields exact-str tokens.
            return [str.strip(str(part)) for part in parts]
        except Exception as e:
            # ValueError is the one signal every caller catches.  A leftover
            # cyclic YAML field used to RecursionError GET /api/scheduler/jobs
            # via next_run_ts; a field item whose ``str()`` raised anything
            # else (a ``__str__`` bomb, an over-cap int's digit-limit
            # ValueError is already covered) still escaped next_run_ts's
            # (ValueError, RecursionError) net and 500'd the same route.
            raise ValueError(
                "a cron expression has five fields: min hour dom month dow"
            ) from e
    if not _isinst(expr, str):
        raise ValueError("a cron expression has five fields: min hour dom month dow")
    # Unbound str.split: a str-subclass expression whose ``split()`` raised
    # escaped next_run_ts's (ValueError, RecursionError) net and 500'd
    # GET /api/scheduler/jobs; the unbound view also yields exact-str fields.
    try:
        fields = str.split(expr)
    except Exception as e:
        # A liar whose ``__class__`` answers str passes the gate but is not
        # a real str: the unbound descriptor refuses it with TypeError,
        # which used to escape every caller's ValueError net and 500 the
        # same route (and abort the whole engine tick).
        raise ValueError(
            "a cron expression has five fields: min hour dom month dow"
        ) from e
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


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if _isinst(value, bytes) else bytearray
    try:
        return base.decode(value, "utf-8", "replace")
    except Exception:
        # A liar whose ``__class__`` *answers* bytes passes the callers'
        # _isinst gates but is not really bytes: the unbound descriptor
        # refuses it with TypeError, which used to ride out of _jsonable's
        # bytes arm and 500 GET /api/scheduler/jobs.
        return ""


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if _isinst(value, (bytes, bytearray)):
        return _decode_bytes(value)
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound base encode: ``str()`` of a str subclass whose ``__str__``
    # returns self keeps the subclass, so a bound ``.encode`` bomb in a
    # leftover job id/name/params value used to raise here — outside the
    # try — and 500 GET /api/scheduler/jobs (and drop the run-journal
    # record from _record_run's shaping).  The modules6/docker6 unbound
    # convention, like hub.docker_cli._utf8_text.
    return str.encode(text, "utf-8", "replace").decode("utf-8")


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
    # ``type(value) is bool``, not isinstance: a liar whose ``__class__``
    # *answers* bool passed the old gate and rode raw into json.dumps
    # (TypeError, 500); bool cannot be subclassed, so the exact check is
    # complete and the impostor falls to the int arm's unbound coercion.
    if value is None or type(value) is bool:
        return value
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a leftover subclass
                # ``__str__`` bomb used to blow the digit-cap probe below
                # (only ValueError was caught) and 500 GET /api/scheduler/jobs
                # — the modules5 unbound convention.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isinst(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a leftover subclass
                # ``__eq__``/``__ne__`` bomb used to blow the NaN/inf
                # probes below and 500 GET /api/scheduler/jobs.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinst(value, str):
        return _utf8_text(value)
    if _isinst(value, (bytes, bytearray)):
        # Unbound base decode: a leftover bytes-subclass ``decode`` bomb
        # (a poisoned job name / params value) used to 500 the encoder walk.
        return _decode_bytes(value)
    if _isinst(value, dict):
        if type(value) is not dict:
            # dict() copies through the C-level storage, ignoring overridden
            # items()/keys()/__iter__ — a leftover nested dict-subclass bomb
            # (a ``params`` row whose .items() raised) used to 500
            # GET /api/scheduler/jobs (same guard as hub.jobs._jsonable).
            try:
                value = dict(value)
            except Exception:
                return None
        out = {}
        for k, v in value.items():
            if not _isinst(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isinst(value, (list, tuple, set, frozenset)):
        try:
            items = list(value)
        except Exception:
            # Leftover nested sequence subclass whose __iter__ raises.
            return None
        return [_jsonable(v, depth + 1) for v in items]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # Property bomb / __getattr__ raising something that is not
        # AttributeError escapes getattr's default.
        iso = None
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


def _in_field(n: int, values) -> bool:
    """``n in values`` that a leftover member ``__eq__`` bomb cannot raise through.

    A parse_cron product holds frozensets of exact ints, but the matcher
    fast path accepts any set-typed field values — and a set membership test
    compares the probe against every stored member whose hash collides,
    dispatching into that member's own ``__eq__``.  A leftover int-*subclass*
    member with a bombing ``__eq__`` (hash of a real minute, so the probe
    reaches it) used to raise out of :func:`cron_matches` /
    :func:`_day_matches` past :func:`_tick_once`'s (ValueError, TypeError)
    net and abort the whole tick.  A bombed field is junk: it matches
    nothing, so the job never fires — the same contract as an unparsable
    expression — and the siblings keep their minute.
    """
    try:
        return n in values
    except Exception:
        return False


def _day_matches(parsed: dict, *, month: int, dom: int, dow: int) -> bool:
    """Vixie day rule: when *both* dom and dow are restricted, either may match."""
    if not _in_field(month, parsed["month"]):
        return False
    dom_ok = _in_field(dom, parsed["dom"])
    dow_ok = _in_field(dow, parsed["dow"])
    if parsed["dom_star"] and parsed["dow_star"]:
        return True
    if parsed["dom_star"]:
        return dow_ok
    if parsed["dow_star"]:
        return dom_ok
    return dom_ok or dow_ok


#: Every key a parse_cron product carries; _day_matches reads all of them.
_MATCHER_KEYS = frozenset(
    ("minute", "hour", "dom", "month", "dow",
     "minute_star", "hour_star", "dom_star", "month_star", "dow_star")
)


def _parsed_matcher(expr) -> dict | None:
    """*expr* when it is a parse_cron product, else None.

    The old sniff — ``expr.get("minute")`` behind a bare isinstance — had two
    holes.  A leftover dict-*subclass* cron whose ``.get`` raised detonated
    the probe itself, and a YAML mapping cron that happened to carry a
    ``!!set`` ``minute`` passed the sniff and KeyError'd :func:`_day_matches`
    on the matcher keys it did not have.  Either escaped
    :func:`_tick_once`'s (ValueError, TypeError) net and aborted the whole
    tick — every *other* job's matching minute was lost (the sched7
    thread-name class again).  Only an exact dict carrying every matcher key
    with set-typed field values and exact-bool star flags takes the fast
    path; everything else goes to parse_cron's ValueError, the one signal
    every caller catches.

    The whole probe runs in a try: the key-subset test and the ``expr[k]``
    reads both hash-probe the dict, and that probe compares the interned
    matcher key against every stored key whose hash collides — so a leftover
    hash-shadow key (a str *subclass* with a matcher key's text and a
    bombing ``__eq__``) used to raise out of the ``<=`` itself and abort the
    whole tick.  A raise means "not a parse_cron product": the dict goes to
    parse_cron's ValueError like every other impostor.

    The star flags are read as raw truth by :func:`_day_matches`, so they
    must be exact bools here (parse_cron only ever writes exact bools): a
    leftover ``__bool__``-bomb star value used to pass the old gate and
    detonate the ``and`` inside the day rule, aborting the tick the same
    way.  This *strengthens* the gate; the fast path for genuine parse_cron
    products is unchanged.
    """
    try:
        if type(expr) is not dict or not _MATCHER_KEYS <= expr.keys():
            return None
        # _isinst: an exact-dict cron carrying a ``__class__``-bomb field
        # value used to detonate this probe and abort the whole tick.
        if not all(_isinst(expr[k], (set, frozenset))
                   for k in ("minute", "hour", "dom", "month", "dow")):
            return None
        if not all(type(expr[f"{k}_star"]) is bool
                   for k in ("minute", "hour", "dom", "month", "dow")):
            return None
        return expr
    except Exception:
        return None


def cron_matches(expr: str | dict | list | tuple, t: time.struct_time) -> bool:
    """Whether *t* (a local struct_time) is a matching minute for *expr*."""
    # A parsed matcher carries frozensets; a job mapping also looks like a
    # dict and must go through parse_cron (ValueError) instead of
    # ``5 not in "*"`` TypeError, which used to abort the whole tick.
    parsed = _parsed_matcher(expr) if _isinst(expr, dict) else None
    if parsed is None:
        parsed = parse_cron(expr)
    # _in_field, not bare ``in``: a leftover ``__eq__``-bomb member in a
    # matcher set used to raise here and abort the whole tick.
    if not _in_field(t.tm_min, parsed["minute"]) or not _in_field(t.tm_hour, parsed["hour"]):
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

def _plain_dict(value) -> dict | None:
    """*value* as a plain ``dict``, or None.

    A leftover dict-*subclass* row (the same bomb class hub.jobs._plain_dict
    guards the Maintenance routes against: passes the isinstance gate, then
    ``.get()`` / ``dict()``'s ``keys()`` fallback raises) used to 500
    GET /api/scheduler/jobs from :func:`list_jobs`'s bare ``dict(j)`` copy.
    ``dict()`` on a plain-iter subclass copies through the C-level storage;
    when the subclass overrides ``__iter__``/``keys`` the copy itself raises,
    so the row is junk and drops.
    """
    if type(value) is dict:
        return value
    # _isinst, not a bare isinstance: a leftover non-dict row whose
    # ``__class__`` is a raising property used to detonate the gate itself
    # and 500 GET /api/scheduler/jobs plus every mutation's get_job scan.
    if _isinst(value, dict):
        try:
            return dict(value)
        except Exception:
            return None
    return None


def _mapping_get(mapping, key, default=None):
    """Field read that a leftover hash-shadowing mapping *key* cannot 500.

    The hub.jobs._mapping_get seam this module never got: :func:`_plain_dict`
    returns the row (or a ``dict()`` copy) with its *keys* intact, and even a
    plain ``dict.get`` probe still compares the probe against every stored
    key whose hash collides — dispatching into that key's own ``__eq__``.  A
    leftover str-subclass key whose text shadows a real field name and whose
    ``__eq__`` raises used to detonate ``job.get("id")`` in :func:`_job_id`
    (500 on GET /api/scheduler/jobs and, via :func:`_matches_id`'s
    :func:`get_job` scan, on DELETE / PUT / enable / run-now for *healthy*
    sibling jobs), ``job.get("enabled")`` in :func:`job_enabled` (500 on the
    list route), ``job.get("cron")`` in :func:`_tick_once` (a RuntimeError
    past its (ValueError, TypeError) net aborted the whole tick — every
    other job's matching minute lost), and ``job.get("type")`` in
    :func:`_execute`'s entry builds (breaking its "never raises" contract).
    Only the shadowed field degrades to its default; sibling fields and rows
    keep their sane data.
    """
    if not _isinst(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except Exception:
        # A raise can only come from a poisoned stored key (or a liar whose
        # ``__class__`` merely answers dict, which the unbound descriptor
        # refuses): the field is junk-shadowed either way.
        return default


def list_jobs() -> list[dict]:
    # Guarded like storage_pool_svc._pool_config: a cfg() snapshot provider
    # that raises used to escape this reader and 500 GET /api/scheduler/jobs
    # and every job mutation's get_job scan at once.
    try:
        data = cfg()
    except Exception:
        data = {}
    # dict.get, not the bound method: cfg() parses YAML to exact types, but
    # the snapshot is whatever an in-process caller last stored, and a
    # dict-*subclass* config root with a bombing ``.get`` used to detonate
    # here and 500 the same routes.  The unbound builtin reads the C-level
    # storage underneath the override.
    if _isinst(data, dict):
        try:
            raw = dict.get(data, "schedules")
        except Exception:
            # The unbound builtin is a descriptor bound to the real dict
            # layout: a liar whose ``__class__`` merely *answers* dict (the
            # maint9/modules9 impostor class — real type is no dict at all)
            # passes _isinst above and then TypeErrors right here, which
            # used to 500 GET /api/scheduler/jobs, every mutation's get_job
            # scan, and abort the engine tick from outside every net.  A
            # raise means "not really a dict": the impostor root degrades
            # to the empty job list.
            raw = None
    else:
        raw = None
    if _isinst(raw, list):
        try:
            # list() through the C storage: a leftover list-subclass whose
            # __iter__ raises used to 500 GET /api/scheduler/jobs (the same
            # guard hub.jobs.maintenance_tasks applies to its rows).
            rows = list(raw)
        except Exception:
            rows = []
    else:
        rows = []
    out: list[dict] = []
    for j in rows:
        row = _plain_dict(j)
        if row is not None:
            out.append(row)
    return out


def _matches_id(job: dict, job_id) -> bool:
    """Whether *job* is the record an API path names.

    Raw equality first (the historic shape), then the same ``str()`` coercion
    :func:`_job_id` applies.  A hand-edited numeric YAML ``id: 123`` is listed
    — and *fired by the engine* — as ``"123"``, but the lookups here compared
    with raw ``==``, so the path string never matched the stored int: every
    enable/update/delete/run-now on the running job mis-404'd
    ``scheduler.not_found`` while the engine kept firing it, leaving no way to
    stop the job through the API.

    The raw equality is guarded: a leftover ``__eq__``-bomb id value on ANY
    sibling row used to raise out of :func:`get_job`'s scan and 500 every
    DELETE / PUT / enable / run-now — for jobs whose own records were fine.
    """
    try:
        if job.get("id") == job_id:
            return True
    except Exception:
        pass
    if not _isinst(job_id, str) or not job_id:
        return False
    coerced = _job_id(job)
    return bool(coerced) and coerced == job_id


def get_job(job_id: str) -> dict | None:
    for j in list_jobs():
        if _matches_id(j, job_id):
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
            if isinstance(j, dict) and _matches_id(j, record["id"]):
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
        kept = [j for j in jobs if not (isinstance(j, dict) and _matches_id(j, job_id))]
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
            if isinstance(j, dict) and _matches_id(j, job_id):
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
    except Exception:
        # Broad on purpose: a ``__bool__`` bomb in the ``or``, an
        # int-subclass ``__int__`` bomb, or a ``__class__`` bomb with no
        # numeric protocol raised RuntimeError past the old (TypeError,
        # ValueError, OverflowError) net.
        t = DEFAULT_TIMEOUT
    return max(1, min(t, MAX_TIMEOUT))


def _epoch_int(raw, default: int = 0) -> int:
    """Finite epoch seconds. Leftover ``time.time() = inf`` OverflowError'd ``int()``."""
    if type(raw) is bool or raw is None:
        return default
    if _isinst(raw, float):
        if type(raw) is not float:
            try:
                # Base coercion first: a float-subclass clock whose
                # ``__eq__``/``__ne__`` raised used to blow the NaN probe
                # below out of _execute's journal build.
                raw = float.__float__(raw)
            except Exception:
                return default
        if raw != raw or raw in (float("inf"), float("-inf")):
            return default
    try:
        return int(raw)
    except Exception:
        return default


def _finite_duration(ended, started) -> float:
    """Seconds between two clocks, or 0 when leftover inf/NaN would 500 JSON."""
    try:
        duration = round(float(ended) - float(started), 1)
    except Exception:
        # Broad on purpose: a float-subclass clock whose ``__float__``
        # raised RuntimeError escaped the old net out of _execute's
        # journal build, so the run was never journalled.
        return 0.0
    if duration != duration or duration in (float("inf"), float("-inf")):
        return 0.0
    return duration


def _job_params(job: dict) -> dict:
    # _plain_dict over _mapping_get: a leftover params dict-subclass (or a
    # ``__class__`` bomb) degrades to {}, and a hash-shadowing bomb key
    # beside "params" degrades field-level ("!! no command configured")
    # instead of costing the whole run an opaque "!! error".
    p = _plain_dict(_mapping_get(job, "params"))
    return p if p is not None else {}


def _job_id(job: dict) -> str:
    """Stable job identity.  A missing/bool/mapping id must not become ``'None'``.

    _mapping_get, not ``job.get``: a leftover hash-shadowing bomb key with
    "id"'s text used to detonate the bare probe and 500
    GET /api/scheduler/jobs, every mutation's get_job scan (healthy sibling
    jobs included), and abort the engine tick.
    """
    raw = _mapping_get(job, "id")
    if type(raw) is bool or raw is None:
        return ""
    if _isinst(raw, int):
        if type(raw) is not int:
            try:
                # Base coercion first: an int-subclass id whose ``__str__``
                # raised anything but the digit-cap ValueError used to 500
                # GET /api/scheduler/jobs — and, via _matches_id's scan,
                # DELETE / run-now on *healthy* sibling jobs.
                raw = int.__index__(raw)
            except Exception:
                return ""
        try:
            return str(raw)
        except ValueError:
            # A YAML hex/octal ``id`` dodges CPython's str->int digit cap on
            # parse (base 16/8 are exempt), and the int->str cap then
            # ValueError'd here — 500ing GET /api/scheduler/jobs and aborting
            # the whole engine tick, so every *other* job's minute was lost.
            return ""
    if _isinst(raw, float):
        if type(raw) is not float:
            try:
                # A float-subclass id whose ``__eq__``/``__ne__`` raised used
                # to blow the NaN probe below and 500 the same routes.
                raw = float.__float__(raw)
            except Exception:
                return ""
        # YAML ``id: .inf``: ``float('inf').is_integer()`` is True and
        # ``int(inf)`` OverflowError used to 500 GET /api/scheduler/jobs.
        if raw != raw or raw in (float("inf"), float("-inf")) or not raw.is_integer():
            return ""
        try:
            return str(int(raw))
        except (OverflowError, ValueError):
            return ""
    if _isinst(raw, str):
        # Through _utf8_text, not a bare ``raw.strip()``: the encode/decode
        # round trip yields a plain ``str``, so a leftover str-*subclass* id
        # whose overridden ``strip()`` (or ``__hash__``, once the id becomes
        # a ``_running`` set member) raised can no longer 500
        # GET /api/scheduler/jobs.  Same coercion hub.jobs._task_id applies.
        return _utf8_text(raw).strip()
    return ""


def job_enabled(job: dict) -> bool:
    """Whether *job* should fire.  YAML ``"false"`` / ``"0"`` are off, not on.

    _mapping_get, not ``job.get``: a leftover hash-shadowing bomb key with
    "enabled"'s text used to detonate the bare probe and 500
    GET /api/scheduler/jobs (and abort the engine tick).  A junk-shadowed
    flag fails closed — junk must not fire operator shell.
    """
    raw = _mapping_get(job, "enabled")
    if _isinst(raw, str):
        # Unbound str.strip: a str-subclass value whose ``strip()`` raised
        # used to 500 GET /api/scheduler/jobs (the unbound view returns an
        # exact str, so the chained ``lower()`` is safe too).
        try:
            return str.strip(raw).lower() not in {"", "0", "false", "no", "off", "n", "f"}
        except Exception:
            # A liar whose ``__class__`` answers str is not a real str: the
            # unbound descriptor refuses it with TypeError, which used to
            # 500 the list route and abort the whole tick.
            return False
    # ``type(raw) is bool``, not isinstance: bool cannot be subclassed, and
    # a liar claiming bool must fall through to the numeric arm's unbound
    # coercion instead of escaping this helper un-boolean.
    if type(raw) is bool:
        return raw
    if _isinst(raw, (int, float)):
        if type(raw) not in (int, float):
            try:
                # Base coercion first: an int/float-subclass ``enabled``
                # whose ``__eq__``/``__ne__`` raised used to blow the NaN
                # probe (or the ``!= 0`` test) and 500 the list route.
                raw = float.__float__(raw) if _isinst(raw, float) else int.__index__(raw)
            except Exception:
                return False
        if raw != raw or raw in (float("inf"), float("-inf")):
            return False
        return raw != 0
    return False


def _encodable_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _command_text(raw) -> str:
    """Shell text for a scheduled command.  Leftover non-str is not argv.

    YAML ``!!binary`` is bytes under SafeLoader.  ``str(bytes)`` is the
    repr, not the payload, but leftover lists of non-str parts were still
    joined into ``bash -c`` and leftover mappings stringified.  Only real
    strings.

    Encodable strings only, the rsync-params rule: a lone surrogate (a JSON
    ``"\\ud800"`` body, a hand-edited services.yaml escape) can never be
    spawned — Popen's argv/env UTF-8 encode refuses it — so POST
    /api/scheduler/jobs used to sail it into mutate()'s YAML dump and answer
    the misleading coded 503 ``settings.save_failed`` instead of the same
    400 ``scheduler.bad_params`` its control-character siblings get.
    """
    if _isinst(raw, (list, tuple)):
        parts: list[str] = []
        for part in raw:
            if not _isinst(part, str):
                return ""
            if type(part) is not str:
                # Exact-str launder: a subclass ``strip()`` bomb or a liar
                # claiming str degrades to the empty command, never a raise.
                part = _utf8_text(part)
            text = part.strip()
            if not text:
                continue
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
                return ""
            if not _encodable_utf8(text):
                return ""
            parts.append(text)
        return " ".join(parts)
    if not _isinst(raw, str):
        return ""
    if type(raw) is not str:
        raw = _utf8_text(raw)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return ""
    if not _encodable_utf8(raw):
        return ""
    return raw.strip()


def _run_command(job: dict, log: list[str]) -> int:
    # _mapping_get: a hash-shadowing bomb key beside "command" survives the
    # _plain_dict copy, and the bare probe is caught by _execute's broad net
    # either way — but degrading field-level keeps the "!! no command
    # configured" diagnosis instead of an opaque "!! error" (the
    # hub.jobs.start_job rule).
    command = _command_text(_mapping_get(_job_params(job), "command"))
    if not command.strip():
        log.append("!! no command configured")
        return -1
    log.append(f"$ {command}")
    return run_watchdog(["/bin/bash", "-c", command],
                        timeout=_job_timeout(job), log=log, env=_job_env())


def _run_rsync(job: dict, log: list[str]) -> int:
    from hub import rsync_svc
    # _job_id, not ``str(job.get("id") or "")``: the bare probe dispatched a
    # leftover hash-shadowing bomb key (and the ``or`` a ``__bool__`` bomb)
    # into _execute's broad net, costing the run its rsync log for an
    # opaque "!! error"; the laundered identity degrades field-level.
    return rsync_svc.run_job(_job_params(job), log=log,
                             timeout=_job_timeout(job), job_id=_job_id(job))


def _run_stack_backup(job: dict, log: list[str]) -> int:
    from hub import backups
    params = _job_params(job)
    # _mapping_get twice: shadow bomb keys beside "stack_id"/"retain" keep
    # the "!! no stack configured" / default-retain degrades field-level
    # instead of costing the run an opaque "!! error".
    stack_id = str(_mapping_get(params, "stack_id") or "")
    if not stack_id:
        log.append("!! no stack configured")
        return -1
    try:
        retain = int(_mapping_get(params, "retain") or backups.RETAIN)
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

def _rebuilt_fail_counts(drop: str) -> dict:
    """A fresh plain streak table without *drop*, laundered to exact types.

    Reached only when the live table refused an unbound read/write — a
    leftover hash-shadow key or a ``__class__`` liar with no dict storage
    at all (then there is nothing to salvage and the slate is clean, the
    same quiet side a panel restart errs on).
    """
    try:
        items = list(dict.items(_fail_counts))
    except Exception:
        return {}
    out: dict = {}
    for k, v in items:
        key = _utf8_text(k)
        if not key or key == drop:
            continue
        if type(v) is int and 0 <= v < 1_000_000:
            out[key] = v
    return out


def _running_has(jid) -> bool:
    """``jid in _running`` that a leftover bomb member cannot 500 through.

    Callers hold ``_running_guard``.  A set membership test compares the
    probe against every stored member whose hash collides, and when the
    member is a *subclass* of the probe's type its reflected ``__eq__`` gets
    first shot — so a leftover str-subclass member with a job id's text and
    a bombing ``__eq__`` used to raise out of :func:`is_running` and 500
    GET /api/scheduler/jobs (every row reads its running flag) and POST
    run-now, and out of :func:`_execute`'s overlap check, breaking its
    "never raises" contract.  A set-*subclass* table's overridden
    ``__contains__`` detonated the same callers.  The probe goes through
    the unbound base; on a raise, a scan counts only *exact*-str members:
    ids this module writes are exact by construction (:func:`_job_id`
    launders them), so a subclass twin is junk, not a live run — reading it
    as "running" would skip the job forever, the same wedged-mutex fail
    direction ``hub.jobs._truthy`` refuses.  A genuine live marker is an
    exact str and the scan still finds it, so overlap-skip survives.
    """
    try:
        return set.__contains__(_running, jid)
    except Exception:
        pass
    try:
        members = list(set.__iter__(_running))
    except Exception:
        # Not really a set (a ``__class__`` liar): nothing can be running.
        return False
    for m in members:
        # type(m) is str, then the unbound compare: neither can raise, and
        # a subclass junk member can neither bomb the scan nor pose as live.
        if type(m) is str and str.__eq__(m, jid) is True:
            return True
    return False


def _rebuilt_running(members) -> set:
    """A fresh plain set keeping only the exact-str live markers.

    A str-*subclass* member is a leftover by definition (this module only
    ever stores :func:`_job_id`'s exact strs); keeping a laundered twin
    would mark a job that is not running as live forever.
    """
    out: set = set()
    for m in members:
        if type(m) is str:
            out.add(m)
    return out


def _add_running(jid: str) -> None:
    """``_running.add(jid)`` that never raises.  Callers hold the guard.

    The plain add compares jid against any colliding stored member,
    dispatching into that member's ``__eq__``; a leftover bomb member (or a
    subclass table's overridden ``add``) used to raise here and 500 the
    run-now path.  On a raise the table is rebuilt with laundered exact-str
    members — ids this module writes already are, so a subclass member is a
    leftover by definition and its laundered twin keeps marking the run.
    """
    global _running
    try:
        set.add(_running, jid)
        return
    except Exception:
        pass
    try:
        members = list(set.__iter__(_running))
    except Exception:
        members = []
    fresh = _rebuilt_running(members)
    fresh.add(jid)
    _running = fresh


def _discard_running(jid: str) -> None:
    """``_running.discard(jid)`` that never raises.  Callers hold the guard.

    A raise out of the discard in :func:`_execute`'s ``finally`` used to
    leave the id parked "running" forever — every later trigger skipped —
    so the rebuild both drops the poisoned twin and completes the discard.
    """
    global _running
    try:
        set.discard(_running, jid)
        return
    except Exception:
        pass
    try:
        members = list(set.__iter__(_running))
    except Exception:
        members = []
    fresh = _rebuilt_running(members)
    fresh.discard(jid)
    _running = fresh


def _alert_on_failure(job: dict, entry: dict) -> None:
    """Track consecutive failures; involve the alert pipeline on a streak.

    Imported lazily and wrapped: a broken alert path must not take the
    scheduler thread with it, mirroring how the alerter itself never lets a
    channel exception escape.

    The streak table reads/writes go through the unbound dict builtins in
    a try: every ``_fail_counts`` access hash-probes the table and compares
    jid against any colliding stored key, so a leftover hash-shadow key (a
    str subclass with the id's text and a bombing ``__eq__``) — or a
    dict-subclass table with bombing overrides — used to raise out of
    :func:`_execute` *after* the run was journalled, breaking its "never
    raises" contract and killing the run thread.  On a poisoned write the
    table is rebuilt with laundered exact-str keys and exact-int counts so
    the streak (and the alert it has earned) survives the junk twin.
    """
    global _fail_counts
    jid = _job_id(job)
    if not jid:
        return
    if entry.get("status") == "ok":
        try:
            dict.pop(_fail_counts, jid, None)
        except Exception:
            _fail_counts = _rebuilt_fail_counts(drop=jid)
        return
    if entry.get("status") == "skipped":
        return
    try:
        prev = dict.get(_fail_counts, jid, 0)
    except Exception:
        prev = 0
    # Exact bounded int only: a leftover junk count (a bool, an int-subclass
    # arithmetic bomb, a >4300-digit int whose str() the alert f-string
    # cannot render) restarts the streak instead of detonating it.
    if type(prev) is not int or not 0 <= prev < 1_000_000:
        prev = 0
    count = prev + 1
    try:
        dict.__setitem__(_fail_counts, jid, count)
    except Exception:
        fresh = _rebuilt_fail_counts(drop=jid)
        fresh[jid] = count
        _fail_counts = fresh
    if count < FAILURE_ALERT_AFTER:
        return
    try:
        from hub import alerts
        alerts.emit_alert(
            kind="schedule",
            level="warn",
            alert_id=f"schedule:{jid}",
            message=(
                # _job_label: the bare ``or`` ran a leftover name value's
                # ``__bool__``; the bomb was swallowed by the except below
                # but silently dropped the alert the streak had earned.
                f"scheduled task '{_job_label(job, jid)}' failed "
                f"{count} times in a row (last exit {entry.get('rc')})"
            ),
        )
    except Exception:
        pass


def _job_label(job: dict, jid: str):
    """The job's display name, or its id.

    The bare ``job.get("name") or jid`` ran a leftover name value's own
    ``__bool__``; a subclass bomb there raised out of :func:`_execute`'s
    entry build — *after* the runner had finished — so the run journalled
    nothing and the "Never raises" contract broke.  The rendered value
    itself is _jsonable's problem, not this helper's.
    """
    try:
        name = job.get("name")
        return name if name else jid
    except Exception:
        return jid


def _execute(job: dict, trigger: str) -> dict:
    """Run *job* to completion and journal the outcome.  Never raises."""
    jid = _job_id(job)
    if not jid:
        return {"ok": False, "error": "no_id"}
    # _mapping_get, read once: the entry builds below run *outside* the try
    # (the skipped build before it, the final build after the finally), so a
    # leftover hash-shadowing bomb key with "type"'s text used to raise out
    # of the bare ``job.get("type")`` probes and break the "never raises"
    # contract — after the runner had already finished, so the run was
    # never journalled.
    job_type = _mapping_get(job, "type")
    started = time.time()
    with _running_guard:
        # _running_has / _add_running, not bare set ops: a leftover bomb
        # member (or a subclass table) used to raise here — before the try
        # below — and break the "never raises" contract.
        if _running_has(jid):
            entry = {
                "ts": _epoch_int(started), "end": _epoch_int(started), "job": jid,
                "name": _job_label(job, jid), "type": job_type,
                "trigger": trigger, "status": "skipped", "rc": None,
                "tail": "previous run still in progress", "duration": 0,
            }
            _record_run(entry)
            return entry
        _add_running(jid)
    log: list[str] = []
    rc: int | None = -1
    try:
        runner = _RUNNERS.get(str(job_type or ""))
        if runner is None:
            # _utf8_text, not the raw value: a junk type's own
            # ``__str__``/``__format__`` bomb in the f-string degrades
            # field-level instead of costing the run its diagnosis.
            log.append(f"!! unknown job type: {_utf8_text(job_type)}")
            rc = -1
        else:
            rc = runner(job, log)
    except Exception as e:  # a runner bug must not kill the engine thread
        log.append(f"!! error: {_utf8_text(e)}")
        rc = -1
    finally:
        with _running_guard:
            _discard_running(jid)
    ended = time.time()
    try:
        status = "ok" if rc == 0 else ("timeout" if rc == 124 else "failed")
    except Exception:
        # An int-subclass ``__eq__`` bomb rc from a runner seam used to
        # raise here — *after* the runner finished — so the run journalled
        # nothing and the "Never raises" contract broke (the api_action
        # guarded-rc rule).  A bomb rc is not a clean exit: read it as
        # failure.
        status = "failed"
    entry = {
        "ts": _epoch_int(started), "end": _epoch_int(ended), "job": jid,
        "name": _job_label(job, jid), "type": job_type,
        "trigger": trigger, "status": status, "rc": rc,
        "tail": "\n".join(log)[-TAIL_CHARS:],
        "duration": _finite_duration(ended, started),
    }
    _record_run(entry)
    _alert_on_failure(job, entry)
    return entry


def is_running(job_id: str) -> bool:
    # _running_has, not bare ``in``: a leftover hash-shadow member's
    # reflected ``__eq__`` (or a subclass table's ``__contains__``) used to
    # raise here and 500 GET /api/scheduler/jobs and POST run-now.
    with _running_guard:
        return _running_has(job_id)


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
    last = _last_minute
    try:
        if key == last:
            return []
        went_back = last is not None and key < last
    except Exception:
        # This module only ever writes exact int tuples, but the mark is
        # whatever an in-process leftover last stored: a junk high-water
        # mark (a tuple subclass whose ``__eq__``/``__lt__`` bombs, junk
        # elements the comparison reflects into) used to raise out of every
        # tick forever — every job's every minute was lost while the loop's
        # broad except kept the thread alive.  A junk mark carries no
        # usable timeline: re-anchor on the current minute with boot
        # semantics (marked evaluated, not fired).
        _last_minute = key
        return []
    if went_back:
        # Naive datetimes on purpose: both keys came from time.localtime(),
        # so their difference is the wall-clock distance the operator sees.
        try:
            small_step = datetime(*last) - datetime(*key) <= _BACKWARD_RESYNC
        except Exception:
            # A mark that compares but cannot build a datetime (junk
            # elements) is a leftover, not a timeline: re-anchor.
            small_step = False
        if small_step:
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
            # _mapping_get, not ``job.get``: a leftover hash-shadowing bomb
            # key with "cron"'s text raised RuntimeError past this
            # (ValueError, TypeError) net and aborted the whole tick —
            # every *other* job's matching minute was lost while _loop's
            # broad except kept the thread alive.
            if not cron_matches(_mapping_get(job, "cron"), now):
                continue
        except (ValueError, TypeError):
            continue  # an unparsable expression can never fire
        launched.append(jid)
        threading.Thread(
            target=_execute, args=(job, "schedule"), daemon=True,
            # jid, not the raw id: the f-string ran a leftover id value's
            # own __format__/__str__, and a subclass bomb there aborted the
            # whole tick — every *other* job's matching minute was lost.
            name=f"sched-{jid}",
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
