"""Liveness registry for the panel's long-lived worker threads.

Every core background subsystem here is a daemon thread running a loop —
metrics sampler, alert engine, cron scheduler, SMART test scheduler.  A
daemon thread that dies is the worst failure mode this process has: nothing
restarts it, nothing logs it after the fact, and the panel keeps answering
requests while alerts silently stop firing or metrics silently stop
recording.  The loops themselves guard their bodies, but "the loop is
guarded" is an invariant only tests enforce; this registry makes the runtime
state observable so the health page can report a dead or wedged worker.

Usage, from inside the worker thread:

    worker_health.register("alert-engine", interval)   # loop start
    worker_health.beat("alert-engine")                 # once per iteration

and from the matching ``stop_*`` function:

    worker_health.unregister("alert-engine")           # a stopped worker is
                                                       # not a dead worker

The health check (hub/health_svc.py) calls :func:`problems`, which reports a
worker whose thread is no longer alive, or whose last beat is older than
``interval * STALE_AFTER`` — a loop that is alive but wedged (e.g. blocked
forever on something that escaped every timeout) stops beating and turns
stale.  Deliberately dependency-free: dict + monotonic-ish wall clock, no
subprocesses, no locks held while doing anything slow, so a health probe can
never be the thing that hurts the workers it watches.
"""
from __future__ import annotations

import re
import threading
import time

#: A worker is reported stale when its last beat is older than this many
#: multiples of its own loop interval.  3x tolerates one slow tick and one
#: missed tick before alarming, which keeps the check quiet on a loaded host.
STALE_AFTER = 3.0
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

_lock = threading.Lock()
_workers: dict[str, dict] = {}


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a planted entry/row whose ``__class__`` is a *raising
    property* detonated the very gates below: out of ``snapshot()`` /
    ``problems()`` (silently wiping the workers row from GET
    /api/health/checks), out of ``beat()`` on the worker's own thread —
    killing the loop this registry exists to watch — and out of
    ``register()``/``loop_interval()`` on the sampler/alerter/scheduler
    start path.  A real subclass still matches through the C-level type
    check; only a value that cannot answer what it is takes the
    non-matching branch (the smart_test_svc._isa rule).
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _truthy(value) -> bool:
    """``bool()`` that a leftover ``__bool__`` bomb cannot detonate.

    :func:`problems` does not own the *rows* it is handed (callers pass a
    snapshot they already took, and tests plant rows directly), and a
    ``__bool__``-bomb ``alive``/``stale`` field — or a str-subclass *name*
    whose ``__bool__`` raises, through the old ``name or "?"`` — used to
    raise through the per-row try and silently drop that worker's
    dead/stale report from GET /api/health/checks.  An ``alive`` that
    cannot answer reads False, so the poisoned worker is *reported* dead
    rather than silently passed as healthy (the health_svc._truthy rule,
    fail-closed in the direction this page exists to warn about).
    """
    if type(value) is bool:
        return value
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _mapping_get(mapping, key, default=None):
    """Entry field read that a hostile mapping *key* cannot detonate.

    The health_svc/vms_svc rule: even a plain-dict lookup still runs the
    *stored keys'* own ``__eq__`` during the hash probe, so a leftover
    str-subclass key planted in an entry (same hash as ``thread``/``beat``/
    ``interval``, raising ``__eq__``) used to raise out of ``snapshot()``'s
    bound ``entry.get`` and silently wipe the workers row from GET
    /api/health/checks.  Only the shadowed field degrades to its default.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _evict_unusable_keys() -> None:
    """Drop registry keys that cannot survive a hash-probe compare.

    Called under ``_lock``, on the failure path only.  Production keys are
    always the exact ``str`` that ``_name_key`` answers, so anything else in
    the table is a planted leftover — and a str-subclass key whose hash
    shadows a real worker name (raising ``__eq__``) used to raise out of the
    C-level insert/lookup inside :func:`register` / :func:`beat` /
    :func:`unregister` *on the worker's own thread*, killing the exact loop
    this registry exists to watch.  ``items()`` iteration and ``clear()``
    never compare keys, and re-inserting exact-str keys only ever compares
    exact strings, so this salvage cannot re-detonate.
    """
    salvaged = [(k, v) for k, v in _workers.items() if type(k) is str]
    _workers.clear()
    for k, v in salvaged:
        _workers[k] = v


def _coerce_interval(interval) -> float:
    """A positive finite loop interval, even when a hand-edit passed ``90s``.

    Leftover YAML ``true`` is a bool subclass of int; ``float(True)`` is 1.0
    and used to mark the worker stale after three seconds.
    """
    # _isa: a ``__class__``-property bomb interval detonated this very gate
    # out of register() on the worker's own thread.
    if _isa(interval, bool) or interval is None:
        return 60.0
    try:
        # Base coercions before ``float()`` (the smart_test_svc._schedule_epoch
        # rule): a numeric-subclass ``__float__``/``__index__`` bomb raised
        # RuntimeError past the old arithmetic trio — out of register() on the
        # worker's own thread, and out of snapshot() where it silently wiped
        # the workers row from GET /api/health/checks.
        if isinstance(interval, int):
            interval = int.__index__(interval)
        elif isinstance(interval, float):
            interval = float.__float__(interval)
        n = float(interval)
    except Exception:
        n = 60.0
    if n != n or n in (float("inf"), float("-inf")) or n <= 0:
        n = 60.0
    n = max(1.0, n)
    prod = n * STALE_AFTER
    if prod != prod or prod in (float("inf"), float("-inf")):
        n = 60.0
    return n


def loop_interval(raw, default: int = 90, *, minimum: int = 30, maximum: int = 86400) -> int:
    """Positive seconds for ``Event.wait`` / ``int(interval)`` on the start path.

    YAML leftover ``.inf`` / ``1e308`` / ``true`` / ``!!binary`` used to
    OverflowError ``int(inf)`` on the LaunchAgent thread (sampler / alerter)
    or kill the SMART scheduler on ``stop.wait(check_interval)``.
    """
    # _isa: a ``__class__``-property bomb raw detonated the gate itself on
    # the sampler/alerter/scheduler start path instead of answering default.
    if _isa(raw, bool) or raw is None:
        return default
    try:
        # Base coercions first (the _coerce_interval rule): a float-subclass
        # ``__eq__`` bomb used to blow the NaN probe below, and an
        # int-subclass ``__int__`` bomb blew ``int(raw)`` — both raised on
        # the sampler/alerter/scheduler start path instead of answering the
        # default interval.
        if isinstance(raw, int):
            raw = int.__index__(raw)
        elif isinstance(raw, float):
            raw = float.__float__(raw)
        if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
            return default
        n = int(raw)
    except Exception:
        return default
    if n <= 0 or n > maximum:
        return default
    return n if n >= minimum else minimum


def _wall_now() -> float:
    """Finite wall clock. Leftover ``time.time() = inf`` used to poison health age math."""
    try:
        n = float(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
        return 0.0
    return n


def _finite_beat(raw) -> float:
    """Finite beat timestamp from an entry this walk may not own.

    beat() only ever writes ``_wall_now()``, but tests and tooling plant
    entries directly, and a numeric-subclass ``__bool__``/``__float__`` bomb
    used to blow the old ``raw or 0.0`` / ``float(raw)`` past the arithmetic
    trio — snapshot() raised and the workers row silently vanished from
    GET /api/health/checks (the health7 wipe class, one field over).
    """
    # _isa: a ``__class__``-property bomb beat detonated this gate out of
    # snapshot() — the same wipe, one probe earlier.
    if _isa(raw, bool) or raw is None:
        return 0.0
    try:
        if isinstance(raw, int):
            raw = int.__index__(raw)
        elif isinstance(raw, float):
            raw = float.__float__(raw)
        beat = float(raw)
    except Exception:
        return 0.0
    if beat != beat or beat in (float("inf"), float("-inf")):
        return 0.0
    return beat


def _coerce_now(now) -> float:
    """Wall clock for age math; garbage / overflow must not 500 the health page."""
    if now is None:
        return _wall_now()
    try:
        # Base coercions before ``float()`` (the _finite_beat rule): snapshot()
        # is also called in-process with an explicit *now*, and a
        # float-subclass ``__float__`` bomb raised RuntimeError past the old
        # arithmetic trio — out of snapshot()/problems() where it silently
        # wiped the workers row from GET /api/health/checks.
        if isinstance(now, int) and not isinstance(now, bool):
            now = int.__index__(now)
        elif isinstance(now, float):
            now = float.__float__(now)
        n = float(now)
    except Exception:
        return _wall_now()
    if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
        return _wall_now()
    return n


def _name_key(name) -> str:
    """The registry key for *name*; a ``__str__`` bomb keys by its type.

    register(), beat() and unregister() must agree on the key, so the
    fallback is deterministic rather than "".  A bare ``str(name)`` used to
    re-raise a subclass ``__str__`` bomb out of register() on the worker's
    own thread — killing the loop this registry exists to watch.

    Exact ``str`` always (the modules6 rule at key rank): ``str(x)`` of a
    subclass whose ``__str__`` answers *self* — or any ``__str__`` that
    answers a str *subclass* — skips CPython's exact-str copy, so the old
    answer still carried live comparison hooks.  Planted as a registry name,
    that rode this key into :func:`snapshot`'s ``sorted`` compare, where a
    ``__lt__``/``__gt__`` bomb raised out of the sort itself: snapshot()
    blew up, ``problems()``'s rows=None path re-raised, and the workers row
    — honest dead-worker reports included — silently vanished from GET
    /api/health/checks.  The unbound base encode/decode copies the
    subclass's real storage without running any of its hooks; an exact str
    passes through untouched, so honest keys are unchanged.
    """
    try:
        text = str(name)
    except Exception:
        try:
            text = type(name).__name__
        except Exception:
            return "?"
    if type(text) is str:
        return text
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except Exception:
        return "?"


def register(name: str, interval: float, thread: threading.Thread | None = None) -> None:
    """(Re-)register a worker; records an initial beat.

    *thread* defaults to the calling thread, which is the normal case: the
    worker loop registers itself as its first act.  Passing an explicit
    thread exists for tests, which register fakes.
    """
    entry = {
        "thread": thread if thread is not None else threading.current_thread(),
        "interval": _coerce_interval(interval),
        "beat": _wall_now(),
    }
    with _lock:
        # Guarded insert: a planted hash-shadowing junk key (same hash as
        # this worker's name, raising ``__eq__``) used to raise out of the
        # C-level compare on the worker's own thread — killing the
        # sampler/alerter/scheduler loop at its very first act.  Evict the
        # poison and retry so the honest registration still lands.
        try:
            _workers[_name_key(name)] = entry
        except Exception:
            try:
                _evict_unusable_keys()
                _workers[_name_key(name)] = entry
            except Exception:
                pass


def beat(name: str) -> None:
    """Record one loop iteration.  A beat for an unregistered name is a no-op
    (the worker may have been unregistered by a concurrent ``stop_*``)."""
    with _lock:
        # Guarded lookup (the register() rule): a planted hash-shadowing
        # junk key used to raise out of the C-level compare inside
        # ``_workers.get`` on the worker's own thread — the same loop kill,
        # one call later.  An unreadable slot reads as unregistered.
        try:
            entry = _workers.get(_name_key(name))
        except Exception:
            entry = None
        # _isa + unbound ``dict.__setitem__``: a planted entry whose
        # ``__class__`` is a raising property (or a dict subclass with a
        # ``__setitem__`` bomb) used to raise out of beat() on the worker's
        # own thread — killing the loop this registry exists to watch.
        if _isa(entry, dict):
            try:
                dict.__setitem__(entry, "beat", _wall_now())
            except Exception:
                pass


def unregister(name: str) -> None:
    with _lock:
        # Guarded pop (the register() rule): the C-level lookup compare of a
        # planted hash-shadowing junk key raised out of the ``stop_*``
        # teardown path.  Evict the poison and retry so a genuinely stopped
        # worker cannot linger as a false "thread died" health row.
        try:
            _workers.pop(_name_key(name), None)
        except Exception:
            try:
                _evict_unusable_keys()
                _workers.pop(_name_key(name), None)
            except Exception:
                pass


def snapshot(now: float | None = None) -> list[dict]:
    """State of every registered worker, sorted by name."""
    now_f = _coerce_now(now)
    with _lock:
        items = []
        for name, entry in _workers.items():
            # _isa: a planted ``__class__``-property-bomb entry detonated
            # this gate and silently wiped the workers row from GET
            # /api/health/checks; the poisoned entry drops alone instead.
            if _isa(entry, dict):
                # Copy in a try: a dict-subclass ``keys``/``__iter__`` bomb
                # (or colliding junk keys raising out of the C-level insert
                # compare) used to raise out of the copy itself — the same
                # silent wipe, one call earlier.  The unreadable entry
                # drops alone; its siblings keep their rows.
                try:
                    items.append((name, dict(entry)))
                except Exception:
                    continue
    out = []
    # _name_key, not bare str(): a planted name key that is an over-cap int
    # (YAML/plist hex loads uncapped) ValueError'd the sort key itself, and a
    # subclass ``__str__`` bomb raised the same way — snapshot() blew up and
    # the workers row silently vanished from GET /api/health/checks.
    # Guarded sort: _name_key now answers exact strs (whose compares cannot
    # run user hooks), but the sort stays fail-open to insertion order so no
    # future key shape can re-detonate the same wipe.
    try:
        ordered = sorted(items, key=lambda kv: _name_key(kv[0]))
    except Exception:
        ordered = items
    for name, entry in ordered:
        # _mapping_get, not bound ``.get``: a hash-shadowing junk key riding
        # the copied entry (same hash as ``thread``/``beat``/``interval``,
        # raising ``__eq__``) used to detonate the plain-dict lookup here
        # and silently wipe the workers row; the shadowed field now degrades
        # alone and the worker still renders.
        thread = _mapping_get(entry, "thread")
        try:
            alive = bool(thread is not None and thread.is_alive())
        except Exception:
            alive = False
        beat = _finite_beat(_mapping_get(entry, "beat"))
        interval = _coerce_interval(_mapping_get(entry, "interval"))
        age = max(0.0, now_f - beat)
        if age != age or age in (float("inf"), float("-inf")):
            age = 0.0
        age_sec = round(age, 1)
        if age_sec != age_sec or age_sec in (float("inf"), float("-inf")):
            age_sec = 0.0
        try:
            stale = age > interval * STALE_AFTER
        except (OverflowError, TypeError, ValueError):
            stale = True
        out.append({
            "name": _utf8_text(name),
            "alive": alive,
            "interval": interval,
            "age_sec": age_sec,
            "stale": stale,
        })
    return out


def _pull_guarded(rows) -> list:
    """Materialize *rows* one element at a time, absorbing a mid-walk raise.

    A generic iterable that *answers* ``iter()`` but raises mid-iteration
    (a patched ``problems(rows=...)`` provider) used to blow the caller's
    per-row guard; the elements already yielded survive, the bomb costs only
    its own tail.  Also the fall-through for a lying-``list`` impostor whose
    unbound ``list.__iter__`` raised.
    """
    try:
        it = iter(rows)
    except Exception:
        return []
    collected = []
    while True:
        try:
            collected.append(next(it))
        except StopIteration:
            break
        except Exception:
            break
    return collected


def problems(now: float | None = None, rows: list[dict] | None = None) -> list[str]:
    """Human-readable descriptions of dead or stale workers (empty = healthy).

    *rows* reuses a :func:`snapshot` already taken by the caller so health
    cannot report ``N worker threads ticking`` from one read and a dead-thread
    line from a second read that raced with unregister.
    """
    if rows is None:
        rows = snapshot(now)
    elif _isa(rows, list):
        # Unbound base walk (the health_svc._as_checks rule): this function
        # does not own *rows*, and a list-subclass ``__iter__`` bomb used to
        # raise here and silently wipe the workers row from the health page.
        # _isa on the gate itself: a ``__class__``-property-bomb rows object
        # detonated the old bare isinstance the same way.  The unbound
        # descriptor runs in a try: a lying-``__class__`` impostor (the
        # docker10/json9 shape — ``isinstance`` says list, the real object is
        # not one) passed the gate but made ``list.__iter__`` raise
        # ``TypeError``; it falls through to the generic guarded pull loop.
        try:
            rows = list.__iter__(rows)
        except Exception:
            rows = _pull_guarded(rows)
    else:
        # Materialize with a guarded pull loop: a generic iterable that
        # *answers* iter() but raises mid-iteration used to blow the for
        # loop below past the per-row guard — the rows already yielded
        # survive, the bomb costs only its own tail.
        rows = _pull_guarded(rows)
    out = []
    for w in rows:
        # _isa: a ``__class__``-property-bomb row detonated the gate itself,
        # outside the per-row try, and wiped the workers row.
        if not _isa(w, dict):
            continue
        try:
            # _mapping_get, not unbound ``dict.get``, and one Exception net
            # per row: a dict-subclass row drops alone rather than costing
            # every sibling's dead/stale report — but the old bare
            # ``dict.get`` still ran the *stored keys'* own ``__eq__``
            # during the hash probe, so a hash-shadowing junk key riding a
            # row (same hash as ``name``/``alive``/``stale``/``age_sec``,
            # raising ``__eq__``) raised through this try and silently
            # dropped that worker's report — a dead worker passed as
            # healthy, the exact fail-open direction the ``alive`` launder
            # below exists to prevent.  Only the shadowed field degrades to
            # its default; a shadowed ``alive`` reads absent -> falsy ->
            # the "thread died" report.  _utf8_text *before* the ``or``
            # (its answer is an exact str, so the truth test is safe) and
            # _truthy on the flag fields: a ``__bool__``-bomb name/alive/
            # stale used to raise through this try and silently drop the
            # dead-worker line — a bombed ``alive`` now reads as the
            # "thread died" report instead of vanishing.
            raw_name = _mapping_get(w, "name")
            name = (_utf8_text(raw_name) if raw_name is not None else "") or "?"
            if not _truthy(_mapping_get(w, "alive")):
                out.append(f"{name}: thread died")
            elif _truthy(_mapping_get(w, "stale")):
                age = int(_finite_beat(_mapping_get(w, "age_sec")))
                interval = int(_finite_beat(_mapping_get(w, "interval")))
                out.append(f"{name}: last tick {age}s ago (interval {interval}s)")
        except Exception:
            continue
    return out
