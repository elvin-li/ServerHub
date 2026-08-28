"""OrbStack Docker-compatible CLI helpers."""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from hub.paths import DOCKER
from hub.util import safe_json_loads, sh

SENSITIVE = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|KEY|PASS|CREDENTIAL)", re.I)
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: ``_jsonable``'s rank gates blew
    GET /api/stacks and GET /api/stacks/jobs/{id} on one poisoned job-row
    field, and ``_as_text``'s bytes gate blew the job-log join the same way
    (the nas8 / catalog10 rule).  A real subclass still matches through the
    C-level type check; only a value that cannot answer what it is takes
    the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    Both bases, real layout first-come. A lying ``__class__`` that only
    claims bytes no longer wipes genuine str storage.
    """
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
        return ""


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


def _as_text(value) -> str:
    # _isa, not a bare isinstance: a leftover log item whose ``__class__``
    # is a raising property used to detonate this gate and 500 the
    # stack-job log join (GET /api/stacks/jobs/{id}).
    decoded = None
    if _isa(value, (bytes, bytearray)):
        try:
            decoded = _decode_bytes(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            decoded = None
    if decoded is not None:
        value = decoded
    elif value is None:
        return ""
    elif type(value) is not str:
        # str() also keeps a str *subclass* whose ``__str__`` answers self;
        # the unbound encode below is what disarms its bound method bombs.
        try:
            value = str(value)
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
        text = str.encode(value, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _jsonable(value, depth: int = 0):
    """Drop leftover inf/NaN/bytes/``\\ud800`` so Starlette cannot 500.

    Python ``json.loads`` accepts ``Infinity`` in inspect / ``{{json .}}``
    NDJSON; Starlette's encoder does not. A leftover ``\\ud800`` name still
    500'd ``ensure_ascii=False`` then UTF-8 on GET /api/docker/info and
    GET /api/apps/managed.
    A >4300-digit leftover int still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    # _isa on every rank gate: a leftover whose ``__class__`` is a raising
    # property used to detonate the *first* isinstance below and 500
    # GET /api/stacks and GET /api/stacks/jobs/{id} on one poisoned job-row
    # scalar (rc/started/…) — one step ahead of every scrub in this funnel.
    # ``type(value) is bool``, not _isa: a liar whose ``__class__`` *answers*
    # bool passed the old gate and rode raw through every consumer of this
    # funnel into Starlette's encoder (an autostart toggle's ``ok`` field
    # 500'd POST /api/apps/managed/action); bool cannot be subclassed, so
    # the exact check is complete and the impostor falls to the int arm's
    # unbound coercion (the jobs/scheduler_svc convention).
    if value is None or type(value) is bool:
        return value
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # in a poisoned job-row ``rc`` used to blow the digit-cap
                # probe below (only ValueError was caught) and 500
                # GET /api/stacks and GET /api/stacks/jobs/{id} — the
                # modules5 unbound convention (hub.status/_modules twins).
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``/
                # ``__ne__`` bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode: a subclass ``.decode`` bomb cannot fire.
            # The try is for a lying ``__class__`` (claims bytes, is not):
            # the unbound call TypeErrors and the impostor drops.
            return _decode_bytes(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isa(value, dict):
        if type(value) is not dict:
            # dict() copies through the C-level storage, ignoring overridden
            # items()/keys()/__iter__ — a leftover nested dict-subclass bomb
            # cannot fire (same guard as hub.jobs._jsonable).
            try:
                value = dict(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        out = {}
        for k, v in value.items():
            # _isa on the key gates too: a ``__class__``-property-bomb KEY
            # in a poisoned row detonated the bytes gate the same way.
            if _isa(k, (bytes, bytearray)):
                try:
                    k = _decode_bytes(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            elif not _isa(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            items = list(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Leftover nested sequence subclass whose __iter__ raises.
            return None
        return [_jsonable(v, depth + 1) for v in items]
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Property bomb / __getattr__ raising something that is not
        # AttributeError escapes getattr's default.
        iso = None
    if callable(iso):
        try:
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; junk reads as failure.

    This module does not own ``sh`` (tests and tooling patch it — the
    health9 / hub.host_address._rc_int rule), and :func:`docker` laundered
    only the two text streams of the tuple.  A leftover riding the *rc*
    slot went out raw to every consumer:

    * an int-subclass whose ``__eq__``/``__ne__`` raises detonated the bare
      ``rc == -1`` probe inside :func:`engine_up` and 500'd essentially
      every docker route (GET /api/containers, /api/stacks, /api/images,
      /api/volumes, /api/networks and the action/exec/prune mutations);
    * a lying-``__class__`` impostor (claims bool/int/str, is none of
      them) and a raising ``__class__`` property rode
      ``exec_in_container``'s raw ``"rc": rc`` echo into the response
      encoder — the bool/int liar is unserializable and the class bomb
      detonates the encoder's own isinstance rank gates — a raw 500 on
      POST /api/containers/{name}/exec;
    * a >4300-digit int passed every gate untouched and then ValueError'd
      ``str()`` past CPython's digit cap — ``container_action``'s
      ``f"exit {rc}"`` 500'd POST /api/containers/{name}/action, and the
      encoder 500'd the exec echo the same way.

    ``-255`` is no honest exit status and is distinct from the ``-1``
    timeout / not-found sentinel, so junk can never be misread as a
    timeout, a vanished CLI, or success.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        # Unbound base coercion: a subclass ``__index__``/``__int__`` bomb
        # cannot fire, and a lying-``__class__`` impostor TypeErrors here
        # instead of passing the gate (the modules5 unbound convention).
        value = int.__index__(rc) if isinstance(rc, int) else int(rc)
        # Digit-cap probe: past CPython's int->str cap the status cannot be
        # rendered by any log line or JSON encoder — junk, reads as failure.
        str(value)
        return value
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def docker(*args, timeout=30) -> tuple[int, str, str]:
    # Guarded unwrap of the whole ``sh`` answer, not just its three slots:
    # this module does not own ``sh`` (tests and tooling patch it), and a
    # leftover riding the *shape* of the return — a 2-tuple, a scalar, a
    # sequence subclass whose ``__iter__`` raises, a ``__class__``-property
    # bomb — used to detonate the bare ``rc, out, err = …`` unpack itself
    # and 500 essentially every docker route at once (the listings, inspect,
    # /api/docker/df|sizes and the action/exec/prune mutations), one step
    # ahead of the per-slot launders below.  A junk shape carries no exit
    # status and no output: it reads as the same ``-255`` failure `_rc_int`
    # assigns junk rc values — never the ``-1`` timeout / not-found sentinel,
    # never success — so the routes degrade to their coded answers.
    try:
        rc, out, err = sh([DOCKER, *args], timeout=timeout)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rc, out, err = -255, "", ""
    return _rc_int(rc), _as_text(out), _as_text(err)


#: What the docker CLI / compose plugin print when the daemon is unreachable.
#: One definition for every engine-down classifier (compose validate, the
#: Apps-page compose wrapper, catalog install/uninstall, the stack jobs), so
#: a new phrasing only ever needs adding here.
ENGINE_DOWN_RE = re.compile(
    r"cannot connect to the docker daemon"
    r"|is the docker daemon running"
    r"|error during connect"
    r"|docker daemon is not running",
    re.I,
)


def looks_engine_down(text) -> bool:
    """True when CLI output *text* reads like the daemon socket is gone.

    Purely a message-pattern gate: callers must still confirm with a forced
    ``engine_up`` probe before classifying, so output that merely quotes these
    strings (a container's own log, say) cannot flip a real failure into
    ``container.engine_down``.
    """
    return bool(ENGINE_DOWN_RE.search(_as_text(text)))


def looks_cli_vanished(text) -> bool:
    """True when *text* is ``run_capped``/``sh``'s FileNotFoundError sentinel.

    Both helpers report a binary that could not be spawned as the exact
    two-word sentinel ``"not found"`` (with rc -1) — never a real CLI exit.
    A docker CLI that vanished between an up-front presence gate and the
    spawn (OrbStack uninstalled mid-request, a dying mount) is the same
    operator-facing state as a stopped engine — docker is unreachable — so
    the classifiers that already map daemon-socket failures to
    ``container.engine_down`` treat the two alike (the hub/backups.py
    ``_docker_vanished`` convention).

    Purely a message-pattern gate like :func:`looks_engine_down`: callers
    must still confirm with a forced ``engine_up`` probe — which cannot
    answer "up" while the CLI is gone — so a genuine CLI exit whose output
    merely reads "not found" while the engine is up keeps its original
    failure mapping.
    """
    return _as_text(text).strip() == "not found"


def cli_on_disk() -> bool:
    """True when the DOCKER binary is still present on disk.

    ``run_capped``/``sh`` collapse *every* FileNotFoundError spawn into the
    same ``(-1, "not found")`` sentinel — a cwd that vanished between the
    caller's own mkdir/exists gate and the spawn (a stack directory deleted
    mid-request) raises exactly like a vanished binary.  Classifiers that
    map the sentinel to ``container.engine_down`` must therefore confirm
    the CLI actually left the disk first: with the binary still present and
    the engine merely off, the 503 told the operator to start the engine
    when the real problem was the missing directory.  A stat that raises
    (EIO/ESTALE under a dying mount holding the binary) counts as gone —
    the CLI is unreachable either way.
    """
    try:
        return Path(DOCKER).exists()
    except (OSError, ValueError):
        return False


def parse_int_capped(digits: str):
    """``json.loads`` *parse_int* hook that survives >4300-digit literals.

    CPython's int(str) digit cap makes the decoder itself raise ValueError —
    not JSONDecodeError — on a leftover huge number, so callers that catch
    "corrupt JSON" dropped the *whole* document: one poisoned entry in
    docker-update-status.json wiped every sibling image's state on the next
    save, and one huge number anywhere in ``docker inspect`` output turned
    an existing container into a coded 404.  A number past the cap cannot be
    rendered by any JSON encoder anyway, so it loads as None — the same drop
    ``_jsonable`` applies to an already-int leftover.
    """
    try:
        return int(digits)
    except ValueError:
        return None


def inspect_object(out: str) -> dict | None:
    """First object from ``docker inspect`` JSON, or None if unusable.

    ``docker inspect`` prints a list.  A torn/empty/non-object payload used
    to raise ``IndexError``/``AttributeError`` on ``json.loads(out)[0]``
    and 500 the inspect and recreate routes.
    """
    try:
        parsed = safe_json_loads(out, parse_int=parse_int_capped)
    except (TypeError, ValueError, RecursionError):
        return None
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else None
    if not isinstance(parsed, dict):
        return None
    cleaned = _jsonable(parsed)
    return cleaned if isinstance(cleaned, dict) else None


def docker_json(args: list[str], timeout=30) -> Any:
    rc, out, err = docker(*args, timeout=timeout)
    out, err = _as_text(out), _as_text(err)
    if rc != 0:
        return None, rc, err or out
    if not out.strip():
        argv = args if isinstance(args, (list, tuple)) else ()
        return [] if "--format" in " ".join(str(a) for a in argv) else None, 0, ""
    try:
        # docker --format '{{json .}}' produces NDJSON
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if len(lines) > 1 or (lines and lines[0].startswith("{") and "\n" not in out.strip()):
            # multi-line NDJSON or single object
            if all(ln.lstrip().startswith("{") or ln.lstrip().startswith("[") for ln in lines):
                objs: list[dict] = []
                for ln in lines:
                    try:
                        parsed = safe_json_loads(ln, parse_int=parse_int_capped)
                    except (TypeError, ValueError, RecursionError):
                        # RecursionError: leftover nested NDJSON row is not
                        # ValueError; skip it so siblings still list.
                        continue
                    if isinstance(parsed, list):
                        objs.extend(
                            _jsonable(x) for x in parsed if isinstance(x, dict)
                        )
                    elif isinstance(parsed, dict):
                        objs.append(_jsonable(parsed))
                return [x for x in objs if isinstance(x, dict)], 0, ""
        parsed = safe_json_loads(out, parse_int=parse_int_capped)
        if isinstance(parsed, list):
            return [
                x for x in (_jsonable(row) for row in parsed if isinstance(row, dict))
                if isinstance(x, dict)
            ], 0, ""
        if isinstance(parsed, dict):
            cleaned = _jsonable(parsed)
            return cleaned if isinstance(cleaned, dict) else {}, 0, ""
        return [], 0, ""
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return [], 0, ""


#: Liveness of the Docker engine, memoised.
#:
#: `engine_up()` has around twenty call sites across a dozen modules and each one
#: ran a full `docker info` purely to read its exit status -- measured at 160ms to
#: 1.1s per call against the daemon.  Building one page payload probed the engine
#: two or three times (health checks 2, autostart 2, network 3), all within
#: milliseconds of each other and all necessarily agreeing.
#:
#: The TTL is short on purpose: this value decides whether the UI says Docker is
#: running, so a stale "up" after the engine dies would be misleading.  Five
#: seconds collapses every duplicate inside a request while still reflecting a
#: start or stop within one poll cycle.
_ENGINE_TTL = 5.0
_engine_cache: dict = {"t": 0.0, "v": None}
#: A single lock rather than per-key: there is only one engine, so a second caller
#: arriving mid-probe should wait for that answer instead of launching its own.
_engine_lock = threading.Lock()

#: How many *consecutive* probe timeouts may re-serve the last real observation
#: before the engine is reported down anyway.  A stopped engine fails fast
#: ("Cannot connect to the Docker daemon"), it does not time out; a timeout
#: means the host was too loaded to answer inside the budget, and reporting
#: that as "engine down" flapped every Docker indicator during load storms.
#: The cap keeps a genuinely wedged daemon visible.
_TIMEOUT_TOLERANCE = 3
#: Consecutive timeout count.  Only touched under `_engine_lock`.
_engine_timeouts = 0


def invalidate_engine_state() -> None:
    """Force the next :func:`engine_up` to re-probe.

    For callers that just started or stopped the engine and must not report the
    previous state for the rest of the TTL.
    """
    global _engine_timeouts
    with _engine_lock:
        _engine_cache.update(t=0.0, v=None)
        _engine_timeouts = 0


def _cache_view() -> tuple[bool | None, bool]:
    """The engine memo's ``(value, is-fresh)`` with leftover junk read as unknown.

    ``_engine_cache`` outlives every request, so a leftover planted in either
    slot went out raw: a junk ``t`` (a float-subclass ``__rsub__`` bomb, a
    str) detonated the bare ``time.time() - t < TTL`` freshness probe, and a
    junk ``v`` (a ``__bool__`` bomb) rode out as :func:`engine_up`'s answer
    and blew the caller's own ``if not engine_up()`` — each one a raw 500 on
    GET /api/containers and GET /api/stacks (the tools twins were saved only
    by their ``_safe_flag``).

    ``type(v) is bool``, not isinstance/_isa: bool cannot be subclassed, so
    the exact check is complete, and a bool-liar (``__class__`` answers bool,
    the object is not one) or any other impostor reads as "never probed" —
    junk is not evidence of engine state, so the caller re-probes.  A junk
    ``t`` reads as stale for the same reason.
    """
    v = _engine_cache.get("v")
    if type(v) is not bool:
        v = None
    try:
        # bool() inside the try: a poisoned ``t`` whose reflected subtraction
        # or comparison answers junk must not hand a ``__bool__`` bomb out.
        fresh = bool(time.time() - _engine_cache.get("t") < _ENGINE_TTL)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        fresh = False
    return v, fresh


def _timeouts_int(value) -> int:
    """Exact consecutive-timeout count; junk reads as the tolerance spent.

    The counter is a module global that outlives requests, so a leftover
    int-subclass whose ``__add__`` raises used to detonate the ``+= 1``
    inside the lock the moment one probe timed out — a raw 500 on every
    docker listing route.  The unbound base coercion keeps a real subclass's
    value while defusing its bound-method bombs (the ``+ 1`` then runs on an
    exact int); a lying-``__class__`` impostor TypeErrors and drops.  Junk is
    not evidence that recent probes succeeded, so it reads as the tolerance
    already spent: the timeout reports as engine-down instead of re-serving
    a stale answer through a counter that cannot count.
    """
    if type(value) is int:
        return value
    try:
        if not _isa(value, bool) and _isa(value, int):
            return int.__index__(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    return _TIMEOUT_TOLERANCE


def engine_up(force: bool = False) -> bool:
    if not force:
        cached, fresh = _cache_view()
        if cached is not None and fresh:
            return cached

    global _engine_timeouts
    with _engine_lock:
        # Re-check under the lock: another caller may have finished the same probe
        # while this one waited, which is what makes this single-flight.
        cached, fresh = _cache_view()
        if not force and cached is not None and fresh:
            return cached
        rc, _, err = docker("info", timeout=8)
        if rc == -1 and err == "timeout":
            # No evidence either way: keep the last real observation alive for
            # a bounded number of slow probes instead of flipping to "down".
            _engine_timeouts = _timeouts_int(_engine_timeouts) + 1
            if _engine_timeouts < _TIMEOUT_TOLERANCE and cached is not None:
                _engine_cache.update(t=time.time(), v=cached)
                return cached
        else:
            _engine_timeouts = 0
        up = rc == 0
        _engine_cache.update(t=time.time(), v=up)
        return up


def peek_engine() -> bool | None:
    """Last observed engine state, or None if nothing has probed yet.

    Does not spawn ``docker info``. Host identity in low mode only needs a
    badge; the 5s probe TTL is for callers that must reflect a restart.
    ``_cache_view`` rather than the raw slot: a leftover planted in the memo
    (a ``__bool__`` bomb, a bool-liar) must read as "never probed", not ride
    out to the badge renderers.
    """
    return _cache_view()[0]


def redact_env(env_list: list[str] | None) -> list[str]:
    out = []
    for e in env_list if isinstance(env_list, list) else []:
        if not isinstance(e, str):
            continue
        if "=" in e:
            k, v = e.split("=", 1)
            if SENSITIVE.search(k):
                out.append(f"{k}=***")
            else:
                out.append(e)
        else:
            out.append(e)
    return out
