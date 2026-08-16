"""OrbStack Docker-compatible CLI helpers."""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from hub.paths import DOCKER
from hub.util import sh

SENSITIVE = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|KEY|PASS|CREDENTIAL)", re.I)


def docker(*args, timeout=30) -> tuple[int, str, str]:
    return sh([DOCKER, *args], timeout=timeout)


def docker_json(args: list[str], timeout=30) -> Any:
    rc, out, err = docker(*args, timeout=timeout)
    if rc != 0:
        return None, rc, err or out
    if not out.strip():
        return [] if "--format" in " ".join(args) else None, 0, ""
    try:
        # docker --format '{{json .}}' produces NDJSON
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if len(lines) > 1 or (lines and lines[0].startswith("{") and "\n" not in out.strip()):
            # multi-line NDJSON or single object
            if all(ln.lstrip().startswith("{") or ln.lstrip().startswith("[") for ln in lines):
                objs = []
                for ln in lines:
                    objs.append(json.loads(ln))
                # if single array line
                if len(objs) == 1 and isinstance(objs[0], list):
                    return objs[0], 0, ""
                return objs, 0, ""
        return json.loads(out), 0, ""
    except json.JSONDecodeError:
        return out, 0, ""


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


def engine_up(force: bool = False) -> bool:
    if not force:
        cached = _engine_cache["v"]
        if cached is not None and time.time() - _engine_cache["t"] < _ENGINE_TTL:
            return cached

    global _engine_timeouts
    with _engine_lock:
        # Re-check under the lock: another caller may have finished the same probe
        # while this one waited, which is what makes this single-flight.
        cached = _engine_cache["v"]
        if not force and cached is not None and time.time() - _engine_cache["t"] < _ENGINE_TTL:
            return cached
        rc, _, err = docker("info", timeout=8)
        if rc == -1 and err == "timeout":
            # No evidence either way: keep the last real observation alive for
            # a bounded number of slow probes instead of flipping to "down".
            _engine_timeouts += 1
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
    """
    return _engine_cache["v"]


def redact_env(env_list: list[str] | None) -> list[str]:
    out = []
    for e in env_list or []:
        if "=" in e:
            k, v = e.split("=", 1)
            if SENSITIVE.search(k):
                out.append(f"{k}=***")
            else:
                out.append(e)
        else:
            out.append(e)
    return out
