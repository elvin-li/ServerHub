"""Single source for `brew services list --json`.

That command costs ~1.25s.  Four modules needed it (brew_svc, autostart_svc,
health_svc, native_catalog) and each shelled out on its own, so one
`/api/apps/managed` request paid for it eight times — 10 of the endpoint's 12
seconds.  This caches the parsed result behind a short TTL and collapses
concurrent callers into a single invocation.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from typing import Any

from hub.paths import BREW, DATA_DIR
from hub.util import sh

#: Service state changes only on user action, and every caller in a single
#: request wants the same snapshot.
#:
#: Deliberately longer than the caches that consume it. At 6s this expired before
#: `apps_manage_svc._INV_TTL` (then 8s) did, so every inventory rebuild re-ran
#: `brew services list --json` -- measured at 0.7-1.2s, which was a quarter of the
#: whole Apps page payload. A dependency cache with a shorter lifetime than its
#: consumer guarantees a miss on every consumer refresh, which is the opposite of
#: what a cache is for.
#:
#: Raising it costs nothing in truthfulness because every path that changes service
#: state calls invalidate_brew_services(): brew_svc.service_action, autostart_svc,
#: and the native install/uninstall flows. The only staleness left is a start or
#: stop performed outside the panel, which is bounded by this window.
_TTL = 30.0

_cache: dict[str, Any] = {"t": 0.0, "v": None}
_lock = threading.Lock()
#: Serialises the refresh so N concurrent cold callers run one subprocess.
_refresh_lock = threading.Lock()
#: After invalidate(), disk must not answer until a fresh `_load` rewrites it.
_disk_ok = True
_bg_lock = threading.Lock()
_bg_running = False
_DISK = DATA_DIR / "brew-services.cache.json"


def invalidate_brew_services() -> None:
    """Drop the snapshot after a start/stop so the next read is truthful."""
    global _disk_ok
    with _lock:
        _cache["t"] = 0.0
        _cache["v"] = None
        _disk_ok = False


def _fresh() -> list[dict] | None:
    with _lock:
        if _cache["v"] is not None and time.time() - _cache["t"] < _TTL:
            # Copy: callers annotate the dicts they get back.
            return [dict(x) for x in _cache["v"]]
    return None


def _stale_memory() -> list[dict] | None:
    with _lock:
        if _cache["v"] is None:
            return None
        return [dict(x) for x in _cache["v"]]


def _read_disk() -> list[dict] | None:
    if not _disk_ok:
        return None
    try:
        parsed = json.loads(_DISK.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(parsed, list):
        return None
    return [x for x in parsed if isinstance(x, dict)]


def _write_disk(items: list[dict]) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _DISK.write_text(json.dumps(items, separators=(",", ":")))
    except OSError:
        pass


def _brew_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    return env


def _keep_last_good() -> list[dict] | None:
    """Last parsed snapshot, preferring memory then the on-disk copy.

    An empty list is not "last good": that is what a timed-out `_load`
    used to write, and serving it made every brew row disappear for the
    whole TTL.
    """
    stale = _stale_memory()
    if stale:
        return stale
    disk = _read_disk()
    if disk:
        return disk
    return None


def _publish(items: list[dict], *, write_disk: bool) -> list[dict]:
    global _disk_ok
    with _lock:
        _cache.update(t=time.time(), v=items)
        _disk_ok = True
    if write_disk:
        _write_disk(items)
    return [dict(x) for x in items]


def _brew_busy() -> bool:
    """True when another Homebrew process already holds the lock.

    `brew outdated` and `brew services list --json` then sit on flock
    until they hit our timeout, which is how the err log filled up.
    Match the brew binary path so a Python file named brew_cache.py
    does not count as busy.
    """
    try:
        proc = subprocess.run(
            ["/usr/bin/pgrep", "-f", BREW],
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def _load() -> list[dict]:
    if _brew_busy():
        kept = _keep_last_good()
        if kept is not None:
            return _publish(kept, write_disk=False)
        return _publish([], write_disk=False)
    rc, out, _ = sh(
        [BREW, "services", "list", "--json"], timeout=20, env=_brew_env(),
    )
    if rc == 0 and out.strip():
        try:
            parsed = json.loads(out)
            if isinstance(parsed, list):
                items = [x for x in parsed if isinstance(x, dict)]
                return _publish(items, write_disk=True)
        except ValueError:
            pass
    # Timeout, brew crash, or unparseable JSON: keep the last good
    # snapshot and refresh its TTL so stale-while-revalidate does not
    # immediately re-enter `_load` and reprint the same timeout.
    kept = _keep_last_good()
    if kept is not None:
        return _publish(kept, write_disk=True)
    return _publish([], write_disk=False)


def _kick_refresh() -> None:
    """One background reload; overlapping callers share it."""
    global _bg_running
    with _bg_lock:
        if _bg_running:
            return
        _bg_running = True

    def run() -> None:
        global _bg_running
        try:
            with _refresh_lock:
                if _fresh() is None:
                    _load()
        except Exception:
            pass
        finally:
            with _bg_lock:
                _bg_running = False

    threading.Thread(target=run, daemon=True, name="brew-services-swr").start()


def brew_services(force: bool = False) -> list[dict]:
    """Parsed `brew services list --json`, cached for a few seconds.

    A TTL miss with a previous snapshot (or a disk copy from the last process)
    returns immediately and refreshes in the background.  `brew services list
    --json` measured 1.2s on this host; the Apps page used to wait that out on
    every cold inventory.  invalidate_brew_services() still forces a reload so
    a panel start/stop cannot flash the pre-action state.
    """
    if not force:
        hit = _fresh()
        if hit is not None:
            return hit
        stale = _stale_memory()
        if stale is not None:
            _kick_refresh()
            return stale
        disk = _read_disk()
        if disk is not None:
            with _lock:
                _cache.update(t=0.0, v=disk)
            _kick_refresh()
            return [dict(x) for x in disk]

    with _refresh_lock:
        # A concurrent caller may have refreshed while this one waited; reuse
        # that result rather than paying for a second subprocess.
        if not force:
            hit = _fresh()
            if hit is not None:
                return hit
        return _load()


#: Callers (brew_svc, autostart_svc, health_svc) import this name.  Keep both
#: spellings exported so neither side of the rename can break the panel: a
#: missing symbol here is an ImportError at module load, which takes down every
#: route, not just the one that wanted brew state.
brew_services_list = brew_services
