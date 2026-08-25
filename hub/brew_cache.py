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
import re
import subprocess
import tempfile
import threading
import time
from typing import Any

from hub.paths import BREW, DATA_DIR
from hub.secure_io import replace_bytes
from hub.util import read_text_capped, safe_json_loads, sh, utf8_env

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
#: After invalidate(), disk must not answer a *hit* until a fresh `_load`
#: rewrites it.  Failure paths may still read the file as last-good.
_disk_ok = True
#: Bumped on every invalidate so an in-flight `_load` cannot republish the
#: pre-action snapshot on top of a start/stop that finished while it ran.
_generation = 0
_bg_lock = threading.Lock()
_bg_running = False
_DISK = DATA_DIR / "brew-services.cache.json"
#: Leftover multi-MB cache used to OOM GET /api/brew/services.
_DISK_CAP = 256 * 1024


def _as_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, str):
        text = value
    elif value is None:
        return ""
    else:
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


def _json_safe(value, depth: int = 0):
    """Starlette encodes with allow_nan=False; leftover NaN/bytes 500 the list.

    Top-level floats were already coerced.  A nested ``meta`` / extra brew
    field with Inf/bytes still landed in the snapshot, so ``_write_disk``
    silently skipped (allow_nan=False) and any caller that returned the
    row 500'd.  A leftover ``\\ud800`` in ``name`` still 500'd the UTF-8 encode.
    """
    if depth > 16:
        return None
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # YAML hex/octal leftovers dodge CPython's str->int digit cap, so
            # an over-cap int in a snapshot row survived every parse and then
            # ValueError'd both `_write_disk` (silently skipped) and every
            # caller that returned the row — same drop as its inf float
            # sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, (bytes, bytearray)):
                key = k.decode("utf-8", "replace")
            else:
                try:
                    key = k if isinstance(k, str) else str(k)
                except RecursionError:
                    try:
                        key = type(k).__name__
                    except Exception:
                        continue
                except Exception:
                    continue
            try:
                key = key.encode("utf-8", "replace").decode("utf-8")
            except Exception:
                continue
            out[key] = _json_safe(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/brew/services.
            return _json_safe(iso(), depth + 1)
        except Exception:
            return None
    return None


def _copy_items(items) -> list[dict]:
    if not isinstance(items, list):
        return []
    cleaned = []
    for x in items:
        if not isinstance(x, dict):
            continue
        row = _json_safe(x)
        if isinstance(row, dict):
            cleaned.append(row)
    return cleaned


def invalidate_brew_services() -> None:
    """Drop the snapshot after a start/stop so the next read is truthful."""
    global _disk_ok, _generation
    with _lock:
        _generation += 1
        _cache["t"] = 0.0
        _cache["v"] = None
        _disk_ok = False


def _fresh() -> list[dict] | None:
    with _lock:
        raw = _cache["v"]
        if raw is not None and time.time() - _cache["t"] < _TTL:
            # Copy: callers annotate the dicts they get back.
            return _copy_items(raw)
    return None


def _stale_memory() -> list[dict] | None:
    with _lock:
        raw = _cache["v"]
        if raw is None:
            return None
        return _copy_items(raw)


def _read_disk_file() -> list[dict] | None:
    """On-disk snapshot, ignoring the post-invalidate gate.

    A failed `_load` after invalidate used to have no last-good (memory was
    cleared and `_read_disk` honoured `_disk_ok=False`) and then published
    `[]` as a fresh hit — every brew row vanished for the whole TTL.
    """
    try:
        parsed = safe_json_loads(read_text_capped(_DISK, _DISK_CAP))
    except (OSError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested cache is not ValueError.
        return None
    if not isinstance(parsed, list):
        return None
    items = [x for x in parsed if isinstance(x, dict)]
    return items or None


def _read_disk() -> list[dict] | None:
    if not _disk_ok:
        return None
    items = _read_disk_file()
    return _copy_items(items) if items else None


def _write_disk(items: list[dict]) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        # Atomic: a crash mid-write used to leave a half JSON that _read_disk
        # treated as "no cache", forcing every brew page to wait on a live list.
        replace_bytes(_DISK, json.dumps(
            items, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8"))
    except (OSError, TypeError, ValueError, RecursionError):
        # RecursionError: leftover circular brew cache after parse is not
        # ValueError; GET /api/brew/services used to 500 the disk write.
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

    Disk is consulted even after invalidate(): a miss on the live command
    must not look like "zero services".  Happy-path SWR still uses
    `_read_disk()`, which honours `_disk_ok`.
    """
    stale = _stale_memory()
    if stale:
        return stale
    return _read_disk_file()


def _publish(items: list[dict], *, write_disk: bool, gen: int | None = None) -> list[dict]:
    global _disk_ok
    items = _copy_items(items)
    with _lock:
        if gen is not None and gen != _generation:
            # A start/stop invalidated while this load ran; publishing would
            # put the pre-action snapshot back and give it a fresh TTL.
            return items
        _cache.update(t=time.time(), v=items)
        _disk_ok = True
    if write_disk:
        _write_disk(items)
    return [dict(x) for x in items]


def _services_from_output(out) -> list[dict] | None:
    """Parsed brew-services JSON, or None when this is not a successful list.

    Distinguishes a real empty install (`[]`) from garbage/timeouts (None).
    A stub that already returned a list used to AttributeError on ``.strip``.
    """
    if isinstance(out, list):
        parsed = out
    else:
        text = _as_text(out).strip()
        if not text:
            return None
        try:
            parsed = safe_json_loads(text)
        except (ValueError, RecursionError):
            return None
    if not isinstance(parsed, list):
        return None
    return [x for x in parsed if isinstance(x, dict)]


def _brew_argv_patterns() -> tuple[str, str]:
    """pgrep -f regexes that match a live brew, not a mention of its path.

    Homebrew's wrapper execs ruby ``Library/Homebrew/brew.rb``, so a
    substring match on ``BREW`` both misses the lock holder and matches
    ``vim /opt/homebrew/bin/brew`` / ``cat …/brew``.
    """
    brew = re.escape(str(BREW))
    return (
        rf"^{brew}($| )",
        r"(^|/)ruby[0-9.]* .*Library/Homebrew/brew\.rb($| )",
    )


#: pgrep prints PIDs; a wedged child must not RSS-bomb the request thread.
_PGREP_CAP = 4096


def _brew_busy() -> bool:
    """True when another Homebrew process already holds the lock.

    `brew outdated` and `brew services list --json` then sit on flock
    until they hit our timeout, which is how the err log filled up.
    """
    for pattern in _brew_argv_patterns():
        try:
            with tempfile.TemporaryFile() as out:
                proc = subprocess.run(
                    ["/usr/bin/pgrep", "-f", pattern],
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    check=False,
                    env=utf8_env(),
                )
                captured = getattr(proc, "stdout", None)
                if isinstance(captured, (bytes, bytearray)):
                    text = bytes(captured)[:_PGREP_CAP]
                elif isinstance(captured, str):
                    text = captured.encode("utf-8", "replace")[:_PGREP_CAP]
                else:
                    # Live path: stdout is the TemporaryFile, not a buffer
                    # on the CompletedProcess.  Treating the file object as
                    # empty made every real pgrep look idle.
                    try:
                        out.seek(0)
                        text = out.read(_PGREP_CAP)
                    except OSError:
                        text = b""
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
            # Leftover ``\\ud800`` pattern UnicodeEncodeError is ValueError, not OSError.
            continue
        if proc.returncode == 0 and bool(text.strip()):
            return True
    return False


def _load() -> list[dict]:
    with _lock:
        gen = _generation
    if _brew_busy():
        kept = _keep_last_good()
        if kept is not None:
            return _publish(kept, write_disk=False, gen=gen)
        # Do not cache emptiness: that made every brew row vanish for `_TTL`
        # after invalidate + a still-held Homebrew lock.
        return []
    rc, out, _ = sh(
        [BREW, "services", "list", "--json"], timeout=20, env=_brew_env(),
    )
    if rc == 0:
        items = _services_from_output(out)
        if items is not None:
            return _publish(items, write_disk=True, gen=gen)
    # Timeout, brew crash, or unparseable JSON: keep the last good
    # snapshot and refresh its TTL so stale-while-revalidate does not
    # immediately re-enter `_load` and reprint the same timeout.
    kept = _keep_last_good()
    if kept is not None:
        return _publish(kept, write_disk=True, gen=gen)
    return []


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

    try:
        threading.Thread(target=run, daemon=True, name="brew-services-swr").start()
    except RuntimeError:
        with _bg_lock:
            _bg_running = False


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
