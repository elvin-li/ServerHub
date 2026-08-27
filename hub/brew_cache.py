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


def _isinstance(value, types) -> bool:
    """isinstance that survives a leftover raising ``__class__`` property.

    When the type check fails, CPython's isinstance consults
    ``value.__class__`` — so a leftover object whose ``__class__`` is a
    raising property used to blow ``_plain_rc`` / ``_services_from_output``
    / ``_json_safe`` and discard the *fresh* snapshot (or the last-good one)
    instead of costing only the poisoned value.  A real subclass never
    reaches the ``__class__`` lookup (the type check answers first), so
    degrading the raise to False only reclassifies impostors — the
    brew_svc._isinstance convention.
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _as_text(value) -> str:
    # Unbound through the base types, like brew_svc._as_text: a leftover
    # bytes-subclass whose bound ``.decode`` raises (or a str-subclass whose
    # ``.encode`` does) used to raise out of _services_from_output and cost
    # the whole fresh snapshot instead of nothing.  Guarded isinstance:
    # a ``__class__`` property bomb used to blow the chain itself.
    if _isinstance(value, bytes):
        text = bytes.decode(value, "utf-8", "replace")
    elif _isinstance(value, bytearray):
        text = bytearray.decode(value, "utf-8", "replace")
    elif _isinstance(value, str):
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
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _json_safe(value, depth: int = 0):
    """Starlette encodes with allow_nan=False; leftover NaN/bytes 500 the list.

    Top-level floats were already coerced.  A nested ``meta`` / extra brew
    field with Inf/bytes still landed in the snapshot, so ``_write_disk``
    silently skipped (allow_nan=False) and any caller that returned the
    row 500'd.  A leftover ``\\ud800`` in ``name`` still 500'd the UTF-8 encode.

    Base-type coercions throughout (unbound ``dict.items`` / ``__iter__``,
    ``int.__index__``, ``float.__float__``, unbound ``str.encode`` /
    ``bytes.decode``): a leftover subclass whose ``items``/``__iter__``/
    ``__eq__``/``__str__``/``encode``/``decode`` bombs used to raise out of
    ``_copy_items`` and wipe every brew row from the whole snapshot instead
    of costing only the poisoned value — the docker_cli/modules ``_jsonable``
    convention.

    Guarded isinstance throughout (see :func:`_isinstance`): a leftover
    value — or a leftover mapping *key* — whose ``__class__`` property
    raises used to blow the probes here and wipe every sibling row.
    """
    if depth > 16:
        return None
    if _isinstance(value, bool) or value is None:
        return value
    if _isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # used to blow the digit-cap probe below (only ValueError
                # was caught).
                value = int.__index__(value)
            except Exception:
                return None
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
    if _isinstance(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinstance(value, str):
        # Unbound base encode: a str-subclass ``.encode`` bomb cannot fire.
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    if _isinstance(value, bytes):
        return bytes.decode(value, "utf-8", "replace")
    if _isinstance(value, bytearray):
        return bytearray.decode(value, "utf-8", "replace")
    if _isinstance(value, dict):
        out = {}
        # Unbound base view: reads the C-level storage, so a dict-subclass
        # row whose ``items``/``keys``/``__iter__``/``get`` raises still
        # yields its real pairs.  Key probes guarded too: one mapping key
        # whose ``__class__`` property raises used to wipe the whole row.
        for k, v in dict.items(value):
            if _isinstance(k, bytes):
                key = bytes.decode(k, "utf-8", "replace")
            elif _isinstance(k, bytearray):
                key = bytearray.decode(k, "utf-8", "replace")
            else:
                try:
                    key = k if _isinstance(k, str) else str(k)
                except RecursionError:
                    try:
                        key = type(k).__name__
                    except Exception:
                        continue
                except Exception:
                    continue
            try:
                key = str.encode(key, "utf-8", "replace").decode("utf-8")
            except Exception:
                continue
            out[key] = _json_safe(v, depth + 1)
        return out
    if _isinstance(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isinstance(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot fire and the real elements still survive.
                return [_json_safe(v, depth + 1) for v in base.__iter__(value)]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # Property bomb / ``__getattr__`` raising non-AttributeError past
        # getattr's default.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/brew/services.
            return _json_safe(iso(), depth + 1)
        except Exception:
            return None
    return None


def _plain_rc(value):
    """Exact-type spawn rc for :func:`_load`'s success gate.

    ``if rc == 0`` used to dispatch into a leftover numeric-subclass
    ``__eq__`` bomb and raise out of ``_load`` — discarding the *fresh*
    snapshot the spawn had just produced and wiping every brew row for the
    caller.  Unbound base-type calls dodge the override; anything
    non-numeric degrades to None (reads as failure), the
    brew_svc/autostart_svc ``_plain_rc`` convention.  Guarded isinstance:
    a leftover rc whose ``__class__`` property raises used to blow the
    first probe here, raise out of ``_load`` and discard the fresh snapshot.
    """
    if _isinstance(value, bool):
        return int(value)
    if _isinstance(value, int):
        try:
            return int.__index__(value)
        except Exception:
            return None
    if _isinstance(value, float):
        try:
            return float.__float__(value)
        except Exception:
            return None
    return None


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole document: one poisoned ``exit_code`` in
    `brew services list --json` output used to make
    :func:`_services_from_output` return None, so :func:`_load` discarded the
    *fresh* snapshot and republished the stale last-good with a new TTL —
    every start/stop stayed invisible while brew kept printing that number.
    The same literal in the on-disk snapshot made :func:`_read_disk_file`
    treat the whole journal as corrupt.  Dropping just the number keeps the
    document, same as the docker_cli / notify_channels hooks, and matches
    the drop ``_json_safe`` applies to an already-int leftover.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _copy_items(items) -> list[dict]:
    if not _isinstance(items, list):
        return []
    cleaned = []
    # Unbound base iteration: a primed list-subclass ``__iter__`` bomb
    # cannot cost the snapshot its real rows.  Guarded element probe: one
    # ``__class__``-bomb element used to blow the filter and cost them all.
    for x in list.__iter__(items):
        if not _isinstance(x, dict):
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
        parsed = safe_json_loads(
            read_text_capped(_DISK, _DISK_CAP), parse_int=_capped_json_int,
        )
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
    Guarded probes: a stdout — or one element — whose ``__class__`` property
    raises used to raise out of ``_load`` and cost the whole fresh snapshot.
    """
    if _isinstance(out, list):
        parsed = out
    else:
        text = _as_text(out).strip()
        if not text:
            return None
        try:
            parsed = safe_json_loads(text, parse_int=_capped_json_int)
        except (ValueError, RecursionError):
            return None
    if not _isinstance(parsed, list):
        return None
    # Unbound base iteration, like _copy_items: a stub that returned a
    # list-*subclass* whose ``__iter__`` raises used to raise out of _load
    # and cost the whole fresh snapshot instead of nothing.
    return [x for x in list.__iter__(parsed) if _isinstance(x, dict)]


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
                if _isinstance(captured, (bytes, bytearray)):
                    try:
                        # bytes() dispatches a subclass ``__bytes__`` bomb —
                        # RuntimeError from one escaped the except tuple
                        # below and raised out of _load via _brew_busy.
                        text = bytes(memoryview(captured))[:_PGREP_CAP]
                    except Exception:
                        text = b""
                elif _isinstance(captured, str):
                    # Unbound base encode: a str-subclass ``.encode`` bomb
                    # cannot fire.
                    text = str.encode(captured, "utf-8", "replace")[:_PGREP_CAP]
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
    try:
        rc, out, _ = sh(
            [BREW, "services", "list", "--json"], timeout=20, env=_brew_env(),
        )
    except (TypeError, ValueError):
        # A malformed spawn result (wrong-arity/non-iterable stub tuple)
        # used to raise out of the unpack and wipe the last-good snapshot;
        # it must degrade to the keep-last-good tail like any other failure.
        rc, out = None, None
    if _plain_rc(rc) == 0:
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
