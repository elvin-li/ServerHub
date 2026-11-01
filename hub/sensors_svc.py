"""Rich host sensors — Glances / Unraid Dashboard style (macOS)."""
from __future__ import annotations

import ctypes
import os
import plistlib
import re
import shutil
import threading
import time
from pathlib import Path

from hub import gpu_native
from hub.proc_cache import ps_lines
from hub.util import LazyPool, sh, strftime_now

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    planted in the sensors / top caches detonated ``_jsonable``'s rank
    gates one step ahead of every scrub and 500'd GET /api/system/sensors
    (the docker_cli / nas8 rule).  A real subclass still matches through
    the C-level type check; only a value that cannot answer what it is
    takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
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


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The health11 rule on the sensors surface: even a plain-dict lookup runs
    the *stored keys'* own ``__eq__`` during the hash probe, so a leftover
    str-subclass key whose hash shadows ``v`` / ``t`` planted in the module
    caches used to detonate the bare ``_cache["v"]`` / ``_cache["t"]``
    subscripts in ``peek_sensors`` / ``collect_sensors`` — a raw 500 on
    GET /api/system/sensors before any scrub ran.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _cache_age(now, stamp) -> float:
    """Age of a cache stamp; an unreadable leftover stamp reads as expired.

    The host_address._cached_detection rule: a clock bomb planted in a
    ``t`` slot (``__float__`` / ``__rsub__`` / comparison raising) used to
    detonate the bare ``time.time() - _cache["t"]`` arithmetic and 500
    GET /api/system/sensors.  Junk reads as infinitely old and re-collects.
    """
    try:
        return now - float(stamp)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return float("inf")


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; a bomb reads as failure.

    The health9 rule: this module does not own ``sh`` (tests and tooling
    patch it), and an rc-subclass whose ``__eq__`` / ``__ne__`` raises used
    to detonate the bare probes in the collector legs.  ``-255`` is no
    honest exit status, so a bomb keeps the failure branch.
    """
    try:
        if type(rc) is bool:
            return int(rc)
        if _isa(rc, int):
            return int.__index__(rc)
        return int(rc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _sh_run(cmd, timeout) -> tuple:
    """Spawn with the unpack inside the guard (the nginx `_sh_triple` rule).

    A real ``sh`` never raises and always answers ``(rc, out, err)``, but a
    patched or odd one — raising outright, or answering a 2-tuple, a
    scalar, a tuple subclass whose ``__iter__`` raises, or a
    lying-``__class__`` tuple impostor — used to detonate the bare
    ``rc, out, _ = sh(…)`` unpacks: through ``_memory_base`` it was a raw
    500 on the light GET /api/system/sensors tick, and through the pooled
    legs a silent leg wipe.  Junk degrades to ``(-255, "", "")`` — nonzero,
    never a success rc.
    """
    try:
        value = sh(cmd, timeout=timeout)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return (-255, "", "")
    if type(value) is tuple:
        items = value
    elif _isa(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    elif _isa(value, list):
        try:
            items = tuple(list.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    else:
        return (-255, "", "")
    if len(items) != 3:
        return (-255, "", "")
    return items


def _as_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if value is None:
        return ""
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


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    return _as_text(value)


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Inf CPU / huge RSS were already dropped at parse; leftover ``\\ud800``
    in a process name, leftover bytes, or a leftover inf planted in the
    peek cache still 500'd GET /api/system/sensors?light=1.

    A >4300-digit int (planted in the peek cache, or the sum of per-iface
    byte counters that each parse under the cap) still passed through
    untouched: CPython's int->str digit limit then ValueError'd
    ``json.dumps`` itself.

    A leftover dict-*subclass* planted in the peek cache whose ``.items()``
    raised (usage5's row-bomb class, one level below the shape bombs) used
    to raise straight out of this sanitizer and 500 GET /api/system/sensors;
    same for a list subclass whose ``__iter__`` raised, and for an object
    whose ``isoformat`` attribute *access* raised (property bomb /
    ``__getattr__`` raising non-AttributeError past getattr's default).

    The remaining bound probes still blew on the modules5 subclass-bomb
    classes: an int subclass whose ``__str__`` raises (only ValueError was
    caught around the digit-cap probe), a float subclass whose
    ``__eq__``/``__ne__`` raises (the NaN probe and the inf tuple-membership
    probe both call it), and a bytes/bytearray subclass whose ``decode``
    raises — as a value and as a mapping key — each 500'd
    GET /api/system/sensors on the cache-hit path and the light peek.
    Hence the unbound base-type calls below, the modules5 convention.
    """
    if depth > 32:
        return None
    # _isa on every rank gate: a leftover whose ``__class__`` is a raising
    # property used to detonate the *first* isinstance below — as a value,
    # a mapping key or the whole planted cache — and 500
    # GET /api/system/sensors on the cache hit, the light peek and the
    # cold collect's final sweep.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` cannot be subclassed, so anything passing this gate that
        # is not the exact type is a *lying* ``__class__`` impostor.  It
        # used to be returned verbatim — every other liar drops at its
        # unbound base call, but the bool gate had nothing to call — and
        # the C-level JSON encoder then refused it: a raw 500 on cache-hit
        # GET /api/system/sensors and the light peek.
        return value if type(value) is bool else None
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
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
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
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
            # The try is for a lying ``__class__`` (claims bytes, is not):
            # the unbound decode TypeErrors and the impostor drops.
            return _decode_bytes(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isa(value, dict):
        out = {}
        # Unbound base view: a dict subclass whose ``items()`` raises or
        # yields non-pairs cannot 500 and the real entries still survive.
        # The try is for a lying-``__class__`` dict impostor, which
        # TypeErrors the unbound view itself.
        try:
            entries = dict.items(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        for k, v in entries:
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
        for base in (list, tuple, set, frozenset):
            if _isa(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot drop the real elements.  The try is for a
                # lying-``__class__`` impostor, which TypeErrors here.
                try:
                    items = base.__iter__(value)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    return None
                return [_jsonable(v, depth + 1) for v in items]
        return None
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
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/system/sensors.
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


def _sysctl_int(value) -> int | None:
    """int from a sysctl `-n` payload that may be str, bytes, or already int."""
    if type(value) is bool or value is None:
        return None
    if _isa(value, int):
        if type(value) is not int:
            # Base coercion before the ``>= 0`` probe: a leftover int
            # subclass whose comparison methods raise (the modules5 bomb
            # class) used to escape this helper's callers.
            try:
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        return value if value >= 0 else None
    text = _as_text(value).strip()
    if not text.isdigit():
        return None
    try:
        return int(text)
    except ValueError:
        # ``isdigit()`` does not bound length: a >4300-digit thermal level is
        # ValueError (CPython's str->int cap) and used to drop the whole
        # thermal leg from GET /api/system/sensors through _thermal's pool.
        return None


def _finite_float(value) -> float | None:
    """float from a sensor token, or None for inf/NaN/overflow.

    Exception, not the three usual conversion errors: ``float()`` of a
    leftover float-subclass dispatches into its own ``__float__``, whose
    modules5 bomb used to raise out of every parser leg that funnels here.
    """
    try:
        n = float(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if n != n or n in (float("inf"), float("-inf")):
        return None
    return n


def _safe_div(num, den) -> float | None:
    """num/den as a finite float. Huge ints used to OverflowError the dashboard."""
    try:
        return _finite_float(num / den)
    except (TypeError, ZeroDivisionError, OverflowError):
        return None


def _bytes_to_gb(n, digits: int = 1) -> float | None:
    ratio = _safe_div(n, 2**30)
    return None if ratio is None else round(ratio, digits)

# ── Mach host CPU ticks — accurate, non-blocking CPU% via cumulative deltas ──
# host_statistics(HOST_CPU_LOAD_INFO) returns lifetime ticks in
# [user, system, idle, nice]. Diffing two reads gives true busy% over the
# interval — matching Activity Monitor without top's 1s sampling block.
_HOST_CPU_LOAD_INFO = 3
_CPU_STATE_MAX = 4


class _HostCpuLoadInfo(ctypes.Structure):
    _fields_ = [("ticks", ctypes.c_uint * _CPU_STATE_MAX)]


try:
    _libc = ctypes.CDLL("/usr/lib/libSystem.dylib")
    _libc.mach_host_self.restype = ctypes.c_uint
except _CONTROL_FLOW:
    raise
except BaseException:  # pragma: no cover — non-macOS / sandbox
    _libc = None

_cpu_ticks_prev: list[int] | None = None
_cpu_ticks_lock = threading.Lock()


def _read_cpu_ticks() -> list[int] | None:
    if _libc is None:
        return None
    try:
        host = _libc.mach_host_self()
        info = _HostCpuLoadInfo()
        count = ctypes.c_uint(_CPU_STATE_MAX)
        rc = _libc.host_statistics(
            host, _HOST_CPU_LOAD_INFO, ctypes.byref(info), ctypes.byref(count)
        )
        if rc != 0:
            return None
        return list(info.ticks)  # [user, system, idle, nice]
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _cpu_from_ticks() -> dict | None:
    """Busy%/user/sys/idle from the delta since the previous read.

    First call seeds the baseline with a tiny 0.15s sample (once per process);
    every later call is an instant diff against the prior collection.
    """
    global _cpu_ticks_prev
    with _cpu_ticks_lock:
        cur = _read_cpu_ticks()
        if cur is None:
            return None
        prev = _cpu_ticks_prev
        if prev is None:
            # One-time bootstrap so the very first sample is meaningful.
            time.sleep(0.15)
            nxt = _read_cpu_ticks()
            if nxt is None:
                _cpu_ticks_prev = cur
                return None
            prev, cur = cur, nxt
        # c_uint wrap or a short noisy window can make a field go backwards;
        # re-seed instead of publishing used_pct > 100 (measured 149% once).
        if any(c < p for c, p in zip(cur, prev)):
            _cpu_ticks_prev = cur
            return None
        _cpu_ticks_prev = cur
    du = cur[0] - prev[0]
    ds = cur[1] - prev[1]
    di = cur[2] - prev[2]
    dn = cur[3] - prev[3]
    busy = du + ds + dn
    total = busy + di
    if total <= 0:
        return None
    used = round(busy / total * 100, 1)
    if used > 100.0:
        return None
    return {
        "user": round((du + dn) / total * 100, 1),
        "sys": round(ds / total * 100, 1),
        "idle": round(di / total * 100, 1),
        "used_pct": used,
    }


_cache = {"t": 0.0, "v": None}
# Above the Dashboard's 20s light poll: a shorter TTL expired every tick and
# re-ran top (measured 1.6s here).  30s lets two UI polls share one sample.
_TTL = 30.0
_TTL_HIGH = 15.0
#: `top -l 1` is the expensive half of a sensors collect.  PhysMem breakdown
#: changes slowly; reuse it across a couple of UI polls.
_TOP_TTL = 60.0
_TOP_TTL_HIGH = 20.0


def _sensors_ttl() -> float:
    from hub.resource_mode import is_high
    return _TTL_HIGH if is_high() else _TTL


def _top_ttl() -> float:
    from hub.resource_mode import is_high
    return _TOP_TTL_HIGH if is_high() else _TOP_TTL
_top_cache = {"t": 0.0, "v": None}
_refresh_lock = threading.Lock()
_net_prev = {"t": 0.0, "rx": 0, "tx": 0}
# hw.ncpu / memsize / pagesize almost never change at runtime
_static = {"t": 0.0, "ncpu": None, "mem_gb": None, "page_size": 16384}
_STATIC_TTL = 300.0
_pool = LazyPool(9, "hub-sensors")


def shutdown_executor() -> None:
    _pool.shutdown()


def _parse_size_to_gb(token: str) -> float | None:
    """Parse 30G / 2548M / 975M / 1.2T into GB."""
    token = _as_text(token).strip().replace(",", "")
    m = re.match(r"^([\d.]+)\s*([KMGTP]?)B?$", token, re.I)
    if not m:
        return None
    n = _finite_float(m.group(1))
    if n is None:
        return None
    u = (m.group(2) or "G").upper()
    mul = {"": 1 / 1024**3, "K": 1 / 1024**2, "M": 1 / 1024, "G": 1, "T": 1024, "P": 1024**2}
    out = n * mul.get(u, 1)
    if out != out or out in (float("inf"), float("-inf")):
        return None
    return round(out, 2)


def _cpu_and_mem_from_top_cached() -> dict:
    now = time.time()
    # _mapping_get / _cache_age: a hash-shadowing ``v``/``t`` key or a
    # clock bomb planted in the top cache used to detonate these bare
    # reads and silently wipe the top leg (PhysMem, load, process counts).
    hit = _mapping_get(_top_cache, "v")
    if hit is not None and _cache_age(now, _mapping_get(_top_cache, "t")) < _top_ttl():
        # Plain-dict the hit: a leftover dict-subclass planted in the top
        # cache used to pass ``or {}`` truthiness / ``.get()`` bombs straight
        # into _collect_sensors_uncached and 500 GET /api/system/sensors;
        # a leftover non-dict fell through to AttributeError the same way.
        # A poisoned hit re-collects instead.  _isa, not bare isinstance: a
        # ``__class__``-property bomb planted as the whole hit used to
        # detonate the gate itself and silently wipe the top leg (PhysMem,
        # load, process counts) for a full TTL.
        if type(hit) is dict:
            return hit
        if _isa(hit, dict):
            try:
                return dict(hit)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                pass
    value = _cpu_and_mem_from_top() or {}
    if not _isa(value, dict):
        value = {}
    try:
        _top_cache.update(t=now, v=value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A shadow key raises out of the insert compare; clear() never
        # compares keys, so evicting the poison and rewriting always lands.
        try:
            _top_cache.clear()
            _top_cache.update(t=now, v=value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    return value


def _cpu_and_mem_from_top() -> dict:
    """Single fast top sample for PhysMem + load snapshots (point-in-time).

    CPU% is NOT taken from here — top's single-frame CPU line over-reports on
    macOS. Accurate CPU busy% comes from _cpu_from_ticks() (Mach deltas). The
    CPU line is still parsed as a last-resort fallback only.
    """
    rc, out, _ = _sh_run(["/usr/bin/top", "-l", "1", "-n", "0", "-s", "0"], timeout=10)
    if _rc_int(rc) != 0:
        return {}
    data: dict = {}
    for line in _as_text(out).splitlines():
        if "CPU usage" in line:
            for part in line.split(":")[-1].split(","):
                part = part.strip()
                if "% user" in part:
                    n = _finite_float(part.replace("% user", "").strip())
                    if n is not None:
                        data["user"] = n
                elif "% sys" in part:
                    n = _finite_float(part.replace("% sys", "").strip())
                    if n is not None:
                        data["sys"] = n
                elif "% idle" in part:
                    n = _finite_float(part.replace("% idle", "").strip())
                    if n is not None:
                        data["idle"] = n
        if line.startswith("Load Avg:"):
            nums = line.split(":")[-1].replace(" ", "").split(",")
            n1 = _finite_float(nums[0]) if nums else None
            n5 = _finite_float(nums[1]) if len(nums) > 1 else None
            n15 = _finite_float(nums[2]) if len(nums) > 2 else None
            if n1 is not None:
                data["load1"] = n1
            if n5 is not None:
                data["load5"] = n5
            if n15 is not None:
                data["load15"] = n15
        if line.startswith("PhysMem:"):
            raw = line.split(":", 1)[1].strip()
            data["physmem_raw"] = raw
            # 30G used (2548M wired, 1309M compressor), 975M unused.
            m_used = re.search(r"([\d.]+[KMGTP]?)\s+used", raw, re.I)
            m_unused = re.search(r"([\d.]+[KMGTP]?)\s+unused", raw, re.I)
            m_wired = re.search(r"([\d.]+[KMGTP]?)\s+wired", raw, re.I)
            m_comp = re.search(r"([\d.]+[KMGTP]?)\s+compressor", raw, re.I)
            if m_used:
                data["mem_used_gb"] = _parse_size_to_gb(m_used.group(1))
            if m_unused:
                data["mem_unused_gb"] = _parse_size_to_gb(m_unused.group(1))
            if m_wired:
                data["mem_wired_gb"] = _parse_size_to_gb(m_wired.group(1))
            if m_comp:
                data["mem_compressor_gb"] = _parse_size_to_gb(m_comp.group(1))
        if line.startswith("Networks:"):
            # Networks: packets: 123/456 in, 78/90 out.
            data["networks_raw"] = line.split(":", 1)[1].strip()
        if line.startswith("Disks:"):
            data["disks_raw"] = line.split(":", 1)[1].strip()
        if "processes:" in line.lower() and "total" in line.lower():
            # Processes: 512 total, 8 running, 504 sleeping...
            data["processes_raw"] = line.strip()
            # _sysctl_int, not bare int(): a >4300-digit top process count is
            # ValueError (CPython's str->int cap) and used to drop the whole
            # top leg — PhysMem, load, CPU fallback — from GET
            # /api/system/sensors through _collect_sensors_uncached's pool,
            # the same way the guarded pmset thermal level below once did.
            m = re.search(r"(\d+)\s+total", line)
            n = _sysctl_int(m.group(1)) if m else None
            if n is not None:
                data["proc_total"] = n
            m = re.search(r"(\d+)\s+running", line)
            n = _sysctl_int(m.group(1)) if m else None
            if n is not None:
                data["proc_running"] = n
    return data


def _static_hw() -> dict:
    """ncpu / total RAM / page size — stable, cached 5 min."""
    now = time.time()
    # _mapping_get / _cache_age: _memory_base runs on the request thread
    # for the light tick, so a shadow key or clock bomb planted here used
    # to 500 GET /api/system/sensors?light rather than wipe one leg.
    ncpu_hit = _mapping_get(_static, "ncpu")
    if ncpu_hit is not None and _cache_age(now, _mapping_get(_static, "t")) < _STATIC_TTL:
        return {
            "ncpu": ncpu_hit,
            "mem_total_gb": _mapping_get(_static, "mem_gb"),
            "page_size": _mapping_get(_static, "page_size", 16384),
        }
    from hub import macos_sysctl

    ncpu_i = macos_sysctl.sysctl_int("hw.ncpu", timeout=2, sh=sh)
    mem_n = macos_sysctl.sysctl_int("hw.memsize", timeout=2, sh=sh)
    pgsz = macos_sysctl.sysctl_int("hw.pagesize", timeout=2, sh=sh)
    mem_gb = _bytes_to_gb(mem_n) if mem_n is not None else None
    page_n = pgsz
    page_size = page_n if page_n else 16384
    try:
        _static.update(t=now, ncpu=ncpu_i, mem_gb=mem_gb, page_size=page_size)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Same shadow-key insert-compare class as the top cache write.
        try:
            _static.clear()
            _static.update(t=now, ncpu=ncpu_i, mem_gb=mem_gb, page_size=page_size)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    return {"ncpu": ncpu_i, "mem_total_gb": mem_gb, "page_size": page_size}


# ── Activity-Monitor memory breakdown ───────────────────────────────────────
# host_statistics64(HOST_VM_INFO64) is what vm_stat prints; reading it via
# ctypes costs microseconds, so even the light dashboard tick can carry the
# real App / Wired / Compressed / Cached split.  The previous card derived
# "cache" as PhysMem used - wired - compressor, which swallowed all app
# memory (a 5-7 GB local model included) into "cache" and called wired
# memory "used".
_HOST_VM_INFO64 = 4


class _VmStatistics64(ctypes.Structure):
    _fields_ = [
        ("free_count", ctypes.c_uint32),
        ("active_count", ctypes.c_uint32),
        ("inactive_count", ctypes.c_uint32),
        ("wire_count", ctypes.c_uint32),
        ("zero_fill_count", ctypes.c_uint64),
        ("reactivations", ctypes.c_uint64),
        ("pageins", ctypes.c_uint64),
        ("pageouts", ctypes.c_uint64),
        ("faults", ctypes.c_uint64),
        ("cow_faults", ctypes.c_uint64),
        ("lookups", ctypes.c_uint64),
        ("hits", ctypes.c_uint64),
        ("purges", ctypes.c_uint64),
        ("purgeable_count", ctypes.c_uint32),
        ("speculative_count", ctypes.c_uint32),
        ("decompressions", ctypes.c_uint64),
        ("compressions", ctypes.c_uint64),
        ("swapins", ctypes.c_uint64),
        ("swapouts", ctypes.c_uint64),
        ("compressor_page_count", ctypes.c_uint32),
        ("throttled_count", ctypes.c_uint32),
        ("external_page_count", ctypes.c_uint32),
        ("internal_page_count", ctypes.c_uint32),
        ("total_uncompressed_pages_in_compressor", ctypes.c_uint64),
    ]


class _XswUsage(ctypes.Structure):
    _fields_ = [
        ("xsu_total", ctypes.c_uint64),
        ("xsu_avail", ctypes.c_uint64),
        ("xsu_used", ctypes.c_uint64),
        ("xsu_pagesize", ctypes.c_uint32),
        ("xsu_encrypted", ctypes.c_bool),
    ]


class _RusageInfoV2(ctypes.Structure):
    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
        ("ri_child_user_time", ctypes.c_uint64),
        ("ri_child_system_time", ctypes.c_uint64),
        ("ri_child_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_child_interrupt_wkups", ctypes.c_uint64),
        ("ri_child_pageins", ctypes.c_uint64),
        ("ri_child_elapsed_abstime", ctypes.c_uint64),
        ("ri_diskio_bytesread", ctypes.c_uint64),
        ("ri_diskio_byteswritten", ctypes.c_uint64),
    ]


_RUSAGE_INFO_V2 = 2
# Local LLM runtimes whose resident weights deserve their own line on the
# memory card.  Matched against the ps command line (lower-cased).
_LOCAL_MODEL_MARKERS = (
    ("mlx-lm/backend.py", "mlx-lm"),
    ("mlx_lm.server", "mlx-lm"),
    ("mlx_lm ", "mlx-lm"),
    ("ollama runner", "Ollama"),
    ("ollama serve", "Ollama"),
    ("llama-server", "llama.cpp"),
)


def _vm_counts_ctypes() -> dict | None:
    if _libc is None:
        return None
    try:
        stats = _VmStatistics64()
        count = ctypes.c_uint(ctypes.sizeof(stats) // 4)
        host = _libc.mach_host_self()
        kr = _libc.host_statistics64(
            ctypes.c_uint(host), ctypes.c_int(_HOST_VM_INFO64),
            ctypes.byref(stats), ctypes.byref(count),
        )
        if kr != 0:
            return None
        return {
            "free": int(stats.free_count),
            "speculative": int(stats.speculative_count),
            "wired": int(stats.wire_count),
            "purgeable": int(stats.purgeable_count),
            "external": int(stats.external_page_count),
            "internal": int(stats.internal_page_count),
            "compressor": int(stats.compressor_page_count),
        }
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


_VM_STAT_KEYS = {
    "pages free": "free",
    "pages speculative": "speculative",
    "pages wired down": "wired",
    "pages purgeable": "purgeable",
    "file-backed pages": "external",
    "anonymous pages": "internal",
    "pages occupied by compressor": "compressor",
}


def _vm_counts_vm_stat() -> dict | None:
    rc, out, _ = _sh_run(["/usr/bin/vm_stat"], timeout=4)
    if _rc_int(rc) != 0:
        return None
    counts: dict = {}
    for line in _as_text(out).splitlines():
        key, _sep, val = line.partition(":")
        name = _VM_STAT_KEYS.get(key.strip().strip('"').lower())
        if not name:
            continue
        n = _sysctl_int(val.strip().rstrip("."))
        if n is not None:
            counts[name] = n
    return counts if len(counts) == len(_VM_STAT_KEYS) else None


def _swap_used_bytes() -> int | None:
    if _libc is None:
        return None
    try:
        xsw = _XswUsage()
        size = ctypes.c_size_t(ctypes.sizeof(xsw))
        if _libc.sysctlbyname(b"vm.swapusage", ctypes.byref(xsw), ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
            return None
        return int(xsw.xsu_used)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _local_model_memory() -> dict | None:
    """phys_footprint (= Activity Monitor's Memory column) of local LLM runtimes."""
    if _libc is None:
        return None
    try:
        from hub.proc_cache import ps_pid_commands

        rows = ps_pid_commands()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    total = wired = 0
    names: list[str] = []
    pids: list[int] = []
    for pid, cmd in rows:
        low = _as_text(cmd).lower()
        label = next((lab for needle, lab in _LOCAL_MODEL_MARKERS if needle in low), None)
        if not label:
            continue
        try:
            info = _RusageInfoV2()
            if _libc.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(_RUSAGE_INFO_V2), ctypes.byref(info)) != 0:
                continue
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        foot = int(info.ri_phys_footprint)
        if foot < 256 * 2**20:
            # adapters / CLIs, not the process that holds the weights
            continue
        total += foot
        wired += int(info.ri_wired_size)
        pids.append(int(pid))
        if label not in names:
            names.append(label)
    if not pids:
        return None
    return {
        "gb": _bytes_to_gb(total, 2),
        "wired_gb": _bytes_to_gb(wired, 2),
        "name": " + ".join(names),
        "pids": pids,
    }


def _memory_breakdown(total_gb, page_size, *, include_model: bool = True) -> dict:
    """Activity Monitor's split, in GiB (Activity Monitor labels GiB as "GB").

    App memory = anonymous (internal) - purgeable; Wired = wired down;
    Compressed = pages occupied by the compressor; Memory Used = the three;
    Cached Files = file-backed + purgeable (the kernel drops these on
    demand); Available = total - Memory Used.  ``include_model=False`` skips
    the local-model scan (a process-table read) for callers that never show
    it.
    """
    counts = _vm_counts_ctypes()
    source = "host_statistics64"
    if not counts:
        counts = _vm_counts_vm_stat()
        source = "vm_stat"
    if not counts:
        return {}
    pg = page_size or 16384
    gb = lambda pages, d=2: _bytes_to_gb(max(0, pages) * pg, d)  # noqa: E731
    app_p = counts["internal"] - counts["purgeable"]
    used_p = app_p + counts["wired"] + counts["compressor"]
    cached_p = counts["external"] + counts["purgeable"]
    out = {
        "app_gb": gb(app_p),
        "wired_gb": gb(counts["wired"]),
        "compressor_gb": gb(counts["compressor"]),
        "mem_used_gb": gb(used_p),
        "cached_files_gb": gb(cached_p),
        "free_pages_gb": gb(counts["free"]),
        "source": source,
    }
    if total_gb is not None:
        try:
            avail = _finite_float(total_gb - out["mem_used_gb"])
        except (TypeError, OverflowError):
            avail = None
        out["available_gb"] = None if avail is None else round(max(0.0, avail), 1)
        ratio = _safe_div(out["mem_used_gb"], total_gb)
        out["mem_used_pct"] = None if ratio is None else round(min(100.0, ratio * 100), 1)
    swap = _swap_used_bytes()
    out["swap_used_gb"] = None if swap is None else _bytes_to_gb(swap, 2)
    model = _local_model_memory() if include_model else None
    if model:
        out["model"] = model
    return out


def _safe_breakdown(total_gb, page_size, *, include_model: bool = True) -> dict:
    try:
        bd = _memory_breakdown(total_gb, page_size, include_model=include_model)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {}
    return bd if _isa(bd, dict) else {}


_BREAKDOWN_KEYS = (
    "app_gb", "wired_gb", "compressor_gb", "cached_files_gb", "swap_used_gb",
    "mem_used_gb", "mem_used_pct", "free_pages_gb", "model",
)


def _apply_breakdown(memory: dict, bd) -> dict:
    """Overlay the Activity-Monitor split onto a ``memory`` payload.

    ``used_gb`` / ``available_gb`` switch from the memory_pressure guess
    (total x free%%, which counted app memory as free) to Memory Used and
    total - Memory Used.  ``cache_gb`` keeps its name for old clients but
    now means Cached Files.  Pressure fields are left alone.
    """
    if not _isa(bd, dict) or bd.get("mem_used_gb") is None:
        return memory
    for k in _BREAKDOWN_KEYS:
        if bd.get(k) is not None:
            memory[k] = bd[k]
    memory["cache_gb"] = bd.get("cached_files_gb")
    memory["used_gb"] = bd.get("mem_used_gb")
    if bd.get("available_gb") is not None:
        memory["available_gb"] = bd["available_gb"]
        memory["free_gb"] = bd["available_gb"]
    memory["breakdown_source"] = bd.get("source")
    memory["unit"] = "GiB"
    return memory


def _memory_base(*, include_model: bool = True) -> dict:
    try:
        raw_load = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    else:
        load1 = _finite_float(raw_load[0])
        load5 = _finite_float(raw_load[1])
        load15 = _finite_float(raw_load[2])
    # _sh_run, not a bare unpack: an sh answer-shape bomb here used to be a
    # raw 500 on the light GET /api/system/sensors tick — _memory_base is
    # the one collector leg collect_light calls on the request thread.
    rc, out, _ = _sh_run(["/usr/bin/memory_pressure", "-Q"], timeout=4)
    free_pct = None
    pages_free = pages_spec = pages_inactive = pages_wired = None
    for line in _as_text(out).splitlines():
        low = line.lower()
        if "free percentage" in low:
            # ``int(float('inf'))`` OverflowError'd collect_light / the
            # dashboard light poll; skip a matching line that is not finite.
            m = re.search(r"(\d+(?:\.\d+)?)\s*%", line)
            raw = m.group(1) if m else line.split(":")[-1].strip().rstrip("%")
            n = _finite_float(raw)
            if n is not None:
                try:
                    free_pct = int(n)
                except (TypeError, ValueError, OverflowError):
                    pass
        elif "pages free" in low:
            try:
                pages_free = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
        elif "pages speculative" in low:
            try:
                pages_spec = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
        elif "pages inactive" in low:
            try:
                pages_inactive = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
        elif "pages wired down" in low:
            try:
                pages_wired = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
    hw = _static_hw()
    return {
        "load1": None if load1 is None else round(load1, 2),
        "load5": None if load5 is None else round(load5, 2),
        "load15": None if load15 is None else round(load15, 2),
        "mem_free_pct": free_pct,
        "mem_used_pct": (100 - free_pct) if free_pct is not None else None,
        "ncpu": hw["ncpu"],
        "mem_total_gb": hw["mem_total_gb"],
        "page_size": hw["page_size"],
        "pages_free": pages_free,
        "pages_speculative": pages_spec,
        "pages_inactive": pages_inactive,
        "pages_wired": pages_wired,
        "breakdown": _safe_breakdown(
            hw["mem_total_gb"], hw["page_size"], include_model=include_model,
        ),
    }


def _disk() -> dict:
    try:
        du = shutil.disk_usage("/")
    except OSError:
        # A dying root mount used to OSError collect_light / the dashboard.
        return {
            "root_pct": 0,
            "root_used_gb": None,
            "root_total_gb": None,
            "root_free_gb": None,
        }
    total = du.total or 0
    used = du.used or 0
    free = du.free or 0
    pct = 0
    if total:
        ratio = _safe_div(used, total)
        if ratio is not None:
            pct = round(min(100.0, max(0.0, ratio * 100)), 1)
    return {
        "root_pct": pct,
        "root_used_gb": _bytes_to_gb(used),
        "root_total_gb": _bytes_to_gb(total),
        "root_free_gb": _bytes_to_gb(free),
    }


def _top_processes(limit: int = 8) -> list:
    """Top CPU rows from the shared ``ps aux`` table.

    A dedicated ``ps -A -o … -r`` used to run on every full sensors sample
    and timed out on this host while ``proc_cache`` already held the same
    table for the request.  ``aux`` is not CPU-sorted, so we sort here.
    """
    lines = ps_lines()
    if len(lines) < 2:
        return []
    rows = []
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            pid = int(parts[1])
        except (TypeError, ValueError, OverflowError):
            continue
        # inf/nan %CPU in `ps aux` used to leak into GET /api/system/sensors
        # (Starlette allow_nan=False). A 400-digit RSS OverflowError'd / 1024.
        cpu = _finite_float(parts[2])
        mem = _finite_float(parts[3])
        if cpu is None or mem is None:
            continue
        try:
            rss_kb = int(parts[5])
        except (TypeError, ValueError, OverflowError):
            rss_mb = None
        else:
            rss = _safe_div(rss_kb, 1024)
            rss_mb = None if rss is None else round(rss, 1)
        name = parts[10].strip()
        if "/" in name:
            name = name.split(None, 1)[0].rsplit("/", 1)[-1]
        rows.append({
            "pid": pid,
            "cpu": round(cpu, 1),
            "mem": round(mem, 1),
            "rss_mb": rss_mb,
            "name": name[:40],
        })
    rows.sort(key=lambda r: (r["cpu"], r["mem"]), reverse=True)
    try:
        cap = max(1, int(limit))
    except (TypeError, ValueError, OverflowError):
        cap = 8
    return rows[:cap]


def _network_rates() -> dict:
    """Aggregate interface bytes and compute RX/TX B/s since last sample."""
    global _net_prev
    rc, out, _ = _sh_run(["/usr/sbin/netstat", "-ibn"], timeout=5)
    if _rc_int(rc) != 0:
        return {}
    # netstat -ibn: multiple rows per iface. Prefer Link# rows (have MAC) and real NICs.
    by_name: dict[str, dict] = {}
    for line in _as_text(out).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[0].rstrip("*")
        # only physical / useful interfaces
        if not (name.startswith("en") or name.startswith("bridge") or name.startswith("ap")):
            continue
        if "Link#" not in line and not any(c.isdigit() and "." in p for p in parts[2:4] for c in "1"):
            # still accept; prefer highest byte counts below
            pass
        try:
            # Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            # When Network is <Link#N>, Address is MAC → same column indices still hold on macOS
            ibytes = int(parts[6])
            obytes = int(parts[9])
        except (ValueError, TypeError, IndexError):
            continue
        prev = by_name.get(name)
        if not prev or ibytes + obytes > prev["rx_bytes"] + prev["tx_bytes"]:
            by_name[name] = {"iface": name, "rx_bytes": ibytes, "tx_bytes": obytes}
    ifaces = sorted(by_name.values(), key=lambda x: -(x["rx_bytes"] + x["tx_bytes"]))[:6]
    total_rx = sum(i["rx_bytes"] for i in ifaces)
    total_tx = sum(i["tx_bytes"] for i in ifaces)
    now = time.time()
    rx_bps = tx_bps = None
    # Guarded stamp read: a shadow key or clock bomb planted in _net_prev
    # used to detonate the bare truthiness / compare and wipe the net leg.
    try:
        prev_t = float(_mapping_get(_net_prev, "t", 0.0))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        prev_t = 0.0
    if prev_t and now > prev_t:
        dt = now - prev_t
        if dt > 0.5:
            # A leftover 400-digit Ibytes counter used to OverflowError
            # `int((total - prev) / dt)` on the second sample.  Blanket
            # except: a planted counter whose ``__rsub__`` raises anything
            # is junk the same way.
            try:
                rx_bps = max(0, int((total_rx - _mapping_get(_net_prev, "rx", 0)) / dt))
                tx_bps = max(0, int((total_tx - _mapping_get(_net_prev, "tx", 0)) / dt))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                rx_bps = tx_bps = None
    _net_prev = {"t": now, "rx": total_rx, "tx": total_tx}
    return {
        "rx_bytes": total_rx,
        "tx_bytes": total_tx,
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "ifaces": ifaces[:8],
    }


def _thermal() -> dict | None:
    """Best-effort CPU temperature plus Apple's thermal-pressure status.

    Apple Silicon does not expose a stable, unprivileged absolute-temperature
    API.  Use an installed temperature helper when available and always report
    the OS thermal-pressure state instead of inventing a Celsius value.
    """
    temp_c = None
    source = None
    helpers = [
        (shutil.which("osx-cpu-temp"), []),
        (shutil.which("istats"), ["cpu", "temp", "--value-only"]),
    ]
    for binary, args in helpers:
        if not binary:
            continue
        rc, out, _ = _sh_run([binary, *args], timeout=4)
        if _rc_int(rc) == 0:
            m = re.search(r"(-?\d+(?:\.\d+)?)\s*(?:°?C)?", _as_text(out), re.I)
            if m:
                value = float(m.group(1))
                if 0 < value < 130:
                    temp_c = round(value, 1)
                    source = Path(binary).name
                    break

    rc, out, _ = _sh_run(["/usr/sbin/sysctl", "-n", "machdep.xcpm.cpu_thermal_level"], timeout=2)
    level_n = _sysctl_int(out) if _rc_int(rc) == 0 else None
    if level_n is not None:
        level = level_n
        return {
            "cpu_temp_c": temp_c,
            "temp_source": source,
            "pressure": "normal" if level == 0 else "warning",
            "cpu_thermal_level": level,
            "available": temp_c is not None,
        }

    rc, out, _ = _sh_run(["/usr/bin/pmset", "-g", "therm"], timeout=3)
    text = _as_text(out).lower()
    if _rc_int(rc) != 0 or "error:" in text or "failed to get" in text:
        pressure = "unknown"
    elif "no thermal warning" in text:
        pressure = "normal"
    else:
        m = re.search(r"thermal warning level\D+(\d+)", text)
        # _sysctl_int, not bare int(): a >4300-digit pmset level ValueError'd
        # here and nulled the whole thermal leg of GET /api/system/sensors.
        level_n = _sysctl_int(m.group(1)) if m else None
        pressure = "warning" if level_n is not None and level_n > 0 else "normal"
    return {
        "cpu_temp_c": temp_c,
        "temp_source": source,
        "pressure": pressure,
        "available": temp_c is not None,
        "reason": None if temp_c is not None else "absolute_temperature_unavailable",
    }


def _nonneg_bytes(value) -> int | None:
    """Non-negative byte count, or None for leftovers that would 500 JSON."""
    if type(value) is bool or value is None:
        return None
    if _isa(value, int):
        if type(value) is not int:
            # Base coercion before the range probe: a leftover int subclass
            # whose comparison methods raise (the modules5 bomb class) used
            # to blow ``0 <= value`` and escape the GPU leg's guards.
            try:
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        return value if 0 <= value <= 2**62 else None
    n = _finite_float(value)
    if n is None:
        return None
    try:
        i = int(n)
    except (OverflowError, ValueError):
        return None
    return i if 0 <= i <= 2**62 else None


def _gpu_model(entry: dict) -> str | None:
    for key in ("model", "Model", "IORegistryEntryName", "IONameMatched"):
        raw = entry.get(key)
        if raw is None:
            continue
        text = _utf8_text(raw).strip()
        if text and text != "IOAccelerator":
            return text[:80]
    return None


def _iter_ioreg_dicts(value, depth: int = 0):
    if depth > 6 or value is None:
        return
    if _isa(value, dict):
        yield value
        for v in value.values():
            yield from _iter_ioreg_dicts(v, depth + 1)
    elif _isa(value, (list, tuple)):
        for item in value:
            yield from _iter_ioreg_dicts(item, depth + 1)


def _gpu_entries():
    """IOAccelerator entries: from IOKit when it answers, else ``ioreg -a``.

    The light dashboard tick and every metrics sample read these.  IOKit
    answers the same properties in under a millisecond; the ``ioreg`` spawn
    cost about 24 ms of child CPU, 9 ms in the panel and 100 KB of XML through
    two temp files.  An empty or failed native read falls back to ``ioreg``,
    which also covers hosts without IOKit.
    """
    try:
        native = gpu_native.accelerator_entries()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        native = None
    if type(native) is list and native:
        return native
    rc, out, _ = _sh_run(
        ["/usr/sbin/ioreg", "-a", "-r", "-d", "1", "-c", "IOAccelerator"],
        timeout=4,
    )
    if _rc_int(rc) != 0 or not out:
        return None
    raw = out.encode("utf-8", "replace") if _isa(out, str) else out
    return plistlib.loads(raw)


def _gpu() -> dict | None:
    """Best-effort GPU util / memory from IOAccelerator (macOS IORegistry).

    Read through :func:`_gpu_entries` (IOKit, or the ``ioreg -a`` XML plist).
    Failures return None so GET /api/system/sensors never 500s when the
    accelerator is missing or the plist is leftover junk.
    """
    try:
        parsed = _gpu_entries()
        if parsed is None:
            return None

        best = None
        best_score = -1.0
        for entry in _iter_ioreg_dicts(parsed):
            if not _isa(entry, dict):
                continue
            stats = entry.get("PerformanceStatistics")
            if not _isa(stats, dict):
                stats = {}
            util_raw = stats.get("Device Utilization %")
            util = None if type(util_raw) is bool else _finite_float(util_raw)
            used = _nonneg_bytes(stats.get("In use system memory"))
            alloc = _nonneg_bytes(stats.get("Alloc system memory"))
            model = _gpu_model(entry)
            if util is None and used is None and alloc is None and not model:
                continue
            score = 0.0
            if util is not None:
                score += 1000.0
            if alloc is not None:
                score += min(alloc, 10**15) / 10**9
            if used is not None:
                score += 1.0
            if model:
                score += 0.1
            if score > best_score:
                best_score = score
                best = {
                    "util_pct": None if util is None else round(util, 1),
                    "mem_used_bytes": used,
                    "mem_alloc_bytes": alloc,
                    "model": model,
                }
        return best
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _uptime() -> dict:
    rc, out, _ = _sh_run(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    hours = 0.0
    text = _as_text(out)
    if _rc_int(rc) == 0 and "sec =" in text:
        try:
            boot = int(text.split("sec =")[1].split(",")[0].strip())
            hours = (time.time() - boot) / 3600 if boot else 0.0
        except (IndexError, TypeError, ValueError, OverflowError):
            hours = 0.0
    hours = _finite_float(hours) or 0.0
    try:
        days = int(hours // 24)
        h = int(hours % 24)
        m = int((hours * 60) % 60)
    except (TypeError, ValueError, OverflowError):
        days, h, m = 0, 0, 0
        hours = 0.0
    if days:
        text = f"{days}d {h}h"
    elif h:
        text = f"{h}h {m}m"
    else:
        text = f"{m}m"
    return {"uptime_hours": round(hours, 2), "uptime_text": text}


def peek_sensors() -> dict | None:
    """Return the last full sample if it is still within the TTL, else None.

    The metrics sampler uses this so a 5-minute idle tick does not spawn
    ``top`` (1.6s on this host) just to write one jsonl point.
    Re-sanitizes: leftover inf / bytes / ``\\ud800`` in the peek cache
    used to 500 GET /api/system/sensors?light=1 at encode time.
    """
    # _mapping_get / _cache_age: a hash-shadowing ``v``/``t`` key or a
    # clock bomb planted in the module cache used to detonate these bare
    # reads and 500 the light GET /api/system/sensors tick.
    v = _mapping_get(_cache, "v")
    if v is not None and _cache_age(time.time(), _mapping_get(_cache, "t")) < _sensors_ttl():
        cleaned = _jsonable(v)
        # Same isinstance guard as collect_sensors' cache hit: a leftover
        # non-dict planted in the cache used to escape here verbatim —
        # GET /api/system/sensors?light=1 answered a JSON array, and the
        # metrics sampler then AttributeError'd on snapshot.get().
        return cleaned if _isa(cleaned, dict) else None
    return None


def collect_light(*, include_model: bool = True) -> dict:
    """CPU / memory / load without top, netstat or the top-process list.

    Mach ticks + memory_pressure + hw.memsize, plus the ioreg GPU sample the
    CPU card shows.  First ticks call sleeps 0.15s to seed a baseline; later
    calls are microseconds.  ``include_model=False`` skips the local-model
    memory scan (a process-table read) for a caller that never shows it: the
    metrics sampler.  Does not overwrite the full sensors cache, so a
    dashboard poll still gets process rows and PhysMem the next time it asks
    for a full sample.
    """
    mem = _memory_base(include_model=include_model)
    cpu_ticks = _cpu_from_ticks() or {}
    disk = _disk()
    ncpu = mem.get("ncpu") or 1
    load1 = mem.get("load1")
    load5 = mem.get("load5")
    load15 = mem.get("load15")
    ratio = _safe_div(load1 or 0, ncpu) if ncpu else None
    load_pct = None if ratio is None else round(min(200.0, ratio * 100), 1)
    cpu_used = _finite_float(cpu_ticks.get("used_pct"))
    if cpu_used is None:
        cpu_used = load_pct
    if cpu_used is not None:
        cpu_used = min(100.0, max(0.0, cpu_used))
    pressure_free = mem.get("mem_free_pct")
    pressure_used = (100 - pressure_free) if pressure_free is not None else None
    mem_total = mem.get("mem_total_gb")
    available_gb = None
    if mem_total is not None and pressure_free is not None:
        try:
            held = _finite_float(mem_total * pressure_free / 100)
        except (TypeError, OverflowError):
            held = None
        available_gb = None if held is None else round(held, 1)
    used_gb = None
    if mem_total is not None and available_gb is not None:
        try:
            used_gb = round(max(0.0, mem_total - available_gb), 1)
        except (TypeError, OverflowError):
            used_gb = None
    return _jsonable({
        "ts": strftime_now("%H:%M:%S"),
        "cpu": {
            "user": cpu_ticks.get("user"),
            "sys": cpu_ticks.get("sys"),
            "idle": cpu_ticks.get("idle"),
            "used_pct": cpu_used,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "load_pct": load_pct,
            "ncpu": ncpu,
        },
        "memory": {
            "total_gb": mem_total,
            "used_pct": pressure_used,
            "free_pct": pressure_free,
            "used_gb": used_gb,
            "free_gb": available_gb,
            "available_gb": available_gb,
            "pressure_free_pct": pressure_free,
            "pressure_used_pct": pressure_used,
            **_apply_breakdown({}, mem.get("breakdown")),
        },
        "disk": disk,
        "network": {},
        "top_processes": [],
        # ioreg GPU is cheap vs top; light ticks still need util for the CPU card.
        "gpu": _gpu(),
        "cpu_used_pct": cpu_used,
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "light": True,
    })


def collect_sensors(force: bool = False) -> dict:
    # ``is not None``, not truthiness: a leftover dict-subclass planted in
    # the cache whose ``__bool__`` raised used to 500 GET /api/system/sensors
    # before _jsonable ever saw it (peek_sensors was already immune because
    # it tests ``is not None``).
    # _mapping_get / _cache_age on every cache touch: a hash-shadowing
    # ``v``/``t`` key or a clock bomb planted in the module cache used to
    # detonate the bare subscripts / age arithmetic here — a raw 500 on
    # GET /api/system/sensors before any scrub ran.  An unreadable cache
    # reads as a miss and re-collects.
    hit = _mapping_get(_cache, "v")
    if not force and hit is not None and _cache_age(time.time(), _mapping_get(_cache, "t")) < _sensors_ttl():
        # Re-sanitize: leftover inf / ``\ud800`` planted in the cache used
        # to 500 GET /api/system/sensors (the light peek already re-sanitized).
        cleaned = _jsonable(hit)
        return cleaned if _isa(cleaned, dict) else {}

    with _refresh_lock:
        # Single-flight: concurrent dashboard/metrics callers share one sample.
        # Coalesce back-to-back force=True (metrics + UI) within 1s.
        hit = _mapping_get(_cache, "v")
        age = _cache_age(time.time(), _mapping_get(_cache, "t")) if hit is not None else 1e9
        if hit is not None and ((not force and age < _sensors_ttl()) or age < 1.0):
            cleaned = _jsonable(hit)
            return cleaned if _isa(cleaned, dict) else {}
        return _collect_sensors_uncached()


def _collect_sensors_uncached() -> dict:
    # Parallel shell collection — top is the slowest (~0.5–1s); overlap the rest.
    f_mem = _pool.submit(_memory_base)
    f_disk = _pool.submit(_disk)
    f_top = _pool.submit(_cpu_and_mem_from_top_cached)
    f_cpu = _pool.submit(_cpu_from_ticks)
    f_thermal = _pool.submit(_thermal)
    f_gpu = _pool.submit(_gpu)
    f_net = _pool.submit(_network_rates)
    f_procs = _pool.submit(_top_processes, 8)
    f_up = _pool.submit(_uptime)

    def _result(fut, fallback):
        try:
            return fut.result()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return fallback

    # `.result()` re-raises; one wedged `top`/`pmset` must not 500 the dashboard.
    mem = _result(f_mem, {}) or {}
    disk = _result(f_disk, {}) or {}
    top = _result(f_top, {}) or {}
    cpu_ticks = _result(f_cpu, {}) or {}
    thermal = _result(f_thermal, None)
    gpu = _result(f_gpu, None)
    net = _result(f_net, {}) or {}
    procs = _result(f_procs, []) or []
    up = _result(f_up, {}) or {}

    ncpu = mem.get("ncpu") or 1
    load1 = top.get("load1", mem.get("load1"))
    load5 = top.get("load5", mem.get("load5"))
    load15 = top.get("load15", mem.get("load15"))

    # load as % of core capacity (Unraid / Glances style)
    ratio = _safe_div(load1 or 0, ncpu) if ncpu else None
    load_pct = None if ratio is None else round(min(200.0, ratio * 100), 1)

    # Prefer Mach-tick deltas (accurate, matches Activity Monitor); fall back
    # to top's single-frame CPU line, then to load-based estimate.
    cpu_user = cpu_ticks.get("user", top.get("user"))
    cpu_sys = cpu_ticks.get("sys", top.get("sys"))
    cpu_idle = cpu_ticks.get("idle", top.get("idle"))
    if cpu_ticks.get("used_pct") is not None:
        cpu_used_pct = _finite_float(cpu_ticks["used_pct"])
    elif cpu_idle is not None:
        cpu_used_pct = _finite_float(100 - cpu_idle)
        cpu_used_pct = None if cpu_used_pct is None else round(cpu_used_pct, 1)
    elif cpu_user is not None and cpu_sys is not None:
        cpu_used_pct = _finite_float(cpu_user + cpu_sys)
        cpu_used_pct = None if cpu_used_pct is None else round(cpu_used_pct, 1)
    else:
        cpu_used_pct = load_pct

    # --- Memory (macOS-aware) ---
    # PhysMem "used" includes file cache and is almost always near-full; NOT stress.
    # memory_pressure free% is the right "is the machine tight?" metric.
    mem_total = mem.get("mem_total_gb")
    phys_used_gb = top.get("mem_used_gb")  # includes cache
    phys_unused_gb = top.get("mem_unused_gb")
    wired_gb = top.get("mem_wired_gb")
    compressor_gb = top.get("mem_compressor_gb")
    pressure_free_pct = mem.get("mem_free_pct")  # memory_pressure -Q

    # Primary stress metric from Apple memory_pressure
    if pressure_free_pct is not None:
        used = _finite_float(100 - pressure_free_pct)
        pressure_used_pct = None if used is None else round(used, 1)
        free_pct = pressure_free_pct
        used_pct = pressure_used_pct
    else:
        free_pct = None
        used_pct = None
        pressure_used_pct = None

    # Approx non-cache footprint (wired + compressor); cache ≈ phys_used - that
    app_gb = None
    cache_gb = None
    if wired_gb is not None or compressor_gb is not None:
        try:
            app_gb = round((wired_gb or 0) + (compressor_gb or 0), 2)
        except (TypeError, OverflowError):
            app_gb = None
        if phys_used_gb is not None and app_gb is not None:
            try:
                cache_gb = round(max(0.0, phys_used_gb - app_gb), 2)
            except (TypeError, OverflowError):
                cache_gb = None

    # Available ≈ total * free_pct / 100 (pressure free), fallback unused
    available_gb = None
    if mem_total is not None and free_pct is not None:
        try:
            held = _finite_float(mem_total * free_pct / 100)
        except (TypeError, OverflowError):
            held = None
        available_gb = None if held is None else round(held, 1)
    elif phys_unused_gb is not None:
        available_gb = phys_unused_gb

    # "In use" under pressure ≈ total - available
    pressure_used_gb = None
    if mem_total is not None and available_gb is not None:
        try:
            pressure_used_gb = round(max(0.0, mem_total - available_gb), 1)
        except (TypeError, OverflowError):
            pressure_used_gb = None

    v = {
        "ts": strftime_now("%H:%M:%S"),
        "uptime": up,
        "cpu": {
            "user": cpu_user,
            "sys": cpu_sys,
            "idle": cpu_idle,
            "used_pct": cpu_used_pct,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "load_pct": load_pct,
            "ncpu": ncpu,
            "thermal": thermal,
            "proc_total": top.get("proc_total"),
            "proc_running": top.get("proc_running"),
        },
        "memory": {
            "total_gb": mem_total,
            # primary UI fields = pressure-based (not PhysMem cache-inflated)
            "used_pct": used_pct,
            "free_pct": free_pct,
            "used_gb": pressure_used_gb,
            "free_gb": available_gb,
            "available_gb": available_gb,
            # breakdown
            "wired_gb": wired_gb,
            "compressor_gb": compressor_gb,
            "app_gb": app_gb,
            "cache_gb": cache_gb,
            "phys_used_gb": phys_used_gb,
            "phys_unused_gb": phys_unused_gb,
            "pressure_free_pct": pressure_free_pct,
            "pressure_used_pct": pressure_used_pct,
            "physmem_raw": top.get("physmem_raw"),
            "hint": "Pressure follows memory_pressure; Memory Used = App + Wired + Compressed (Activity Monitor)",
            **_apply_breakdown({}, mem.get("breakdown")),
        },
        "disk": disk,
        "network": net,
        "top_processes": procs,
        "thermal": thermal,
        "gpu": gpu,
        # backward-compat flat fields used by existing UI
        "cpu_used_pct": cpu_used_pct,
        "load1": load1,
        "load5": load5,
        "load15": load15,
    }
    v = _jsonable(v)
    try:
        _cache.update(t=time.time(), v=v)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A hash-shadowing key planted in the module cache raises out of
        # the C-level insert compare at the very end of a successful
        # collection — pre-fix a raw 500 on GET /api/system/sensors.
        # clear() never compares keys, so evict the poison and rewrite.
        try:
            _cache.clear()
            _cache.update(t=time.time(), v=v)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    return v
