"""Host system metrics."""
from __future__ import annotations

import os
import re
import shutil
import time
from hub.paths import SMARTCTL
from hub.util import LazyPool, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

_pool = LazyPool(4, "hub-system")


def shutdown_executor() -> None:
    _pool.shutdown()

_smart_cache = {"t": 0.0, "v": None}


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    planted in the SMART cache detonated ``_jsonable``'s rank gates, raised
    out of ``collect_system`` and silently wiped the whole ``system`` tile
    from GET /api/status (the docker_cli / nas8 rule).  A real subclass
    still matches through the C-level type check; only a value that cannot
    answer what it is takes the non-matching branch.
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

    The health11 rule on the system tile: even a plain-dict lookup runs the
    *stored keys'* own ``__eq__`` during the hash probe, so a leftover
    str-subclass key whose hash shadows ``v`` / ``t`` planted in the SMART
    cache used to detonate the bare ``_smart_cache["v"]`` subscript and the
    due-probe arithmetic — raising out of ``collect_system`` and silently
    wiping the whole ``system`` tile (load, disk, uptime and SMART
    together) from GET /api/status.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


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


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    OverflowError on huge memsize / disk / boottime was already isolated;
    leftover ``\\ud800`` / inf in the SMART cache still leaked into
    GET /api/status's ``system`` object when the status sanitizer was
    bypassed (and into any direct collect_system caller).
    A >4300-digit leftover int in the SMART cache still passed through
    untouched: CPython's int->str digit limit then ValueError'd
    ``json.dumps`` itself.

    The bound probes still blew on the modules5 subclass-bomb classes: an
    int subclass whose ``__str__`` raises, a float subclass whose
    ``__eq__``/``__ne__`` raises, a bytes subclass whose ``decode`` raises
    (as a value and as a mapping key), a dict subclass whose ``items()``
    raises, a sequence subclass whose ``__iter__`` raises, and an object
    whose ``isoformat`` *access* raises (getattr's default only swallows
    AttributeError).  One such bomb in the SMART cache raised out of
    ``collect_system`` and the status build's fallback silently wiped the
    whole ``system`` tile — load, disk and uptime died with the poison.
    Hence the unbound base-type calls below, the modules5 convention.
    """
    if depth > 32:
        return None
    # _isa on every rank gate: a leftover whose ``__class__`` is a raising
    # property used to detonate the *first* isinstance below — as a value
    # or a mapping key in the SMART cache — raising out of collect_system
    # and wiping the whole ``system`` tile from GET /api/status.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` cannot be subclassed, so anything passing this gate that
        # is not the exact type is a *lying* ``__class__`` impostor.  It
        # used to be returned verbatim — every other liar drops at its
        # unbound base call, but the bool gate had nothing to call — and
        # the C-level JSON encoder then refused it out of the SMART cache:
        # a raw 500 on GET /api/status?force through the system tile.
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
        return _as_text(value)
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
        # yields non-pairs cannot raise and the real entries still survive.
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
            out[_as_text(k)] = _jsonable(v, depth + 1)
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
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/status system.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _as_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``in`` probes; a bomb reads as failure.

    This module does not own ``sh`` (tests and tooling patch it), and an
    rc-*subclass* whose ``__eq__`` raises used to detonate the bare
    ``rc == 0`` / ``rc in (0, 4)`` probes in ``collect_system``'s main body
    — one bomb wiped the whole ``system`` tile (load, disk, uptime and
    SMART together) from GET /api/status (the health9 rule).  ``-255`` is
    no honest exit status, so a bomb keeps the failure branch.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        if isinstance(rc, int):
            return int.__index__(rc)
        return int(rc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _sh3(value) -> tuple:
    """Exact ``(rc, out, err)`` storage from a possibly-poisoned ``sh`` answer.

    The nginx/docker11 guarded-shape rule: this module does not own ``sh``
    (tests and tooling patch it), and a leftover riding the *shape* of the
    return — a 2-tuple, a scalar, a tuple subclass whose ``__iter__``
    raises, a lying-``__class__`` tuple impostor — used to detonate the
    bare ``rc, out, _ = …`` unpacks in ``collect_system``'s main body and
    wipe the whole system tile from GET /api/status.  Junk degrades to
    ``(-255, "", "")``: nonzero, never a success rc.
    """
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


def _sysctl_int(value) -> int | None:
    """int from a sysctl `-n` payload that may be str, bytes, or already int."""
    if _isa(value, bool) or value is None:
        return None
    if _isa(value, int):
        try:
            # Base coercion before the ``>= 0`` probe: a leftover int
            # subclass whose comparison methods raise (the modules5 bomb
            # class) used to escape this helper's callers.
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
        # ``isdigit()`` does not bound length: ``int()`` of a >4300-digit
        # leftover is ValueError (CPython's str->int cap), the same class the
        # sibling parsers in sensors_svc / macos_sysctl now absorb.
        return None


def _after_colon(line: str) -> str | None:
    if ":" not in line:
        return None
    return line.split(":", 1)[1].strip() or None


def _finite_float(value) -> float | None:
    """float from a memory_pressure token, or None for inf/NaN/overflow."""
    try:
        n = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if n != n or n in (float("inf"), float("-inf")):
        return None
    return n


def _safe_div(num, den) -> float | None:
    """num/den as a finite float. Huge ints OverflowError'd collect_system."""
    try:
        return _finite_float(num / den)
    except (TypeError, ZeroDivisionError, OverflowError):
        return None


def _bytes_to_gb(n, digits: int | None = 1):
    ratio = _safe_div(n, 2**30)
    if ratio is None:
        return None
    return round(ratio) if digits is None else round(ratio, digits)


def _mem_free_pct(out) -> int | None:
    """Free-memory percent from ``memory_pressure -Q``, or None if unreadable.

    ``int(float(raw))`` used to OverflowError on ``inf%`` / huge digit strings
    and 500 ``/api/status``.  A matching line that does not parse is skipped
    rather than poisoning the whole snapshot.
    """
    mem_free = None
    for line in _as_text(out).splitlines():
        if "free percentage" not in line:
            continue
        m = re.search(r"(\d+(?:\.\d+)?)\s*%", line)
        raw = m.group(1) if m else line.split(":")[-1].strip().rstrip("%")
        n = _finite_float(raw)
        if n is None:
            continue
        try:
            mem_free = int(n)
        except (TypeError, ValueError, OverflowError):
            continue
    return mem_free


def collect_system():
    try:
        raw_load = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    else:
        load1 = _finite_float(raw_load[0]) if len(raw_load) > 0 else None
        load5 = _finite_float(raw_load[1]) if len(raw_load) > 1 else None
        load15 = _finite_float(raw_load[2]) if len(raw_load) > 2 else None

    try:
        du = shutil.disk_usage("/")
        used = getattr(du, "used", 0) or 0
        total = getattr(du, "total", 0) or 0
        free = getattr(du, "free", 0) or 0
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A dying root mount used to OSError/RuntimeError collect_system
        # and empty the ``system`` object on GET /api/status.
        used = total = free = None

    # This is one leg of the /api/status fan-out, which the dashboard polls every
    # 12s, so its own internals sit on that endpoint's critical path. The four
    # reads below are independent, and two of them are the slow ones:
    # `memory_pressure -Q` and — once every 10 minutes — a `sudo -n smartctl`.
    # Running them in sequence made the whole status refresh wait for their sum.
    # Guarded stamp read: a hash-shadowing ``t`` key (the C-level probe
    # runs the stored bomb's ``__eq__``) or a clock bomb planted in the
    # slot (``__float__`` / ``__rsub__`` / ``__gt__`` raising) used to
    # detonate this bare arithmetic and wipe the whole system tile.  An
    # unreadable stamp reads as due and re-probes.
    try:
        smart_due = time.time() - float(_mapping_get(_smart_cache, "t", 0.0)) > 600
    except _CONTROL_FLOW:
        raise
    except BaseException:
        smart_due = True
    def _ncpu_and_memsize():
        # One worker, two cheap integer sysctls: ctypes first, shell fallback.
        # The pool is already full with boot / memory_pressure / (sometimes)
        # smartctl, and hw.memsize is what lets the dashboard print RAM total
        # from /api/status before sensors land.  kern.boottime stays on sh().
        from hub import macos_sysctl
        ncpu = macos_sysctl.sysctl_int("hw.ncpu", timeout=2, sh=sh)
        memsize = macos_sysctl.sysctl_int("hw.memsize", timeout=2, sh=sh)
        return ncpu, memsize

    f_boot = _pool.submit(sh, ["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    f_mem = _pool.submit(sh, ["/usr/bin/memory_pressure", "-Q"], timeout=4)
    f_hw = _pool.submit(_ncpu_and_memsize)
    f_smart = (
        _pool.submit(sh, ["/usr/bin/sudo", "-n", SMARTCTL, "-a", "/dev/disk0"], timeout=10)
        if smart_due
        else None
    )

    def _result(fut, fallback):
        try:
            return fut.result()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return fallback

    # `.result()` re-raises; memory_pressure must not drop load/disk from /api/status.
    # _sh3 on every unpack: an sh answer-shape bomb used to detonate the
    # bare tuple unpack itself and wipe the whole tile.
    rc, out, _ = _sh3(_result(f_boot, (1, "", "")))
    out = _as_text(out)
    uptime_h = 0.0
    # _rc_int on every probe below: an rc-``__eq__`` bomb from a patched/odd
    # ``sh`` used to raise here and wipe the whole system tile.
    if _rc_int(rc) == 0 and "sec =" in out:
        try:
            boot = int(out.split("sec =")[1].split(",")[0].strip())
        except (IndexError, TypeError, ValueError, OverflowError):
            boot = 0
        if boot:
            try:
                uptime_h = (time.time() - boot) / 3600
            except (TypeError, OverflowError):
                uptime_h = 0.0
            else:
                n = _finite_float(uptime_h)
                uptime_h = n if n is not None else 0.0

    rc, out, _ = _sh3(_result(f_mem, (1, "", "")))
    mem_free = _mem_free_pct(out)

    ncpu_i, mem_n = _result(f_hw, (None, None))
    if ncpu_i is not None:
        ncpu_i = _sysctl_int(ncpu_i)
    if mem_n is not None:
        mem_n = _sysctl_int(mem_n)
    mem_total_gb = _bytes_to_gb(mem_n, 1) if mem_n is not None else None

    # _mapping_get: a hash-shadowing ``v`` key planted in the cache used to
    # detonate this bare subscript the same way as the stamp above.
    smart = _mapping_get(_smart_cache, "v")
    # _isa: the cache normally only ever holds the plain dict this function
    # writes, but a leftover non-dict (a ``__class__``-property bomb, a
    # scalar) planted as the whole value is junk — degrade the SMART field
    # alone rather than serving it as a garbage string in the payload.
    if smart is not None and not _isa(smart, dict):
        smart = None
    if f_smart is not None:
        rc, out, _ = _sh3(_result(f_smart, (1, "", "")))
        if _rc_int(rc) in (0, 4):
            smart = {}
            for line in _as_text(out).splitlines():
                if "Data Units Written" in line and "[" in line:
                    smart["written"] = line.split("[")[1].rstrip("]")
                elif "Percentage Used" in line:
                    wear = _after_colon(line)
                    if wear:
                        smart["wear"] = wear
                elif line.strip().startswith("Temperature:"):
                    temp = _after_colon(line)
                    if temp:
                        smart.setdefault("temp", temp)
                elif "Temperature_Celsius" in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        smart.setdefault("temp", f"{parts[9]} Celsius")
                elif "Airflow_Temperature" in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        smart.setdefault("temp", f"{parts[9]} Celsius")
            try:
                _smart_cache.update(t=time.time(), v=smart)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A shadow key raises out of the insert compare at the end
                # of a successful probe; clear() never compares keys.
                try:
                    _smart_cache.clear()
                    _smart_cache.update(t=time.time(), v=smart)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    pass
    n = ncpu_i or 1
    load_pct = None
    if load1 is not None:
        ratio = _safe_div(load1 * 100, n)
        if ratio is not None:
            load_pct = round(min(200.0, ratio), 1)
    disk_ratio = _safe_div(used, total) if total else None
    disk_pct = round(disk_ratio * 100) if disk_ratio is not None else 0
    try:
        days = int(uptime_h // 24)
        hours = int(uptime_h % 24)
    except (TypeError, ValueError, OverflowError):
        days, hours = 0, 0
        uptime_h = 0.0
    if load1 is None or load5 is None or load15 is None:
        load_s = ""
    else:
        load_s = f"{round(load1, 2):.2f} / {round(load5, 2):.2f} / {round(load15, 2):.2f}"
    cleaned = _jsonable({
        "load": load_s,
        "load1": None if load1 is None else round(load1, 2),
        "load5": None if load5 is None else round(load5, 2),
        "load15": None if load15 is None else round(load15, 2),
        "load_pct": load_pct,
        "ncpu": ncpu_i,
        "mem_total_gb": mem_total_gb,
        "mem_free_pct": mem_free,
        "mem_used_pct": (100 - mem_free) if mem_free is not None else None,
        "disk_used_gb": _bytes_to_gb(used, None),
        "disk_total_gb": _bytes_to_gb(total, None),
        "disk_free_gb": _bytes_to_gb(free, None),
        "disk_pct": disk_pct,
        "uptime": (
            f"{days} days {hours} hours"
            if uptime_h >= 24
            else f"{uptime_h:.1f} hours"
        ),
        "uptime_hours": round(uptime_h, 2),
        "smart": smart,
    })
    return cleaned if isinstance(cleaned, dict) else {}
