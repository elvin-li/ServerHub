"""In-process integer sysctl reads (ctypes) with a shell fallback.

``hw.ncpu`` / ``hw.memsize`` / ``hw.pagesize`` are integers.  ``kern.boottime``
is a ``struct timeval``; its text form (``sec =``) stays on ``sh()``.  A
too-short ctypes buffer can return ``rc == 0`` with a truncated RAM total, so
this module size-probes, rejects a zero ``hw.memsize``, and falls back to
``/usr/sbin/sysctl -n``.
"""
from __future__ import annotations

import ctypes
import re
import struct

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

INTEGER_KEYS = frozenset({"hw.ncpu", "hw.memsize", "hw.pagesize"})
_SYSCTL = "/usr/sbin/sysctl"

_libc = None
try:
    for _path in ("/usr/lib/libSystem.dylib", "/usr/lib/libSystem.B.dylib"):
        try:
            _libc = ctypes.CDLL(_path, use_errno=True)
            break
        except OSError:
            continue
except _CONTROL_FLOW:
    raise
except BaseException:  # pragma: no cover — non-macOS / sandbox
    _libc = None

if _libc is not None:
    try:
        _libc.sysctlbyname.argtypes = [
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        _libc.sysctlbyname.restype = ctypes.c_int
    except _CONTROL_FLOW:
        raise
    except BaseException:  # pragma: no cover
        _libc = None


def parse_int(value) -> int | None:
    """int from a sysctl ``-n`` payload that may be str, bytes, or already int."""
    if type(value) is bool or value is None:
        return None
    if type(value) is int:
        return value if value >= 0 else None
    for base in (bytes, bytearray):
        try:
            value = base.decode(value, "utf-8", "replace")
            break
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        text = str(value).strip()
    except RecursionError:
        return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if not text.isdigit():
        return None
    try:
        return int(text)
    except ValueError:
        # ``isdigit()`` does not bound length: ``int()`` of a >4300-digit
        # leftover is ValueError (CPython's str->int cap).  It used to raise
        # through sysctl_int into sensors_svc._static_hw and 500
        # GET /api/system/sensors?light=1, and kill metrics sampler ticks.
        return None


def sysctlbyname_int(name: str) -> int | None:
    """Read an integer sysctl via ctypes.  None on any failure (caller falls back)."""
    if name not in INTEGER_KEYS or _libc is None:
        return None
    try:
        raw_name = name.encode("ascii")
    except (TypeError, UnicodeEncodeError, AttributeError):
        return None
    try:
        size = ctypes.c_size_t(0)
        rc = _libc.sysctlbyname(raw_name, None, ctypes.byref(size), None, 0)
        if rc != 0 or size.value not in (4, 8):
            return None
        buf = ctypes.create_string_buffer(size.value)
        got = ctypes.c_size_t(size.value)
        rc = _libc.sysctlbyname(raw_name, buf, ctypes.byref(got), None, 0)
        if rc != 0 or got.value != size.value:
            return None
        data = buf.raw[: size.value]
        if size.value == 8:
            value = struct.unpack("<Q", data)[0]
        else:
            value = struct.unpack("<I", data)[0]
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if name == "hw.memsize" and value == 0:
        return None
    return int(value)


def sysctl_int(name: str, *, timeout: int = 2, sh=None) -> int | None:
    """Integer sysctl: ctypes first, then ``sysctl -n``.  Never ``kern.boottime``."""
    if name not in INTEGER_KEYS:
        return None
    n = sysctlbyname_int(name)
    if n is not None:
        return n
    run = sh
    if run is None:
        from hub.util import sh as run
    try:
        rc, out, _ = run([_SYSCTL, "-n", name], timeout=timeout)
        # Inside the guard, not one line past it: this helper does not own
        # the runner, and an rc-subclass ``__ne__`` bomb from a patched/odd
        # ``sh`` used to detonate this bare probe — through sensors_svc's
        # ``_static_hw`` that ran on the request thread of the light
        # GET /api/system/sensors tick.  An unreadable status reads as
        # failure, same as a raising spawn.
        if rc != 0:
            return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return parse_int(out)
