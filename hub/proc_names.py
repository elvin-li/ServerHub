"""Whether a process with an exact name is running, read in-process.

``pgrep -x NAME`` costs a spawn (about 4.5 ms of child CPU and 1.7 ms in the
caller).  The panel asks it before every ``utmctl`` call, because utmctl
relaunches UTM.app when the app is closed.  :func:`process_named` answers the
same question from one ``sysctl({CTL_KERN, KERN_PROC, KERN_PROC_ALL})`` read
(about 0.4 ms): a process whose ``p_comm`` (its executable's file name, cut to
16 bytes) is exactly *name*.

It skips kernel processes, processes that are exiting and zombies: none of
them can answer an Apple Event, which is what the UTM check is for, and pgrep
does not match a zombie either.  pgrep matches the base name of ``argv[0]``
instead of ``p_comm``.  The two agree for an app bundle's binary such as UTM,
but not for a program started through a symlink or one that rewrites its argv
(postgres, nginx), so this is not a general pgrep replacement.

None, so the caller runs pgrep, when the name is longer than ``p_comm`` holds
or not printable ASCII, when the read fails, when the table does not contain
this process (so its layout is not the one below), and under
``SERVERHUB_NO_NATIVE_PROCNAME``, which the test bootstrap sets so stubbed
pgrep answers still reach the callers.
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys
import threading

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

# <sys/sysctl.h>, <sys/proc.h> (macOS SDK); offsets checked with offsetof().
_CTL_KERN = 1
_KERN_PROC = 14
_KERN_PROC_ALL = 0
_KINFO_PROC_SIZE = 648
_OFF_FLAG = 32  # kp_proc.p_flag (int)
_OFF_STAT = 36  # kp_proc.p_stat (char)
_OFF_PID = 40  # kp_proc.p_pid (int)
_OFF_COMM = 243  # kp_proc.p_comm[MAXCOMLEN + 1]
_COMM_SIZE = 17
_P_SYSTEM = 0x200
_P_WEXIT = 0x2000
_SZOMB = 5
_ENOMEM = 12
#: Extra entries asked for beyond the size the kernel reported, so a process
#: started between the two calls does not make the read fail.
_SLACK = 64

_libc = None
_libc_loaded = False
_libc_lock = threading.Lock()


def _load():
    global _libc, _libc_loaded
    with _libc_lock:
        if _libc_loaded:
            return _libc
        _libc_loaded = True
        if sys.platform != "darwin":
            return None
        try:
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.sysctl.argtypes = [
                ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t,
            ]
            libc.sysctl.restype = ctypes.c_int
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        _libc = libc
        return libc


def _table(libc) -> bytes | None:
    mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROC, _KERN_PROC_ALL)
    for _ in range(5):
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            return None
        size.value += _KINFO_PROC_SIZE * _SLACK
        buf = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
            if ctypes.get_errno() == _ENOMEM:
                continue  # the table grew past the slack; ask again
            return None
        if size.value % _KINFO_PROC_SIZE:
            return None
        return ctypes.string_at(buf, size.value)
    return None


def process_named(name: str) -> bool | None:
    """True if a live process's ``p_comm`` is exactly *name*; None if unknown."""
    if os.environ.get("SERVERHUB_NO_NATIVE_PROCNAME"):
        return None
    if type(name) is not str or not name or len(name) >= _COMM_SIZE:
        return None
    if not all(0x20 < ord(ch) < 0x7F for ch in name):
        return None
    libc = _load()
    if libc is None:
        return None
    try:
        data = _table(libc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    if data is None:
        return None
    want = name.encode("ascii")
    me = os.getpid()
    seen_me = False
    found = False
    unpack_int = struct.Struct("<i").unpack_from
    for off in range(0, len(data), _KINFO_PROC_SIZE):
        pid = unpack_int(data, off + _OFF_PID)[0]
        if pid == me:
            seen_me = True
            continue
        if found:
            continue
        comm = data[off + _OFF_COMM:off + _OFF_COMM + _COMM_SIZE].split(b"\0", 1)[0]
        if comm != want:
            continue
        if unpack_int(data, off + _OFF_FLAG)[0] & (_P_SYSTEM | _P_WEXIT):
            continue
        if data[off + _OFF_STAT] == _SZOMB:
            continue
        found = True
    # This process is always in the table; when it is not, the layout is not
    # the one these offsets describe.
    return found if seen_me else None
