"""Listening TCP sockets read in-process through libproc, as `lsof` reports them.

`lsof -nP -iTCP -sTCP:LISTEN` gets its rows from libproc: every pid
(``proc_listallpids``), each one's descriptors (``PROC_PIDLISTFDS``), each
socket's state (``PROC_PIDFDSOCKETINFO``) and the process name
(``PROC_PIDTBSDINFO``).  Those calls make the same permission checks for lsof
as for this process, so reading them here gives the same rows without the
spawn: about 50-80 ms of child CPU and two temp files per snapshot, against
about 8 ms here.

:func:`listen_rows` returns :class:`Listener` rows in lsof's order and in
its text.  COMMAND is the first nine columns of the name with a space written
``\\x20``; an escape that does not fit is dropped, not cut.  NAME is
``*:port``, ``a.b.c.d:port`` or ``[::1]:port``.  :func:`lsof_text` renders
the rows as lsof's output for the readers that parse it.  For anything they
do not reproduce exactly (another character in a name, another IPv6 address,
a descriptor list that cannot be read whole, a user name lsof might print
another way) they return None and the caller runs lsof.  So does
``SERVERHUB_NO_NATIVE_LSOF``, which the test bootstrap sets so canned lsof
text still reaches the parsers.
"""
from __future__ import annotations

import ctypes
import os
import pwd
import re
import socket
import struct
import sys
import threading
from typing import NamedTuple

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

# <sys/proc_info.h> (macOS SDK).  Offsets checked with offsetof() and against
# lsof's output on this host.
_PROC_PIDLISTFDS = 1
_PROC_PIDTBSDINFO = 3
_PROC_PIDFDSOCKETINFO = 3
_PROX_FDTYPE_SOCKET = 2
_SOCKINFO_TCP = 2
_TSI_S_LISTEN = 1
_AF_INET = 2
_AF_INET6 = 30
#: sizeof(struct proc_fdinfo): int32 proc_fd, uint32 proc_fdtype.
_FDINFO_SIZE = 8
#: sizeof(struct socket_fdinfo) and the fields read from it.
_SOCKET_FDINFO_SIZE = 792
_OFF_FAMILY = 184  # psi.soi_family
_OFF_KIND = 256  # psi.soi_kind
_OFF_LPORT = 268  # psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport (network order)
_OFF_LADDR = 312  # psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr (16 bytes)
_OFF_STATE = 344  # psi.soi_proto.pri_tcp.tcpsi_state
#: sizeof(struct proc_bsdinfo), pbi_uid and pbi_comm[MAXCOMLEN + 1] in it.
_BSDINFO_SIZE = 136
_OFF_UID = 20
_OFF_COMM = 48
_COMM_SIZE = 17
#: User names printed as they are: lsof's text for longer or other names is
#: not checked here.
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,7}")


class Listener(NamedTuple):
    """One listening socket, in lsof's text where lsof prints the field."""

    command: str
    pid: int
    uid: int
    fd: int
    family: int
    name: str
    port: int
#: lsof's default COMMAND width.
_COMMAND_COLUMNS = 9
#: Descriptors read per process before asking for the exact count.
_FD_SLOTS = 1024

_lib = None
_lib_loaded = False
_lib_lock = threading.Lock()


def _load():
    global _lib, _lib_loaded
    with _lib_lock:
        if _lib_loaded:
            return _lib
        _lib_loaded = True
        if sys.platform != "darwin":
            return None
        try:
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
            lib.proc_listallpids.restype = ctypes.c_int
            lib.proc_pidinfo.argtypes = [
                ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
            ]
            lib.proc_pidinfo.restype = ctypes.c_int
            lib.proc_pidfdinfo.argtypes = [
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
            ]
            lib.proc_pidfdinfo.restype = ctypes.c_int
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        _lib = lib
        return lib


def _lsof_command(name: bytes) -> str | None:
    """lsof's COMMAND text for a process name, or None if it is not reproduced.

    Printable ASCII is copied, a space becomes ``\\x20``, and the text stops
    before the first character whose text would pass nine columns.  lsof
    escapes backslashes, control characters and non-ASCII bytes in other
    ways; those names return None.
    """
    out = []
    used = 0
    for byte in name:
        if byte == 0x20:
            token = "\\x20"
        elif 0x20 < byte < 0x7F and byte != 0x5C:
            token = chr(byte)
        else:
            return None
        if used + len(token) > _COMMAND_COLUMNS:
            break
        out.append(token)
        used += len(token)
    return "".join(out)


def _address(family: int, info: bytes, base: int = _OFF_LADDR) -> str | None:
    """lsof's address text for a socket's local address, or None."""
    if family == _AF_INET:
        raw = info[base + 12:base + 16]
        return "*" if raw == b"\0\0\0\0" else socket.inet_ntoa(raw)
    raw = info[base:base + 16]
    if raw == bytes(16):
        return "*"
    if raw == bytes(15) + b"\1":
        return "[::1]"
    # Scoped, mapped and global IPv6 addresses: lsof's text for them is not
    # reproduced here.
    return None


def _lsof_user(uid: int) -> str | None:
    """lsof's USER text for *uid* (its login name), or None if not reproduced."""
    try:
        name = pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError, TypeError, ValueError):
        return None  # lsof prints the number; not reproduced here
    if type(name) is not str or not _USER_RE.fullmatch(name):
        return None
    return name


def lsof_text() -> str | None:
    """``lsof -nP -iTCP -sTCP:LISTEN`` output built from :func:`listen_rows`.

    The COMMAND, PID, USER and NAME columns are lsof's; FD, TYPE, DEVICE,
    SIZE/OFF and NODE are filled in so every column sits where lsof puts it.
    None when the rows or a user name cannot be reproduced.
    """
    rows = listen_rows()
    if rows is None:
        return None
    users: dict[int, str | None] = {}
    lines = ["COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"]
    for row in rows:
        if row.uid not in users:
            users[row.uid] = _lsof_user(row.uid)
        user = users[row.uid]
        if user is None:
            return None
        kind = "IPv4" if row.family == _AF_INET else "IPv6"
        lines.append(
            f"{row.command} {row.pid} {user} {row.fd}u {kind} 0x0 0t0 TCP "
            f"{row.name} (LISTEN)"
        )
    return "\n".join(lines) + "\n"


def listen_rows() -> list[Listener] | None:
    """Every listening TCP socket as a :class:`Listener`, or None."""
    if os.environ.get("SERVERHUB_NO_NATIVE_LSOF"):
        return None
    lib = _load()
    if lib is None:
        return None
    try:
        return _read(lib)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _read(lib) -> list[Listener] | None:
    count = lib.proc_listallpids(None, 0)
    if count <= 0:
        return None
    pids = (ctypes.c_int * (count + 64))()
    got = lib.proc_listallpids(pids, ctypes.sizeof(pids))
    if got <= 0:
        return None
    fds = ctypes.create_string_buffer(_FDINFO_SIZE * _FD_SLOTS)
    sock = ctypes.create_string_buffer(_SOCKET_FDINFO_SIZE)
    bsd = ctypes.create_string_buffer(_BSDINFO_SIZE)
    unpack_int = struct.Struct("<i").unpack_from
    rows: list[Listener] = []
    for pid in sorted(set(pids[:min(got, len(pids))])):
        if pid <= 0:
            continue
        size = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, fds, len(fds))
        if size <= 0:
            # Gone, or another user's process: lsof cannot read it either.
            continue
        if size >= len(fds):
            need = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, None, 0)
            if need <= 0:
                continue
            fds = ctypes.create_string_buffer(need + _FDINFO_SIZE * 256)
            size = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, fds, len(fds))
            if size <= 0:
                continue
            if size >= len(fds):
                return None
        listeners = []
        table = ctypes.string_at(fds, size - size % _FDINFO_SIZE)
        for fd, fdtype in struct.iter_unpack("<iI", table):
            if fdtype != _PROX_FDTYPE_SOCKET:
                continue
            if lib.proc_pidfdinfo(
                pid, fd, _PROC_PIDFDSOCKETINFO, sock, _SOCKET_FDINFO_SIZE,
            ) != _SOCKET_FDINFO_SIZE:
                continue  # closed since the descriptor list was read
            info = ctypes.string_at(sock, _SOCKET_FDINFO_SIZE)
            if unpack_int(info, _OFF_KIND)[0] != _SOCKINFO_TCP:
                continue
            if unpack_int(info, _OFF_STATE)[0] != _TSI_S_LISTEN:
                continue
            family = unpack_int(info, _OFF_FAMILY)[0]
            if family not in (_AF_INET, _AF_INET6):
                continue
            port = socket.ntohs(unpack_int(info, _OFF_LPORT)[0] & 0xFFFF)
            if not 1 <= port <= 65535:
                continue
            address = _address(family, info)
            if address is None:
                return None
            listeners.append((fd, family, f"{address}:{port}", port))
        if not listeners:
            continue
        if lib.proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, bsd, _BSDINFO_SIZE) != _BSDINFO_SIZE:
            continue  # exited since its descriptors were read
        bsdinfo = ctypes.string_at(bsd, _BSDINFO_SIZE)
        uid = struct.unpack_from("<I", bsdinfo, _OFF_UID)[0]
        comm = bsdinfo[_OFF_COMM:_OFF_COMM + _COMM_SIZE]
        command = _lsof_command(comm.split(b"\0", 1)[0])
        if not command:
            return None
        for fd, family, name, port in listeners:
            rows.append(Listener(command, pid, uid, fd, family, name, port))
    return rows
