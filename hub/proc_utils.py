"""Process-table lookups shared by launchd discovery.

App-managed helpers (Baidu Netdisk and similar) keep a LaunchAgent loaded
that exits on a singleton lock while the same binary is already running
outside launchd.  Discovery needs the live PIDs of that binary — and it
must not find them with ``pgrep -f <basename>``, which matches unrelated
host processes (``true``, ``zsh``, ``cloudflared``) and reports exited
jobs as healthy.

The table is the shared ``ps aux`` snapshot in :mod:`hub.proc_cache`.
Matching is by full command prefix (joined ProgramArguments) or, for a
single absolute path, that path as argv0.  Basename-only needles are
rejected.
"""
from __future__ import annotations

import re

from hub.proc_cache import ps_pid_commands

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew unguarded gates in ``ps`` COMMAND rows and
    launchd ProgramArguments — GET /api/status answered HTTP 500 instead
    of dropping the junk cell.  Fail-closed.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """Drop leftover types / lone surrogates so a bad ``ps`` row cannot 500."""
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


def _absolute_needle(value) -> str:
    """An absolute argv0 / command prefix, or ``""`` if it must not match.

    Relative paths and bare names (``true``, ``zsh``) are how the pgrep
    fallback adopted host processes.  A trailing slash is not an executable.
    """
    text = _as_text(value).strip()
    if not text.startswith("/") or text.endswith("/"):
        return ""
    return text


def _pids_with_command_prefix(prefix: str) -> list[int]:
    if not prefix:
        return []
    try:
        rows = ps_pid_commands()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    found: list[int] = []
    seen: set[int] = set()
    for pid, cmd in rows:
        text = cmd if _isinst(cmd, str) else _as_text(cmd)
        if text != prefix and not text.startswith(prefix + " "):
            continue
        if pid in seen:
            continue
        seen.add(pid)
        found.append(pid)
    return found


def pids_for_exe(exe: str) -> list[int]:
    """PIDs whose ``ps`` COMMAND is absolute path *exe* as argv0.

    A process matches when COMMAND equals *exe* or is *exe* plus arguments.
    *exe* must be an absolute path; basename-only needles return no PIDs.
    """
    return _pids_with_command_prefix(_absolute_needle(exe))


def _program_arguments(arguments) -> list[str]:
    if not _isinst(arguments, (list, tuple)):
        return []
    out: list[str] = []
    for item in arguments:
        text = _as_text(item).strip()
        if text:
            out.append(text)
    return out


def pids_for_argv(arguments) -> list[int]:
    """PIDs matching launchd ``ProgramArguments``.

    Joined arguments are a command-line prefix, so
    ``["/bin/zsh", "/tmp/job.sh"]`` does not match a login ``zsh``.  A
    single absolute path uses :func:`pids_for_exe` (exact argv0).
    """
    args = _program_arguments(arguments)
    if not args:
        return []
    if not _absolute_needle(args[0]):
        return []
    if len(args) == 1:
        return pids_for_exe(args[0])
    # Prefer the full ProgramArguments prefix.  If nothing matches, accept a
    # process whose COMMAND is exactly argv0 (no extra args).  Baidu Netdisk's
    # agent lists ``--hidden`` while the live helper often runs bare; do NOT
    # use pids_for_exe here — that would also match ``cloudflared --version``
    # when the agent asked for ``cloudflared tunnel run``.
    found = _pids_with_command_prefix(" ".join(args))
    if found:
        return found
    argv0 = args[0]
    try:
        rows = ps_pid_commands()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    out: list[int] = []
    seen: set[int] = set()
    for pid, cmd in rows:
        text = cmd if _isinst(cmd, str) else _as_text(cmd)
        if text != argv0 or pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
    return out
