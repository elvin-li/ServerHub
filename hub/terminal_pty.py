"""Authenticated interactive PTY sessions for the terminal WebSocket.

This endpoint is intentionally stricter than ordinary API routes.  A terminal is
remote code execution, so it always requires a valid browser session even when
``settings.auth.enabled`` is false, requires an exact same-origin WebSocket
upgrade, and keeps the existing explicit host-terminal switch.
"""
from __future__ import annotations

import asyncio
import errno
import fcntl
import json
import os
import pty
import re
import secrets
import signal
import struct
import subprocess
import termios
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from fastapi import WebSocket, WebSocketDisconnect

from hub.paths import DOCKER
from hub import terminal_svc
from hub.errors import exc_detail
from hub.util import safe_json_loads
from hub.websocket_security import authenticate_websocket

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    Fail-closed: a raising ``__class__`` property cannot 500 a JSON route.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False

_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

MAX_SESSIONS = 4
MAX_SESSIONS_PER_USER = 2
MAX_INPUT_BYTES = 64 * 1024
MAX_MESSAGE_BYTES = 70 * 1024
MAX_COLS = 500
MAX_ROWS = 300
IDLE_TIMEOUT = 15 * 60
MAX_SESSION_SECONDS = 60 * 60
READ_SIZE = 16 * 1024


@dataclass
class _Session:
    session_id: str
    user: str
    target: str
    container: str
    started: float


_sessions: dict[str, _Session] = {}
_sessions_lock = threading.Lock()


def _bounded_int(value: str | int | None, default: int, low: int, high: int) -> int:
    # Bool is an int, and JSON ``1e309`` is ``inf`` — ``int(inf)`` OverflowError
    # used to kill the PTY session as ``io_error`` on a resize frame.
    if type(value) is bool or value is None:
        parsed = default
    else:
        try:
            parsed = int(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            parsed = default
    return max(low, min(parsed, high))


def _safe_arg(value: str | None, *, max_len: int = 255) -> str:
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            text = base.decode(value, "utf-8", "replace")
            break
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    else:
        try:
            text = str.__str__(value) if type(value) is str else str(value)
        except RecursionError:
            return ""
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8").strip()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    if _ADDR_REPR_RE.search(text):
        return ""
    if len(text) > max_len or "\x00" in text or "\n" in text or "\r" in text:
        return ""
    return text


def _safe_container(value: str | None) -> str:
    """Return a Docker name/id that cannot be parsed as a CLI option."""
    text = _safe_arg(value)
    if not text or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", text):
        return ""
    return text


def _json_object(text: str) -> dict | None:
    """Control-plane JSON from the browser.  A list used to raise ``.get``."""
    try:
        payload = safe_json_loads(text, loads=json.loads)
    except (TypeError, ValueError, RecursionError):
        return None
    return payload if _isinst(payload, dict) else None


def _argv(target: str, container: str, shell: str) -> tuple[list[str], str | None]:
    if target == "host":
        if not terminal_svc.host_enabled():
            raise PermissionError("terminal.host_disabled")
        host_shell = shell or terminal_svc._default_shell()
        try:
            ok = Path(host_shell).is_file()
        except (OSError, ValueError):
            ok = False
        if not ok:
            host_shell = terminal_svc._default_shell()
        return [host_shell, "-l"], terminal_svc._resolve_cwd(None)
    if target == "container":
        if not container:
            raise ValueError("terminal.no_container")
        container_shell = shell or "/bin/sh"
        return [DOCKER, "exec", "-it", container, container_shell], None
    raise ValueError("terminal.bad_target")


async def _write_all(fd: int, data: bytes) -> None:
    """Write to the non-blocking PTY fd without dying on a full buffer.

    A large paste fills the kernel PTY buffer faster than the shell drains it;
    a bare ``os.write`` then raises ``BlockingIOError``, which the generic
    handler used to turn into an ``io_error`` close — the paste killed the
    session.  Retrying after a short yield lets the shell catch up.
    """
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            await asyncio.sleep(0.01)
            continue
        view = view[written:]


def _set_size(fd: int, cols: int, rows: int) -> None:
    packed = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)
    except OSError:
        # A failed resize must not tear the session down; the shell keeps the
        # previous window size.
        pass


def _reserve(user: str, target: str, container: str) -> _Session | None:
    with _sessions_lock:
        if len(_sessions) >= MAX_SESSIONS:
            return None
        if sum(s.user == user for s in _sessions.values()) >= MAX_SESSIONS_PER_USER:
            return None
        session = _Session(secrets.token_urlsafe(12), user, target, container, time.monotonic())
        _sessions[session.session_id] = session
        return session


def _release(session_id: str) -> None:
    with _sessions_lock:
        _sessions.pop(session_id, None)


async def _reject(websocket: WebSocket, code: int, error: str) -> None:
    # Accepting first lets the first-party UI receive a machine-readable reason.
    # Authentication failures still reveal no credentials or server state.
    await websocket.accept()
    await websocket.send_json({"type": "error", "code": error})
    await websocket.close(code=code)


def _sync_reap(proc: subprocess.Popen | None) -> int | None:
    """Kill and reap the child with no awaits, for the cancelled-cleanup path.

    When the handler task is being torn down, every ``await`` in the cleanup
    re-raises CancelledError, so the graceful SIGHUP-then-wait sequence cannot
    run.  Blocking the (already tearing-down) event loop for up to a second
    here is the lesser evil: the alternative was leaking the shell as a
    zombie child of the panel process.
    """
    if proc is None:
        return None
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        return proc.wait(timeout=1.0)
    except (subprocess.TimeoutExpired, OSError):
        return proc.poll()


async def terminal_websocket(websocket: WebSocket) -> None:
    authenticated = await authenticate_websocket(websocket)
    if authenticated is None:
        return
    _, user = authenticated

    target = _safe_arg(websocket.query_params.get("target"), max_len=16) or "host"
    container = _safe_container(websocket.query_params.get("container"))
    shell = _safe_arg(websocket.query_params.get("shell"))
    cols = _bounded_int(websocket.query_params.get("cols"), 100, 20, MAX_COLS)
    rows = _bounded_int(websocket.query_params.get("rows"), 30, 5, MAX_ROWS)
    try:
        argv, cwd = _argv(target, container, shell)
    except PermissionError as exc:
        await _reject(websocket, 4403, exc_detail(exc))
        return
    except ValueError as exc:
        await _reject(websocket, 4400, exc_detail(exc))
        return

    session = _reserve(user, target, container)
    if session is None:
        await _reject(websocket, 4429, "terminal.too_many_sessions")
        return

    master_fd = slave_fd = -1
    proc: subprocess.Popen[bytes] | None = None
    tasks: list[asyncio.Task] = []
    started = time.monotonic()
    last_input = started
    close_reason = "disconnect"
    input_bytes = 0
    try:
        # Inside the try: a client that vanishes (or a cancellation that
        # lands) during the accept must still release the reservation.
        await websocket.accept()
        master_fd, slave_fd = pty.openpty()
        _set_size(master_fd, cols, rows)
        env = terminal_svc._color_env()
        env.update({"TERM": "xterm-256color", "COLORTERM": "truecolor"})
        proc = subprocess.Popen(
            argv,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=cwd,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave_fd)
        slave_fd = -1
        os.set_blocking(master_fd, False)
        terminal_svc._audit({
            "ts": terminal_svc._now(), "event": "pty_start", "session": session.session_id,
            "target": target, "container": container, "who": user,
        })
        await websocket.send_json({
            "type": "ready", "session": session.session_id,
            "target": target, "container": container,
            "limits": {"idle_seconds": IDLE_TIMEOUT, "max_seconds": MAX_SESSION_SECONDS},
        })

        async def output_loop() -> None:
            nonlocal close_reason
            # Adaptive idle backoff: a fixed 15ms sleep woke the loop ~66
            # times a second per idle terminal, continuously, for sessions
            # that live up to an hour.  Backing off toward 200ms while idle
            # cuts that to ~5/s with no perceptible echo latency, and one
            # keystroke's output resets it to 15ms instantly.
            idle_sleep = 0.015
            while proc is not None and proc.poll() is None:
                try:
                    chunk = os.read(master_fd, READ_SIZE)
                except BlockingIOError:
                    await asyncio.sleep(idle_sleep)
                    idle_sleep = min(idle_sleep * 1.5, 0.2)
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:  # normal PTY EOF on macOS/Linux
                        break
                    raise
                if chunk:
                    idle_sleep = 0.015
                    await websocket.send_bytes(chunk)
                else:
                    await asyncio.sleep(idle_sleep)
                    idle_sleep = min(idle_sleep * 1.5, 0.2)
            # Drain the final bytes emitted while the process exited.
            for _ in range(8):
                try:
                    chunk = os.read(master_fd, READ_SIZE)
                except (BlockingIOError, OSError):
                    break
                if not chunk:
                    break
                await websocket.send_bytes(chunk)
            close_reason = "process_exit"

        async def input_loop() -> None:
            nonlocal last_input, input_bytes, close_reason
            while True:
                message = await websocket.receive()
                if message.get("type") == "websocket.disconnect":
                    raise WebSocketDisconnect(message.get("code", 1000))
                raw = message.get("bytes")
                text = message.get("text")
                if raw is not None:
                    data = raw
                    input_bytes += len(data)
                    if len(data) > MAX_MESSAGE_BYTES or input_bytes > MAX_INPUT_BYTES:
                        close_reason = "input_limit"
                        return
                    await _write_all(master_fd, data)
                    last_input = time.monotonic()
                    continue
                if text is None or len(text.encode("utf-8", "replace")) > MAX_MESSAGE_BYTES:
                    close_reason = "input_limit"
                    return
                payload = _json_object(text)
                if payload is None:
                    continue
                kind = payload.get("type")
                if kind == "input":
                    # JSON ``"\\ud800"`` is a str; strict UTF-8 used to kill the
                    # session as ``io_error`` instead of replacing the leftover.
                    data = str(payload.get("data") or "").encode("utf-8", "replace")
                    input_bytes += len(data)
                    if input_bytes > MAX_INPUT_BYTES:
                        close_reason = "input_limit"
                        return
                    await _write_all(master_fd, data)
                    last_input = time.monotonic()
                elif kind == "resize":
                    new_cols = _bounded_int(payload.get("cols"), cols, 20, MAX_COLS)
                    new_rows = _bounded_int(payload.get("rows"), rows, 5, MAX_ROWS)
                    _set_size(master_fd, new_cols, new_rows)
                elif kind == "ping":
                    last_input = time.monotonic()

        async def watchdog() -> None:
            nonlocal close_reason
            while proc is not None and proc.poll() is None:
                await asyncio.sleep(5)
                now = time.monotonic()
                if now - started >= MAX_SESSION_SECONDS:
                    close_reason = "max_duration"
                    return
                if now - last_input >= IDLE_TIMEOUT:
                    close_reason = "idle_timeout"
                    return

        tasks = [asyncio.create_task(output_loop()), asyncio.create_task(input_loop()), asyncio.create_task(watchdog())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            try:
                task.result()
            except WebSocketDisconnect:
                close_reason = "disconnect"
            except _CONTROL_FLOW:
                raise
            except BaseException:
                close_reason = "io_error"
    except (WebSocketDisconnect, BrokenPipeError, ConnectionResetError):
        close_reason = "disconnect"
    except (OSError, TypeError, ValueError):
        # FileNotFoundError is OSError; cwd EIO/ESTALE and a missing PTY
        # used to escape the FileNotFoundError-only handler as a 500.
        close_reason = "not_found"
        try:
            await websocket.send_json({"type": "error", "code": "terminal.runtime_not_found"})
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    finally:
        # A transport-level cancellation — the server tearing this handler
        # task down after the client vanished, or a shutdown sweep — lands
        # CancelledError on the *first await inside this finally* (the
        # SIGHUP grace sleep), and under anyio-style level cancellation every
        # later await re-raises it too.  The SIGKILL escalation, the fd
        # closes, the child reap, the pty_end audit line and _release() were
        # all skipped: two abrupt disconnects per user (four global) then
        # ratcheted the reservation caps into a *permanent*
        # terminal.too_many_sessions lockout, and every leaked shell stayed
        # an unreaped child.  The must-run bookkeeping is now synchronous and
        # runs on the cancelled path as well.
        for task in tasks:
            if not task.done():
                task.cancel()

        def _finish(code) -> None:
            """No awaits, never raises: runs on both the normal and the
            cancelled path, exactly once."""
            for fd in (master_fd, slave_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            # Retrieve finished tasks' exceptions synchronously so a
            # cancelled-path WebSocketDisconnect from input_loop is not left
            # as an "exception was never retrieved" loop warning.
            for task in tasks:
                if task.done() and not task.cancelled():
                    task.exception()
            terminal_svc._audit({
                "ts": terminal_svc._now(), "event": "pty_end", "session": session.session_id,
                "target": target, "container": container, "who": user,
                "rc": code,
                "duration_ms": terminal_svc._duration_ms(started, time.monotonic()),
                "reason": close_reason, "input_bytes": input_bytes,
            })
            _release(session.session_id)

        rc = None
        try:
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGHUP)
                    await asyncio.sleep(0.15)
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            if proc is not None:
                # Reap the child after signalling it.  poll() alone observes
                # status but does not guarantee a terminated child has been
                # waited for, which can accumulate zombies across many
                # terminal sessions.
                try:
                    rc = await asyncio.to_thread(proc.wait, 1.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        rc = await asyncio.to_thread(proc.wait, 1.0)
                    except subprocess.TimeoutExpired:
                        rc = proc.poll()
        except BaseException:
            # CancelledError mid-cleanup (or RuntimeError from to_thread on a
            # closing loop): finish synchronously, then let the cancellation
            # propagate — the reservation and the child must not outlive it.
            _finish(_sync_reap(proc))
            raise
        _finish(rc)
        try:
            await websocket.close(code=1000 if close_reason == "process_exit" else 1001)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
