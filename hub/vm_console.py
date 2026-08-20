"""Authenticated web console (VNC/RFB) bridge for UTM virtual machines.

Design constraints that shape this module:

* The browser never names a target.  It sends an opaque ``console_id`` and the
  endpoint is resolved server-side from ``settings.vm_console.allowlist``, so a
  logged-in page cannot turn the panel into a generic TCP proxy.
* Only loopback endpoints are accepted.  A VNC listener reachable from the LAN
  would bypass panel authentication entirely, so a non-loopback configuration is
  refused rather than silently proxied.
* The 7-day browser session is too coarse to authorise a raw byte bridge, so a
  console URL carries a single-use, short-lived ticket bound to that session.
* OrbStack machines have no virtual display.  They report a stable reason
  instead of a console the operator could click but never use.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

# Imported at module scope even though `from __future__ import annotations`
# defers the annotation: FastAPI resolves the signature when the route is
# registered, so a lazily-typed WebSocket would fail at startup, not import.
from fastapi import WebSocket

from hub.config import settings_section

#: A console ticket only has to survive the round trip from the REST response to
#: the WebSocket upgrade the browser opens immediately afterwards.
TICKET_TTL_SECONDS = 30
MAX_SESSIONS = 4
MAX_SESSIONS_PER_USER = 2
MAX_SESSIONS_PER_VM = 1
IDLE_TIMEOUT_SECONDS = 15 * 60
MAX_SESSION_SECONDS = 60 * 60
CONNECT_TIMEOUT_SECONDS = 3.0
#: RFB framebuffer updates are large; read in chunks and await every send so a
#: slow browser applies backpressure instead of growing an unbounded queue.
READ_SIZE = 64 * 1024
MAX_CLIENT_FRAME_BYTES = 256 * 1024
#: Ticket minting is cheap for the server but is the entry point to a byte
#: bridge, so it is rate limited per administrator independently of session caps.
TICKET_RATE_LIMIT = 10
TICKET_RATE_WINDOW = 60.0

_CONSOLE_ID_RE = re.compile(r"^utm:[0-9A-Fa-f-]{36}$")


@dataclass(frozen=True)
class ConsoleTarget:
    """A resolved, loopback-only console endpoint."""

    console_id: str
    vm_uuid: str
    protocol: str
    host: str
    port: int
    view_only: bool


@dataclass
class _Ticket:
    digest: str
    console_id: str
    user: str
    session_digest: str
    view_only: bool
    expires_at: float


@dataclass
class _Session:
    session_id: str
    console_id: str
    user: str
    started: float


_tickets: dict[str, _Ticket] = {}
_sessions: dict[str, _Session] = {}
#: Ticket-mint timestamps per admin user, so a scripted loop cannot mint an
#: unbounded number of short-lived bridge authorisations.
_ticket_requests: dict[str, list[float]] = {}
_lock = threading.Lock()


def console_id_for_utm(vm_uuid: str) -> str:
    """Stable console identifier.

    Keyed by UUID rather than the VM name: a rename must never silently move an
    authorisation to a different machine.
    """
    return f"utm:{vm_uuid}"


def _allowlist() -> dict[str, Any]:
    settings = settings_section("vm_console")
    allowlist = settings.get("allowlist")
    return allowlist if isinstance(allowlist, dict) else {}


def _entry_for(vm_uuid: str) -> dict[str, Any] | None:
    allowlist = _allowlist()
    for key, value in allowlist.items():
        if str(key).strip().lower() == str(vm_uuid).strip().lower():
            return value if isinstance(value, dict) else None
    return None


def _as_host_text(value) -> str:
    """Allowlist host as text.  YAML ``!!binary`` is bytes; leftover numbers are not hosts."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return ""
    if not isinstance(value, str):
        return ""
    return value.strip()


def _is_loopback(host: str) -> bool:
    """True only when *host* can exclusively resolve to a loopback address.

    Resolution is checked rather than pattern-matched: a name that resolves off
    the loopback interface (or to a mix of addresses) is rejected, which also
    rules out DNS-rebinding style configuration mistakes.
    """
    text = _as_host_text(host)
    # Control characters (NUL) used to truncate ``127.0.0.1\\x00evil`` at the
    # resolver.  A leftover 10k host used to UnicodeError ``getaddrinfo`` and
    # 500 GET /api/vms via capability().  YAML ``!!binary`` host used to
    # TypeError ``ord()`` on bytes.
    if not text or len(text) > 253:
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        return False
    try:
        return ipaddress.ip_address(text).is_loopback
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        infos = socket.getaddrinfo(text, None, proto=socket.IPPROTO_TCP)
    except (OSError, TypeError, ValueError, UnicodeError, OverflowError):
        return False
    if not infos:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_loopback:
                return False
        except (TypeError, ValueError, IndexError, OverflowError):
            return False
    return True


def resolve_target(console_id: str, *, vm_uuid: str | None = None) -> ConsoleTarget | None:
    """Resolve a console_id to its configured loopback endpoint, or None."""
    text = console_id.strip() if isinstance(console_id, str) else ""
    if not _CONSOLE_ID_RE.match(text):
        return None
    uuid = text.split(":", 1)[1]
    if vm_uuid is not None and uuid.lower() != str(vm_uuid).strip().lower():
        return None
    entry = _entry_for(uuid)
    if not entry or not entry.get("enabled"):
        return None
    protocol = str(entry.get("protocol") or "vnc").strip().lower()
    if protocol != "vnc":
        return None
    raw_host = entry.get("host")
    host = "127.0.0.1" if raw_host in (None, "") else _as_host_text(raw_host)
    if not host:
        return None
    raw_port = entry.get("port")
    # Bool is an int (``True`` → port 1).  JSON ``1e309`` / YAML ``port: .inf``
    # OverflowError ``int(inf)``; a 400-digit leftover int is not a TCP port.
    if isinstance(raw_port, bool):
        return None
    try:
        port = int(raw_port or 0)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 1 <= port <= 65535 or not _is_loopback(host):
        return None
    return ConsoleTarget(
        console_id=console_id_for_utm(uuid),
        vm_uuid=uuid,
        protocol=protocol,
        host=host,
        port=port,
        view_only=bool(entry.get("view_only")),
    )


def capability(*, backend: str, vm_uuid: str, running: bool) -> dict[str, Any]:
    """Safe console summary for /api/vms.

    Deliberately omits host, port and any credential: the list endpoint is the
    broadest surface in the panel and must not leak an internal endpoint map.
    """
    if backend != "utm":
        return {"available": False, "protocol": None, "reason": "vm_console.no_graphical_console"}
    target = resolve_target(console_id_for_utm(vm_uuid))
    if target is None:
        return {"available": False, "protocol": None, "reason": "vm_console.not_configured"}
    if not running:
        return {"available": False, "protocol": target.protocol, "reason": "vm_console.vm_not_running"}
    return {
        "available": True,
        "protocol": target.protocol,
        "reason": None,
        "view_only": target.view_only,
    }


def _digest(value: str) -> str:
    # Cookie / query leftovers can carry ``\\ud800``; strict UTF-8 used to 500
    # POST /api/vms/.../console/session and the WebSocket upgrade.
    return hashlib.sha256(str(value).encode("utf-8", "surrogatepass")).hexdigest()


def _now() -> float:
    """Finite wall clock. Leftover ``time.time() = inf`` used to poison ticket expiry."""
    try:
        n = float(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
        return 0.0
    return n


def _purge_expired_locked(now: float) -> None:
    for key in [k for k, t in _tickets.items() if t.expires_at <= now]:
        _tickets.pop(key, None)


def issue_ticket(target: ConsoleTarget, *, user: str, session_token: str) -> dict[str, Any]:
    """Mint a single-use ticket bound to this admin session and VM."""
    ticket = secrets.token_urlsafe(32)
    now = _now()
    record = _Ticket(
        digest=_digest(ticket),
        console_id=target.console_id,
        user=user,
        session_digest=_digest(session_token),
        view_only=target.view_only,
        expires_at=now + TICKET_TTL_SECONDS,
    )
    with _lock:
        _purge_expired_locked(now)
        _tickets[record.digest] = record
    return {
        "ticket": ticket,
        "expires_in": TICKET_TTL_SECONDS,
        "view_only": target.view_only,
        "max_session_seconds": MAX_SESSION_SECONDS,
    }


def consume_ticket(ticket: str | None, *, console_id: str, user: str, session_token: str) -> _Ticket | None:
    """Validate and burn a ticket. Returns None when it must be refused."""
    if not ticket:
        return None
    digest = _digest(ticket)
    now = _now()
    with _lock:
        _purge_expired_locked(now)
        record = _tickets.get(digest)
        if record is None:
            return None
        # Single use: remove before any further check so a replay always fails.
        _tickets.pop(digest, None)
    if record.expires_at <= now:
        return None
    if record.console_id != console_id or record.user != user:
        return None
    if not hmac.compare_digest(record.session_digest, _digest(session_token)):
        return None
    return record


def allow_ticket_request(user: str) -> bool:
    """Throttle ticket minting so a stolen page cannot farm console URLs."""
    now = _now()
    with _lock:
        recent = [t for t in _ticket_requests.get(user, []) if now - t < TICKET_RATE_WINDOW]
        if len(recent) >= TICKET_RATE_LIMIT:
            _ticket_requests[user] = recent
            return False
        recent.append(now)
        _ticket_requests[user] = recent
        return True


def reserve_session(*, console_id: str, user: str) -> _Session | None:
    with _lock:
        if len(_sessions) >= MAX_SESSIONS:
            return None
        if sum(s.user == user for s in _sessions.values()) >= MAX_SESSIONS_PER_USER:
            return None
        if sum(s.console_id == console_id for s in _sessions.values()) >= MAX_SESSIONS_PER_VM:
            return None
        session = _Session(secrets.token_urlsafe(12), console_id, user, time.monotonic())
        _sessions[session.session_id] = session
        return session


def release_session(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)


def active_sessions() -> int:
    with _lock:
        return len(_sessions)


async def bridge(websocket, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[str, int, int]:
    """Pump bytes both ways until either side ends.

    Returns ``(reason, bytes_from_client, bytes_to_client)``.  Every transfer is
    awaited, so a slow consumer throttles the producer instead of buffering an
    entire framebuffer in memory.
    """
    from fastapi import WebSocketDisconnect

    state = {"reason": "disconnect", "up": 0, "down": 0, "last": time.monotonic()}

    async def to_vnc() -> None:
        while True:
            message = await websocket.receive()
            kind = message.get("type")
            if kind == "websocket.disconnect":
                state["reason"] = "disconnect"
                return
            data = message.get("bytes")
            if data is None:
                # RFB is a binary protocol; a text frame means a non-conforming
                # client, not something to translate.
                state["reason"] = "protocol_error"
                return
            if len(data) > MAX_CLIENT_FRAME_BYTES:
                state["reason"] = "frame_too_large"
                return
            state["up"] += len(data)
            state["last"] = time.monotonic()
            writer.write(data)
            await writer.drain()

    async def to_browser() -> None:
        while True:
            chunk = await reader.read(READ_SIZE)
            if not chunk:
                state["reason"] = "console_closed"
                return
            state["down"] += len(chunk)
            state["last"] = time.monotonic()
            await websocket.send_bytes(chunk)

    async def watchdog() -> None:
        started = time.monotonic()
        while True:
            await asyncio.sleep(5)
            now = time.monotonic()
            if now - started >= MAX_SESSION_SECONDS:
                state["reason"] = "max_duration"
                return
            if now - state["last"] >= IDLE_TIMEOUT_SECONDS:
                state["reason"] = "idle_timeout"
                return

    tasks = [
        asyncio.create_task(to_vnc()),
        asyncio.create_task(to_browser()),
        asyncio.create_task(watchdog()),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            try:
                task.result()
            except WebSocketDisconnect:
                state["reason"] = "disconnect"
            except (BrokenPipeError, ConnectionResetError):
                state["reason"] = "console_closed"
            except Exception:
                state["reason"] = "io_error"
    finally:
        for task in tasks:
            task.cancel()
    return str(state["reason"]), int(state["up"]), int(state["down"])


async def console_websocket(websocket: WebSocket, console_id: str) -> None:
    """Bridge one authenticated browser socket to a VM's loopback VNC port.

    Every check runs before ``accept()``: the browser session, an exact
    Origin/Host match, a single-use ticket bound to that session and VM, the VM
    still running, and the target still resolving to loopback in the current
    config.
    """
    from hub import terminal_svc, vms_svc
    from hub.websocket_security import authenticate_websocket, reject_websocket

    authenticated = await authenticate_websocket(websocket)
    if authenticated is None:
        return
    session_token, user = authenticated

    target = resolve_target(console_id)
    if target is None:
        await reject_websocket(websocket, 4404, "vm_console.unavailable")
        return

    ticket = consume_ticket(
        websocket.query_params.get("ticket"),
        console_id=target.console_id,
        user=user,
        session_token=session_token,
    )
    if ticket is None:
        await reject_websocket(websocket, 4401, "vm_console.invalid_ticket")
        return

    # Re-checked after the ticket is burned: a VM that stopped, or an allowlist
    # entry revoked, between issuing and connecting must not still open.
    # In a worker thread: this runs `utmctl` twice (up to 10s each) and this
    # handler is on the event loop — inline it would freeze every request in
    # the process for the duration.
    if not await asyncio.to_thread(vms_svc.utm_vm_running, target.vm_uuid):
        await reject_websocket(websocket, 4404, "vm_console.unavailable")
        return

    session = reserve_session(console_id=target.console_id, user=user)
    if session is None:
        await reject_websocket(websocket, 4429, "vm_console.too_many_sessions")
        return

    reader = writer = None
    started = time.monotonic()
    reason = "connect_failed"
    sent = received = 0
    try:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError):
            await reject_websocket(websocket, 4502, "vm_console.connect_failed")
            return

        await websocket.accept()
        terminal_svc._audit({
            "ts": terminal_svc._now(), "event": "vm_console_start",
            "session": session.session_id, "console": target.console_id,
            "who": user, "view_only": bool(ticket.view_only),
        })
        reason, sent, received = await bridge(websocket, reader, writer)
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
            try:
                await writer.wait_closed()
            except Exception:
                pass
        release_session(session.session_id)
        terminal_svc._audit({
            "ts": terminal_svc._now(), "event": "vm_console_end",
            "session": session.session_id, "console": target.console_id,
            "who": user, "reason": reason,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "bytes_from_client": sent, "bytes_to_client": received,
        })
        try:
            await websocket.close(code=1000 if reason == "console_closed" else 1001)
        except Exception:
            pass

