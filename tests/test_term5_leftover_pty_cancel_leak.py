"""Terminal leftover sweep #5: the PTY teardown must survive cancellation.

The live leftover this sweep found (terms 1-4 never drove an *abrupt* client
disconnect through the mounted route): when the transport tears the handler
task down — the client's TCP vanishing while the server cancels the ASGI
task, a shutdown sweep, or the TestClient/anyio portal closing — the
CancelledError landed on the first ``await`` inside ``terminal_websocket``'s
``finally`` (the SIGHUP grace sleep).  Everything below it was skipped:

* ``_release(session.session_id)`` never ran, so the reservation leaked
  forever.  MAX_SESSIONS_PER_USER is 2 and MAX_SESSIONS is 4: two abrupt
  disconnects per user ratcheted the caps into a *permanent*
  ``terminal.too_many_sessions`` (4429) lockout for the life of the process —
  the WS-surface equivalent of an unhandled 500;
* the SIGKILL escalation and the ``proc.wait`` reap were skipped, leaving
  the shell an unreaped child;
* both PTY fds stayed open;
* the ``pty_end`` audit line — the only record that a root-capable shell
  session ended — was never written (``pty_start`` had no matching end);
* ``input_loop``'s WebSocketDisconnect was left as an "exception was never
  retrieved" loop warning.

The fix makes the must-run bookkeeping synchronous (``_finish``: fd closes,
pty_end audit, release) and runs it on the cancelled path as well, reaping
the child without awaits (``_sync_reap``) before re-raising the
cancellation.  ``websocket.accept()`` also moved inside the try so a client
that vanishes mid-accept cannot leak the reservation either.

These pins drive the real mounted app over Starlette's TestClient, whose
context exit cancels the handler task mid-session — exactly the transport
behaviour that used to leak.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import terminal_pty, terminal_svc
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


async def _admin_auth(_websocket):
    return ("tok", "admin")


class _PtySandbox(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term5-cancel-"))
        self.audit = self.dir / "terminal-audit.jsonl"
        for patched in (
            mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit),
            mock.patch.object(terminal_pty, "authenticate_websocket", new=_admin_auth),
            mock.patch.object(
                terminal_svc,
                "settings_section",
                return_value={"host_enabled": True, "shell": "/bin/sh"},
            ),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        with terminal_pty._sessions_lock:
            terminal_pty._sessions.clear()
        self.client = _client()

    def tearDown(self):
        with terminal_pty._sessions_lock:
            leaked = dict(terminal_pty._sessions)
            terminal_pty._sessions.clear()
        self.assertEqual(leaked, {}, "PTY session reservation leaked")

    def _sessions(self) -> dict:
        with terminal_pty._sessions_lock:
            return dict(terminal_pty._sessions)

    def _abrupt_session(self) -> None:
        """Open a live host PTY, then vanish without a close handshake.

        The TestClient context exit cancels the handler task while the
        session is live — the transport-level teardown that used to skip
        the whole cleanup.
        """
        ws = self.client.websocket_connect("/api/terminal/ws?target=host")
        conn = ws.__enter__()
        ready = conn.receive_json()
        self.assertEqual(ready["type"], "ready", ready)
        ws.__exit__(None, None, None)

    def _wait_released(self, deadline_s: float = 10.0) -> dict:
        deadline = time.monotonic() + deadline_s
        while self._sessions() and time.monotonic() < deadline:
            time.sleep(0.05)
        return self._sessions()

    def _audit_events(self) -> list[str]:
        if not self.audit.exists():
            return []
        out = []
        for line in self.audit.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line).get("event"))
            except ValueError:
                continue
        return out


class AbruptDisconnectReleasePinTests(_PtySandbox):
    def test_cancelled_teardown_releases_the_reservation(self):
        self._abrupt_session()
        self.assertEqual(self._wait_released(), {},
                         "abrupt disconnect leaked the session reservation")

    def test_cancelled_teardown_still_writes_the_pty_end_audit(self):
        # The trail is the only record of a root-capable shell session; the
        # cancelled path used to end sessions with pty_start and no pty_end.
        self._abrupt_session()
        self._wait_released()
        events = self._audit_events()
        self.assertEqual(events.count("pty_start"), 1, events)
        self.assertEqual(events.count("pty_end"), 1, events)

    def test_abrupt_disconnects_do_not_ratchet_into_the_429_lockout(self):
        # MAX_SESSIONS_PER_USER is 2: three leaked reservations would already
        # refuse this user forever.  Five abrupt sessions, then a normal one
        # must still be the ready frame, never terminal.too_many_sessions.
        for _ in range(5):
            self._abrupt_session()
            self._wait_released()
        with self.client.websocket_connect("/api/terminal/ws?target=host") as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            ws.send_text('{"type":"input","data":"exit\\n"}')
            for _ in range(1000):
                if ws.receive()["type"] == "websocket.close":
                    break
            else:
                self.fail("server never closed the normal session")

    def test_normal_exit_path_is_unchanged_by_the_restructure(self):
        # Clean exit: shell output flows, close code 1000, reservation
        # released, both audit lines written.
        with self.client.websocket_connect("/api/terminal/ws?target=host") as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            ws.send_text('{"type":"input","data":"exit\\n"}')
            saw_bytes = False
            for _ in range(1000):
                message = ws.receive()
                if message.get("bytes"):
                    saw_bytes = True
                if message["type"] == "websocket.close":
                    break
            else:
                self.fail("server never closed")
        self.assertTrue(saw_bytes, "no PTY output before close")
        self.assertEqual(self._wait_released(), {})
        events = self._audit_events()
        self.assertEqual(events.count("pty_start"), 1, events)
        self.assertEqual(events.count("pty_end"), 1, events)


if __name__ == "__main__":
    unittest.main()
