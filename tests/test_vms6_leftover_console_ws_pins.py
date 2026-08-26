"""VMs leftover sweep #6: console WebSocket bridge stays-immune pins.

The vms5 sweep pinned the happy-path bridge, unauthenticated/bad-ticket
rejects and the mint rate limit.  This sweep drove the *lifecycle* edges of
the mounted WS route and found no live 500 — these pins hold that line:

* The per-VM session cap answers a coded error frame to the second
  concurrent bridge; the reservation is released after disconnect, so the
  cap never wedges shut.
* An oversize client frame and a text frame (RFB is binary) both end the
  session with a clean close — coded 1001, never an unhandled exception —
  and release the reservation.
* A refused loopback connect (nothing listening on the allowlisted port)
  answers the coded connect_failed error frame.
* An IPv6 loopback allowlist host (``::1``) bridges — loopback-only means
  loopback, not IPv4-only.
* An allowlist entry revoked between the mint and the upgrade, and a VM
  that stopped in that window, both answer the coded unavailable frame —
  the burned ticket buys nothing.
* Hostile ticket query values (percent-encoded lone surrogate, NUL, a 7k
  run) answer the coded invalid_ticket frame, never a digest/UTF-8 500.
"""
from __future__ import annotations

import contextlib
import socket
import threading
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, config, vm_console, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


async def _fake_auth(ws):
    return ("session-token", "admin")


class _WsCase(unittest.TestCase):
    def setUp(self):
        try:
            self._orig_yaml = config.YAML_PATH.read_bytes()
        except OSError:
            self._orig_yaml = None
        self.addCleanup(self._restore)
        self._reset_console_state()
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.client = TestClient(app, raise_server_exceptions=False)

    @staticmethod
    def _reset_console_state():
        with vm_console._lock:
            vm_console._sessions.clear()
            vm_console._tickets.clear()
            vm_console._ticket_requests.clear()

    def _restore(self):
        self._reset_console_state()
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass
        if self._orig_yaml is not None:
            config.YAML_PATH.write_bytes(self._orig_yaml)
        config.reload_cfg()
        vms_svc.invalidate_vm_lists()

    def _allow(self, port: int, host: str = "127.0.0.1"):
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(
            "settings:\n  vm_console:\n    allowlist:\n"
            f'      {_UUID}: {{enabled: true, host: "{host}", port: {port}}}\n',
            encoding="utf-8",
        )
        config.reload_cfg()

    def _start_fake_vnc(self, family=socket.AF_INET, addr="127.0.0.1"):
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((addr, 0))
        srv.listen(4)
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]

        def handle(conn):
            try:
                conn.sendall(b"RFB 003.008\n")
                while True:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        return port

    def _bridge_patches(self, running=True):
        return (
            mock.patch("hub.websocket_security.authenticate_websocket", _fake_auth),
            mock.patch.object(vms_svc, "utm_vm_running", return_value=running),
            mock.patch.object(audit, "record"),
        )

    def _ticket(self):
        target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        return vm_console.issue_ticket(
            target, user="admin", session_token="session-token",
        )["ticket"]

    def _connect(self, ticket):
        return self.client.websocket_connect(
            f"/api/vms/utm:{_UUID}/console/ws?ticket={ticket}"
        )

    def _assert_sessions_release(self, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with vm_console._lock:
                if not vm_console._sessions:
                    return
            time.sleep(0.05)
        with vm_console._lock:
            leaked = dict(vm_console._sessions)
        self.fail(f"console session reservation leaked: {leaked}")

    @staticmethod
    def _drain_to_close(ws, limit=50):
        """Read until the server's close frame; never block past it."""
        with contextlib.suppress(Exception):
            for _ in range(limit):
                message = ws.receive()
                if isinstance(message, dict) and message.get("type") == "websocket.close":
                    return message
        return None


class SessionLifecycleTests(_WsCase):
    def test_per_vm_cap_rejects_second_bridge_then_releases(self):
        port = self._start_fake_vnc()
        self._allow(port)
        p = self._bridge_patches()
        with p[0], p[1], p[2]:
            first, second = self._ticket(), self._ticket()
            with self._connect(first) as ws1:
                self.assertTrue(ws1.receive_bytes().startswith(b"RFB"))
                with self._connect(second) as ws2:
                    self.assertEqual(
                        ws2.receive_json(),
                        {"type": "error", "code": "vm_console.too_many_sessions"},
                    )
        self._assert_sessions_release()

    def test_oversize_client_frame_closes_cleanly(self):
        port = self._start_fake_vnc()
        self._allow(port)
        p = self._bridge_patches()
        with p[0], p[1], p[2]:
            with self._connect(self._ticket()) as ws:
                ws.receive_bytes()
                ws.send_bytes(b"z" * (vm_console.MAX_CLIENT_FRAME_BYTES + 1))
                close = self._drain_to_close(ws)
                if close is not None:
                    self.assertEqual(close.get("code"), 1001)
        self._assert_sessions_release()

    def test_text_frame_ends_binary_bridge_cleanly(self):
        port = self._start_fake_vnc()
        self._allow(port)
        p = self._bridge_patches()
        with p[0], p[1], p[2]:
            with self._connect(self._ticket()) as ws:
                ws.receive_bytes()
                ws.send_text("RFB is binary; this is a protocol error")
                close = self._drain_to_close(ws)
                if close is not None:
                    self.assertEqual(close.get("code"), 1001)
        self._assert_sessions_release()


class TargetEdgeTests(_WsCase):
    def test_refused_connect_answers_coded_frame(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        self._allow(dead_port)
        p = self._bridge_patches()
        with p[0], p[1], p[2]:
            with self._connect(self._ticket()) as ws:
                self.assertEqual(
                    ws.receive_json(),
                    {"type": "error", "code": "vm_console.connect_failed"},
                )
        self._assert_sessions_release()

    def test_ipv6_loopback_host_bridges(self):
        try:
            port = self._start_fake_vnc(socket.AF_INET6, "::1")
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        self._allow(port, host="::1")
        p = self._bridge_patches()
        with p[0], p[1], p[2]:
            with self._connect(self._ticket()) as ws:
                self.assertTrue(ws.receive_bytes().startswith(b"RFB"))
                ws.send_bytes(b"ping6")
                self.assertEqual(ws.receive_bytes(), b"ping6")
        self._assert_sessions_release()

    def test_allowlist_revoked_between_mint_and_upgrade(self):
        port = self._start_fake_vnc()
        self._allow(port)
        p = self._bridge_patches()
        with p[0], p[1], p[2]:
            ticket = self._ticket()
            config.YAML_PATH.write_text(
                "settings:\n  vm_console:\n    allowlist: {}\n", encoding="utf-8",
            )
            config.reload_cfg()
            with self._connect(ticket) as ws:
                self.assertEqual(
                    ws.receive_json(),
                    {"type": "error", "code": "vm_console.unavailable"},
                )
        self._assert_sessions_release()

    def test_vm_stopped_between_mint_and_upgrade(self):
        port = self._start_fake_vnc()
        self._allow(port)
        p = self._bridge_patches(running=False)
        with p[0], p[1], p[2]:
            with self._connect(self._ticket()) as ws:
                self.assertEqual(
                    ws.receive_json(),
                    {"type": "error", "code": "vm_console.unavailable"},
                )
        self._assert_sessions_release()


class HostileTicketTests(_WsCase):
    def test_hostile_ticket_values_answer_coded_invalid_ticket(self):
        self._allow(5900)
        for label, query in {
            "pct-encoded-surrogate": "ticket=%ED%A0%80",
            "nul": "ticket=%00",
            "seven-k-run": "ticket=" + "x" * 7000,
            "missing": "",
        }.items():
            with self.subTest(case=label):
                with mock.patch(
                    "hub.websocket_security.authenticate_websocket", _fake_auth,
                ):
                    with self.client.websocket_connect(
                        f"/api/vms/utm:{_UUID}/console/ws?{query}"
                    ) as ws:
                        self.assertEqual(
                            ws.receive_json(),
                            {"type": "error", "code": "vm_console.invalid_ticket"},
                        )


if __name__ == "__main__":
    unittest.main()
