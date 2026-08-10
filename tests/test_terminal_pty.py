from __future__ import annotations

import unittest
from unittest.mock import patch

from hub import terminal_pty, websocket_security


class _FakeWebSocket:
    def __init__(self):
        self.cookies = {"serverhub_session": "session-token"}
        self.headers = {
            "origin": "https://panel.example",
            "host": "panel.example",
        }
        self.messages = []
        self.close_code = None

    async def accept(self):
        return None

    async def send_json(self, payload):
        self.messages.append(payload)

    async def close(self, code):
        self.close_code = code


class TerminalPtySecurityTests(unittest.TestCase):
    def tearDown(self):
        with terminal_pty._sessions_lock:
            terminal_pty._sessions.clear()

    def test_origin_must_exactly_match_host(self):
        self.assertTrue(websocket_security.origin_allowed("https://panel.example", "panel.example"))
        self.assertTrue(websocket_security.origin_allowed("http://localhost:8086", "localhost:8086"))
        self.assertFalse(websocket_security.origin_allowed("https://evil.example", "panel.example"))
        self.assertFalse(websocket_security.origin_allowed("https://panel.example.evil", "panel.example"))
        self.assertFalse(websocket_security.origin_allowed(None, "panel.example"))
        self.assertFalse(websocket_security.origin_allowed("https://panel.example", None))
        self.assertFalse(websocket_security.origin_allowed("file:///tmp/panel", "panel.example"))

    def test_container_name_cannot_be_a_docker_option(self):
        self.assertEqual(terminal_pty._safe_container("music-assistant_1"), "music-assistant_1")
        self.assertEqual(terminal_pty._safe_container("-H"), "")
        self.assertEqual(terminal_pty._safe_container("name\n--privileged"), "")
        self.assertEqual(terminal_pty._safe_container("name/other"), "")

    def test_terminal_dimensions_are_bounded(self):
        self.assertEqual(terminal_pty._bounded_int("1", 100, 20, 500), 20)
        self.assertEqual(terminal_pty._bounded_int("9999", 100, 20, 500), 500)
        self.assertEqual(terminal_pty._bounded_int("bad", 100, 20, 500), 100)

    def test_member_is_refused_by_shared_websocket_authentication(self):
        ws = _FakeWebSocket()
        with (
            patch.object(websocket_security, "setup_required", return_value=False),
            patch.object(websocket_security, "verify_session", return_value=True),
            patch.object(websocket_security, "session_username", return_value="mom"),
            patch.object(websocket_security, "is_admin", return_value=False),
        ):
            result = __import__("asyncio").run(
                websocket_security.authenticate_websocket(ws)
            )

        self.assertIsNone(result)
        self.assertEqual(ws.messages, [{"type": "error", "code": "auth.admin_required"}])
        self.assertEqual(ws.close_code, 4403)

    def test_admin_is_accepted_by_shared_websocket_authentication(self):
        ws = _FakeWebSocket()
        with (
            patch.object(websocket_security, "setup_required", return_value=False),
            patch.object(websocket_security, "verify_session", return_value=True),
            patch.object(websocket_security, "session_username", return_value="admin"),
            patch.object(websocket_security, "is_admin", return_value=True),
        ):
            result = __import__("asyncio").run(
                websocket_security.authenticate_websocket(ws)
            )

        self.assertEqual(result, ("session-token", "admin"))
        self.assertEqual(ws.messages, [])
        self.assertIsNone(ws.close_code)

    def test_per_user_and_global_session_limits_release_cleanly(self):
        first = terminal_pty._reserve("admin", "host", "")
        second = terminal_pty._reserve("admin", "container", "one")
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNone(terminal_pty._reserve("admin", "container", "two"))

        terminal_pty._release(first.session_id)
        replacement = terminal_pty._reserve("admin", "container", "two")
        self.assertIsNotNone(replacement)

        other = terminal_pty._reserve("other", "container", "three")
        fourth = terminal_pty._reserve("third", "container", "four")
        self.assertIsNotNone(other)
        self.assertIsNotNone(fourth)
        self.assertIsNone(terminal_pty._reserve("fourth", "container", "five"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
