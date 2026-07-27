from __future__ import annotations

import unittest

from hub import terminal_pty


class TerminalPtySecurityTests(unittest.TestCase):
    def tearDown(self):
        with terminal_pty._sessions_lock:
            terminal_pty._sessions.clear()

    def test_origin_must_exactly_match_host(self):
        self.assertTrue(terminal_pty.origin_allowed("https://panel.example", "panel.example"))
        self.assertTrue(terminal_pty.origin_allowed("http://localhost:8086", "localhost:8086"))
        self.assertFalse(terminal_pty.origin_allowed("https://evil.example", "panel.example"))
        self.assertFalse(terminal_pty.origin_allowed("https://panel.example.evil", "panel.example"))
        self.assertFalse(terminal_pty.origin_allowed(None, "panel.example"))
        self.assertFalse(terminal_pty.origin_allowed("https://panel.example", None))
        self.assertFalse(terminal_pty.origin_allowed("file:///tmp/panel", "panel.example"))

    def test_container_name_cannot_be_a_docker_option(self):
        self.assertEqual(terminal_pty._safe_container("music-assistant_1"), "music-assistant_1")
        self.assertEqual(terminal_pty._safe_container("-H"), "")
        self.assertEqual(terminal_pty._safe_container("name\n--privileged"), "")
        self.assertEqual(terminal_pty._safe_container("name/other"), "")

    def test_terminal_dimensions_are_bounded(self):
        self.assertEqual(terminal_pty._bounded_int("1", 100, 20, 500), 20)
        self.assertEqual(terminal_pty._bounded_int("9999", 100, 20, 500), 500)
        self.assertEqual(terminal_pty._bounded_int("bad", 100, 20, 500), 100)

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
