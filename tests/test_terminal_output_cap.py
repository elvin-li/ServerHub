"""One-shot terminal must not buffer an unbounded pipe before clipping."""
from __future__ import annotations

import unittest

from fastapi import HTTPException

from hub import terminal_svc


class TerminalRunCapTests(unittest.TestCase):
    def test_huge_stdout_is_clipped_without_loading_the_prefix(self):
        saved = terminal_svc.MAX_OUTPUT
        terminal_svc.MAX_OUTPUT = 64
        self.addCleanup(setattr, terminal_svc, "MAX_OUTPUT", saved)
        result = terminal_svc._run(
            ["/bin/sh", "-c", "python3 -c 'print(\"x\"*4000)'"],
            timeout=10,
        )
        self.assertLessEqual(len(result["stdout"]), 64)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["rc"], 0)

    def test_timeout_kills_a_silent_child(self):
        with self.assertRaises(HTTPException) as raised:
            terminal_svc._run(["/bin/sleep", "30"], timeout=1)
        self.assertEqual(raised.exception.detail["code"], "terminal.timeout")

    def test_missing_binary_is_rc_127(self):
        result = terminal_svc._run(["/no/such/serverhub-binary"], timeout=2)
        self.assertEqual(result["rc"], 127)
        self.assertFalse(result["ok"])

    def test_does_not_use_capture_output(self):
        from pathlib import Path
        source = Path(terminal_svc.__file__).read_text(encoding="utf-8")
        self.assertNotIn("capture_output=True,", source)
        self.assertIn("iter_capped_lines", source)
        self.assertIn("start_new_session=True", source)

    def test_nul_command_is_400_not_500(self):
        with self.assertRaises(HTTPException) as raised:
            terminal_svc._check_command("id\x00reboot")
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail["code"], "terminal.bad_command")

    def test_nul_in_argv_does_not_raise(self):
        result = terminal_svc._run(["/bin/echo", "hi\x00there"], timeout=2)
        self.assertFalse(result["ok"])
        self.assertEqual(result["rc"], 127)

    def test_infinite_timeout_clamps(self):
        self.assertEqual(terminal_svc._clamp_timeout(float("inf")), terminal_svc.DEFAULT_TIMEOUT)
        self.assertEqual(terminal_svc._clamp_timeout(True), terminal_svc.DEFAULT_TIMEOUT)
        self.assertEqual(terminal_svc._clamp_timeout(0), 1)
