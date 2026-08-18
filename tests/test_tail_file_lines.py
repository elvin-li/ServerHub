"""Callers that used to slurp a whole log just to show a tail."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hub import (
    alerts,
    apps_manage_svc,
    audit,
    cloudflared_svc,
    logs_svc,
    scheduler_svc,
    services_manage_svc,
    terminal_svc,
    tools_svc,
)
from hub.util import tail_file_lines


class TailFileLinesTests(unittest.TestCase):
    def test_returns_the_last_n_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.txt"
            path.write_text("a\nb\nc\nd\n")
            self.assertEqual(tail_file_lines(path, 2), ["c", "d"])

    def test_drops_a_torn_first_row_after_a_mid_file_seek(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.txt"
            path.write_bytes(b"OLD\n" + b"x" * 4000 + b"\nTAIL\n")
            lines = tail_file_lines(path, 2, max_bytes=16)
            self.assertEqual(lines[-1], "TAIL")
            self.assertNotIn("OLD", lines)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.txt"
            path.write_bytes(b"")
            self.assertEqual(tail_file_lines(path, 10), [])


class CallSiteContractTests(unittest.TestCase):
    """A helper nobody calls is not a fix."""

    def test_log_tails_go_through_the_capped_reader(self):
        sites = {
            cloudflared_svc: "def logs",
            apps_manage_svc: "def _native_logs",
            tools_svc: "def _syslog_tail_uncached",
            terminal_svc: "def recent_audit",
            services_manage_svc: "def _tail_file",
            logs_svc: "def tail_log",
            audit: "def recent",
            scheduler_svc: "def _journal_lines",
            alerts: "def list_alerts",
        }
        for module, marker in sites.items():
            source = Path(module.__file__).read_text()
            self.assertIn(
                "tail_file_lines",
                source,
                f"{module.__name__} stopped using tail_file_lines",
            )
            self.assertIn(marker, source)

    def test_wireguard_registry_writes_atomically(self):
        from hub import wireguard_svc
        source = Path(wireguard_svc.__file__).read_text()
        body = source[source.index("def _save_registry"): source.index("\ndef ", source.index("def _save_registry") + 10)]
        self.assertIn("replace_secret_text", body)
        self.assertNotIn("write_secret_text", body)

    def test_wireguard_live_conf_writes_atomically(self):
        from hub import wireguard_svc
        source = Path(wireguard_svc.__file__).read_text()
        start = source.index("def _write_conf")
        body = source[start: source.index("\ndef ", start + 10)]
        self.assertIn("replace_secret_text(path, body)", body)
        self.assertNotIn("write_secret_text(path,", body)

    def test_rsync_preview_caps_lines(self):
        from hub import rsync_svc
        source = Path(rsync_svc.__file__).read_text()
        self.assertIn("iter_capped_lines", source)

    def test_terminal_audit_rotation_is_capped_and_atomic(self):
        source = Path(terminal_svc.__file__).read_text()
        body = source[source.index("def _audit"): source.index("\ndef _clip")]
        self.assertIn("tail_file_lines", body)
        self.assertIn("replace_secret_text", body)
        self.assertNotIn("write_secret_text(", body)

    def test_auth_audit_trim_is_capped_and_atomic(self):
        source = Path(audit.__file__).read_text()
        body = source[source.index("def _trim"): source.index("\ndef record")]
        self.assertIn("tail_file_lines", body)
        self.assertIn("replace_secret_text", body)
        self.assertNotIn("write_secret_text(", body)
