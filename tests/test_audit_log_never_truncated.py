"""Appending an audit entry must never be able to erase the audit history.

`record()` ensured the log existed before appending:

    if not AUDIT_PATH.exists():
        secure_io.write_secret_text(AUDIT_PATH, "")

`write_secret_text` opens with O_TRUNC, so the "ensure it exists" step emptied the
whole file whenever `exists()` answered wrongly -- and what it erases here is the
record of sign-ins, failures and source addresses, i.e. exactly what an audit log
is kept for.  The same check-then-write shape reset a populated services.yaml to
defaults on every test-suite run, so this is a pattern rather than an accident.

Creation now goes through the O_EXCL helper: the kernel decides whether the file
is new, and a wrong guess is a no-op instead of a truncation.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import audit  # noqa: E402

EXISTING = (
    '{"ts": "2026-08-01T10:00:00+0800", "event": "auth.login", "user": "elvin"}\n'
    '{"ts": "2026-08-01T10:05:00+0800", "event": "auth.failed", "user": "root"}\n'
)


class AuditAppendTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "auth-audit.jsonl"
        self.path.write_text(EXISTING)
        self.path.chmod(0o600)
        patcher = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_new_entry_is_appended_not_substituted(self):
        audit.record("auth.login", user="elvin")
        body = self.path.read_text()
        self.assertIn('"event": "auth.login", "user": "elvin"', body.replace("'", '"'))
        self.assertIn("auth.failed", body, "an earlier entry disappeared")
        self.assertGreaterEqual(len(body.splitlines()), 3)

    def test_history_survives_an_exists_that_lies(self):
        """The exact failure mode: every path claims to be missing."""
        with mock.patch.object(Path, "exists", return_value=False):
            audit.record("auth.login", user="elvin")
        body = self.path.read_text()
        self.assertIn(
            "auth.failed",
            body,
            "a false negative from exists() truncated the audit history",
        )
        self.assertIn("elvin", body, "the new entry was not recorded")

    def test_the_log_is_created_when_it_is_genuinely_absent(self):
        """The feature must keep working on a fresh install."""
        self.path.unlink()
        audit.record("auth.login", user="elvin")
        self.assertTrue(self.path.is_file(), "no audit log was created")
        self.assertIn("elvin", self.path.read_text())

    def test_a_created_log_is_not_readable_by_other_users(self):
        """It names accounts and source addresses."""
        self.path.unlink()
        audit.record("auth.login", user="elvin")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_record_does_not_raise_when_the_log_is_unwritable(self):
        """A failed audit write must never turn a valid sign-in into a 500."""
        with mock.patch.object(
            audit.secure_io, "create_secret_text", side_effect=OSError("read-only")
        ):
            entry = audit.record("auth.login", user="elvin")
        self.assertEqual(entry["event"], "auth.login")


class SourceShapeTests(unittest.TestCase):
    def test_audit_does_not_use_the_truncating_helper(self):
        """Pinned in the source: the O_TRUNC helper must not reach this path."""
        src = (BASE / "hub" / "audit.py").read_text()
        self.assertNotIn(
            "write_secret_text(AUDIT_PATH",
            src,
            "appending to the audit log must not go through an O_TRUNC write",
        )
        self.assertIn("append_secret_text(", src)
        self.assertNotIn("AUDIT_PATH.open(\"a\"", src)


if __name__ == "__main__":
    unittest.main()
