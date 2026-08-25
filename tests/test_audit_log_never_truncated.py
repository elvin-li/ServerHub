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

import json
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

    def test_extra_ts_and_event_fields_cannot_clobber_the_record(self):
        written = audit.record(
            audit.LOGIN_OK, username="admin", ts="1900-01-01", event="forged",
        )
        self.assertEqual(written["event"], audit.LOGIN_OK)
        self.assertNotEqual(written["ts"], "1900-01-01")
        self.assertEqual(written["username"], "admin")
        on_disk = [json.loads(ln) for ln in self.path.read_text().splitlines() if ln.strip()]
        last = on_disk[-1]
        self.assertEqual(last["event"], audit.LOGIN_OK)
        self.assertNotEqual(last["ts"], "1900-01-01")

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

    def test_trim_is_skipped_while_the_file_is_small(self):
        """A sign-in must not read-and-rewrite a trail still under the cap."""
        with mock.patch.object(audit, "_TRIM_SOFT_BYTES", 10**9):
            with mock.patch.object(audit.secure_io, "replace_secret_text") as write:
                audit.record("auth.login", user="elvin")
        write.assert_not_called()

    def test_trim_drops_oldest_once_over_the_byte_cap(self):
        fat = '{"ts": "x", "event": "auth.login", "pad": "' + ("n" * 400) + '"}\n'
        self.path.write_text(fat * (audit.MAX_LINES + 8))
        self.assertGreater(self.path.stat().st_size, audit._TRIM_SOFT_BYTES)
        audit._trim(self.path)
        lines = self.path.read_text().splitlines()
        self.assertEqual(len(lines), audit.MAX_LINES)


class ConcurrentRecordTests(unittest.TestCase):
    """Concurrent record() calls must not throw each other's entries away.

    The O_APPEND write is atomic, but _trim is read-tail-then-rename: an entry
    appended by another thread inside that window vanished with the temp-file
    swap.  Sync handlers run on uvicorn's thread pool, so one operator acting
    while the dashboard polls is enough to open the window.  Forcing the trim
    on every record (soft cap 0) makes the pre-fix loss near-certain rather
    than occasional.
    """

    def test_no_entry_is_lost_to_a_concurrent_trim(self):
        import threading

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "auth-audit.jsonl"
        threads_n, per_thread = 8, 40
        with mock.patch.object(audit, "AUDIT_PATH", path), \
             mock.patch.object(audit, "_TRIM_SOFT_BYTES", 0), \
             mock.patch.object(audit, "MAX_LINES", threads_n * per_thread + 100):
            start = threading.Barrier(threads_n)

            def hammer(worker: int) -> None:
                start.wait()
                for i in range(per_thread):
                    audit.record("auth.login", user=f"w{worker}-{i}")

            workers = [
                threading.Thread(target=hammer, args=(w,)) for w in range(threads_n)
            ]
            for t in workers:
                t.start()
            for t in workers:
                t.join()
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        self.assertEqual(
            len(lines),
            threads_n * per_thread,
            "entries appended during another thread's trim were discarded",
        )


class ConcurrentTerminalAuditTests(unittest.TestCase):
    """The terminal trail has the same append+trim shape as the auth trail and
    had the same unlocked window; it is the only record of what an operator
    typed into a root-capable shell."""

    def test_no_command_record_is_lost_to_a_concurrent_trim(self):
        import threading

        from hub import terminal_svc
        from hub.util import tail_file_lines as real_tail

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "terminal-audit.jsonl"
        threads_n, per_thread = 8, 40
        # _AUDIT_MAX_BYTES=1 forces the trim branch on every record; it also
        # caps the trim's tail read, so widen that back out or the trim itself
        # would evict everything and hide the race being tested.
        with mock.patch.object(terminal_svc, "AUDIT_PATH", path), \
             mock.patch.object(terminal_svc, "_AUDIT_MAX_BYTES", 1), \
             mock.patch.object(terminal_svc, "_AUDIT_KEEP_LINES",
                               threads_n * per_thread + 100), \
             mock.patch.object(
                 terminal_svc, "tail_file_lines",
                 lambda p, n, max_bytes=None: real_tail(p, n, max_bytes=10**7)):
            start = threading.Barrier(threads_n)

            def hammer(worker: int) -> None:
                start.wait()
                for i in range(per_thread):
                    terminal_svc._audit({"cmd": f"echo w{worker}-{i}", "rc": 0})

            workers = [
                threading.Thread(target=hammer, args=(w,)) for w in range(threads_n)
            ]
            for t in workers:
                t.start()
            for t in workers:
                t.join()
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        self.assertEqual(
            len(lines),
            threads_n * per_thread,
            "terminal audit lines appended during another thread's trim were discarded",
        )


class SourceShapeTests(unittest.TestCase):
    def test_audit_does_not_use_the_truncating_helper(self):
        """Pinned in the source: the O_TRUNC helper must not reach this path."""
        src = (BASE / "hub" / "audit.py").read_text()
        self.assertNotIn(
            "write_secret_text(AUDIT_PATH",
            src,
            "appending to the audit log must not go through an O_TRUNC write",
        )
        self.assertIn("create_secret_text(AUDIT_PATH", src)
        self.assertIn("replace_secret_text", src)
        self.assertIn("tail_file_lines", src)


if __name__ == "__main__":
    unittest.main()
