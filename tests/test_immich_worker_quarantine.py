"""A deliberately stopped worker must not be reported as a fault to go fix.

`~/.immich-accelerator/worker.quarantine` is written when the enclosure holding
the media volume has failed isolated F_FULLFSYNC write-barrier tests -- on this
host, with EIO, on a USB path that was never replaced.  keep-immich-alive.sh
reads the same file and refuses to start the worker while it exists.

The health page did not read it.  A stopped worker was always a red error whose
"fix" column said `~/Services/immich/start-worker-native.sh`, which is exactly
the action the quarantine exists to prevent: resuming media writes to hardware
known to lose write barriers.  The panel was, in effect, advising a data-loss
risk in its remediation column.

The inverse state matters just as much and had no representation at all: a worker
that is running *while* the note stands is the dangerous case, not the healthy
one, so it is the loudest of the four.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import immich_svc  # noqa: E402

REASON = "MD202 USB detached mid-write; F_FULLFSYNC returned EIO"


class WorkerCheckStatesTests(unittest.TestCase):
    def test_running_with_no_quarantine_is_healthy(self):
        check = immich_svc._worker_check(4321, "01:23:45", "")
        self.assertTrue(check["ok"])
        self.assertEqual(check["level"], "ok")
        self.assertIn("4321", check["detail"])
        self.assertEqual(check["fix"], "")

    def test_stopped_under_quarantine_is_a_warning_that_names_the_reason(self):
        check = immich_svc._worker_check(None, "", REASON)
        self.assertFalse(check["ok"])
        self.assertEqual(
            check["level"],
            "warn",
            "a deliberate stop was reported at the same severity as a crash",
        )
        self.assertIn(REASON, check["detail"])

    def test_stopped_under_quarantine_does_not_advise_starting_it(self):
        check = immich_svc._worker_check(None, "", REASON)
        self.assertNotIn(
            "start-worker-native",
            check["fix"],
            "the remedy column pointed at the one action the quarantine forbids",
        )
        self.assertIn("worker.quarantine", check["fix"])

    def test_stopped_with_no_quarantine_still_says_how_to_start_it(self):
        # The quarantine handling must not swallow the ordinary crashed case.
        check = immich_svc._worker_check(None, "", "")
        self.assertFalse(check["ok"])
        self.assertEqual(check["level"], "error")
        self.assertIn("start-worker-native", check["fix"])

    def test_running_despite_the_quarantine_is_an_error(self):
        check = immich_svc._worker_check(4321, "00:10", REASON)
        self.assertFalse(check["ok"])
        self.assertEqual(
            check["level"],
            "error",
            "a worker writing to quarantined hardware was not flagged",
        )
        self.assertIn("4321", check["detail"])
        self.assertIn(REASON, check["detail"])

    def test_every_state_reports_under_one_id_and_label(self):
        seen = {
            (c["id"], c["name"])
            for c in (
                immich_svc._worker_check(1, "x", ""),
                immich_svc._worker_check(1, "x", REASON),
                immich_svc._worker_check(None, "", REASON),
                immich_svc._worker_check(None, "", ""),
            )
        }
        self.assertEqual(seen, {("immich_worker", immich_svc.WORKER_LABEL)})


class QuarantineReadingTests(unittest.TestCase):
    def test_no_file_means_no_quarantine(self):
        missing = Path("/nonexistent/serverhub-test/worker.quarantine")
        with patch.object(immich_svc, "QUARANTINE", missing):
            self.assertEqual(immich_svc._worker_quarantine(), "")

    def test_the_reason_line_is_preferred(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.quarantine"
            path.write_text(
                f"quarantined_at=2026-07-28 18:00:48 local\nreason={REASON}\n"
                "action=Keep the worker stopped\n",
                encoding="utf-8",
            )
            with patch.object(immich_svc, "QUARANTINE", path):
                self.assertEqual(immich_svc._worker_quarantine(), REASON)

    def test_a_file_without_a_reason_line_still_counts_as_quarantined(self):
        # Presence is what keep-immich-alive.sh acts on. Answering "" for an
        # unparseable note would turn the warning back into "go start it".
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.quarantine"
            path.write_text("do not start\n", encoding="utf-8")
            with patch.object(immich_svc, "QUARANTINE", path):
                self.assertEqual(immich_svc._worker_quarantine(), "do not start")

    def test_an_empty_file_still_counts_as_quarantined(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.quarantine"
            path.write_text("", encoding="utf-8")
            with patch.object(immich_svc, "QUARANTINE", path):
                self.assertTrue(immich_svc._worker_quarantine())

    def test_a_long_note_is_truncated(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.quarantine"
            path.write_text("reason=" + "x" * 5000, encoding="utf-8")
            with patch.object(immich_svc, "QUARANTINE", path):
                self.assertLessEqual(len(immich_svc._worker_quarantine()), 300)


class ThisHostTests(unittest.TestCase):
    def test_the_real_path_is_under_the_accelerator_dir_not_the_media_volume(self):
        # Reading the note must never touch the suspect volume: a hung mount
        # there would block the whole health page.
        self.assertEqual(immich_svc.QUARANTINE.parent, immich_svc.ACCEL)
        self.assertNotIn("/Volumes/", str(immich_svc.QUARANTINE))


if __name__ == "__main__":
    unittest.main()
