"""Maintenance jobs must hit their timeout even when the child is silent.

``for line in p.stdout`` blocks until the child writes or closes the pipe.  A
deadline checked *inside* that loop therefore never runs for a child that prints
nothing (``sleep 60``), which is exactly the shape of a hung maintenance task.
The enforcement has to come from a watchdog that does not depend on the reader
making progress.  Remove the watchdog in ``hub/jobs.py`` and
``test_silent_child_hits_the_deadline`` goes red.
"""
from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import jobs  # noqa: E402


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


class StartJobGuardTests(unittest.TestCase):
    def tearDown(self):
        jobs._jobs.clear()

    def test_missing_command_clears_the_running_flag(self):
        jobs._jobs.clear()
        jobs.start_job({"id": "broken", "timeout": 10})
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and jobs._jobs["broken"].get("running"):
            time.sleep(0.02)
        self.assertFalse(jobs._jobs["broken"]["running"])
        self.assertEqual(jobs._jobs["broken"]["rc"], -1)

    def test_null_timeout_does_not_stick_the_mutex(self):
        jobs._jobs.clear()
        jobs.start_job({"id": "null-to", "command": "true", "timeout": None})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and jobs._jobs["null-to"].get("running"):
            time.sleep(0.02)
        self.assertFalse(jobs._jobs["null-to"]["running"])


def _run(command: str, timeout: int, tid: str, wait: float = 25.0) -> dict:
    jobs._jobs.clear()
    jobs.start_job({"id": tid, "command": command, "timeout": timeout})
    started = time.monotonic()
    deadline = started + wait
    while time.monotonic() < deadline:
        j = jobs._jobs[tid]
        if not j.get("running"):
            j = dict(j)
            j["elapsed"] = time.monotonic() - started
            return j
        time.sleep(0.05)
    raise AssertionError(f"job {tid} still running after {wait}s")


class TestMaintenanceJobTimeout(unittest.TestCase):
    def test_silent_child_hits_the_deadline(self):
        """The regression: a child that prints nothing must still be killed."""
        j = _run("sleep 60", 2, "silent")
        self.assertEqual(j["rc"], 124, "a timed-out job must report 124")
        self.assertLess(j["elapsed"], 15, "the watchdog did not fire on a silent child")
        self.assertTrue(any("timeout" in line for line in j["log"]))

    def test_chatty_child_hits_the_deadline(self):
        j = _run("while true; do echo tick; sleep 0.05; done", 2, "chatty")
        self.assertEqual(j["rc"], 124)
        self.assertLess(j["elapsed"], 15)

    def test_exit_status_is_propagated(self):
        j = _run("echo hello; exit 3", 30, "status")
        self.assertEqual(j["rc"], 3)
        self.assertIn("hello", j["log"])

    def test_clean_exit_reports_zero(self):
        j = _run("echo ok", 30, "clean")
        self.assertEqual(j["rc"], 0)

    def test_log_is_trimmed(self):
        j = _run("seq 1 2000", 60, "chatty_trim")
        self.assertEqual(j["rc"], 0)
        self.assertLessEqual(len(j["log"]), 800, "job log exceeded its retention cap")

    def test_descendants_die_with_the_process_group(self):
        marker = BASE / "data" / f".test-jobpgid-{os.getpid()}"
        marker.parent.mkdir(parents=True, exist_ok=True)
        if marker.exists():
            marker.unlink()
        try:
            _run(
                f"(while true; do sleep 0.1; done & echo $! > {marker}); sleep 60",
                2,
                "pgid",
            )
            grandchild = 0
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    grandchild = int(marker.read_text().strip())
                    break
                except (OSError, ValueError):
                    time.sleep(0.05)
            self.assertTrue(grandchild, "test setup: grandchild pid not recorded")
            for _ in range(40):
                if not _alive(grandchild):
                    break
                time.sleep(0.1)
            self.assertFalse(
                _alive(grandchild),
                "the job's process group survived the timeout kill",
            )
        finally:
            if marker.exists():
                marker.unlink()


class TestTimeoutEnforcementShape(unittest.TestCase):
    """Guard the fix's structure so the old pattern cannot come back."""

    def setUp(self):
        self.source = (BASE / "hub" / "jobs.py").read_text()

    def test_watchdog_is_independent_of_the_read_loop(self):
        self.assertIn("threading.Timer(timeout", self.source)

    def test_process_group_teardown_is_present(self):
        self.assertIn("start_new_session=True", self.source)
        self.assertIn("killpg", self.source)

    def test_no_bare_wait_after_the_read_loop(self):
        self.assertNotRegex(
            self.source,
            r"for line in p\.stdout:(?:.|\n)*?\n\s{8}p\.wait\(",
            "p.wait() placed after a blocking read loop can never fire",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
