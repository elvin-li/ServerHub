"""Container job subprocesses must be bounded and always reaped.

These jobs hold a global mutex — only one container job runs at a time — so a
command that never returns used to lock the whole subsystem until the panel was
restarted.  ``p.wait(timeout=...)`` after ``for line in p.stdout`` could never
fire, because the loop itself blocks until the child closes the pipe.
"""
from __future__ import annotations

import os
import re
import sys
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import containers_svc  # noqa: E402


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


class TestStreamJobCommand(unittest.TestCase):
    def test_deadline_fires_while_reading_and_reaps_the_child(self):
        """A child that never closes its pipe must still hit the deadline."""
        job: dict = {"log": []}
        # Prints forever: the read loop would block indefinitely without a
        # deadline check inside the loop.
        cmd = ["/bin/sh", "-c", "while true; do echo tick; sleep 0.05; done"]

        started = time.monotonic()
        rc = containers_svc._stream_job_command(cmd, job, timeout=2)
        elapsed = time.monotonic() - started

        self.assertEqual(rc, 124, "a timed-out command must report 124")
        self.assertLess(elapsed, 20, "the deadline did not interrupt the read loop")
        self.assertTrue(
            any("timeout" in line for line in job["log"]),
            "the timeout should be visible in the job log",
        )

    def test_exit_status_is_propagated(self):
        job: dict = {"log": []}
        rc = containers_svc._stream_job_command(
            ["/bin/sh", "-c", "echo out; exit 3"], job, timeout=30
        )
        self.assertEqual(rc, 3)
        self.assertIn("out", job["log"])

    def test_output_is_streamed_and_trimmed(self):
        """A chatty command must not grow the job dict without bound."""
        job: dict = {"log": []}
        lines = containers_svc.JOB_LOG_MAX_LINES + 500
        rc = containers_svc._stream_job_command(
            ["/bin/sh", "-c", f"seq 1 {lines}"], job, timeout=60
        )
        self.assertEqual(rc, 0)
        self.assertLessEqual(
            len(job["log"]),
            containers_svc.JOB_LOG_MAX_LINES,
            "job log exceeded its retention cap",
        )
        self.assertGreater(len(job["log"]), 0)

    def test_child_process_group_is_terminated(self):
        """Killing only the CLI would leave descendants holding the pipe."""
        job: dict = {"log": []}
        marker = BASE / "data" / f".test-pgid-{os.getpid()}"
        marker.parent.mkdir(parents=True, exist_ok=True)
        if marker.exists():
            marker.unlink()
        try:
            # The shell spawns a grandchild that outlives it and keeps stdout
            # open; only a process-group kill reclaims it.
            script = (
                f"(while true; do sleep 0.1; done & echo $! > {marker}); "
                "while true; do echo tick; sleep 0.05; done"
            )
            containers_svc._stream_job_command(
                ["/bin/sh", "-c", script], job, timeout=2
            )
            deadline = time.monotonic() + 5
            grandchild = 0
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
                "the child's process group survived the timeout kill",
            )
        finally:
            if marker.exists():
                marker.unlink()


class TestNoBlockingStreamPatternReturns(unittest.TestCase):
    """Guard against reintroducing the unbounded read loop."""

    def test_job_streaming_goes_through_the_helper(self):
        source = (BASE / "hub" / "containers_svc.py").read_text()
        # The helper itself is the only place allowed to open a streaming pipe.
        popen_sites = re.findall(r"subprocess\.Popen\(", source)
        self.assertEqual(
            len(popen_sites),
            1,
            "container jobs must stream through _stream_job_command()",
        )
        self.assertNotRegex(
            source,
            r"p\.wait\(timeout=\d+\)\s*\n(?!\s*#)",
            "p.wait() after a blocking read loop can never fire",
        )
        self.assertIn("start_new_session=True", source)
        self.assertIn("killpg", source)


class TestSseLogStreamReapsChild(unittest.TestCase):
    def test_container_log_stream_awaits_the_killed_process(self):
        """kill() without wait() leaks a zombie and its pipe fds."""
        source = (BASE / "hub" / "routers" / "containers.py").read_text()
        self.assertIn("await proc.wait()", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
