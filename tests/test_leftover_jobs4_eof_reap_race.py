"""Fourth leftover sweep of the Jobs domain: the EOF reap SIGTERM race.

``hub.jobs.run_watchdog`` — the executor behind POST /api/maintenance/{tid}/run
AND the scheduler engine (hub/scheduler_svc.py reuses it) — called ``_reap()``
unconditionally the moment ``for line in p.stdout`` hit EOF.  ``_reap()``
checks ``p.poll()`` first, but EOF only proves every writer closed the pipe,
not that the child is waitable yet: a command that closes its stdout/stderr
and then finishes its last step (a daemonizing helper, a CLI that detaches
its log stream, a plain flush-then-cleanup script) was SIGTERM-killed
mid-cleanup and its job finished ``rc: -15`` instead of the real exit code —
a false failure badge on the Maintenance page and a false ``failed`` run in
the scheduler journal.  The sibling executor,
``containers_svc._stream_job_command``, already fixed exactly this race
(wait-then-reap after EOF; see the leftover CI flake note there); jobs kept
the old immediate kill.

The fix mirrors the sibling: after EOF, ``p.wait(timeout=2)`` first, and only
reap the group when the child is genuinely still running past the grace.
The source pin below is the same one test_job_subprocess_lifecycle applies to
containers_svc.py: a literal ``p.wait(timeout=N)`` may appear only when the
next line is a comment — the wait-is-the-reap shape — never as a bare
post-loop wait that could reintroduce the unbounded-read pattern.
"""
from __future__ import annotations

import re
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import jobs  # noqa: E402


class RunWatchdogEofReapRaceTests(unittest.TestCase):
    """Module layer: the executor itself, no HTTP in the way."""

    def test_child_that_closes_its_pipe_keeps_its_real_exit_code(self):
        """EOF before exit must not be treated as "kill it now".

        ``exec 1>&- 2>&-`` closes both writers (stderr shares the pipe via
        STDOUT redirect), so the read loop sees EOF while the child is still
        alive doing its last step.  The old immediate ``_reap()`` SIGTERMed
        the group and reported rc -15 for a command that went on to exit 0/7.
        """
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code):
                log: list[str] = []
                rc = jobs.run_watchdog(
                    ["/bin/sh", "-c",
                     f"echo eof-ok; exec 1>&- 2>&-; sleep 0.4; exit {exit_code}"],
                    timeout=30, log=log,
                )
                self.assertEqual(rc, exit_code,
                                 "the child's own exit code must survive EOF")
                self.assertIn("eof-ok", log)
                self.assertFalse(any("timeout" in line for line in log))

    def test_child_that_closes_its_pipe_and_hangs_is_still_reaped(self):
        """The grace wait must stay a grace, not a new unbounded wait: a
        child that closes the pipe and then wedges is reaped after ~2s,
        long before its own sleep or the 60s watchdog."""
        log: list[str] = []
        started = time.monotonic()
        rc = jobs.run_watchdog(
            ["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 30"],
            timeout=60, log=log,
        )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 15,
                        "post-EOF grace turned into an unbounded wait")
        # SIGTERM (or SIGKILL if the shell shrugged off the first signal).
        self.assertIn(rc, (-15, -9))

    def test_watchdog_timeout_still_kills_and_reports_124(self):
        """The deadline path must not regress: a chatty child that never
        exits is still group-killed and reported as GNU-timeout 124."""
        log: list[str] = []
        started = time.monotonic()
        rc = jobs.run_watchdog(
            ["/bin/sh", "-c", "while true; do echo tick; sleep 0.05; done"],
            timeout=2, log=log,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(rc, 124)
        self.assertLess(elapsed, 20)
        self.assertTrue(any("timeout" in line for line in log))


class RunWatchdogSourcePin(unittest.TestCase):
    """Same source contract test_job_subprocess_lifecycle pins for
    containers_svc.py, applied to hub/jobs.py."""

    def test_bare_post_loop_wait_stays_banned_and_grace_wait_exists(self):
        source = (BASE / "hub" / "jobs.py").read_text()
        # A literal p.wait(timeout=N) is only legal in the wait-is-the-reap
        # shape: the very next line must be a comment saying so.  A bare one
        # is the old can-never-fire wait after a blocking read loop.
        self.assertNotRegex(
            source,
            r"p\.wait\(timeout=\d+\)\s*\n(?!\s*#)",
            "p.wait() after a blocking read loop can never fire",
        )
        # The grace wait itself must exist (the immediate _reap() race).
        self.assertRegex(source, r"p\.wait\(timeout=\d+\)")
        self.assertIn("start_new_session=True", source)
        self.assertIn("killpg", source)


class MountedMaintenanceEofRaceTests(unittest.TestCase):
    """HTTP layer: the run/log round trip over the real mounted app must
    serve the child's real exit code, not a raced -15."""

    _CFG = {"maintenance": [
        {"id": "eof-race",
         "name": "EOF race",
         "command": "echo maint-eof-ok; exec 1>&- 2>&-; sleep 0.4; exit 5",
         "timeout": 30},
    ]}

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def tearDown(self):
        jobs._jobs.clear()

    def _wait_finished(self, tid: str, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = jobs._jobs.get(tid) or {}
            if isinstance(row, dict) and row and not row.get("running"):
                return
            time.sleep(0.05)
        raise AssertionError(f"job {tid!r} did not finish")

    def test_run_and_log_report_the_real_exit_code_over_http(self):
        with mock.patch.object(jobs, "cfg", return_value=self._CFG):
            r = self.client.post("/api/maintenance/eof-race/run")
            self.assertEqual(r.status_code, 200, r.text)
            self._wait_finished("eof-race")
            r = self.client.get("/api/maintenance/eof-race/log")
        self.assertEqual(r.status_code, 200, r.text)
        payload = r.json()
        self.assertEqual(payload["rc"], 5,
                         "the EOF reap race replaced the real exit code")
        self.assertIn("maint-eof-ok", payload["log"])
        self.assertFalse(payload["running"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
