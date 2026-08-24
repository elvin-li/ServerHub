"""``login_start`` must bound its read loop against a clock that cannot step.

``cloudflared tunnel login`` prints its browser URL on stdout, and
:func:`hub.cloudflared_svc.login_start` reads that line on the request thread
under a deadline.  That deadline used to be ``time.time() + 12``.  The wall
clock is not a stopwatch: NTP steps it, and this very panel sets it outright
from Settings -> date & time.  A backwards step leaves ``time.time() <
deadline`` true for the length of the correction, so the request thread stays
in the read loop for as long as the clock was wrong -- minutes or hours, not
twelve seconds.

The tests below run the loop under a clock that steps backwards and assert it
still gives up.  Each fake caps its own call count so the regression fails the
run instead of hanging it.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import cloudflared_svc


class SteppingClock:
    """A wall clock that jumps backwards, beside a monotonic that cannot.

    ``time()`` walks forward until *step_after* reads and then loses *step_by*
    seconds, which is what an NTP correction or a manual date change looks
    like from inside a loop.  ``monotonic()`` just advances.
    """

    def __init__(self, *, step_after: int = 3, step_by: float = 3600.0, tick: float = 0.5):
        self.tick = tick
        self.step_after = step_after
        self.step_by = step_by
        self.wall_reads = 0
        self.mono_reads = 0
        self.slept = 0.0

    def time(self) -> float:
        self.wall_reads += 1
        walked = 1_000_000.0 + self.wall_reads * self.tick
        return walked - self.step_by if self.wall_reads > self.step_after else walked

    def monotonic(self) -> float:
        self.mono_reads += 1
        return self.mono_reads * self.tick

    def sleep(self, seconds: float) -> None:
        self.slept += seconds


class ChattyLogin:
    """A login child that prints forever and never names a URL.

    The real one is quiet, but a wedged or misconfigured cloudflared can log
    steadily, which is the case where nothing but the deadline stops the loop.
    """

    def __init__(self, budget: int = 5000):
        self.budget = budget
        self.reads = 0
        self.pid = 4242
        self.stdout = self
        self.closed = False

    def readline(self, _cap: int | None = None) -> str:
        self.reads += 1
        if self.reads > self.budget:
            raise AssertionError(
                f"the read loop made {self.reads} reads without stopping: "
                "its deadline is not on a clock that only moves forward"
            )
        return "INF[0000] Please open the following URL\n"

    def poll(self):
        return None

    def close(self) -> None:
        self.closed = True


class LoginReadDeadlineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.clock = SteppingClock()
        self.child = ChattyLogin()

        for patcher in (
            mock.patch.object(cloudflared_svc, "CF_HOME", root),
            mock.patch.object(cloudflared_svc, "LOGIN_PID", root / "login.pid"),
            mock.patch.object(cloudflared_svc, "LOGIN_LOG", root / "login.log"),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE", root / "login.url"),
            mock.patch.object(cloudflared_svc, "time", self.clock),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=False),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_terminate_login_process", return_value=True),
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/true"),
            mock.patch.object(subprocess, "Popen", return_value=self.child),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(lambda: setattr(cloudflared_svc, "_login_proc", None))

    def test_a_backwards_clock_step_does_not_extend_the_read_loop(self):
        result = cloudflared_svc.login_start()

        self.assertTrue(result.get("login_pending"))
        self.assertFalse(result.get("ok"))
        # 12s of budget at half a second per read is ~24 reads.  The bound is
        # loose on purpose; the point is that it is a bound at all, which it
        # was not while the wall clock could hand back seconds it had spent.
        self.assertLess(
            self.child.reads,
            100,
            "the loop kept reading well past its 12s budget",
        )

    def test_the_loop_is_timed_on_the_monotonic_clock(self):
        cloudflared_svc.login_start()

        self.assertGreater(
            self.clock.mono_reads,
            1,
            "login_start never asked the monotonic clock for the time",
        )

    def test_a_url_still_ends_the_read_early(self):
        """The deadline change must not cost the loop its actual job."""
        lines = iter([
            "INF[0000] starting\n",
            "Please open https://dash.cloudflare.com/argotunnel?aud=x to authorize\n",
        ])
        self.child.readline = lambda _cap=None: next(lines, "")

        result = cloudflared_svc.login_start()

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["login_url"],
            "https://dash.cloudflare.com/argotunnel?aud=x",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
