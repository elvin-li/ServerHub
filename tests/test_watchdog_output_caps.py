"""Subprocess output capture must be bounded in bytes, not just in lines.

Both streaming executors (hub/jobs.run_watchdog and
hub/containers_svc._stream_job_command) trimmed their logs by line count,
but ``for line in stdout`` buffers a whole line before the trim can see it —
one giant line (a dumped blob, a \\r-driven progress bar) ballooned memory
without limit.  These tests pin the per-line cap, the total cap, the
preserved line-trim semantics, and the watchdog behaviour the caps ride on:
a *silent* hang must still hit the deadline (an in-loop check only fires
while output flows).
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import containers_svc, jobs  # noqa: E402
from hub.util import iter_capped_lines  # noqa: E402


class IterCappedLinesTests(unittest.TestCase):
    def _lines(self, text: str, cap: int) -> list[str]:
        import io
        return list(iter_capped_lines(io.StringIO(text), cap))

    def test_normal_lines_pass_through(self):
        self.assertEqual(self._lines("a\nbb\nccc\n", 10), ["a", "bb", "ccc"])

    def test_final_line_without_newline_is_kept(self):
        self.assertEqual(self._lines("a\ntail", 10), ["a", "tail"])

    def test_giant_line_is_capped_and_marked(self):
        out = self._lines("x" * 1000 + "\nafter\n", 100)
        self.assertEqual(len(out), 2)
        self.assertLessEqual(len(out[0]), 100 + len(" …[line truncated]"))
        self.assertIn("truncated", out[0])
        self.assertEqual(out[1], "after", "the remainder must be discarded, "
                         "not delivered as phantom lines")

    def test_line_exactly_at_cap_is_not_marked(self):
        out = self._lines("y" * 99 + "\n", 100)
        self.assertEqual(out, ["y" * 99])


class RunWatchdogCapTests(unittest.TestCase):
    def test_one_giant_line_is_capped(self):
        log: list[str] = []
        rc = jobs.run_watchdog(
            ["/bin/sh", "-c",
             "head -c 2000000 /dev/zero | tr '\\0' 'x'; echo; echo done"],
            timeout=60, log=log,
        )
        self.assertEqual(rc, 0)
        self.assertIn("done", log)
        self.assertLessEqual(
            max(len(line) for line in log),
            jobs.LOG_LINE_CAP + 32,
            "a single line must be capped near LOG_LINE_CAP",
        )
        self.assertTrue(any("truncated" in line for line in log),
                        "the cut must be visible in the log")
        self.assertLessEqual(sum(len(line) for line in log), jobs.LOG_TOTAL_CAP)

    def test_total_cap_bounds_many_long_lines(self):
        log: list[str] = []
        # 400 lines x ~3000 chars ≈ 1.2 MB of output inside the 800-line
        # window: the line trim alone would retain it all.
        rc = jobs.run_watchdog(
            ["/bin/sh", "-c",
             'i=0; while [ $i -lt 400 ]; do printf "%03000d\\n" $i; '
             'i=$((i+1)); done; echo done'],
            timeout=60, log=log,
        )
        self.assertEqual(rc, 0)
        self.assertIn("done", log)
        self.assertLessEqual(sum(len(line) for line in log), jobs.LOG_TOTAL_CAP)
        self.assertGreater(sum(len(line) for line in log), jobs.LOG_TOTAL_CAP // 8,
                           "the cap must trim the oldest lines, not empty the log")

    def test_line_trim_semantics_are_preserved(self):
        """The pre-existing 800-line window still applies to short lines."""
        log: list[str] = []
        rc = jobs.run_watchdog(["/bin/sh", "-c", "seq 1 3000"], timeout=60, log=log)
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(log), 800)
        self.assertIn("3000", log[-1], "the newest output must survive the trim")

    def test_binary_output_does_not_kill_the_read(self):
        log: list[str] = []
        rc = jobs.run_watchdog(
            ["/bin/sh", "-c", "printf 'a\\377b\\n'; echo done"],
            timeout=30, log=log,
        )
        self.assertEqual(rc, 0, f"binary bytes must be replaced, not raised: {log}")
        self.assertIn("done", log)


class StreamJobCommandTests(unittest.TestCase):
    def test_silent_hang_hits_the_deadline(self):
        """No output at all: the in-loop deadline check never runs, so only
        an independent watchdog can release the blocked reader."""
        job: dict = {"log": []}
        started = time.monotonic()
        rc = containers_svc._stream_job_command(
            ["/bin/sh", "-c", "sleep 30"], job, timeout=2,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(rc, 124)
        self.assertLess(elapsed, 25, "the silent child must be reaped at the deadline")
        self.assertTrue(any("timeout" in line for line in job["log"]))

    def test_one_giant_line_is_capped(self):
        job: dict = {"log": []}
        rc = containers_svc._stream_job_command(
            ["/bin/sh", "-c",
             "head -c 2000000 /dev/zero | tr '\\0' 'x'; echo; echo done"],
            job, timeout=60,
        )
        self.assertEqual(rc, 0)
        self.assertIn("done", job["log"])
        self.assertLessEqual(
            max(len(line) for line in job["log"]),
            containers_svc.JOB_LOG_LINE_CAP + 32,
        )
        self.assertLessEqual(
            sum(len(line) for line in job["log"]),
            containers_svc.JOB_LOG_TOTAL_CAP,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
