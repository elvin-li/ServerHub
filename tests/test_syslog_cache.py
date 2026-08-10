"""`log show` must be cached: it cost 10-21s on *every* syslog request.

macOS scans the unified log archive on each `log show`, measured at 10-21s on this
host. It was the only heavy reader in ``hub/tools_svc.py`` without a cache --
``hardware_profile`` and ``updates`` in the same module both have one -- so opening
the Logs page, or leaving it polling, paid the full scan every time.

The cache is keyed on the query because a different window or level is a different
scan, and the refresh is single-flighted so a second viewer arriving mid-scan waits
for that result instead of starting its own.
"""
from __future__ import annotations

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import tools_svc  # noqa: E402

LOG_OUTPUT = "2026-08-05 11:00:00 error something broke\n"


class SyslogCacheTests(unittest.TestCase):
    def setUp(self):
        tools_svc._syslog_cache.clear()
        self.addCleanup(tools_svc._syslog_cache.clear)
        self.calls: list[list[str]] = []

    def _sh(self, cmd, timeout=None):
        self.calls.append(list(cmd))
        return (0, LOG_OUTPUT, "")

    def test_second_identical_request_does_not_rerun_log_show(self):
        with patch.object(tools_svc, "sh", side_effect=self._sh):
            first = tools_svc.syslog_tail(minutes=60, limit=80, level="error")
            second = tools_svc.syslog_tail(minutes=60, limit=80, level="error")
        self.assertEqual(len(self.calls), 1, "log show ran twice for one query")
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(first["lines"], second["lines"])

    def test_a_different_query_is_a_different_scan(self):
        with patch.object(tools_svc, "sh", side_effect=self._sh):
            tools_svc.syslog_tail(minutes=60, limit=80, level="error")
            tools_svc.syslog_tail(minutes=60, limit=80, level="fault")
            tools_svc.syslog_tail(minutes=30, limit=80, level="error")
        self.assertEqual(len(self.calls), 3)

    def test_force_bypasses_the_cache(self):
        """An explicit refresh on the page must reach the log, not the cache."""
        with patch.object(tools_svc, "sh", side_effect=self._sh):
            tools_svc.syslog_tail(minutes=60, limit=80, level="error")
            result = tools_svc.syslog_tail(minutes=60, limit=80, level="error", force=True)
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(result["cached"])

    def test_concurrent_viewers_share_one_scan(self):
        started = threading.Event()
        release = threading.Event()

        def slow_sh(cmd, timeout=None):
            self.calls.append(list(cmd))
            started.set()
            release.wait(timeout=5)
            return (0, LOG_OUTPUT, "")

        with patch.object(tools_svc, "sh", side_effect=slow_sh):
            with ThreadPoolExecutor(max_workers=4) as ex:
                futures = [
                    ex.submit(tools_svc.syslog_tail, 60, 80, "error") for _ in range(4)
                ]
                self.assertTrue(started.wait(timeout=5))
                release.set()
                results = [f.result(timeout=10) for f in futures]

        self.assertEqual(len(self.calls), 1, "concurrent viewers each ran log show")
        self.assertTrue(all(r["lines"] == [LOG_OUTPUT.strip()] for r in results))

    def test_a_failed_scan_is_not_cached(self):
        """Caching a failure would pin the error for the whole TTL."""
        attempts = {"n": 0}

        def failing(cmd, timeout=None):
            attempts["n"] += 1
            return (1, "", "log: boom")

        with (
            patch.object(tools_svc, "sh", side_effect=failing),
            patch.object(tools_svc.Path, "exists", return_value=False),
        ):
            tools_svc.syslog_tail(minutes=60, limit=80, level="error")
            tools_svc.syslog_tail(minutes=60, limit=80, level="error")
        self.assertEqual(attempts["n"], 2)

    def test_cache_does_not_grow_without_bound(self):
        with patch.object(tools_svc, "sh", side_effect=self._sh):
            for minutes in range(5, 60):
                tools_svc.syslog_tail(minutes=minutes, limit=80, level="error")
        self.assertLessEqual(len(tools_svc._syslog_cache), 24)


if __name__ == "__main__":
    unittest.main()
