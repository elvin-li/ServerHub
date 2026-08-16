"""Repeated subprocess timeouts must not reprint into the panel log.

`brew outdated` and `brew services list --json` hung past their timeouts
for hours on this host.  `sh()` already returns a fallback; logging every
call filled ~/Library/Logs/serverhub.err.log with the same line.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import util  # noqa: E402


class TimeoutLogTests(unittest.TestCase):
    def setUp(self):
        with util._noisy_log_lock:
            util._noisy_log_at.clear()

    def test_repeated_timeout_logs_once(self):
        expired = subprocess.TimeoutExpired(["brew", "outdated"], 1)
        with patch.object(util.subprocess, "run", side_effect=expired):
            with patch.object(util.log, "warning") as warn:
                self.assertEqual(util.sh(["brew", "outdated"], timeout=1)[2], "timeout")
                self.assertEqual(util.sh(["brew", "outdated"], timeout=1)[2], "timeout")
        self.assertEqual(warn.call_count, 1)

    def test_different_commands_log_separately(self):
        expired = subprocess.TimeoutExpired("brew", 1)
        with patch.object(util.subprocess, "run", side_effect=expired):
            with patch.object(util.log, "warning") as warn:
                util.sh(["brew", "outdated"], timeout=1)
                util.sh(["brew", "services", "list", "--json"], timeout=1)
        self.assertEqual(warn.call_count, 2)

    def test_gap_allows_another_line(self):
        expired = subprocess.TimeoutExpired(["brew", "outdated"], 1)
        with util._noisy_log_lock:
            util._noisy_log_at[("timeout", ("brew", "outdated"))] = 1.0
        with patch.object(util.subprocess, "run", side_effect=expired):
            with patch.object(util.log, "warning") as warn:
                util.sh(["brew", "outdated"], timeout=1)
        self.assertEqual(warn.call_count, 1)


class BrewOutdatedCooldownTests(unittest.TestCase):
    def setUp(self):
        from hub import tools_svc

        self.tools_svc = tools_svc
        self.tools_svc._brew_retry_at = 0.0
        self.addCleanup(setattr, tools_svc, "_brew_retry_at", 0.0)

    def test_cooldown_skips_brew_after_a_timeout(self):
        svc = self.tools_svc
        svc._updates_cache.update(
            t=svc.time.time(),
            v={"brew": {"ok": False, "outdated": [], "count": 0, "raw": "timeout"}},
        )
        self.addCleanup(svc._updates_cache.update, t=0.0, v=None)
        svc._brew_retry_at = svc.time.time() + 60
        with patch.object(svc, "sh") as sh:
            out = svc._brew_outdated()
        sh.assert_not_called()
        self.assertEqual(out["raw"], "timeout")

    def test_timeout_opens_the_cooldown(self):
        svc = self.tools_svc
        with (
            patch.object(svc, "BREW", "/opt/homebrew/bin/brew"),
            patch.object(svc.Path, "exists", return_value=True),
            patch.object(svc, "sh", return_value=(-1, "", "timeout")),
        ):
            out = svc._brew_outdated()
        self.assertEqual(out["raw"], "timeout")
        self.assertGreater(svc._brew_retry_at, svc.time.time())


if __name__ == "__main__":
    unittest.main()
