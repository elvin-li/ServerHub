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


class RunCappedTests(unittest.TestCase):
    def test_keeps_only_the_tail(self):
        rc, text = util.run_capped(
            ["/bin/sh", "-c", "python3 -c 'print(\"x\"*4000)'"],
            timeout=10,
            cap=64,
        )
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(text.encode("utf-8")), 80)
        self.assertIn("x", text)

    def test_missing_binary_is_not_found(self):
        rc, text = util.run_capped(["/no/such/serverhub-binary"], timeout=2)
        self.assertEqual(rc, -1)
        self.assertEqual(text, "not found")

    def test_oserror_is_not_a_500(self):
        with patch.object(util.subprocess, "run", side_effect=PermissionError("denied")):
            self.assertEqual(util.sh(["/bin/echo"], timeout=1)[0], -1)
            self.assertIn("denied", util.sh(["/bin/echo"], timeout=1)[2])

    def test_huge_stdout_is_capped_without_loading_the_prefix_into_return(self):
        saved = util._SH_CAP
        util._SH_CAP = 64
        self.addCleanup(setattr, util, "_SH_CAP", saved)
        rc, out, err = util.sh(
            ["/bin/sh", "-c", "python3 -c 'print(\"x\"*4000)'"],
            timeout=10,
        )
        self.assertEqual(rc, 0)
        self.assertLessEqual(len(out.encode("utf-8")), 64)
        self.assertTrue(out.startswith("x"))
        self.assertEqual(err, "")

    def test_sh_does_not_use_capture_output(self):
        source = Path(util.__file__).read_text(encoding="utf-8")
        body = source[source.index("def sh("): source.index("\ndef port_open")]
        self.assertNotIn("capture_output=True", body)
        self.assertIn("TemporaryFile", body)

    def test_gap_allows_another_line(self):
        expired = subprocess.TimeoutExpired(["brew", "outdated"], 1)
        with util._noisy_log_lock:
            util._noisy_log_at[("timeout", ("brew", "outdated"))] = 1.0
        with patch.object(util.subprocess, "run", side_effect=expired):
            with patch.object(util.log, "warning") as warn:
                util.sh(["brew", "outdated"], timeout=1)
        self.assertEqual(warn.call_count, 1)


class RunBytesTests(unittest.TestCase):
    def test_small_stdout_is_returned_intact(self):
        rc, data, err = util.run_bytes(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'plist')"],
            timeout=10,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(data, b"plist")
        self.assertEqual(err, b"")

    def test_oversize_stdout_is_refused_not_torn(self):
        rc, data, err = util.run_bytes(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*4000)"],
            timeout=10,
            cap=64,
        )
        self.assertEqual(rc, -1)
        self.assertEqual(data, b"")
        self.assertEqual(err, b"truncated")

    def test_stub_stdout_is_honoured(self):
        class Done:
            returncode = 0
            stdout = b"abc"

        rc, data, err = util.run_bytes(
            ["diskutil"], timeout=1, runner=lambda *a, **kw: Done(),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(data, b"abc")
        self.assertEqual(err, b"")

    def test_missing_binary(self):
        rc, data, err = util.run_bytes(["/no/such/serverhub-binary"], timeout=2)
        self.assertEqual(rc, -1)
        self.assertEqual(data, b"")
        self.assertEqual(err, b"not found")

    def test_does_not_use_capture_output(self):
        source = Path(util.__file__).read_text(encoding="utf-8")
        start = source.index("def run_bytes(")
        end = source.index("\n#: Per-stream ceiling for :func:`sh`")
        impl = source[start:end].split('"""', 2)[-1]
        self.assertNotIn("capture_output=True", impl)
        self.assertIn("TemporaryFile", impl)


class PortOpenLeftoverTests(unittest.TestCase):
    def test_infinite_port_does_not_raise(self):
        """YAML leftover ``port: .inf`` / ``.nan`` used to raise out of port_open."""
        self.assertFalse(util.port_open(float("inf")))
        self.assertFalse(util.port_open(float("nan")))
        self.assertFalse(util.port_open({}))
        self.assertIsNone(util.port_open(0))
        self.assertIsNone(util.port_open(None))


class BrewOutdatedCooldownTests(unittest.TestCase):
    def setUp(self):
        from hub import tools_svc

        self.tools_svc = tools_svc
        self.tools_svc._brew_retry_at = 0.0
        # Lifespan's hotpath warmer (and other tests in a combined run) can
        # leave a still-fresh _updates_cache hit; this test must see `sh`.
        self.tools_svc._updates_cache.update(t=0.0, v=None)
        self.addCleanup(setattr, tools_svc, "_brew_retry_at", 0.0)
        self.addCleanup(self.tools_svc._updates_cache.update, t=0.0, v=None)

    def test_cooldown_skips_brew_after_a_timeout(self):
        svc = self.tools_svc
        svc._updates_cache.update(
            t=svc.time.time(),
            v={"brew": {"ok": False, "outdated": [], "count": 0, "raw": "timeout"}},
        )
        self.addCleanup(svc._updates_cache.update, t=0.0, v=None)
        svc._brew_retry_at = svc.time.time() + 60
        brew = "/bin/sh" if Path("/bin/sh").exists() else sys.executable
        with patch.object(svc, "BREW", brew), patch.object(svc, "sh") as sh:
            out = svc._brew_outdated()
        sh.assert_not_called()
        self.assertEqual(out["raw"], "timeout")

    def test_timeout_opens_the_cooldown(self):
        svc = self.tools_svc
        with (
            patch.object(svc, "BREW", "/opt/homebrew/bin/brew"),
            patch.object(svc.Path, "exists", return_value=True),
            patch.object(svc, "_brew_busy", return_value=False),
            patch.object(svc, "sh", return_value=(-1, "", "timeout")),
        ):
            out = svc._brew_outdated()
        self.assertEqual(out["raw"], "timeout")
        self.assertGreater(svc._brew_retry_at, svc.time.time())


if __name__ == "__main__":
    unittest.main()
