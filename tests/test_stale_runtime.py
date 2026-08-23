"""KeepAlive PIDs on a deleted Homebrew Python must not look healthy.

After a ``brew upgrade python@3.12`` the old Cellar path is gone, but
launchd keeps the process that launched against it.  TCP still accepts,
so the services table stayed green while ESPHome's UI died inside
aiohttp.  ``hub.stale_runtime`` is the watchdog: ``scan`` finds those
PIDs, the health page warns, and the alerter kickstarts (panel last).
"""
from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hub import alerts, health_svc, stale_runtime
from hub.paths import UID


GONE = "/opt/homebrew/Cellar/python@3.12/3.12.13_4/Python"


class _Listing:
    def __init__(self, pids: dict[str, str | None]):
        self._pids = pids

    def pid_for(self, label: str):
        return self._pids.get(label)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        stale_runtime._last_kick.clear()

    def _write(self, label: str, **body):
        payload = {"Label": label, "ProgramArguments": ["/bin/zsh"], **body}
        (self.dir / f"{label}.plist").write_bytes(plistlib.dumps(payload))

    def _scan(self, pids: dict[str, str | None], exe=GONE):
        with (
            patch.object(stale_runtime, "AGENTS_DIR", self.dir),
            patch.object(stale_runtime, "launchd_listing", lambda: _Listing(pids)),
            patch.object(stale_runtime, "pid_exe_path", lambda pid: exe),
        ):
            return stale_runtime.scan()

    def test_missing_exe_is_stale(self):
        self._write("local.esphome", KeepAlive=True)
        rows = self._scan({"local.esphome": "4242"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "local.esphome")
        self.assertEqual(rows[0]["pid"], 4242)
        self.assertEqual(rows[0]["exe"], GONE)

    def test_present_exe_is_clean(self):
        self._write("local.esphome", KeepAlive=True)
        rows = self._scan({"local.esphome": "4242"}, exe="/bin/sh")
        self.assertEqual(rows, [])

    def test_no_pid_is_skipped(self):
        self._write("local.esphome", KeepAlive=True)
        rows = self._scan({"local.esphome": None})
        self.assertEqual(rows, [])

    def test_unreadable_exe_is_not_stale(self):
        self._write("local.esphome", KeepAlive=True)
        rows = self._scan({"local.esphome": "4242"}, exe=None)
        self.assertEqual(rows, [])


class PidExePathTests(unittest.TestCase):
    """next-server blanks proc_pidpath; lsof txt still names the Cellar node."""

    def setUp(self):
        stale_runtime.invalidate_exe_cache()
        self.addCleanup(stale_runtime.invalidate_exe_cache)

    def test_lsof_txt_when_proc_pidpath_empty_and_ps_is_a_title(self):
        calls: list[list[str]] = []

        def fake_sh(cmd, **kwargs):
            calls.append(list(cmd))
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, "next-server (v16.2.12)", ""
            if cmd[0] == "/usr/sbin/lsof":
                return 0, "p2761\nftxt\nn/opt/homebrew/Cellar/node/26.5.0_1/bin/node\n", ""
            return 1, "", ""

        with (
            patch.object(stale_runtime, "_LIBC", None),
            patch.object(stale_runtime, "sh", fake_sh),
        ):
            path = stale_runtime.pid_exe_path(2761)
        self.assertEqual(path, "/opt/homebrew/Cellar/node/26.5.0_1/bin/node")
        self.assertTrue(any(c[0] == "/usr/sbin/lsof" for c in calls))

    def test_lsof_skips_a_leading_dylib(self):
        def fake_sh(cmd, **kwargs):
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, "next-server (v16.2.12)", ""
            if cmd[0] == "/usr/sbin/lsof":
                return 0, (
                    "p2761\n"
                    "ftxt\n"
                    "n/opt/homebrew/Cellar/node/26.5.0_1/lib/libnode.dylib\n"
                    "ftxt\n"
                    "n/opt/homebrew/Cellar/node/26.5.0_1/bin/node\n"
                ), ""
            return 1, "", ""

        with (
            patch.object(stale_runtime, "_LIBC", None),
            patch.object(stale_runtime, "sh", fake_sh),
        ):
            self.assertEqual(
                stale_runtime.pid_exe_path(2761),
                "/opt/homebrew/Cellar/node/26.5.0_1/bin/node",
            )

    def test_lsof_stdout_is_used_even_when_exit_is_nonzero(self):
        def fake_sh(cmd, **kwargs):
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, "next-server (v16.2.12)", ""
            if cmd[0] == "/usr/sbin/lsof":
                return 1, "p2761\nftxt\nn/opt/homebrew/Cellar/node/26.5.0_1/bin/node\n", "lsof: no pwd"
            return 1, "", ""

        with (
            patch.object(stale_runtime, "_LIBC", None),
            patch.object(stale_runtime, "sh", fake_sh),
        ):
            self.assertEqual(
                stale_runtime.pid_exe_path(2761),
                "/opt/homebrew/Cellar/node/26.5.0_1/bin/node",
            )

    def test_absolute_ps_command_skips_lsof(self):
        def fake_sh(cmd, **kwargs):
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, "/opt/homebrew/opt/python@3.14/bin/python3.14 -m uvicorn", ""
            raise AssertionError(f"unexpected {cmd}")

        with (
            patch.object(stale_runtime, "_LIBC", None),
            patch.object(stale_runtime, "sh", fake_sh),
        ):
            self.assertEqual(
                stale_runtime.pid_exe_path(9),
                "/opt/homebrew/opt/python@3.14/bin/python3.14",
            )

    def test_second_lookup_does_not_respawn_lsof(self):
        calls: list[list[str]] = []

        def fake_sh(cmd, **kwargs):
            calls.append(list(cmd))
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, "next-server (v16.2.12)", ""
            if cmd[0] == "/usr/sbin/lsof":
                return 0, "p2761\nftxt\nn/opt/homebrew/Cellar/node/26.5.0_1/bin/node\n", ""
            return 1, "", ""

        with (
            patch.object(stale_runtime, "_LIBC", None),
            patch.object(stale_runtime, "sh", fake_sh),
        ):
            first = stale_runtime.pid_exe_path(2761)
            second = stale_runtime.pid_exe_path(2761)
        self.assertEqual(first, second)
        self.assertEqual(sum(1 for c in calls if c[0] == "/usr/sbin/lsof"), 1)


class ScanSkipTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        stale_runtime._last_kick.clear()

    def _write(self, label: str, **body):
        payload = {"Label": label, "ProgramArguments": ["/bin/zsh"], **body}
        (self.dir / f"{label}.plist").write_bytes(plistlib.dumps(payload))

    def _scan(self, pids: dict[str, str | None], exe=GONE):
        with (
            patch.object(stale_runtime, "AGENTS_DIR", self.dir),
            patch.object(stale_runtime, "launchd_listing", lambda: _Listing(pids)),
            patch.object(stale_runtime, "pid_exe_path", lambda pid: exe),
        ):
            return stale_runtime.scan()

    def test_disabled_plist_is_skipped(self):
        self._write("local.esphome", KeepAlive=True, Disabled=True)
        rows = self._scan({"local.esphome": "4242"})
        self.assertEqual(rows, [])

    def test_interval_job_is_skipped(self):
        self._write(
            "local.nightly",
            StartCalendarInterval={"Hour": 3, "Minute": 30},
        )
        rows = self._scan({"local.nightly": "4242"})
        self.assertEqual(rows, [])

    def test_health_checks_warn(self):
        with patch.object(stale_runtime, "scan", lambda: [
            {"label": "local.esphome", "pid": 1, "exe": GONE},
        ]):
            rows = stale_runtime.health_checks()
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ok"])
        self.assertEqual(rows[0]["id"], "stale_runtime")
        self.assertEqual(rows[0]["level"], "warn")
        self.assertIn("local.esphome", rows[0]["detail"])
        self.assertIn("kickstart", rows[0]["fix"])

    def test_health_checks_silent_when_clean(self):
        with patch.object(stale_runtime, "scan", lambda: []):
            self.assertEqual(stale_runtime.health_checks(), [])


class RemediateTests(unittest.TestCase):
    def setUp(self):
        stale_runtime._last_kick.clear()
        self.addCleanup(stale_runtime._last_kick.clear)

    def test_kickstarts_once_then_cooldown(self):
        rows = [
            {"label": "com.elvin.serverhub", "pid": 2, "exe": GONE},
            {"label": "local.esphome", "pid": 1, "exe": GONE},
            {"label": "local.kidsmusic", "pid": 3, "exe": GONE},
        ]
        calls: list[list[str]] = []

        def fake_sh(cmd, **kwargs):
            calls.append(list(cmd))
            return 0, "", ""

        def fake_emit(**kwargs):
            return {"id": kwargs["alert_id"]}

        invalidated = []
        with (
            patch.object(stale_runtime, "scan", lambda: rows),
            patch.object(stale_runtime, "sh", fake_sh),
            patch.object(stale_runtime, "invalidate_launchd", lambda: invalidated.append(1)),
            patch("hub.alerts.emit_alert", fake_emit),
        ):
            first = stale_runtime.remediate(1000)
            n_first = len(calls)
            stale_runtime.remediate(1100)
            self.assertEqual(len(calls), n_first, "cooldown must suppress a second kick")
            stale_runtime.remediate(1000 + stale_runtime.KICK_COOLDOWN_SEC)
            self.assertEqual(len(calls), n_first * 2)

        labels = [c[-1].rsplit("/", 1)[-1] for c in calls[:3]]
        self.assertEqual(labels[-1], "com.elvin.serverhub", "panel label must be last")
        self.assertEqual(sorted(labels[:2]), ["local.esphome", "local.kidsmusic"])
        self.assertTrue(all(
            c[:3] == ["/bin/launchctl", "kickstart", "-k"] for c in calls
        ))
        self.assertTrue(all(c[-1].startswith(f"gui/{UID}/") for c in calls))
        self.assertEqual(
            [a["id"] for a in first],
            [
                "stale_runtime:local.esphome",
                "stale_runtime:local.kidsmusic",
                "stale_runtime:com.elvin.serverhub",
            ],
        )
        self.assertEqual(invalidated, [1, 1], "each kick wave drops the listing cache")

    def test_failed_kickstart_retries_before_full_cooldown(self):
        rows = [{"label": "local.esphome", "pid": 1, "exe": GONE}]
        calls: list[list[str]] = []

        def fake_sh(cmd, **kwargs):
            calls.append(list(cmd))
            return 1, "", "not loaded"

        with (
            patch.object(stale_runtime, "scan", lambda: rows),
            patch.object(stale_runtime, "sh", fake_sh),
            patch.object(stale_runtime, "invalidate_launchd", lambda: None),
            patch("hub.alerts.emit_alert", lambda **kw: {"id": kw["alert_id"]}),
        ):
            stale_runtime.remediate(1000)
            stale_runtime.remediate(1030)
            self.assertEqual(len(calls), 1, "must not retry inside the fail cooldown")
            stale_runtime.remediate(1000 + stale_runtime.KICK_FAIL_COOLDOWN_SEC)
            self.assertEqual(len(calls), 2)

    def test_failed_kickstart_does_not_claim_restarted(self):
        rows = [{"label": "local.esphome", "pid": 1, "exe": GONE}]
        recorded = []

        def fake_emit(**kwargs):
            recorded.append(kwargs["message"])
            return {"id": kwargs["alert_id"]}

        with (
            patch.object(stale_runtime, "scan", lambda: rows),
            patch.object(stale_runtime, "sh", lambda *a, **k: (1, "", "not loaded")),
            patch.object(stale_runtime, "invalidate_launchd", lambda: None),
            patch("hub.alerts.emit_alert", fake_emit),
        ):
            stale_runtime.remediate(1000)
        self.assertEqual(len(recorded), 1)
        self.assertIn("Could not restart local.esphome", recorded[0])
        self.assertNotIn("Restarted local.esphome", recorded[0])

    def test_overlapping_sweeps_kick_once(self):
        import threading

        rows = [{"label": "local.esphome", "pid": 1, "exe": GONE}]
        calls: list[list[str]] = []
        gate = threading.Barrier(8)

        def gated_scan():
            gate.wait(timeout=2)
            return rows

        def fake_sh(cmd, **kwargs):
            calls.append(list(cmd))
            return 0, "", ""

        with (
            patch.object(stale_runtime, "scan", gated_scan),
            patch.object(stale_runtime, "sh", fake_sh),
            patch.object(stale_runtime, "invalidate_launchd", lambda: None),
            patch("hub.alerts.emit_alert", lambda **kw: {"id": kw["alert_id"]}),
        ):
            threads = [
                threading.Thread(target=stale_runtime.remediate, args=(1000,))
                for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=2)
        self.assertEqual(len(calls), 1, f"double-kicked: {calls}")

    def test_clean_scan_does_not_touch_launchctl(self):
        calls = []
        with (
            patch.object(stale_runtime, "scan", lambda: []),
            patch.object(stale_runtime, "sh", lambda *a, **k: calls.append(1) or (0, "", "")),
        ):
            self.assertEqual(stale_runtime.remediate(1000), [])
        self.assertEqual(calls, [])


class WiringTests(unittest.TestCase):
    """A watchdog that is never called tests nothing."""

    def test_health_svc_calls_the_probe(self):
        source = Path(health_svc.__file__).read_text()
        self.assertIn("_stale_runtime_checks", source)
        self.assertIn("stale_runtime.health_checks()", source)

    def test_alerts_check_once_calls_remediate(self):
        source = Path(alerts.__file__).read_text()
        self.assertIn("stale_runtime.remediate", source)

    def test_check_once_runs_remediate(self):
        called = []
        quiet = lambda *a, **k: []  # noqa: E731
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with (
                patch.object(alerts, "ALERTS_FILE", tmp_path / "alerts.jsonl"),
                patch.object(alerts, "STATE_FILE", tmp_path / "alert_state.json"),
                patch.object(alerts, "full_status", lambda force=False: {"groups": []}),
                patch.object(alerts, "_check_resource_thresholds", quiet),
                patch.object(alerts, "_check_smart_health", quiet),
                patch.object(alerts, "_check_ups", quiet),
                patch("hub.freshness_svc.check_freshness", quiet),
                patch("hub.ups_policy.sweep", lambda now: []),
                patch("hub.stale_runtime.remediate", lambda now=None: called.append(now) or []),
            ):
                alerts.check_once()
        self.assertEqual(len(called), 1, "check_once never reached remediate")


class RemediateClockLeftoverTests(unittest.TestCase):
    def test_infinite_clock_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to 500 the alerter kickstart."""
        with (
            patch.object(stale_runtime, "scan", return_value=[]),
            patch.object(stale_runtime.time, "time", return_value=float("inf")),
        ):
            self.assertEqual(stale_runtime.remediate(), [])


if __name__ == "__main__":
    unittest.main()
