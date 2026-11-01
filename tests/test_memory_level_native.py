"""The free-memory percentage is read in-process, not from `memory_pressure`.

`memory_pressure -Q` prints the kernel's ``memorystatus_level``; the
``kern.memorystatus_level`` sysctl reads the same variable without a spawn.
The status, sensors and metrics collectors each spawned the command (about
three times a minute with the dashboard open, and once a minute when idle,
the panel's last idle spawn).  These tests check the native value is the one
the command prints, that each collector uses it without spawning, and that
each still falls back to the command when the read fails.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import macos_sysctl, metrics, sensors_svc, system  # noqa: E402

PRINTED = (
    "The system has 34359738368 (2097152 pages with a page size of 16384).\n"
    "System-wide memory free percentage: 33%\n"
)


class _Recorder:
    """Stand-in for a runner: records argv, answers memory_pressure only."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, *args, **kwargs):
        self.calls.append([str(a) for a in argv])
        if "memory_pressure" in self.calls[-1][0]:
            return 0, PRINTED, ""
        return 1, "", ""

    @property
    def spawned_memory_pressure(self) -> bool:
        return any("memory_pressure" in argv[0] for argv in self.calls)


class MemoryLevelTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop("SERVERHUB_NO_NATIVE_MEMLEVEL", None)

    @unittest.skipUnless(
        sys.platform == "darwin" and os.path.exists("/usr/bin/memory_pressure"),
        "needs macOS memory_pressure",
    )
    def test_the_native_value_is_what_memory_pressure_prints(self):
        pairs = []
        for _ in range(3):
            native = macos_sysctl.memory_free_pct()
            out = subprocess.run(
                ["/usr/bin/memory_pressure", "-Q"],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout
            printed = int(re.search(r"free percentage: (\d+)%", out).group(1))
            pairs.append((native, printed))
            if native == printed:
                break
        # One variable read a moment apart: equal unless it moved in between.
        self.assertTrue(any(n == p for n, p in pairs), pairs)

    def test_a_failed_or_out_of_range_read_is_none(self):
        for raw in (None, 101, 2**32 - 1):
            with self.subTest(raw=raw), \
                    mock.patch.object(macos_sysctl, "_read_int", return_value=raw):
                self.assertIsNone(macos_sysctl.memory_free_pct())
        with mock.patch.object(macos_sysctl, "_read_int", return_value=0):
            self.assertEqual(macos_sysctl.memory_free_pct(), 0)

    def test_the_env_flag_turns_the_read_off(self):
        os.environ["SERVERHUB_NO_NATIVE_MEMLEVEL"] = "1"
        with mock.patch.object(macos_sysctl, "_read_int", return_value=57):
            self.assertIsNone(macos_sysctl.memory_free_pct())

    # -- the three collectors ------------------------------------------------
    def _status(self, native):
        run = _Recorder()
        with mock.patch.object(macos_sysctl, "memory_free_pct", return_value=native), \
                mock.patch.object(system, "sh", side_effect=run):
            got = system.collect_system()
        return got.get("mem_free_pct"), run

    def _sensors(self, native):
        run = _Recorder()
        with mock.patch.object(macos_sysctl, "memory_free_pct", return_value=native), \
                mock.patch.object(sensors_svc, "_sh_run", side_effect=run), \
                mock.patch.object(sensors_svc, "_safe_breakdown", return_value={}):
            got = sensors_svc._memory_base(include_model=False)
        return got["mem_free_pct"], run

    def _metrics(self, native):
        run = _Recorder()
        with mock.patch.object(macos_sysctl, "memory_free_pct", return_value=native), \
                mock.patch.object(metrics, "_sensors_snapshot", return_value={}), \
                mock.patch.object(metrics, "sh", side_effect=run):
            got = metrics._sample()
        return got["mem_free_pct"], run

    def test_collectors_use_the_native_value_without_spawning(self):
        for name, collect in (("status", self._status), ("sensors", self._sensors),
                              ("metrics", self._metrics)):
            with self.subTest(name):
                value, run = collect(57)
                self.assertEqual(value, 57)
                self.assertFalse(run.spawned_memory_pressure, run.calls)

    def test_collectors_fall_back_to_memory_pressure(self):
        for name, collect in (("status", self._status), ("sensors", self._sensors),
                              ("metrics", self._metrics)):
            with self.subTest(name):
                value, run = collect(None)
                self.assertEqual(value, 33)
                self.assertTrue(run.spawned_memory_pressure, run.calls)


if __name__ == "__main__":
    unittest.main()
