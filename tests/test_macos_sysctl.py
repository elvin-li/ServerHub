"""In-process integer sysctl (ctypes) with shell fallback.  Not kern.boottime."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from hub import macos_sysctl, metrics, sensors_svc, system


class SysctlIntHelperTests(unittest.TestCase):
    def test_live_integer_keys_are_positive(self):
        ncpu = macos_sysctl.sysctlbyname_int("hw.ncpu")
        mem = macos_sysctl.sysctlbyname_int("hw.memsize")
        page = macos_sysctl.sysctlbyname_int("hw.pagesize")
        self.assertIsInstance(ncpu, int)
        self.assertGreater(ncpu, 0)
        self.assertIsInstance(mem, int)
        self.assertGreater(mem, 0)
        self.assertIsInstance(page, int)
        self.assertGreater(page, 0)

    def test_boottime_is_not_an_integer_sysctl(self):
        self.assertNotIn("kern.boottime", macos_sysctl.INTEGER_KEYS)
        self.assertIsNone(macos_sysctl.sysctlbyname_int("kern.boottime"))
        self.assertIsNone(
            macos_sysctl.sysctl_int(
                "kern.boottime",
                sh=lambda *a, **k: (_ for _ in ()).throw(AssertionError("sh")),
            )
        )

    def test_ctypes_miss_falls_back_to_shell(self):
        def fake_sh(cmd, **kw):
            self.assertEqual(cmd, ["/usr/sbin/sysctl", "-n", "hw.ncpu"])
            return 0, "8", ""

        with patch.object(macos_sysctl, "sysctlbyname_int", return_value=None):
            self.assertEqual(macos_sysctl.sysctl_int("hw.ncpu", sh=fake_sh), 8)

    def test_leftover_shell_payloads(self):
        with patch.object(macos_sysctl, "sysctlbyname_int", return_value=None):
            self.assertIsNone(macos_sysctl.sysctl_int("hw.ncpu", sh=lambda *a, **k: (0, None, "")))
            self.assertEqual(
                macos_sysctl.sysctl_int("hw.ncpu", sh=lambda *a, **k: (0, b"8", "")),
                8,
            )
            self.assertEqual(
                macos_sysctl.sysctl_int("hw.ncpu", sh=lambda *a, **k: (0, 8, "")),
                8,
            )
            huge = macos_sysctl.sysctl_int(
                "hw.memsize", sh=lambda *a, **k: (0, "9" * 400, "")
            )
            self.assertEqual(huge, int("9" * 400))

    def test_zero_memsize_from_ctypes_falls_back(self):
        def fake_sh(cmd, **kw):
            return 0, str(16 * 2**30), ""

        with patch.object(macos_sysctl, "sysctlbyname_int", return_value=None):
            self.assertEqual(
                macos_sysctl.sysctl_int("hw.memsize", sh=fake_sh),
                16 * 2**30,
            )


class StaticHwTests(unittest.TestCase):
    def setUp(self):
        sensors_svc._static.update(t=0.0, ncpu=None, mem_gb=None, page_size=16384)
        self.addCleanup(
            sensors_svc._static.update,
            t=0.0, ncpu=None, mem_gb=None, page_size=16384,
        )

    def test_static_hw_does_not_shell_when_ctypes_works(self):
        def boom(*a, **k):
            raise AssertionError(f"sh {a}")

        with patch.object(sensors_svc, "sh", side_effect=boom):
            hw = sensors_svc._static_hw()
        self.assertIsInstance(hw["ncpu"], int)
        self.assertGreater(hw["ncpu"], 0)
        self.assertIsInstance(hw["mem_total_gb"], float)
        json.dumps(hw, allow_nan=False)

    def test_static_hw_cache_still_300s(self):
        self.assertEqual(sensors_svc._STATIC_TTL, 300.0)
        first = sensors_svc._static_hw()

        def boom(*a, **k):
            raise AssertionError("re-read")

        with (
            patch.object(macos_sysctl, "sysctl_int", side_effect=boom),
            patch.object(sensors_svc, "sh", side_effect=boom),
        ):
            again = sensors_svc._static_hw()
        self.assertEqual(again["ncpu"], first["ncpu"])


class CollectSystemSysctlTests(unittest.TestCase):
    def test_collect_system_uses_in_process_ncpu_without_shell(self):
        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "kern.boottime":
                return 0, "sec = 1,", ""
            if argv[0].endswith("memory_pressure"):
                return 0, "The system has 50% free percentage", ""
            raise AssertionError(f"unexpected sh {argv}")

        with (
            patch.object(system, "sh", side_effect=fake_sh),
            patch.object(system, "_smart_cache", {"t": 9e9, "v": None}),
        ):
            snap = system.collect_system()
        self.assertIsInstance(snap["ncpu"], int)
        self.assertGreater(snap["ncpu"], 0)
        self.assertIsInstance(snap["mem_total_gb"], float)
        json.dumps(snap, allow_nan=False)

    def test_collect_system_boottime_still_shells(self):
        seen = []

        def fake_sh(argv, **kwargs):
            seen.append(argv[-1] if argv else "")
            last = argv[-1]
            if last == "kern.boottime":
                return 0, "sec = 1,", ""
            if argv[0].endswith("memory_pressure"):
                return 0, "The system has 50% free percentage", ""
            return 1, "", ""

        with (
            patch.object(system, "sh", side_effect=fake_sh),
            patch.object(system, "_smart_cache", {"t": 9e9, "v": None}),
        ):
            system.collect_system()
        self.assertIn("kern.boottime", seen)
        self.assertNotIn("hw.ncpu", seen)
        self.assertNotIn("hw.memsize", seen)


class MetricsNcpuTests(unittest.TestCase):
    def setUp(self):
        metrics._ncpu_cache.update(t=0.0, n=None)

    def test_ncpu_does_not_shell_when_ctypes_works(self):
        def boom(*a, **k):
            raise AssertionError("sh")

        with patch.object(metrics, "sh", side_effect=boom):
            n = metrics._ncpu()
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_ncpu_cache_still_600s(self):
        self.assertEqual(metrics._NCPU_TTL, 600.0)
        n = metrics._ncpu()

        def boom(*a, **k):
            raise AssertionError("re-read")

        with (
            patch.object(macos_sysctl, "sysctl_int", side_effect=boom),
            patch.object(metrics, "sh", side_effect=boom),
        ):
            self.assertEqual(metrics._ncpu(), n)
