"""GPU sample on GET /api/system/sensors from IOAccelerator (IOKit or ioreg plist)."""
from __future__ import annotations

import json
import os
import plistlib
import sys
import unittest
from unittest import mock

from hub import gpu_native, sensors_svc
from hub.util import sh as real_sh


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _accel_xml(stats=None, model="Apple M1 Pro", extra=None):
    item = {"model": model, "PerformanceStatistics": stats or {}}
    if extra:
        item.update(extra)
    return plistlib.dumps([item], fmt=plistlib.FMT_XML).decode("utf-8")


class GpuCollectorTests(unittest.TestCase):
    def test_happy_path_reads_ioreg_plist(self):
        xml = _accel_xml({
            "Device Utilization %": 68,
            "In use system memory": 1159086080,
            "Alloc system memory": 8613429248,
        })
        seen = []

        def fake_sh(argv, **kwargs):
            seen.append(list(argv))
            return 0, xml, ""

        with mock.patch.object(sensors_svc, "sh", side_effect=fake_sh):
            data = sensors_svc._gpu()
        self.assertEqual(
            seen[0],
            ["/usr/sbin/ioreg", "-a", "-r", "-d", "1", "-c", "IOAccelerator"],
        )
        self.assertEqual(data["util_pct"], 68.0)
        self.assertEqual(data["mem_used_bytes"], 1159086080)
        self.assertEqual(data["mem_alloc_bytes"], 8613429248)
        self.assertEqual(data["model"], "Apple M1 Pro")
        _json(data)

    def test_picks_accelerator_with_utilization(self):
        xml = plistlib.dumps([
            {"model": "Display", "PerformanceStatistics": {"Alloc system memory": 1}},
            {
                "model": "Apple M1 Pro",
                "PerformanceStatistics": {
                    "Device Utilization %": 12.4,
                    "In use system memory": 100,
                    "Alloc system memory": 200,
                },
            },
        ], fmt=plistlib.FMT_XML).decode("utf-8")
        with mock.patch.object(sensors_svc, "sh", return_value=(0, xml, "")):
            data = sensors_svc._gpu()
        self.assertEqual(data["model"], "Apple M1 Pro")
        self.assertEqual(data["util_pct"], 12.4)

    def test_command_failure_returns_none(self):
        with mock.patch.object(sensors_svc, "sh", return_value=(1, "", "boom")):
            self.assertIsNone(sensors_svc._gpu())

    def test_empty_and_invalid_plist_return_none(self):
        with mock.patch.object(sensors_svc, "sh", return_value=(0, "", "")):
            self.assertIsNone(sensors_svc._gpu())
        with mock.patch.object(sensors_svc, "sh", return_value=(0, "not a plist", "")):
            self.assertIsNone(sensors_svc._gpu())
        empty = plistlib.dumps([], fmt=plistlib.FMT_XML).decode("utf-8")
        with mock.patch.object(sensors_svc, "sh", return_value=(0, empty, "")):
            self.assertIsNone(sensors_svc._gpu())

    def test_ioreg_raise_returns_none(self):
        with mock.patch.object(sensors_svc, "sh", side_effect=RuntimeError("ioreg")):
            self.assertIsNone(sensors_svc._gpu())

    def test_nonfinite_util_and_huge_bytes_are_null(self):
        xml = _accel_xml({
            "Device Utilization %": float("inf"),
            "In use system memory": "9" * 400,
            "Alloc system memory": True,
        }, model="Apple M1 Pro")
        with mock.patch.object(sensors_svc, "sh", return_value=(0, xml, "")):
            data = sensors_svc._gpu()
        self.assertEqual(data["model"], "Apple M1 Pro")
        self.assertIsNone(data["util_pct"])
        self.assertIsNone(data["mem_used_bytes"])
        self.assertIsNone(data["mem_alloc_bytes"])
        _json(data)

    def test_bool_utilization_is_not_one_percent(self):
        xml = _accel_xml({"Device Utilization %": True})
        with mock.patch.object(sensors_svc, "sh", return_value=(0, xml, "")):
            data = sensors_svc._gpu()
        self.assertIsNone(data["util_pct"])


class GpuCollectWiringTests(unittest.TestCase):
    def tearDown(self):
        sensors_svc._cache.update(t=0.0, v=None)

    def _patches(self, **kwargs):
        defaults = {
            "_thermal": None,
            "_gpu": None,
            "_disk": {"root_pct": 11},
            "_memory_base": {"ncpu": 8, "load1": 0.1, "load5": 0.1, "load15": 0.1},
            "_cpu_and_mem_from_top_cached": {},
            "_cpu_from_ticks": {"used_pct": 4},
            "_network_rates": {},
            "_top_processes": [],
            "_uptime": {"uptime_text": "1h"},
        }
        defaults.update(kwargs)
        return mock.patch.multiple(sensors_svc, **{
            name: mock.MagicMock(side_effect=value)
            if isinstance(value, BaseException)
            else mock.MagicMock(return_value=value)
            for name, value in defaults.items()
        })

    def test_collect_includes_gpu_object(self):
        gpu = {
            "util_pct": 68.0,
            "mem_used_bytes": 1159086080,
            "mem_alloc_bytes": 8613429248,
            "model": "Apple M1 Pro",
        }
        with self._patches(_gpu=gpu):
            data = sensors_svc._collect_sensors_uncached()
        self.assertEqual(data["gpu"], gpu)
        self.assertEqual(data["disk"]["root_pct"], 11)
        _json(data)

    def test_gpu_raise_does_not_drop_disk_or_500(self):
        with self._patches(_gpu=RuntimeError("ioreg")):
            data = sensors_svc._collect_sensors_uncached()
        self.assertEqual(data["disk"]["root_pct"], 11)
        self.assertIsNone(data["gpu"])
        _json(data)

    def test_collect_light_includes_gpu(self):
        gpu = {
            "util_pct": 41.0,
            "mem_used_bytes": 1000,
            "mem_alloc_bytes": 2000,
            "model": "Apple M1 Pro",
        }
        with self._patches(_gpu=gpu):
            data = sensors_svc.collect_light()
        self.assertEqual(data["gpu"], gpu)
        self.assertTrue(data.get("light"))
        _json(data)


_IOREG = ["/usr/sbin/ioreg", "-a", "-r", "-d", "1", "-c", "IOAccelerator"]


class NativeGpuSourceTests(unittest.TestCase):
    """_gpu() asks IOKit first and spawns ``ioreg`` only when IOKit has no answer."""

    ENTRY = {
        "model": "Apple M1 Pro",
        "IORegistryEntryName": "AGXAcceleratorG13X",
        "PerformanceStatistics": {
            "Device Utilization %": 12,
            "In use system memory": 2048,
            "Alloc system memory": 4096,
        },
    }

    def test_an_iokit_answer_needs_no_ioreg_spawn(self):
        with (
            mock.patch.object(gpu_native, "accelerator_entries", return_value=[dict(self.ENTRY)]),
            mock.patch.object(sensors_svc, "sh", side_effect=AssertionError("ioreg spawned")),
        ):
            data = sensors_svc._gpu()
        self.assertEqual(data, {
            "util_pct": 12.0,
            "mem_used_bytes": 2048,
            "mem_alloc_bytes": 4096,
            "model": "Apple M1 Pro",
        })
        _json(data)

    def test_ioreg_answers_when_iokit_cannot(self):
        xml = _accel_xml({"Device Utilization %": 7}, model="From ioreg")
        for native in (None, [], "junk", RuntimeError("iokit")):
            with self.subTest(native=native):
                answer = (
                    {"side_effect": native} if isinstance(native, BaseException)
                    else {"return_value": native}
                )
                with (
                    mock.patch.object(gpu_native, "accelerator_entries", **answer),
                    mock.patch.object(sensors_svc, "sh", return_value=(0, xml, "")) as spawn,
                ):
                    data = sensors_svc._gpu()
                spawn.assert_called_once()
                self.assertEqual(spawn.call_args.args[0], _IOREG)
                self.assertEqual(data["model"], "From ioreg")
                self.assertEqual(data["util_pct"], 7.0)

    def test_the_suite_switch_and_other_platforms_skip_iokit(self):
        with (
            mock.patch.object(gpu_native, "_get_reader", side_effect=AssertionError("loaded")),
            mock.patch.dict(os.environ, {"SERVERHUB_NO_NATIVE_GPU": "1"}),
        ):
            self.assertIsNone(gpu_native.accelerator_entries())
        env = {k: v for k, v in os.environ.items() if k != "SERVERHUB_NO_NATIVE_GPU"}
        with (
            mock.patch.object(gpu_native, "_get_reader", side_effect=AssertionError("loaded")),
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(gpu_native, "_ON_MACOS", False),
        ):
            self.assertIsNone(gpu_native.accelerator_entries())

    def test_a_framework_that_fails_to_load_is_not_retried(self):
        env = {k: v for k, v in os.environ.items() if k != "SERVERHUB_NO_NATIVE_GPU"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(gpu_native, "_ON_MACOS", True),
            mock.patch.object(gpu_native, "_reader", None),
            mock.patch.object(gpu_native, "_unavailable", False),
            mock.patch.object(gpu_native, "_Reader", side_effect=OSError("no IOKit")) as load,
        ):
            self.assertIsNone(gpu_native.accelerator_entries())
            self.assertIsNone(gpu_native.accelerator_entries())
            self.assertEqual(load.call_count, 1)

    # Not os.path.exists(gpu_native._IOKIT): since macOS 11 system frameworks
    # live only in the dyld shared cache, and CDLL still loads them.
    @unittest.skipUnless(sys.platform == "darwin", "needs macOS IOKit")
    def test_iokit_reads_what_ioreg_reports_on_this_mac(self):
        env = {k: v for k, v in os.environ.items() if k != "SERVERHUB_NO_NATIVE_GPU"}
        with mock.patch.dict(os.environ, env, clear=True):
            native = gpu_native.accelerator_entries()
        rc, out, _ = real_sh(_IOREG, timeout=10)
        if rc != 0 or not out or not native:
            self.skipTest("no IOAccelerator on this host")
        listed = plistlib.loads(out.encode("utf-8", "replace"))
        self.assertEqual(len(native), len(listed))
        for mine, theirs in zip(native, listed):
            for key in ("model", "Model", "IORegistryEntryName", "IONameMatched"):
                self.assertEqual(mine.get(key), theirs.get(key), key)
            stats, their_stats = mine["PerformanceStatistics"], theirs["PerformanceStatistics"]
            self.assertEqual(sorted(stats), sorted(their_stats))
            for key, value in stats.items():
                # Readings move between two reads; their types do not.
                self.assertIs(type(value), type(their_stats[key]), key)
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(sensors_svc, "sh", side_effect=AssertionError("ioreg spawned")),
        ):
            data = sensors_svc._gpu()
        self.assertEqual(data["model"], listed[0].get("model"))
        _json(data)
