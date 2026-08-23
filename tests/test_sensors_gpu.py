"""GPU sample on GET /api/system/sensors from IOAccelerator (ioreg plist)."""
from __future__ import annotations

import json
import plistlib
import unittest
from unittest import mock

from hub import sensors_svc


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
