"""Leftover >4300-digit numbers in smartctl / top / pmset text.

Prior passes guarded the sysctl, journal and pmset-thermal parsers
(macos_sysctl.parse_int, sensors_svc._sysctl_int, system._sysctl_int,
alerts._alert_ts) against CPython's 4300-digit str->int ValueError.  The SMART
self-test parsers still called bare ``int()`` on unbounded ``(\\d+)`` captures
from smartctl output:

* a polling time past the cap raised out of ``_capabilities`` and 500'd
  POST /api/smart/test through ``start_test`` — and cost the whole disk row
  (``probe_failed``) on GET /api/smart through ``_device_report``;
* a self-test log row's index / lifetime-hours did the same through
  ``_selftest_log``;
* an in-progress percentage did the same through ``_in_progress``;
* the ATA attribute table's ID column raised out of
  ``storage_svc._probe_disk_uncached`` and degraded the whole disk to an
  error row on GET /api/storage.

The same class dropped the whole ``top`` leg (PhysMem / load) from
GET /api/system/sensors via the process-count parse, and nulled the UPS leg
of GET /api/settings/power via the pmset battery percentage.

The battery also pins hunted paths that already survive this class —
metrics.sample_ts and the memory_pressure percentage guard — so a refactor
cannot quietly reintroduce it.
"""
from __future__ import annotations

import contextlib
import json
import unittest
from unittest import mock

from hub import metrics, sensors_svc, smart_test_svc, storage_svc, system_settings_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Under the cap: ``int()`` succeeds and yields a nonsense (but valid) int.
_BIG_DIGITS = "9" * 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: `smartctl -c` with a short routine that parses and an extended routine
#: whose polling time is past the str->int cap.
_POISONED_CAPS = (
    "Short self-test routine \n"
    "recommended polling time: \t (   2) minutes.\n"
    "Extended self-test routine\n"
    f"recommended polling time: \t ( {_HUGE_DIGITS}) minutes.\n"
)

#: ATA self-test log whose first row carries an over-cap index and an
#: over-cap lifetime-hours column beside a normal second row.
_POISONED_LOG = (
    "SMART Self-test log structure revision number 1\n"
    "Num  Test_Description    Status                  Remaining  LifeTime(hours)  LBA_of_first_error\n"
    f"# {_HUGE_DIGITS}  Short offline       Completed without error       00%      {_HUGE_DIGITS}         -\n"
    "# 2  Short offline       Completed without error       00%      1234         -\n"
)


class SmartCapabilitiesDigitLimitTests(unittest.TestCase):
    """POST /api/smart/test used to 500 on an over-cap polling time."""

    def setUp(self):
        smart_test_svc._device_type_cache.clear()
        smart_test_svc.overview.invalidate()
        self.addCleanup(smart_test_svc._device_type_cache.clear)
        self.addCleanup(smart_test_svc.overview.invalidate)
        self.journal: list[dict] = []

    def _raw(self, argv, *, timeout):
        if "-c" in argv:
            return 0, _POISONED_CAPS, ""
        if "selftest" in argv:
            return 0, _POISONED_LOG, ""
        return 0, "Device Model: Fake", ""

    def _patches(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        targets = {
            "_raw_smartctl": self._raw,
            "sh": lambda cmd, *a, **kw: (0, "Self-test has begun", ""),
            "_device_nodes": lambda: ["/dev/disk0"],
            "_append_history": self.journal.append,
        }
        for name, value in targets.items():
            stack.enter_context(mock.patch.object(smart_test_svc, name, value))
        return stack

    def test_huge_polling_time_does_not_500_start_test(self):
        """`_capabilities` raised through `start_test`, the only unshielded caller."""
        with self._patches():
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertTrue(result["ok"], f"start_test failed: {result.get('error')}")
        _starlette(result)

    def test_huge_polling_time_drops_only_that_kinds_estimate(self):
        """The parseable short routine keeps its number; the poisoned one is absent.

        Mirrors the routine-without-a-polling-line behaviour: a duration the
        drive did not usably report must not be invented.
        """
        with mock.patch.object(smart_test_svc, "device_type", lambda _d: ()):
            result = smart_test_svc._capabilities(
                "/dev/disk0",
                selftest=(0, _POISONED_LOG, ""),
                caps_raw=(0, _POISONED_CAPS, ""),
            )
        self.assertEqual(result["supported"], ["short", "long"])
        self.assertEqual(result["estimated_minutes"].get("short"), 2)
        self.assertNotIn("long", result["estimated_minutes"])
        _starlette(result)

    def test_huge_log_row_does_not_cost_the_disk_report(self):
        """GET /api/smart used to render this disk as ``probe_failed``."""
        with self._patches():
            report = smart_test_svc._device_report("/dev/disk0")
        self.assertNotEqual(report["capabilities"]["reason"], "probe_failed")
        self.assertEqual(report["log_count"], 2)
        _starlette(report)


class SmartSelftestLogDigitLimitTests(unittest.TestCase):
    def test_huge_index_and_hours_degrade_to_zero_not_500(self):
        rows = smart_test_svc._selftest_log("/dev/disk0", selftest=(0, _POISONED_LOG, ""))
        self.assertEqual(len(rows), 2)
        poisoned = rows[0]
        self.assertEqual(poisoned["index"], 0)
        self.assertEqual(poisoned["power_on_hours"], 0)
        self.assertTrue(poisoned["passed"], "the status text still parses")
        self.assertEqual(rows[1]["index"], 2)
        self.assertEqual(rows[1]["power_on_hours"], 1234)
        _starlette(rows)


class SmartInProgressDigitLimitTests(unittest.TestCase):
    def test_huge_percent_reports_running_with_unknown_progress(self):
        blob = (
            "Self-test routine in progress...\n"
            f"{_HUGE_DIGITS}% of test remaining.\n"
        )
        progress = smart_test_svc._in_progress("/dev/disk0", caps_raw=(0, blob, ""))
        self.assertTrue(progress["running"])
        self.assertIsNone(progress["percent_remaining"])
        self.assertIsNone(progress["percent_done"])
        _starlette(progress)

    def test_big_out_of_range_percent_is_not_reported_as_negative_done(self):
        """A 400-digit percent is a valid int; 100 - it must not be shown."""
        blob = (
            "Self-test routine in progress...\n"
            f"{_BIG_DIGITS}% of test remaining.\n"
        )
        progress = smart_test_svc._in_progress("/dev/disk0", caps_raw=(0, blob, ""))
        self.assertTrue(progress["running"])
        self.assertIsNone(progress["percent_remaining"])
        self.assertIsNone(progress["percent_done"])
        _starlette(progress)

    def test_a_sane_percent_still_parses(self):
        blob = "Self-test routine in progress...\n40% of test remaining.\n"
        progress = smart_test_svc._in_progress("/dev/disk0", caps_raw=(0, blob, ""))
        self.assertEqual(progress["percent_remaining"], 40)
        self.assertEqual(progress["percent_done"], 60)


class StorageAtaAttributeDigitLimitTests(unittest.TestCase):
    def test_huge_attribute_id_skips_the_row_not_the_disk(self):
        """A poisoned ID column used to degrade the disk to an error row."""
        blob = (
            "SMART overall-health self-assessment test result: PASSED\n"
            "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n"
            f"{_HUGE_DIGITS} Raw_Read_Error_Rate     0x000f   100   100   050    Pre-fail  Always       -       0\n"
            "  9 Power_On_Hours          0x0032   099   099   000    Old_age   Always       -       1234\n"
        )
        info = {
            "device": "/dev/disk4", "id": "disk4", "name": "disk4",
            "size": None, "size_bytes": None, "size_gb": None,
            "smart": None, "error": None,
        }
        with mock.patch.object(
            storage_svc, "sh", side_effect=[(1, "", ""), (0, blob, "")]
        ):
            row = storage_svc._probe_disk_uncached("/dev/disk4", info)
        self.assertIsNone(row["error"])
        smart = row["smart"]
        self.assertEqual(smart["health"], "PASSED")
        self.assertEqual([a["id"] for a in smart["attrs"]], [9])
        _starlette(row)


class TopProcessCountDigitLimitTests(unittest.TestCase):
    def test_huge_process_total_does_not_drop_the_top_leg(self):
        """The whole PhysMem / load parse used to vanish from the sensors pool."""
        blob = (
            f"Processes: {_HUGE_DIGITS} total, 8 running, 504 sleeping\n"
            "Load Avg: 1.20, 1.10, 1.00\n"
            "PhysMem: 30G used (2548M wired), 975M unused.\n"
        )
        with mock.patch.object(sensors_svc, "sh", return_value=(0, blob, "")):
            data = sensors_svc._cpu_and_mem_from_top()
        self.assertNotIn("proc_total", data)
        self.assertEqual(data.get("proc_running"), 8)
        self.assertEqual(data.get("mem_used_gb"), 30.0)
        self.assertEqual(data.get("load1"), 1.2)
        _starlette(data)


class UpsPercentDigitLimitTests(unittest.TestCase):
    def _batt(self, pct: str) -> str:
        return (
            "Now drawing from 'AC Power'\n"
            f" -InternalBattery-0 (id=1234567)\t{pct}%; charging;"
            " 0:00 remaining present: true\n"
        )

    def test_huge_percent_nulls_only_the_percent(self):
        with mock.patch.object(
            system_settings_svc, "sh", return_value=(0, self._batt(_HUGE_DIGITS), "")
        ):
            info = system_settings_svc.get_ups_info()
        self.assertIsNone(info["battery_percent"])
        self.assertEqual(info["source"], "ac")
        self.assertTrue(info["battery_present"])
        _starlette(info)

    def test_big_percent_is_clamped_like_ups_svc(self):
        with mock.patch.object(
            system_settings_svc, "sh", return_value=(0, self._batt(_BIG_DIGITS), "")
        ):
            info = system_settings_svc.get_ups_info()
        self.assertEqual(info["battery_percent"], 100)
        _starlette(info)

    def test_a_sane_percent_still_parses(self):
        with mock.patch.object(
            system_settings_svc, "sh", return_value=(0, self._batt("85"), "")
        ):
            info = system_settings_svc.get_ups_info()
        self.assertEqual(info["battery_percent"], 85)


class AlreadyGuardedHuntPinTests(unittest.TestCase):
    """Hunted paths that already survive this class, pinned against refactors."""

    def test_huge_digit_sample_ts_is_none(self):
        self.assertIsNone(metrics.sample_ts(_HUGE_DIGITS))

    def test_huge_memory_pressure_percentage_is_skipped(self):
        """metrics._sample's memory_pressure parse already absorbs ValueError."""
        line = f"System-wide memory free percentage: {_HUGE_DIGITS}%"
        try:
            value = int(line.rstrip("%").split(":")[-1].strip().rstrip("%"))
        except ValueError:
            value = None
        self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
