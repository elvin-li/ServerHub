"""Leftover >4300-digit numerics in the host/dashboard sensor parsers.

The prior pass fixed this class (CPython refuses str->int past 4300 digits
with ValueError, which ``isdigit()`` does not defend against) in
tools_svc.diagnostics and system_extra._host_snapshot.  Three sibling parsers
kept the bare ``int(text) if text.isdigit()`` form:

- macos_sysctl.parse_int raised through sysctl_int into sensors_svc._static_hw
  and 500'd GET /api/system/sensors?light=1 (collect_light has no pool guard),
  and killed metrics sampler ticks via metrics._ncpu.
- sensors_svc._sysctl_int (fed raw ``machdep.xcpm.cpu_thermal_level`` stdout)
  and the bare ``int()`` on pmset's warning level nulled the whole thermal
  leg of GET /api/system/sensors.
- system._sysctl_int was one refactor away from the same raise.
- alerts._alert_ts caught OverflowError only, so a >4300-digit journal ``t``
  string ValueError'd GET /api/alerts through list_alerts.

The pin battery covers the range grammar that already survives this class:
metrics_rollup.parse_range refuses it whole and GET /api/metrics?range= maps
that to the coded 400 ``metrics.bad_range``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from hub import alerts, macos_sysctl, metrics, metrics_rollup, sensors_svc, system
from hub.routers import settings_api

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class SysctlIntDigitLimitTests(unittest.TestCase):
    def test_parse_int_refuses_huge_digits(self):
        """int() of >4300 digits is ValueError; parse_int must return None."""
        self.assertIsNone(macos_sysctl.parse_int(_HUGE_DIGITS))
        self.assertIsNone(macos_sysctl.parse_int(_HUGE_DIGITS.encode()))
        self.assertEqual(macos_sysctl.parse_int("8"), 8)

    def test_sysctl_int_shell_fallback_refuses_huge_digits(self):
        with patch.object(macos_sysctl, "sysctlbyname_int", return_value=None):
            n = macos_sysctl.sysctl_int(
                "hw.ncpu", sh=lambda *a, **k: (0, _HUGE_DIGITS, "")
            )
        self.assertIsNone(n)

    def test_local_sysctl_int_copies_refuse_huge_digits(self):
        """sensors_svc / system keep local copies of the same helper."""
        self.assertIsNone(sensors_svc._sysctl_int(_HUGE_DIGITS))
        self.assertIsNone(system._sysctl_int(_HUGE_DIGITS))
        self.assertEqual(sensors_svc._sysctl_int("4"), 4)
        self.assertEqual(system._sysctl_int("4"), 4)


class LightSensorsDigitLimitTests(unittest.TestCase):
    def test_huge_sysctl_digits_do_not_500_light_sensors(self):
        """>4300-digit hw.* ValueError'd GET /api/system/sensors?light=1.

        collect_light -> _memory_base -> _static_hw runs on the request
        thread with no pool guard, unlike the full-collect path.
        """
        def fake_sh(argv, **kwargs):
            last = argv[-1] if argv else ""
            if last in ("hw.ncpu", "hw.memsize", "hw.pagesize"):
                return 0, _HUGE_DIGITS, ""
            if argv and argv[0].endswith("memory_pressure"):
                return 0, "System-wide memory free percentage: 42%", ""
            return 1, "", ""

        with (
            patch.object(sensors_svc, "sh", side_effect=fake_sh),
            patch.object(macos_sysctl, "sysctlbyname_int", return_value=None),
            patch.dict(sensors_svc._static, {
                "t": 0.0, "ncpu": None, "mem_gb": None, "page_size": 16384,
            }),
        ):
            data = sensors_svc.collect_light()
        self.assertEqual(data["cpu"]["ncpu"], 1)
        self.assertIsNone(data["memory"]["total_gb"])
        self.assertEqual(data["memory"]["free_pct"], 42)
        _starlette(data)

    def test_huge_thermal_levels_degrade_not_drop(self):
        """Huge sysctl and pmset thermal levels used to null the thermal leg."""
        def fake_sh(argv, **kwargs):
            last = argv[-1] if argv else ""
            if last == "machdep.xcpm.cpu_thermal_level":
                return 0, _HUGE_DIGITS, ""
            if argv and argv[0].endswith("pmset"):
                return 0, f"thermal warning level = {_HUGE_DIGITS}", ""
            return 1, "", ""

        with (
            patch.object(sensors_svc, "sh", side_effect=fake_sh),
            patch.object(sensors_svc.shutil, "which", return_value=None),
        ):
            data = sensors_svc._thermal()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["pressure"], "normal")
        _starlette(data)


class MetricsSamplerDigitLimitTests(unittest.TestCase):
    def test_huge_ncpu_fallback_does_not_kill_sampler(self):
        """A huge hw.ncpu used to ValueError _sample() and lose the tick."""
        with (
            patch.dict(metrics._ncpu_cache, {"t": 0.0, "n": None}),
            patch.object(macos_sysctl, "sysctlbyname_int", return_value=None),
            patch.object(metrics, "sh", side_effect=lambda *a, **k: (0, _HUGE_DIGITS, "")),
        ):
            self.assertEqual(metrics._ncpu(), 1)


class AlertJournalDigitLimitTests(unittest.TestCase):
    def test_huge_digit_alert_ts_does_not_500_alert_list(self):
        """A >4300-digit journal ``t`` string ValueError'd GET /api/alerts."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            path.write_text(
                json.dumps({"t": _HUGE_DIGITS, "kind": "cpu", "msg": "hot"}) + "\n"
                + json.dumps({"t": 1700000000, "kind": "disk", "msg": "full"}) + "\n",
                encoding="utf-8",
            )
            with patch.object(alerts, "ALERTS_FILE", path):
                rows = alerts.list_alerts(10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["t"], 1700000000)
        self.assertIsNone(rows[1]["t"])
        _starlette(rows)

    def test_alert_ts_refuses_huge_and_nonascii_digits(self):
        self.assertIsNone(alerts._alert_ts(_HUGE_DIGITS))
        self.assertIsNone(alerts._alert_ts("-" + _HUGE_DIGITS))
        # Superscript passes isdigit() but is not int()-parseable.
        self.assertIsNone(alerts._alert_ts("\u00b2"))
        self.assertEqual(alerts._alert_ts("1700000000"), 1700000000)


class MetricsRangeDigitLimitPinTests(unittest.TestCase):
    def test_huge_range_digits_are_refused_whole(self):
        """parse_range's documented ValueError covers the digit-cap class."""
        with self.assertRaises(ValueError):
            metrics_rollup.parse_range(f"{_HUGE_DIGITS}h")

    def test_huge_range_is_coded_bad_range(self):
        with self.assertRaises(HTTPException) as ctx:
            settings_api.get_metrics(range_=f"{_HUGE_DIGITS}h")
        self.assertEqual(_code(ctx.exception), "metrics.bad_range")
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
