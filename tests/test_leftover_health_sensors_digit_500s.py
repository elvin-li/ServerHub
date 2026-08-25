"""Leftover >4300-digit ints on the Health page and host-sensor payloads.

Prior passes guarded the digit *parsers* on these paths (``_sysctl_int``,
the pmset thermal level, ``_panel_port``, the ps/netstat column parses) and
dropped inf / bytes / ``\\ud800`` in the encoder-facing sanitizers — but
both sanitizers, hub/health_svc.py and hub/sensors_svc.py ``_jsonable``,
passed ``int`` through untouched.  A >4300-digit leftover (a poisoned
cached snapshot, a junk row from the Immich/Ollama check modules whose
dicts bypass ``_check``, or the sum of per-interface byte counters that
each parse under the cap) then hit CPython's int->str digit limit *inside*
Starlette's ``json.dumps`` — a ValueError 500 on GET /api/health/checks and
GET /api/system/sensors (both plain and ?light=1, whose peek path re-serves
the same cache) after the handler itself had already succeeded.  Fixed the
same way as the jobs/scheduler/backups sanitizers: an int the encoder
cannot render is dropped to None, the same rule as its inf float sibling;
anything ``str()`` can render — a 400-digit int included — still passes.

Already safe, pinned rather than changed:

* ``health_svc._check`` coerces every field through ``_as_text``, whose
  guarded ``str()`` absorbs the huge int to an empty string, so no row
  built by the health collector itself can carry one;
* ``sensors_svc._network_rates`` parses each interface's byte counters with
  a capped ``int()`` (over-cap rows are skipped), and the rate math absorbs
  the OverflowError — only the *sum* of legal counters can go over the cap,
  which the sanitizer now drops.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

from hub import health_svc, sensors_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Over the cap as an int object: each half parses, the sum does not render.
_HUGE_INT = int("9" * 4300) + int("9" * 4300)
#: Under the cap: ``str()`` renders it, so the encoder can too.
_BIG_INT = int("9" * 400)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class HealthJsonableDigitTests(unittest.TestCase):
    def test_over_cap_int_is_dropped_like_inf(self):
        self.assertIsNone(health_svc._jsonable(_HUGE_INT))
        self.assertIsNone(health_svc._jsonable(-_HUGE_INT))

    def test_renderable_ints_still_pass(self):
        self.assertEqual(health_svc._jsonable(8086), 8086)
        self.assertEqual(health_svc._jsonable(_BIG_INT), _BIG_INT)
        self.assertIs(health_svc._jsonable(True), True)

    def test_nested_over_cap_int_is_dropped_everywhere(self):
        cleaned = health_svc._jsonable({
            "summary": {"ok": _HUGE_INT, "total": 3},
            "checks": [{"id": "immich_jobs", "queue_depth": _HUGE_INT}],
        })
        self.assertIsNone(cleaned["summary"]["ok"])
        self.assertEqual(cleaned["summary"]["total"], 3)
        self.assertIsNone(cleaned["checks"][0]["queue_depth"])
        _starlette(cleaned)


class HealthCachedSnapshotDigitTests(unittest.TestCase):
    """GET /api/health/checks serves TTL hits through _serve_cached."""

    def test_poisoned_cache_hit_renders_instead_of_500(self):
        poisoned = {
            "ts": "2026-08-25 03:00:00",
            "summary": {"ok": _HUGE_INT, "warn": 0, "error": 0, "total": 1},
            "checks": [{"id": "immich", "name": "Immich", "ok": True,
                        "level": "ok", "detail": "", "queue_depth": _HUGE_INT}],
            "healthy": True,
        }
        with mock.patch.dict(health_svc._cache, {"t": time.time(), "v": poisoned}):
            out = health_svc.run_checks()
        # Same snapshot object, scrubbed in place: single-flight waiters and
        # later TTL hits must share one clean dict, not diverging copies.
        self.assertIs(out, poisoned)
        self.assertIsNone(out["summary"]["ok"])
        self.assertIsNone(out["checks"][0]["queue_depth"])
        self.assertEqual(out["summary"]["total"], 1)
        _starlette(out)

    def test_check_rows_absorb_huge_int_fields(self):
        """_check's _as_text coercion eats the huge int before it can 500."""
        row = health_svc._check("x", "X", "warn", False, _HUGE_INT, fix=_HUGE_INT)
        self.assertEqual(row["detail"], "")
        self.assertEqual(row["fix"], "")
        _starlette(row)


class SensorsJsonableDigitTests(unittest.TestCase):
    def test_over_cap_int_is_dropped_like_inf(self):
        self.assertIsNone(sensors_svc._jsonable(_HUGE_INT))
        self.assertIsNone(sensors_svc._jsonable(-_HUGE_INT))

    def test_renderable_ints_still_pass(self):
        self.assertEqual(sensors_svc._jsonable(16384), 16384)
        self.assertEqual(sensors_svc._jsonable(_BIG_INT), _BIG_INT)
        self.assertIs(sensors_svc._jsonable(False), False)


class SensorsCacheDigitTests(unittest.TestCase):
    """?light=1 peeks and plain GETs both re-serve _cache through _jsonable."""

    def _poisoned(self) -> dict:
        return {
            "ts": "03:00:00",
            "cpu": {"used_pct": 12.5, "proc_total": _HUGE_INT},
            "network": {"rx_bytes": _HUGE_INT, "tx_bytes": 42},
            "top_processes": [{"pid": 1, "rss_mb": _HUGE_INT, "name": "launchd"}],
        }

    def test_poisoned_peek_cache_renders_instead_of_500(self):
        with mock.patch.dict(sensors_svc._cache, {"t": time.time(), "v": self._poisoned()}):
            out = sensors_svc.peek_sensors()
        self.assertIsInstance(out, dict)
        self.assertIsNone(out["cpu"]["proc_total"])
        self.assertIsNone(out["network"]["rx_bytes"])
        self.assertEqual(out["network"]["tx_bytes"], 42)
        self.assertIsNone(out["top_processes"][0]["rss_mb"])
        _starlette(out)

    def test_poisoned_full_cache_hit_renders_instead_of_500(self):
        with mock.patch.dict(sensors_svc._cache, {"t": time.time(), "v": self._poisoned()}):
            out = sensors_svc.collect_sensors()
        self.assertIsNone(out["network"]["rx_bytes"])
        self.assertEqual(out["cpu"]["used_pct"], 12.5)
        _starlette(out)


class SensorsNetworkSumDigitTests(unittest.TestCase):
    def test_iface_sum_over_the_cap_is_dropped_at_the_sanitizer(self):
        """Each counter parses under the cap; only their sum cannot render.

        netstat's per-interface Ibytes go through a capped ``int()`` (an
        over-cap column is skipped), so the only over-cap int this leg can
        produce is the aggregate — exactly what the sanitizer now drops
        while the per-interface rows keep their renderable values.
        """
        half = "9" * 4300  # parses (at the cap); the two-iface sum does not render
        header = "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll"
        rows = "\n".join([
            header,
            f"en0 1500 <Link#4> aa:bb:cc:dd:ee:01 9 0 {half} 9 0 100 0",
            f"en1 1500 <Link#5> aa:bb:cc:dd:ee:02 9 0 {half} 9 0 100 0",
        ])
        with (
            mock.patch.object(sensors_svc, "sh", return_value=(0, rows, "")),
            # patch.object, not patch.dict: _network_rates rebinds the module
            # global to a fresh dict, which patch.dict would not restore.
            mock.patch.object(sensors_svc, "_net_prev", {"t": 0.0, "rx": 0, "tx": 0}),
        ):
            net = sensors_svc._network_rates()
        self.assertEqual(net["rx_bytes"], int(half) * 2)
        cleaned = sensors_svc._jsonable(net)
        self.assertIsNone(cleaned["rx_bytes"])
        self.assertEqual(cleaned["tx_bytes"], 200)
        self.assertEqual(cleaned["ifaces"][0]["rx_bytes"], int(half))
        _starlette(cleaned)


if __name__ == "__main__":
    unittest.main()
