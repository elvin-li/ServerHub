"""Metrics / host-stats leftover-500 sweep: every content vector probed came
back immune, so these pins hold the line at the HTTP layer — through the real
app (``create_app``), not a bare router.

What this file adds over ``test_metrics_range_api`` (bare-ASGI contract),
``test_leftover_alert_metrics_notify_500s`` (service-level sanitizers) and
``test_leftover_host_sensor_digit_500s`` (parser digit caps):

* **One journal carrying every leftover class at once**, served by the
  mounted GET /api/metrics: surrogate keys AND values, a >4300-digit number
  (``json.loads`` raises CPython's digit-cap *ValueError*, not
  JSONDecodeError — the trap that must never wipe the readable rows around
  it), ``Infinity``/``NaN`` literals, an over-cap ``t``, a deep nest, and a
  torn binary line.  The good rows survive; the poison drops row-by-row.
* **The rollup tier files and state file poisoned the same way** under
  GET /api/metrics?range= — the head/tail tier probes parse past the poison
  instead of 500ing or falling to the wrong tier.
* **Query-param abuse through the app wiring**: >4300-digit ``since`` /
  ``minutes`` / ``points`` (pydantic parses or refuses, never 500s;
  ``_epoch``'s str() probe drops the over-cap int), an over-cap ``range``
  (coded 400), and a lone-surrogate ``range`` that must not echo.
* **Planted poisoned caches served by GET /api/health and
  GET /api/system/sensors?light=1** — the re-sanitizing promise of
  ``cached_status()`` / ``peek_sensors()`` pinned at the routes that serve
  them, with over-cap ints (the YAML/plist hex bypass arrives already-int),
  surrogates, bytes and inf in one snapshot.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import metrics, metrics_rollup, sensors_svc, status  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000
_INF = float("inf")


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class AppClientBase(unittest.TestCase):
    """The real app: sanitizing 422 handler, mounted routers, auth overridden."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def get(self, path: str, **params):
        r = self.client.get(path, params=params or None)
        # Every answer in this battery must be encodable and surrogate-free.
        _starlette(r.json())
        self.assertNotIn("\ud800", r.text)
        return r


class PoisonedJournalPins(AppClientBase):
    """GET /api/metrics (legacy and range forms) over fully poisoned files."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics3-pins-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.now = int(time.time())
        raw = [
            # Reaches back past 48h so the raw tier demonstrably covers the
            # range query below despite the poison around it.
            json.dumps({"t": self.now - 49 * 3600, "cpu_used_pct": 0.5}),
            json.dumps({
                "t": self.now - 30, "cpu_used_pct": 1.0,
                "note": "ok\ud800", "\ud800": 2,
            }),
            '{"t": %d, "n": %s}' % (self.now - 40, _HUGE_DIGITS),
            '{"t": %s, "cpu_used_pct": 2.0}' % _HUGE_DIGITS,
            '{"t": %d, "cpu_used_pct": Infinity, "mem_used_pct": NaN}'
            % (self.now - 50),
            '{"k":' * 3000 + "1" + "}" * 3000,
            "torn binary \xff\xfe line",
            json.dumps({"t": self.now - 20, "cpu_used_pct": 3.0}),
        ]
        (root / "metrics.jsonl").write_text("\n".join(raw) + "\n")
        five = [
            '{"t": %d, "n": %s}' % (self.now - 3600, _HUGE_DIGITS),
            json.dumps({
                "t": self.now - 40 * 86400, "n": 5,
                "cpu_used_pct": 3.0, "cpu_used_pct_max": 4.0, "x\ud800": 1,
            }),
            '{"t": %d, "n": 5, "cpu_used_pct": Infinity}' % (self.now - 500),
            json.dumps({"t": self.now - 600, "n": 5, "cpu_used_pct": 5.0}),
        ]
        (root / "metrics-5m.jsonl").write_text("\n".join(five) + "\n")
        one = [
            '{"t": %d, "n": %s}' % (self.now - 7200, _HUGE_DIGITS),
            json.dumps({"t": self.now - 300 * 86400, "n": 40, "cpu_used_pct": 7.0}),
            json.dumps({"t": self.now - 3600, "n": 40, "cpu_used_pct": 9.0}),
        ]
        (root / "metrics-1h.jsonl").write_text("\n".join(one) + "\n")
        (root / "state.json").write_text(
            '{"w5": ' + _HUGE_DIGITS + ', "w1h": Infinity}'
        )
        for target, attr, value in (
            (metrics, "METRICS_FILE", root / "metrics.jsonl"),
            (metrics, "_write_buf", []),
            (metrics_rollup, "FILE_5M", root / "metrics-5m.jsonl"),
            (metrics_rollup, "FILE_1H", root / "metrics-1h.jsonl"),
            (metrics_rollup, "STATE_FILE", root / "state.json"),
            (metrics_rollup, "_state", {"w5": 0, "w1h": 0}),
            (metrics_rollup, "_state_loaded", False),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)

    def test_legacy_get_keeps_the_good_rows(self):
        r = self.get("/api/metrics")
        self.assertEqual(r.status_code, 200, r.text)
        pts = r.json()["points"]
        self.assertEqual(
            sorted(p["t"] for p in pts),
            [self.now - 50, self.now - 30, self.now - 20],
        )
        by_t = {p["t"]: p for p in pts}
        # Infinity/NaN dropped to null on the row that carried them.
        self.assertIsNone(by_t[self.now - 50]["cpu_used_pct"])
        self.assertEqual(by_t[self.now - 20]["cpu_used_pct"], 3.0)

    def test_range_raw_tier_survives_the_same_journal(self):
        r = self.get("/api/metrics", range="48h")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tier"], "raw")
        self.assertTrue(r.json()["points"])

    def test_range_5m_tier_parses_past_the_poisoned_head(self):
        r = self.get("/api/metrics", range="30d")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tier"], "5m")
        self.assertTrue(all(p.get("n") == 5 for p in r.json()["points"]))

    def test_range_1h_tier_parses_past_the_poisoned_head(self):
        r = self.get("/api/metrics", range="1y")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tier"], "1h")

    def test_over_cap_since_is_a_4xx_not_500(self):
        # pydantic-core refuses the >4300-digit query int (int_parsing_size)
        # through the sanitizing 422 handler create_app registers; the pin is
        # that this stays a client error, never a 500.
        r = self.get("/api/metrics", since=_HUGE_DIGITS)
        self.assertEqual(r.status_code, 422, r.text)

    def test_merely_huge_since_is_the_coded_400(self):
        # 100 digits parse fine as int (below the cap); the window then ends
        # before it starts and must be the coded refusal, not an overflow 500.
        r = self.get("/api/metrics", since="9" * 100)
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "metrics.bad_window")

    def test_merely_huge_window_answers_empty_not_500(self):
        # A far-future explicit window: float()/int() of a 100-digit epoch
        # survives the tier probes and answers no points.
        huge = int("9" * 100)
        r = self.get("/api/metrics", since=huge, until=huge + 100)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["points"], [])

    def test_over_cap_minutes_and_points_never_500(self):
        for params in ({"minutes": _HUGE_DIGITS},
                       {"range": "48h", "points": _HUGE_DIGITS}):
            with self.subTest(params=params):
                r = self.get("/api/metrics", **params)
                self.assertLess(r.status_code, 500, r.text)

    def test_over_cap_range_is_the_coded_400(self):
        r = self.get("/api/metrics", range=_HUGE_DIGITS + "h")
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "metrics.bad_range")

    def test_surrogate_range_is_a_4xx_that_does_not_echo(self):
        r = self.client.get("/api/metrics?range=%ED%A0%80h")
        self.assertGreaterEqual(r.status_code, 400)
        self.assertLess(r.status_code, 500)
        _starlette(r.json())
        self.assertNotIn("\ud800", r.text)

    def test_inverted_window_is_the_coded_400(self):
        r = self.get("/api/metrics", since=self.now, until=self.now - 60)
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "metrics.bad_window")


class PlantedStatusCachePins(AppClientBase):
    """The health/status routes re-sanitize the planted status cache."""

    POISON = {
        "counts": {"ok": _HUGE_INT, "\ud800warn": 2, "down": _INF},
        "engine_up": _INF,
        "groups": [],
    }

    def test_public_health_stays_ok_ts_over_a_poisoned_cache(self):
        # create_app's unauthenticated watchdog probe never touches the
        # snapshot; it must stay {ok, ts} whatever was planted.
        with mock.patch.dict(
            status._status_cache, {"t": time.time(), "v": dict(self.POISON)},
        ):
            r = self.get("/api/health")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("counts", r.json())

    def test_authenticated_health_serves_sanitized_counts(self):
        # The router /api/health (menubar) attaches cached counts; mount it
        # bare so the public app-factory probe does not shadow it.
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hub.routers.api import router

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app, raise_server_exceptions=False)
        with mock.patch.dict(
            status._status_cache, {"t": time.time(), "v": dict(self.POISON)},
        ):
            r = client.get("/api/health")
        self.assertEqual(r.status_code, 200, r.text)
        _starlette(r.json())
        self.assertNotIn("\ud800", r.text)
        counts = r.json()["counts"]
        self.assertIsNone(counts["ok"])       # over-cap int dropped
        self.assertIsNone(counts["down"])     # inf dropped
        self.assertIsNone(r.json()["engine_up"])

    def test_status_cache_hit_serves_sanitized_snapshot(self):
        with mock.patch.dict(
            status._status_cache, {"t": time.time(), "v": dict(self.POISON)},
        ):
            r = self.get("/api/status")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["counts"]["ok"])


class PlantedSensorsCachePins(AppClientBase):
    """GET /api/system/sensors re-sanitizes the planted peek cache."""

    POISON = {
        "ts": "12:00:00",
        "cpu": {"used_pct": _INF, "ncpu": _HUGE_INT, "name\ud800": 1},
        "memory": {"total_gb": b"\xff", "used_pct": 40.0},
        "network": {"rx_bps": _HUGE_INT},
        "top_processes": [{"name": "proc\ud800", "cpu": _INF}],
        "cpu_used_pct": _INF,
        "light": True,
    }

    def test_light_poll_serves_sanitized_peek(self):
        with (
            mock.patch.dict(
                sensors_svc._cache, {"t": time.time(), "v": self.POISON},
            ),
            mock.patch("hub.resource_mode.is_high", return_value=False),
        ):
            r = self.get("/api/system/sensors", light=1)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIsNone(body["cpu"]["used_pct"])
        self.assertIsNone(body["cpu"]["ncpu"])
        self.assertIsNone(body["network"]["rx_bps"])
        self.assertEqual(body["memory"]["used_pct"], 40.0)

    def test_full_poll_serves_sanitized_cache(self):
        with mock.patch.dict(
            sensors_svc._cache, {"t": time.time(), "v": dict(self.POISON)},
        ):
            r = self.get("/api/system/sensors")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["cpu_used_pct"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
