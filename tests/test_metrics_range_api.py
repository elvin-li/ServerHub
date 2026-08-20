"""/api/metrics with the tiered history: compatibility first, then ranges.

The endpoint predates the rollup layers and has at least one external
consumer (the menubar) that calls it bare or with ?minutes=.  The contract
pinned here: without new parameters the response is byte-for-byte the old
shape -- raw points, {"points", "latest"}, nothing else.  With ?range= or
?since=/until= the backend picks the storage tier for the span, annotates the
response, and never returns more than the point cap.

Runs the router over a bare ASGI scope (no create_app: this file needs the
settings router only) against temp-dir metric files.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI  # noqa: E402

from hub import metrics, metrics_rollup as rollup  # noqa: E402
from hub.routers.settings_api import router as settings_router  # noqa: E402


async def _asgi_get(path, query=None):
    app = FastAPI()
    app.include_router(settings_router)
    messages: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": path, "raw_path": path.encode(),
        "query_string": urlencode(query or {}).encode(), "root_path": "",
        "headers": [], "server": ("localhost", 8086),
        "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(raw or b"{}")


def get(path, query=None):
    return asyncio.run(_asgi_get(path, query))


class MetricsApiBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.raw = root / "metrics.jsonl"
        self.f5 = root / "metrics-5m.jsonl"
        self.f1 = root / "metrics-1h.jsonl"
        for target, name, value in (
            (metrics, "METRICS_FILE", self.raw),
            (metrics, "_write_buf", []),
            (metrics, "_last_flush", time.time()),
            (rollup, "FILE_5M", self.f5),
            (rollup, "FILE_1H", self.f1),
            (rollup, "STATE_FILE", root / "state.json"),
            (rollup, "_state", {"w5": 0, "w1h": 0}),
            (rollup, "_state_loaded", False),
        ):
            patched = mock.patch.object(target, name, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.now = int(time.time())

    def seed(self, path, rows):
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))


class LegacyContract(MetricsApiBase):
    def test_bare_call_keeps_the_exact_old_shape(self):
        rows = [
            {"t": self.now - 120, "cpu_used_pct": 10.0},
            {"t": self.now - 30, "cpu_used_pct": 20.0},
        ]
        self.seed(self.raw, rows)
        status, body = get("/api/metrics")
        self.assertEqual(status, 200)
        # Exactly the pre-rollup keys: external pollers parse this shape.
        self.assertEqual(set(body), {"points", "latest"})
        self.assertEqual(body["points"], rows)  # raw rows, unmodified
        self.assertEqual(body["latest"], rows[-1])

    def test_leftover_inf_fields_do_not_500(self):
        """Starlette encodes with allow_nan=False; Infinity used to 500 GET /api/metrics."""
        self.seed(self.raw, [
            {"t": self.now - 30, "cpu_used_pct": float("inf"), "mem_used_pct": float("nan")},
        ])
        status, body = get("/api/metrics")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["points"]), 1)
        self.assertIsNone(body["points"][0]["cpu_used_pct"])
        self.assertIsNone(body["points"][0]["mem_used_pct"])
        json.dumps(body, allow_nan=False)

    def test_leftover_surrogate_field_does_not_500(self):
        """JSON ``\\ud800`` used to UnicodeEncodeError GET /api/metrics."""
        self.seed(self.raw, [
            {"t": self.now - 30, "cpu_used_pct": 1.0, "note": "ok\ud800", "\ud800": 2},
        ])
        status, body = get("/api/metrics")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["points"]), 1)
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", body["points"][0].get("note", ""))
        self.assertNotIn("\ud800", body["points"][0])

    def test_minutes_still_filters(self):
        self.seed(self.raw, [
            {"t": self.now - 7200, "cpu_used_pct": 1.0},
            {"t": self.now - 60, "cpu_used_pct": 2.0},
        ])
        status, body = get("/api/metrics", {"minutes": 30})
        self.assertEqual(status, 200)
        self.assertEqual([p["t"] for p in body["points"]], [self.now - 60])


class RangeSelectsTiers(MetricsApiBase):
    def setUp(self):
        super().setUp()
        # Raw reaches back 72h; 5m rows n=5 reach ~31d; 1h rows n=40 reach
        # ~300d.  Distinct n values identify which file served the response.
        self.seed(self.raw, [
            {"t": self.now - 72 * 3600, "cpu_used_pct": 1.0},
            {"t": self.now - 60, "cpu_used_pct": 2.0},
        ])
        self.seed(self.f5, [
            {"t": self.now - 31 * 86400, "n": 5, "cpu_used_pct": 3.0, "cpu_used_pct_max": 4.0},
            {"t": self.now - 600, "n": 5, "cpu_used_pct": 5.0, "cpu_used_pct_max": 6.0},
        ])
        self.seed(self.f1, [
            {"t": self.now - 300 * 86400, "n": 40, "cpu_used_pct": 7.0, "cpu_used_pct_max": 8.0},
            {"t": self.now - 3600, "n": 40, "cpu_used_pct": 9.0, "cpu_used_pct_max": 10.0},
        ])

    def test_48h_comes_from_raw(self):
        status, body = get("/api/metrics", {"range": "48h"})
        self.assertEqual(status, 200)
        self.assertEqual(body["tier"], "raw")
        self.assertEqual(body["until"] - body["since"], 48 * 3600)
        self.assertTrue(all("n" not in p for p in body["points"]))

    def test_30d_comes_from_the_5m_layer(self):
        status, body = get("/api/metrics", {"range": "30d"})
        self.assertEqual(status, 200)
        self.assertEqual(body["tier"], "5m")
        self.assertTrue(all(p["n"] == 5 for p in body["points"]))
        # Aggregate rows keep the raw field names (avg) plus _max peaks, so
        # chart code written for raw rows reads them unchanged.
        self.assertIn("cpu_used_pct", body["points"][0])
        self.assertIn("cpu_used_pct_max", body["points"][0])

    def test_1y_comes_from_the_1h_layer(self):
        status, body = get("/api/metrics", {"range": "1y"})
        self.assertEqual(status, 200)
        self.assertEqual(body["tier"], "1h")
        self.assertTrue(all(p["n"] == 40 for p in body["points"]))

    def test_short_range_falls_through_when_raw_cannot_reach(self):
        # Raw history starts an hour ago (fresh file after an interval
        # change); the 5m layer reaches further back, so a 48h ask is served
        # from it instead of silently truncating to one hour.
        self.seed(self.raw, [{"t": self.now - 3600, "cpu_used_pct": 1.0}])
        status, body = get("/api/metrics", {"range": "48h"})
        self.assertEqual(status, 200)
        self.assertEqual(body["tier"], "5m")

    def test_explicit_since_until_window(self):
        # Raw holds 72h here, so it fully covers [now-3d, now-1d] and wins on
        # resolution despite the window being historical.
        status, body = get("/api/metrics", {
            "since": self.now - 3 * 86400, "until": self.now - 86400,
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["tier"], "raw")
        self.assertEqual(body["since"], self.now - 3 * 86400)
        self.assertEqual(body["until"], self.now - 86400)
        for p in body["points"]:
            self.assertGreaterEqual(p["t"], body["since"])
            self.assertLessEqual(p["t"], body["until"])

    def test_historical_window_beyond_raw_uses_an_aggregate_tier(self):
        # Same 2-day span but ten days back: raw cannot reach it, the 5m
        # layer can, so the short span alone must not force raw.
        status, body = get("/api/metrics", {
            "since": self.now - 10 * 86400, "until": self.now - 8 * 86400,
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["tier"], "5m")


class Validation(MetricsApiBase):
    def test_garbage_range_is_a_400(self):
        for bad in ("bananas", "0h", "12", "-1d"):
            status, _ = get("/api/metrics", {"range": bad})
            self.assertEqual(status, 400, bad)

    def test_inverted_window_is_a_400(self):
        status, _ = get("/api/metrics", {"since": self.now, "until": self.now - 60})
        self.assertEqual(status, 400)


class Decimation(MetricsApiBase):
    def test_cap_peaks_and_holes(self):
        # 48h of 90s samples (~1900 rows) with a 6h hole and one CPU spike.
        rows = []
        spike_t = self.now - 30 * 3600
        hole_lo, hole_hi = self.now - 20 * 3600, self.now - 14 * 3600
        t = self.now - 48 * 3600
        while t <= self.now:
            if not (hole_lo <= t < hole_hi):
                rows.append({
                    "t": t,
                    "cpu_used_pct": 99.0 if t == spike_t else 10.0,
                })
            t += 90
        self.seed(self.raw, rows)

        status, body = get("/api/metrics", {"range": "48h", "points": 200})
        self.assertEqual(status, 200)
        self.assertLessEqual(len(body["points"]), 200)
        self.assertGreater(len(body["points"]), 50)

        # The spike survives decimation through the _max channel even though
        # its bucket's average is diluted.
        peak = max(p.get("cpu_used_pct_max", 0) for p in body["points"])
        self.assertEqual(peak, 99.0)

        # Buckets are keyed by time, so the sleep hole stays visible: no
        # output point claims a timestamp inside it (one bucket of slop at
        # each edge, since buckets straddle the boundaries).
        bucket = (48 * 3600) // 200 + 1
        for p in body["points"]:
            self.assertFalse(
                hole_lo + bucket < p["t"] < hole_hi - bucket,
                f"point {p['t']} sits inside the sampling hole",
            )

    def test_point_cap_is_clamped_to_the_server_maximum(self):
        rows = [
            {"t": self.now - i * 90, "cpu_used_pct": 1.0}
            for i in range(1900)
        ]
        self.seed(self.raw, rows)
        status, body = get("/api/metrics", {"range": "48h", "points": 999999})
        self.assertEqual(status, 200)
        self.assertLessEqual(len(body["points"]), rollup.MAX_QUERY_POINTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
