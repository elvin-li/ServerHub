"""Metrics sweep #4: leftover non-dict *shapes* in the sensors snapshot.

The prior sweeps poisoned journal content and cache *values* (inf, over-cap
ints, surrogates, bytes).  What was still live is poisoned cache *shape*:

* ``sensors_svc.peek_sensors()`` re-sanitized the planted cache with
  ``_jsonable`` but — unlike its sibling ``collect_sensors()`` cache hit —
  returned the result without an isinstance guard.  A leftover non-dict
  planted in the cache (a list, a bare string) escaped verbatim:
  GET /api/system/sensors?light=1 answered a JSON *array* instead of the
  object the dashboard poll consumes.
* ``metrics._sample()`` called ``.get()`` on ``snapshot.get("network")`` /
  ``snapshot.get("memory")`` behind an ``or {}`` truthiness fallback, so a
  leftover truthy non-dict field ("down", a list) raised AttributeError.
  ``metrics._loop`` swallows the exception, but the tick's jsonl row was
  silently lost AND ``maybe_rollup()`` was skipped with it — the raw journal
  and both rollup tiers stopped advancing for as long as the cache stayed
  poisoned.  ``_cpu_used_quick`` had the same unguarded ``.get`` behind a
  numeric-only except.

These pins run the fixed paths over the real mounted app (``create_app``)
and directly over the sampler entry points.
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

from hub import metrics, sensors_svc  # noqa: E402


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: Snapshot dicts whose *fields* carry leftover non-dict shapes.
HOSTILE_FIELD_SNAPSHOTS = [
    {"memory": [1, 2], "network": "down", "gpu": [1], "cpu_used_pct": "wat"},
    {"memory": "low", "network": ["eth0"], "gpu": "none", "load1": {}},
    {"memory": True, "network": 3.5, "gpu": b"\xff", "cpu_used_pct": None},
]
#: Cache values that are not dicts at all.
HOSTILE_WHOLE_SNAPSHOTS = [["not", "a", "dict"], "down", 42, [{"cpu": 1}]]


class PeekSensorsShapeGuard(unittest.TestCase):
    """peek_sensors never returns a non-dict, matching collect_sensors."""

    def test_planted_non_dict_cache_answers_none(self):
        for planted in HOSTILE_WHOLE_SNAPSHOTS:
            with self.subTest(planted=planted):
                with mock.patch.dict(
                    sensors_svc._cache, {"t": time.time(), "v": planted},
                ):
                    self.assertIsNone(sensors_svc.peek_sensors())

    def test_planted_dict_cache_still_serves(self):
        with mock.patch.dict(
            sensors_svc._cache, {"t": time.time(), "v": {"cpu_used_pct": 7.0}},
        ):
            hit = sensors_svc.peek_sensors()
        self.assertIsInstance(hit, dict)
        self.assertEqual(hit["cpu_used_pct"], 7.0)


class SamplerSurvivesHostileShapes(unittest.TestCase):
    """One sampler tick over a poisoned snapshot still lands a jsonl row."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics4-shapes-")
        self.addCleanup(tmp.cleanup)
        self.journal = Path(tmp.name) / "metrics.jsonl"
        for target, attr, value in (
            (metrics, "METRICS_FILE", self.journal),
            (metrics, "_write_buf", []),
            (metrics, "_last_sample", None),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _tick(self):
        sample = metrics.record_sample(immediate=True)
        self.assertIsInstance(sample, dict)
        lines = [ln for ln in self.journal.read_text().splitlines() if ln.strip()]
        self.assertTrue(lines, "tick lost its jsonl row")
        row = json.loads(lines[-1])
        _starlette(row)
        return row

    def test_hostile_field_shapes_do_not_kill_the_tick(self):
        for snap in HOSTILE_FIELD_SNAPSHOTS:
            with self.subTest(snap=snap):
                self.journal.unlink(missing_ok=True)
                with mock.patch.object(
                    sensors_svc, "peek_sensors", return_value=dict(snap),
                ):
                    row = self._tick()
                self.assertIn("t", row)

    def test_whole_snapshot_non_dict_does_not_kill_the_tick(self):
        # Belt and braces below the peek_sensors guard: even if a hostile
        # collector hands _sensors_snapshot a non-dict, the tick survives.
        for snap in HOSTILE_WHOLE_SNAPSHOTS:
            with self.subTest(snap=snap):
                self.journal.unlink(missing_ok=True)
                with mock.patch.object(
                    sensors_svc, "peek_sensors", return_value=snap,
                ):
                    row = self._tick()
                self.assertIn("t", row)

    def test_cpu_used_quick_tolerates_non_dict_snapshot(self):
        for snap in HOSTILE_WHOLE_SNAPSHOTS:
            with self.subTest(snap=snap):
                got = metrics._cpu_used_quick(snap)
                self.assertTrue(got is None or isinstance(got, float))


class MountedRoutesOverPoisonedShapeCache(unittest.TestCase):
    """The real app: light sensors poll and /api/metrics after a hostile tick."""

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

    def test_light_sensors_poll_answers_an_object_not_the_planted_array(self):
        for planted in HOSTILE_WHOLE_SNAPSHOTS:
            with self.subTest(planted=planted):
                with (
                    mock.patch.dict(
                        sensors_svc._cache, {"t": time.time(), "v": planted},
                    ),
                    mock.patch("hub.resource_mode.is_high", return_value=False),
                ):
                    r = self.client.get("/api/system/sensors", params={"light": 1})
                self.assertEqual(r.status_code, 200, r.text)
                body = r.json()
                _starlette(body)
                # The dashboard poll consumes an object; the planted array
                # used to be served verbatim.
                self.assertIsInstance(body, dict)

    def test_metrics_route_serves_the_row_a_hostile_tick_produced(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics4-http-")
        self.addCleanup(tmp.cleanup)
        journal = Path(tmp.name) / "metrics.jsonl"
        with (
            mock.patch.object(metrics, "METRICS_FILE", journal),
            mock.patch.object(metrics, "_write_buf", []),
            mock.patch.object(
                sensors_svc, "peek_sensors",
                return_value=dict(HOSTILE_FIELD_SNAPSHOTS[0]),
            ),
        ):
            metrics.record_sample(immediate=True)
            r = self.client.get("/api/metrics")
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            _starlette(body)
            # The tick over the hostile snapshot must not have been wiped:
            # its row is on disk and served.
            self.assertTrue(body["points"], body)
            self.assertIsNotNone(body["latest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
