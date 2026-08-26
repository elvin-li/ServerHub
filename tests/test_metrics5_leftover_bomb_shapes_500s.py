"""Metrics sweep #5: leftover method-bomb *subclasses* in sensor snapshots.

The metrics4 sweep pinned poisoned cache *shapes* (non-dicts, non-dict
fields).  What was still live one level below — usage5's row-bomb class,
"passes the isinstance gate, refuses the protocol" — is a dict/list
*subclass* whose method raises:

* ``sensors_svc._jsonable`` iterated ``value.items()`` directly, so a
  leftover dict-subclass planted in the sensors cache whose ``items()``
  raised blew up ``peek_sensors`` / ``collect_sensors`` and 500'd
  GET /api/system/sensors (light and full).  A list subclass whose
  ``__iter__`` raised, and an object whose ``isoformat`` attribute *access*
  raised (property bomb; ``__getattr__`` raising non-AttributeError escapes
  ``getattr``'s default), 500'd the same encoder path.
* ``collect_sensors`` gated its cache hit on ``_cache["v"]`` *truthiness*,
  so a subclass whose ``__bool__`` raised 500'd the full poll before the
  sanitizer ever ran (``peek_sensors`` was already immune: ``is not None``).
* ``_cpu_and_mem_from_top_cached`` returned its cache hit verbatim, so a
  bombed (or non-dict) leftover in the top cache reached
  ``_collect_sensors_uncached``'s ``or {}`` / ``.get()`` and 500'd
  GET /api/system/sensors?force=1.
* ``metrics._sensors_snapshot`` passed a dict-subclass through its
  isinstance gate, so a ``.get()`` / ``__bool__`` bomb raised inside
  ``_sample()`` — ``metrics._loop`` swallows it, but the tick's jsonl row
  was silently lost and ``maybe_rollup()`` skipped with it.
  ``record_sample(sample=...)`` had the same ``sample or`` truthiness bomb.

The fix plain-dicts subclasses through ``dict()`` (C-level copy: overridden
methods cannot fire) and guards the sequence/isoformat legs.  These pins run
the fixed paths over the real mounted app and the sampler entry points.
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

from hub import metrics, metrics_rollup, sensors_svc  # noqa: E402


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ItemsBombDict(dict):
    def items(self):
        raise ValueError("items bomb")


class GetBombDict(dict):
    def get(self, *a, **kw):
        raise ValueError("get bomb")


class BoolBombDict(dict):
    def __bool__(self):
        raise ValueError("bool bomb")


class KeysBombDict(dict):
    def keys(self):
        raise ValueError("keys bomb")


class IterBombList(list):
    def __iter__(self):
        raise ValueError("iter bomb")


class GetattrBomb:
    """__getattr__ raising non-AttributeError escapes getattr's default."""

    def __getattr__(self, name):
        raise RuntimeError("getattr bomb")


class IsoformatPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")


def _bomb_snapshots() -> dict:
    return {
        "items-bomb-dict": ItemsBombDict({"cpu_used_pct": 5.0}),
        "get-bomb-dict": GetBombDict({"cpu_used_pct": 5.0}),
        "bool-bomb-dict": BoolBombDict({"cpu_used_pct": 5.0}),
        "keys-bomb-dict": KeysBombDict({"cpu_used_pct": 5.0}),
        "items-bomb-nested": {"cpu_used_pct": 5.0, "memory": ItemsBombDict({"a": 1})},
        "getattr-bomb-value": {"cpu_used_pct": 5.0, "gpu": GetattrBomb()},
        "isoformat-bomb-value": {"cpu_used_pct": 5.0, "gpu": IsoformatPropertyBomb()},
        "iter-bomb-list-value": {"cpu_used_pct": 5.0, "top_processes": IterBombList([1])},
    }


class JsonableNeutralizesMethodBombs(unittest.TestCase):
    """All three sanitizer clones survive the bombs and stay encodable."""

    def test_sanitizers_survive_and_starlette_encodes_the_result(self):
        for mod in (metrics, metrics_rollup, sensors_svc):
            for name, planted in _bomb_snapshots().items():
                with self.subTest(module=mod.__name__, planted=name):
                    cleaned = mod._jsonable(planted)
                    _starlette(cleaned)

    def test_subclass_payload_survives_the_copy(self):
        # The bomb rides a subclass *method*; the data inside is fine and
        # must not be thrown away with it.
        for mod in (metrics, metrics_rollup, sensors_svc):
            cleaned = mod._jsonable(ItemsBombDict({"cpu_used_pct": 5.0}))
            self.assertEqual(cleaned, {"cpu_used_pct": 5.0})
            self.assertIs(type(cleaned), dict)


class SensorsCacheBombsStayCoded(unittest.TestCase):
    """GET /api/system/sensors answers 200 over every planted bomb."""

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

    def test_light_poll_over_planted_bombs(self):
        for name, planted in _bomb_snapshots().items():
            with self.subTest(planted=name):
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
                self.assertIsInstance(body, dict)

    def test_full_poll_over_planted_bombs(self):
        # bool-bomb-dict was the found full-poll case: the truthiness gate
        # fired before the sanitizer.
        for name, planted in _bomb_snapshots().items():
            with self.subTest(planted=name):
                with mock.patch.dict(
                    sensors_svc._cache, {"t": time.time(), "v": planted},
                ):
                    r = self.client.get("/api/system/sensors")
                self.assertEqual(r.status_code, 200, r.text)
                _starlette(r.json())

    def test_force_poll_over_planted_top_cache_bombs(self):
        hostile = [
            ("get-bomb", GetBombDict({"load1": 1.0})),
            ("bool-bomb", BoolBombDict({"load1": 1.0})),
            ("items-bomb", ItemsBombDict({"load1": 1.0})),
            ("non-dict", "down"),
            ("list", ["x"]),
        ]
        for name, planted in hostile:
            with self.subTest(planted=name):
                with (
                    mock.patch.dict(sensors_svc._cache, {"t": 0.0, "v": None}),
                    mock.patch.dict(
                        sensors_svc._top_cache, {"t": time.time(), "v": planted},
                    ),
                ):
                    r = self.client.get("/api/system/sensors", params={"force": 1})
                self.assertEqual(r.status_code, 200, r.text)
                _starlette(r.json())

    def test_top_cache_subclass_hit_serves_the_payload_as_a_plain_dict(self):
        with mock.patch.dict(
            sensors_svc._top_cache,
            {"t": time.time(), "v": GetBombDict({"load1": 1.5})},
        ):
            got = sensors_svc._cpu_and_mem_from_top_cached()
        self.assertIs(type(got), dict)
        self.assertEqual(got.get("load1"), 1.5)

    def test_peek_still_serves_a_clean_hit(self):
        with mock.patch.dict(
            sensors_svc._cache, {"t": time.time(), "v": {"cpu_used_pct": 7.0}},
        ):
            hit = sensors_svc.peek_sensors()
        self.assertIsInstance(hit, dict)
        self.assertEqual(hit["cpu_used_pct"], 7.0)


class SamplerTickSurvivesMethodBombs(unittest.TestCase):
    """A bombed snapshot must not lose the tick's jsonl row."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics5-bombs-")
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

    def test_bombed_peek_snapshot_does_not_kill_the_tick(self):
        # get-bomb-dict and bool-bomb-dict were the found tick killers: they
        # passed metrics4's isinstance gate, then raised in _sample().
        for name, planted in _bomb_snapshots().items():
            with self.subTest(planted=name):
                self.journal.unlink(missing_ok=True)
                with mock.patch.object(
                    sensors_svc, "peek_sensors", return_value=planted,
                ):
                    row = self._tick()
                self.assertIn("t", row)

    def test_subclass_snapshot_payload_still_feeds_the_sample(self):
        with mock.patch.object(
            sensors_svc, "peek_sensors",
            return_value=ItemsBombDict({"cpu_used_pct": 5.0}),
        ):
            row = self._tick()
        self.assertEqual(row.get("cpu_used_pct"), 5.0)

    def test_record_sample_with_a_bombed_caller_sample(self):
        for name, planted in (
            ("bool-bomb", BoolBombDict({"t": 123})),
            ("get-bomb", GetBombDict({"t": 123})),
            ("items-bomb", ItemsBombDict({"t": 123})),
        ):
            with self.subTest(planted=name):
                self.journal.unlink(missing_ok=True)
                s = metrics.record_sample(planted, immediate=True)
                self.assertIsInstance(s, dict)
                _starlette(s)
                lines = [
                    ln for ln in self.journal.read_text().splitlines() if ln.strip()
                ]
                self.assertTrue(lines, "caller sample lost its jsonl row")

    def test_cpu_used_quick_tolerates_bombed_snapshots(self):
        for name, planted in _bomb_snapshots().items():
            with self.subTest(planted=name):
                got = metrics._cpu_used_quick(planted)
                self.assertTrue(got is None or isinstance(got, float))

    def test_plain_dict_helper_contract(self):
        self.assertIsNone(metrics._plain_dict(None))
        self.assertIsNone(metrics._plain_dict(["x"]))
        self.assertIsNone(metrics._plain_dict("down"))
        same = {"a": 1}
        self.assertIs(metrics._plain_dict(same), same)
        copied = metrics._plain_dict(GetBombDict({"a": 1}))
        self.assertIs(type(copied), dict)
        self.assertEqual(copied, {"a": 1})


class MetricsRouteAfterBombedTick(unittest.TestCase):
    """The real app serves the row a bombed tick produced."""

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

    def test_metrics_route_serves_rows_ticked_over_bombed_snapshots(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics5-http-")
        self.addCleanup(tmp.cleanup)
        journal = Path(tmp.name) / "metrics.jsonl"
        for name, planted in _bomb_snapshots().items():
            with self.subTest(planted=name):
                journal.unlink(missing_ok=True)
                with (
                    mock.patch.object(metrics, "METRICS_FILE", journal),
                    mock.patch.object(metrics, "_write_buf", []),
                    mock.patch.object(
                        sensors_svc, "peek_sensors", return_value=planted,
                    ),
                ):
                    metrics.record_sample(immediate=True)
                    r = self.client.get("/api/metrics")
                    self.assertEqual(r.status_code, 200, r.text)
                    body = r.json()
                    _starlette(body)
                    self.assertTrue(body["points"], body)
                    self.assertIsNotNone(body["latest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
