"""Metrics sweep #6: modules5 unbound-jsonable bombs in metrics / rollup.

The metrics5 sweep neutralized dict/list *method* bombs (items / get /
__bool__ / __iter__) and sensors_svc._jsonable got the full modules5
treatment (unbound base coercions: int.__index__, float.__float__,
bytes.decode, base.__iter__).  metrics._jsonable and
metrics_rollup._jsonable never got that port — their bound probes were
still live one level down:

* An int subclass whose ``__str__`` raises: only ValueError was caught
  around the digit-cap probe, so the bomb raised out of the sanitizer.
* A float subclass whose ``__eq__``/``__float__`` raises: the NaN probe
  (``value != value``), the inf tuple membership, and every bare
  ``float(...)`` (sample_ts, _finite_num, _cpu_used_quick, the gpu leg of
  _sample) dispatched into the override — RuntimeError is none of
  (TypeError, ValueError, OverflowError).
* A bytes/bytearray subclass whose bound ``decode`` raises — as a value
  and as a mapping key — escaped ``_utf8_text`` in both modules.
* ``int(...)`` in metrics.history / metrics._ncpu / rollup's
  ``float(now)`` / query_range's ``int(max_points)`` dispatched into a
  subclass ``__int__``/``__index__``/``__trunc__`` bomb past the
  three-error catch.
* ``_aggregate_window``: a str-subclass key gets *reflected* priority in
  ``key in ("t", "n")`` (it subclasses the tuple items' type), so its
  ``__eq__`` bomb aborted the whole aggregation pass; an int-subclass
  ``n`` blew ``w > 0`` through _finite_num's eq probes.
* sensors_svc helpers outside _jsonable kept bound probes too:
  ``_finite_float`` (bare ``float(value)``), ``_sysctl_int`` and
  ``_nonneg_bytes`` (comparison probes on a subclass int).

Blast radius: a bombed snapshot field killed the sampler tick past
metrics5's shape guards (jsonl row silently lost, maybe_rollup skipped),
record_sample(sample=...) raised back at its caller, and an aggregation
pass died whole.  The fix ports the modules5 unbound-base convention.

These pins reproduce each class and assert the surfaces stay coded /
the tick keeps its row, over the real mounted app where HTTP applies.
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


# --- the modules5 bomb classes -------------------------------------------

class IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")
    __repr__ = __str__


class IntIntBomb(int):
    def __int__(self):
        raise RuntimeError("int int bomb")


class IntCmpBomb(int):
    def __le__(self, other):
        raise RuntimeError("int cmp bomb")
    __ge__ = __lt__ = __gt__ = __le__


class IntEqBomb(int):
    def __eq__(self, other):
        raise RuntimeError("int eq bomb")
    __ne__ = __eq__
    __hash__ = int.__hash__


class FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")
    __ne__ = __eq__
    __hash__ = float.__hash__


class FloatFloatBomb(float):
    def __float__(self):
        raise RuntimeError("float float bomb")


class FloatIntBomb(float):
    def __int__(self):
        raise RuntimeError("float int bomb")


class FloatTruncBomb(float):
    def __trunc__(self):
        raise RuntimeError("float trunc bomb")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **kw):
        raise RuntimeError("bytes decode bomb")


class ByteArrayDecodeBomb(bytearray):
    def decode(self, *a, **kw):
        raise RuntimeError("bytearray decode bomb")


class StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("str eq bomb")
    __ne__ = __eq__
    __hash__ = str.__hash__


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("set iter bomb")


def _bomb_values() -> dict:
    return {
        "int-str-bomb": IntStrBomb(7),
        "int-int-bomb": IntIntBomb(7),
        "float-eq-bomb": FloatEqBomb(1.5),
        "float-float-bomb": FloatFloatBomb(1.5),
        "float-int-bomb": FloatIntBomb(1.5),
        "float-trunc-bomb": FloatTruncBomb(1.5),
        "bytes-decode-bomb": BytesDecodeBomb(b"x"),
        "bytearray-decode-bomb": ByteArrayDecodeBomb(b"x"),
        "bytes-decode-bomb-key": {BytesDecodeBomb(b"k"): 1},
        "str-eq-bomb-key": {StrEqBomb("k"): 1},
        "nested-mixed": {"a": [FloatEqBomb(2.0), IntStrBomb(3)], "b": BytesDecodeBomb(b"v")},
        "iter-bomb-list": IterBombList([1, 2]),
        "iter-bomb-set": IterBombSet({1}),
    }


class SanitizersNeutralizeSubclassBombs(unittest.TestCase):
    """metrics/_rollup _jsonable now match sensors_svc's modules5 immunity."""

    def test_jsonable_survives_and_result_encodes(self):
        for mod in (metrics, metrics_rollup, sensors_svc):
            for name, planted in _bomb_values().items():
                with self.subTest(module=mod.__name__, planted=name):
                    cleaned = mod._jsonable(planted)
                    _starlette(cleaned)

    def test_iter_bomb_subclass_keeps_its_elements(self):
        # metrics/_rollup used to throw the payload away with the bomb
        # (bare list(value) dispatched into the override); sensors kept it.
        for mod in (metrics, metrics_rollup, sensors_svc):
            with self.subTest(module=mod.__name__):
                self.assertEqual(mod._jsonable(IterBombList([1, 2])), [1, 2])

    def test_bytes_decode_bomb_key_keeps_the_entry(self):
        for mod in (metrics, metrics_rollup, sensors_svc):
            with self.subTest(module=mod.__name__):
                cleaned = mod._jsonable({BytesDecodeBomb(b"k"): 1})
                self.assertEqual(cleaned, {"k": 1})

    def test_utf8_text_survives_decode_bombs(self):
        for mod in (metrics, metrics_rollup, sensors_svc):
            for planted in (BytesDecodeBomb(b"x"), ByteArrayDecodeBomb(b"x")):
                with self.subTest(module=mod.__name__, planted=type(planted).__name__):
                    self.assertEqual(mod._utf8_text(planted), "x")


class TimestampAndNumericProbesSurvive(unittest.TestCase):
    """sample_ts / _sample_ts / _finite_num / sensors numeric helpers."""

    def test_sample_ts_drops_bombed_numbers(self):
        for name, planted in _bomb_values().items():
            with self.subTest(planted=name):
                got = metrics.sample_ts(planted)
                got2 = metrics_rollup._sample_ts(planted)
                for value in (got, got2):
                    self.assertTrue(value is None or isinstance(value, int))

    def test_sample_ts_still_answers_plain_values(self):
        self.assertEqual(metrics.sample_ts(1700000000), 1700000000)
        self.assertEqual(metrics.sample_ts(1700000000.9), 1700000000)
        self.assertEqual(metrics_rollup._sample_ts("1700000000"), 1700000000)

    def test_finite_num_drops_bombed_numbers(self):
        for name, planted in _bomb_values().items():
            with self.subTest(planted=name):
                got = metrics_rollup._finite_num(planted)
                self.assertTrue(got is None or isinstance(got, float))
        self.assertEqual(metrics_rollup._finite_num(3), 3.0)

    def test_sensors_numeric_helpers_drop_bombs(self):
        cases = (
            FloatFloatBomb(1.5), FloatEqBomb(1.5), IntStrBomb(7),
            IntCmpBomb(7), IntEqBomb(7), IntIntBomb(7),
        )
        for planted in cases:
            with self.subTest(planted=type(planted).__name__):
                got = sensors_svc._finite_float(planted)
                self.assertTrue(got is None or isinstance(got, float))
                got = sensors_svc._nonneg_bytes(planted)
                self.assertTrue(got is None or type(got) is int)
                got = sensors_svc._sysctl_int(planted)
                self.assertTrue(got is None or type(got) is int)

    def test_sysctl_int_still_answers_a_plain_subclass_payload(self):
        # The bomb rides the methods; a benign subclass value must survive.
        self.assertEqual(sensors_svc._sysctl_int(IntStrBomb(5)), 5)
        self.assertEqual(sensors_svc._nonneg_bytes(IntCmpBomb(5)), 5)


class AggregationSurvivesSubclassBombs(unittest.TestCase):
    """_aggregate_window: reflected __eq__ keys and bombed weights."""

    def test_str_eq_bomb_key_does_not_abort_the_window(self):
        out = metrics_rollup._aggregate_window(
            [{StrEqBomb("x"): 1.0, "t": 0, "load1": 2.0}], 0
        )
        _starlette(metrics_rollup._jsonable(out))
        # The healthy sibling field still aggregates.
        self.assertEqual(out.get("load1"), 2.0)

    def test_bombed_n_weight_falls_back_to_one(self):
        for planted in (IntEqBomb(3), IntStrBomb(3), FloatFloatBomb(3.0)):
            with self.subTest(planted=type(planted).__name__):
                out = metrics_rollup._aggregate_window(
                    [{"t": 0, "n": planted, "load1": 2.0}], 0
                )
                _starlette(metrics_rollup._jsonable(out))
                self.assertEqual(out.get("load1"), 2.0)

    def test_bombed_value_is_dropped_not_raised(self):
        out = metrics_rollup._aggregate_window(
            [{"t": 0, "load1": FloatEqBomb(2.0), "load5": 1.0}], 0
        )
        _starlette(metrics_rollup._jsonable(out))
        self.assertEqual(out.get("load5"), 1.0)

    def test_maybe_rollup_with_a_bombed_now(self):
        for planted in (FloatFloatBomb(1.5), IntIntBomb(7), FloatTruncBomb(1.5)):
            with self.subTest(planted=type(planted).__name__):
                done = metrics_rollup.maybe_rollup(now=planted)
                self.assertIsInstance(done, dict)

    def test_query_range_with_a_bombed_max_points(self):
        got = metrics_rollup.query_range(0, 10, max_points=IntIntBomb(5))
        self.assertIsInstance(got, dict)
        _starlette(got)


class SamplerTickSurvivesFloatBombs(unittest.TestCase):
    """A bombed snapshot number must not lose the tick's jsonl row."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics6-bombs-")
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

    def test_bombed_snapshot_numbers_do_not_kill_the_tick(self):
        # float-float-bomb was the found tick killer: _cpu_used_quick's
        # ``float(s["cpu_used_pct"])`` dispatched into the override past
        # the three-error catch.
        snapshots = {
            "float-float-cpu": {"cpu_used_pct": FloatFloatBomb(5.0)},
            "float-eq-cpu": {"cpu_used_pct": FloatEqBomb(5.0)},
            "int-str-mem": {"memory": {"pressure_used_pct": IntStrBomb(40)}},
            "float-float-gpu": {"gpu": {"util_pct": FloatFloatBomb(9.0)}},
            "bytes-bomb-field": {"nm": BytesDecodeBomb(b"x")},
        }
        for name, planted in snapshots.items():
            with self.subTest(planted=name):
                self.journal.unlink(missing_ok=True)
                with mock.patch.object(
                    sensors_svc, "peek_sensors", return_value=planted,
                ):
                    row = self._tick()
                self.assertIn("t", row)

    def test_record_sample_with_a_bombed_caller_sample(self):
        for name, planted in (
            ("int-str-field", {"t": 123, "load1": IntStrBomb(2)}),
            ("float-eq-field", {"t": 123, "load1": FloatEqBomb(2.0)}),
            ("bytes-decode-field", {"t": 123, "nm": BytesDecodeBomb(b"x")}),
            ("bytes-decode-key", {"t": 123, BytesDecodeBomb(b"k"): 1}),
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

    def test_history_with_a_bombed_minutes(self):
        for planted in (IntIntBomb(60), FloatTruncBomb(60.0)):
            with self.subTest(planted=type(planted).__name__):
                got = metrics.history(planted)
                self.assertIsInstance(got, list)

    def test_ncpu_with_a_bombed_cache(self):
        with mock.patch.dict(
            metrics._ncpu_cache, {"t": time.time(), "n": IntIntBomb(4)},
        ):
            got = metrics._ncpu()
        self.assertIsInstance(got, int)
        self.assertGreater(got, 0)

    def test_cpu_used_quick_with_bombed_snapshots(self):
        for planted in (
            {"cpu_used_pct": FloatFloatBomb(5.0)},
            {"cpu_used_pct": FloatEqBomb(5.0)},
        ):
            with self.subTest(planted=type(planted["cpu_used_pct"]).__name__):
                got = metrics._cpu_used_quick(planted)
                self.assertTrue(got is None or isinstance(got, float))


class HttpSurfacesStayCoded(unittest.TestCase):
    """The mounted app answers 200 over every planted bomb."""

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
        tmp = tempfile.TemporaryDirectory(prefix="metrics6-http-")
        self.addCleanup(tmp.cleanup)
        journal = Path(tmp.name) / "metrics.jsonl"
        snapshots = {
            "float-float-cpu": {"cpu_used_pct": FloatFloatBomb(5.0)},
            "int-str-mem": {"memory": {"pressure_used_pct": IntStrBomb(40)}},
            "bytes-bomb-field": {"nm": BytesDecodeBomb(b"x")},
        }
        for name, planted in snapshots.items():
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

    def test_sensors_polls_over_planted_subclass_number_bombs(self):
        planted_sets = {
            "float-float-field": {"cpu_used_pct": FloatFloatBomb(5.0)},
            "int-str-field": {"rx_bytes": IntStrBomb(7)},
            "bytes-decode-key": {BytesDecodeBomb(b"k"): 1},
            "float-eq-nested": {"memory": {"used_pct": FloatEqBomb(40.0)}},
        }
        for name, planted in planted_sets.items():
            with self.subTest(planted=name):
                with mock.patch.dict(
                    sensors_svc._cache, {"t": time.time(), "v": planted},
                ):
                    for params in ({}, {"light": 1}):
                        r = self.client.get("/api/system/sensors", params=params)
                        self.assertEqual(r.status_code, 200, r.text)
                        _starlette(r.json())

    def test_range_query_stays_coded_over_a_freshly_aggregated_window(self):
        # since/until spanning aggregation exercises _decimate ->
        # _aggregate_window on the request path.
        tmp = tempfile.TemporaryDirectory(prefix="metrics6-range-")
        self.addCleanup(tmp.cleanup)
        journal = Path(tmp.name) / "metrics.jsonl"
        now = int(time.time())
        rows = [
            json.dumps({"t": now - 3600 + i * 90, "load1": 1.0 + i * 0.01})
            for i in range(40)
        ]
        journal.write_text("\n".join(rows) + "\n")
        with (
            mock.patch.object(metrics, "METRICS_FILE", journal),
            mock.patch.object(metrics, "_write_buf", []),
        ):
            r = self.client.get(
                "/api/metrics",
                params={"since": now - 3600, "until": now, "points": 5},
            )
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        _starlette(body)
        self.assertTrue(body["points"], body)
        self.assertLessEqual(len(body["points"]), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
