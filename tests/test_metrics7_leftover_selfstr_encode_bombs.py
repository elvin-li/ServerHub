"""Metrics sweep #7: self-``__str__`` encode bombs in metrics / rollup.

metrics6 ported the modules5 unbound coercions (int.__index__,
float.__float__, bytes.decode, base.__iter__, dict() copies) into
metrics._jsonable and metrics_rollup._jsonable.  One modules6 convention
never made it across: the unbound ``str.encode`` that sensors_svc._utf8_text
and nas_common._utf8_text already carry.  ``str()`` of a subclass whose
``__str__`` answers *self* skips CPython's exact-str copy, so both modules'
``text.encode("utf-8", "replace")`` tail dispatched into the subclass
override.  Each shape here was live pre-fix:

* A raising ``encode`` bomb (as a value or a mapping key) escaped
  ``_utf8_text`` and raised straight out of ``_jsonable`` in both modules:
  record_sample() raised back at its caller and the sampler tick lost its
  jsonl row past metrics6's guards; the same bomb walked out of rollup's
  ``_jsonable`` dict walk (the append line in _rollup_tier_locked and the
  state save catch TypeError/ValueError/RecursionError — RuntimeError is
  none of them).

* An ``encode`` override that *returned* a hostile buffer whose ``decode``
  answers a lone-surrogate str skipped the scrub entirely: the surrogate
  rode the _jsonable output into Starlette's ``ensure_ascii=False`` +
  UTF-8 encode, a 500 on GET /api/metrics.

The fix is the sensors_svc tail verbatim: ``str.encode(text, "utf-8",
"replace").decode("utf-8")`` answers an exact scrubbed str always, so no
override can fire and no surrogate survives.  These pins reproduce each
class and assert the surfaces stay coded over the real mounted app.
"""
from __future__ import annotations

import json
import sys
import tempfile
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


class SelfStrEncodeBomb(str):
    """``str()`` answers self (subclass survives); the bound ``.encode``
    raises — the modules6 class both metrics ``_utf8_text`` copies missed."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _SurrogateBytes(bytes):
    """The hostile buffer of the returns-hostile chain: its ``decode``
    answers a lone-surrogate str instead of scrubbed text."""

    def decode(self, *args, **kwargs):
        return "a\ud800b"


class HostileEncodeStr(str):
    """encode *returns* a hostile buffer (no raise inside the scrub); the
    surrogate only detonates downstream, in Starlette's UTF-8 encode."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        return _SurrogateBytes(b"x")


class Utf8TextUnitContractTests(unittest.TestCase):
    """Both metrics copies now answer an exact scrubbed str, like sensors."""

    MODULES = (metrics, metrics_rollup, sensors_svc)

    def test_raising_encode_bomb_answers_its_exact_text(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                out = mod._utf8_text(SelfStrEncodeBomb("ok"))
                self.assertEqual(out, "ok")
                self.assertIs(type(out), str)

    def test_returns_hostile_chain_cannot_smuggle_a_surrogate(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                out = mod._utf8_text(HostileEncodeStr("plain"))
                self.assertIs(type(out), str)
                _starlette({"v": out})

    def test_surrogate_inside_the_bomb_subclass_scrubs(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                out = mod._utf8_text(SelfStrEncodeBomb("a\ud800b"))
                self.assertEqual(out, "a?b")
                _starlette({"v": out})


class JsonableEncodeBombTests(unittest.TestCase):
    """The bomb survives _jsonable — as a value, a key, and nested."""

    MODULES = (metrics, metrics_rollup)

    def test_bomb_value_keeps_its_real_text(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                cleaned = mod._jsonable({"nm": SelfStrEncodeBomb("x")})
                _starlette(cleaned)
                self.assertEqual(cleaned, {"nm": "x"})

    def test_bomb_key_keeps_the_entry(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                cleaned = mod._jsonable({SelfStrEncodeBomb("k"): 1})
                _starlette(cleaned)
                self.assertEqual(cleaned, {"k": 1})

    def test_nested_bomb_inside_a_list_survives(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                cleaned = mod._jsonable({"a": [SelfStrEncodeBomb("v"), 1.5]})
                _starlette(cleaned)
                self.assertEqual(cleaned, {"a": ["v", 1.5]})

    def test_hostile_chain_result_still_encodes(self):
        for mod in self.MODULES:
            with self.subTest(module=mod.__name__):
                cleaned = mod._jsonable({"nm": HostileEncodeStr("plain")})
                _starlette(cleaned)


class SamplerTickSurvivesEncodeBombs(unittest.TestCase):
    """A bombed snapshot / caller string must not lose the tick's jsonl row."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics7-bombs-")
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

    def test_record_sample_with_an_encode_bomb_caller_sample(self):
        for name, planted in (
            ("bomb-value", {"t": 123, "nm": SelfStrEncodeBomb("x")}),
            ("bomb-key", {"t": 123, SelfStrEncodeBomb("k"): 1}),
            ("hostile-chain", {"t": 123, "nm": HostileEncodeStr("plain")}),
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
                _starlette(json.loads(lines[-1]))

    def test_tick_over_a_bombed_snapshot_keeps_its_row(self):
        # network.rx_bps / memory.pressure_used_pct flow *verbatim* into the
        # sample dict, so a planted str-subclass bomb reached _jsonable and
        # killed the tick pre-fix (row silently lost past metrics6's guards).
        snapshots = {
            "net-bomb": {"network": {"rx_bps": SelfStrEncodeBomb("42")}},
            "mem-bomb": {"memory": {"pressure_used_pct": SelfStrEncodeBomb("40")}},
            "hostile-chain": {"network": {"tx_bps": HostileEncodeStr("7")}},
        }
        for name, planted in snapshots.items():
            with self.subTest(planted=name):
                self.journal.unlink(missing_ok=True)
                with mock.patch.object(
                    sensors_svc, "peek_sensors", return_value=planted,
                ):
                    sample = metrics.record_sample(immediate=True)
                self.assertIsInstance(sample, dict)
                lines = [
                    ln for ln in self.journal.read_text().splitlines() if ln.strip()
                ]
                self.assertTrue(lines, "tick lost its jsonl row")
                _starlette(json.loads(lines[-1]))

    def test_latest_sample_alert_path_answers_cleaned(self):
        metrics.record_sample({"t": 123, "nm": SelfStrEncodeBomb("x")}, immediate=True)
        latest = metrics.latest_sample()
        self.assertIsInstance(latest, dict)
        _starlette(latest)
        self.assertEqual(latest.get("nm"), "x")


class RollupSurfacesSurviveEncodeBombs(unittest.TestCase):
    """Aggregation output with a bombed key sanitizes instead of aborting."""

    def test_aggregate_window_output_with_a_bomb_key_sanitizes(self):
        out = metrics_rollup._aggregate_window(
            [{SelfStrEncodeBomb("load1"): 2.0, "t": 0}], 0
        )
        cleaned = metrics_rollup._jsonable(out)
        _starlette(cleaned)
        self.assertEqual(cleaned.get("load1"), 2.0)

    def test_state_save_with_a_bomb_key_stays_silent(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics7-state-")
        self.addCleanup(tmp.cleanup)
        state_file = Path(tmp.name) / "metrics-rollup-state.json"
        with (
            mock.patch.object(metrics_rollup, "STATE_FILE", state_file),
            mock.patch.object(
                metrics_rollup, "_state",
                {"w5": 300, "w1h": 3600, SelfStrEncodeBomb("k"): 1},
            ),
        ):
            metrics_rollup._save_state_locked()
        saved = json.loads(state_file.read_text())
        self.assertEqual(saved.get("w5"), 300)
        self.assertEqual(saved.get("k"), 1)


class HttpSurfaceStaysCoded(unittest.TestCase):
    """GET /api/metrics answers 200 with the ticked row over the bomb."""

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

    def test_metrics_route_serves_the_row_ticked_over_the_bomb(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics7-http-")
        self.addCleanup(tmp.cleanup)
        journal = Path(tmp.name) / "metrics.jsonl"
        snapshots = {
            "raising-bomb": {"network": {"rx_bps": SelfStrEncodeBomb("42")}},
            "hostile-chain": {"memory": {"pressure_used_pct": HostileEncodeStr("40")}},
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


class MetricsBaseExceptionNetTests(unittest.TestCase):
    def test_sensors_snapshot_swallows_provider_baseexception(self):
        class LeftoverWatchdogTimeout(BaseException):
            pass

        def boom():
            raise LeftoverWatchdogTimeout("sensors watchdog")

        from hub import sensors_svc

        with mock.patch.object(sensors_svc, "peek_sensors", boom):
            self.assertIsNone(metrics._sensors_snapshot())

    def test_jsonable_swallows_isoformat_getattr_baseexception(self):
        class LeftoverWatchdogTimeout(BaseException):
            pass

        class _IsoBomb:
            @property
            def isoformat(self):
                raise LeftoverWatchdogTimeout("metrics isoformat watchdog")

        self.assertEqual(metrics._jsonable(_IsoBomb()), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
