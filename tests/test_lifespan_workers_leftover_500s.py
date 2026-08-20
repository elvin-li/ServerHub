"""Leftover YAML/IO 500s and LaunchAgent aborts on the lifespan path.

``metrics_interval: .inf`` / ``true`` are already clamped in lifespan.
Leftover ``1e308``, ``!!binary``, a YAML date, ``start_sampler(.inf)``
itself, ``start_scheduler(check_interval=.inf)``, ``maybe_rollup(now=.inf)``,
and ``Path.exists()`` EIO on services.yaml still aborted startup or 500'd
GET /api/smart / GET /api/health/checks.
"""
from __future__ import annotations

import datetime
import errno
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    alerts, app_factory, config, health_svc, metrics, metrics_rollup,
    smart_test_svc, worker_health,
)
from hub.app_factory import create_app  # noqa: E402


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


_LEFTOVER_INTERVALS = (
    float("inf"),
    float("-inf"),
    float("nan"),
    True,
    False,
    b"90",
    b"\xff\xfe",
    datetime.date(2026, 8, 19),
    {"daily"},
    10 ** 400,
    1e308,
    "ok\ud800",
    None,
    "90s",
)


class LifespanHugeIntervalTests(unittest.TestCase):
    def _quiet_lifespan(self):
        mocks = {}
        from hub import backups, network_svc, scheduler_svc, tools_svc

        for module, names in (
            (metrics, ("start_sampler", "stop_sampler")),
            (alerts, ("start_alerter", "stop_alerter")),
            (scheduler_svc, ("start_scheduler", "stop_scheduler")),
            (smart_test_svc, ("start_scheduler", "stop_scheduler")),
            (tools_svc, ("start_updates_warmer", "stop_updates_warmer")),
            (network_svc, ("start_alias_autobind", "stop_alias_autobind")),
            (backups, ("recover_interrupted_stack_backups",)),
        ):
            for name in names:
                key = f"{module.__name__.rsplit('.', 1)[-1]}.{name}"
                patched = mock.patch.object(module, name, mock.MagicMock())
                mocks[key] = patched.start()
                self.addCleanup(patched.stop)
        return mocks

    def test_huge_finite_interval_does_not_abort_lifespan(self):
        """YAML ``metrics_interval: 1e308`` used to start the sampler then
        OverflowError ``Event.wait`` on the first tick."""
        from fastapi.testclient import TestClient

        mocks = self._quiet_lifespan()
        with mock.patch.object(
            app_factory, "cfg",
            return_value={"settings": {
                "metrics_interval": 1e308,
                "alert_interval": 10 ** 400,
            }},
        ):
            with TestClient(create_app()):
                mocks["metrics.start_sampler"].assert_called_once_with(90)
                mocks["alerts.start_alerter"].assert_called_once_with(90)


class StartSamplerLeftoverTests(unittest.TestCase):
    def tearDown(self):
        metrics.stop_sampler()
        alerts.stop_alerter()

    def test_leftover_interval_does_not_raise_start_sampler(self):
        """``int(inf)`` used to OverflowError on the LaunchAgent thread."""
        with (
            mock.patch.object(metrics, "record_sample", lambda *a, **k: {}),
            mock.patch("hub.metrics_rollup.maybe_rollup", lambda: None),
        ):
            for leftover in _LEFTOVER_INTERVALS:
                with self.subTest(leftover=leftover):
                    metrics.stop_sampler()
                    metrics.start_sampler(leftover)
                    self.assertTrue(
                        metrics._thread and metrics._thread.is_alive(),
                        leftover,
                    )

    def test_leftover_interval_does_not_raise_start_alerter(self):
        with (
            mock.patch.object(alerts, "full_status", lambda force=False: {}),
            mock.patch.object(alerts, "check_once", lambda **k: []),
        ):
            for leftover in _LEFTOVER_INTERVALS:
                with self.subTest(leftover=leftover):
                    alerts.stop_alerter()
                    alerts.start_alerter(leftover)
                    self.assertTrue(
                        alerts._thread and alerts._thread.is_alive(),
                        leftover,
                    )


class SmartSchedulerLeftoverTests(unittest.TestCase):
    def tearDown(self):
        smart_test_svc.stop_scheduler()

    def test_leftover_check_interval_does_not_kill_the_worker(self):
        """YAML leftover ``.inf`` / ``!!binary`` OverflowError'd ``Event.wait``
        and the SMART scheduler thread died on its first tick."""
        for leftover in _LEFTOVER_INTERVALS:
            with self.subTest(leftover=leftover):
                smart_test_svc.stop_scheduler()
                smart_test_svc.start_scheduler(check_interval=leftover)
                thread = smart_test_svc._scheduler_thread
                self.assertIsNotNone(thread)
                self.assertTrue(thread.is_alive(), leftover)

    def test_history_leftover_types_do_not_500(self):
        """Leftover ``!!binary`` / a YAML date / ``!!set`` / ``\\ud800``
        used to 500 GET /api/smart."""
        rows = [
            {"ts": 1, "message": "bad\ud800", "ok": True},
            {"ts": 2, "message": b"x", "when": datetime.date(2026, 8, 19),
             "tags": {"short"}, "\ud800": 1},
        ]
        with mock.patch.object(smart_test_svc, "_load_history", return_value=rows):
            out = smart_test_svc.history(10)
        _starlette(out)
        self.assertEqual(len(out), 2)
        # newest first
        self.assertIsInstance(out[0]["message"], str)
        self.assertEqual(out[0]["when"], "2026-08-19")
        self.assertEqual(out[0]["tags"], ["short"])
        self.assertNotIn("\ud800", out[1].get("message", ""))
        self.assertNotIn("\ud800", out[0])

    def test_leftover_bool_last_run_is_zero(self):
        with mock.patch.object(
            smart_test_svc, "cfg",
            return_value={"settings": {"smart_schedule": {
                "interval": "daily", "kind": "short", "last_run": True,
            }}},
        ):
            sched = smart_test_svc.get_schedule()
        self.assertEqual(sched["last_run"], 0.0)
        _json(sched)


class RollupNowLeftoverTests(unittest.TestCase):
    def test_leftover_now_does_not_raise_maybe_rollup(self):
        """Leftover ``now: .inf`` used to ``int(inf // 300)`` the first pass."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        with (
            mock.patch.object(metrics, "METRICS_FILE", root / "metrics.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_5M", root / "5m.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_1H", root / "1h.jsonl"),
            mock.patch.object(metrics_rollup, "STATE_FILE", root / "state.json"),
            mock.patch.object(metrics_rollup, "_state", {"w5": 0, "w1h": 0}),
            mock.patch.object(metrics_rollup, "_state_loaded", False),
            mock.patch.object(metrics_rollup, "_last_trim", {"5m": 0.0, "1h": 0.0}),
        ):
            for leftover in _LEFTOVER_INTERVALS:
                with self.subTest(leftover=leftover):
                    done = metrics_rollup.maybe_rollup(now=leftover)
                    self.assertIn("w5", done)
                    self.assertIn("w1h", done)


class WorkerHealthLeftoverTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(worker_health._workers)
        worker_health._workers.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        worker_health._workers.clear()
        worker_health._workers.update(self._saved)

    def test_leftover_bool_interval_is_not_one_second(self):
        """YAML ``true`` used to register a 1s interval (``float(True)``)."""
        worker_health.register("w", True, thread=None)
        snap = worker_health.snapshot()
        self.assertEqual(snap[0]["interval"], 60.0)
        _json(snap)

    def test_leftover_surrogate_name_does_not_500(self):
        """Leftover ``\\ud800`` in a worker name used to 500 GET /api/health."""
        class Dead:
            def is_alive(self):
                return False

        worker_health.register("w\ud800", 10, thread=Dead())
        snap = worker_health.snapshot()
        problems = worker_health.problems()
        rows = health_svc._worker_checks()
        _starlette({"snap": snap, "problems": problems, "checks": rows})
        self.assertNotIn("\ud800", snap[0]["name"])
        self.assertTrue(problems)


class CfgExistsEioTests(unittest.TestCase):
    def test_exists_eio_does_not_abort_cfg(self):
        """Dying-mount ``Path.exists()`` EIO used to abort the LaunchAgent."""
        real_exists = Path.exists

        def boom(self_path):
            if self_path == config.YAML_PATH:
                raise OSError(errno.EIO, "I/O error")
            return real_exists(self_path)

        with mock.patch.object(Path, "exists", boom):
            data = config.cfg()
        self.assertIsInstance(data, dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
