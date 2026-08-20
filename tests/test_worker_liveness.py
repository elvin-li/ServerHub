"""Dead or wedged worker threads must be visible, not silent.

Every long-lived subsystem here is a daemon thread; when one dies nothing
restarts it and nothing reports it — alerts stop firing while the panel keeps
answering requests.  hub/worker_health.py is the registry that makes that
state observable, and hub/health_svc.py renders it as a health-check row.

The registry is tested with fakes (no real worker is harmed), and the loop
instrumentation is tested by really starting and stopping each worker with
its heavy tick body mocked out.
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import health_svc, worker_health  # noqa: E402


class _FakeThread:
    def __init__(self, alive: bool):
        self._alive = alive

    def is_alive(self) -> bool:
        return self._alive


class _Registry(unittest.TestCase):
    """Empty registry per test; never leaks entries into other tests."""

    def setUp(self):
        self._saved = dict(worker_health._workers)
        worker_health._workers.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        worker_health._workers.clear()
        worker_health._workers.update(self._saved)


class RegistryTests(_Registry):
    def test_dead_thread_is_reported(self):
        worker_health.register("w-dead", 60, thread=_FakeThread(alive=False))
        problems = worker_health.problems()
        self.assertEqual(problems, ["w-dead: thread died"])

    def test_fresh_worker_is_healthy(self):
        worker_health.register("w-ok", 60, thread=_FakeThread(alive=True))
        self.assertEqual(worker_health.problems(), [])
        snap = worker_health.snapshot()
        self.assertEqual(
            [(w["name"], w["alive"], w["stale"]) for w in snap],
            [("w-ok", True, False)],
        )

    def test_stale_beat_is_reported(self):
        """Alive but wedged: no beat for > interval * STALE_AFTER."""
        worker_health.register("w-stuck", 10, thread=_FakeThread(alive=True))
        limit = 10 * worker_health.STALE_AFTER
        now = time.time()
        self.assertEqual(worker_health.problems(now=now + limit - 1), [])
        problems = worker_health.problems(now=now + limit + 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("w-stuck: last tick", problems[0])

    def test_beat_resets_staleness(self):
        worker_health.register("w", 10, thread=_FakeThread(alive=True))
        worker_health._workers["w"]["beat"] = time.time() - 3600
        self.assertTrue(worker_health.problems(), "an hour-old beat is stale")
        worker_health.beat("w")
        self.assertEqual(worker_health.problems(), [])

    def test_unregister_silences_a_stopped_worker(self):
        worker_health.register("w-stopped", 60, thread=_FakeThread(alive=False))
        worker_health.unregister("w-stopped")
        self.assertEqual(worker_health.problems(), [])
        self.assertEqual(worker_health.snapshot(), [])

    def test_beat_for_unknown_name_is_a_noop(self):
        worker_health.beat("never-registered")
        self.assertEqual(worker_health.snapshot(), [])

    def test_reregistration_replaces_the_entry(self):
        """A restarted worker must overwrite its predecessor's corpse."""
        worker_health.register("w", 60, thread=_FakeThread(alive=False))
        worker_health.register("w", 60, thread=_FakeThread(alive=True))
        self.assertEqual(worker_health.problems(), [])


class HealthCheckRowTests(_Registry):
    def test_no_row_before_any_worker_registers(self):
        """Apps built without the lifespan must see an unchanged payload."""
        self.assertEqual(health_svc._worker_checks(), [])

    def test_healthy_workers_render_an_ok_row(self):
        worker_health.register("alert-engine", 300, thread=_FakeThread(alive=True))
        worker_health.register("metrics-sampler", 300, thread=_FakeThread(alive=True))
        rows = health_svc._worker_checks()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["id"], "workers")
        self.assertTrue(row["ok"])
        self.assertEqual(row["level"], "ok")
        self.assertIn("2 worker", row["detail"])

    def test_dead_worker_renders_an_error_row(self):
        worker_health.register("alert-engine", 300, thread=_FakeThread(alive=False))
        rows = health_svc._worker_checks()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["level"], "error")
        self.assertIn("alert-engine: thread died", row["detail"])
        self.assertTrue(row["fix"])

    def test_collect_checks_includes_the_worker_row(self):
        """Pin the wiring: the snapshot builder must render worker liveness.

        Source-level, matching this suite's other wiring guards: running the
        real _collect_checks fans out to smartctl/launchctl/brew, which a
        unit test must not do.
        """
        source = (BASE / "hub" / "health_svc.py").read_text()
        self.assertIn("checks.extend(_worker_checks())", source)


class LoopInstrumentationTests(_Registry):
    """Really start each worker (tick body mocked) and watch it register."""

    def _wait_for(self, name: str, present: bool, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            names = {w["name"] for w in worker_health.snapshot()}
            if (name in names) is present:
                return True
            time.sleep(0.02)
        return False

    def test_metrics_sampler_registers_and_unregisters(self):
        from hub import metrics

        # The tick body is fully mocked: no sensor subprocess, no write to the
        # repo's data/ (record_sample and the rollup both land there).
        with mock.patch.object(metrics, "record_sample", lambda *a, **k: {}), \
             mock.patch("hub.sensors_svc.collect_sensors", lambda **k: {}), \
             mock.patch("hub.metrics_rollup.maybe_rollup", lambda: None):
            metrics.start_sampler(30)
            try:
                self.assertTrue(self._wait_for("metrics-sampler", True),
                                "sampler loop never registered")
            finally:
                metrics.stop_sampler()
        self.assertTrue(self._wait_for("metrics-sampler", False),
                        "stop_sampler must unregister the worker")

    def test_alerter_registers_and_unregisters(self):
        from hub import alerts

        state = Path(self.enterContext(_tempdir())) / "alert_state.json"
        with mock.patch.object(alerts, "full_status", lambda force=False: {}), \
             mock.patch.object(alerts, "check_once", lambda **k: []), \
             mock.patch.object(alerts, "STATE_FILE", state):
            alerts.start_alerter(30)
            try:
                self.assertTrue(self._wait_for("alert-engine", True),
                                "alerter loop never registered")
            finally:
                alerts.stop_alerter()
        self.assertTrue(self._wait_for("alert-engine", False),
                        "stop_alerter must unregister the worker")

    def test_panel_scheduler_registers_and_unregisters(self):
        from hub import scheduler_svc

        with mock.patch.object(scheduler_svc, "list_jobs", lambda: []):
            scheduler_svc.start_scheduler()
            try:
                self.assertTrue(self._wait_for("panel-scheduler", True),
                                "scheduler loop never registered")
            finally:
                scheduler_svc.stop_scheduler()
        self.assertTrue(self._wait_for("panel-scheduler", False),
                        "stop_scheduler must unregister the worker")

    def test_smart_schedule_registers_and_unregisters(self):
        from hub import smart_test_svc

        smart_test_svc.start_scheduler(check_interval=900)
        try:
            self.assertTrue(self._wait_for("smart-schedule", True),
                            "smart-test loop never registered")
        finally:
            smart_test_svc.stop_scheduler()
        self.assertTrue(self._wait_for("smart-schedule", False),
                        "stop_scheduler must unregister the worker")

    def test_a_crashed_loop_shows_up_as_dead(self):
        """End to end on a real thread: loop dies -> problems() reports it."""
        def doomed():
            worker_health.register("doomed-loop", 1)
            raise RuntimeError("boom")

        # The crash is the point of the test; keep its traceback out of the
        # suite's stderr.
        with mock.patch.object(threading, "excepthook", lambda args: None):
            t = threading.Thread(target=doomed, daemon=True)
            t.start()
            t.join(timeout=5)
        self.assertEqual(worker_health.problems(), ["doomed-loop: thread died"])


class InfClockLeftoverTests(_Registry):
    def test_leftover_inf_clock_does_not_500_snapshot(self):
        """Leftover ``time.time() = inf`` used to poison worker age math."""
        import json

        with mock.patch.object(worker_health.time, "time", return_value=float("inf")):
            worker_health.register("w-inf", 60, thread=_FakeThread(alive=True))
            worker_health.beat("w-inf")
            snap = worker_health.snapshot()
            problems = worker_health.problems()
        json.dumps(snap, allow_nan=False)
        json.dumps(problems, allow_nan=False)
        self.assertEqual(len(snap), 1)
        self.assertTrue(all(row.get("age_sec") == row.get("age_sec") for row in snap))
        self.assertNotIn(float("inf"), [row.get("age_sec") for row in snap])


def _tempdir():
    import tempfile
    return tempfile.TemporaryDirectory()


if __name__ == "__main__":
    unittest.main(verbosity=2)
