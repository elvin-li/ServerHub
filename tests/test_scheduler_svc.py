"""Scheduler engine semantics: tick, no-backfill, overlap skip, history, alerts.

Time is always injected (``_tick_once(now_ts=...)``) and the run journal is
redirected to a scratch directory, so these tests are deterministic and never
touch the panel's real ``data/``.  The only real subprocesses are two
one-liner ``/bin/bash`` commands exercising the shared watchdog executor.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import scheduler_svc  # noqa: E402


def _ts(year, month, day, hour, minute, second=0):
    return datetime(year, month, day, hour, minute, second).timestamp()


class _Sandbox(unittest.TestCase):
    """Scratch run journal + clean engine state per test."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-sched-{os.getpid()}-{id(self)}"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        runs = mock.patch.object(scheduler_svc, "RUNS_PATH", root / "schedule-runs.jsonl")
        runs.start()
        self.addCleanup(runs.stop)
        # Reset the trim time gate so no test inherits another's window.
        for attr, value in (("_last_trim", 0.0), ("_last_minute", None)):
            setattr(scheduler_svc, attr, value)
        scheduler_svc._fail_counts.clear()
        with scheduler_svc._running_guard:
            scheduler_svc._running.clear()

    def journal(self) -> list[dict]:
        try:
            lines = scheduler_svc.RUNS_PATH.read_text().splitlines()
        except OSError:
            return []
        return [json.loads(ln) for ln in lines if ln.strip()]

    def use_jobs(self, jobs: list[dict]):
        patched = mock.patch.object(scheduler_svc, "list_jobs", lambda: [dict(j) for j in jobs])
        patched.start()
        self.addCleanup(patched.stop)

    def capture_launches(self) -> list:
        """Replace _execute so ticks record launches instead of running jobs."""
        launched: list = []
        patched = mock.patch.object(
            scheduler_svc, "_execute",
            lambda job, trigger: launched.append((job["id"], trigger)),
        )
        patched.start()
        self.addCleanup(patched.stop)
        return launched


class TickTests(_Sandbox):
    JOB = {"id": "j1", "name": "every minute", "type": "command",
           "cron": "* * * * *", "enabled": True, "params": {"command": "true"}}

    def test_fires_matching_minute(self):
        self.use_jobs([self.JOB])
        self.capture_launches()
        fired = scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30))
        self.assertEqual(fired, ["j1"])

    def test_leftover_inf_clock_does_not_raise_tick(self):
        """Leftover ``time.time() = inf`` OverflowError'd ``time.localtime``."""
        self.use_jobs([self.JOB])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(float("inf")), [])
        self.assertEqual(scheduler_svc._tick_once(float("-inf")), [])
        self.assertEqual(scheduler_svc._tick_once(float("nan")), [])

    def test_leftover_inf_clock_does_not_nan_the_wait(self):
        """``inf % 60`` is nan; ``Event.wait(nan)`` OverflowError'd the loop."""
        self.assertEqual(scheduler_svc._delay_until_next_minute(float("inf")), 30.0)
        self.assertEqual(scheduler_svc._delay_until_next_minute(float("-inf")), 30.0)
        self.assertEqual(scheduler_svc._delay_until_next_minute(float("nan")), 30.0)
        self.assertEqual(scheduler_svc._delay_until_next_minute(1e308), 30.0)
        self.assertAlmostEqual(
            scheduler_svc._delay_until_next_minute(100.0), 20.5,
        )

    def test_disabled_job_never_fires(self):
        self.use_jobs([{**self.JOB, "enabled": False}])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), [])

    def test_non_matching_minute_does_not_fire(self):
        self.use_jobs([{**self.JOB, "cron": "0 4 * * *"}])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), [])

    def test_unparsable_cron_never_fires(self):
        self.use_jobs([{**self.JOB, "cron": "banana"}])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), [])

    def test_yaml_list_cron_fires(self):
        self.use_jobs([{**self.JOB, "cron": ["*", "*", "*", "*", "*"]}])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), ["j1"])

    def test_string_false_enabled_does_not_fire(self):
        self.use_jobs([{**self.JOB, "enabled": "false"}])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), [])

    def test_job_without_id_is_skipped(self):
        self.use_jobs([{k: v for k, v in self.JOB.items() if k != "id"}])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), [])

    def test_mapping_cron_does_not_abort_the_tick(self):
        """A job-shaped cron dict used to TypeError past the ValueError guard."""
        self.use_jobs([
            {**self.JOB, "id": "bad", "cron": {"minute": "*", "hour": "*"}},
            {**self.JOB, "id": "good"},
        ])
        self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), ["good"])

    def test_same_minute_is_evaluated_once(self):
        self.use_jobs([self.JOB])
        launched = self.capture_launches()
        scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30, 2))
        scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30, 40))
        self.assertEqual(len(launched), 1, "one minute, one launch")

    def test_missed_minutes_are_not_backfilled(self):
        """Sleeping through five matching minutes yields one launch, not five."""
        self.use_jobs([self.JOB])
        launched = self.capture_launches()
        scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30))
        # The machine slept; the next evaluation happens five minutes later.
        scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 35))
        self.assertEqual(len(launched), 2, "only the two evaluated minutes fire")
        self.assertEqual([t for _, t in launched], ["schedule", "schedule"])

    def test_boot_minute_is_marked_evaluated_not_fired(self):
        """start_scheduler's contract, tested via the same mechanism it uses."""
        self.use_jobs([self.JOB])
        launched = self.capture_launches()
        now = _ts(2026, 8, 13, 3, 30)
        scheduler_svc._last_minute = scheduler_svc._minute_key(
            __import__("time").localtime(now))
        self.assertEqual(scheduler_svc._tick_once(now), [])
        self.assertEqual(launched, [])


class ClockJumpTests(_Sandbox):
    """Wall-clock steps must never double-run a job or stall the engine.

    ``_last_minute`` is a high-water mark: an NTP correction (or DST
    fall-back on hosts that observe it) replays wall-clock minutes that were
    already evaluated, and before the guard every fixed-time job in the
    replayed window fired a second time.
    """

    JOB = {"id": "j1", "name": "every minute", "type": "command",
           "cron": "* * * * *", "enabled": True, "params": {"command": "true"}}

    def test_small_backwards_step_does_not_refire(self):
        """03:35 fired; the clock steps back to 03:30: the replayed window
        stays quiet, and normal firing resumes past the high-water mark."""
        self.use_jobs([self.JOB])
        launched = self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 35)), ["j1"])
        for minute in (30, 31, 34, 35):  # the replayed window, incl. the mark
            self.assertEqual(
                scheduler_svc._tick_once(_ts(2026, 8, 13, 3, minute)), [],
                f"03:{minute} was already evaluated once and must not re-fire",
            )
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 36)), ["j1"])
        self.assertEqual(len(launched), 2, "one launch per wall-clock minute")

    def test_fixed_time_job_survives_a_dst_style_hour_replay(self):
        """A nightly 03:30 job: the hour replays (fall-back), one run only."""
        self.use_jobs([{**self.JOB, "cron": "30 3 * * *"}])
        launched = self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), ["j1"])
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 59)), [])
        # The wall clock falls back one hour and walks through 03:30 again.
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 0)), [])
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 30)), [])
        self.assertEqual(len(launched), 1)

    def test_large_backwards_step_reanchors_with_boot_semantics(self):
        """An operator fixing a day-fast clock must not silence the engine
        for a day: past _BACKWARD_RESYNC the new timeline is adopted, with
        the current minute marked evaluated rather than fired (boot rule)."""
        self.use_jobs([self.JOB])
        launched = self.capture_launches()
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 12, 0)), ["j1"])
        # Nine hours back: deliberate clock change, not a correction.
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 0)), [],
                         "the re-anchor minute is marked, not fired")
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 1)), ["j1"],
                         "the minute after the re-anchor schedules normally")
        self.assertEqual(len(launched), 2)

    def test_backwards_step_never_stalls_permanently(self):
        """Even inside the quiet window the mark is eventually re-passed."""
        self.use_jobs([self.JOB])
        self.capture_launches()
        scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 35))
        scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 33))  # small step back
        self.assertEqual(scheduler_svc._last_minute, (2026, 8, 13, 3, 35),
                         "a small step must not move the high-water mark")
        self.assertEqual(scheduler_svc._tick_once(_ts(2026, 8, 13, 3, 36)), ["j1"])


class ExecuteTests(_Sandbox):
    def test_overlap_is_skipped_and_journalled(self):
        job = {"id": "busy", "name": "busy", "type": "command",
               "cron": "* * * * *", "enabled": True, "params": {"command": "true"}}
        with scheduler_svc._running_guard:
            scheduler_svc._running.add("busy")
        entry = scheduler_svc._execute(job, "schedule")
        self.assertEqual(entry["status"], "skipped")
        records = self.journal()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "skipped")
        # The stuck marker must survive: this run did not clear it.
        self.assertTrue(scheduler_svc.is_running("busy"))

    def test_command_runner_captures_output_and_succeeds(self):
        job = {"id": "echo", "name": "echo", "type": "command", "timeout": 30,
               "params": {"command": "echo scheduled-hello"}}
        entry = scheduler_svc._execute(job, "manual")
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["rc"], 0)
        self.assertIn("scheduled-hello", entry["tail"])

    def test_command_list_payload_joins_and_runs(self):
        job = {"id": "echo", "name": "echo", "type": "command", "timeout": 30,
               "params": {"command": ["echo", "list-payload-hello"]}}
        entry = scheduler_svc._execute(job, "manual")
        self.assertEqual(entry["status"], "ok")
        self.assertIn("list-payload-hello", entry["tail"])
        self.assertEqual(entry["trigger"], "manual")
        self.assertFalse(scheduler_svc.is_running("echo"))

    def test_timeout_is_reported_as_timeout(self):
        job = {"id": "slow", "name": "slow", "type": "command", "timeout": 1,
               "params": {"command": "sleep 30"}}
        entry = scheduler_svc._execute(job, "schedule")
        self.assertEqual(entry["rc"], 124)
        self.assertEqual(entry["status"], "timeout")

    def test_unknown_type_fails_without_raising(self):
        job = {"id": "odd", "name": "odd", "type": "teleport", "params": {}}
        entry = scheduler_svc._execute(job, "schedule")
        self.assertEqual(entry["status"], "failed")

    def test_runner_exception_is_contained(self):
        job = {"id": "boom", "name": "boom", "type": "command", "params": {}}
        with mock.patch.dict(scheduler_svc._RUNNERS,
                             {"command": mock.Mock(side_effect=RuntimeError("kapow"))}):
            entry = scheduler_svc._execute(job, "schedule")
        self.assertEqual(entry["status"], "failed")
        self.assertIn("kapow", entry["tail"])
        self.assertFalse(scheduler_svc.is_running("boom"))

    def test_runner_recursing_exc_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 POST run-now wait=True."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        job = {"id": "boom", "name": "boom", "type": "command", "params": {}}
        with mock.patch.dict(
            scheduler_svc._RUNNERS,
            {"command": mock.Mock(side_effect=Recursing())},
        ):
            entry = scheduler_svc._execute(job, "schedule")
        json.dumps(entry, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(entry["status"], "failed")
        self.assertIn("Recursing", entry["tail"])
        self.assertFalse(scheduler_svc.is_running("boom"))


class FailureAlertTests(_Sandbox):
    def _failing_job(self):
        return {"id": "flaky", "name": "flaky", "type": "command",
                "params": {"command": "exit 3"}, "timeout": 30}

    def test_alert_fires_on_second_consecutive_failure(self):
        job = self._failing_job()
        with mock.patch("hub.alerts.emit_alert") as emit:
            scheduler_svc._execute(job, "schedule")
            emit.assert_not_called()
            scheduler_svc._execute(job, "schedule")
            emit.assert_called_once()
            kwargs = emit.call_args.kwargs
        self.assertEqual(kwargs["kind"], "schedule")
        self.assertEqual(kwargs["alert_id"], "schedule:flaky")
        self.assertIn("flaky", kwargs["message"])

    def test_success_resets_the_streak(self):
        job = self._failing_job()
        ok_job = {**job, "params": {"command": "true"}}
        with mock.patch("hub.alerts.emit_alert") as emit:
            scheduler_svc._execute(job, "schedule")
            scheduler_svc._execute(ok_job, "schedule")
            scheduler_svc._execute(job, "schedule")
            emit.assert_not_called()

    def test_skip_does_not_count_as_failure(self):
        job = self._failing_job()
        with mock.patch("hub.alerts.emit_alert") as emit:
            scheduler_svc._execute(job, "schedule")
            with scheduler_svc._running_guard:
                scheduler_svc._running.add("flaky")
            scheduler_svc._execute(job, "schedule")   # skipped
            emit.assert_not_called()

    def test_emit_alert_record_carries_name_and_event(self):
        """The Alerts page renders a.name and a.event; emit_alert records
        used to omit both, leaving blank cells for every scheduler alert."""
        from hub import alerts

        appended: list = []
        with mock.patch.object(alerts, "_append_alert", appended.append), \
             mock.patch.object(alerts, "notify_settings", lambda: {"enabled": False}):
            alert = alerts.emit_alert(
                kind="schedule", level="warn",
                alert_id="schedule:flaky", message="failed twice",
            )
            fallback = alerts.emit_alert(
                kind="schedule", level="warn",
                alert_id="schedule:anon", message="m", title="",
            )
        self.assertEqual(alert["name"], "ServerHub scheduled task")
        self.assertEqual(alert["event"], "problem")
        self.assertEqual(appended[0], alert)
        self.assertEqual(fallback["name"], "schedule:anon",
                         "an empty title falls back to the alert id")


class HistoryTests(_Sandbox):
    def test_journal_is_capped(self):
        # _TRIM_INTERVAL=0 opens the time gate on every append, so the cap
        # itself (not the gate) is what this test exercises.
        with mock.patch.object(scheduler_svc, "MAX_RUNS", 10), \
             mock.patch.object(scheduler_svc, "_TRIM_SOFT_BYTES", 0), \
             mock.patch.object(scheduler_svc, "_TRIM_INTERVAL", 0.0):
            for i in range(25):
                scheduler_svc._record_run({"ts": i, "job": "j", "status": "ok"})
        records = self.journal()
        self.assertLessEqual(len(records), 10)
        self.assertEqual(records[-1]["ts"], 24, "newest records survive the trim")

    def test_trim_is_time_gated_not_per_append(self):
        """The full-file rewrite runs at most once per _TRIM_INTERVAL.

        The previous every-N-appends rule rewrote the whole journal every 20
        records once the file sat at the cap — for a minute-level job that is
        a multi-MB rewrite every 20 minutes, forever (tens of MB/day of write
        amplification on an appliance SSD).
        """
        with mock.patch.object(scheduler_svc, "MAX_RUNS", 5), \
             mock.patch.object(scheduler_svc, "_TRIM_SOFT_BYTES", 0):
            # Gate closed: appends far past the cap must not trigger a rewrite.
            scheduler_svc._last_trim = __import__("time").time()
            for i in range(20):
                scheduler_svc._record_run({"ts": i, "job": "j", "status": "ok"})
            self.assertGreater(
                len(self.journal()), 5,
                "no rewrite may happen while the time gate is closed",
            )
            # Gate open: the next append trims back to the cap.
            scheduler_svc._last_trim = 0.0
            scheduler_svc._record_run({"ts": 99, "job": "j", "status": "ok"})
        records = self.journal()
        self.assertLessEqual(len(records), 5)
        self.assertEqual(records[-1]["ts"], 99)

    def test_runs_filters_by_job_and_orders_newest_first(self):
        for i in range(5):
            scheduler_svc._record_run({"ts": i, "job": "a" if i % 2 else "b", "status": "ok"})
        hits = scheduler_svc.runs("a", limit=10)
        self.assertEqual([r["ts"] for r in hits], [3, 1])
        self.assertEqual(scheduler_svc.runs(limit=2)[0]["ts"], 4)

    def test_last_run(self):
        self.assertIsNone(scheduler_svc.last_run("nope"))
        scheduler_svc._record_run({"ts": 1, "job": "x", "status": "failed"})
        scheduler_svc._record_run({"ts": 2, "job": "x", "status": "ok"})
        self.assertEqual(scheduler_svc.last_run("x")["ts"], 2)


class RunNowTests(_Sandbox):
    def test_run_now_unknown_job(self):
        with mock.patch.object(scheduler_svc, "get_job", lambda _: None):
            self.assertFalse(scheduler_svc.run_job_now("ghost")["ok"])

    def test_run_now_wait_returns_the_run(self):
        job = {"id": "now", "name": "now", "type": "command",
               "params": {"command": "echo ran-now"}, "timeout": 30}
        with mock.patch.object(scheduler_svc, "get_job", lambda _: dict(job)):
            result = scheduler_svc.run_job_now("now", wait=True)
        self.assertTrue(result["ok"])
        self.assertIn("ran-now", result["run"]["tail"])


class EngineStartLeftoverTests(_Sandbox):
    def tearDown(self):
        scheduler_svc.stop_scheduler()
        super().tearDown()

    def test_leftover_localtime_overflow_still_starts_the_engine(self):
        """``time.localtime()`` OverflowError used to skip starting the thread."""
        self.use_jobs([])
        scheduler_svc.stop_scheduler()
        with (
            mock.patch.object(scheduler_svc, "_tick_once", return_value=[]),
            mock.patch.object(
                scheduler_svc.time, "localtime",
                side_effect=OverflowError("clock"),
            ),
        ):
            scheduler_svc.start_scheduler()
            self.assertTrue(
                scheduler_svc._thread and scheduler_svc._thread.is_alive(),
            )
            self.assertIsNone(scheduler_svc._last_minute)


if __name__ == "__main__":
    unittest.main(verbosity=2)
