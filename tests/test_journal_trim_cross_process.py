"""Journal appends must survive a trim in another panel process.

Sibling of test_audit_trail_cross_process.py for the three remaining bounded
journals — ``alerts.jsonl``, ``schedule-runs.jsonl`` and ``metrics.jsonl``.
Each one appends with O_APPEND and occasionally rewrites itself down to a tail
through an atomic tmp+replace, guarded by a ``threading.Lock`` a second
interpreter never sees.  The documented two-process deployment (packaged
ServerHub.app + LaunchAgent panel sharing one ``data/``) runs the alert sweep,
the scheduler and the metrics sampler in *both* processes, so an entry one of
them lands on the pre-swap inode inside the other's trim window was silently
discarded: an alert row, a job-run record, or a window of samples.

Same rig as the audit-trail tests: two spawn-context interpreters, the
trimmer's ``tail_file_lines`` patched with a sleep to hold its read→replace
window open, the appender landing inside it.  Only ``secure_io.file_lock``
makes the appended line survive.
"""
from __future__ import annotations

import json
import multiprocessing
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from hub import alerts, metrics, scheduler_svc

_MP = multiprocessing.get_context("spawn")


def _slow_tail(module, delay: float):
    real = module.tail_file_lines

    def slow(*args, **kwargs):
        lines = real(*args, **kwargs)
        time.sleep(delay)
        return lines

    return mock.patch.object(module, "tail_file_lines", slow)


# ── child processes (top-level so the spawn context can import them) ─────────


def _alerts_trimmer(store: str, barrier, queue) -> None:
    from hub import alerts as mod

    with mock.patch.object(mod, "ALERTS_FILE", Path(store)), _slow_tail(mod, 0.8):
        mod._appends_since_trim = mod._TRIM_EVERY - 1
        barrier.wait(timeout=30)
        mod._append_alert({"level": "warn", "msg": "race-trimmer", "t": 1})
    queue.put("trimmer")


def _alerts_appender(store: str, barrier, queue) -> None:
    from hub import alerts as mod

    with mock.patch.object(mod, "ALERTS_FILE", Path(store)):
        barrier.wait(timeout=30)
        time.sleep(0.3)
        mod._append_alert({"level": "warn", "msg": "race-victim", "t": 2})
    queue.put("appender")


def _runs_trimmer(store: str, barrier, queue) -> None:
    from hub import scheduler_svc as mod

    with mock.patch.object(mod, "RUNS_PATH", Path(store)), _slow_tail(mod, 0.8):
        mod._last_trim = 0.0
        barrier.wait(timeout=30)
        mod._record_run({"job": "race-trimmer", "status": "ok"})
    queue.put("trimmer")


def _runs_appender(store: str, barrier, queue) -> None:
    from hub import scheduler_svc as mod

    with mock.patch.object(mod, "RUNS_PATH", Path(store)):
        # Keep this process's own time-gated trim out of the picture.
        mod._last_trim = time.time()
        barrier.wait(timeout=30)
        time.sleep(0.3)
        mod._record_run({"job": "race-victim", "status": "ok"})
    queue.put("appender")


def _metrics_trimmer(store: str, barrier, queue) -> None:
    from hub import metrics as mod

    with mock.patch.object(mod, "METRICS_FILE", Path(store)), _slow_tail(mod, 0.8):
        mod._write_buf.append(json.dumps({"t": 1, "who": "race-trimmer"}) + "\n")
        barrier.wait(timeout=30)
        mod.flush_metrics()
    queue.put("trimmer")


def _metrics_appender(store: str, barrier, queue) -> None:
    from hub import metrics as mod

    with mock.patch.object(mod, "METRICS_FILE", Path(store)):
        mod._write_buf.append(json.dumps({"t": 2, "who": "race-victim"}) + "\n")
        barrier.wait(timeout=30)
        time.sleep(0.3)
        mod.flush_pending()
    queue.put("appender")


class _Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_pair(self, target_a, args_a: tuple, target_b, args_b: tuple) -> None:
        barrier = _MP.Barrier(2)
        queue = _MP.Queue()
        procs = [
            _MP.Process(target=target_a, args=(*args_a, barrier, queue)),
            _MP.Process(target=target_b, args=(*args_b, barrier, queue)),
        ]
        for p in procs:
            p.start()
        for _ in procs:
            queue.get(timeout=60)
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)

    @staticmethod
    def _grow(path: Path, lines: int, row: dict) -> None:
        payload = json.dumps(row) + "\n"
        with path.open("w", encoding="utf-8") as fh:
            for _ in range(lines):
                fh.write(payload)


class AlertsJournalCrossProcessTests(_Sandbox):
    def test_an_alert_appended_during_another_processes_trim_survives(self):
        store = self.dir / "alerts.jsonl"
        self._grow(store, alerts.MAX_ALERTS + 50, {"level": "info", "msg": "filler", "t": 0})
        self.run_pair(
            _alerts_trimmer, (str(store),),
            _alerts_appender, (str(store),),
        )
        text = store.read_text(encoding="utf-8")
        self.assertIn("race-victim", text,
                      "the other process's trim discarded the alert")
        self.assertIn("race-trimmer", text)


class ScheduleRunsCrossProcessTests(_Sandbox):
    def test_a_run_recorded_during_another_processes_trim_survives(self):
        store = self.dir / "schedule-runs.jsonl"
        filler = {"job": "filler", "status": "ok", "pad": "x" * 600}
        self._grow(store, scheduler_svc._TRIM_SOFT_BYTES // 600 + 200, filler)
        self.run_pair(
            _runs_trimmer, (str(store),),
            _runs_appender, (str(store),),
        )
        text = store.read_text(encoding="utf-8")
        self.assertIn("race-victim", text,
                      "the other process's trim discarded the run record")
        self.assertIn("race-trimmer", text)


class MetricsCrossProcessTests(_Sandbox):
    def test_samples_flushed_during_another_processes_trim_survive(self):
        store = self.dir / "metrics.jsonl"
        self._grow(store, metrics.MAX_POINTS + metrics._TRIM_SLACK + 100,
                   {"t": 0, "who": "filler"})
        self.run_pair(
            _metrics_trimmer, (str(store),),
            _metrics_appender, (str(store),),
        )
        text = store.read_text(encoding="utf-8")
        self.assertIn("race-victim", text,
                      "the other process's trim discarded the samples")
        self.assertIn("race-trimmer", text)


if __name__ == "__main__":
    unittest.main()
