"""Leftover FIFO / non-regular nodes occupying the metrics journals.

Every prior metrics sweep hardened what the journals *contain* (surrogates,
over-cap digits, Infinity, deep nests).  What was still missing is what the
journal *is*: a leftover FIFO planted at data/metrics.jsonl parked
``os.open`` until a writer appeared, which hung

* GET /api/metrics forever (``history`` -> ``tail_file_lines``),
* GET /api/metrics?range= forever (the tier probe ``_first_row_ts`` and
  ``_rows_since`` used bare ``open()``),
* the alert-threshold read (``latest_sample`` used a bare ``open()``), and
* the sampler flush (``append_text``'s ``O_WRONLY`` open of a reader-less
  FIFO blocks) — *while holding* ``metrics._lock``, so even a healthy
  GET /api/metrics wedged behind the flush.

Same class one file over: a FIFO at metrics-rollup-state.json parked
``read_text_capped`` and wedged the rollup pass, and a leftover *directory*
at alerts.jsonl IsADirectoryError'd ``emit_alert`` out of the scheduler/UPS
caller (the FIFO sibling hung it).

The fixes: ``tail_file_lines`` / ``read_text_capped`` / ``read_bytes_capped``
/ ``append_text`` open with ``O_NONBLOCK`` and refuse non-regular nodes with
the OSError every caller already handles; the journal writers self-heal by
dropping the leftover node (``secure_io.drop_leftover_nonfile``) before the
append, so one planted pipe costs nothing but itself.
"""
from __future__ import annotations

import errno
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import alerts, metrics, metrics_rollup, secure_io  # noqa: E402
from hub.util import read_bytes_capped, read_text_capped, tail_file_lines  # noqa: E402


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class WatchdogMixin:
    """Run *fn* on a daemon thread; a hang fails the test instead of CI."""

    #: Generous next to the ~0s expected runtime, tiny next to a real hang.
    JOIN_TIMEOUT = 10.0

    def _run_with_watchdog(self, fn):
        box: dict = {}

        def worker():
            try:
                box["value"] = fn()
            except BaseException as exc:  # surfaced below, not swallowed
                box["exc"] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(self.JOIN_TIMEOUT)
        self.assertFalse(
            t.is_alive(),
            "blocked on the planted FIFO instead of returning",
        )
        if "exc" in box:
            raise box["exc"]
        return box.get("value")


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
class FifoJournalBase(WatchdogMixin, unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics-fifo-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def fifo(self, name: str) -> Path:
        path = self.root / name
        os.mkfifo(path)
        return path


class TailAndCappedReadFifoTests(FifoJournalBase):
    """The shared readers refuse a FIFO with OSError instead of parking."""

    def test_tail_file_lines_raises_oserror_not_hang(self):
        path = self.fifo("metrics.jsonl")
        with self.assertRaises(OSError):
            self._run_with_watchdog(lambda: tail_file_lines(path, 10))

    def test_read_text_capped_raises_einval_not_hang(self):
        path = self.fifo("state.json")
        with self.assertRaises(OSError) as ctx:
            self._run_with_watchdog(lambda: read_text_capped(path, 1024))
        self.assertEqual(ctx.exception.errno, errno.EINVAL)

    def test_read_bytes_capped_raises_einval_not_hang(self):
        path = self.fifo("blob.plist")
        with self.assertRaises(OSError) as ctx:
            self._run_with_watchdog(lambda: read_bytes_capped(path, 1024))
        self.assertEqual(ctx.exception.errno, errno.EINVAL)

    def test_regular_files_still_read(self):
        path = self.root / "ok.jsonl"
        path.write_text("a\nb\n")
        self.assertEqual(tail_file_lines(path, 1), ["b"])
        self.assertEqual(read_text_capped(path, 16), "a\nb\n")
        self.assertEqual(read_bytes_capped(path, 16), b"a\nb\n")


class AppendTextFifoTests(FifoJournalBase):
    """append_text raises the OSError a leftover directory already produced."""

    def test_readerless_fifo_raises_oserror_not_hang(self):
        path = self.fifo("journal.jsonl")
        with self.assertRaises(OSError):
            self._run_with_watchdog(
                lambda: secure_io.append_text(path, "x\n")
            )

    def test_fifo_with_reader_is_refused_before_the_write(self):
        path = self.fifo("journal.jsonl")
        # With a reader attached the open itself succeeds; the regular-file
        # check must still keep journal bytes out of the pipe.
        rfd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, rfd)
        with self.assertRaises(OSError) as ctx:
            self._run_with_watchdog(
                lambda: secure_io.append_text(path, "x\n")
            )
        self.assertEqual(ctx.exception.errno, errno.EINVAL)
        try:
            leaked = os.read(rfd, 64)
        except BlockingIOError:
            leaked = b""
        self.assertEqual(leaked, b"")

    def test_regular_append_and_symlink_refusal_are_unchanged(self):
        path = self.root / "ok.log"
        secure_io.append_text(path, "one\n")
        secure_io.append_text(path, "two\n")
        self.assertEqual(path.read_text(), "one\ntwo\n")
        victim = self.root / "victim"
        victim.write_text("")
        link = self.root / "link.log"
        link.symlink_to(victim)
        with self.assertRaises(OSError):
            secure_io.append_text(link, "leak\n")


class MetricsReadFifoTests(FifoJournalBase):
    """GET /api/metrics reads survive a FIFO journal."""

    def test_history_returns_buffered_points_not_hang(self):
        path = self.fifo("metrics.jsonl")
        now = int(time.time())
        buffered = json.dumps({"t": now - 10, "cpu_used_pct": 2.0}) + "\n"
        with (
            mock.patch.object(metrics, "METRICS_FILE", path),
            mock.patch.object(metrics, "_write_buf", [buffered]),
        ):
            rows = self._run_with_watchdog(lambda: metrics.history(60))
        _starlette(rows)
        self.assertEqual([r["cpu_used_pct"] for r in rows], [2.0])

    def test_latest_sample_returns_none_not_hang(self):
        path = self.fifo("metrics.jsonl")
        with (
            mock.patch.object(metrics, "METRICS_FILE", path),
            mock.patch.object(metrics, "_last_sample", None),
        ):
            self.assertIsNone(
                self._run_with_watchdog(metrics.latest_sample)
            )

    def test_rollup_probes_and_rows_survive_a_fifo(self):
        path = self.fifo("metrics-5m.jsonl")
        self.assertIsNone(
            self._run_with_watchdog(lambda: metrics_rollup._first_row_ts(path))
        )
        self.assertIsNone(
            self._run_with_watchdog(lambda: metrics_rollup._last_row_ts(path))
        )
        self.assertEqual(
            self._run_with_watchdog(lambda: metrics_rollup._rows_since(path, 0)),
            [],
        )

    def test_rollup_trim_survives_a_fifo(self):
        path = self.fifo("metrics-5m.jsonl")
        with mock.patch.object(
            metrics_rollup, "_last_trim", {"5m": 0.0, "1h": 0.0},
        ):
            out = self._run_with_watchdog(
                lambda: metrics_rollup._maybe_trim_locked(
                    "5m", path, now=1_800_000_000,
                )
            )
        self.assertFalse(out)

    def test_maybe_rollup_survives_a_fifo_state_file(self):
        state = self.fifo("metrics-rollup-state.json")
        with (
            mock.patch.object(metrics, "METRICS_FILE", self.root / "raw.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_5M", self.root / "5m.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_1H", self.root / "1h.jsonl"),
            mock.patch.object(metrics_rollup, "STATE_FILE", state),
            mock.patch.object(metrics_rollup, "_state", {"w5": 0, "w1h": 0}),
            mock.patch.object(metrics_rollup, "_state_loaded", False),
        ):
            done = self._run_with_watchdog(
                lambda: metrics_rollup.maybe_rollup(now=1_800_000_000)
            )
        self.assertIn("w5", done)


class MetricsFlushSelfHealTests(FifoJournalBase):
    """The sampler flush drops the planted node and keeps its samples."""

    def test_flush_onto_a_fifo_recreates_a_regular_journal(self):
        path = self.fifo("metrics.jsonl")
        line = '{"t": 1, "cpu_used_pct": 1.0}\n'
        with (
            mock.patch.object(metrics, "METRICS_FILE", path),
            mock.patch.object(metrics, "_write_buf", [line]),
        ):
            self._run_with_watchdog(metrics.flush_pending)
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text(), line)

    def test_flush_onto_a_directory_recreates_a_regular_journal(self):
        path = self.root / "metrics.jsonl"
        path.mkdir()
        line = '{"t": 2, "cpu_used_pct": 2.0}\n'
        with (
            mock.patch.object(metrics, "METRICS_FILE", path),
            mock.patch.object(metrics, "_write_buf", [line]),
        ):
            metrics.flush_pending()
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text(), line)


class AlertJournalSelfHealTests(FifoJournalBase):
    """emit_alert survives (and heals) a leftover node at alerts.jsonl."""

    def test_emit_alert_onto_a_directory_does_not_raise(self):
        path = self.root / "alerts.jsonl"
        path.mkdir()
        with (
            mock.patch.object(alerts, "ALERTS_FILE", path),
            mock.patch.object(
                alerts, "notify_settings", return_value={"enabled": False},
            ),
        ):
            alert = alerts.emit_alert(
                kind="schedule", level="warn",
                alert_id="schedule:x", message="failed",
            )
        _starlette(alert)
        self.assertTrue(path.is_file())
        rows = [json.loads(ln) for ln in path.read_text().splitlines()]
        self.assertEqual([r["id"] for r in rows], ["schedule:x"])

    def test_emit_alert_onto_a_fifo_does_not_hang(self):
        path = self.fifo("alerts.jsonl")
        with (
            mock.patch.object(alerts, "ALERTS_FILE", path),
            mock.patch.object(
                alerts, "notify_settings", return_value={"enabled": False},
            ),
        ):
            alert = self._run_with_watchdog(
                lambda: alerts.emit_alert(
                    kind="schedule", level="warn",
                    alert_id="schedule:y", message="failed",
                )
            )
        _starlette(alert)
        self.assertTrue(path.is_file())


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
class HttpMetricsFifoTests(WatchdogMixin, unittest.TestCase):
    """The mounted routes answer 200 over a FIFO journal, within the watchdog."""

    @classmethod
    def setUpClass(cls):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hub.routers.settings_api import router

        app = FastAPI()
        app.include_router(router)
        cls.client = TestClient(app, raise_server_exceptions=False)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="metrics-fifo-http-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, node in (
            ("metrics.jsonl", "fifo"),
            ("metrics-5m.jsonl", "fifo"),
            ("metrics-1h.jsonl", "fifo"),
        ):
            os.mkfifo(self.root / name)
        for target, attr, value in (
            (metrics, "METRICS_FILE", self.root / "metrics.jsonl"),
            (metrics, "_write_buf", []),
            (metrics_rollup, "FILE_5M", self.root / "metrics-5m.jsonl"),
            (metrics_rollup, "FILE_1H", self.root / "metrics-1h.jsonl"),
            (metrics_rollup, "STATE_FILE", self.root / "state.json"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)

    def test_get_metrics_answers_200_over_a_fifo_journal(self):
        r = self._run_with_watchdog(lambda: self.client.get("/api/metrics"))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["points"], [])

    def test_get_metrics_range_answers_200_over_fifo_tiers(self):
        r = self._run_with_watchdog(
            lambda: self.client.get("/api/metrics", params={"range": "48h"})
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["points"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
