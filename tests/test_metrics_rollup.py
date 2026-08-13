"""Tiered metrics rollup: the semantics that make year-long history trustworthy.

What is pinned here, and why it matters:

* Window aggregation is avg + max per field, wall-clock aligned.  The max is
  the whole point of the exercise -- a spike averaged into a 1-hour window
  would vanish from the year view.
* Watermarks persist and never move backwards: a panel restart must not
  re-aggregate (duplicated rows would double-weight history) nor skip a
  segment, and an NTP correction must not rewind the rollup into data it
  already consumed.
* Sampling holes stay holes.  Sleep/downtime windows produce no rows; nothing
  interpolates, because invented data on a *monitoring* page is worse than a
  gap.
* Trims are time-gated and atomic, following metrics.py's pattern, so the
  aggregate files never regress to a rewrite-per-pass cadence.

Everything runs against a temp directory; the real data/ tree is never
touched.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import metrics, metrics_rollup as rollup  # noqa: E402

# Hour-aligned epoch base (1699999200 % 3600 == 0) so 5m and 1h windows both
# start exactly at T0 and window arithmetic in assertions stays readable.
T0 = 1_699_999_200


class RollupBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.raw = root / "metrics.jsonl"
        self.f5 = root / "metrics-5m.jsonl"
        self.f1 = root / "metrics-1h.jsonl"
        self.state = root / "metrics-rollup-state.json"
        for target, name, value in (
            (metrics, "METRICS_FILE", self.raw),
            (metrics, "_write_buf", []),
            (metrics, "_last_flush", time.time()),
            (metrics, "_last_trim", time.time()),
            (rollup, "FILE_5M", self.f5),
            (rollup, "FILE_1H", self.f1),
            (rollup, "STATE_FILE", self.state),
            (rollup, "_state", {"w5": 0, "w1h": 0}),
            (rollup, "_state_loaded", False),
            (rollup, "_last_trim", {"5m": 0.0, "1h": 0.0}),
        ):
            patched = mock.patch.object(target, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    # -- helpers ----------------------------------------------------------
    def write_raw(self, rows, append=False):
        payload = "".join(json.dumps(r) + "\n" for r in rows)
        if append and self.raw.exists():
            with open(self.raw, "a") as f:
                f.write(payload)
        else:
            self.raw.write_text(payload)

    def rows_5m(self):
        if not self.f5.exists():
            return []
        return [json.loads(ln) for ln in self.f5.read_text().splitlines() if ln]

    def rows_1h(self):
        if not self.f1.exists():
            return []
        return [json.loads(ln) for ln in self.f1.read_text().splitlines() if ln]

    def simulate_restart(self):
        """Forget all in-memory rollup state, as a new process would."""
        rollup._state["w5"] = 0
        rollup._state["w1h"] = 0
        rollup._state_loaded = False


class FiveMinuteAggregation(RollupBase):
    def test_avg_max_alignment_and_field_semantics(self):
        # Window A [T0, T0+300): three samples with a null, a missing field
        # and a non-numeric field.  Window B starts *exactly* on the boundary:
        # windows are half-open [W, W+300), so t == T0+300 belongs to B.
        self.write_raw([
            {"t": T0, "cpu_used_pct": 10.0, "mem_used_pct": 50, "disk_pct": 60.0,
             "net_rx_bps": 2_000_000.7, "note": "text"},
            {"t": T0 + 90, "cpu_used_pct": 20.0, "mem_used_pct": None},
            {"t": T0 + 180, "cpu_used_pct": 30.0, "mem_used_pct": 70},
            {"t": T0 + 300, "cpu_used_pct": 40.0},
        ])
        done = rollup.maybe_rollup(now=T0 + 600 + 5)
        self.assertEqual(done["w5"], 2)

        rows = self.rows_5m()
        self.assertEqual([r["t"] for r in rows], [T0, T0 + 300])

        a, b = rows
        self.assertEqual(a["n"], 3)
        self.assertEqual(a["cpu_used_pct"], 20.0)
        self.assertEqual(a["cpu_used_pct_max"], 30.0)
        # Nulls don't count toward the average; the field still aggregates
        # over the rows that did report it.
        self.assertEqual(a["mem_used_pct"], 60.0)
        self.assertEqual(a["mem_used_pct_max"], 70.0)
        self.assertEqual(a["disk_pct"], 60.0)
        # Large values are stored as integers (decimals are noise on bps).
        self.assertEqual(a["net_rx_bps"], 2_000_001)
        # Non-numeric fields never leak into aggregates.
        self.assertNotIn("note", a)
        self.assertNotIn("note_max", a)

        self.assertEqual((b["t"], b["n"], b["cpu_used_pct"]), (T0 + 300, 1, 40.0))

    def test_the_open_window_is_never_aggregated(self):
        self.write_raw([
            {"t": T0, "cpu_used_pct": 10.0},
            {"t": T0 + 320, "cpu_used_pct": 90.0},  # current window, still open
        ])
        done = rollup.maybe_rollup(now=T0 + 450)
        self.assertEqual(done["w5"], 1)
        rows = self.rows_5m()
        self.assertEqual([r["t"] for r in rows], [T0])
        self.assertEqual(rollup._state["w5"], T0 + 300)

    def test_first_pass_backfills_both_tiers_from_raw_history(self):
        # Fresh state + 3h of raw history (the upgrade scenario): one pass
        # populates the 5m tier and derives the 1h tier from it.
        self.write_raw([
            {"t": T0 + k * 300, "cpu_used_pct": float(k % 10)} for k in range(36)
        ])
        done = rollup.maybe_rollup(now=T0 + 3 * 3600 + 20)
        self.assertEqual(done, {"w5": 36, "w1h": 3})
        hours = self.rows_1h()
        self.assertEqual([r["t"] for r in hours], [T0, T0 + 3600, T0 + 7200])
        # 12 five-minute samples per hour, weight 1 each.
        self.assertEqual(hours[0]["n"], 12)
        self.assertEqual(hours[0]["cpu_used_pct_max"], 9.0)


class HourAggregation(RollupBase):
    def test_hour_average_is_weighted_by_sample_count(self):
        # 5m rows carrying different n must not be averaged naively:
        # (10*3 + 50*1) / 4 = 20, while mean-of-means would say 30.
        self.f5.write_text(
            json.dumps({"t": T0, "n": 3, "cpu_used_pct": 10.0, "cpu_used_pct_max": 15.0}) + "\n"
            + json.dumps({"t": T0 + 300, "n": 1, "cpu_used_pct": 50.0, "cpu_used_pct_max": 55.0}) + "\n"
        )
        rollup.maybe_rollup(now=T0 + 3600 + 30)
        hours = self.rows_1h()
        self.assertEqual(len(hours), 1)
        self.assertEqual(hours[0]["t"], T0)
        self.assertEqual(hours[0]["n"], 4)
        self.assertEqual(hours[0]["cpu_used_pct"], 20.0)
        self.assertEqual(hours[0]["cpu_used_pct_max"], 55.0)

    def test_hour_target_is_clamped_to_a_lagging_5m_watermark(self):
        # The 5m pass fails (disk hiccup) and its watermark stays at T0+600.
        # The hour tier must not run past floor(w5/1h): aggregating the hour
        # [T0, T0+3600) from incomplete 5m rows would undercount it forever.
        rollup._state.update(w5=T0 + 600, w1h=0)
        rollup._state_loaded = True
        self.write_raw([{"t": T0 + 700, "cpu_used_pct": 5.0}])
        self.f5.write_text(json.dumps({"t": T0, "n": 1, "cpu_used_pct": 1.0}) + "\n")

        real = rollup._rollup_tier_locked

        def flaky(src, dst, win, key, target):
            if key == "w5":
                raise OSError("disk hiccup")
            return real(src, dst, win, key, target)

        with mock.patch.object(rollup, "_rollup_tier_locked", side_effect=flaky):
            done = rollup.maybe_rollup(now=T0 + 2 * 3600 + 30)
        self.assertEqual(done, {"w5": 0, "w1h": 0})
        self.assertEqual(rollup._state["w5"], T0 + 600)  # retried later
        self.assertEqual(self.rows_1h(), [])

        # Next tick the disk is fine again: the 5m tier catches up first and
        # only then does the hour tier consume the now-complete window.
        done = rollup.maybe_rollup(now=T0 + 2 * 3600 + 40)
        self.assertEqual(done["w5"], 1)
        self.assertEqual([r["t"] for r in self.rows_1h()], [T0])
        # Both the pre-seeded 5m row (n=1) and the raw sample rolled at T0+600
        # land in hour T0.
        self.assertEqual(self.rows_1h()[0]["n"], 2)


class WatermarksAndRestarts(RollupBase):
    def test_restart_neither_duplicates_nor_skips(self):
        self.write_raw([
            {"t": T0 + 10, "cpu_used_pct": 1.0},
            {"t": T0 + 310, "cpu_used_pct": 2.0},
        ])
        rollup.maybe_rollup(now=T0 + 700)
        self.assertEqual(len(self.rows_5m()), 2)

        self.simulate_restart()
        self.write_raw([{"t": T0 + 610, "cpu_used_pct": 3.0}], append=True)
        done = rollup.maybe_rollup(now=T0 + 1000)
        # Only the one new window; the two already-aggregated windows must not
        # reappear after the restart.
        self.assertEqual(done["w5"], 1)
        ts = [r["t"] for r in self.rows_5m()]
        self.assertEqual(ts, [T0, T0 + 300, T0 + 600])
        self.assertEqual(len(set(ts)), 3)

    def test_lost_state_file_recovers_from_the_aggregate_tail(self):
        # Crash between "append aggregate rows" and "save state": the state
        # file is stale (or gone), but the last row of the aggregate file
        # proves what was already consumed.
        self.write_raw([{"t": T0 + 10, "cpu_used_pct": 1.0}])
        rollup.maybe_rollup(now=T0 + 400)
        self.assertEqual(len(self.rows_5m()), 1)

        self.state.unlink()
        self.simulate_restart()
        self.write_raw([{"t": T0 + 350, "cpu_used_pct": 2.0}], append=True)
        rollup.maybe_rollup(now=T0 + 700)
        ts = [r["t"] for r in self.rows_5m()]
        self.assertEqual(ts, [T0, T0 + 300])

    def test_state_file_round_trips(self):
        self.write_raw([{"t": T0 + 10, "cpu_used_pct": 1.0}])
        rollup.maybe_rollup(now=T0 + 400)
        saved = json.loads(self.state.read_text())
        self.assertEqual(saved["w5"], T0 + 300)


class ClockRollback(RollupBase):
    def test_rollback_is_a_noop_and_the_watermark_never_regresses(self):
        self.write_raw([{"t": T0 + 10, "cpu_used_pct": 1.0}])
        rollup.maybe_rollup(now=T0 + 700)
        self.assertEqual(rollup._state["w5"], T0 + 600)
        before_rows = self.rows_5m()

        # NTP steps the clock back two windows: nothing runs, nothing rewinds.
        done = rollup.maybe_rollup(now=T0 + 100)
        self.assertEqual(done, {"w5": 0, "w1h": 0})
        self.assertEqual(rollup._state["w5"], T0 + 600)
        self.assertEqual(self.rows_5m(), before_rows)

    def test_samples_stamped_before_the_watermark_are_never_recounted(self):
        self.write_raw([{"t": T0 + 10, "cpu_used_pct": 1.0}])
        rollup.maybe_rollup(now=T0 + 700)
        # A post-rollback sample lands with t inside an already-aggregated
        # window; counting it would double that window's weight.
        self.write_raw([{"t": T0 + 20, "cpu_used_pct": 99.0}], append=True)
        rollup.maybe_rollup(now=T0 + 1000)
        ts = [r["t"] for r in self.rows_5m()]
        self.assertEqual(len(ts), len(set(ts)))
        first = self.rows_5m()[0]
        self.assertEqual(first["cpu_used_pct_max"], 1.0)


class HolesStayHoles(RollupBase):
    def test_sleep_gap_produces_no_rows_in_either_tier(self):
        # Samples in hour 0 and hour 2; the machine slept through hour 1.
        self.write_raw([
            {"t": T0 + 10, "cpu_used_pct": 1.0},
            {"t": T0 + 2 * 3600 + 10, "cpu_used_pct": 2.0},
        ])
        rollup.maybe_rollup(now=T0 + 3 * 3600 + 20)
        ts5 = [r["t"] for r in self.rows_5m()]
        self.assertEqual(ts5, [T0, T0 + 2 * 3600])
        ts1 = [r["t"] for r in self.rows_1h()]
        self.assertEqual(ts1, [T0, T0 + 2 * 3600])
        # No fabricated zero/interpolated rows anywhere in the gap.
        self.assertFalse(any(T0 + 300 <= t < T0 + 2 * 3600 for t in ts5))


class BufferedSamples(RollupBase):
    def test_buffered_samples_are_flushed_before_the_window_is_read(self):
        # record_sample batches to memory (flush cadence up to 5 min); a
        # window can therefore complete while its samples are still in the
        # buffer.  The rollup must see them anyway.
        metrics.record_sample({"t": T0 + 100, "cpu_used_pct": 42.0})
        self.assertFalse(self.raw.exists())  # really still buffered
        rollup.maybe_rollup(now=T0 + 305)
        rows = self.rows_5m()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cpu_used_pct"], 42.0)


class CheapTick(RollupBase):
    def test_no_boundary_crossed_means_no_file_io(self):
        rollup._state.update(w5=T0 + 300, w1h=T0)
        rollup._state_loaded = True
        with mock.patch.object(rollup, "_rows_since") as read:
            done = rollup.maybe_rollup(now=T0 + 400)  # inside the open window
        self.assertEqual(done, {"w5": 0, "w1h": 0})
        read.assert_not_called()
        self.assertFalse(self.state.exists())  # state not rewritten either


class TailReads(RollupBase):
    def test_tail_read_covers_an_old_watermark_and_skips_junk(self):
        rows = [{"t": T0 + i * 90, "cpu_used_pct": float(i)} for i in range(5000)]
        payload = "".join(json.dumps(r) + "\n" for r in rows)
        # Corruption mid-file (partial write) must not poison the read.
        self.raw.write_text(payload[: len(payload) // 2] + "garbage\n" + payload[len(payload) // 2:])
        got = rollup._rows_since(self.raw, T0)
        # Every intact row is recovered; the split row and junk are skipped.
        self.assertGreaterEqual(len(got), 4998)
        recent = rollup._rows_since(self.raw, T0 + 4990 * 90)
        self.assertEqual(len(recent), 10)
        self.assertTrue(all(r["t"] >= T0 + 4990 * 90 for r in recent))


class Trim(RollupBase):
    def test_trim_is_time_gated_slack_gated_and_atomic(self):
        now = float(T0)
        retain = rollup._RETAIN["5m"]
        slack = rollup._TRIM_SLACK["5m"]
        old = {"t": int(now - retain - slack - 600), "n": 1, "cpu_used_pct": 1.0}
        recent = {"t": int(now - 300), "n": 1, "cpu_used_pct": 2.0}
        self.f5.write_text(json.dumps(old) + "\n" + json.dumps(recent) + "\n")

        # Gate open (last trim at 0): old row past retention+slack -> rewrite.
        self.assertTrue(rollup._maybe_trim_locked("5m", self.f5, now))
        self.assertEqual([r["t"] for r in self.rows_5m()], [recent["t"]])
        self.assertEqual(list(self.f5.parent.glob("*.tmp")), [])

        # Same call inside the time gate is a no-op even with old data back.
        self.f5.write_text(json.dumps(old) + "\n" + json.dumps(recent) + "\n")
        self.assertFalse(rollup._maybe_trim_locked("5m", self.f5, now + 10))
        self.assertEqual(len(self.rows_5m()), 2)

        # Gate reopened but the oldest row is within retention+slack: the
        # rewrite is not worth the IO yet, exactly like metrics._TRIM_SLACK.
        rollup._last_trim["5m"] = 0.0
        within = {"t": int(now - retain + 600), "n": 1, "cpu_used_pct": 3.0}
        self.f5.write_text(json.dumps(within) + "\n" + json.dumps(recent) + "\n")
        self.assertFalse(rollup._maybe_trim_locked("5m", self.f5, now))
        self.assertEqual(len(self.rows_5m()), 2)


class RangeParsing(unittest.TestCase):
    def test_units_and_clamps(self):
        self.assertEqual(rollup.parse_range("48h"), 48 * 3600)
        self.assertEqual(rollup.parse_range("30d"), 30 * 86400)
        self.assertEqual(rollup.parse_range("1y"), 365 * 86400)
        self.assertEqual(rollup.parse_range("2w"), 14 * 86400)
        # Absurd spans clamp to the 1h tier's retention.
        self.assertEqual(rollup.parse_range("99y"), rollup.RETAIN_1H)

    def test_rejects_garbage(self):
        for bad in ("", "h", "12", "0h", "-3d", "1x", "1.5h", "abc"):
            with self.assertRaises(ValueError, msg=bad):
                rollup.parse_range(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
