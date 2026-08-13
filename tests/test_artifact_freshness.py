"""A scheduler watchdog that watches the scheduler is watching the wrong thing.

On 2026-08-10 a batch of LaunchAgent plists was corrupted into a state where
launchd kept the jobs *loaded* but their calendar triggers were dead.  The
service sweep in hub.alerts only alerts on "Not loaded", so four daily jobs
silently did not run for three days.  hub.freshness_svc closes that hole by
watching each job's artifact instead of launchd's opinion of the job: if the
newest matching file is too old, the job did not run.

These tests pin the properties that make the check trustworthy:

* staleness and *absence* both alert at ``down`` -- the level that passes the
  notify gate even on installs with ``include_warn=False``, because that is
  the level the incident's eventual "Not loaded" alert went out at;
* a fresh artifact is silent, and the newest match is what counts (the jobs
  prune their own old archives, so old siblings are always present);
* the state machine is edge-triggered with a ~daily re-announce, resolves on
  recovery, and fires on first sight (a job already stale when ServerHub
  starts must not wait for a second incident);
* the wiring in alerts.check_once() actually runs the check and persists its
  bookkeeping, since a check that is never called tests nothing.

Everything runs against a temp directory; the real TARGETS table is only
inspected structurally, never stat()ed, so the suite is green regardless of
what state the host's real backups are in.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import alerts, freshness_svc  # noqa: E402
from hub.freshness_svc import Target, check_freshness  # noqa: E402

#: Fixed "now" so ages are exact instead of racing the wall clock.
NOW = 1_800_000_000

HOUR = 3600


class _Harness(unittest.TestCase):
    """Make a sweep observable without touching the real host.

    Same guards as the SMART alert suite and for the same reasons: the two
    journal files are redirected into a temp dir (this suite runs on the
    machine ServerHub serves, and fabricated stale-backup alerts must not
    land in the operator's real alerts.jsonl), and ``send_ha_notify`` raises
    by default so a test that satisfies the notification gate by accident
    fails loudly instead of pushing to a phone.

    Deliberately holds no ``test_*`` methods: WiringTests also inherits it,
    and test methods here would run twice under two class names.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.artifacts = self.tmp / "artifacts"
        self.artifacts.mkdir()
        patches = [
            mock.patch.object(alerts, "ALERTS_FILE", self.tmp / "alerts.jsonl"),
            mock.patch.object(alerts, "STATE_FILE", self.tmp / "alert_state.json"),
            mock.patch.object(alerts, "notify_settings", lambda: {"enabled": False}),
            mock.patch.object(
                alerts, "send_ha_notify",
                mock.Mock(side_effect=AssertionError("a test must never notify")),
            ),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self._tmp.cleanup)

    # -- helpers ---------------------------------------------------------

    def write_artifact(self, name: str, age_hours: float, now: float = NOW) -> Path:
        """A file under artifacts/ whose mtime is *age_hours* before *now*.

        Sweeps driven by this file's own ``sweep()`` pass the fixed NOW; the
        wiring tests drive the real ``check_once()``, which reads the wall
        clock, so they must age their artifacts against ``time.time()``.
        """
        p = self.artifacts / name
        p.write_text("x")
        stamp = now - age_hours * HOUR
        os.utime(p, (stamp, stamp))
        return p

    def target(self, pattern: str | None = None, max_age_hours: float = 25.0) -> Target:
        return Target(
            id="t1",
            label="local.example-daily",
            pattern=pattern or str(self.artifacts / "example_*.tgz"),
            max_age_hours=max_age_hours,
        )

    def sweep(self, targets, prev=None, now=NOW):
        """``(emitted, new_state)`` for one freshness pass."""
        state: dict = {}
        emitted = check_freshness(dict(prev or {}), state, now, targets=tuple(targets))
        return emitted, state

    def one(self, targets, prev=None, now=NOW) -> dict:
        emitted, _ = self.sweep(targets, prev=prev, now=now)
        self.assertEqual(len(emitted), 1, f"expected exactly one alert, got {emitted}")
        return emitted[0]

class FreshnessTests(_Harness):
    """The check itself, driven directly with a fixed clock."""

    # -- staleness and absence alert; fresh does not --------------------

    def test_a_stale_artifact_alerts_down(self):
        """26h-old artifact against a 25h limit: the job did not run today.

        ``down``, not ``warn``: include_warn ships false on real installs, and
        an alert this module swallows is a re-run of the incident it exists
        to prevent.
        """
        self.write_artifact("example_20260810.tgz", age_hours=26)
        alert = self.one([self.target()])
        self.assertEqual(alert["level"], "down")
        self.assertEqual(alert["kind"], "freshness")
        self.assertEqual(alert["id"], "freshness:t1")
        self.assertEqual(alert["event"], "problem")
        self.assertIn("26.0h", alert["detail"])
        self.assertIn("25h", alert["detail"])
        self.assertIn("local.example-daily", alert["message"])

    def test_a_fresh_artifact_is_silent(self):
        self.write_artifact("example_20260813.tgz", age_hours=1)
        emitted, state = self.sweep([self.target()])
        self.assertEqual(emitted, [])
        self.assertEqual(state["freshness:t1"], "ok")

    def test_the_newest_match_is_what_counts(self):
        """The jobs prune their own archives, so 30-day-old siblings always
        exist next to today's; only the newest one says whether the job ran."""
        self.write_artifact("example_20260713.tgz", age_hours=720)
        self.write_artifact("example_20260813.tgz", age_hours=2)
        emitted, state = self.sweep([self.target()])
        self.assertEqual(emitted, [])
        self.assertEqual(state["freshness:t1"], "ok")

    def test_an_empty_glob_alerts_as_missing(self):
        """Directory exists, nothing matches: the job has never produced."""
        alert = self.one([self.target()])
        self.assertEqual(alert["level"], "down")
        self.assertIn("no artifact matches", alert["detail"])

    def test_a_missing_directory_is_the_same_as_no_artifact(self):
        """The backups directory being renamed/unmounted means backups are not
        happening, which is exactly the alertable condition -- and glob answers
        [] for both, so the two cases must behave identically."""
        gone = self.tmp / "no-such-dir" / "example_*.tgz"
        alert = self.one([self.target(pattern=str(gone))])
        self.assertEqual(alert["level"], "down")
        self.assertIn("no artifact matches", alert["detail"])

    def test_exactly_at_the_limit_is_still_fresh(self):
        """The comparison is strict: 25.0h old against 25h does not alert.
        Cadence math lands exactly on the limit when a job runs to the second,
        and a boundary alert there would flap daily."""
        self.write_artifact("example_x.tgz", age_hours=25)
        emitted, _ = self.sweep([self.target()])
        self.assertEqual(emitted, [])

    # -- state machine ---------------------------------------------------

    def test_ongoing_staleness_does_not_repeat_every_sweep(self):
        """Second sweep 90s later: still stale, already announced, quiet."""
        self.write_artifact("example_x.tgz", age_hours=26)
        prev = {"freshness:t1": "down", "_freshness_last": {"t1": NOW - 90}}
        emitted, state = self.sweep([self.target()], prev=prev)
        self.assertEqual(emitted, [])
        self.assertEqual(state["freshness:t1"], "down")
        self.assertEqual(state["_freshness_last"], {"t1": NOW - 90},
                         "the stamp must survive quiet sweeps or the "
                         "re-announce timer resets itself")

    def test_still_stale_reannounces_after_a_day(self):
        """Day two of the same stall gets one reminder, not silence forever
        (the incident lasted three days) and not a ping per sweep (which
        would train the operator to ignore the alert)."""
        self.write_artifact("example_x.tgz", age_hours=50)
        prev = {"freshness:t1": "down",
                "_freshness_last": {"t1": NOW - freshness_svc.REANNOUNCE_SEC}}
        alert = self.one([self.target()], prev=prev)
        self.assertEqual(alert["level"], "down")

    def test_recovery_emits_resolved_and_drops_the_stamp(self):
        self.write_artifact("example_x.tgz", age_hours=1)
        prev = {"freshness:t1": "down", "_freshness_last": {"t1": NOW - 7200}}
        emitted, state = self.sweep([self.target()], prev=prev)
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["event"], "resolved")
        self.assertEqual(emitted[0]["level"], "ok")
        self.assertEqual(state["freshness:t1"], "ok")
        self.assertEqual(state["_freshness_last"], {},
                         "a resolved episode must release its stamp so a "
                         "relapse alerts immediately instead of waiting out "
                         "a day-old timer")

    def test_first_sight_counts(self):
        """prev={} is a fresh state file (restart, wiped data/).  A job that is
        already stale at boot must alert now: this check only runs after a
        restart in the first place, and staying quiet until the *next* miss
        would add a day of silence to every incident."""
        self.write_artifact("example_x.tgz", age_hours=26)
        alert = self.one([self.target()], prev={})
        self.assertEqual(alert["level"], "down")

    def test_a_quiet_sweep_leaves_state_equal_so_nothing_is_rewritten(self):
        """check_once only writes alert_state.json when the map changed; a
        steady ok state must therefore reproduce itself exactly, or this
        check alone would rewrite the file every sweep, forever."""
        self.write_artifact("example_x.tgz", age_hours=1)
        _, first = self.sweep([self.target()])
        _, second = self.sweep([self.target()], prev=first)
        self.assertEqual(first, second)

    # -- notification gate -----------------------------------------------

    def test_stale_notifies_when_enabled_regardless_of_include_warn(self):
        """The incident's "Not loaded" alert reached the operator because
        service-down bypasses include_warn.  Freshness must ride the same
        gate, or it is quieter than the blind spot it replaces."""
        self.write_artifact("example_x.tgz", age_hours=26)
        sent = mock.Mock()
        with mock.patch.object(alerts, "notify_settings",
                               lambda: {"enabled": True, "include_warn": False}), \
             mock.patch.object(alerts, "send_ha_notify", sent):
            self.one([self.target()])
        self.assertEqual(sent.call_count, 1)
        self.assertEqual(sent.call_args.kwargs.get("level"), "down")

    def test_resolve_respects_notify_resolve(self):
        self.write_artifact("example_x.tgz", age_hours=1)
        prev = {"freshness:t1": "down", "_freshness_last": {"t1": NOW - 7200}}
        sent = mock.Mock()
        with mock.patch.object(alerts, "notify_settings",
                               lambda: {"enabled": True, "notify_resolve": False}), \
             mock.patch.object(alerts, "send_ha_notify", sent):
            emitted, _ = self.sweep([self.target()], prev=prev)
        self.assertEqual(len(emitted), 1, "the resolved alert is still recorded")
        self.assertEqual(sent.call_count, 0, "…but not pushed when the "
                                             "operator opted out of resolves")

    def test_alerts_land_in_the_journal(self):
        """The Alerts page reads alerts.jsonl; an alert that is returned but
        never appended would be invisible there."""
        self.write_artifact("example_x.tgz", age_hours=26)
        self.one([self.target()])
        lines = (self.tmp / "alerts.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["id"], "freshness:t1")


class WiringTests(_Harness):
    """check_freshness only helps if check_once actually calls it.

    check_once reads the real wall clock, so unlike the fixed-clock tests
    above these age their artifacts against ``time.time()``.
    """

    def _check_once(self):
        """Run the real check_once with every *other* probe stubbed out.

        full_status, resources, SMART and UPS all read the real host and
        would inject unrelated alerts (or spawn smartctl) into this test.
        """
        quiet = lambda prev, new_state, now: []  # noqa: E731
        with mock.patch.object(alerts, "full_status", lambda force=False: {"groups": []}), \
             mock.patch.object(alerts, "_check_resource_thresholds", quiet), \
             mock.patch.object(alerts, "_check_smart_health", quiet), \
             mock.patch.object(alerts, "_check_ups", quiet):
            return alerts.check_once()

    def test_check_once_runs_the_freshness_check_and_persists_state(self):
        self.write_artifact("example_x.tgz", age_hours=26, now=time.time())
        with mock.patch.object(freshness_svc, "TARGETS", (self.target(),)):
            emitted = self._check_once()
        self.assertEqual([a["id"] for a in emitted], ["freshness:t1"])
        saved = json.loads((self.tmp / "alert_state.json").read_text())
        self.assertEqual(saved.get("freshness:t1"), "down")
        self.assertIn("t1", saved.get("_freshness_last") or {},
                      "the re-announce stamp must be persisted or every "
                      "restart resets the daily reminder timer")

    def test_check_once_carries_the_stamp_map_across_sweeps(self):
        """The bookkeeping copy at the top of check_once: a stamp map that is
        dropped when the check raises re-announces on every sweep after the
        next restart -- the exact bug the _resource_last carry fixed."""
        self.write_artifact("example_x.tgz", age_hours=26, now=time.time())
        with mock.patch.object(freshness_svc, "TARGETS", (self.target(),)):
            self._check_once()
            # Second sweep: the check itself blows up before touching state.
            with mock.patch.object(freshness_svc, "newest_mtime",
                                   mock.Mock(side_effect=RuntimeError("boom"))):
                self._check_once()
        saved = json.loads((self.tmp / "alert_state.json").read_text())
        self.assertIn("t1", saved.get("_freshness_last") or {},
                      "a raising sweep must not lose the stamp map")


class RealTableTests(unittest.TestCase):
    """Structural checks on the shipped TARGETS — no host filesystem access,
    so these stay green whatever state the real backups are in."""

    def test_ids_are_unique_and_key_safe(self):
        ids = [t.id for t in freshness_svc.TARGETS]
        self.assertEqual(len(ids), len(set(ids)))
        for tid in ids:
            self.assertRegex(tid, r"\A[a-z0-9-]+\Z",
                             "ids end up in state keys and alert ids")

    def test_patterns_are_absolute_and_limits_sane(self):
        for t in freshness_svc.TARGETS:
            with self.subTest(target=t.id):
                self.assertTrue(os.path.isabs(t.pattern),
                                "the sweep runs from an arbitrary cwd")
                # A daily job needs >24h of allowance or it alerts every
                # morning before its own run; anything past 48h means a
                # whole missed day goes unreported.
                self.assertGreater(t.max_age_hours, 24)
                self.assertLess(t.max_age_hours, 48)
                self.assertTrue(t.label)

    def test_the_four_stalled_jobs_of_2026_08_10_are_covered(self):
        """The incident this module exists for: these four must stay in the
        table unless the jobs themselves are retired."""
        labels = {t.label for t in freshness_svc.TARGETS}
        self.assertLessEqual(
            {"local.config-backup", "local.immich-backup",
             "local.onedrive-share-regulations", "com.gravity.rotate-logs"},
            labels,
        )


if __name__ == "__main__":
    unittest.main()
