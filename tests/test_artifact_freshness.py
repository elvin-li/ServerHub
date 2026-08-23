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
  bookkeeping, since a check that is never called tests nothing;
* the table itself comes from services.yaml (``freshness_targets:``) with no
  built-in entries -- the four /Users/a0000 jobs it used to hardcode moved to
  this host's live config, so the parser must reproduce the old table from
  that config (LIVE_FRESHNESS_TARGETS below is a verbatim fixture copy of it).
  ``test_live_yaml_gravity_marker_matches_fixture`` greps the live pattern
  line (never yaml.safe_load -- secrets) so fixture-vs-live drift cannot
  go green.  Missing services.yaml (gitignored on a fresh checkout) skips.

Everything runs against a temp directory; no test stat()s the host's real
backups.  The one live-file read is the pattern-line grep above, skipped
when services.yaml is absent, so the rest of the suite is green regardless
of what state this machine's archives are in.
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

import hub.config  # noqa: E402
from hub import alerts, freshness_svc  # noqa: E402
from hub.freshness_svc import Target, check_freshness, configured_targets  # noqa: E402

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

    def target(
        self,
        pattern: str | None = None,
        max_age_hours: float = 25.0,
        require_dir: str | None = None,
    ) -> Target:
        return Target(
            id="t1",
            label="local.example-daily",
            pattern=pattern or str(self.artifacts / "example_*.tgz"),
            max_age_hours=max_age_hours,
            require_dir=require_dir,
        )

    def sweep(self, targets, prev=None, now=NOW):
        """``(emitted, new_state)`` for one freshness pass.

        ``targets=None`` exercises the config-reading default path.
        """
        state: dict = {}
        emitted = check_freshness(
            dict(prev or {}), state, now,
            targets=tuple(targets) if targets is not None else None,
        )
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

    def test_missing_require_dir_is_ok_without_false_down(self):
        """External-disk jobs exit 0 with SKIP when the mount is unplugged.
        Freshness must not treat the missing artifact as a job that failed."""
        gone = str(self.tmp / "no-such-volume")
        emitted, state = self.sweep([self.target(require_dir=gone)])
        self.assertEqual(emitted, [])
        self.assertEqual(state["freshness:t1"], "ok")

        prev = {"freshness:t1": "down", "_freshness_last": {"t1": NOW - 90}}
        emitted, state = self.sweep([self.target(require_dir=gone)], prev=prev)
        self.assertEqual(state["freshness:t1"], "ok")
        self.assertTrue(emitted)
        self.assertEqual(emitted[0]["event"], "resolved")
        self.assertEqual(emitted[0]["level"], "ok")

    def test_require_dir_present_still_age_checks(self):
        mount = self.tmp / "volume"
        mount.mkdir()
        self.write_artifact("example_x.tgz", age_hours=26)
        alert = self.one([self.target(require_dir=str(mount))])
        self.assertEqual(alert["level"], "down")
        self.assertIn("26.0h", alert["detail"])

        self.write_artifact("example_x.tgz", age_hours=1)
        emitted, state = self.sweep([self.target(require_dir=str(mount))])
        self.assertEqual(emitted, [])
        self.assertEqual(state["freshness:t1"], "ok")

    def test_exactly_at_the_limit_is_still_fresh(self):
        """The comparison is strict: 25.0h old against 25h does not alert.
        Cadence math lands exactly on the limit when a job runs to the second,
        and a boundary alert there would flap daily."""
        self.write_artifact("example_x.tgz", age_hours=25)
        emitted, _ = self.sweep([self.target()])
        self.assertEqual(emitted, [])

    def test_an_unconfigured_install_sweeps_quietly(self):
        """No freshness_targets in services.yaml: the sweep is a clean no-op
        (no alerts, no per-target state keys), not an error in the alert
        thread of every install that never configured the watchdog."""
        with mock.patch.object(hub.config, "cfg", lambda: {}):
            emitted, state = self.sweep(None)
        self.assertEqual(emitted, [])
        self.assertEqual(state, {"_freshness_last": {}})

    # -- state machine ---------------------------------------------------

    def test_a_junk_last_fire_stamp_does_not_abort_the_sweep(self):
        """A torn `_freshness_last` used to raise `int("oops")` and skip the job."""
        self.write_artifact("example_x.tgz", age_hours=26)
        prev = {"freshness:t1": "down", "_freshness_last": {"t1": "yesterday"}}
        alert = self.one([self.target()], prev=prev)
        self.assertEqual(alert["level"], "down")
        self.assertEqual(alert["id"], "freshness:t1")

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
             mock.patch.object(alerts, "_check_ups", quiet), \
             mock.patch("hub.stale_runtime.remediate", lambda now=None: []):
            return alerts.check_once()

    def test_check_once_runs_the_freshness_check_and_persists_state(self):
        self.write_artifact("example_x.tgz", age_hours=26, now=time.time())
        with mock.patch.object(freshness_svc, "configured_targets",
                               lambda raw=None: (self.target(),)):
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
        with mock.patch.object(freshness_svc, "configured_targets",
                               lambda raw=None: (self.target(),)):
            self._check_once()
            # Second sweep: the check itself blows up before touching state.
            with mock.patch.object(freshness_svc, "newest_mtime",
                                   mock.Mock(side_effect=RuntimeError("boom"))):
                self._check_once()
        saved = json.loads((self.tmp / "alert_state.json").read_text())
        self.assertIn("t1", saved.get("_freshness_last") or {},
                      "a raising sweep must not lose the stamp map")


#: Verbatim fixture copy of ``freshness_targets:`` in this host's
#: services.yaml.  If the live file changes, change this fixture with it.
#: 2026-08-15: gravity-rotate-logs watches rotate_logs.freshness, not
#: freshness.log (that file is co-written by write_freshness.py).
LIVE_FRESHNESS_TARGETS = [
    {"id": "config-backup", "label": "local.config-backup",
     "pattern": "/Users/a0000/Services/backups/configs_*.tgz",
     "max_age_hours": 25},
    {"id": "immich-backup", "label": "local.immich-backup",
     "pattern": "/Users/a0000/Services/backups/immich_*.sql.gz",
     "max_age_hours": 25},
    {"id": "onedrive-share-regulations",
     "label": "local.onedrive-share-regulations",
     "pattern": "/Users/a0000/Library/Logs/onedrive-share-regulations.log",
     "max_age_hours": 27},
    {"id": "gravity-rotate-logs", "label": "com.gravity.rotate-logs",
     "pattern": "/Users/a0000/Services/gravity/logs/rotate_logs.freshness",
     "max_age_hours": 25},
]

#: The table hub.freshness_svc.TARGETS hardcoded before it became
#: configuration, plus the 2026-08-15 marker split.  The four jobs that
#: stalled on 2026-08-10 are still the watched set; only the rotate-logs
#: path changed so the watchdog is not fooled by write_freshness.py.
OLD_HARDCODED_TABLE = (
    Target(id="config-backup", label="local.config-backup",
           pattern="/Users/a0000/Services/backups/configs_*.tgz",
           max_age_hours=25.0),
    Target(id="immich-backup", label="local.immich-backup",
           pattern="/Users/a0000/Services/backups/immich_*.sql.gz",
           max_age_hours=25.0),
    Target(id="onedrive-share-regulations",
           label="local.onedrive-share-regulations",
           pattern="/Users/a0000/Library/Logs/onedrive-share-regulations.log",
           max_age_hours=27.0),
    Target(id="gravity-rotate-logs", label="com.gravity.rotate-logs",
           pattern="/Users/a0000/Services/gravity/logs/rotate_logs.freshness",
           max_age_hours=25.0),
)


class ConfiguredTargetsTests(unittest.TestCase):
    """Parsing of ``freshness_targets:`` -- no host filesystem access, so
    these stay green whatever state the real backups are in."""

    def test_this_hosts_config_reproduces_the_old_hardcoded_table(self):
        """The incident guard, restated for configuration: parsing this
        host's live entries (fixture copy above) must yield exactly the
        table the module used to hardcode -- the four jobs that stalled on
        2026-08-10 included."""
        self.assertEqual(configured_targets(LIVE_FRESHNESS_TARGETS),
                         OLD_HARDCODED_TABLE)

    def test_live_yaml_gravity_marker_matches_fixture(self):
        """services.yaml 的 gravity-rotate-logs pattern 必须与夹具同字,
        否则热加载看着绿、夹具却还盯着 freshness.log。不 yaml.safe_load
        整文件(里面有凭据)。"""
        yaml_path = BASE / "services.yaml"
        if not yaml_path.exists():
            self.skipTest("no live services.yaml in this checkout")
        text = yaml_path.read_text(encoding="utf-8")
        expected = LIVE_FRESHNESS_TARGETS[-1]["pattern"]
        self.assertEqual(LIVE_FRESHNESS_TARGETS[-1]["id"], "gravity-rotate-logs")
        self.assertIn("pattern: " + expected, text)
        self.assertNotIn(
            "pattern: /Users/a0000/Services/gravity/logs/freshness.log", text)

    def test_no_config_means_no_targets(self):
        with mock.patch.object(hub.config, "cfg", lambda: {}):
            self.assertEqual(configured_targets(), ())

    def test_wrong_shapes_mean_no_targets(self):
        for raw in ({}, "text", 7):
            with self.subTest(raw=raw):
                self.assertEqual(configured_targets(raw), ())

    def test_malformed_entries_are_skipped_not_fatal(self):
        """One mistyped row must not take the watchdog down for the rows
        that are fine -- a watchdog that stops watching is the incident."""
        raw = [
            "not-a-mapping",
            {"label": "no-id", "pattern": "/x/*.log", "max_age_hours": 25},
            {"id": "no-pattern", "max_age_hours": 25},
            {"id": "relative", "pattern": "logs/*.log", "max_age_hours": 25},
            {"id": "Bad_Id", "pattern": "/x/*.log", "max_age_hours": 25},
            {"id": "bad-age", "pattern": "/x/*.log", "max_age_hours": "soon"},
            {"id": "zero-age", "pattern": "/x/*.log", "max_age_hours": 0},
            {"id": "negative", "pattern": "/x/*.log", "max_age_hours": -3},
            {"id": "good", "pattern": "/x/*.log", "max_age_hours": 25},
            {"id": "good", "pattern": "/dup/*.log", "max_age_hours": 25},
        ]
        parsed = configured_targets(raw)
        self.assertEqual([t.id for t in parsed], ["good"])
        self.assertEqual(parsed[0].pattern, "/x/*.log")

    def test_tilde_patterns_expand_to_absolute(self):
        (t,) = configured_targets(
            [{"id": "home", "pattern": "~/Services/backups/x_*.tgz",
              "max_age_hours": 25}]
        )
        self.assertTrue(os.path.isabs(t.pattern))
        self.assertTrue(t.pattern.endswith("/Services/backups/x_*.tgz"))

    def test_label_defaults_to_the_id(self):
        (t,) = configured_targets(
            [{"id": "nightly", "pattern": "/x/*.log", "max_age_hours": "26.5"}]
        )
        self.assertEqual(t.label, "nightly")
        self.assertEqual(t.max_age_hours, 26.5)
        self.assertIsNone(t.require_dir)

    def test_require_dir_is_parsed_and_relative_is_ignored(self):
        (t,) = configured_targets([
            {"id": "ext", "label": "local.ext",
             "pattern": "/x/*.log", "max_age_hours": 25,
             "require_dir": "/Volumes/Backup"},
        ])
        self.assertEqual(t.require_dir, "/Volumes/Backup")

        (aliased,) = configured_targets([
            {"id": "ext", "pattern": "/x/*.log", "max_age_hours": 25,
             "require_mount": "/Volumes/Backup"},
        ])
        self.assertEqual(aliased.require_dir, "/Volumes/Backup")

        (relative,) = configured_targets([
            {"id": "ext", "pattern": "/x/*.log", "max_age_hours": 25,
             "require_dir": "Volumes/Backup"},
        ])
        self.assertIsNone(relative.require_dir)


if __name__ == "__main__":
    unittest.main()
