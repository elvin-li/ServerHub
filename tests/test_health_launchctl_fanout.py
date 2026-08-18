"""Health checks must read `launchctl list` once, not once per service.

``run_checks`` already fetched the full listing to find stalled KeepAlive agents,
but that happened *below* the Homebrew section, so the brew loop asked launchctl
about each service individually — up to four extra subprocesses answering a
question the single listing already answers.

The judgement is identical either way: a label with a PID in the first column is
running, which is exactly what the per-service probe looked for. This pins the
call count so the fan-out cannot creep back, and pins the verdict so collapsing it
cannot silently start reporting a stopped service as healthy.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import health_svc, launchd_cache  # noqa: E402

#: `launchctl list` output: PID, status, label.
LAUNCHCTL_LIST = "\n".join([
    "PID\tStatus\tLabel",
    "501\t0\thomebrew.mxcl.grafana",
    "-\t0\thomebrew.mxcl.mosquitto",
    "612\t0\thomebrew.mxcl.postgresql@17",
])


#: The listing now comes from hub.launchd_cache, which settled on the absolute path:
#: a bare `launchctl` depends on the panel's PATH, and a LaunchAgent need not set one.
LISTING_ARGV = ["/bin/launchctl", "list"]


class LaunchctlFanoutTests(unittest.TestCase):
    def setUp(self):
        # run_checks memoises for 45s, so without clearing this a test reads a
        # previous run's result and observes no subprocesses at all.
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(lambda: health_svc._cache.update(t=0.0, v=None))
        # Same hazard one level down: the listing is shared process-wide, so a
        # neighbouring test's copy would answer this one and no argv would be seen.
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)

    def _run(self, brew_states):
        """Run the checks with launchctl and brew stubbed; return (checks, argvs)."""
        argvs = []

        def fake_sh(argv, **kwargs):
            argvs.append(list(argv))
            if list(argv[:2]) == LISTING_ARGV:
                return (0, LAUNCHCTL_LIST, "")
            return (1, "", "")

        with (
            patch.object(health_svc, "sh", side_effect=fake_sh),
            patch.object(launchd_cache, "sh", side_effect=fake_sh),
            patch.object(health_svc, "brew_services_list", return_value=brew_states),
        ):
            result = health_svc.run_checks(force=True)
        checks = result.get("checks") if isinstance(result, dict) else result
        return checks, argvs

    def test_launchctl_list_is_called_once(self):
        brew = [{"name": n, "status": "none"} for n in
                ("postgresql@17", "postgresql@18", "mosquitto", "grafana")]
        _, argvs = self._run(brew)
        listings = [a for a in argvs if a[:2] == LISTING_ARGV]
        self.assertEqual(
            len(listings), 1,
            f"expected one full listing, got {len(listings)}: {listings}",
        )

    def test_no_per_label_launchctl_probe_remains(self):
        brew = [{"name": n, "status": "none"} for n in
                ("postgresql@17", "mosquitto", "grafana")]
        _, argvs = self._run(brew)
        per_label = [a for a in argvs if a[:2] == LISTING_ARGV and len(a) > 2]
        self.assertEqual(
            per_label, [], f"per-service launchctl probes returned: {per_label}"
        )

    def test_a_label_with_a_pid_counts_as_running(self):
        """brew reports 'none' for an agent it does not manage; launchd knows better."""
        checks, _ = self._run([{"name": "grafana", "status": "none"}])
        grafana = next(c for c in checks if c["id"] == "brew_grafana")
        self.assertTrue(grafana["ok"], "a running launchd agent was reported as down")
        self.assertIn("launchd", grafana["detail"])

    def test_a_label_without_a_pid_stays_down(self):
        checks, _ = self._run([{"name": "mosquitto", "status": "none"}])
        mosquitto = next(c for c in checks if c["id"] == "brew_mosquitto")
        self.assertFalse(
            mosquitto["ok"], "a service with no PID was reported as healthy"
        )

    def test_a_label_launchd_has_never_heard_of_stays_down(self):
        checks, _ = self._run([{"name": "postgresql@18", "status": "none"}])
        pg = next(c for c in checks if c["id"] == "brew_postgresql@18")
        self.assertFalse(pg["ok"])

    def test_brews_own_started_status_is_still_trusted(self):
        checks, _ = self._run([{"name": "mosquitto", "status": "started"}])
        mosquitto = next(c for c in checks if c["id"] == "brew_mosquitto")
        self.assertTrue(mosquitto["ok"])


class KeepAliveWatchTests(unittest.TestCase):
    def test_disabled_plist_is_not_unsupervised(self):
        self.assertTrue(health_svc._skip_keepalive_watch(
            {"Disabled": True, "KeepAlive": True}, "local.photoshub-originals",
        ))

    def test_hidden_override_is_not_unsupervised(self):
        with patch.object(health_svc, "override", return_value={"hide": True}):
            self.assertTrue(health_svc._skip_keepalive_watch(
                {"KeepAlive": True}, "homebrew.mxcl.redis",
            ))

    def test_live_keepalive_is_watched(self):
        with patch.object(health_svc, "override", return_value={}):
            self.assertFalse(health_svc._skip_keepalive_watch(
                {"KeepAlive": True}, "local.foo",
            ))


class FanOutIsolationTests(unittest.TestCase):
    def setUp(self):
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(lambda: health_svc._cache.update(t=0.0, v=None))
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)

    def test_one_probe_raise_does_not_empty_checks(self):
        with (
            patch.object(health_svc, "sh", return_value=(1, "", "")),
            patch.object(launchd_cache, "sh", return_value=(0, LAUNCHCTL_LIST, "")),
            patch.object(health_svc, "brew_services_list", return_value=[]),
            patch.object(health_svc, "_immich_checks", side_effect=RuntimeError("boom")),
        ):
            result = health_svc.run_checks(force=True)
        checks = result.get("checks") if isinstance(result, dict) else result
        ids = [c["id"] for c in checks]
        self.assertIn("disk_root", ids)
        self.assertGreater(len(checks), 1)

    def test_non_dict_plist_does_not_empty_checks(self):
        import plistlib
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "garbage.plist").write_bytes(plistlib.dumps(["not", "a", "dict"]))
            (Path(tmp) / "keep.plist").write_bytes(plistlib.dumps({
                "Label": "local.keep",
                "KeepAlive": True,
            }))
            with (
                patch.object(health_svc, "AGENTS_DIR", Path(tmp)),
                patch.object(health_svc, "sh", return_value=(1, "", "")),
                patch.object(launchd_cache, "sh", return_value=(0, LAUNCHCTL_LIST, "")),
                patch.object(health_svc, "brew_services_list", return_value=[]),
            ):
                result = health_svc.run_checks(force=True)
        checks = result.get("checks") if isinstance(result, dict) else result
        ids = [c["id"] for c in checks]
        self.assertIn("disk_root", ids)
        self.assertIn("la_local.keep", ids)
        self.assertGreater(len(checks), 1)


if __name__ == "__main__":
    unittest.main()
