"""The config-backup agent manifest must cover every incident-class plist.

Regression guard for the 2026-08-10 outage: an overnight session rewrote
several LaunchAgent plists and broke their StartCalendarInterval triggers.
Three of the four damaged agents (local.config-backup, local.immich-backup,
com.gravity.rotate-logs) matched none of the manifest keywords of the day, so
no configs_*.tgz archive held a pre-damage copy to diff against -- the root
cause had to be inferred instead of read.  local.config-backup is the agent
that runs the backup itself, which made the gap especially embarrassing.

The keyword list has since been split: :data:`DEFAULT_AGENT_KEYWORDS` ships
in code and names the panel's own agents plus the products it integrates
with, and each install adds its private apps through
``backups.config_archive.agent_keywords`` in services.yaml.
:data:`LIVE_EXTRA_KEYWORDS` below is a verbatim fixture copy of what this
host's services.yaml carries -- deliberately a fixture and not a read of the
live file, so the suite passes on a machine where neither the config nor the
agents exist.  Fixture-vs-live drift is caught by the operator equivalence
check, not here.

What this file pins, so the guard cannot silently weaken:

* the merged manifest (defaults + this host's extras) still matches every
  incident plist and everything the pre-incident list matched;
* the defaults alone cover the panel's own agents -- they must be archived
  before any install-specific config exists;
* config can only widen the manifest: malformed config degrades to the
  defaults, never to nothing;
* vendor plists stay out even after merging.

These tests pin filenames, not filesystem state: they must pass on a machine
where none of the agents are installed.
"""
import unittest
from unittest import mock

from hub import backups
from hub.backups import DEFAULT_AGENT_KEYWORDS, _wanted_agent, agent_keywords

#: Verbatim copy of ``backups.config_archive.agent_keywords`` in this host's
#: services.yaml.  If the live file changes, change this fixture with it.
LIVE_EXTRA_KEYWORDS = (
    "onedrive", "gravity", "sgcc", "kiro-go", "kidsmusic", "esphome",
    "sub2api", "system-nginx", "cf-ips", "remote-desktop", "server-autostart",
)

#: What agent_keywords() answers on this host: defaults first, extras after.
MERGED = DEFAULT_AGENT_KEYWORDS + LIVE_EXTRA_KEYWORDS


def _cfg_with_extras(extras):
    return {"backups": {"config_archive": {"agent_keywords": extras}}}


class IncidentPlistsAreArchived(unittest.TestCase):
    """Every plist damaged in the 2026-08-10 incident matches the manifest."""

    INCIDENT = (
        "local.config-backup.plist",
        "local.immich-backup.plist",
        "local.onedrive-share-regulations.plist",
        "com.gravity.rotate-logs.plist",
    )

    def test_incident_plists_match_the_merged_manifest(self):
        for name in self.INCIDENT:
            with self.subTest(name=name):
                self.assertTrue(
                    _wanted_agent(name, MERGED),
                    f"{name} was unrecoverable in the 2026-08-10 incident and "
                    "must never fall out of the backup manifest again",
                )

    def test_incident_plists_match_through_the_config_merge(self):
        """The same assertion driven through agent_keywords() reading a config
        dict, so the merge itself is pinned and not just the fixture tuple."""
        with mock.patch.object(
            backups, "cfg", lambda: _cfg_with_extras(list(LIVE_EXTRA_KEYWORDS))
        ):
            for name in self.INCIDENT:
                with self.subTest(name=name):
                    self.assertTrue(_wanted_agent(name))

    def test_the_panels_own_agents_need_no_config(self):
        """The backup agent and the panel exist before any config does, so the
        shipped defaults alone must archive them on a fresh install."""
        for name in (
            "local.config-backup.plist",
            "com.elvin.serverhub.plist",
            "local.serverhub.watchdog.plist",
            "local.services-logrotate.plist",
        ):
            with self.subTest(name=name):
                self.assertTrue(_wanted_agent(name, DEFAULT_AGENT_KEYWORDS))


class PreIncidentCoverageIsKept(unittest.TestCase):
    """The seven plists the oldest keyword list archived still match."""

    LEGACY = (
        "com.elvin.serverhub-launcher.plist",
        "com.elvin.serverhub.plist",
        "com.homeassistant.core.plist",
        "local.cloudflare-ddns.plist",
        "local.cloudflared-tunnel.plist",
        "local.filebrowser.plist",
        "local.onedrive-share.plist",
    )

    def test_legacy_plists_still_match(self):
        for name in self.LEGACY:
            with self.subTest(name=name):
                self.assertTrue(_wanted_agent(name, MERGED))


class VendorPlistsStayOut(unittest.TestCase):
    """brew/Google regenerate their plists on upgrade; archiving them is noise.

    This direction matters too: if someone "fixes" coverage by matching
    everything, the archive silently grows vendor churn and the deliberate
    exclusion documented on DEFAULT_AGENT_KEYWORDS is lost.  Checked against
    the *merged* manifest -- the widest set this host ever matches with.
    """

    VENDOR = (
        "homebrew.mxcl.grafana.plist",
        "homebrew.mxcl.mosquitto.plist",
        "homebrew.mxcl.postgresql@17.plist",
        "com.google.keystone.agent.plist",
        "com.google.GoogleUpdater.wake.plist",
    )

    def test_vendor_plists_do_not_match(self):
        for name in self.VENDOR:
            with self.subTest(name=name):
                self.assertFalse(_wanted_agent(name, MERGED))


class KeywordConfigMerging(unittest.TestCase):
    """agent_keywords() can be widened by config but never narrowed."""

    def test_no_config_yields_exactly_the_defaults(self):
        with mock.patch.object(backups, "cfg", lambda: {}):
            self.assertEqual(agent_keywords(), DEFAULT_AGENT_KEYWORDS)

    def test_malformed_config_degrades_to_the_defaults(self):
        """A bad edit may fail to widen the manifest; it must never empty it."""
        for bad in (
            {"backups": "nonsense"},
            {"backups": {"config_archive": ["not", "a", "mapping"]}},
            {"backups": {"config_archive": {"agent_keywords": "gravity"}}},
            {"backups": {"config_archive": {"agent_keywords": {"a": 1}}}},
        ):
            with self.subTest(cfg=bad):
                with mock.patch.object(backups, "cfg", lambda bad=bad: bad):
                    self.assertEqual(agent_keywords(), DEFAULT_AGENT_KEYWORDS)

    def test_extras_merge_after_defaults_and_deduplicate(self):
        extras = ["gravity", "serverhub", "", "   ", 42, ["x"], "gravity", " sgcc "]
        with mock.patch.object(backups, "cfg", lambda: _cfg_with_extras(extras)):
            self.assertEqual(
                agent_keywords(), DEFAULT_AGENT_KEYWORDS + ("gravity", "sgcc")
            )

    def test_every_default_survives_any_config(self):
        for extras in ([], ["something-else"], [""], [None]):
            with self.subTest(extras=extras):
                with mock.patch.object(
                    backups, "cfg", lambda extras=extras: _cfg_with_extras(extras)
                ):
                    merged = agent_keywords()
                for kw in DEFAULT_AGENT_KEYWORDS:
                    self.assertIn(kw, merged)


if __name__ == "__main__":
    unittest.main()
