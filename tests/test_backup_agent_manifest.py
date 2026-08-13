"""The config-backup agent manifest must cover every incident-class plist.

Regression guard for the 2026-08-10 outage: an overnight session rewrote
several LaunchAgent plists and broke their StartCalendarInterval triggers.
Three of the four damaged agents (local.config-backup, local.immich-backup,
com.gravity.rotate-logs) matched none of the manifest keywords of the day, so
no configs_*.tgz archive held a pre-damage copy to diff against -- the root
cause had to be inferred instead of read.  local.config-backup is the agent
that runs the backup itself, which made the gap especially embarrassing.

These tests pin filenames, not filesystem state: they must pass on a machine
where none of the agents are installed.
"""
import unittest

from hub.backups import _wanted_agent


class IncidentPlistsAreArchived(unittest.TestCase):
    """Every plist damaged in the 2026-08-10 incident matches the manifest."""

    INCIDENT = (
        "local.config-backup.plist",
        "local.immich-backup.plist",
        "local.onedrive-share-regulations.plist",
        "com.gravity.rotate-logs.plist",
    )

    def test_incident_plists_match(self):
        for name in self.INCIDENT:
            with self.subTest(name=name):
                self.assertTrue(
                    _wanted_agent(name),
                    f"{name} was unrecoverable in the 2026-08-10 incident and "
                    "must never fall out of the backup manifest again",
                )


class PreIncidentCoverageIsKept(unittest.TestCase):
    """The seven plists the old keyword list archived still match."""

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
                self.assertTrue(_wanted_agent(name))


class VendorPlistsStayOut(unittest.TestCase):
    """brew/Google regenerate their plists on upgrade; archiving them is noise.

    This direction matters too: if someone "fixes" coverage by matching
    everything, the archive silently grows vendor churn and the deliberate
    exclusion documented on _AGENT_KEYWORDS is lost.
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
                self.assertFalse(_wanted_agent(name))


if __name__ == "__main__":
    unittest.main()
