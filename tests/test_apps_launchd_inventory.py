"""Self-hosted LaunchAgents appear on the Apps page and can be uninstalled.

Brew formulae, the panel's own agents, and native-catalog labels already have
their own rows.  Listing them again as ``launchd:…`` would duplicate uninstall
paths; this is the set that used to show only on Services, with no Apps action.
"""
from __future__ import annotations

import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import HTTPException

from hub import apps_manage_svc
from hub.launchd_cache import Listing


def write_agent(agents: Path, label: str, program: str = "/usr/bin/true") -> Path:
    path = agents / f"{label}.plist"
    path.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": [program],
    }))
    return path


class LaunchdInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = Path(self.tmp.name) / "LaunchAgents"
        self.agents.mkdir()
        self.addCleanup(self.tmp.cleanup)

        write_agent(self.agents, "com.example.worker")
        write_agent(self.agents, "local.serverhub.panel")
        write_agent(self.agents, "homebrew.mxcl.nginx")
        write_agent(self.agents, "homebrew.au.colima")
        write_agent(self.agents, "local.filebrowser")
        write_agent(self.agents, "com.homeassistant.core")
        write_agent(self.agents, "local.cloudflared-tunnel")

        # A real Listing, not a stand-in: the pid column is a raw string
        # straight from `launchctl list`, and how it is interpreted is exactly
        # what LaunchdRunStateTests below pins down.
        listing = Listing({"com.example.worker": ("4242", "0")})
        for patched in (
            patch("hub.paths.AGENTS_DIR", self.agents),
            patch("hub.launchd_cache.listing", return_value=listing),
            patch("hub.config.override", return_value={"name": "Example Worker", "group": "AI"}),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_only_self_hosted_agents_are_listed(self):
        items = apps_manage_svc._launchd_apps()
        self.assertEqual([i["id"] for i in items], ["launchd:com.example.worker"])
        self.assertEqual(items[0]["name"], "Example Worker")
        self.assertEqual(items[0]["kind"], "launchd")
        self.assertIn("uninstall", items[0]["actions"])

    def test_protected_brew_and_catalog_labels_are_excluded(self):
        labels = {i["source_id"] for i in apps_manage_svc._launchd_apps()}
        self.assertNotIn("local.serverhub.panel", labels)
        self.assertNotIn("homebrew.mxcl.nginx", labels)
        self.assertNotIn("homebrew.au.colima", labels)
        self.assertNotIn("local.filebrowser", labels)
        self.assertNotIn("com.homeassistant.core", labels)
        self.assertNotIn("local.cloudflared-tunnel", labels)


class LaunchdRunStateTests(unittest.TestCase):
    """`launchctl list` prints "-" in the pid column for a loaded, idle job.

    Reading that column as a pid made every on-demand agent look like it was
    running: on a real host 42 of 44 rows claimed ``Running · pid -`` when only
    16 processes existed, and the page's running/stopped headline counts were
    wrong by the difference.  It also made "Loaded but not running" dead code,
    since a listed label was never considered stopped.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = Path(self.tmp.name) / "LaunchAgents"
        self.agents.mkdir()
        self.addCleanup(self.tmp.cleanup)
        for label in ("com.example.live", "com.example.idle", "com.example.gone"):
            write_agent(self.agents, label)
        listing = Listing({
            "com.example.live": ("4242", "0"),
            "com.example.idle": ("-", "0"),
            # com.example.gone is installed but absent from the listing.
        })
        for patched in (
            patch("hub.paths.AGENTS_DIR", self.agents),
            patch("hub.launchd_cache.listing", return_value=listing),
            patch("hub.config.override", return_value={}),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def rows(self) -> dict[str, dict]:
        return {i["source_id"]: i for i in apps_manage_svc._launchd_apps()}

    def test_a_numeric_pid_is_running(self):
        row = self.rows()["com.example.live"]
        self.assertEqual(row["state"], "ok")
        self.assertEqual(row["status_text"], "Running · pid 4242")
        self.assertIn("stop", row["actions"])

    def test_a_dash_pid_is_loaded_but_not_running(self):
        row = self.rows()["com.example.idle"]
        self.assertEqual(row["state"], "down")
        self.assertEqual(row["status_text"], "Loaded but not running")
        self.assertIn("start", row["actions"])

    def test_an_unlisted_agent_is_not_loaded(self):
        row = self.rows()["com.example.gone"]
        self.assertEqual(row["state"], "down")
        self.assertEqual(row["status_text"], "Not loaded")


class LaunchdActionTests(unittest.TestCase):
    def test_uninstall_forwards_remove_data(self):
        with (
            patch(
                "hub.services_uninstall_svc.uninstall",
                return_value={"ok": True, "label": "com.example.worker"},
            ) as uninst,
            patch.object(apps_manage_svc, "invalidate_inventory"),
        ):
            result = apps_manage_svc.action(
                "launchd:com.example.worker", "uninstall", remove_data=True,
            )
        uninst.assert_called_once_with("com.example.worker", remove_data=True)
        self.assertTrue(result["ok"])

    def test_start_goes_through_run_action(self):
        with (
            patch("hub.actions.run_action", return_value=(0, "started", "")) as run,
            patch.object(apps_manage_svc, "invalidate_inventory"),
        ):
            result = apps_manage_svc.action("launchd:com.example.worker", "start")
        run.assert_called_once_with("com.example.worker", "start")
        self.assertTrue(result["ok"])

    def test_unknown_launchd_detail_is_404(self):
        with patch.object(apps_manage_svc, "_launchd_apps", return_value=[]):
            with self.assertRaises(HTTPException) as caught:
                apps_manage_svc.detail("launchd:com.missing")
        detail = caught.exception.detail
        code = detail.get("code") if isinstance(detail, dict) else detail
        self.assertEqual(code, "apps.launchd_not_found")


if __name__ == "__main__":
    unittest.main()
