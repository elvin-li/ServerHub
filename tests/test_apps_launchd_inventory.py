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


def write_agent(agents: Path, label: str, program: str = "/usr/bin/true", extra: dict | None = None) -> Path:
    path = agents / f"{label}.plist"
    payload = {
        "Label": label,
        "ProgramArguments": [program],
    }
    if extra:
        payload.update(extra)
    path.write_bytes(plistlib.dumps(payload))
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


class LaunchdScheduledAndHiddenTests(unittest.TestCase):
    """StartInterval agents have no PID between ticks; hide must match Services."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = Path(self.tmp.name) / "LaunchAgents"
        self.agents.mkdir()
        self.addCleanup(self.tmp.cleanup)
        write_agent(self.agents, "local.immich-keepalive", extra={"StartInterval": 120})
        write_agent(self.agents, "local.cloudflare-ddns", extra={"StartCalendarInterval": {"Hour": 4}})
        write_agent(self.agents, "local.cloudflared-zaoxue")
        listing = Listing({
            "local.immich-keepalive": ("-", "0"),
            "local.cloudflare-ddns": ("-", "1"),
            "local.cloudflared-zaoxue": ("-", "0"),
        })

        def override(label):
            if label == "local.cloudflared-zaoxue":
                return {"hide": True, "name": "Cloudflare Tunnel（早学）"}
            return {}

        for patched in (
            patch("hub.paths.AGENTS_DIR", self.agents),
            patch("hub.launchd_cache.listing", return_value=listing),
            patch("hub.config.override", side_effect=override),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def rows(self) -> dict[str, dict]:
        return {i["source_id"]: i for i in apps_manage_svc._launchd_apps()}

    def test_interval_job_is_ok_while_idle(self):
        row = self.rows()["local.immich-keepalive"]
        self.assertEqual(row["state"], "ok")
        self.assertEqual(row["status_text"], "Loaded · scheduled task")

    def test_calendar_job_last_exit_is_not_down(self):
        row = self.rows()["local.cloudflare-ddns"]
        self.assertEqual(row["state"], "ok")
        self.assertIn("scheduled task", row["status_text"])
        self.assertIn("last exit code 1", row["status_text"])

    def test_hidden_agents_are_omitted(self):
        self.assertNotIn("local.cloudflared-zaoxue", self.rows())


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


class DockerRelatedRowTests(unittest.TestCase):
    """Junk rows in the container list used to 500 Apps detail and autostart."""

    def test_detail_skips_non_dict_and_numeric_ids(self):
        junk = {
            "containers": [
                "not-a-row",
                None,
                {"id": 12, "name": "immich_server", "project": "immich", "state": "ok"},
                {"id": "immich_postgres", "project": "immich", "ports": "5432"},
            ]
        }
        with (
            patch("hub.containers_svc.list_containers", return_value=junk),
            patch("hub.containers_svc.list_stacks", return_value=[]),
            patch.object(apps_manage_svc, "fan_out", return_value=[(1, ""), (1, "")]),
        ):
            detail = apps_manage_svc._docker_detail("immich")
        names = {c["name"] for c in detail["containers"]}
        self.assertIn("12", names)
        self.assertIn("immich_postgres", names)
        self.assertNotIn(None, names)

    def test_autostart_skips_junk_rows_instead_of_500(self):
        junk = {
            "containers": [
                "nope",
                {"id": 7, "project": "immich"},
                {"id": "immich_server", "project": "immich"},
            ]
        }
        calls = []

        def fake_set(name, enabled):
            calls.append(name)
            return {"ok": True, "message": f"set {name}"}

        with (
            patch("hub.containers_svc.list_containers", return_value=junk),
            patch("hub.autostart_svc.set_docker_autostart", side_effect=fake_set),
            patch.object(apps_manage_svc, "invalidate_inventory"),
        ):
            result = apps_manage_svc.action("docker:immich", "autostart_on")
        self.assertTrue(result["ok"])
        self.assertEqual(calls, ["7", "immich_server"])

    def test_autostart_overview_skips_junk_container_rows(self):
        from hub import autostart_svc

        junk = {
            "containers": [
                "nope",
                None,
                {"id": True, "name": "bool-id"},
                {"id": 7, "name": "numeric", "restart_policy": "always", "autostart": True},
                {"id": "immich_server", "name": "immich", "raw_state": "running"},
            ]
        }
        with (
            patch.object(autostart_svc, "engine_up", return_value=True),
            patch("hub.containers_svc.list_containers", return_value=junk),
        ):
            items = autostart_svc._docker_autostart_items()
        labels = [i["label"] for i in items]
        self.assertEqual(labels, ["7", "immich_server"])

    def test_docker_stacks_tolerate_non_str_path_and_junk_rows(self):
        stacks = [
            "not-a-stack",
            {"id": ["bad"], "path": ["/not", "a", "path"]},
            {"id": "immich", "path": "/tmp/immich", "running_containers": {"web": 1}},
        ]
        junk = {"containers": ["x", {"id": "immich_server", "project": "immich", "state": "ok"}]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch("hub.containers_svc.list_stacks", return_value=stacks),
                patch("hub.containers_svc.list_containers", return_value=junk),
                patch.object(apps_manage_svc, "SERVICES_ROOT", root),
            ):
                items = apps_manage_svc._docker_stacks()
        ids = [i["id"] for i in items]
        self.assertIn("docker:immich", ids)
        self.assertTrue(all(isinstance(i, dict) for i in items))


class AppsLeftoverTypingTests(unittest.TestCase):
    def test_native_detail_scalar_ports_do_not_500(self):
        from hub import native_catalog

        app = {
            "id": "native-htop", "name": "htop", "ports": 8080,
            "package": "btop", "method": "brew_formula",
        }
        with (
            patch.object(native_catalog, "NATIVE_APPS", [app]),
            patch.object(
                native_catalog, "list_native_apps",
                return_value=["oops", {"id": "native-htop", "running": False}],
            ),
        ):
            detail = apps_manage_svc._native_detail("native-htop")
        self.assertEqual(detail["ports"][0]["target"], 8080)

    def test_native_detail_glob_oserror_does_not_500(self):
        from hub import native_catalog

        app = {
            "id": "native-htop", "name": "htop", "ports": ["8080"],
            "package": "btop", "method": "brew_formula",
        }

        def boom(self, pattern):
            raise PermissionError("nope")

        with (
            patch.object(native_catalog, "NATIVE_APPS", [app]),
            patch.object(
                native_catalog, "list_native_apps",
                return_value=[{"id": "native-htop"}],
            ),
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "glob", boom),
        ):
            detail = apps_manage_svc._native_detail("native-htop")
        self.assertEqual(detail["source_id"], "native-htop")

    def test_native_apps_skip_junk_rows_instead_of_500(self):
        from hub import native_catalog

        with patch.object(
            native_catalog, "list_native_apps",
            return_value=["oops", {"id": "native-x", "installed": True, "name": "X"}],
        ):
            items = apps_manage_svc._native_apps()
        self.assertEqual([i["id"] for i in items], ["native:native-x"])

    def test_launchd_glob_oserror_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        agents = tmp / "LaunchAgents"
        agents.mkdir()

        def boom(self, pattern):
            raise PermissionError("nope")

        with (
            patch("hub.paths.AGENTS_DIR", agents),
            patch.object(Path, "glob", boom),
        ):
            self.assertEqual(apps_manage_svc._launchd_apps(), [])

    def test_docker_detail_and_logs_tolerate_junk_payloads(self):
        with patch("hub.containers_svc.list_containers", return_value=["nope"]):
            detail = apps_manage_svc._docker_detail("immich")
        self.assertEqual(detail["source_id"], "immich")
        self.assertEqual(detail["containers"], [])

        with (
            patch("hub.containers_svc.list_containers", return_value={"containers": 5}),
            patch.object(Path, "exists", return_value=False),
        ):
            logs = apps_manage_svc._docker_logs("immich")
        self.assertIn("log", logs)

    def test_vm_detail_scalar_ips_do_not_500(self):
        with patch(
            "hub.vms_svc.list_all_vms",
            return_value={"vms": [{"id": "u1", "name": "vm", "ips": 1}]},
        ):
            detail = apps_manage_svc._vm_detail("u1")
        self.assertEqual(detail["ips"], [])
        self.assertEqual(detail["networks"], [])


if __name__ == "__main__":
    unittest.main()
