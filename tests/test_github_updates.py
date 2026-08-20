"""GitHub version check for the Tools → Updates card."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import tools_svc


def _release(**over):
    payload = {
        "tag_name": "v3.10.0",
        "html_url": "https://github.com/elvin-li/ServerHub/releases/tag/v3.10.0",
        "published_at": "2026-08-20T00:00:00Z",
        "body": "notes",
        "name": "ServerHub v3.10.0",
    }
    payload.update(over)
    return payload


class ParseVersionTests(unittest.TestCase):
    def test_v_prefix_and_git_describe(self):
        self.assertEqual(tools_svc.parse_version("v3.9.1"), (3, 9, 1))
        self.assertEqual(tools_svc.parse_version("3.9.1"), (3, 9, 1))
        self.assertEqual(tools_svc.parse_version("v3.9.1-4-gdead"), (3, 9, 1))
        self.assertEqual(tools_svc.parse_version(""), (0,))
        self.assertEqual(tools_svc.parse_version(None), (0,))

    def test_newer_release_compares_as_greater(self):
        self.assertGreater(tools_svc.parse_version("3.10.0"), tools_svc.parse_version("3.9.1"))
        self.assertEqual(tools_svc.parse_version("3.9.1"), tools_svc.parse_version("v3.9.1"))


class GithubLatestTests(unittest.TestCase):
    def setUp(self):
        tools_svc._github_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._github_cache.update, t=0.0, v=None)

    def test_latest_release_newer_than_installed(self):
        with mock.patch.object(tools_svc, "_github_get_json", return_value=_release()):
            with mock.patch.object(tools_svc, "__version__", "3.9.1"):
                snap = tools_svc._github_latest(force=True)
        json.dumps(snap, allow_nan=False)
        self.assertTrue(snap["ok"])
        self.assertTrue(snap["update_available"])
        self.assertEqual(snap["latest"], "3.10.0")
        self.assertTrue(snap["html_url"].startswith("https://github.com/"))

    def test_same_version_is_not_an_update(self):
        with mock.patch.object(
            tools_svc, "_github_get_json",
            return_value=_release(tag_name="v3.9.1"),
        ):
            with mock.patch.object(tools_svc, "__version__", "3.9.1"):
                snap = tools_svc._github_latest(force=True)
        self.assertTrue(snap["ok"])
        self.assertFalse(snap["update_available"])

    def test_404_falls_through_to_tags(self):
        def fake(path):
            if path.endswith("/releases/latest"):
                raise RuntimeError('{"message":"Not Found"}')
            return [{"name": "v3.9.2"}]

        with mock.patch.object(tools_svc, "_github_get_json", side_effect=fake):
            with mock.patch.object(tools_svc, "__version__", "3.9.1"):
                snap = tools_svc._github_latest(force=True)
        self.assertTrue(snap["ok"])
        self.assertEqual(snap["source"], "tag")
        self.assertTrue(snap["update_available"])

    def test_network_error_is_ok_false_not_raised(self):
        with mock.patch.object(
            tools_svc, "_github_get_json",
            side_effect=RuntimeError("timed out"),
        ):
            snap = tools_svc._github_latest(force=True)
        json.dumps(snap, allow_nan=False)
        self.assertFalse(snap["ok"])
        self.assertFalse(snap["update_available"])
        self.assertIn("timed out", snap["error"])

    def test_fetch_false_does_not_open_a_socket(self):
        with mock.patch.object(tools_svc, "_github_get_json") as get:
            snap = tools_svc.github_update_status(fetch=False)
        get.assert_not_called()
        self.assertFalse(snap["ok"])

    def test_hostile_html_url_is_rewritten(self):
        found = tools_svc._release_from_payload(
            _release(html_url="https://evil.example/x"),
            repo="elvin-li/ServerHub",
            source="release",
        )
        self.assertTrue(found["html_url"].startswith("https://github.com/elvin-li/ServerHub/"))

    def test_leftover_json_recursion_is_not_500(self):
        with mock.patch.object(tools_svc, "_github_get_json", side_effect=RuntimeError("invalid github json")):
            snap = tools_svc._github_latest(force=True)
        json.dumps(snap, allow_nan=False)
        self.assertFalse(snap["ok"])


class ApplyUpdateTests(unittest.TestCase):
    def test_confirm_required(self):
        with self.assertRaises(HTTPException) as ctx:
            tools_svc.apply_github_update(confirm=False)
        self.assertEqual(ctx.exception.detail["code"], "tools.confirm_required")

    def test_dirty_tree_is_coded(self):
        with (
            mock.patch.object(tools_svc, "_github_latest", return_value={
                "ok": True, "update_available": True, "tag": "v3.10.0",
                "latest": "3.10.0", "error": "",
            }),
            mock.patch.object(tools_svc, "_checkout_is_git", return_value=True),
            mock.patch.object(tools_svc, "_git_dirty", return_value=True),
        ):
            with self.assertRaises(HTTPException) as ctx:
                tools_svc.apply_github_update(confirm=True)
        self.assertEqual(ctx.exception.detail["code"], "tools.dirty_tree")

    def test_no_update_is_coded(self):
        with mock.patch.object(tools_svc, "_github_latest", return_value={
            "ok": True, "update_available": False, "tag": "v3.9.1",
            "latest": "3.9.1", "error": "",
        }):
            with mock.patch.object(tools_svc, "_checkout_is_git", return_value=True):
                with self.assertRaises(HTTPException) as ctx:
                    tools_svc.apply_github_update(confirm=True)
        self.assertEqual(ctx.exception.detail["code"], "tools.no_update")

    def test_starts_a_maintenance_job_when_clean(self):
        with (
            mock.patch.object(tools_svc, "_github_latest", return_value={
                "ok": True, "update_available": True, "tag": "v3.10.0",
                "latest": "3.10.0", "error": "",
            }),
            mock.patch.object(tools_svc, "_checkout_is_git", return_value=True),
            mock.patch.object(tools_svc, "_git_dirty", return_value=False),
            mock.patch("hub.jobs.start_job") as start,
        ):
            out = tools_svc.apply_github_update(confirm=True)
        json.dumps(out, allow_nan=False)
        self.assertTrue(out["ok"])
        self.assertEqual(out["job_id"], "panel-update")
        start.assert_called_once()
        cmd = start.call_args[0][0]["command"]
        self.assertIn("git fetch --tags origin", cmd)
        self.assertIn("v3.10.0", cmd)
        self.assertIn("install.sh", cmd)
        self.assertNotIn("stash push", cmd)

    def test_stash_flag_stashes_dirty_work_then_installs(self):
        with (
            mock.patch.object(tools_svc, "_github_latest", return_value={
                "ok": True, "update_available": True, "tag": "v3.10.0",
                "latest": "3.10.0", "error": "",
            }),
            mock.patch.object(tools_svc, "_checkout_is_git", return_value=True),
            mock.patch.object(tools_svc, "_git_dirty", return_value=True),
            mock.patch("hub.jobs.start_job") as start,
        ):
            out = tools_svc.apply_github_update(confirm=True, stash=True)
        self.assertTrue(out["stashed"])
        cmd = start.call_args[0][0]["command"]
        self.assertIn("git stash push", cmd)
        self.assertIn("v3.10.0", cmd)


class BrewUpgradeTests(unittest.TestCase):
    def test_confirm_required(self):
        with self.assertRaises(HTTPException) as ctx:
            tools_svc.apply_brew_upgrade(confirm=False)
        self.assertEqual(ctx.exception.detail["code"], "tools.confirm_required")

    def test_busy_is_coded(self):
        with mock.patch.object(tools_svc, "_brew_busy", return_value=True):
            with self.assertRaises(HTTPException) as ctx:
                tools_svc.apply_brew_upgrade(confirm=True)
        self.assertEqual(ctx.exception.detail["code"], "tools.brew_busy")

    def test_starts_brew_upgrade_job(self):
        with (
            mock.patch.object(tools_svc, "_brew_busy", return_value=False),
            mock.patch.object(tools_svc, "BREW", "/opt/homebrew/bin/brew"),
            mock.patch.object(tools_svc.Path, "is_file", return_value=True),
            mock.patch("hub.jobs.start_job") as start,
        ):
            out = tools_svc.apply_brew_upgrade(confirm=True)
        json.dumps(out, allow_nan=False)
        self.assertEqual(out["job_id"], "brew-upgrade")
        start.assert_called_once()
        self.assertIn("upgrade --quiet", start.call_args[0][0]["command"])
