"""PhotosHub status is gated on a real tree and never invents LAN URLs."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import photoshub_svc


class PhotosHubStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-photoshub-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.hub = self.tmp / "PhotosHub"
        self.hub.mkdir()
        (self.hub / "config").mkdir()
        (self.hub / "state").mkdir()
        self.patches = [
            mock.patch.object(photoshub_svc, "HUB", self.hub),
            mock.patch.object(photoshub_svc, "CFG_PATH", self.hub / "config" / "config.json"),
            mock.patch.object(photoshub_svc, "STATE", self.hub / "state"),
            mock.patch.object(photoshub_svc, "BIN_PHOTOCTL", self.hub / "bin" / "photoctl"),
            mock.patch.object(photoshub_svc, "SCRIPTS", self.hub / "scripts"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def _install_photoctl(self):
        bin_dir = self.hub / "bin"
        bin_dir.mkdir()
        (bin_dir / "photoctl").write_text("#!/bin/sh\n", encoding="utf-8")

    def test_missing_tree_is_not_ok(self):
        snap = photoshub_svc.status()
        self.assertFalse(snap["photoshub_ok"])
        self.assertEqual(snap["links"]["immich"], "")
        self.assertEqual(snap["links"]["panel"], "")
        self.assertNotIn("192.168.", json.dumps(snap))

    def test_photoctl_on_disk_is_ok_and_uses_configured_urls(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({
                "immich": {"public_url": "http://immich.example:2283"},
                "panel": {"url": "http://photos.example:8283/"},
            }),
            encoding="utf-8",
        )
        snap = photoshub_svc.status()
        self.assertTrue(snap["photoshub_ok"])
        self.assertEqual(snap["links"]["immich"], "http://immich.example:2283")
        self.assertEqual(snap["links"]["panel"], "http://photos.example:8283/")

    def test_javascript_public_url_is_dropped(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"public_url": "javascript:alert(1)"}}),
            encoding="utf-8",
        )
        snap = photoshub_svc.status()
        self.assertEqual(snap["links"]["immich"], "")

    def test_action_without_tree_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.run_action("sync")
        self.assertEqual(raised.exception.detail["code"], "photoshub.not_installed")

    def test_unknown_action_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.run_action("explode")
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_action")

    def test_people_script_must_exist(self):
        self._install_photoctl()
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.run_action("configure-people")
        self.assertEqual(raised.exception.detail["code"], "photoshub.script_missing")

    def test_run_action_uses_watchdog(self):
        self._install_photoctl()
        with mock.patch.object(photoshub_svc, "run_watchdog", return_value=0) as wd:
            result = photoshub_svc.run_action("doctor")
        self.assertTrue(result["ok"])
        wd.assert_called_once()
        argv = wd.call_args[0][0]
        self.assertEqual(argv[0], str(self.hub / "bin" / "photoctl"))
        self.assertEqual(argv[1], "doctor")

    def test_public_immich_api_url_is_rejected(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"base_url": "https://immich.example.com"}}),
            encoding="utf-8",
        )
        (self.hub / "config" / "immich_api_key").write_text("secret", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc._immich_base()
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_immich_url")

    def test_loopback_immich_url_is_allowed(self):
        self._install_photoctl()
        for url in (
            "http://127.0.0.1:2283",
            "http://[::1]:2283",
            "http://[0:0:0:0:0:0:0:1]:2283",
        ):
            (self.hub / "config" / "config.json").write_text(
                json.dumps({"immich": {"base_url": url}}),
                encoding="utf-8",
            )
            with self.subTest(url=url):
                self.assertEqual(photoshub_svc._immich_base(), url)

    def test_status_does_not_leak_the_home_path(self):
        self._install_photoctl()
        (self.hub / "handbook.md").write_text("notes", encoding="utf-8")
        snap = photoshub_svc.status()
        self.assertEqual(snap["links"]["handbook"], "handbook.md")
        self.assertNotIn(str(self.hub), json.dumps(snap))

    def test_private_lan_immich_url_is_allowed(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"base_url": "http://192.168.1.206:2283"}}),
            encoding="utf-8",
        )
        self.assertEqual(photoshub_svc._immich_base(), "http://192.168.1.206:2283")

    def test_cloud_metadata_immich_url_is_rejected(self):
        self._install_photoctl()
        for url in (
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/latest/meta-data",
            "http://metadata/",
        ):
            (self.hub / "config" / "config.json").write_text(
                json.dumps({"immich": {"base_url": url}}),
                encoding="utf-8",
            )
            with self.subTest(url=url):
                with self.assertRaises(HTTPException) as raised:
                    photoshub_svc._immich_base()
                self.assertEqual(raised.exception.detail["code"], "photoshub.bad_immich_url")

    def test_public_ipv6_immich_url_is_rejected(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"base_url": "http://[2001:4860:4860::8888]:2283"}}),
            encoding="utf-8",
        )
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc._immich_base()
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_immich_url")

    def test_single_label_lan_name_is_allowed(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"base_url": "http://immich:2283"}}),
            encoding="utf-8",
        )
        self.assertEqual(photoshub_svc._immich_base(), "http://immich:2283")

    def test_immich_redirects_are_refused(self):
        from hub.http_guard import NoRedirect

        handler = NoRedirect()
        with self.assertRaises(photoshub_svc._ImmichRedirect):
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://169.254.169.254/",
            )
        self._install_photoctl()
        (self.hub / "config" / "immich_api_key").write_text("secret", encoding="utf-8")
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"base_url": "http://127.0.0.1:2283"}}),
            encoding="utf-8",
        )
        with mock.patch.object(
            photoshub_svc._IMMICH_OPENER, "open",
            side_effect=photoshub_svc._ImmichRedirect("redirect to http://evil/ refused"),
        ):
            with self.assertRaises(HTTPException) as raised:
                photoshub_svc._immich_api("GET", "/api/albums")
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_immich_url")

    def test_pending_rejects_bad_asset_ids(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc._safe_id("../etc/passwd")
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_ids")

    def test_pending_without_tree_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.pending_delete_assets()
        self.assertEqual(raised.exception.detail["code"], "photoshub.not_installed")
