"""PhotosHub status is gated on a real tree and never invents LAN URLs."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date, datetime
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

    def test_array_status_files_do_not_500_the_page(self):
        """A torn write leaving ``[]`` used to raise ``list.get`` on /api/photoshub."""
        self._install_photoctl()
        (self.hub / "state" / "originals_status.json").write_text("[]", encoding="utf-8")
        (self.hub / "state" / "inventory_report.json").write_text('"oops"', encoding="utf-8")
        snap = photoshub_svc.status()
        self.assertTrue(snap["photoshub_ok"])
        self.assertFalse(snap["gates"]["originals_ready"])
        self.assertEqual(photoshub_svc._delete_gated(), True)

    def test_non_finite_status_json_does_not_500_the_page(self):
        """``1e400`` is valid JSON and becomes inf; Starlette refuses to encode it."""
        self._install_photoctl()
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "n": 1e400}', encoding="utf-8",
        )
        (self.hub / "state" / "inventory_report.json").write_text(
            '{"missing_elsewhere": 1e400}', encoding="utf-8",
        )
        (self.hub / "config" / "config.json").write_text(
            '{"gates": {"min_local_original_pct": 1e400}}', encoding="utf-8",
        )
        snap = photoshub_svc.status()
        cfg = photoshub_svc.public_config()
        json.dumps(snap, allow_nan=False)
        json.dumps(cfg, allow_nan=False)
        self.assertEqual(snap["inventory"]["missing_elsewhere"], 0)
        self.assertEqual(cfg["gates"]["min_local_original_pct"], 99.0)
        self.assertTrue(snap["gates"]["originals_ready"])

    def test_inventory_inf_does_not_500(self):
        self.assertEqual(
            photoshub_svc._inventory_public({"missing_elsewhere": float("inf")}),
            {"missing_elsewhere": 0},
        )

    def test_leftover_inf_bytes_and_yaml_dates_do_not_500_config_write(self):
        """``_write_cfg`` used allow_nan=True; inf keys / bytes / dates 500'd PATCH."""
        self._install_photoctl()
        photoshub_svc._write_cfg({
            float("inf"): 1,
            "extra": float("nan"),
            "when": datetime(2026, 8, 19, 12, 0, 0),
            "day": date(2026, 8, 19),
            "blob": b"hello",
            "load": (float("inf"), 1.0),
            "people": {"yuanbao": {"name": "元宝"}},
        })
        stored = json.loads((self.hub / "config" / "config.json").read_text(encoding="utf-8"))
        json.dumps(stored, allow_nan=False)
        self.assertEqual(stored["blob"], "hello")
        self.assertEqual(stored["load"], [None, 1.0])
        self.assertTrue(str(stored["when"]).startswith("2026-08-19"))
        snap = photoshub_svc.public_config()
        json.dumps(snap, allow_nan=False)
        self.assertEqual(snap["people"]["yuanbao"]["name"], "元宝")

    def test_people_leftover_inf_and_bytes_do_not_500(self):
        got = photoshub_svc._people_public({
            "people": {"yuanbao": {"name": float("inf"), "birthday": b"2022-02"}},
        })
        json.dumps(got, allow_nan=False)
        self.assertEqual(got["yuanbao"]["name"], "")
        self.assertEqual(got["yuanbao"]["birthday"], "2022-02")

    def test_non_object_nested_config_does_not_500_the_page(self):
        """``public_config`` already guarded; ``status()`` still did ``or {}``."""
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({
                "immich": [],
                "gates": "nope",
                "bridge": None,
                "panel": ["url"],
                "people": [],
            }),
            encoding="utf-8",
        )
        (self.hub / "config" / "immich_api_key").write_bytes(b"\xff\xfe not utf-8")
        snap = photoshub_svc.status()
        self.assertTrue(snap["photoshub_ok"])
        self.assertEqual(snap["links"]["immich"], "")
        self.assertEqual(snap["links"]["panel"], "")
        self.assertEqual(photoshub_svc.public_config()["immich"]["has_api_key"], False)
        self.assertTrue(photoshub_svc._delete_gated())

    def test_huge_api_key_file_does_not_oom_status(self):
        """``read_text()`` of a leftover multi-MB key file used to OOM GET /api/photoshub."""
        self._install_photoctl()
        (self.hub / "config" / "immich_api_key").write_text("k" * 200_000, encoding="utf-8")
        snap = photoshub_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertLessEqual(len(photoshub_svc._immich_key()), 4096)

    def test_run_action_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 POST /api/photoshub/action."""
        self._install_photoctl()
        with (
            mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")),
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=0),
            mock.patch.object(photoshub_svc, "status", return_value={"ok": True}),
        ):
            out = photoshub_svc.run_action("status")
        json.dumps(out, allow_nan=False)
        self.assertTrue(out["ok"])

    def test_status_inf_clock_isoformat_does_not_500(self):
        """datetime.fromtimestamp OverflowError on leftover inf used to 500 GET /api/photoshub."""
        self._install_photoctl()
        with mock.patch.object(photoshub_svc.time, "time", return_value=float("inf")):
            snap = photoshub_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertIsNone(snap["ts"])

    def test_status_isoformat_inf_does_not_500_ts(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/photoshub ts."""
        self._install_photoctl()
        with mock.patch.object(photoshub_svc, "_iso_now", return_value=float("inf")):
            snap = photoshub_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertIsNone(snap["ts"])

    def test_run_action_inf_clock_isoformat_does_not_500(self):
        """datetime.fromtimestamp OverflowError on leftover inf used to 500 POST /api/photoshub/action."""
        self._install_photoctl()
        with (
            mock.patch.object(photoshub_svc.time, "time", return_value=float("inf")),
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=0),
        ):
            out = photoshub_svc.run_action("status")
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["started"])
        self.assertTrue(out["ok"])

    def test_run_action_isoformat_inf_does_not_500_started(self):
        """A leftover ``isoformat()`` returning inf used to 500 POST /api/photoshub/action."""
        self._install_photoctl()
        with (
            mock.patch.object(photoshub_svc, "_iso_now", return_value=float("inf")),
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=0),
            mock.patch.object(photoshub_svc, "status", return_value={"ok": True}),
        ):
            out = photoshub_svc.run_action("status")
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["started"])

    def test_non_string_album_titles_do_not_500(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {
                "album_pending_delete": ["Pending Delete"],
                "album_yuanbao": 3,
                "album_erbao": {"name": "x"},
            }}),
            encoding="utf-8",
        )
        albums = photoshub_svc.status()["albums"]
        self.assertEqual(albums["pending_delete"], "Pending Delete")
        self.assertEqual(albums["yuanbao"], "")
        self.assertEqual(albums["erbao"], "")
        self.assertEqual(photoshub_svc._pending_album_name(), "Pending Delete")

    def test_pending_assets_skip_non_objects(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"album_pending_delete": "Pending Delete"}}),
            encoding="utf-8",
        )
        (self.hub / "config" / "immich_api_key").write_text("secret", encoding="utf-8")
        with mock.patch.object(
            photoshub_svc, "_immich_api",
            side_effect=[
                [{"albumName": "Pending Delete", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}],
                {"assets": ["oops", {"id": "11111111-2222-3333-4444-555555555555", "type": "IMAGE"}]},
            ],
        ):
            pending = photoshub_svc.pending_delete_assets()
        self.assertEqual(pending["count"], 2)
        self.assertEqual(len(pending["assets"]), 1)
        self.assertEqual(pending["assets"][0]["id"], "11111111-2222-3333-4444-555555555555")

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

    def test_write_cfg_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; PhotosHub save used to 500."""
        dest = self.hub / "config" / "config.json"
        if dest.exists():
            dest.unlink()
        with mock.patch.object(photoshub_svc.json, "dumps", side_effect=RecursionError):
            photoshub_svc._write_cfg({"ok": True})
        self.assertFalse(dest.exists())

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

    def test_chinese_handbook_name_is_surfaced(self):
        self._install_photoctl()
        (self.hub / "手册.md").write_text("notes", encoding="utf-8")
        snap = photoshub_svc.status()
        self.assertEqual(snap["links"]["handbook"], "手册.md")
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
            photoshub_svc, "_immich_open",
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

    def test_public_config_omits_the_api_key(self):
        self._install_photoctl()
        (self.hub / "config" / "immich_api_key").write_text("super-secret\n", encoding="utf-8")
        (self.hub / "config" / "config.json").write_text(
            json.dumps({
                "photos_library": "/Volumes/PhotoVault/Photos Library.photoslibrary",
                "immich": {
                    "base_url": "http://127.0.0.1:2283",
                    "public_url": "http://192.168.1.206:8282",
                    "api_key_file": str(self.hub / "config" / "immich_api_key"),
                    "album_pending_delete": "待删除",
                },
                "people": {"yuanbao": {"name": "元宝", "birthday": "2022-02"}},
            }),
            encoding="utf-8",
        )
        snap = photoshub_svc.public_config()
        blob = json.dumps(snap)
        self.assertTrue(snap["immich"]["has_api_key"])
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("api_key_file", blob)
        self.assertEqual(snap["people"]["yuanbao"]["name"], "元宝")
        self.assertEqual(snap["albums"]["pending_delete"], "待删除")

    def test_update_config_patches_safe_fields_and_keeps_the_rest(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text(
            json.dumps({
                "photos_library": "/Volumes/PhotoVault/Photos Library.photoslibrary",
                "immich": {
                    "base_url": "http://127.0.0.1:2283",
                    "compose_dir": "/Users/a0000/Services/immich",
                    "album_pending_delete": "Pending Delete",
                },
                "gates": {"allow_delete_channel": False},
            }),
            encoding="utf-8",
        )
        snap = photoshub_svc.update_config({
            "people": {"yuanbao": {"name": "元宝", "birthday": "2022-02"}},
            "albums": {"pending_delete": "待删除", "yuanbao": "元宝成长"},
            "immich": {"public_url": "http://192.168.1.206:8282"},
            "panel": {"url": "http://192.168.1.206:8283/"},
        })
        stored = json.loads((self.hub / "config" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["photos_library"], "/Volumes/PhotoVault/Photos Library.photoslibrary")
        self.assertEqual(stored["immich"]["compose_dir"], "/Users/a0000/Services/immich")
        self.assertFalse(stored["gates"]["allow_delete_channel"])
        self.assertEqual(stored["people"]["yuanbao"]["name"], "元宝")
        self.assertEqual(stored["immich"]["album_pending_delete"], "待删除")
        self.assertEqual(snap["panel"]["url"], "http://192.168.1.206:8283/")

    def test_update_config_rejects_a_public_immich_api(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.update_config({"immich": {"base_url": "https://immich.example.com"}})
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_immich_url")

    def test_update_config_rejects_a_bad_birthday(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.update_config({"people": {"yuanbao": {"birthday": "Feb 2022"}}})
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_birthday")

    def test_update_config_rejects_unknown_people(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.update_config({"people": {"cousin": {"name": "x"}}})
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_person")

    def test_update_config_without_tree_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.update_config({"panel": {"url": "http://127.0.0.1:8283/"}})
        self.assertEqual(raised.exception.detail["code"], "photoshub.not_installed")

    def test_broken_config_is_not_overwritten(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text("{not-json", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.update_config({"panel": {"url": "http://127.0.0.1:8283/"}})
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_config")
        self.assertEqual((self.hub / "config" / "config.json").read_text(encoding="utf-8"), "{not-json")

    def test_backup_log_name_is_allowed(self):
        self._install_photoctl()
        (self.hub / "logs").mkdir()
        (self.hub / "logs" / "backup-2026.log").write_text("copied\n", encoding="utf-8")
        snap = photoshub_svc.recent_logs("backup")
        self.assertEqual(snap["lines"], ["copied"])
        self.assertEqual(snap["path"], "logs/backup-2026.log")
        self.assertNotIn(str(self.hub), json.dumps(snap))

    def test_backup_log_tail_does_not_load_the_prefix(self):
        self._install_photoctl()
        (self.hub / "logs").mkdir()
        path = self.hub / "logs" / "backup-2026.log"
        # More than max_bytes of prefix, then a unique last line.
        path.write_bytes(b"OLD\n" + b"x" * 4000 + b"\nTAIL\n")
        from hub.util import tail_file_lines
        lines = tail_file_lines(path, 2, max_bytes=16)
        self.assertEqual(lines[-1], "TAIL")
        self.assertNotIn("OLD", lines)

    def test_pending_missing_album_is_still_gated(self):
        self._install_photoctl()
        with mock.patch.object(photoshub_svc, "_pending_album_id", return_value=None):
            snap = photoshub_svc.pending_delete_assets()
        self.assertTrue(snap["gated"])
        self.assertEqual(snap["count"], 0)
        self.assertEqual(snap["assets"], [])

    def test_unknown_log_name_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.recent_logs("passwd")
        self.assertEqual(raised.exception.detail["code"], "photoshub.bad_log")

    def test_unreadable_log_dir_does_not_500(self):
        self._install_photoctl()

        def boom(self, pattern):
            raise PermissionError("nope")

        with mock.patch.object(Path, "glob", boom):
            snap = photoshub_svc.recent_logs("bridge")
        self.assertEqual(snap["lines"], [])
        self.assertIsNone(snap["path"])

    def test_tree_stat_eio_does_not_500_the_page(self):
        """``Path.is_dir`` EIO used to 500 GET /api/photoshub/status."""
        self._install_photoctl()
        with mock.patch.object(Path, "is_dir", side_effect=OSError(5, "I/O error")):
            snap = photoshub_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertFalse(snap["photoshub_ok"])

    def test_status_json_stat_eio_does_not_500_the_page(self):
        """``originals_status.json`` ``exists()`` EIO used to 500 the PhotosHub page."""
        self._install_photoctl()
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true}', encoding="utf-8",
        )
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            snap = photoshub_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertTrue(snap["photoshub_ok"])
        self.assertFalse(snap["gates"]["originals_ready"])

    def test_handbook_stat_eio_does_not_500_the_page(self):
        self._install_photoctl()
        real_is_file = Path.is_file

        def is_file(self):
            if self.suffix == ".md":
                raise OSError(5, "I/O error")
            return real_is_file(self)

        with mock.patch.object(Path, "is_file", is_file):
            snap = photoshub_svc.status()
        json.dumps(snap, allow_nan=False)
        self.assertTrue(snap["photoshub_ok"])
        self.assertEqual(snap["links"]["handbook"], "")

    def test_log_stat_eio_does_not_500(self):
        """One log file ``exists()`` EIO used to 500 GET /api/photoshub/logs/bridge."""
        self._install_photoctl()
        (self.hub / "logs").mkdir()
        (self.hub / "logs" / "bridge-1.log").write_text("ok\n", encoding="utf-8")
        real_exists = Path.exists

        def exists(self):
            if self.suffix == ".log":
                raise OSError(5, "I/O error")
            return real_exists(self)

        with mock.patch.object(Path, "exists", exists):
            snap = photoshub_svc.recent_logs("bridge")
        self.assertEqual(snap["lines"], [])
        self.assertIsNone(snap["path"])


class PhotosHubThumbnails(PhotosHubStatus):
    """The preview proxy that lets the review grid show pictures.

    The browser must never receive the Immich API key, so these bytes travel
    through the panel; that makes the panel responsible for the size ceiling and
    for refusing anything that is not a raster image.
    """

    ASSET = "0b2f1a3c-4d5e-6f70-8192-a3b4c5d6e7f8"

    def _serve(self, body: bytes, ctype: str):
        """Stand in for the Immich endpoint, honouring the caller's read cap."""
        resp = mock.MagicMock()
        resp.headers = {"Content-Type": ctype}
        resp.read.side_effect = lambda n=None: body[:n] if n else body
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return mock.patch.object(
            photoshub_svc, "_immich_open", return_value=resp
        )

    def _with_key(self):
        (self.hub / "config" / "immich_api_key").write_text("secret-key\n", encoding="utf-8")
        (self.hub / "config" / "config.json").write_text(
            json.dumps({"immich": {"base_url": "http://127.0.0.1:2283"}}), encoding="utf-8"
        )

    def test_thumbnail_is_returned_with_its_content_type(self):
        self._install_photoctl()
        self._with_key()
        with self._serve(b"\xff\xd8\xff\xe0jpegbytes", "image/jpeg; charset=binary") as opener:
            raw, ctype = photoshub_svc.asset_thumbnail(self.ASSET)
        self.assertEqual(raw, b"\xff\xd8\xff\xe0jpegbytes")
        self.assertEqual(ctype, "image/jpeg")
        # The key travels in a header, never in the URL the panel logs.
        request = opener.call_args.args[0]
        self.assertEqual(request.get_header("X-api-key"), "secret-key")
        self.assertNotIn("secret-key", request.full_url)
        self.assertIn(self.ASSET, request.full_url)

    def test_a_bad_asset_id_never_reaches_immich(self):
        self._install_photoctl()
        self._with_key()
        with mock.patch.object(photoshub_svc, "_immich_open") as opener:
            for bad in ("../../etc/passwd", "a" * 100, "id with spaces", ""):
                with self.assertRaises(HTTPException) as raised:
                    photoshub_svc.asset_thumbnail(bad)
                self.assertEqual(raised.exception.detail["code"], "photoshub.bad_ids")
        opener.assert_not_called()

    def test_an_svg_is_refused(self):
        """``image/*`` would admit a script document; the grid only needs raster."""
        self._install_photoctl()
        self._with_key()
        with self._serve(b"<svg onload='alert(1)'/>", "image/svg+xml"):
            with self.assertRaises(HTTPException) as raised:
                photoshub_svc.asset_thumbnail(self.ASSET)
        self.assertEqual(raised.exception.detail["code"], "photoshub.thumb_failed")

    def test_an_oversized_preview_is_refused(self):
        self._install_photoctl()
        self._with_key()
        big = b"x" * (photoshub_svc._THUMB_MAX + 10)
        with self._serve(big, "image/jpeg"):
            with self.assertRaises(HTTPException) as raised:
                photoshub_svc.asset_thumbnail(self.ASSET)
        self.assertEqual(raised.exception.detail["code"], "photoshub.thumb_failed")

    def test_thumbnail_without_a_key_is_coded(self):
        self._install_photoctl()
        (self.hub / "config" / "config.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.asset_thumbnail(self.ASSET)
        self.assertEqual(raised.exception.detail["code"], "photoshub.key_missing")

    def test_thumbnail_without_the_tree_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            photoshub_svc.asset_thumbnail(self.ASSET)
        self.assertEqual(raised.exception.detail["code"], "photoshub.not_installed")

    def test_immich_json_is_capped(self):
        self._install_photoctl()
        self._with_key()
        huge = b"[" + b"0," * (photoshub_svc._API_MAX) + b"0]"
        with self._serve(huge, "application/json"):
            with self.assertRaises(HTTPException) as raised:
                photoshub_svc._immich_api("GET", "/api/albums")
        self.assertEqual(raised.exception.detail["code"], "photoshub.immich_response")

    def test_immich_nested_json_does_not_500(self):
        """json.loads RecursionError is not JSONDecodeError; leftover nested
        Immich JSON used to 500 GET /api/photoshub/pending-delete."""
        self._install_photoctl()
        self._with_key()
        with self._serve(b'{"ok": true}', "application/json"):
            with mock.patch.object(
                photoshub_svc.json, "loads", side_effect=RecursionError,
            ):
                with self.assertRaises(HTTPException) as raised:
                    photoshub_svc._immich_api("GET", "/api/albums")
        self.assertEqual(raised.exception.detail["code"], "photoshub.immich_response")

    def test_immich_body_leftover_inf_does_not_500(self):
        """``json.dumps(body)`` without allow_nan=False used to send Infinity to Immich."""
        self._install_photoctl()
        self._with_key()
        captured = []

        class _Resp:
            def read(self, n):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_open(req, timeout=None):
            captured.append(req.data)
            return _Resp()

        with mock.patch.object(photoshub_svc, "_immich_open", side_effect=fake_open):
            photoshub_svc._immich_api("DELETE", "/api/albums/x/assets", {
                "ids": ["ok"],
                "n": float("inf"),
                "blob": b"hello",
            })
        raw = json.loads(captured[0])
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["ids"], ["ok"])
        self.assertIsNone(raw["n"])
        self.assertEqual(raw["blob"], "hello")

    def test_immich_body_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not ValueError; leftover nested Immich body used to 500."""
        self._install_photoctl()
        self._with_key()
        with mock.patch.object(photoshub_svc.json, "dumps", side_effect=RecursionError):
            with self.assertRaises(HTTPException) as raised:
                photoshub_svc._immich_api("DELETE", "/api/albums/x/assets", {"ids": ["ok"]})
        self.assertEqual(raised.exception.detail["code"], "photoshub.immich_response")

    def test_every_thumb_failure_code_is_registered(self):
        """A code the SPA cannot translate surfaces as a bare identifier."""
        from hub import errors

        self.assertIn("photoshub.thumb_failed", errors.CODES)
        self.assertEqual(errors.CODES["photoshub.thumb_failed"][0], 502)


class PhotosHubThumbnailRoute(unittest.TestCase):
    """The preview endpoint itself.

    ``asset_thumbnail()`` existed for a while with no route in front of it, so
    the review grid had nothing to show and the only way to judge a photo was
    its filename.  These assert the wiring, not just the helper.
    """

    def test_the_route_is_registered_for_get(self):
        from hub.routers import photoshub_api

        routes = {
            (getattr(r, "path", ""), tuple(sorted(getattr(r, "methods", ()) or ())))
            for r in photoshub_api.router.routes
        }
        self.assertIn(
            ("/api/photoshub/pending-delete/thumb/{asset_id}", ("GET",)), routes
        )

    def test_it_returns_the_bytes_with_hardening_headers(self):
        from hub.routers import photoshub_api

        with mock.patch.object(
            photoshub_api.photoshub_svc,
            "asset_thumbnail",
            return_value=(b"\xff\xd8jpeg", "image/jpeg"),
        ):
            resp = photoshub_api.pending_delete_thumb("abc-123")
        self.assertEqual(resp.body, b"\xff\xd8jpeg")
        self.assertEqual(resp.media_type, "image/jpeg")
        self.assertEqual(resp.headers["x-content-type-options"], "nosniff")
        self.assertIn("private", resp.headers["cache-control"])
        self.assertIn("default-src 'none'", resp.headers["content-security-policy"])

    def test_a_coded_refusal_is_passed_through_untouched(self):
        """The 404/502 distinction is the SPA's cue; it must not become a 500."""
        from hub.errors import api_error
        from hub.routers import photoshub_api

        with mock.patch.object(
            photoshub_api.photoshub_svc,
            "asset_thumbnail",
            side_effect=api_error("photoshub.not_installed"),
        ):
            with self.assertRaises(HTTPException) as raised:
                photoshub_api.pending_delete_thumb("abc-123")
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.detail["code"], "photoshub.not_installed")

    def test_an_unexpected_error_becomes_a_coded_thumb_failure(self):
        from hub.routers import photoshub_api

        with mock.patch.object(
            photoshub_api.photoshub_svc,
            "asset_thumbnail",
            side_effect=OSError("connection reset"),
        ):
            with self.assertRaises(HTTPException) as raised:
                photoshub_api.pending_delete_thumb("abc-123")
        self.assertEqual(raised.exception.status_code, 502)
        self.assertEqual(raised.exception.detail["code"], "photoshub.thumb_failed")


class PhotosHubAlbumJson(unittest.TestCase):
    def test_pending_album_id_tolerates_an_object_payload(self):
        with mock.patch.object(
            photoshub_svc, "_immich_api", return_value={"error": "nope"}
        ):
            self.assertIsNone(photoshub_svc._pending_album_id("Pending Delete"))

    def test_pending_assets_tolerates_a_list_detail(self):
        with mock.patch.object(photoshub_svc, "installed", return_value=True), \
             mock.patch.object(photoshub_svc, "_pending_album_id", return_value="a" * 32), \
             mock.patch.object(photoshub_svc, "_immich_api", return_value=["not", "an", "object"]), \
             mock.patch.object(photoshub_svc, "_delete_gated", return_value=False):
            got = photoshub_svc.pending_delete_assets()
        self.assertEqual(got["assets"], [])
        self.assertEqual(got["count"], 0)

    def test_infinite_asset_fields_do_not_500(self):
        """Immich JSON ``1e400`` used to 500 GET /api/photoshub/pending-delete."""
        with mock.patch.object(photoshub_svc, "installed", return_value=True), \
             mock.patch.object(photoshub_svc, "_pending_album_id", return_value="a" * 32), \
             mock.patch.object(photoshub_svc, "_immich_api", return_value={
                 "assets": [{
                     "id": "11111111-2222-3333-4444-555555555555",
                     "originalFileName": float("inf"),
                     "localDateTime": float("nan"),
                     "isArchived": float("inf"),
                     "type": "IMAGE",
                     "thumbHash": float("inf"),
                 }],
             }), \
             mock.patch.object(photoshub_svc, "_delete_gated", return_value=False):
            got = photoshub_svc.pending_delete_assets()
        json.dumps(got, allow_nan=False)
        self.assertEqual(got["count"], 1)
        self.assertEqual(got["assets"][0]["id"], "11111111-2222-3333-4444-555555555555")

    def test_pending_bytes_and_yaml_dates_do_not_500(self):
        """``_jsonable`` used to walk dict/list/float only; Immich leftovers leaked."""
        when = datetime(2026, 8, 19, 12, 0, 0)
        with mock.patch.object(photoshub_svc, "installed", return_value=True), \
             mock.patch.object(photoshub_svc, "_pending_album_id", return_value="a" * 32), \
             mock.patch.object(photoshub_svc, "_immich_api", return_value={
                 "assets": [{
                     "id": "11111111-2222-3333-4444-555555555555",
                     "originalFileName": b"x.jpg",
                     "localDateTime": when,
                     "type": b"IMAGE",
                     "thumbHash": b"abcd",
                 }],
             }), \
             mock.patch.object(photoshub_svc, "_delete_gated", return_value=False):
            got = photoshub_svc.pending_delete_assets()
        json.dumps(got, allow_nan=False)
        asset = got["assets"][0]
        self.assertEqual(asset["originalFileName"], "x.jpg")
        self.assertEqual(asset["localDateTime"], when.isoformat())
        self.assertEqual(asset["type"], "IMAGE")

    def test_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/photoshub."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(photoshub_svc._jsonable(_Stamp()))
        out = photoshub_svc._jsonable({"localDateTime": _Stamp(), "id": "ok"})
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["localDateTime"])
        self.assertEqual(out["id"], "ok")
