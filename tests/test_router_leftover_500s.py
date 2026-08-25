"""Leftover parse/type 500s on catalog, compose, sensors, apps, SMART, usage.

A scalar AppleLanguages plist, a NUL compose cwd, sysctl payloads that are
already int, a junk logs/history/limit query, and a string model_extra each
used to raise on the request path instead of skipping or clamping.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException

from hub import (
    apps_manage_svc,
    catalog,
    compose_svc,
    sensors_svc,
    smart_test_svc,
    usage_svc,
)
from hub.routers import modules_api


class CatalogLanguagePlistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        catalog._lang_cache = None
        self.addCleanup(setattr, catalog, "_lang_cache", None)

    def _prefs(self, payload) -> Path:
        path = Path(self.tmp.name) / "GlobalPreferences.plist"
        path.write_bytes(plistlib.dumps(payload))
        return path

    def test_scalar_apple_languages_does_not_500(self):
        with mock.patch.object(catalog, "_GLOBAL_PREFS", self._prefs({"AppleLanguages": 3})):
            self.assertEqual(catalog.host_languages(), ("en",))

    def test_string_apple_languages_does_not_500(self):
        with mock.patch.object(
            catalog, "_GLOBAL_PREFS", self._prefs({"AppleLanguages": "en-CN"})
        ):
            self.assertEqual(catalog.host_languages(), ("en",))


class ComposeCwdPathTests(unittest.TestCase):
    def test_nul_cwd_is_invalid_not_500(self):
        out = compose_svc.validate_compose_text("services: {}\n", cwd="/tmp/\x00compose")
        self.assertFalse(out["ok"])
        self.assertIn("working directory", out["message"])

    def test_non_string_cwd_falls_back(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        with (
            mock.patch.object(Path, "home", return_value=tmp),
            mock.patch.object(compose_svc, "run_capped", return_value=(0, "valid")),
        ):
            out = compose_svc.validate_compose_text("services: {}\n", cwd=["/tmp"])
        self.assertTrue(out["ok"])


class ComposePathTypingTests(unittest.TestCase):
    def _code(self, ctx) -> str:
        detail = ctx.exception.detail
        return detail["code"] if isinstance(detail, dict) else str(detail)

    def test_nul_compose_path_is_coded_not_500(self):
        from fastapi import HTTPException

        stack = {
            "id": "x", "name": "x", "path": "/tmp",
            "compose_path": "/tmp/foo\x00.yml",
        }
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.get_compose("x")
        self.assertEqual(self._code(ctx), "container.no_compose_file")
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.save_compose("x", "services: {}\n", validate=False)
        self.assertEqual(self._code(ctx), "container.no_compose_file")

    def test_list_compose_path_is_coded_not_500(self):
        from fastapi import HTTPException

        stack = {
            "id": "x", "name": "x", "path": "/tmp",
            "compose_path": ["/tmp/x.yml"],
        }
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.get_compose("x")
        self.assertEqual(self._code(ctx), "container.no_compose_file")


class CatalogOverviewTypingTests(unittest.TestCase):
    def test_unhashable_category_does_not_500_the_store(self):
        junk = [{"id": "x", "category": ["net"], "kind": ["docker"], "name": "X"}]
        with (
            mock.patch.object(catalog, "list_templates", return_value=junk),
            mock.patch.object(catalog, "fan_out", return_value=(junk, [])),
        ):
            data = catalog.catalog_overview()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["counts"].get("other"), 1)
        self.assertEqual(data["counts"].get("docker"), 1)


class SensorsTypingTests(unittest.TestCase):
    def setUp(self):
        sensors_svc._static.update(t=0.0, ncpu=None, mem_gb=None, page_size=16384)
        self.addCleanup(
            sensors_svc._static.update,
            t=0.0, ncpu=None, mem_gb=None, page_size=16384,
        )

    def test_int_sysctl_payloads_do_not_500(self):
        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, 8, ""
            if last == "hw.memsize":
                return 0, 16 * 2**30, ""
            if last == "hw.pagesize":
                return 0, 16384, ""
            if argv[0].endswith("memory_pressure"):
                return 0, "The system has 12.5% free percentage", ""
            return 1, "", ""

        with (
            mock.patch("hub.macos_sysctl.sysctlbyname_int", return_value=None),
            mock.patch.object(sensors_svc, "sh", side_effect=fake_sh),
        ):
            hw = sensors_svc._static_hw()
            mem = sensors_svc._memory_base()
        self.assertEqual(hw["ncpu"], 8)
        self.assertEqual(hw["mem_total_gb"], 16.0)
        self.assertEqual(mem["mem_free_pct"], 12)

    def test_int_boottime_does_not_500(self):
        with mock.patch.object(sensors_svc, "sh", return_value=(0, 12, "")):
            self.assertEqual(sensors_svc._uptime()["uptime_hours"], 0.0)


class AppsLogsLimitTests(unittest.TestCase):
    def test_junk_lines_is_clamped_not_500(self):
        with mock.patch.object(
            apps_manage_svc, "_docker_logs", return_value={"ok": True, "log": ""}
        ) as logs:
            out = apps_manage_svc.logs("docker:web", lines="nope")
        self.assertTrue(out["ok"])
        self.assertEqual(logs.call_args[0][1], 120)


class SmartHistoryLimitTests(unittest.TestCase):
    def test_junk_limit_does_not_500(self):
        with mock.patch.object(smart_test_svc, "_load_history", return_value=[]):
            self.assertEqual(smart_test_svc.history("nope"), [])
            self.assertEqual(smart_test_svc.history(["50"]), [])
            self.assertEqual(smart_test_svc.history(float("inf")), [])


class UsageLargestLimitTests(unittest.TestCase):
    def test_list_limit_does_not_500(self):
        with (
            mock.patch.object(usage_svc, "_resolve", return_value=Path("/tmp")),
            mock.patch.object(usage_svc, "_walk_parallel", return_value=[]),
        ):
            out = usage_svc.largest_files("/", None, limit=["50"])
        self.assertEqual(out["items"], [])
        self.assertEqual(out["scanned"], 0)


class ComposeExtraFieldsTests(unittest.TestCase):
    def test_string_model_extra_does_not_500(self):
        body = SimpleNamespace(check=True, content="services: {}\n", model_extra="validate")
        with mock.patch.object(
            modules_api.compose_svc, "save_compose", return_value={"ok": True}
        ) as save, mock.patch.object(modules_api.audit, "record"):
            out = modules_api.compose_put("demo", body)
        self.assertTrue(out["ok"])
        save.assert_called_once_with("demo", "services: {}\n", validate=True)


class NasCommonLeftoverTests(unittest.TestCase):
    def test_non_dict_admin_result_is_coded_not_500(self):
        from hub.routers import nas_common

        with self.assertRaises(HTTPException) as ctx:
            nas_common.raise_for_admin_result(None)
        self.assertEqual(ctx.exception.detail["code"], "admin.failed")
        with self.assertRaises(HTTPException) as ctx:
            nas_common.raise_service_error(["nope"], {"bad_device": "smart.bad_device"})
        self.assertEqual(ctx.exception.detail["code"], "admin.failed")

    def test_leftover_inf_ok_payload_does_not_500(self):
        from hub.routers import nas_common

        out = nas_common.raise_for_admin_result({
            "ok": True, "n": float("inf"), "name": "ok\ud800",
        })
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(out["n"])
        self.assertNotIn("\ud800", out["name"])

    def test_leftover_inf_param_key_is_coded_not_500(self):
        from hub.routers import nas_common

        with self.assertRaises(HTTPException) as ctx:
            nas_common.raise_service_error(
                {"ok": False, "error": "bad_device", float("inf"): "x", "device": "disk0"},
                {"bad_device": "smart.bad_device"},
            )
        json.dumps(ctx.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(ctx.exception.detail["code"], "smart.bad_device")


class StoragePageLeftoverTests(unittest.TestCase):
    def test_non_dict_overview_does_not_500(self):
        from hub.routers import storage as storage_router

        with (
            mock.patch.object(
                storage_router.storage_svc, "storage_overview", return_value=["not-a-dict"]
            ),
            mock.patch.object(
                storage_router.disk_power_svc, "list_power_disks", return_value=[]
            ),
            mock.patch.object(storage_router.disk_manage_svc, "overview", return_value={}),
        ):
            out = storage_router.storage()
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(out["power_disks"], [])
        self.assertIn("error", out)

    def test_leftover_surrogate_probe_error_does_not_500(self):
        from hub.routers import storage as storage_router

        with (
            mock.patch.object(
                storage_router.storage_svc, "storage_overview",
                side_effect=RuntimeError("e\ud800"),
            ),
            mock.patch.object(
                storage_router.disk_power_svc, "list_power_disks", return_value=[]
            ),
            mock.patch.object(storage_router.disk_manage_svc, "overview", return_value={}),
        ):
            out = storage_router.storage()
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", out["error"])


class CatalogCredentialLeftoverTests(unittest.TestCase):
    def test_leftover_apply_message_does_not_500(self):
        from hub.routers import catalog as catalog_router

        body = catalog_router.CredentialSaveBody(
            service_id="x", username="u", password="password1", apply_to_service=True,
        )
        with (
            mock.patch.object(catalog_router, "_require_browser_session"),
            mock.patch.object(
                catalog_router.service_credentials, "adapter_for", return_value="generic"
            ),
            mock.patch.object(
                catalog_router.service_credentials, "apply",
                return_value={"ok": True, "message": "ok\ud800"},
            ),
            mock.patch.object(
                catalog_router.service_credentials, "store",
                return_value={"service_id": "x"},
            ),
            # The save is audited; the fake request cannot resolve an
            # identity, and the trail must not collect fixture noise.
            mock.patch.object(catalog_router.audit, "record"),
            mock.patch.object(catalog_router.auth, "request_username",
                              lambda r: "admin"),
            mock.patch.object(catalog_router.auth, "request_client_id",
                              lambda r: "127.0.0.1"),
        ):
            out = catalog_router.save_app_credential(body, SimpleNamespace())
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", out["message"])


class ServicesBulkLeftoverTests(unittest.TestCase):
    def test_leftover_sh_bytes_and_surrogate_do_not_500(self):
        from hub.routers import services_api

        body = services_api.BulkActionBody(ids=["s1", "s2"], action="start")
        with (
            mock.patch.object(
                services_api.actions, "run_action",
                side_effect=[(0, "ok\ud800", ""), (1, b"bytes-out", None)],
            ),
            mock.patch.object(services_api, "invalidate_status"),
            # Keep the bulk-action audit line out of the real trail.
            mock.patch.object(services_api.audit, "record"),
        ):
            out = services_api.services_bulk(body)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", out["results"][0]["message"])
        self.assertEqual(out["results"][1]["message"], "bytes-out")


class NfsPreviewLeftoverTests(unittest.TestCase):
    def test_leftover_raw_and_junk_entries_do_not_500(self):
        from hub.routers import nas_storage

        with mock.patch.object(
            nas_storage.nfs_svc, "read_exports",
            return_value=[{"raw": "ok\ud800"}, "nope", {"raw": 12}],
        ):
            resp = nas_storage.api_nfs_preview()
        body = resp.body
        if isinstance(body, (bytes, bytearray)):
            text = bytes(body).decode("utf-8")
        else:
            text = body.encode("utf-8").decode("utf-8")
        self.assertNotIn("\ud800", text)
        self.assertIn("12", text)


class RouterAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_catalog_as_text_recursing_does_not_500(self):
        from hub.routers import catalog as catalog_router

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(catalog_router._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": catalog_router._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    def test_services_api_as_text_recursing_does_not_500(self):
        from hub.routers import services_api

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(services_api._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": services_api._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    def test_storage_router_as_text_recursing_does_not_500(self):
        from hub.routers import storage as storage_router

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(storage_router._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": storage_router._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
