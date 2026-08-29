"""Leftover YAML/IO 500s on GET /api/settings, GET /api/modules, and saves.

Hand-edited ``metrics_interval: .inf``, ``username: 2026-08-19``, ``!!binary``
theme, and a ``!!set`` groups_order used to 500 GET /api/settings under
Starlette's ``allow_nan=False`` encoder. The same leftover types in a
registry row 500'd GET /api/modules. A leftover directory occupying
services.yaml / ``.services.yaml.lock``, or EIO copying the file, 500'd
PUT /api/settings. Leftover Infinity in a diagnostics section used to
rewrite onto disk from GET /api/diagnostics.

Follow-up: leftover ``\\ud800`` in a username / stack name / module name /
diagnostics field still 500'd Starlette's UTF-8 encode. Deeply nested YAML
is RecursionError, not YAMLError, and used to 500 cfg() and the export.

Follow-up: leftover ``!!timestamp .inf`` / ``2026-13-01`` / a 5000-digit int
/ ``!!bool 2`` raise TypeError/ValueError/AttributeError/KeyError — not
YAMLError — and used to 500 cfg(). ``Path.read_bytes()`` of leftover
multi-MB services.yaml used to OOM PUT /api/settings during the backup copy.

Follow-up: a >4300-digit leftover *int* (already parsed, so no str->int guard
fires) rode through every Settings-domain sanitizer unchanged and
ValueError'd ``json.dumps`` itself (CPython's int->str digit cap) — a 500 on
GET /api/settings, /api/settings/system, /api/diagnostics, /api/modules,
/api/ups and /api/docker/info after the handler had already succeeded.
"""
from __future__ import annotations

import datetime
import errno
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import config, modules, system_settings_svc
from hub.routers import settings_api


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


NESTED_YAML = "{k: " * 2000 + "1" + "}" * 2000


class PublicSettingsLeftoverTests(unittest.TestCase):
    def _pub(self, data: dict) -> dict:
        with (
            mock.patch.object(settings_api, "cfg", return_value=data),
            mock.patch.object(settings_api, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(settings_api, "configured_host", return_value="auto"),
            mock.patch.object(settings_api, "auth_enabled", return_value=True),
        ):
            return settings_api.get_settings()

    def test_leftover_inf_dates_set_and_binary_do_not_500(self):
        pub = self._pub({
            "settings": {
                "metrics_interval": float("inf"),
                "alert_interval": float("nan"),
                "adaptive": float("inf"),
                "auth": {
                    "username": datetime.date(2026, 8, 19),
                    "password_hash": b"abc",
                },
                "notify": {
                    "notify_resolve": float("inf"),
                    "ha_url": datetime.date(2026, 8, 19),
                    "ha_service": b"notify.notify",
                },
                "ui": {
                    "locale": datetime.date(2026, 8, 19),
                    "theme": b"system",
                    "density": float("inf"),
                },
                "thresholds": {
                    "enabled": float("inf"),
                    "cpu_pct": float("inf"),
                    "mem_pct": float("nan"),
                    "disk_pct": datetime.date(2026, 8, 19),
                    "cooldown_sec": b"1800",
                    "smart_enabled": float("inf"),
                    "smart_temp_c": float("inf"),
                    "smart_wear_pct": float("inf"),
                    "smart_spare_pct": float("inf"),
                },
                "ip_aliases": {
                    float("inf"): 1,
                    "ips": {"10.0.0.2", "10.0.0.3"},
                    "interval": float("inf"),
                    "netmask": datetime.date(2026, 8, 19),
                },
                "ollama": {
                    "url": datetime.date(2026, 8, 19),
                    "label": b"local",
                },
            },
            "stacks": [{
                "id": "s",
                "name": datetime.date(2026, 8, 19),
                "port": float("inf"),
            }],
            "log_sources": [{"id": b"sys", "path": datetime.date(2026, 8, 19)}],
            "groups_order": [
                "Core", datetime.date(2026, 8, 19), float("inf"), b"ops", {"a", "b"},
            ],
        })
        _json(pub)
        self.assertEqual(pub["metrics_interval"], 90)
        self.assertEqual(pub["alert_interval"], 90)
        self.assertIs(pub["adaptive"], True)
        self.assertEqual(pub["auth"]["username"], "2026-08-19")
        self.assertEqual(pub["notify"]["ha_service"], "notify.notify")
        self.assertIs(pub["notify"]["notify_resolve"], True)
        self.assertEqual(pub["ui"]["locale"], "zh-CN")
        self.assertEqual(pub["ui"]["theme"], "system")
        self.assertEqual(pub["ui"]["density"], "compact")
        self.assertEqual(pub["thresholds"]["cpu_pct"], 90)
        self.assertIs(pub["thresholds"]["enabled"], True)
        self.assertEqual(pub["ollama"]["label"], "local")
        self.assertEqual(pub["stacks"][0]["name"], "2026-08-19")
        self.assertIsNone(pub["stacks"][0]["port"])
        self.assertIn("Core", pub["groups_order"])
        self.assertNotIn(float("inf"), pub["groups_order"])

    def test_isoformat_inf_does_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/settings."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(settings_api._jsonable(_Stamp()))
        _json(settings_api._jsonable({"when": _Stamp(), "name": "ok"}))
        pub = self._pub({"stacks": [{"id": "s", "name": _Stamp()}]})
        _json(pub)
        self.assertIsNone(pub["stacks"][0]["name"])

    def test_leftover_surrogate_username_does_not_500(self):
        """A leftover ``\\ud800`` username still 500'd GET /api/settings UTF-8."""
        pub = self._pub({
            "settings": {"auth": {"username": "\ud800"}},
            "stacks": [{"id": "s", "name": "\ud800stack"}],
        })
        _starlette(pub)
        self.assertNotIn("\ud800", pub["auth"]["username"])
        self.assertNotIn("\ud800", pub["stacks"][0]["name"])

    def test_leftover_surrogate_host_ip_does_not_500(self):
        """Patched leftover ``\\ud800`` host_ip still 500'd GET /api/settings UTF-8."""
        with (
            mock.patch.object(settings_api, "cfg", return_value={"settings": {}}),
            mock.patch.object(settings_api, "host_ip", return_value="10.0.0.1\ud800"),
            mock.patch.object(settings_api, "configured_host", return_value="auto\ud800"),
            mock.patch.object(settings_api, "auth_enabled", return_value=True),
        ):
            pub = settings_api.get_settings()
        _starlette(pub)
        self.assertNotIn("\ud800", pub["host_ip"])
        self.assertNotIn("\ud800", pub["host_ip_config"])

    def test_leftover_inf_now_does_not_500_range_metrics(self):
        """``int(time.time())`` OverflowError used to 500 GET /api/metrics?range=."""
        with (
            mock.patch.object(settings_api.time, "time", return_value=float("inf")),
            mock.patch.object(
                settings_api.metrics_rollup, "query_range",
                return_value={"points": [], "tier": "raw"},
            ),
        ):
            body = settings_api.get_metrics(range_="1h", points=50)
        _json(body)
        self.assertEqual(body["points"], [])

    def test_clean_settings_still_round_trip(self):
        pub = self._pub({
            "settings": {
                "metrics_interval": 45,
                "alert_interval": 60,
                "adaptive": False,
                "resource_mode": "high",
                "auth": {"username": "elvin", "password_hash": "x"},
                "ui": {"locale": "en", "theme": "nord", "density": "cozy"},
            },
            "groups_order": ["Core", "Apps"],
        })
        _json(pub)
        self.assertEqual(pub["metrics_interval"], 45)
        self.assertIs(pub["adaptive"], False)
        self.assertEqual(pub["resource_mode"], "high")
        self.assertEqual(pub["auth"]["username"], "elvin")
        self.assertEqual(pub["ui"]["locale"], "en")
        self.assertEqual(pub["groups_order"], ["Core", "Apps"])


class ModuleRegistryYamlLeftoverTests(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)

    def tearDown(self):
        modules.MODULES[:] = self._saved

    def test_leftover_inf_dates_set_and_binary_do_not_500(self):
        modules.MODULES.append({
            "id": b"plugin",
            "name": datetime.date(2026, 8, 19),
            "description": float("inf"),
            "category": "ops",
            "apis": {"/api/x", "/api/y"},
            "ui_routes": (float("inf"), "/x"),
            "inspired_by": b"casaos",
            "enabled": float("inf"),
            float("inf"): "k",
        })
        rows = modules.list_modules()
        by_cat = modules.modules_by_category()
        payload = {"modules": rows, "by_category": by_cat}
        _json(payload)
        row = next(r for r in rows if r.get("id") == "plugin")
        self.assertEqual(row["name"], "2026-08-19")
        self.assertIsNone(row["description"])
        self.assertIs(row["enabled"], True)
        self.assertEqual(sorted(row["apis"]), ["/api/x", "/api/y"])
        self.assertIn("ops", by_cat)

    def test_leftover_surrogate_name_does_not_500(self):
        modules.MODULES.append({
            "id": "plugin",
            "name": "\ud800",
            "description": "ops",
            "category": "ops",
            "apis": ["/api/x"],
            "ui_routes": ["/x"],
        })
        rows = modules.list_modules()
        _starlette({"modules": rows})
        row = next(r for r in rows if r.get("id") == "plugin")
        self.assertNotIn("\ud800", row["name"])

    def test_isoformat_inf_does_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/modules."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(modules._jsonable(_Stamp()))
        _json(modules._jsonable({"when": _Stamp(), "name": "ok"}))


class SystemSettingsDateSetLeftoverTests(unittest.TestCase):
    def test_allow_localhost_inf_does_not_500(self):
        with (
            mock.patch.object(system_settings_svc, "cfg", return_value={"settings": {}}),
            mock.patch.object(
                system_settings_svc, "settings_section",
                return_value={"enabled": True, "username": "admin",
                              "allow_localhost": float("inf")},
            ),
            mock.patch.object(system_settings_svc, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(system_settings_svc, "configured_host", return_value="auto"),
        ):
            data = system_settings_svc.get_management_access()
        _json(data)
        self.assertIs(data["allow_localhost"], True)

    def test_scheduler_date_and_set_do_not_500(self):
        with mock.patch(
            "hub.tools_svc.launchd_timers",
            return_value=[{
                "label": datetime.date(2026, 8, 19),
                "interval": datetime.date(2026, 8, 19),
                "calendar": datetime.date(2026, 8, 19),
                "path": {"a", "b"},
            }],
        ):
            data = system_settings_svc.get_scheduler_summary()
        _json(data)
        self.assertEqual(data["timers"][0]["label"], "2026-08-19")
        self.assertEqual(data["timers"][0]["calendar"], "2026-08-19")
        self.assertIsNone(data["timers"][0]["path"])

    def test_disk_date_and_set_do_not_500(self):
        with mock.patch.object(
            system_settings_svc, "fan_out",
            return_value=[
                {"disksleep": 0},
                ({}, []),
                [{"id": datetime.date(2026, 8, 19), "name": {"x"},
                  "power_state": datetime.date(2026, 8, 19),
                  "size_gb": datetime.date(2026, 8, 19)}],
            ],
        ):
            data = system_settings_svc.get_disk_settings()
        _json(data)
        self.assertEqual(data["power_disks"][0]["id"], "2026-08-19")
        self.assertEqual(data["power_disks"][0]["power_state"], "2026-08-19")
        self.assertIsNone(data["power_disks"][0]["size_gb"])


class ConfigLeftoverDirEioTests(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfg-leftover-"))
        data = root / "data"
        data.mkdir()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.data = data
        self.yaml = root / "services.yaml"
        self.lock = data / ".services.yaml.lock"
        for target, value in (
            ("YAML_PATH", self.yaml),
            ("DATA_DIR", self.data),
            ("_LOCK_PATH", self.lock),
            ("_cfg", {"mtime": None, "data": {}}),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)

    def test_empty_yaml_directory_is_replaced_not_500(self):
        self.yaml.mkdir()
        config.save_full({"settings": {"a": 1}})
        self.assertTrue(self.yaml.is_file())
        self.assertEqual(config.cfg().get("settings", {}).get("a"), 1)

    def test_nonempty_yaml_directory_is_coded_not_500(self):
        self.yaml.mkdir()
        (self.yaml / "nested").write_text("keep")
        with self.assertRaises(HTTPException) as ctx:
            config.save_full({"settings": {"a": 1}})
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "settings.save_failed")
        self.assertTrue(self.yaml.is_dir())
        self.assertEqual((self.yaml / "nested").read_text(), "keep")

    def test_empty_lock_directory_is_replaced_not_500(self):
        self.yaml.write_text("settings: {a: 1}\n")
        self.lock.mkdir()
        config.save_full({"settings": {"a": 2}})
        self.assertTrue(self.lock.is_file())
        self.assertEqual(config.cfg()["settings"]["a"], 2)

    def test_nonempty_lock_directory_falls_back_not_500(self):
        self.yaml.write_text("settings: {a: 1}\n")
        self.lock.mkdir()
        (self.lock / "x").write_text("y")
        config.save_full({"settings": {"a": 3}})
        self.assertEqual(config.cfg()["settings"]["a"], 3)
        self.assertTrue(self.lock.is_dir())

    def test_lock_eio_falls_back_not_500(self):
        self.yaml.write_text("settings: {a: 1}\n")
        real_open = os.open

        def eio_open(path, flags, mode=0o777):
            if str(path) == str(self.lock):
                raise OSError(errno.EIO, "I/O error")
            return real_open(path, flags, mode)

        with mock.patch("os.open", side_effect=eio_open):
            config.save_full({"settings": {"a": 4}})
        self.assertEqual(config.cfg()["settings"]["a"], 4)

    def test_yaml_eio_on_backup_copy_still_saves(self):
        self.yaml.write_text("settings: {a: 1}\n")
        real_read = config.secure_io.read_bytes_capped

        def eio_read(path, max_bytes):
            if Path(path) == self.yaml:
                raise OSError(errno.EIO, "I/O error")
            return real_read(path, max_bytes)

        with mock.patch.object(config.secure_io, "read_bytes_capped", eio_read):
            config.save_full({"settings": {"a": 5}})
        self.assertEqual(config.cfg()["settings"]["a"], 5)

    def test_huge_yaml_backup_copy_does_not_oom_save(self):
        """``Path.read_bytes()`` of leftover multi-MB services.yaml used to OOM PUT /api/settings."""
        self.yaml.write_bytes(b"x" * (2 * 1024 * 1024))
        config.save_full({"settings": {"a": 6}})
        self.assertEqual(config.cfg()["settings"]["a"], 6)
        self.assertLess(self.yaml.stat().st_size, 64 * 1024)

    def test_update_settings_empty_yaml_dir_does_not_500(self):
        self.yaml.mkdir()
        out = config.update_settings({"host_ip": "10.0.0.1"})
        self.assertEqual(out.get("host_ip"), "10.0.0.1")
        self.assertTrue(self.yaml.is_file())

    def test_deeply_nested_yaml_does_not_500_cfg(self):
        """yaml.safe_load RecursionError is not YAMLError; cfg() used to 500 every route."""
        self.yaml.write_text(NESTED_YAML)
        self.assertEqual(config.cfg(), {})
        self.assertEqual(config._read_disk(), {})

    def test_deeply_nested_yaml_is_coded_not_500_export(self):
        """GET /api/export/services-yaml used to RecursionError leftover nested YAML."""
        self.yaml.write_text(NESTED_YAML)
        import hub.paths as paths
        with mock.patch.object(paths, "CONFIG_FILE", self.yaml):
            with self.assertRaises(HTTPException) as ctx:
                settings_api.export_services_yaml()
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "system_settings.export_failed")

    def test_dump_recursion_is_coded_not_500(self):
        """yaml.safe_dump RecursionError used to 500 PUT /api/settings."""
        with mock.patch.object(config.yaml, "safe_dump", side_effect=RecursionError):
            with self.assertRaises(HTTPException) as ctx:
                config._dump({"settings": {"a": 1}})
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "settings.save_failed")

    def test_leftover_timestamp_inf_does_not_500_cfg(self):
        """yaml.safe_load AttributeError on ``!!timestamp .inf`` is not YAMLError."""
        self.yaml.write_text("settings:\n  last_run: !!timestamp .inf\n")
        self.assertEqual(config.cfg(), {})
        self.assertEqual(config._read_disk(), {})

    def test_leftover_invalid_yaml_date_does_not_500_cfg(self):
        """yaml.safe_load ValueError on ``2026-13-01`` is not YAMLError."""
        self.yaml.write_text("settings:\n  last_run: 2026-13-01\n")
        self.assertEqual(config.cfg(), {})
        self.assertEqual(config._read_disk(), {})

    def test_leftover_huge_int_does_not_500_or_wipe_cfg(self):
        """yaml.safe_load ValueError on a 5000-digit int is not YAMLError.

        Degrading to ``{}`` was the old shape: it hid the WHOLE config (auth
        block included, so the panel read "setup required") and the next
        mutate() persisted that wipe.  The capped-int retry keeps every
        sibling and drops only the unrenderable scalar.
        """
        self.yaml.write_text(
            "settings:\n  keep: kept\n  port: " + "9" * 5000 + "\n"
        )
        self.assertEqual(config.cfg()["settings"]["keep"], "kept")
        self.assertIsNone(config.cfg()["settings"]["port"])
        self.assertEqual(config._read_disk()["settings"]["keep"], "kept")
        self.assertIsNone(config._read_disk()["settings"]["port"])

    def test_leftover_bool_tag_does_not_500_cfg(self):
        """yaml.safe_load KeyError on ``!!bool 2`` is not YAMLError."""
        self.yaml.write_text("settings:\n  enabled: !!bool 2\n")
        self.assertEqual(config.cfg(), {})
        self.assertEqual(config._read_disk(), {})

    def test_yaml_safe_load_typeerror_does_not_500_cfg(self):
        """CSafeLoader TypeError is not YAMLError; cfg() used to 500 every route."""
        self.yaml.write_text("settings: {a: 1}\n")
        with mock.patch.object(config.yaml, "safe_load", side_effect=TypeError("a string value is expected")):
            self.assertEqual(config.cfg(), {})
            self.assertEqual(config._read_disk(), {})


class DiagnosticsBundleDumpLeftoverTests(unittest.TestCase):
    def test_persist_diagnostics_drops_leftover_inf(self):
        """``json.dumps`` without allow_nan=False used to rewrite Infinity onto disk."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        with mock.patch.object(system_settings_svc, "DATA_DIR", root):
            path, err = system_settings_svc._persist_diagnostics({
                "health": {"load": float("inf"), "ok": True},
                "when": datetime.date(2026, 8, 19),
                "blob": b"hello",
            })
        self.assertIsNone(err)
        self.assertTrue(path)
        raw = json.loads(Path(path).read_text())
        _json(raw)
        self.assertIsNone(raw["health"]["load"])
        self.assertIs(raw["health"]["ok"], True)
        self.assertEqual(raw["blob"], "hello")
        self.assertTrue(str(raw["when"]).startswith("2026-08-19"))

    def test_collect_diagnostics_leftover_inf_does_not_500(self):
        with (
            mock.patch.object(
                system_settings_svc, "fan_out",
                return_value=[{"health": {"n": float("inf")}, "blob": b"x"}],
            ),
            mock.patch.object(
                system_settings_svc, "_persist_diagnostics",
                return_value=(None, None),
            ),
        ):
            bundle = system_settings_svc.collect_diagnostics()
        _json(bundle)
        self.assertIsNone(bundle["health"]["n"])
        self.assertEqual(bundle["blob"], "x")
        self.assertIsNone(bundle["saved_path"])

    def test_collect_diagnostics_leftover_surrogate_does_not_500(self):
        """A leftover ``\\ud800`` field still 500'd GET /api/diagnostics UTF-8."""
        with (
            mock.patch.object(
                system_settings_svc, "fan_out",
                return_value=[{"health": {"name": "\ud800", "\ud800": True}}],
            ),
            mock.patch.object(
                system_settings_svc, "_persist_diagnostics",
                return_value=(None, None),
            ),
        ):
            bundle = system_settings_svc.collect_diagnostics()
        _starlette(bundle)
        dumped = json.dumps(bundle, ensure_ascii=False)
        self.assertNotIn("\ud800", dumped)

    def test_diagnostics_download_leftover_inf_is_empty_not_500(self):
        """json.dumps without allow_nan=False used to 500 GET /api/diagnostics/download."""
        from hub.routers import unraid_parity

        with mock.patch.object(
            unraid_parity.system_settings_svc,
            "collect_diagnostics",
            return_value={"n": float("inf")},
        ):
            resp = unraid_parity.api_diagnostics_download()
        body = resp.body.decode("utf-8") if isinstance(resp.body, (bytes, bytearray)) else resp.body
        json.dumps(json.loads(body), allow_nan=False)

    def test_leftover_surrogate_atom_and_text_do_not_500(self):
        _starlette({"tz": system_settings_svc._as_text("\ud800zone")})
        _starlette({"name": system_settings_svc._json_atom("\ud800disk")})
        self.assertNotIn("\ud800", system_settings_svc._as_text("\ud800zone"))
        self.assertNotIn("\ud800", system_settings_svc._json_atom("\ud800disk"))

    def test_json_tree_isoformat_inf_and_path_do_not_500(self):
        class _Stamp:
            def isoformat(self):
                return float("inf")

        cleaned = system_settings_svc._json_tree({
            "when": _Stamp(),
            "n": float("inf"),
            "name": "ok\ud800",
            "path": Path("/tmp"),
        })
        _starlette(cleaned)
        self.assertIsNone(cleaned["when"])
        self.assertIsNone(cleaned["n"])
        self.assertNotIn("\ud800", cleaned["name"])
        self.assertIsInstance(cleaned["path"], str)

    def test_bundle_leftover_inf_and_surrogate_do_not_500(self):
        """Leftover identity / alias_auto inf / ``\\ud800`` used to 500 GET /api/settings/system."""
        system_settings_svc.unraid_settings_bundle.invalidate()
        self.addCleanup(system_settings_svc.unraid_settings_bundle.invalidate)
        with (
            mock.patch("hub.identity_svc.get_identity", return_value={
                "hostname": "box\ud800", "n": float("inf"),
            }),
            mock.patch("hub.network_svc.alias_auto_status", return_value={
                "ips": [float("inf")],
            }),
            mock.patch.object(system_settings_svc, "get_share_globals", return_value={}),
            mock.patch.object(system_settings_svc, "get_scheduler_summary", return_value={"timers": []}),
            mock.patch.object(system_settings_svc, "get_vm_settings", return_value={}),
            mock.patch.object(system_settings_svc, "get_datetime_info", return_value={}),
            mock.patch.object(system_settings_svc, "get_power_info", return_value={}),
            mock.patch.object(system_settings_svc, "get_disk_settings", return_value={}),
            mock.patch.object(system_settings_svc, "get_management_access", return_value={
                "host_ip": "10.0.0.1\ud800",
            }),
            mock.patch.object(system_settings_svc, "get_other_settings", return_value={}),
            mock.patch.object(system_settings_svc, "get_thresholds", return_value={}),
        ):
            bundle = system_settings_svc.unraid_settings_bundle(force=True)
        _starlette(bundle)
        self.assertNotIn("\ud800", bundle["identity"]["hostname"])
        self.assertIsNone(bundle["identity"]["n"])
        self.assertIsNone(bundle["alias_auto"]["ips"][0])
        self.assertNotIn("\ud800", bundle["management"]["host_ip"])

    def test_management_leftover_surrogate_host_does_not_500(self):
        with (
            mock.patch.object(system_settings_svc, "cfg", return_value={"settings": {}}),
            mock.patch.object(
                system_settings_svc, "settings_section",
                return_value={"enabled": True, "username": "admin"},
            ),
            mock.patch.object(system_settings_svc, "host_ip", return_value="10.0.0.1\ud800"),
            mock.patch.object(system_settings_svc, "configured_host", return_value="auto\ud800"),
        ):
            data = system_settings_svc.get_management_access()
        _starlette(data)
        self.assertNotIn("\ud800", data["host_ip"])
        self.assertNotIn("\ud800", data["host_ip_config"])
        self.assertNotIn("\ud800", data["nginx_https"])

    def test_bundle_recursing_collector_error_does_not_500(self):
        """``str(e)`` RecursionError used to 500 GET /api/settings/system."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        system_settings_svc.unraid_settings_bundle.invalidate()
        self.addCleanup(system_settings_svc.unraid_settings_bundle.invalidate)
        with (
            mock.patch("hub.identity_svc.get_identity", side_effect=Recursing()),
            mock.patch("hub.network_svc.alias_auto_status", return_value=None),
            mock.patch.object(system_settings_svc, "get_share_globals", return_value={}),
            mock.patch.object(system_settings_svc, "get_scheduler_summary", return_value={"timers": []}),
            mock.patch.object(system_settings_svc, "get_vm_settings", return_value={}),
            mock.patch.object(system_settings_svc, "get_datetime_info", return_value={}),
            mock.patch.object(system_settings_svc, "get_power_info", return_value={}),
            mock.patch.object(system_settings_svc, "get_disk_settings", return_value={}),
            mock.patch.object(system_settings_svc, "get_management_access", return_value={}),
            mock.patch.object(system_settings_svc, "get_other_settings", return_value={}),
            mock.patch.object(system_settings_svc, "get_thresholds", return_value={}),
        ):
            bundle = system_settings_svc.unraid_settings_bundle(force=True)
        _starlette(bundle)
        self.assertEqual(bundle["identity"].get("error"), "Recursing")

    def test_persist_surrogate_save_error_does_not_500(self):
        """``save_error = str(e)`` leftover ``\\ud800`` used to 500 GET /api/diagnostics."""
        class Surrogate(Exception):
            def __str__(self):
                return "disk\ud800"

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with (
            mock.patch.object(system_settings_svc, "DATA_DIR", Path(tmp.name)),
            mock.patch.object(system_settings_svc, "replace_bytes", side_effect=Surrogate()),
        ):
            path, err = system_settings_svc._persist_diagnostics({"ok": True})
        self.assertIsNone(path)
        _starlette({"save_error": err})
        self.assertNotIn("\ud800", err or "")

    def test_diag_host_surrogate_hostname_does_not_500(self):
        """Raw ``platform.node()`` leftover ``\\ud800`` used to 500 GET /api/diagnostics."""
        with (
            mock.patch.object(system_settings_svc.platform, "node", return_value="box\ud800"),
            mock.patch.object(
                system_settings_svc.platform, "python_version", return_value="3.12\ud800",
            ),
            mock.patch("hub.identity_svc.platform_string", return_value="mac\ud800"),
        ):
            host = system_settings_svc._diag_host()
        _starlette(host)
        self.assertNotIn("\ud800", host["hostname"])
        self.assertNotIn("\ud800", host["python"])
        self.assertNotIn("\ud800", host["platform"])

    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(system_settings_svc._utf8_text(Recursing()), "Recursing")
        _starlette({"k": system_settings_svc._utf8_text(Recursing())})


#: Over CPython's default 4300-digit int->str cap: ``str()`` / ``json.dumps``
#: of this raise ValueError.  Built by arithmetic, so no str->int guard fires.
HUGE_INT = 10 ** 5000


class SettingsDomainDigitCapLeftoverTests(unittest.TestCase):
    """A >4300-digit leftover int used to 500 the whole Settings domain."""

    def _pub(self, data: dict) -> dict:
        with (
            mock.patch.object(settings_api, "cfg", return_value=data),
            mock.patch.object(settings_api, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(settings_api, "configured_host", return_value="auto"),
            mock.patch.object(settings_api, "auth_enabled", return_value=True),
        ):
            return settings_api.get_settings()

    def test_settings_jsonable_drops_over_cap_int(self):
        self.assertIsNone(settings_api._jsonable(HUGE_INT))
        _json(settings_api._jsonable({"port": HUGE_INT, "name": "ok"}))
        _json(settings_api._jsonable([HUGE_INT, 1]))
        # An over-cap key cannot be rendered either; the entry is dropped.
        _json(settings_api._jsonable({HUGE_INT: "x", "keep": 1}))

    def test_settings_finite_and_epoch_fall_back(self):
        self.assertEqual(settings_api._finite(HUGE_INT, 90), 90)
        self.assertEqual(settings_api._finite(45, 90), 45)
        self.assertEqual(settings_api._epoch(HUGE_INT, 0), 0)
        self.assertEqual(settings_api._epoch(1724500000, 0), 1724500000)

    def test_public_settings_over_cap_ints_do_not_500(self):
        pub = self._pub({
            "settings": {
                "metrics_interval": HUGE_INT,
                "alert_interval": HUGE_INT,
                "thresholds": {"cpu_pct": HUGE_INT},
                "ip_aliases": {"interval": HUGE_INT},
            },
            "stacks": [{"id": "s", "name": "ok", "port": HUGE_INT}],
            "groups_order": ["Core", HUGE_INT],
        })
        _json(pub)
        _starlette(pub)
        self.assertEqual(pub["metrics_interval"], 90)
        self.assertEqual(pub["alert_interval"], 90)
        self.assertEqual(pub["thresholds"]["cpu_pct"], 90)
        self.assertIsNone(pub["ip_aliases"]["interval"])
        self.assertIsNone(pub["stacks"][0]["port"])
        self.assertIn("Core", pub["groups_order"])
        self.assertNotIn(HUGE_INT, pub["groups_order"])

    def test_system_settings_sanitizers_drop_over_cap_int(self):
        self.assertEqual(system_settings_svc._finite_number(HUGE_INT, 60), 60)
        self.assertIsNone(system_settings_svc._json_atom(HUGE_INT))
        cleaned = system_settings_svc._json_tree({"n": HUGE_INT, "ok": 1})
        _json(cleaned)
        self.assertIsNone(cleaned["n"])
        self.assertEqual(cleaned["ok"], 1)
        # An over-cap key is dropped with its entry.
        _json(system_settings_svc._json_tree({HUGE_INT: True, "keep": 1}))

    def test_scheduler_over_cap_interval_does_not_500(self):
        with mock.patch(
            "hub.tools_svc.launchd_timers",
            return_value=[{"label": "com.job", "interval": HUGE_INT,
                           "calendar": None, "path": "/tmp/p.plist"}],
        ):
            data = system_settings_svc.get_scheduler_summary()
        _json(data)
        self.assertIsNone(data["timers"][0]["interval"])

    def test_disk_over_cap_numbers_do_not_500(self):
        with mock.patch.object(
            system_settings_svc, "fan_out",
            return_value=[
                {"disksleep": HUGE_INT},
                ({}, []),
                [{"id": "disk0", "name": "disk0",
                  "power_state": "active", "size_gb": HUGE_INT}],
            ],
        ):
            data = system_settings_svc.get_disk_settings()
        _json(data)
        self.assertIsNone(data["disksleep_minutes"])
        self.assertIsNone(data["power_disks"][0]["size_gb"])

    def test_other_settings_over_cap_intervals_do_not_500(self):
        with (
            mock.patch.object(system_settings_svc, "cfg", return_value={
                "settings": {"metrics_interval": HUGE_INT,
                             "alert_interval": HUGE_INT},
            }),
            mock.patch.object(
                system_settings_svc, "settings_section",
                return_value={"interval": HUGE_INT, "cpu_pct": HUGE_INT},
            ),
        ):
            data = system_settings_svc.get_other_settings()
        _json(data)
        self.assertEqual(data["metrics_interval"], 90)
        self.assertEqual(data["alert_interval"], 90)
        self.assertEqual(data["ip_aliases"]["interval"], 60)
        self.assertEqual(data["thresholds"]["cpu_pct"], 90)

    def test_persist_diagnostics_drops_over_cap_int(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(system_settings_svc, "DATA_DIR", Path(tmp.name)):
            path, err = system_settings_svc._persist_diagnostics({
                "n": HUGE_INT, "ok": True,
            })
        self.assertIsNone(err)
        raw = json.loads(Path(path).read_text())
        _json(raw)
        self.assertIsNone(raw["n"])
        self.assertIs(raw["ok"], True)


class UpsDockerModulesDigitCapLeftoverTests(unittest.TestCase):
    """Same leftover int on GET /api/ups, /api/docker/info and /api/modules."""

    def test_ups_jsonable_drops_over_cap_int(self):
        from hub import ups_svc

        self.assertIsNone(ups_svc._jsonable(HUGE_INT))
        _json(ups_svc._jsonable({"battery_percent": HUGE_INT, "name": "APC"}))

    def test_ups_settings_over_cap_ints_fall_back(self):
        from hub import ups_svc

        with mock.patch.object(ups_svc, "cfg", return_value={
            "settings": {"ups": {
                "low_battery_pct": HUGE_INT,
                "shutdown": {
                    "trigger_pct": HUGE_INT,
                    "trigger_remaining_min": HUGE_INT,
                    "stop_scripts": [HUGE_INT, "backup-flush"],
                },
            }},
        }):
            out = ups_svc.ups_settings()
        _json(out)
        self.assertEqual(out["low_battery_pct"], 20)
        self.assertIsNone(out["shutdown"]["trigger_pct"])
        self.assertIsNone(out["shutdown"]["trigger_remaining_min"])
        self.assertIn("backup-flush", out["shutdown"]["stop_scripts"])

    def test_ups_status_over_cap_halt_level_does_not_500(self):
        from hub import ups_svc

        with (
            mock.patch.object(ups_svc, "ups_snapshot", return_value={
                "present": True, "kind": "ups", "name": "APC",
                "halt_levels": {"haltlevel": HUGE_INT},
            }),
            mock.patch.object(ups_svc, "ups_settings", return_value={
                "alerts_enabled": True, "low_battery_pct": 20,
            }),
        ):
            body = ups_svc.ups_status()
        _json(body)
        self.assertIsNone(body["halt_levels"]["haltlevel"])
        self.assertEqual(body["name"], "APC")

    def test_ups_policy_state_over_cap_int_does_not_500(self):
        from hub import ups_policy

        cleaned = ups_policy._jsonable({"engaged_at": HUGE_INT, "reason": "pct"})
        _json(cleaned)
        self.assertIsNone(cleaned["engaged_at"])
        self.assertEqual(cleaned["reason"], "pct")

    def test_docker_jsonable_drops_over_cap_int(self):
        from hub.docker_cli import _jsonable as docker_jsonable

        cleaned = docker_jsonable({"NCPU": HUGE_INT, "MemTotal": 8})
        _json(cleaned)
        self.assertIsNone(cleaned["NCPU"])
        self.assertEqual(cleaned["MemTotal"], 8)

    def test_module_row_over_cap_ints_do_not_500(self):
        saved = list(modules.MODULES)
        self.addCleanup(lambda: modules.MODULES.__setitem__(slice(None), saved))
        modules.MODULES.append({
            "id": "plugin",
            "name": HUGE_INT,
            "description": "ops",
            "category": "ops",
            "apis": ["/api/x"],
            "ui_routes": ["/x"],
            "priority": HUGE_INT,
        })
        rows = modules.list_modules()
        _json({"modules": rows, "by_category": modules.modules_by_category()})
        row = next(r for r in rows if r.get("id") == "plugin")
        self.assertIsNone(row["name"])
        self.assertIsNone(row["priority"])


class MaintenanceEnvLeftoverTests(unittest.TestCase):
    def test_recursing_and_surrogate_env_do_not_500(self):
        """leftover ``str(env-item)`` RecursionError / ``\\ud800`` used to 500 jobs."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(config, "cfg", return_value={
            "settings": {
                "maintenance_env": {
                    Recursing(): Recursing(),
                    "PATH": "/bin",
                    "bad\ud800": "x\ud800",
                },
            },
        }):
            env = config.maintenance_env()
        _starlette(env)
        self.assertEqual(env["PATH"], "/bin")
        blob = "".join(env.keys()) + "".join(env.values())
        self.assertNotIn("\ud800", blob)


if __name__ == "__main__":
    unittest.main()
