"""Leftover request-path 500s in status, adaptive, brew, health.

groups_order nested mappings, yaml ``1e999`` ports, a collector that
returns None instead of raising, a NaN brew exit_code, and a health
probe that returns None each used to raise on the request path.

Follow-up: YAML timestamps / cyclic quick_links, leftover inf in
``ports`` / member ``port``, bytes brew action text, nested brew-cache
NaN, and a non-OSError disk_usage each still 500'd the encoder or the
handler.

Second follow-up: ``settings: []`` 500'd ``resource_mode()`` on a cached
GET /api/status. ``int(inf)`` pid 500'd adaptive ``ports_for_pid``.
A check row with leftover bytes / ``inf`` 500'd GET /api/health/checks.
``isoformat()`` returning inf slipped past ``_jsonable``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from hub import adaptive, brew_cache, brew_svc, health_svc, resource_mode, stale_runtime, status

_NESTED_JSON = '{"k":' * 12000 + "1" + "}" * 12000


class StatusBuildLeftoverTests(unittest.TestCase):
    def _build(self, **patches):
        defaults = {
            "discover_launchd": [],
            "discover_containers": ([], True),
            "discover_vms": [],
            "collect_system": {"load1": 0.1},
            "collect_scripts": [],
            "collect_apps": [],
            "cfg": {"settings": {"adaptive": False}},
        }
        defaults.update(patches)
        stack = []
        for name, value in defaults.items():
            if isinstance(value, BaseException):
                stack.append(patch.object(status, name, side_effect=value))
            else:
                stack.append(patch.object(status, name, return_value=value))
        for p in stack:
            p.start()
        try:
            return status._build_status()
        finally:
            for p in reversed(stack):
                p.stop()

    def test_unhashable_groups_order_does_not_500(self):
        data = self._build(
            discover_launchd=[{"id": "a", "name": "a", "state": "ok", "group": "Core"}],
            cfg={
                "settings": {"adaptive": False},
                "groups_order": [{"name": "Core"}, ["Apps"], "Core"],
            },
        )
        ids = [s["id"] for g in data["groups"] for s in g["services"]]
        self.assertIn("a", ids)

    def test_infinite_port_does_not_500(self):
        data = self._build(
            discover_launchd=[{
                "id": "a", "name": "a", "state": "ok", "group": "Core",
                "port": float("inf"),
                "meta": {"detected_ports": [float("inf"), 8086]},
            }],
            cfg={"settings": {"adaptive": True}},
            discover_orphan_listeners=[],
            _adaptive_info={"compose_projects": [], "nginx_sites": []},
        )
        self.assertEqual(data["service_total"], 1)

    def test_collector_none_and_bare_container_list_do_not_500(self):
        data = self._build(
            discover_launchd=None,
            discover_containers=[],
            discover_vms=None,
            collect_scripts=None,
        )
        self.assertEqual(data["service_total"], 0)
        self.assertFalse(data["engine_up"])

    def test_orphan_scan_raise_does_not_500(self):
        data = self._build(
            cfg={"settings": {"adaptive": True}},
            discover_orphan_listeners=RuntimeError("lsof"),
            _adaptive_info={"compose_projects": [], "nginx_sites": []},
        )
        self.assertEqual(data["service_total"], 0)
        self.assertEqual(data["adaptive"]["orphan_count"], 0)

    def test_datetime_quick_links_do_not_500_json(self):
        added = datetime(2024, 1, 1, tzinfo=timezone.utc)
        data = self._build(
            cfg={
                "settings": {"adaptive": False},
                "quick_links": [{"name": "Lab", "url": "http://x", "added": added}],
            },
        )
        self.assertEqual(data["links"][0]["name"], "Lab")
        self.assertIsInstance(data["links"][0]["added"], str)
        json.dumps(data, allow_nan=False)

    def test_cyclic_quick_links_do_not_500(self):
        node = {"name": "loop"}
        node["self"] = node
        data = self._build(
            cfg={"settings": {"adaptive": False}, "quick_links": [node]},
        )
        json.dumps(data, allow_nan=False)
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertTrue(isinstance(data["links"], list))
        if data["links"]:
            self.assertEqual(data["links"][0]["name"], "loop")

    def test_inf_ports_list_does_not_500_json(self):
        """``int(inf)`` was isolated; ``ports: [inf]`` still 500'd the encoder."""
        data = self._build(
            collect_scripts=[{
                "id": "s", "name": "s", "state": "ok", "group": "Custom",
                "ports": [float("inf"), 3000],
            }],
        )
        ports = data["groups"][0]["services"][0]["ports"]
        self.assertIn(3000, ports)
        self.assertNotIn(float("inf"), ports)
        json.dumps(data, allow_nan=False)

    def test_inf_clock_strftime_does_not_500_status(self):
        """Leftover ``time.time() = inf`` OverflowError'd GET /api/status ``ts``."""
        with patch("hub.util.time.strftime", side_effect=OverflowError):
            data = self._build()
        json.dumps(data, allow_nan=False)
        self.assertEqual(data["ts"], "")

    def test_leftover_surrogate_service_name_does_not_500_json(self):
        """YAML ``name: "\\ud800"`` used to 500 GET /api/status at encode time."""
        data = self._build(
            discover_launchd=[{
                "id": "a", "name": "agent\ud800", "state": "ok", "group": "Core",
                "detail": "up\udfff",
            }],
        )
        row = data["groups"][0]["services"][0]
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", row["name"])
        self.assertNotIn("\udfff", row["detail"])


class MemberFilterLeftoverTests(unittest.TestCase):
    def test_unhashable_actions_do_not_500_member_status(self):
        filtered = status.filter_status_for_resources(
            {
                "groups": [{
                    "group": "Media",
                    "services": [{
                        "id": "jellyfin",
                        "state": "ok",
                        "actions": ["open", {"id": "detail"}],
                    }],
                }],
            },
            ["jellyfin"],
        )
        self.assertEqual(filtered["service_total"], 1)
        self.assertEqual(filtered["groups"][0]["services"][0]["actions"], ["open"])

    def test_non_dict_status_does_not_500_member_filter(self):
        filtered = status.filter_status_for_resources(None, ["x"])
        self.assertEqual(filtered["groups"], [])
        self.assertEqual(filtered["service_total"], 0)

    def test_inf_port_and_bytes_name_do_not_500_member_json(self):
        filtered = status.filter_status_for_resources(
            {
                "groups": [{
                    "group": "Media",
                    "services": [{
                        "id": "jellyfin",
                        "name": b"JF",
                        "state": "ok",
                        "port": float("inf"),
                        "actions": ["open"],
                    }],
                }],
            },
            ["jellyfin"],
        )
        row = filtered["groups"][0]["services"][0]
        self.assertEqual(row["name"], "JF")
        self.assertIsNone(row["port"])
        json.dumps(filtered, allow_nan=False)


class BrewNanLeftoverTests(unittest.TestCase):
    def test_nan_exit_code_does_not_500_json(self):
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(
                brew_svc, "brew_services_list",
                return_value=[{
                    "name": "redis", "status": "started",
                    "exit_code": float("nan"), "user": None, "file": None,
                }],
            ),
        ):
            rows = brew_svc.list_services()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["exit_code"])
        json.dumps(rows, allow_nan=False)


class BrewPathEioTests(unittest.TestCase):
    def test_isfile_eio_does_not_500_list(self):
        """Dying-mount ``os.path.isfile(BREW)`` EIO used to 500 GET /api/brew."""
        with patch.object(brew_svc.os.path, "isfile", side_effect=OSError(5, "I/O error")):
            rows = brew_svc.list_services()
        self.assertEqual(rows, [])
        json.dumps(rows, allow_nan=False)

    def test_isfile_eio_is_coded_not_500_action(self):
        from fastapi import HTTPException

        with patch.object(brew_svc.os.path, "isfile", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(HTTPException) as ctx:
                brew_svc.service_action("redis", "stop")
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "brew.not_found")
        self.assertNotEqual(ctx.exception.status_code, 500)

    def test_cache_strips_nonfinite_before_publish(self):
        cleaned = brew_cache._copy_items([
            {"name": "x", "exit_code": float("inf")},
            {"name": "y", "exit_code": float("nan")},
            "nope",
        ])
        self.assertEqual(cleaned[0]["exit_code"], None)
        self.assertEqual(cleaned[1]["exit_code"], None)
        json.dumps(cleaned, allow_nan=False)

    def test_nan_user_and_bytes_file_do_not_500_json(self):
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(
                brew_svc, "brew_services_list",
                return_value=[{
                    "name": "redis", "status": "started",
                    "exit_code": 0, "user": float("nan"), "file": b"/tmp/redis.plist",
                }],
            ),
        ):
            rows = brew_svc.list_services()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["user"])
        self.assertEqual(rows[0]["file"], "/tmp/redis.plist")
        json.dumps(rows, allow_nan=False)

    def test_bytes_action_message_does_not_500_json(self):
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(brew_svc, "run_capped", return_value=(0, b"Stopping redis")),
            patch.object(brew_svc, "invalidate_brew_services"),
            patch.object(brew_svc, "invalidate_status"),
        ):
            out = brew_svc.service_action("redis", "stop")
        self.assertTrue(out["ok"])
        self.assertEqual(out["message"], "Stopping redis")
        json.dumps(out, allow_nan=False)

    def test_cache_strips_nested_nonfinite_and_bytes(self):
        cleaned = brew_cache._copy_items([{
            "name": "x",
            "user": b"a0000",
            "meta": {"n": float("inf"), "raw": b"hi"},
        }])
        self.assertEqual(cleaned[0]["user"], "a0000")
        self.assertIsNone(cleaned[0]["meta"]["n"])
        self.assertEqual(cleaned[0]["meta"]["raw"], "hi")
        json.dumps(cleaned, allow_nan=False)

    def test_surrogate_name_does_not_500_json(self):
        """JSON ``\\ud800`` used to UnicodeEncodeError GET /api/brew/services."""
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(
                brew_svc, "brew_services_list",
                return_value=[{
                    "name": "redis\ud800", "status": "started\ud800",
                    "exit_code": 0, "user": "a\ud800", "file": "/x\ud800",
                }],
            ),
        ):
            rows = brew_svc.list_services()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["id"])
        self.assertNotIn("\ud800", rows[0]["user"])
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_cache_strips_surrogates(self):
        cleaned = brew_cache._copy_items([{"name": "x\ud800", "meta": {"n": "y\ud800"}}])
        self.assertNotIn("\ud800", cleaned[0]["name"])
        self.assertNotIn("\ud800", cleaned[0]["meta"]["n"])
        json.dumps(cleaned, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_surrogate_action_message_does_not_500_json(self):
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(brew_svc, "run_capped", return_value=(0, "Stopping\ud800")),
            patch.object(brew_svc, "invalidate_brew_services"),
            patch.object(brew_svc, "invalidate_status"),
        ):
            out = brew_svc.service_action("redis", "stop")
        self.assertNotIn("\ud800", out["message"])
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_fallback_surrogate_name_does_not_500_json(self):
        """Text-parse leftover ``\\ud800`` used to 500 GET /api/brew/services."""
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(brew_svc, "brew_services_list", return_value=[]),
            patch.object(
                brew_svc, "sh",
                return_value=(0, "Name Status User File\nredis\ud800 started a\ud800 /x\n", ""),
            ),
        ):
            rows = brew_svc.list_services()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["id"])
        self.assertNotIn("\ud800", rows[0]["name"])
        self.assertNotIn("\ud800", rows[0]["user"])
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_action_error_surrogate_does_not_500_json(self):
        """Leftover ``\\ud800`` in a raised brew error used to 500 the action."""
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(brew_svc, "run_capped", side_effect=RuntimeError("fail\ud800")),
        ):
            out = brew_svc.service_action("redis", "stop")
        self.assertFalse(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_deeply_nested_disk_cache_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; brew list used to 500."""
        self.addCleanup(brew_cache.invalidate_brew_services)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            path.write_text("[" + _NESTED_JSON + "]", encoding="utf-8")
            brew_cache.invalidate_brew_services()
            brew_cache._disk_ok = True
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache, "_load", return_value=[{"name": "x"}]),
            ):
                self.assertIsNone(brew_cache._read_disk_file())
                got = brew_cache.brew_services()
        self.assertEqual(got, [{"name": "x"}])
        json.dumps(got, allow_nan=False)

    def test_huge_disk_cache_does_not_oom(self):
        """``read_text()`` of leftover multi-MB brew cache used to OOM GET /api/brew."""
        self.addCleanup(brew_cache.invalidate_brew_services)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            path.write_bytes(b"x" * (2 * 1024 * 1024))
            brew_cache.invalidate_brew_services()
            brew_cache._disk_ok = True
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache, "_load", return_value=[{"name": "x"}]),
            ):
                self.assertIsNone(brew_cache._read_disk_file())
                got = brew_cache.brew_services()
        self.assertEqual(got, [{"name": "x"}])
        json.dumps(got, allow_nan=False)

    def test_deeply_nested_brew_output_does_not_500(self):
        self.assertIsNone(brew_cache._services_from_output(_NESTED_JSON))

    def test_write_disk_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; GET /api/brew used to 500."""
        self.addCleanup(brew_cache.invalidate_brew_services)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew-services.cache.json"
            brew_cache._disk_ok = True
            with (
                patch.object(brew_cache, "_DISK", path),
                patch.object(brew_cache.json, "dumps", side_effect=RecursionError),
            ):
                brew_cache._write_disk([{"name": "redis"}])
            self.assertFalse(path.exists())


class AdaptiveLeftoverTests(unittest.TestCase):
    def tearDown(self):
        adaptive.invalidate_lsof_snapshot()

    def test_known_ports_none_and_inf_row_do_not_500(self):
        rows = [
            None,
            {"proc": "node", "pid": "1", "bind": "*:3000", "port": float("inf")},
            {"proc": "node", "pid": "2", "bind": "*:3001", "port": 3001},
        ]
        with patch.object(adaptive, "lsof_listen_snapshot", return_value=rows):
            items = adaptive.discover_orphan_listeners(None, set())
        ports = {i["meta"]["port"] for i in items}
        self.assertEqual(ports, {3001})

    def test_non_dict_plist_and_lsof_raise_do_not_500(self):
        self.assertEqual(adaptive.ports_from_plist(["not", "a", "dict"]), [])
        self.assertIsNone(adaptive.url_from_plist(None))
        self.assertEqual(adaptive.guess_group("local.foo", None, False), "Native Services")
        adaptive.invalidate_lsof_snapshot()
        with patch.object(adaptive, "sh", side_effect=RuntimeError("spawn")):
            self.assertEqual(adaptive.lsof_listen_snapshot(), [])
            self.assertEqual(adaptive.ports_for_pid(1), [])

    def test_enrich_junk_detail_and_meta_do_not_500(self):
        item = adaptive.enrich_service(
            {"detail": 8086, "state": "ok", "meta": "nope"},
            pl={"ProgramArguments": ["x", "--port", "8086"]},
        )
        self.assertEqual(item["detail"], 8086)
        self.assertIsInstance(item["meta"], dict)
        self.assertEqual(item["meta"]["detected_ports"], [8086])


class HealthLeftoverTests(unittest.TestCase):
    def setUp(self):
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(lambda: health_svc._cache.update(t=0.0, v=None))

    def test_home_runtimeerror_and_none_probe_rows_do_not_500(self):
        with (
            patch.object(health_svc.shutil, "disk_usage", side_effect=OSError("nope")),
            patch.object(
                health_svc, "fan_out",
                return_value=(False, None, None, None, None, None, None, None, None, None, None),
            ),
            patch("pathlib.Path.home", side_effect=RuntimeError("no home")),
            patch.object(health_svc, "_worker_checks", return_value=None),
        ):
            result = health_svc._collect_checks()
        ids = [c["id"] for c in result["checks"] if isinstance(c, dict)]
        self.assertIn("disk_root", ids)
        self.assertIn("backup_dir", ids)
        self.assertIn("orbstack", ids)
        self.assertGreater(result["summary"]["total"], 1)

    def test_disk_usage_runtimeerror_does_not_500(self):
        with (
            patch.object(health_svc.shutil, "disk_usage", side_effect=RuntimeError("vfs")),
            patch.object(
                health_svc, "fan_out",
                return_value=(False, None, None, None, None, None, None, None, None, None, None),
            ),
            patch.object(health_svc, "_worker_checks", return_value=[]),
        ):
            result = health_svc._collect_checks()
        disk = next(c for c in result["checks"] if c["id"] == "disk_root")
        self.assertFalse(disk["ok"])
        self.assertIn("unable to read", disk["detail"])
        json.dumps(result, allow_nan=False)

    def test_bytes_and_inf_check_rows_do_not_500_json(self):
        """A leftover bytes detail / inf field used to 500 GET /api/health/checks."""
        with (
            patch.object(health_svc.shutil, "disk_usage", side_effect=OSError("nope")),
            patch.object(
                health_svc, "fan_out",
                return_value=(
                    False,
                    [{"id": "nginx", "name": "n", "level": "ok", "ok": True,
                      "detail": b"running", "fix": "", "pid": float("inf")}],
                    [], frozenset(), [], [], [], [], [], [], [],
                ),
            ),
            patch.object(health_svc, "_worker_checks", return_value=[]),
        ):
            result = health_svc._collect_checks()
        nginx = next(c for c in result["checks"] if isinstance(c, dict) and c.get("id") == "nginx")
        self.assertEqual(nginx["detail"], "running")
        self.assertIsNone(nginx["pid"])
        json.dumps(result, allow_nan=False)

    def test_none_agents_dir_does_not_500(self):
        with (
            patch.object(health_svc.shutil, "disk_usage", side_effect=OSError("nope")),
            patch.object(
                health_svc, "fan_out",
                return_value=(False, None, None, None, None, None, None, None, None, None, None),
            ),
            patch.object(health_svc, "AGENTS_DIR", None),
            patch.object(health_svc, "_worker_checks", return_value=[]),
        ):
            result = health_svc._collect_checks()
        ids = [c["id"] for c in result["checks"] if isinstance(c, dict)]
        self.assertIn("disk_root", ids)
        self.assertIn("backup_dir", ids)
        json.dumps(result, allow_nan=False)

    def test_cache_leftover_surrogate_and_inf_do_not_500(self):
        """Leftover inf / ``\\ud800`` planted in the cache used to 500 GET /api/health/checks."""
        health_svc._cache.update(t=1e18, v={
            "ts": "now",
            "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
            "checks": [{
                "id": "disk_root", "name": "disk\ud800", "detail": "ok",
                "\ud800": 1, "pid": float("inf"),
            }],
            "healthy": True,
        })
        result = health_svc.run_checks()
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
        row = result["checks"][0]
        self.assertNotIn("\ud800", row["name"])
        self.assertNotIn("\ud800", row)
        self.assertIsNone(row["pid"])

    def test_cache_leftover_inf_payload_does_not_500(self):
        """A leftover inf snapshot used to skip sanitization and 500 the encoder."""
        health_svc._cache.update(t=1e18, v=float("inf"))
        with (
            patch.object(health_svc.shutil, "disk_usage", side_effect=OSError("nope")),
            patch.object(
                health_svc, "fan_out",
                return_value=(False, None, None, None, None, None, None, None, None, None, None),
            ),
            patch.object(health_svc, "_worker_checks", return_value=[]),
        ):
            result = health_svc.run_checks()
        json.dumps(result, allow_nan=False)
        ids = [c["id"] for c in result["checks"] if isinstance(c, dict)]
        self.assertIn("disk_root", ids)


class ResourceModeLeftoverTests(unittest.TestCase):
    def test_non_dict_settings_do_not_500(self):
        for payload in ({"settings": ["high"]}, {"settings": "high"}, {"settings": 1}):
            with patch.object(resource_mode, "cfg", return_value=payload):
                self.assertEqual(resource_mode.resource_mode(), "low")
                self.assertFalse(resource_mode.is_high())

    def test_non_dict_settings_do_not_500_cached_status(self):
        """``_status_ttl`` called ``is_high()`` even on a cache hit."""
        saved = dict(status._status_cache)
        status._status_cache.update(t=1e18, v={"ok": True, "locale": "en"})
        try:
            with patch.object(resource_mode, "cfg", return_value={"settings": ["high"]}):
                data = status.full_status()
            self.assertTrue(data["ok"])
            json.dumps(data, allow_nan=False)
        finally:
            status._status_cache.clear()
            status._status_cache.update(saved)


class AdaptivePidPortLeftoverTests(unittest.TestCase):
    def tearDown(self):
        adaptive.invalidate_lsof_snapshot()

    def test_infinite_pid_does_not_500_ports_for_pid(self):
        self.assertEqual(adaptive.ports_for_pid(float("inf")), [])
        self.assertEqual(adaptive.ports_for_pid(float("nan")), [])

    def test_infinite_port_does_not_500_guess_http_url(self):
        self.assertIsNone(adaptive.guess_http_url(float("inf")))

    def test_leftover_surrogate_orphan_does_not_500_json(self):
        """FUSE leftover ``\\ud800`` in an lsof COMMAND used to 500 GET /api/status."""
        rows = [{
            "proc": "node\ud800", "pid": "1", "bind": "*:3000\ud800", "port": 3000,
        }]
        with patch.object(adaptive, "lsof_listen_snapshot", return_value=rows):
            items = adaptive.discover_orphan_listeners(set(), set())
        json.dumps(items, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertTrue(items)
        self.assertNotIn("\ud800", items[0]["name"])
        self.assertNotIn("\ud800", items[0]["detail"])
        self.assertNotIn("\ud800", items[0]["meta"]["process"])

    def test_leftover_surrogate_plist_url_does_not_500(self):
        """YAML leftover ``URL: "http://x\\ud800"`` used to 500 enrich JSON."""
        url = adaptive.url_from_plist({
            "EnvironmentVariables": {"URL": "http://x\ud800"},
        })
        json.dumps({"url": url}, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNotNone(url)
        self.assertNotIn("\ud800", url)
        item = adaptive.enrich_service(
            {"detail": "Running\ud800", "state": "ok"},
            pl={"EnvironmentVariables": {"URL": "http://x\ud800"}},
        )
        json.dumps(item, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", item["url"])
        self.assertNotIn("\ud800", item["detail"])


class StatusJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_does_not_500_json(self):
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(status._jsonable(_Stamp()))
        json.dumps(status._jsonable({"added": _Stamp()}), allow_nan=False)

    def test_leftover_surrogate_name_does_not_500_json(self):
        """YAML ``name: "\\ud800"`` used to 500 GET /api/status."""
        data = status._jsonable({
            "name": "panel\ud800",
            "\ud800": "x",
            "port": float("inf"),
            "raw": b"ok",
        })
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", data["name"])
        self.assertNotIn("\ud800", data)
        self.assertIsNone(data["port"])
        self.assertEqual(data["raw"], "ok")

    def test_peek_leftover_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` planted in the peek cache used to 500 encode."""
        saved = dict(status._status_cache)
        status._status_cache.update(t=1e18, v={
            "ok": True, "locale": "en", "name": "hub\ud800", "\ud800": 1,
        })
        try:
            hit = status.peek_status()
            json.dumps(hit, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.assertNotIn("\ud800", hit["name"])
            self.assertNotIn("\ud800", hit)
            with patch.object(status, "panel_locale", return_value="en"):
                data = status.full_status()
            json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.assertNotIn("\ud800", data["name"])
        finally:
            status._status_cache.clear()
            status._status_cache.update(saved)

    def test_cached_status_leftover_does_not_500(self):
        """Leftover inf / ``\\ud800`` planted in the cache used to 500 GET /api/health."""
        saved = dict(status._status_cache)
        try:
            status._status_cache.update(t=1e18, v={
                "ok": True, "counts": {"ok\ud800": 1},
                "engine_up": float("inf"), "name": "hub\ud800",
            })
            hit = status.cached_status()
            json.dumps(hit, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.assertNotIn("\ud800", hit["name"])
            self.assertNotIn("\ud800", hit["counts"])
            self.assertIsNone(hit["engine_up"])
            status._status_cache.update(t=1e18, v=float("inf"))
            self.assertIsNone(status.cached_status())
            self.assertIsNone(status.peek_status())
        finally:
            status._status_cache.clear()
            status._status_cache.update(saved)


class StaleRuntimeLeftoverTests(unittest.TestCase):
    def test_none_agents_dir_does_not_500_scan(self):
        with (
            patch.object(stale_runtime, "AGENTS_DIR", None),
            patch.object(stale_runtime, "launchd_listing", return_value=type(
                "L", (), {"pid_for": lambda self, label: None}
            )()),
        ):
            self.assertEqual(stale_runtime.scan(), [])
            self.assertEqual(stale_runtime.health_checks(), [])

    def test_infinite_pid_does_not_500_exe_path(self):
        self.assertIsNone(stale_runtime.pid_exe_path(float("inf")))

    def test_recursing_health_checks_do_not_500(self):
        """str(e) RecursionError used to 500 GET /api/health/checks."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with patch.object(stale_runtime, "health_checks", side_effect=Recursing()):
            rows = health_svc._stale_runtime_checks()
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(rows[0]["detail"], "error")

    def test_recursing_nginx_does_not_500(self):
        """``str(e)`` RecursionError used to 500 GET /api/health/checks nginx row."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with patch.object(health_svc, "nginx_overview", side_effect=Recursing()):
            rows = health_svc._nginx_pair()
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(rows[0]["detail"], "error")


class AdaptiveUtf8TextRecursionLeftoverTests(unittest.TestCase):
    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(adaptive._utf8_text(Recursing()), "Recursing")
        json.dumps(
            {"message": adaptive._utf8_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")


class BrewCacheJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_and_recursing_key_do_not_500(self):
        """Leftover isoformat inf / RecursionError keys used to 500 GET /api/brew/services."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertEqual(brew_cache._as_text(Recursing()), "Recursing")
        self.assertIsNone(brew_cache._json_safe(_Stamp()))
        out = brew_cache._json_safe({
            Recursing(): "ok",
            "when": _Stamp(),
            "name": datetime(2026, 8, 19).date(),
            "blob": b"brew",
            "tags": {"started"},
            "n": float("inf"),
        })
        json.dumps(out, allow_nan=False)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(out["Recursing"], "ok")
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "brew")
        self.assertEqual(out["tags"], ["started"])
        self.assertIsNone(out["n"])

    def test_brew_svc_isoformat_inf_does_not_500(self):
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(brew_svc._json_safe(_Stamp()))
        self.assertEqual(brew_svc._json_safe(datetime(2026, 8, 19).date()), "2026-08-19")
        json.dumps({"user": brew_svc._json_safe(_Stamp())}, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
