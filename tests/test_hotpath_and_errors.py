"""Hot-path pools, coded errors, and auth cache headers added in the opt pass."""
from __future__ import annotations

import json
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub.errors import CODES, api_error, exc_detail
from hub.power_svc import power_action
from hub.util import LazyPool, strftime_now
from hub import jobs, metrics, sensors_svc, status, util as hub_util


class TestLazyPool(unittest.TestCase):
    def test_reuses_the_same_executor_until_shutdown(self):
        pool = LazyPool(2, "test-lazy")
        try:
            first = pool._executor()
            self.assertIs(pool._executor(), first)
            pool.shutdown()
            second = pool._executor()
            self.assertIsNot(second, first)
        finally:
            pool.shutdown()

    def test_submit_after_executor_shutdown_runs_inline(self):
        """``ThreadPoolExecutor.submit`` RuntimeError used to 500 GET /api/status."""
        pool = LazyPool(1, "test-lazy-inline")
        try:
            pool._executor().shutdown(wait=True)
            self.assertEqual(pool.submit(lambda: 7).result(), 7)
        finally:
            pool.shutdown()

    def test_map_after_executor_shutdown_runs_inline(self):
        pool = LazyPool(1, "test-lazy-map")
        try:
            pool._executor().shutdown(wait=True)
            self.assertEqual(list(pool.map(lambda x: x + 1, [1, 2])), [2, 3])
        finally:
            pool.shutdown()


class TestStatusPeek(unittest.TestCase):
    def test_peek_does_not_build(self):
        saved = dict(status._status_cache)
        try:
            status._status_cache.update(t=0.0, v=None)
            with patch.object(status, "_build_status", side_effect=AssertionError("built")):
                self.assertIsNone(status.peek_status())
            status._status_cache.update(t=1.0, v={"ok": True})
            with patch.object(status, "_build_status", side_effect=AssertionError("built")):
                self.assertEqual(status.peek_status(), {"ok": True})
        finally:
            status._status_cache.clear()
            status._status_cache.update(saved)


class TestStatusFanoutIsolation(unittest.TestCase):
    def test_one_collector_raise_does_not_empty_status(self):
        with (
            patch.object(status, "discover_launchd", side_effect=RuntimeError("boom")),
            patch.object(status, "discover_containers", return_value=([], True)),
            patch.object(status, "discover_vms", return_value=[]),
            patch.object(status, "collect_system", return_value={"load1": 0.2}),
            patch.object(status, "collect_scripts", return_value=[]),
            patch.object(status, "collect_apps", return_value=[]),
            patch.object(status, "cfg", return_value={"settings": {"adaptive": False}}),
        ):
            data = status._build_status()
        self.assertEqual(data["system"]["load1"], 0.2)
        self.assertEqual(data["engine_up"], True)
        self.assertEqual(data["service_total"], 0)

    def test_adaptive_scan_raise_does_not_empty_status(self):
        status._adaptive_cache.update(t=0.0, compose=None, nginx=None)
        with (
            patch.object(status, "scan_new_compose_projects", return_value=[{"id": "x"}]),
            patch.object(status, "nginx_sites", side_effect=RuntimeError("bad conf")),
        ):
            info = status._adaptive_info()
        self.assertEqual(info["compose_projects"], [{"id": "x"}])
        self.assertEqual(info["nginx_sites"], [])

    def test_junk_rows_and_unhashable_state_do_not_500_status(self):
        """Grouping skipped non-dicts; problems/.get and counts[state] still 500'd."""
        with (
            patch.object(status, "discover_launchd", return_value=[
                "not-a-row",
                {"id": "ok-svc", "name": "ok", "state": "ok", "group": "Core"},
                {"id": "weird", "name": "weird", "state": ["down"], "group": "Core"},
            ]),
            patch.object(status, "discover_containers", return_value=([], True)),
            patch.object(status, "discover_vms", return_value=[]),
            patch.object(status, "collect_system", return_value={"load1": 0.1}),
            patch.object(status, "collect_scripts", return_value=[]),
            patch.object(status, "collect_apps", return_value=[]),
            patch.object(status, "cfg", return_value={"settings": {"adaptive": False}}),
        ):
            data = status._build_status()
        self.assertEqual(data["system"]["load1"], 0.1)
        ids = [s["id"] for g in data["groups"] for s in g["services"]]
        self.assertIn("ok-svc", ids)
        self.assertIn("weird", ids)
        self.assertTrue(all(isinstance(p, dict) for p in data["problems"]))
        self.assertIn("unknown", data["counts"])


class TestMetricsSampleReadsSensorsOnce(unittest.TestCase):
    def test_sample_reuses_a_warm_full_snapshot(self):
        warm = {
            "cpu_used_pct": 12.5,
            "network": {"rx_bps": 1, "tx_bps": 2},
            "memory": {"pressure_used_pct": 40, "pressure_free_pct": 60},
        }
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=warm),
            patch("hub.sensors_svc.collect_light", side_effect=AssertionError("light")),
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        self.assertEqual(sample["cpu_used_pct"], 12.5)
        self.assertEqual(sample["net_rx_bps"], 1)
        self.assertIsNone(sample["gpu_util_pct"])

    def test_sample_uses_light_sensors_when_the_cache_is_cold(self):
        light = {
            "cpu_used_pct": 8.0,
            "network": {},
            "memory": {"pressure_used_pct": 33, "pressure_free_pct": 67},
        }
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=None),
            patch("hub.sensors_svc.collect_light", return_value=light),
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        self.assertEqual(sample["cpu_used_pct"], 8.0)
        self.assertIsNone(sample["net_rx_bps"])

    def test_huge_cpu_used_pct_does_not_500_sample(self):
        """``float(10**400)`` OverflowError is not ValueError."""
        warm = {
            "cpu_used_pct": 10 ** 400,
            "network": {},
            "memory": {},
        }
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=warm),
            patch("hub.sensors_svc.collect_light", side_effect=AssertionError("light")),
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        json.dumps(sample, allow_nan=False)
        self.assertNotEqual(sample["cpu_used_pct"], 10 ** 400)

    def test_sample_records_finite_gpu_util_pct(self):
        warm = {
            "cpu_used_pct": 12.5,
            "network": {},
            "memory": {"pressure_used_pct": 40, "pressure_free_pct": 60},
            "gpu": {"util_pct": 71.2},
        }
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=warm),
            patch("hub.sensors_svc.collect_light", side_effect=AssertionError("light")),
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        self.assertEqual(sample["gpu_util_pct"], 71.2)

    def test_sample_gpu_util_pct_null_when_non_finite(self):
        warm = {
            "cpu_used_pct": 1.0,
            "network": {},
            "memory": {},
            "gpu": {"util_pct": float("nan")},
        }
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=warm),
            patch("hub.sensors_svc.collect_light", side_effect=AssertionError("light")),
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        self.assertIsNone(sample["gpu_util_pct"])


class TestSensorsStayOffTheIdlePath(unittest.TestCase):
    def test_peek_is_none_when_the_cache_is_empty(self):
        saved = dict(sensors_svc._cache)
        try:
            sensors_svc._cache.update(t=0.0, v=None)
            self.assertIsNone(sensors_svc.peek_sensors())
        finally:
            sensors_svc._cache.update(saved)

    def test_light_collect_does_not_spawn_top(self):
        with patch.object(sensors_svc, "_cpu_and_mem_from_top", side_effect=AssertionError("top")):
            with patch.object(sensors_svc, "_memory_base", return_value={
                "ncpu": 8, "load1": 0.2, "load5": 0.2, "load15": 0.2,
                "mem_free_pct": 55, "mem_total_gb": 32.0,
            }):
                with patch.object(sensors_svc, "_cpu_from_ticks", return_value={
                    "user": 5.0, "sys": 2.0, "idle": 93.0, "used_pct": 7.0,
                }):
                    snap = sensors_svc.collect_light()
        self.assertTrue(snap.get("light"))
        self.assertEqual(snap["cpu_used_pct"], 7.0)
        self.assertEqual(snap["top_processes"], [])

    def test_tick_wrap_does_not_report_over_100(self):
        saved = sensors_svc._cpu_ticks_prev
        try:
            sensors_svc._cpu_ticks_prev = [100, 50, 200, 0]
            with patch.object(sensors_svc, "_read_cpu_ticks", return_value=[10, 5, 20, 0]):
                self.assertIsNone(sensors_svc._cpu_from_ticks())
        finally:
            sensors_svc._cpu_ticks_prev = saved

    def test_light_api_skips_full_collect(self):
        from hub.routers.modules_api import sensors

        with (
            patch.object(sensors_svc, "peek_sensors", return_value=None),
            patch.object(sensors_svc, "collect_light", return_value={"light": True, "cpu_used_pct": 4.0}),
            patch.object(sensors_svc, "collect_sensors", side_effect=AssertionError("full")),
        ):
            out = sensors(force=False, light=True)
        self.assertTrue(out.get("light"))
        self.assertEqual(out["cpu_used_pct"], 4.0)

    def test_top_is_reused_inside_its_ttl(self):
        calls = []

        def fake_top():
            calls.append(1)
            return {"mem_used_gb": 10.0}

        saved = dict(sensors_svc._top_cache)
        try:
            sensors_svc._top_cache.update(t=0.0, v=None)
            with patch.object(sensors_svc, "_cpu_and_mem_from_top", fake_top):
                a = sensors_svc._cpu_and_mem_from_top_cached()
                b = sensors_svc._cpu_and_mem_from_top_cached()
            self.assertEqual(calls, [1])
            self.assertEqual(a, b)
        finally:
            sensors_svc._top_cache.update(saved)


class TestCodedErrors(unittest.TestCase):
    def test_second_maintenance_job_is_a_coded_conflict(self):
        jobs._jobs.clear()
        jobs._jobs["keeper"] = {
            "running": True, "rc": None, "log": [],
            "started": "00:00:00", "finished": None,
        }
        try:
            with self.assertRaises(HTTPException) as raised:
                jobs.start_job({"id": "other", "command": "true", "timeout": 5})
            self.assertEqual(raised.exception.status_code, 409)
            self.assertEqual(raised.exception.detail["code"], "jobs.already_running")
        finally:
            jobs._jobs.clear()

    def test_unknown_power_action_is_coded(self):
        with self.assertRaises(HTTPException) as raised:
            power_action("explode", confirm=True)
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail["code"], "power.unknown_action")

    def test_power_requires_confirm(self):
        with self.assertRaises(HTTPException) as raised:
            power_action("sleep", confirm=False)
        self.assertEqual(raised.exception.detail["code"], "power.confirm_required")

    def test_leftover_inf_delay_does_not_sleep_forever(self):
        """The response used to clamp inf *after* ``time.sleep(delay_sec)``."""
        from hub import power_svc as pwr

        slept = []

        class _InlineThread:
            def __init__(self, target=None, **kwargs):
                self._target = target

            def start(self):
                self._target()

        with (
            patch.object(pwr.threading, "Thread", _InlineThread),
            patch.object(pwr, "_do_power"),
            patch.object(pwr.time, "sleep", side_effect=lambda s: slept.append(s)),
        ):
            out = pwr.power_action("sleep", confirm=True, delay_sec=float("inf"))
        self.assertEqual(out["scheduled_in_sec"], 2.0)
        self.assertEqual(slept, [2.0])
        json.dumps(out, allow_nan=False)

    def test_leftover_inf_clock_strftime_is_empty_not_500(self):
        """``time.strftime`` OverflowError on leftover inf clock used to 500 GET /api/status."""
        with patch.object(hub_util.time, "strftime", side_effect=OverflowError):
            self.assertEqual(strftime_now("%H:%M:%S"), "")
            self.assertEqual(strftime_now("%Y-%m-%d %H:%M:%S"), "")

    def test_cli_invalid_value_is_coded(self):
        from hub import cli_args

        with self.assertRaises(HTTPException) as raised:
            cli_args.require_positional("--all", label="name")
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail["code"], "cli.invalid_value")

    def test_settings_and_metrics_rejects_are_coded(self):
        from hub.routers.settings_api import (
            SettingsPatch, UiPatch, get_metrics, put_settings,
        )

        with self.assertRaises(HTTPException) as raised:
            put_settings(SettingsPatch(ui=UiPatch(locale="xx")))
        self.assertEqual(raised.exception.detail["code"], "settings.invalid_locale")

        with self.assertRaises(HTTPException) as raised:
            put_settings(SettingsPatch(ui=UiPatch(theme="neon")))
        self.assertEqual(raised.exception.detail["code"], "settings.invalid_theme")

        with self.assertRaises(HTTPException) as raised:
            put_settings(SettingsPatch(ui=UiPatch(density="huge")))
        self.assertEqual(raised.exception.detail["code"], "settings.invalid_density")

        with self.assertRaises(HTTPException) as raised:
            put_settings(SettingsPatch(resource_mode="turbo"))
        self.assertEqual(raised.exception.detail["code"], "settings.invalid_resource_mode")

        with self.assertRaises(HTTPException) as raised:
            put_settings(SettingsPatch())
        self.assertEqual(raised.exception.detail["code"], "settings.empty_patch")

        with self.assertRaises(HTTPException) as raised:
            get_metrics(since=100, until=50)
        self.assertEqual(raised.exception.detail["code"], "metrics.bad_window")

        with self.assertRaises(HTTPException) as raised:
            get_metrics(range_="forever")
        self.assertEqual(raised.exception.detail["code"], "metrics.bad_range")

    def test_local_client_action_skips_junk_status_rows(self):
        from hub.routers import api as api_router

        with patch.object(api_router, "full_status", return_value={
            "groups": [
                "nope",
                {"services": "not-a-list"},
                {"services": [
                    "x",
                    {"id": "web", "actions": "start"},
                    {"id": "db", "actions": ["start", "stop"]},
                ]},
            ]
        }):
            self.assertTrue(api_router._local_client_action_allowed("db", "start"))
            self.assertFalse(api_router._local_client_action_allowed("web", "start"))

    def test_services_wifi_autostart_and_actions_are_coded(self):
        from hub import actions, autostart_svc
        from hub.routers.services_api import BulkActionBody, services_bulk
        from hub.routers.system_extra import network_wifi

        with self.assertRaises(HTTPException) as raised:
            services_bulk(BulkActionBody(action="explode", ids=["nginx"]))
        self.assertEqual(raised.exception.detail["code"], "services.bad_action")

        with self.assertRaises(HTTPException) as raised:
            network_wifi("maybe")
        self.assertEqual(raised.exception.detail["code"], "network.bad_wifi_state")

        with self.assertRaises(HTTPException) as raised:
            autostart_svc.set_autostart("nope:thing", True)
        self.assertEqual(raised.exception.detail["code"], "autostart.unknown_kind")

        with self.assertRaises(HTTPException) as raised:
            actions._app_process_name("--all")
        self.assertEqual(raised.exception.detail["code"], "actions.bad_process_name")

        with self.assertRaises(HTTPException) as raised:
            actions._script_argv("")
        self.assertEqual(raised.exception.detail["code"], "actions.empty_script")

        with self.assertRaises(HTTPException) as raised:
            actions.run_action("definitely-missing-target", "explode")
        self.assertEqual(raised.exception.detail["code"], "actions.unknown_target")

        from hub import brew_svc, containers_svc, disk_power_svc

        with self.assertRaises(HTTPException) as raised:
            containers_svc.container_action("nginx", "not-an-action")
        self.assertEqual(raised.exception.detail["code"], "container.bad_action")

        with self.assertRaises(HTTPException) as raised:
            containers_svc.batch_action([], "stop")
        self.assertEqual(raised.exception.detail["code"], "container.empty_names")

        with self.assertRaises(HTTPException) as raised:
            containers_svc.prune("everything")
        self.assertEqual(raised.exception.detail["code"], "container.bad_action")

        with self.assertRaises(HTTPException) as raised:
            brew_svc.service_action("syncthing", "obliterate")
        self.assertEqual(raised.exception.detail["code"], "brew.bad_action")

        with self.assertRaises(HTTPException) as raised:
            disk_power_svc.disk_power_action("disk3", "format")
        self.assertEqual(raised.exception.detail["code"], "disk_power.unknown_action")

        from hub import compose_svc, logs_svc

        with self.assertRaises(HTTPException) as raised:
            compose_svc.get_compose("definitely-missing-stack")
        self.assertEqual(raised.exception.detail["code"], "compose.unknown_stack")

        with self.assertRaises(HTTPException) as raised:
            compose_svc.create_stack("--all", None, "services: {}\n")
        self.assertEqual(raised.exception.detail["code"], "cli.invalid_value")

        with self.assertRaises(HTTPException) as raised:
            compose_svc.create_stack("bad.id", None, "services: {}\n")
        self.assertEqual(raised.exception.detail["code"], "compose.bad_stack_id")

        with self.assertRaises(HTTPException) as raised:
            logs_svc.tail_log("--all")
        self.assertEqual(raised.exception.detail["code"], "cli.invalid_value")

        with self.assertRaises(HTTPException) as raised:
            logs_svc.tail_log("definitely-missing-source")
        self.assertEqual(raised.exception.detail["code"], "logs.unknown_source")

        from hub import disk_manage_svc, native_catalog, nginx_svc, services_manage_svc

        with self.assertRaises(HTTPException) as raised:
            native_catalog.install_native("definitely-missing-app")
        self.assertEqual(raised.exception.detail["code"], "catalog.unknown_app")

        with self.assertRaises(HTTPException) as raised:
            native_catalog.uninstall_native("definitely-missing-app")
        self.assertEqual(raised.exception.detail["code"], "catalog.unknown_app")

        with self.assertRaises(HTTPException) as raised:
            native_catalog._install_native({"method": "script", "script_id": "nope"}, "x")
        self.assertEqual(raised.exception.detail["code"], "catalog.unsupported_script")

        with self.assertRaises(HTTPException) as raised:
            native_catalog._install_native({"method": "teleport"}, "x")
        self.assertEqual(raised.exception.detail["code"], "catalog.unsupported_method")

        with self.assertRaises(HTTPException) as raised:
            native_catalog._uninstall_native({"method": "teleport"}, "x")
        self.assertEqual(raised.exception.detail["code"], "catalog.unsupported_uninstall")

        with self.assertRaises(HTTPException) as raised:
            services_manage_svc.service_detail("definitely-missing-svc")
        self.assertEqual(raised.exception.detail["code"], "services.not_found")

        with self.assertRaises(HTTPException) as raised:
            services_manage_svc.service_logs("definitely-missing-svc")
        self.assertEqual(raised.exception.detail["code"], "services.no_logs")

        with self.assertRaises(HTTPException) as raised:
            services_manage_svc.update_override("nginx", {"port": "abc"})
        self.assertEqual(raised.exception.detail["code"], "services.bad_port")

        with self.assertRaises(HTTPException) as raised:
            disk_manage_svc._normalize_id("not-a-disk")
        self.assertEqual(raised.exception.detail["code"], "disk.invalid_device")

        with self.assertRaises(HTTPException) as raised:
            autostart_svc.set_launchd_autostart("com.example.definitely-missing", True)
        self.assertEqual(raised.exception.detail["code"], "autostart.plist_missing")

        from pathlib import Path as RealPath

        with patch.object(nginx_svc, "NGINX_CONF", RealPath("/tmp/opt50h-no-nginx.conf")):
            with self.assertRaises(HTTPException) as raised:
                nginx_svc.test_config()
        self.assertEqual(raised.exception.detail["code"], "nginx.conf_missing")

        with (
            patch.object(nginx_svc, "NGINX_CONF", RealPath(__file__)),
            patch.object(nginx_svc, "NGINX_BIN", "/no/such/nginx-binary"),
        ):
            result = nginx_svc.test_config()
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["message"])

        with patch.object(autostart_svc.Path, "home", return_value=RealPath("/tmp/opt50h-no-home")):
            with self.assertRaises(HTTPException) as raised:
                autostart_svc.run_autostart_now()
        self.assertEqual(raised.exception.detail["code"], "autostart.script_missing")

        from hub import apps_manage_svc, containers_svc

        with self.assertRaises(HTTPException) as raised:
            containers_svc.exec_in_container("nginx", "   ")
        self.assertEqual(raised.exception.detail["code"], "container.empty_command")

        with patch("hub.containers_svc.engine_up", return_value=False):
            with self.assertRaises(HTTPException) as raised:
                containers_svc.start_check_updates_job()
        self.assertEqual(raised.exception.detail["code"], "container.engine_down")

        with self.assertRaises(HTTPException) as raised:
            disk_power_svc.sleep_disk("not-a-disk")
        self.assertEqual(raised.exception.detail["code"], "disk_power.invalid_id")

        with self.assertRaises(HTTPException) as raised:
            disk_power_svc.wake_disk("not-a-disk")
        self.assertEqual(raised.exception.detail["code"], "disk_power.invalid_id")

        with patch.object(disk_power_svc, "list_power_disks", return_value=[]):
            with self.assertRaises(HTTPException) as raised:
                disk_power_svc.sleep_disk("disk99")
        self.assertEqual(raised.exception.detail["code"], "disk_power.not_found")

        with self.assertRaises(HTTPException) as raised:
            apps_manage_svc._native_detail("definitely-missing-app")
        self.assertEqual(raised.exception.detail["code"], "apps.native_not_found")

        with patch("hub.vms_svc.list_all_vms", return_value={"vms": []}):
            with self.assertRaises(HTTPException) as raised:
                apps_manage_svc._vm_detail("definitely-missing-vm")
        self.assertEqual(raised.exception.detail["code"], "apps.vm_not_found")

    def test_photoshub_codes_are_registered(self):
        for code in (
            "photoshub.not_installed",
            "photoshub.bad_immich_url",
            "photoshub.album_missing",
            "photoshub.key_missing",
            "photoshub.script_missing",
            "photoshub.bad_ids",
            "photoshub.bad_config",
            "photoshub.bad_name",
            "photoshub.bad_birthday",
            "photoshub.bad_album",
            "photoshub.bad_person",
            "photoshub.bad_link_url",
        ):
            self.assertIn(code, CODES)

    def test_metrics_uses_absolute_memory_pressure(self):
        from pathlib import Path

        text = Path(__file__).resolve().parents[1].joinpath("hub/metrics.py").read_text()
        self.assertIn('["/usr/bin/memory_pressure", "-Q"]', text)
        self.assertNotIn('["memory_pressure", "-Q"]', text)

    def test_hub_does_not_resolve_privileged_binaries_from_path(self):
        from pathlib import Path

        needles = (
            ('["sudo"', "['sudo'"),
            # Comma after the name so dict keys like detail["launchctl"]
            # and action lists like ["open"] are not flagged.
            ('["launchctl",', "['launchctl',"),
            ('["diskutil",', "['diskutil',"),
            ('["pgrep",', "['pgrep',"),
            ('["/bin/pgrep"', "['/bin/pgrep'"),
            ('["osascript",', "['osascript',"),
            ('["open",', "['open',"),
            ('["tar",', "['tar',"),
        )
        offenders = []
        root = Path(__file__).resolve().parents[1] / "hub"
        for path in root.rglob("*.py"):
            for i, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if any(token in line for pair in needles for token in pair):
                    offenders.append(f"{path.relative_to(root.parent)}:{i}")
        self.assertEqual(
            offenders, [],
            "sudo/launchctl/diskutil/pgrep/osascript/open must be absolute",
        )

    def test_tools_prefers_system_dig(self):
        from pathlib import Path

        text = Path(__file__).resolve().parents[1].joinpath("hub/tools_svc.py").read_text()
        self.assertIn('"/usr/bin/dig"', text)
        self.assertNotIn('shutil.which("dig") or "/usr/bin/dig"', text)

    def test_nginx_bin_comes_from_shared_paths(self):
        from hub import nginx_svc, paths

        self.assertEqual(nginx_svc.NGINX_BIN, paths.NGINX)
        self.assertNotEqual(paths.NGINX, "")

    def test_pick_python_never_returns_a_relative_name(self):
        from hub.native_catalog import _pick_python

        py = _pick_python()
        self.assertTrue(py == "" or py.startswith("/"), py)
        self.assertNotEqual(py, "python3")

    def test_ollama_binary_prefers_known_prefixes(self):
        from pathlib import Path

        text = Path(__file__).resolve().parents[1].joinpath("hub/ollama_svc.py").read_text()
        prefix = text.find('"/opt/homebrew/bin"')
        which = text.find('shutil.which("ollama")')
        self.assertGreater(prefix, 0)
        self.assertGreater(which, prefix)

    def test_native_which_prefers_known_prefixes(self):
        from pathlib import Path

        text = Path(__file__).resolve().parents[1].joinpath("hub/native_catalog.py").read_text()
        start = text.find("def _which(")
        chunk = text[start : start + 700]
        which = chunk.find("shutil.which")
        self.assertGreater(chunk.find("/opt/homebrew/bin"), 0)
        self.assertGreater(chunk.find("/usr/local/bin"), 0)
        self.assertGreater(which, chunk.find("/opt/homebrew/bin"))
        self.assertGreater(which, chunk.find("/usr/local/bin"))

    def test_tools_refusals_carry_a_translatable_code(self):
        from hub import tools_svc

        ping = tools_svc.net_ping("-f", 1)
        self.assertFalse(ping.get("ok"))
        self.assertEqual(ping.get("code"), "tools.bad_host")
        self.assertNotIn("output", ping)

        empty = tools_svc.net_dns_lookup("   ")
        self.assertFalse(empty.get("ok"))
        self.assertEqual(empty.get("code"), "tools.empty_name")
        self.assertNotIn("dig", empty)

        prune = tools_svc.docker_prune(what="dangling", confirm=False)
        self.assertFalse(prune.get("ok"))
        self.assertEqual(prune.get("code"), "tools.confirm_required")

        with patch.object(tools_svc, "engine_up", return_value=True):
            bad = tools_svc.docker_prune(what="everything", confirm=True)
        self.assertFalse(bad.get("ok"))
        self.assertEqual(bad.get("code"), "tools.bad_prune")
        self.assertIn("dangling", bad.get("allowed") or [])

    def test_launcher_missing_app_carries_a_translatable_code(self):
        from hub import launcher_svc

        with patch.object(launcher_svc, "_app_path", return_value=None):
            opened = launcher_svc.open_app()
            login = launcher_svc.set_login_enabled(True)
        self.assertEqual(opened.get("code"), "launcher.not_installed")
        self.assertEqual(login.get("code"), "launcher.not_installed")
        self.assertEqual(
            launcher_svc.schedule_panel_action("explode").get("code"),
            "launcher.bad_action",
        )

    def test_notify_sender_refusals_carry_a_translatable_code(self):
        from hub import notify_channels

        ntfy = notify_channels._send_ntfy({}, {}, "t", "m")
        self.assertFalse(ntfy.get("ok"))
        self.assertEqual(ntfy.get("code"), "notify.missing_field")

        discord = notify_channels._send_discord({}, {}, "t", "m")
        self.assertEqual(discord.get("code"), "notify.missing_field")

        post = notify_channels._post("ftp://example.invalid", {"x": 1})
        self.assertEqual(post.get("code"), "notify.bad_url")

    def test_container_recreate_does_not_capture_unbounded_output(self):
        from hub import containers_svc
        src = Path(containers_svc.__file__).read_text(encoding="utf-8")
        body = src[src.index("def _recreate_simple"): src.index("\ndef start_update_container_job")]
        self.assertIn("run_capped", body)
        self.assertNotIn("capture_output=True", body)

    def test_compose_cmd_does_not_capture_unbounded_output(self):
        from hub import apps_manage_svc
        src = Path(apps_manage_svc.__file__).read_text(encoding="utf-8")
        body = src[src.index("def _compose_cmd"): src.index("\ndef _container_log")]
        self.assertIn("run_capped", body)
        self.assertNotIn("capture_output=True", body)

    def test_compose_cmd_refusals_carry_a_translatable_code(self):
        from hub import apps_manage_svc

        with patch.object(apps_manage_svc, "DOCKER", ""):
            missing_docker = apps_manage_svc._compose_cmd("/tmp/no-such-compose.yml", "ps")
        self.assertFalse(missing_docker.get("ok"))
        self.assertEqual(missing_docker.get("code"), "services.docker_unavailable")

        with patch.object(apps_manage_svc, "DOCKER", "/bin/sh"):
            missing_file = apps_manage_svc._compose_cmd(
                "/tmp/opt50h-no-such-compose.yml", "ps"
            )
        self.assertFalse(missing_file.get("ok"))
        self.assertEqual(missing_file.get("code"), "compose.file_missing")

    def test_power_pref_refusals_carry_a_translatable_code(self):
        from hub import system_settings_svc

        unknown = system_settings_svc.set_power_pref("not-a-key", 1)
        self.assertFalse(unknown.get("ok"))
        self.assertEqual(unknown.get("code"), "power.bad_key")

        not_int = system_settings_svc.set_power_pref("disksleep", "x")
        self.assertFalse(not_int.get("ok"))
        self.assertEqual(not_int.get("code"), "power.bad_value")

        rng = system_settings_svc.set_power_pref("disksleep", 999)
        self.assertFalse(rng.get("ok"))
        self.assertEqual(rng.get("code"), "power.value_range")


class TestAuthResponsesAreNotCached(unittest.TestCase):
    def test_auth_status_sends_no_store(self):
        from hub.app_factory import create_app

        with TestClient(create_app()) as client:
            resp = client.get("/api/auth/status")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("no-store", resp.headers.get("cache-control", "").lower())


class TestPoolsShutDown(unittest.TestCase):
    def test_status_and_sensors_pools_restart_after_shutdown(self):
        a = status._pool._executor()
        status.shutdown_executor()
        b = status._pool._executor()
        self.assertIsNot(a, b)
        status.shutdown_executor()

        c = sensors_svc._pool._executor()
        sensors_svc.shutdown_executor()
        d = sensors_svc._pool._executor()
        self.assertIsNot(c, d)
        sensors_svc.shutdown_executor()

        from hub import bookmarks_svc, network_svc, system

        e = bookmarks_svc._pool._executor()
        bookmarks_svc.shutdown_executor()
        f = bookmarks_svc._pool._executor()
        self.assertIsNot(e, f)
        bookmarks_svc.shutdown_executor()

        g = network_svc._overview_pool._executor()
        network_svc.shutdown_executor()
        h = network_svc._overview_pool._executor()
        self.assertIsNot(g, h)
        network_svc.shutdown_executor()

        i = system._pool._executor()
        system.shutdown_executor()
        j = system._pool._executor()
        self.assertIsNot(i, j)
        system.shutdown_executor()

        from hub import storage_svc
        from hub.routers import storage as storage_router, system_extra

        k = storage_svc._OVERVIEW_POOL._executor()
        storage_svc.shutdown_executor()
        self.assertIsNot(storage_svc._OVERVIEW_POOL._executor(), k)
        storage_svc.shutdown_executor()

        m = storage_router._PAGE_POOL._executor()
        storage_router.shutdown_executor()
        self.assertIsNot(storage_router._PAGE_POOL._executor(), m)
        storage_router.shutdown_executor()

        n = system_extra._HOST_POOL._executor()
        system_extra.shutdown_executor()
        self.assertIsNot(system_extra._HOST_POOL._executor(), n)
        system_extra.shutdown_executor()


class TestDashboardCollectorIsolation(unittest.TestCase):
    def test_sensors_thermal_raise_does_not_drop_disk(self):
        with (
            patch.object(sensors_svc, "_thermal", side_effect=RuntimeError("pmset")),
            patch.object(sensors_svc, "_disk", return_value={"root_pct": 11}),
            patch.object(sensors_svc, "_memory_base", return_value={
                "ncpu": 8, "load1": 0.1, "load5": 0.1, "load15": 0.1,
            }),
            patch.object(sensors_svc, "_cpu_and_mem_from_top_cached", return_value={}),
            patch.object(sensors_svc, "_cpu_from_ticks", return_value={"used_pct": 4}),
            patch.object(sensors_svc, "_network_rates", return_value={}),
            patch.object(sensors_svc, "_top_processes", return_value=[]),
            patch.object(sensors_svc, "_uptime", return_value={"uptime_text": "1h"}),
            patch.object(sensors_svc, "_gpu", return_value=None),
        ):
            data = sensors_svc._collect_sensors_uncached()
        self.assertEqual(data["disk"]["root_pct"], 11)
        self.assertIsNone(data["cpu"]["thermal"])
        self.assertIsNone(data["gpu"])

    def test_uptime_tolerates_a_malformed_boottime(self):
        with patch.object(sensors_svc, "sh", return_value=(0, "sec = not-a-number, usec = 0", "")):
            data = sensors_svc._uptime()
        self.assertEqual(data["uptime_hours"], 0.0)

    def test_storage_smart_raise_does_not_drop_volumes(self):
        from hub import storage_svc

        vols = [{
            "kind": "system", "mount": "/", "disk_id": "disk3",
            "total_gb": 100, "used_gb": 40, "avail_gb": 60, "pct": 40,
            "filesystem": "apfs",
        }]
        with (
            patch.object(storage_svc, "list_volumes", return_value=vols),
            patch.object(storage_svc, "smart_devices", side_effect=RuntimeError("smartctl")),
        ):
            data = storage_svc.storage_overview()
        self.assertEqual(data["volumes"], vols)
        self.assertEqual(data["disks"], [])
        self.assertEqual(data["array"]["system_count"], 1)

    def test_probe_disk_raise_returns_an_error_row(self):
        from hub import storage_svc

        with patch.object(storage_svc, "sh", side_effect=RuntimeError("diskutil wedged")):
            row = storage_svc._probe_disk("disk9")
        self.assertEqual(row["id"], "disk9")
        self.assertIn("diskutil", row["error"])

    def test_power_womp_raise_does_not_drop_screen_sharing(self):
        from hub import power_svc

        with (
            patch.object(power_svc, "_nic", return_value=("en0", "aa:bb:cc:dd:ee:ff")),
            patch.object(power_svc, "_womp_enabled", side_effect=RuntimeError("pmset")),
            patch.object(power_svc, "screensharing_status", return_value={
                "running": True, "host": "192.168.1.9",
            }),
        ):
            data = power_svc.power_overview()
        self.assertEqual(data["wol"]["iface"], "en0")
        self.assertIsNone(data["wol"]["enabled"])
        self.assertTrue(data["screen_sharing"]["running"])

    def test_host_snapshot_iface_raise_still_returns_hostname(self):
        from hub.routers import system_extra

        with (
            patch.object(system_extra, "is_high", return_value=False),
            patch.object(system_extra, "sh", return_value=(0, "nas.local", "")),
            patch.object(system_extra, "default_interface", side_effect=RuntimeError("no route")),
            patch.object(system_extra, "host_ip", return_value="10.0.0.2"),
            patch.object(system_extra, "peek_engine", return_value=True),
        ):
            snap = system_extra._host_snapshot(True)
        self.assertEqual(snap["hostname"], "nas.local")
        self.assertEqual(snap["interfaces"], [])
        self.assertTrue(snap["orbstack"])

    def test_host_snapshot_huge_memsize_does_not_500(self):
        """``int('9'*400) / 2**30`` OverflowError'd GET /api/system/host."""
        from hub.routers import system_extra

        def fake_sh(argv, **kwargs):
            last = argv[-1] if argv else ""
            if last == "hw.memsize":
                return 0, "9" * 400, ""
            if last == "hw.ncpu":
                return 0, "8", ""
            if argv and argv[0].endswith("hostname"):
                return 0, "nas.local", ""
            return 0, "ok", ""

        with (
            patch.object(system_extra, "is_high", return_value=False),
            patch.object(system_extra, "sh", fake_sh),
            patch.object(system_extra, "default_interface", return_value="en0"),
            patch.object(system_extra, "_iface_addresses", return_value=[]),
            patch.object(system_extra, "host_ip", return_value="10.0.0.2"),
            patch.object(system_extra, "peek_engine", return_value=False),
        ):
            snap = system_extra._host_snapshot(True)
        json.dumps(snap, allow_nan=False)
        self.assertEqual(snap["hostname"], "nas.local")
        self.assertEqual(snap["ncpu"], 8)
        self.assertIsNone(snap["mem_total_gb"])


class TestStatusCarriesRamTotal(unittest.TestCase):
    def test_collect_system_reads_hw_memsize(self):
        from hub import system

        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, "8", ""
            if last == "hw.memsize":
                return 0, str(32 * 2**30), ""
            if last == "kern.boottime":
                return 0, "sec = 1,", ""
            if argv[0].endswith("memory_pressure"):
                return 0, "The system has 50% free percentage", ""
            return 1, "", ""

        with patch("hub.macos_sysctl.sysctlbyname_int", return_value=None):
            with patch.object(system, "sh", side_effect=fake_sh):
                with patch.object(system, "_smart_cache", {"t": 9e9, "v": None}):
                    snap = system.collect_system()
        self.assertEqual(snap["mem_total_gb"], 32.0)
        self.assertEqual(snap["ncpu"], 8)

    def test_collect_system_memory_pressure_raise_still_returns_load(self):
        from hub import system

        def fake_sh(argv, **kwargs):
            if argv[0].endswith("memory_pressure"):
                raise RuntimeError("memory_pressure gone")
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, "8", ""
            if last == "hw.memsize":
                return 0, str(16 * 2**30), ""
            if last == "kern.boottime":
                return 0, "sec = not-a-number,", ""
            return 1, "", ""

        with patch("hub.macos_sysctl.sysctlbyname_int", return_value=None):
            with patch.object(system, "sh", side_effect=fake_sh):
                with patch.object(system, "_smart_cache", {"t": 9e9, "v": None}):
                    snap = system.collect_system()
        self.assertEqual(snap["ncpu"], 8)
        self.assertEqual(snap["mem_total_gb"], 16.0)
        self.assertEqual(snap["uptime_hours"], 0.0)
        self.assertIsNone(snap["mem_free_pct"])

    def test_lifespan_starts_the_hotpath_warmer(self):
        from pathlib import Path

        src = Path(__file__).resolve().parents[1].joinpath("hub", "app_factory.py").read_text()
        self.assertIn("def _warm_hotpath", src)
        self.assertIn("hotpath-warmer", src)

    def test_warm_hotpath_uses_light_sensors(self):
        from hub.app_factory import _warm_hotpath

        with (
            patch("hub.brew_cache.brew_services"),
            patch("hub.sensors_svc.collect_light") as light,
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.routers.system_extra._host_snapshot"),
            patch("hub.vms_svc.list_all_vms"),
            patch("hub.status.full_status"),
            patch("hub.apps_manage_svc.inventory"),
        ):
            _warm_hotpath()
        light.assert_called_once()


class TestComposeReadRace(unittest.TestCase):
    def test_vanished_compose_is_coded_not_500(self):
        import tempfile

        from hub import compose_svc

        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            stack = {
                "id": "x", "name": "x", "path": tmp, "compose_path": str(compose),
            }
            compose.unlink()
            with patch.object(compose_svc, "_find_stack", return_value=stack):
                with self.assertRaises(HTTPException) as ctx:
                    compose_svc.get_compose("x")
            self.assertEqual(ctx.exception.detail["code"], "container.no_compose_file")

    def test_read_text_filenotfounderror_is_coded(self):
        import tempfile

        from hub import compose_svc

        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            stack = {
                "id": "x", "name": "x", "path": tmp, "compose_path": str(compose),
            }

            def racing(*a, **k):
                raise FileNotFoundError()

            with (
                patch.object(compose_svc, "_find_stack", return_value=stack),
                patch.object(compose_svc, "read_text_capped", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    compose_svc.get_compose("x")
            self.assertEqual(ctx.exception.detail["code"], "container.no_compose_file")


class TestAutostartCorruptPlist(unittest.TestCase):
    def test_a_non_dict_plist_is_not_overwritten(self):
        import tempfile

        from hub import autostart_svc

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            path = agents / "local.demo.plist"
            path.write_bytes(b"[]")
            written = []
            with (
                patch.object(autostart_svc, "AGENTS_DIR", agents),
                patch.object(autostart_svc, "_write_plist", lambda p, d: written.append(d)),
                patch.object(autostart_svc, "sh", lambda *a, **k: (0, "", "")),
                patch.object(autostart_svc, "invalidate_launchd", lambda: None),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    autostart_svc.set_launchd_autostart("local.demo", True)
            self.assertEqual(ctx.exception.detail["code"], "autostart.bad_plist")
            self.assertEqual(written, [])

    def test_a_missing_label_is_not_overwritten(self):
        import tempfile

        from hub import autostart_svc

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            path = agents / "local.demo.plist"
            path.write_bytes(b"{}")
            written = []
            with (
                patch.object(autostart_svc, "AGENTS_DIR", agents),
                patch.object(autostart_svc, "_write_plist", lambda p, d: written.append(d)),
                patch.object(autostart_svc, "sh", lambda *a, **k: (0, "", "")),
                patch.object(autostart_svc, "invalidate_launchd", lambda: None),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    autostart_svc.set_launchd_autostart("local.demo", False)
            self.assertEqual(ctx.exception.detail["code"], "autostart.bad_plist")
            self.assertEqual(written, [])


class TestDockerNetworkInspectTypes(unittest.TestCase):
    def test_a_dict_inspect_payload_does_not_500(self):
        from hub import network_svc

        def fake_docker(*args, **kwargs):
            if args[:2] == ("network", "ls"):
                return 0, "abc123\tbridge\tbridge\tlocal\n", ""
            return 0, '{"Name": "bridge", "IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}}', ""

        with (
            patch.object(network_svc, "engine_up", return_value=True),
            patch.object(network_svc, "docker", fake_docker),
        ):
            rows = network_svc.docker_networks_detail()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subnet"], "172.17.0.0/16")

    def test_a_string_inspect_payload_does_not_500(self):
        from hub import network_svc

        def fake_docker(*args, **kwargs):
            if args[:2] == ("network", "ls"):
                return 0, "abc123\tbridge\tbridge\tlocal\n", ""
            return 0, '"not-an-object"', ""

        with (
            patch.object(network_svc, "engine_up", return_value=True),
            patch.object(network_svc, "docker", fake_docker),
        ):
            rows = network_svc.docker_networks_detail()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subnet"], "")


class TestCodedErrorParamsDoNot500(unittest.TestCase):
    def test_leftover_inf_param_does_not_500_the_error_body(self):
        """Starlette allow_nan=False: leftover Infinity used to 500 a coded 409."""
        exc = api_error("catalog.no_free_port", port=float("inf"))
        self.assertEqual(exc.status_code, 409)
        json.dumps(exc.detail, allow_nan=False)
        self.assertIsNone(exc.detail["params"]["port"])

    def test_leftover_bytes_and_date_params_do_not_500(self):
        exc = api_error("compose.unknown_stack", stack=b"web")
        json.dumps(exc.detail, allow_nan=False)
        self.assertEqual(exc.detail["params"]["stack"], "web")
        exc = api_error("catalog.no_free_port", port=date(2026, 1, 2))
        json.dumps(exc.detail, allow_nan=False)
        self.assertEqual(exc.detail["params"]["port"], "2026-01-02")

    def test_isoformat_inf_param_does_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 a coded error body."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        exc = api_error("compose.unknown_stack", stack=_Stamp())
        json.dumps(exc.detail, allow_nan=False)
        json.dumps(exc.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(exc.detail["params"]["stack"])

    def test_leftover_surrogate_param_does_not_500_the_error_body(self):
        """Params were cleaned; the formatted message still 500'd UTF-8 encode."""
        exc = api_error("compose.unknown_stack", stack="\ud800web")
        json.dumps(exc.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", exc.detail["message"])
        self.assertNotIn("\ud800", exc.detail["params"]["stack"])
        exc = api_error("catalog.no_free_port", **{"\ud800": 8080, "port": 8080})
        json.dumps(exc.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", json.dumps(exc.detail, ensure_ascii=False))

    def test_recursing_format_param_does_not_500(self):
        """``str.format`` RecursionError is not ValueError; leftover recursive
        ``__format__`` used to 500 every coded error body."""
        class Recursing:
            def __format__(self, spec):
                raise RecursionError("nested")
            def __str__(self):
                raise RecursionError("nested")

        exc = api_error("compose.unknown_stack", stack=Recursing())
        json.dumps(exc.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(exc.detail["message"], "unknown stack: {stack}")
        self.assertIsNone(exc.detail["params"]["stack"])

    def test_exc_detail_recursion_and_surrogate_do_not_500(self):
        """str(e) RecursionError / leftover ``\\ud800`` used to 500 GET /api/photoshub."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(exc_detail(Recursing()), "error")
        text = exc_detail(ValueError("ok\ud800"))
        text.encode("utf-8")
        self.assertNotIn("\ud800", text)
        from hub.routers import photoshub_api, ollama_api
        with patch.object(photoshub_api.photoshub_svc, "status", side_effect=Recursing()):
            with self.assertRaises(HTTPException) as ctx:
                photoshub_api.get_status()
        json.dumps(ctx.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        with patch.object(ollama_api.ollama_svc, "status", side_effect=Recursing()):
            with self.assertRaises(HTTPException) as ctx:
                ollama_api.get_status()
        json.dumps(ctx.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_pending_delete_infinite_limit_does_not_500(self):
        from hub.routers import photoshub_api
        with patch.object(
            photoshub_api.photoshub_svc, "pending_delete_assets",
            return_value={"assets": [], "count": 0},
        ) as pending:
            out = photoshub_api.pending_delete(limit=float("inf"))
        self.assertEqual(out["count"], 0)
        pending.assert_called_once_with(limit=60)


if __name__ == "__main__":
    unittest.main()
