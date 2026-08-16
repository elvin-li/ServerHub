"""Hot-path pools, coded errors, and auth cache headers added in the opt pass."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub.errors import CODES
from hub.power_svc import power_action
from hub.util import LazyPool
from hub import jobs, metrics, sensors_svc, status


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

        with patch.object(system, "sh", side_effect=fake_sh):
            with patch.object(system, "_smart_cache", {"t": 9e9, "v": None}):
                snap = system.collect_system()
        self.assertEqual(snap["mem_total_gb"], 32.0)
        self.assertEqual(snap["ncpu"], 8)

    def test_lifespan_starts_the_hotpath_warmer(self):
        from pathlib import Path

        src = Path(__file__).resolve().parents[1].joinpath("hub", "app_factory.py").read_text()
        self.assertIn("def _warm_hotpath", src)
        self.assertIn("hotpath-warmer", src)


if __name__ == "__main__":
    unittest.main()
