"""Leftover parse/typing 500s on status, adaptive, system, worker health.

Orphan lsof rows, nginx listen lines, a compose tree that cannot be
stat'd, sysctl/smartctl payloads that are not strings, and a worker
registry entry that is not the expected dict each used to raise on the
request path instead of skipping the bad row.

Follow-up: one ``*.conf`` raising MemoryError/ValueError 500'd GET /api/nginx;
``nginx.conf`` is_file() EIO 500'd Test/Reload.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import (
    adaptive,
    docker_info_svc,
    freshness_svc,
    health_svc,
    launchd_cache,
    proc_cache,
    smart_test_svc,
    stale_runtime,
    system,
    worker_health,
)
from hub.discovery import containers
from hub.freshness_svc import Target


class OrphanListenParseTests(unittest.TestCase):
    def test_none_and_bytes_output_do_not_500(self):
        self.assertEqual(adaptive._parse_lsof_listen(None), [])
        rows = adaptive._parse_lsof_listen(
            b"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            b"node  9103 a0000  9u  IPv4 0x33  0t0  TCP *:3000 (LISTEN)\n"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["port"], 3000)
        self.assertEqual(rows[0]["proc"], "node")

    def test_arrow_name_uses_the_local_port(self):
        out = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "python  1 u 5u IPv4 0x 0t0 TCP 10.0.0.1:8086->1.2.3.4:9 (LISTEN)\n"
        )
        rows = adaptive._parse_lsof_listen(out)
        self.assertEqual([r["port"] for r in rows], [8086])

    def test_junk_snapshot_rows_do_not_500(self):
        rows = [
            None,
            {"proc": "x"},
            {"proc": "node", "pid": "1", "bind": "*:3000", "port": "3000"},
            {"proc": "node", "pid": "2", "bind": "*:3001", "port": 3001},
        ]
        with mock.patch.object(adaptive, "lsof_listen_snapshot", return_value=rows):
            items = adaptive.discover_orphan_listeners(set(), {1, "other"})
        ports = {i["meta"]["port"] for i in items}
        self.assertIn(3000, ports)
        self.assertIn(3001, ports)


class NginxSitesParseTests(unittest.TestCase):
    def test_listen_host_port_and_comments(self):
        text = (
            "# listen 80;\n"
            "listen 127.0.0.1:8080;\n"
            "listen [::]:443 ssl http2;\n"
            "listen 80 default_server;\n"
            "listen unix:/tmp/nginx.sock;\n"
            "listen 999999;\n"
        )
        self.assertEqual(adaptive._nginx_listen_ports(text), [8080, 443, 80])

    def test_unreadable_conf_d_parent_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        nginx = tmp / "Services" / "nginx"
        nginx.mkdir(parents=True)
        (nginx / "conf.d").mkdir()
        os.chmod(nginx, 0)
        try:
            with mock.patch.object(Path, "home", return_value=tmp):
                self.assertEqual(adaptive.nginx_sites(), [])
        finally:
            os.chmod(nginx, 0o755)

    def test_none_and_bytes_listen_text_do_not_500(self):
        self.assertEqual(adaptive._nginx_listen_ports(None), [])
        self.assertEqual(adaptive._nginx_listen_ports(80), [])
        self.assertEqual(
            adaptive._nginx_listen_ports(b"listen 8080;\nlisten [::]:443 ssl;\n"),
            [8080, 443],
        )

    def test_one_conf_memoryerror_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        conf_d = tmp / "Services" / "nginx" / "conf.d"
        conf_d.mkdir(parents=True)
        (conf_d / "ok.conf").write_text("listen 8080;\n")
        (conf_d / "bad.conf").write_text("listen 80;\n")
        real = adaptive.read_text_capped

        def boom(path, *args, **kwargs):
            if Path(path).name == "bad.conf":
                raise MemoryError("huge")
            return real(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "home", return_value=tmp),
            mock.patch.object(adaptive, "read_text_capped", boom),
        ):
            sites = adaptive.nginx_sites()
        self.assertEqual([s["file"] for s in sites], ["ok.conf"])
        json.dumps(sites, allow_nan=False)

    def test_one_conf_valueerror_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        conf_d = tmp / "Services" / "nginx" / "conf.d"
        conf_d.mkdir(parents=True)
        (conf_d / "ok.conf").write_text("listen 443;\n")
        (conf_d / "nul.conf").write_text("listen 80;\n")
        real = adaptive.read_text_capped

        def boom(path, *args, **kwargs):
            if Path(path).name == "nul.conf":
                raise ValueError("embedded null byte")
            return real(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "home", return_value=tmp),
            mock.patch.object(adaptive, "read_text_capped", boom),
        ):
            sites = adaptive.nginx_sites()
        self.assertEqual([s["file"] for s in sites], ["ok.conf"])

    def test_huge_conf_does_not_oom_sites(self):
        """``read_text()`` of leftover multi-MB ``*.conf`` used to OOM GET /api/nginx."""
        tmp = Path(tempfile.mkdtemp())
        conf_d = tmp / "Services" / "nginx" / "conf.d"
        conf_d.mkdir(parents=True)
        (conf_d / "ok.conf").write_text("listen 8080;\n")
        (conf_d / "huge.conf").write_bytes(b"# " + b"x" * (2 * 1024 * 1024))
        with mock.patch.object(Path, "home", return_value=tmp):
            sites = adaptive.nginx_sites()
        self.assertEqual([s["file"] for s in sites], ["ok.conf"])
        json.dumps(sites, allow_nan=False)


class NginxSvcOutputTests(unittest.TestCase):
    def test_bytes_and_none_nginx_t_do_not_500_reload(self):
        from hub import nginx_svc

        conf = Path(tempfile.mkdtemp()) / "nginx.conf"
        conf.write_text("events {}\n")
        with mock.patch.object(nginx_svc, "NGINX_CONF", conf):
            with mock.patch.object(nginx_svc, "sh", return_value=(1, b"fail", None)):
                t = nginx_svc.test_config()
                self.assertFalse(t["ok"])
                self.assertIsInstance(t["message"], str)
                r = nginx_svc.reload_nginx()
                self.assertFalse(r["ok"])
                self.assertIsInstance(r["message"], str)
                self.assertIn("Invalid configuration", r["message"])
            with mock.patch.object(nginx_svc, "sh", return_value=(0, b"syntax is ok", None)):
                t = nginx_svc.test_config()
                self.assertTrue(t["ok"])
                self.assertEqual(t["message"], "syntax is ok")
                r = nginx_svc.reload_nginx()
                self.assertTrue(r["ok"])
                self.assertIsInstance(r["message"], str)

    def test_is_file_eio_is_coded_not_500(self):
        from hub import nginx_svc

        with mock.patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(HTTPException) as ctx:
                nginx_svc.test_config()
            self.assertEqual(ctx.exception.detail["code"], "nginx.conf_missing")
            with self.assertRaises(HTTPException) as ctx:
                nginx_svc.reload_nginx()
            self.assertEqual(ctx.exception.detail["code"], "nginx.conf_missing")

    def test_sites_raise_does_not_500_overview(self):
        from hub import nginx_svc

        with (
            mock.patch.object(nginx_svc, "nginx_sites", side_effect=RuntimeError("boom")),
            mock.patch.object(nginx_svc, "launchd_listing") as listing,
        ):
            listing.return_value.pid_for.return_value = None
            ov = nginx_svc.overview()
        self.assertEqual(ov["sites"], [])
        self.assertEqual(ov["site_count"], 0)
        self.assertFalse(ov["running"])
        json.dumps(ov, allow_nan=False)

    def test_missing_home_does_not_raise_default_root(self):
        """``Path.home()`` RuntimeError used to 500 import of nginx_svc."""
        from hub import nginx_svc

        with mock.patch.object(nginx_svc, "user_home", return_value=None):
            root = nginx_svc._default_root()
        self.assertIsInstance(root, Path)
        self.assertTrue(str(root).endswith("serverhub-nginx"))


class ComposeScanTests(unittest.TestCase):
    def test_home_nul_does_not_500(self):
        """Leftover NUL in HOME ValueError'd Path.home() on GET /api/nginx."""
        with mock.patch.object(Path, "home", side_effect=ValueError("embedded null")):
            self.assertEqual(adaptive.scan_new_compose_projects(), [])
            self.assertEqual(adaptive.nginx_sites(), [])

    def test_unreadable_home_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "Services").mkdir()
        os.chmod(tmp, 0)
        try:
            with mock.patch.object(Path, "home", return_value=tmp):
                self.assertEqual(adaptive.scan_new_compose_projects(), [])
        finally:
            os.chmod(tmp, 0o755)

    def test_glob_oserror_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        services = tmp / "Services"
        services.mkdir()
        (services / "ok").mkdir()
        (services / "ok" / "docker-compose.yml").write_text("services: {}\n")

        def boom(self, pattern):
            raise PermissionError("nope")

        with (
            mock.patch.object(Path, "home", return_value=tmp),
            mock.patch.object(Path, "glob", boom),
        ):
            self.assertEqual(adaptive.scan_new_compose_projects(), [])


class SystemSnapshotTypingTests(unittest.TestCase):
    def _collect(self, ncpu, memsize, mem_out="", smart_out=None):
        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, ncpu, ""
            if last == "hw.memsize":
                return 0, memsize, ""
            if last == "kern.boottime":
                return 0, "sec = 1,", ""
            if argv[0].endswith("memory_pressure"):
                return 0, mem_out, ""
            if smart_out is not None and (
                argv[-1] == "/dev/disk0" or "smartctl" in " ".join(str(a) for a in argv)
            ):
                return 0, smart_out, ""
            return 1, "", ""

        cache_t = 0.0 if smart_out is not None else 9e9
        with mock.patch.object(system, "sh", side_effect=fake_sh):
            with mock.patch.object(system, "_smart_cache", {"t": cache_t, "v": None}):
                return system.collect_system()

    def test_int_sysctl_payloads_do_not_500(self):
        snap = self._collect(8, 32 * 2**30, mem_out="The system has 50% free percentage")
        self.assertEqual(snap["ncpu"], 8)
        self.assertEqual(snap["mem_total_gb"], 32.0)
        self.assertEqual(snap["mem_free_pct"], 50)

    def test_fractional_free_percentage_and_header_wear_do_not_500(self):
        snap = self._collect(
            8,
            str(16 * 2**30),
            mem_out="free percentage: 12.5%",
            smart_out="Percentage Used\nTemperature: 41 Celsius\n",
        )
        self.assertEqual(snap["ncpu"], 8)
        self.assertEqual(snap["mem_free_pct"], 12)
        self.assertNotIn("wear", snap["smart"] or {})
        self.assertEqual((snap["smart"] or {}).get("temp"), "41 Celsius")

    def test_infinite_free_percentage_does_not_500(self):
        """``int(float('inf'))`` used to OverflowError on /api/status."""
        snap = self._collect(8, 8 * 2**30, mem_out="free percentage: inf%")
        self.assertEqual(snap["ncpu"], 8)
        self.assertIsNone(snap["mem_free_pct"])
        self.assertIsNone(snap["mem_used_pct"])

    def test_huge_digit_free_percentage_does_not_500(self):
        snap = self._collect(8, 8 * 2**30, mem_out="free percentage: " + ("9" * 400) + "%")
        self.assertIsNone(snap["mem_free_pct"])


class ContainerOverrideTests(unittest.TestCase):
    def test_non_dict_override_does_not_500(self):
        line = "web\trunning\tUp 2 hours\tnginx:latest\tdemo"
        containers.invalidate_containers()
        self.addCleanup(containers.invalidate_containers)
        with (
            mock.patch.object(containers, "sh", return_value=(0, line, "")),
            mock.patch.object(containers, "override", return_value=["oops"]),
            mock.patch.object(containers, "resolve_value", side_effect=lambda v: v),
            mock.patch.object(containers, "configured_signatures", return_value=[]),
        ):
            items, up = containers.discover_containers(force=True)
        self.assertTrue(up)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "web")
        self.assertEqual(items[0]["state"], "ok")


class WorkerHealthDictTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(worker_health._workers)
        worker_health._workers.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        worker_health._workers.clear()
        worker_health._workers.update(self._saved)

    def test_junk_entries_do_not_500_snapshot(self):
        worker_health._workers["plain"] = "not-a-dict"
        worker_health._workers["partial"] = {"interval": 10, "beat": 1}
        worker_health._workers["obj"] = {
            "thread": object(), "interval": "90s", "beat": "nope",
        }
        snap = worker_health.snapshot()
        names = {w["name"] for w in snap}
        self.assertNotIn("plain", names)
        self.assertIn("partial", names)
        self.assertIn("obj", names)
        obj = next(w for w in snap if w["name"] == "obj")
        self.assertFalse(obj["alive"])
        self.assertEqual(obj["interval"], 60.0)

    def test_register_non_numeric_interval_does_not_raise(self):
        worker_health.register("w", "90s", thread=None)
        snap = worker_health.snapshot()
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0]["interval"], 60.0)
        worker_health.beat("w")
        worker_health.beat("plain")

    def test_overflow_interval_and_now_do_not_500(self):
        worker_health.register("huge", 10 ** 1000, thread=None)
        snap = worker_health.snapshot(now=10 ** 1000)
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0]["interval"], 60.0)
        self.assertFalse(snap[0]["stale"])
        self.assertEqual(worker_health.problems(now=float("inf")), [])


class HealthDiskTotalTests(unittest.TestCase):
    def test_zero_disk_total_does_not_500(self):
        import collections

        DU = collections.namedtuple("Usage", "used total free")
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(lambda: health_svc._cache.update(t=0.0, v=None))
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)
        with (
            mock.patch.object(health_svc.shutil, "disk_usage", return_value=DU(0, 0, 0)),
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(launchd_cache, "sh", return_value=(0, "PID\tStatus\tLabel\n", "")),
            mock.patch.object(health_svc, "brew_services_list", return_value=[]),
        ):
            result = health_svc.run_checks(force=True)
        disk = next(c for c in result["checks"] if c["id"] == "disk_root")
        self.assertFalse(disk["ok"])
        self.assertIn("unable to read", disk["detail"])
        self.assertGreater(result["summary"]["total"], 1)


class DockerInfoTypingTests(unittest.TestCase):
    def test_none_and_bytes_payloads_do_not_500(self):
        info = b'{"ServerVersion":"27.1","NCPU":8}'
        version = b'{"Server":{"Version":"27.1"}}'

        def fake_docker(*args, **kwargs):
            argv = list(args)
            if "info" in argv:
                return 0, info, ""
            return 0, version, ""

        with (
            mock.patch.object(docker_info_svc, "engine_up", lambda: True),
            mock.patch.object(docker_info_svc, "docker", fake_docker),
            mock.patch.object(docker_info_svc, "sh", lambda *a, **k: (0, None, "")),
        ):
            data = docker_info_svc.engine_info()
        self.assertTrue(data["engine_up"])
        self.assertEqual(data["info"]["ServerVersion"], "27.1")
        self.assertEqual(data["version"]["Server"]["Version"], "27.1")
        self.assertEqual(data["orb_version"], "")

    def test_engine_up_raise_does_not_500(self):
        with mock.patch.object(docker_info_svc, "engine_up", side_effect=RuntimeError("boom")):
            data = docker_info_svc.engine_info()
        self.assertFalse(data["engine_up"])
        self.assertIn("not running", data["message"])


class FreshnessStampTests(unittest.TestCase):
    def test_infinite_last_fire_does_not_500(self):
        target = Target(id="t1", label="local.x", pattern="/no/such/*.tgz", max_age_hours=25)
        prev = {"freshness:t1": "down", "_freshness_last": {"t1": float("inf")}}
        state: dict = {}
        with (
            mock.patch("hub.alerts.notify_settings", lambda: {"enabled": False}),
            mock.patch("hub.alerts._append_alert", lambda alert: None),
        ):
            emitted = freshness_svc.check_freshness(
                prev, state, 1_800_000_000, targets=(target,),
            )
        self.assertEqual(state["freshness:t1"], "down")
        self.assertTrue(emitted, "a garbage stamp must not silence a still-stale job")

    def test_infinite_clock_does_not_500(self):
        """int(time.time()) OverflowError on leftover inf used to 500 POST /api/alerts/check."""
        target = Target(id="t1", label="local.x", pattern="/no/such/*.tgz", max_age_hours=25)
        with (
            mock.patch("hub.alerts.notify_settings", lambda: {"enabled": False}),
            mock.patch("hub.alerts._append_alert", lambda alert: None),
            mock.patch.object(freshness_svc.time, "time", return_value=float("inf")),
        ):
            emitted = freshness_svc.check_freshness(
                {}, {}, float("inf"), targets=(target,),
            )
        json.dumps(emitted, allow_nan=False)


class SmartTestClockLeftoverTests(unittest.TestCase):
    def test_infinite_clock_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to 500 SMART runs."""
        with mock.patch.object(smart_test_svc.time, "time", return_value=float("inf")):
            self.assertEqual(smart_test_svc._now(), 0)


class HostSnapshotTypingTests(unittest.TestCase):
    def test_bytes_ps_table_does_not_500(self):
        proc_cache.invalidate_processes()
        self.addCleanup(proc_cache.invalidate_processes)
        table = (
            b"USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n"
            b"me 11 9.5 1.5 100 200 ?? S 1:00PM 0:01.00 /opt/homebrew/bin/wstunnel\n"
        )
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, table, "")):
            self.assertEqual(
                proc_cache.ps_pid_commands(),
                ((11, "/opt/homebrew/bin/wstunnel"),),
            )
            self.assertTrue(proc_cache.process_matches("wstunnel"))

    def test_bytes_launchctl_listing_does_not_500(self):
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)
        listing = b"PID\tStatus\tLabel\n4242\t0\tlocal.alpha\n-\t0\tlocal.watchdog\n"
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, listing, "")):
            loaded = launchd_cache.loaded_labels()
        self.assertIn("local.alpha", loaded)
        self.assertIn("local.watchdog", loaded)

    def test_int_pid_listing_does_not_500(self):
        listing = launchd_cache.Listing({"local.alpha": (4242, 0)})
        self.assertIn("local.alpha", listing.running)
        self.assertEqual(listing.pid_for("local.alpha"), "4242")

    def test_surrogate_ps_command_does_not_500(self):
        """Leftover ``\\ud800`` in a ``ps aux`` command used to 500 sensors/Tools JSON."""
        proc_cache.invalidate_processes()
        self.addCleanup(proc_cache.invalidate_processes)
        table = (
            "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n"
            "me 11 9.5 1.5 100 200 ?? S 1:00PM 0:01.00 /bin/cmd\ud800\n"
        )
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, table, "")):
            rows = proc_cache.ps_pid_commands()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 11)
        self.assertNotIn("\ud800", rows[0][1])
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_inf_ps_output_does_not_500(self):
        proc_cache.invalidate_processes()
        self.addCleanup(proc_cache.invalidate_processes)
        with mock.patch.object(proc_cache, "sh", lambda *a, **k: (0, float("inf"), "")):
            self.assertEqual(proc_cache.ps_pid_commands(), ())

    def test_surrogate_launchd_label_does_not_500(self):
        """Leftover ``\\ud800`` in a launchctl label used to 500 health/apps JSON."""
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)
        raw = "PID\tStatus\tLabel\n4242\t0\tlocal.alpha\ud800\n"
        with mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, raw, "")):
            loaded = launchd_cache.loaded_labels()
        self.assertTrue(any("alpha" in label for label in loaded))
        self.assertTrue(all("\ud800" not in label for label in loaded))
        json.dumps(sorted(loaded), ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_inf_pid_column_does_not_500_listing(self):
        listing = launchd_cache.Listing({float("inf"): (float("inf"), 0)})
        json.dumps(sorted(listing.loaded), ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(listing.running, frozenset())
        self.assertIn("inf", listing.loaded)


class StaleRuntimeTypingTests(unittest.TestCase):
    def setUp(self):
        stale_runtime.invalidate_exe_cache()
        self.addCleanup(stale_runtime.invalidate_exe_cache)

    def test_bytes_ps_and_lsof_do_not_500(self):
        def fake_sh(cmd, **kwargs):
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, b"/opt/homebrew/opt/python@3.14/bin/python3.14 -m uvicorn", ""
            raise AssertionError(f"unexpected {cmd}")

        with (
            mock.patch.object(stale_runtime, "_LIBC", None),
            mock.patch.object(stale_runtime, "sh", fake_sh),
        ):
            self.assertEqual(
                stale_runtime.pid_exe_path(9),
                "/opt/homebrew/opt/python@3.14/bin/python3.14",
            )

        stale_runtime.invalidate_exe_cache()

        def fake_lsof(cmd, **kwargs):
            if cmd[:2] == ["/bin/ps", "-p"]:
                return 0, "next-server (v16.2.12)", ""
            if cmd[0] == "/usr/sbin/lsof":
                return 0, b"p2761\nftxt\nn/opt/homebrew/Cellar/node/26.5.0_1/bin/node\n", ""
            return 1, "", ""

        with (
            mock.patch.object(stale_runtime, "_LIBC", None),
            mock.patch.object(stale_runtime, "sh", fake_lsof),
        ):
            self.assertEqual(
                stale_runtime.pid_exe_path(2761),
                "/opt/homebrew/Cellar/node/26.5.0_1/bin/node",
            )


if __name__ == "__main__":
    unittest.main()
