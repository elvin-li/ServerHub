"""Leftover request-path 500s on Services, autostart, credentials, actions.

YAML ``ports: [.inf]`` OverflowError'd GET /api/services/signatures and adopt;
script/app YAML dates / ``!!set`` / bytes / Infinity 500'd GET detail under
Starlette's allow_nan=False encoder; ``int(inf)`` pid/ports 500'd auto detail;
launchctl/docker bytes and inspect Infinity did the same.

Path.resolve() RuntimeError on a symlink-loop workdir 500'd uninstall preview;
is_file/exists/glob EIO 500'd logs, actions.registry, autostart toggles, and
credential apply. Leftover ``updated_at: Infinity`` 500'd GET credentials.

Follow-up: leftover ``launchctl bootout`` bytes 500'd POST uninstall JSON;
leftover ``filebrowser users update`` bytes TypeError'd ``.replace``.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from hub import (
    actions,
    autostart_svc,
    service_credentials as creds,
    service_signatures,
    services_manage_svc as sms,
    services_uninstall_svc as uns,
)
from hub.routers.services_api import BulkActionBody, services_bulk


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _symlink_loop(directory: Path) -> Path:
    loop = directory / "loop"
    loop.symlink_to(loop)
    return loop


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class SignatureParseLeftoverTests(unittest.TestCase):
    def test_inf_port_is_skipped_not_500(self):
        """YAML ``ports: [.inf]`` used to OverflowError GET /api/services/signatures."""
        sig = service_signatures.parse_signature({
            "slug": "x", "name": "X", "ports": [float("inf"), 8080, float("nan")],
        })
        self.assertEqual(sig["ports"], (8080,))
        listed = sms.list_signatures()
        _json(listed)

    def test_set_ports_and_non_dict_extras_do_not_500(self):
        sig = service_signatures.parse_signature({
            "slug": "x", "name": "X", "ports": {8080, 9090},
        })
        self.assertEqual(set(sig["ports"]), {8080, 9090})
        hit = service_signatures.identify(
            "mystery", 5432, extras=["nope", None, {"not": "a-sig"}],
        )
        self.assertEqual(hit["slug"], "postgres")

    def test_configured_signatures_inf_does_not_500_list(self):
        with patch(
            "hub.config.cfg",
            return_value={"service_signatures": [
                {"slug": "x", "name": "X", "ports": [float("inf"), 443]},
            ]},
        ):
            rows = service_signatures.configured_signatures()
            listed = sms.list_signatures()
        self.assertEqual(rows[0]["ports"], (443,))
        _json(listed)


class ServiceDetailLeftoverTests(unittest.TestCase):
    def test_script_yaml_leftovers_do_not_500_json(self):
        svc = {
            "id": "s1", "name": "s1", "kind": "script", "state": "ok",
            "actions": ["detail"], "group": "Custom",
        }
        script = {
            "id": "s1", "name": "s1",
            "ports": [float("inf"), 8080],
            "url": datetime(2026, 8, 19),
            "tags": {"prod", "core"},
            "bin": b"\x00\x01",
            "start": "true",
        }
        ov = {
            "port": float("inf"),
            "added": date(2026, 1, 1),
            "flags": {"a"},
        }
        with (
            patch.object(sms, "find_service", return_value=svc),
            patch.object(sms, "override", return_value=ov),
            patch.object(sms, "cfg", return_value={"scripts": [script], "apps": []}),
        ):
            detail = sms.service_detail("s1")
        _json(detail)
        self.assertNotIn(float("inf"), detail.get("config", {}).get("ports") or [])
        self.assertIsInstance(detail["config"]["tags"], list)
        self.assertIsInstance(detail["config"]["bin"], str)
        self.assertIsInstance(detail["override"]["added"], str)

    def test_launchd_plist_bytes_dates_inf_do_not_500(self):
        pl = {
            "Label": "job",
            "Program": b"/bin/true",
            "ProgramArguments": [b"/bin/true"],
            "KeepAlive": datetime(2026, 1, 1),
            "StartInterval": float("inf"),
            "WorkingDirectory": {"/tmp"},
            "StandardOutPath": date(2026, 1, 1),
        }
        svc = {"id": "job", "name": "job", "kind": "launchd", "state": "ok", "actions": ["detail"]}
        with (
            patch.object(sms, "find_service", return_value=svc),
            patch.object(sms, "override", return_value={}),
            patch.object(sms, "_load_plist", return_value=pl),
            patch.object(sms, "_plist_path", return_value=Path("/tmp/job.plist")),
            patch.object(sms, "sh", return_value=(0, b"state = running\n", b"")),
        ):
            detail = sms.service_detail("job")
        _json(detail)
        self.assertIsInstance(detail["launchctl"], str)
        self.assertIsInstance(detail["program"], str)

    def test_docker_inspect_infinity_does_not_500_json(self):
        insp = {
            "Created": float("inf"),
            "Config": {"Image": "nginx", "Env": ["FOO=1"], "Labels": {}},
            "State": {"Status": "running", "StartedAt": datetime(2026, 1, 1)},
            "HostConfig": {"RestartPolicy": {"Name": "always"}, "NetworkMode": "bridge"},
            "NetworkSettings": {
                "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": float("inf")}]},
            },
            "Mounts": [{"Source": b"/data", "Destination": "/x", "Type": "bind", "RW": True}],
        }
        svc = {"id": "web", "name": "web", "kind": "container", "state": "ok", "actions": ["detail"]}
        with (
            patch.object(sms, "find_service", return_value=svc),
            patch.object(sms, "override", return_value={}),
            patch.object(sms, "_docker_inspect", return_value=insp),
        ):
            detail = sms.service_detail("web")
        _json(detail)
        self.assertIsNone(detail.get("created"))
        self.assertIsInstance(detail.get("started_at"), str)

    def test_adopt_defaults_inf_pid_ports_do_not_500(self):
        auto = {
            "id": "auto:1", "name": "node", "kind": "auto", "url": "http://x",
            "meta": {
                "pid": float("inf"),
                "process": "node",
                "ports": [float("inf"), 3000],
                "port": float("inf"),
            },
        }
        with (
            patch.object(sms, "_full_process_name", return_value=""),
            patch.object(sms, "_process_command_path", return_value=""),
            patch.object(sms, "configured_signatures", return_value=[]),
        ):
            defaults = sms.adopt_defaults(auto)
        self.assertEqual(defaults["ports"], [3000])
        _json(defaults)

    def test_update_override_inf_port_is_coded_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            sms.update_override("nginx", {"port": float("inf")})
        self.assertEqual(_code(ctx.exception), "services.bad_port")


class ServiceLogsLeftoverTests(unittest.TestCase):
    def test_inf_lines_is_clamped_not_500(self):
        with (
            patch.object(sms, "find_service", return_value={"id": "c", "kind": "container", "name": "c"}),
            patch.object(sms, "DOCKER", "/usr/bin/true"),
            patch.object(sms, "sh", return_value=(0, b"hello\n", "")),
        ):
            got = sms.service_logs("c", lines=float("inf"))
        self.assertEqual(got["lines"], 150)
        self.assertEqual(got["log"], "hello")
        _json(got)

    def test_huge_plist_does_not_oom_load(self):
        """``open(rb)`` of leftover multi-MB LaunchAgent used to OOM GET /api/services."""
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            huge = agents / "com.real.job.plist"
            huge.write_bytes(b"x" * (2 * 1024 * 1024))
            with patch.object(sms, "AGENTS_DIR", agents):
                self.assertEqual(sms._plist_label(huge), "com.real.job")
                self.assertEqual(sms._load_plist("com.real.job"), {})
                self.assertEqual(sms._plist_path("com.real.job"), huge)

    def test_plist_is_file_eio_does_not_500_detail_lookup(self):
        with patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")):
            self.assertIsNone(sms._plist_path("com.example.x"))

    def test_path_home_runtimeerror_does_not_500_logs(self):
        with (
            patch.object(sms, "find_service", return_value={"id": "l", "kind": "launchd", "name": "l"}),
            patch.object(sms, "_load_plist", return_value={}),
            patch.object(sms, "_plist_path", return_value=Path("/tmp/x.plist")),
            patch.object(Path, "home", side_effect=RuntimeError("HOME")),
            patch.object(sms, "sh", return_value=(0, b"print", b"")),
        ):
            got = sms.service_logs("l")
        self.assertIsInstance(got["log"], str)
        _json(got)

    def test_path_home_nul_does_not_500_logs(self):
        with (
            patch.object(sms, "find_service", return_value={"id": "l", "kind": "launchd", "name": "l"}),
            patch.object(sms, "_load_plist", return_value={}),
            patch.object(sms, "_plist_path", return_value=Path("/tmp/x.plist")),
            patch.object(Path, "home", side_effect=ValueError("embedded null")),
            patch.object(sms, "sh", return_value=(0, b"print", b"")),
        ):
            got = sms.service_logs("l")
        self.assertIsInstance(got["log"], str)
        _json(got)

    def test_guess_is_file_eio_does_not_500_logs(self):
        with (
            patch.object(sms, "find_service", return_value={"id": "l", "kind": "launchd", "name": "l"}),
            patch.object(sms, "_load_plist", return_value={}),
            patch.object(sms, "_plist_path", return_value=Path("/tmp/x.plist")),
            patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")),
            patch.object(sms, "sh", return_value=(0, "print", "")),
        ):
            got = sms.service_logs("l")
        self.assertIsInstance(got["log"], str)
        _json(got)

    def test_script_logs_recursing_exc_does_not_500(self):
        """str(e) RecursionError used to 500 GET /api/services logs."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with (
            patch.object(sms, "find_service", return_value={"id": "s", "kind": "script", "name": "s"}),
            patch("hub.logs_svc.log_sources", side_effect=Recursing()),
        ):
            got = sms.service_logs("s")
        _json(got)
        self.assertEqual(got["log"], "Recursing")

    def test_tail_file_expanduser_runtimeerror_does_not_500(self):
        """``os.path.expanduser`` RuntimeError used to 500 GET /api/services logs."""
        with patch.object(
            sms.os.path, "expanduser", side_effect=RuntimeError("no home"),
        ):
            text = sms._tail_file("~/Library/Logs/ok.log")
        self.assertIn("invalid log path", text)

    def test_tail_file_recursing_exc_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 GET /api/services logs."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(sms, "tail_file_lines", side_effect=Recursing()),
        ):
            text = sms._tail_file("/tmp/ok.log")
        _starlette({"log": text})
        self.assertIn("read failed", text)
        self.assertIn("Recursing", text)


class UninstallResolveLeftoverTests(unittest.TestCase):
    def test_workdir_symlink_loop_does_not_500_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agents = root / "LaunchAgents"
            agents.mkdir()
            services = root / "Services"
            services.mkdir()
            loop = _symlink_loop(services)
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
                "WorkingDirectory": str(loop),
            }))
            with (
                patch.object(uns, "AGENTS_DIR", agents),
                patch.object(uns, "SERVICES_ROOT", services),
            ):
                info = uns.preview("com.example.app")
            self.assertEqual(info["label"], "com.example.app")
            self.assertFalse(info["can_remove_data"])
            _json(info)

    def test_agents_dir_symlink_loop_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with patch.object(uns, "AGENTS_DIR", loop):
                with self.assertRaises(HTTPException) as ctx:
                    uns.preview("com.example.app")
            self.assertEqual(_code(ctx.exception), "services.uninstall_not_supported")

    def test_preview_is_file_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            real_is_file = Path.is_file

            def boom(self):
                if self.name.endswith(".plist"):
                    raise OSError(5, "I/O error")
                return real_is_file(self)

            with patch.object(uns, "AGENTS_DIR", agents), patch.object(Path, "is_file", boom):
                with self.assertRaises(HTTPException) as ctx:
                    uns.preview("com.example.app")
            self.assertIn(_code(ctx.exception), {
                "services.uninstall_failed",
                "services.uninstall_unknown",
                "services.uninstall_not_supported",
            })

    def test_preview_recursing_is_file_is_coded_not_500(self):
        """leftover ``str(exc)`` RecursionError used to 500 GET uninstall preview."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            real_is_file = Path.is_file

            def boom(self):
                if self.name.endswith(".plist"):
                    raise Recursing(5, "I/O error")
                return real_is_file(self)

            with patch.object(uns, "AGENTS_DIR", agents), patch.object(Path, "is_file", boom):
                with self.assertRaises(HTTPException) as ctx:
                    uns.preview("com.example.app")
            self.assertEqual(_code(ctx.exception), "services.uninstall_failed")
            json.dumps(ctx.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.assertEqual(ctx.exception.detail["params"]["error"], "Recursing")


class AutostartLeftoverTests(unittest.TestCase):
    def test_huge_plist_does_not_oom_read(self):
        """``open(rb)`` of leftover multi-MB LaunchAgent used to OOM GET /api/apps/autostart."""
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            huge = agents / "huge.plist"
            huge.write_bytes(b"x" * (2 * 1024 * 1024))
            (agents / "ok.plist").write_bytes(plistlib.dumps({
                "Label": "com.ok",
                "ProgramArguments": ["/bin/true"],
            }))
            with (
                patch.object(autostart_svc, "AGENTS_DIR", agents),
                patch.object(autostart_svc, "_loaded_labels", return_value=frozenset()),
                patch.object(
                    autostart_svc, "_resolve_script_agent", return_value=(None, None),
                ),
                patch.object(autostart_svc, "_launchctl_loaded", return_value=False),
            ):
                self.assertEqual(autostart_svc._read_plist(huge), {})
                items = autostart_svc._launchd_items()
            _json(items)
            labels = {row["label"] for row in items}
            self.assertIn("com.ok", labels)
            self.assertIn("huge", labels)

    def test_inf_plist_label_does_not_500_launchd_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "bad.plist").write_bytes(plistlib.dumps({
                "Label": float("inf"),
                "ProgramArguments": ["/bin/true"],
            }))
            (agents / "ok.plist").write_bytes(plistlib.dumps({
                "Label": "com.ok",
                "ProgramArguments": ["/bin/true"],
            }))
            with (
                patch.object(autostart_svc, "AGENTS_DIR", agents),
                patch.object(
                    autostart_svc, "_resolve_script_agent",
                    return_value=(agents / "nope.plist", "none"),
                ),
                patch.object(autostart_svc, "sh", return_value=(1, "", "")),
            ):
                items = autostart_svc._launchd_items(frozenset())
            labels = {i["label"] for i in items}
            self.assertIn("com.ok", labels)
            _json(items)

    def test_brew_inf_label_does_not_500_json(self):
        with (
            patch.object(autostart_svc, "_is_file", return_value=True),
            patch.object(
                autostart_svc, "brew_services_list",
                return_value=[{"name": "redis", "status": "started", "file": "/tmp/x.plist"}],
            ),
            patch.object(
                autostart_svc, "_read_plist",
                return_value={"Label": float("inf"), "RunAtLoad": True},
            ),
        ):
            items = autostart_svc._brew_service_items()
        self.assertTrue(items)
        self.assertIsInstance(items[0]["label"], str)
        _json(items)

    def test_is_dir_eio_does_not_500_launchd_items(self):
        with patch.object(Path, "is_dir", side_effect=OSError(5, "I/O error")):
            self.assertEqual(autostart_svc._launchd_items(frozenset()), [])

    def test_set_launchd_exists_eio_is_coded_not_500(self):
        with (
            patch.object(autostart_svc, "AGENTS_DIR", Path("/tmp/no-such-agents-dir")),
            patch.object(Path, "exists", side_effect=OSError(5, "I/O error")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                autostart_svc.set_launchd_autostart("com.ok", True)
        self.assertEqual(_code(ctx.exception), "autostart.plist_missing")

    def test_run_now_home_runtimeerror_is_coded_not_500(self):
        with patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            with self.assertRaises(HTTPException) as ctx:
                autostart_svc.run_autostart_now()
        self.assertEqual(_code(ctx.exception), "autostart.script_missing")

    def test_run_now_home_nul_is_coded_not_500(self):
        """Leftover NUL in HOME ValueError'd Path.home() and 500'd run-now."""
        with patch.object(Path, "home", side_effect=ValueError("embedded null")):
            with self.assertRaises(HTTPException) as ctx:
                autostart_svc.run_autostart_now()
        self.assertEqual(_code(ctx.exception), "autostart.script_missing")

    def test_script_status_home_nul_does_not_500(self):
        with patch.object(Path, "home", side_effect=ValueError("embedded null")):
            row = autostart_svc._script_status(frozenset())
        _json(row)
        self.assertIsNone(row["script"])

    def test_overview_leftover_inf_does_not_500_json(self):
        item = {
            "id": "docker-ctr:web", "kind": "docker", "name": "web",
            "label": "web", "autostart": True, "policy": float("inf"),
            "running": True, "state": "ok", "detail": "restart=inf",
            "project": {"x"}, "actions": ["enable"], "group": "Docker containers",
        }
        with (
            patch.object(autostart_svc, "_loaded_labels", return_value=frozenset()),
            patch.object(autostart_svc.overview, "invalidate"),
            patch.object(autostart_svc, "fan_out", return_value=(
                [item], [], [],
                {"id": "script:x", "kind": "script", "name": "s", "label": "x",
                 "autostart": False, "running": False, "plist": None, "script": None,
                 "detail": "", "actions": [], "group": "Login script"},
            )),
        ):
            snap = autostart_svc.overview(force=True)
        _json(snap)
        self.assertIsNone(snap["items"][1]["policy"])

    def test_overflow_strftime_does_not_500_overview_ts(self):
        """Leftover inf clock OverflowError'd GET /api/apps/autostart ``ts``."""
        with (
            patch("hub.util.time.strftime", side_effect=OverflowError),
            patch.object(autostart_svc, "_loaded_labels", return_value=frozenset()),
            patch.object(
                autostart_svc, "fan_out",
                return_value=(
                    [], [], [],
                    {"id": "script:x", "kind": "script", "name": "s", "label": "x",
                     "autostart": False, "running": False, "plist": None, "script": None,
                     "detail": "", "actions": [], "group": "Login script"},
                ),
            ),
        ):
            snap = autostart_svc.overview(force=True)
        _json(snap)
        json.dumps(snap, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(snap["ts"], "")

    def test_run_now_leftover_env_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` in env UnicodeEncodeError'd Popen and 500'd run-now."""
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            script = home / "Services" / "autostart.sh"
            script.parent.mkdir()
            script.write_text("#!/bin/sh\n")
            proc = type("P", (), {"pid": 4242})()
            leftover_env = {"PATH": "/bin", "HOME": str(home), "BAD": "x\ud800"}
            with (
                patch.object(autostart_svc, "user_home", return_value=home),
                patch.object(autostart_svc.os, "environ", leftover_env),
                patch("subprocess.Popen", return_value=proc) as popen,
            ):
                out = autostart_svc.run_autostart_now()
            self.assertTrue(out["ok"])
            env = popen.call_args.kwargs["env"]
            self.assertNotIn("BAD", env)
            self.assertNotIn("\ud800", "".join(env.values()))
            _starlette(out)

    def test_run_now_popen_valueerror_does_not_500(self):
        """Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError."""
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            script = home / "Services" / "autostart.sh"
            script.parent.mkdir()
            script.write_text("#!/bin/sh\n")
            with (
                patch.object(autostart_svc, "user_home", return_value=home),
                patch("subprocess.Popen", side_effect=UnicodeEncodeError(
                    "utf-8", "\ud800", 0, 1, "surrogates not allowed",
                )),
            ):
                out = autostart_svc.run_autostart_now()
            self.assertFalse(out["ok"])
            self.assertNotIn("\ud800", out["message"])
            _starlette(out)

    def test_run_now_str_recursion_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 POST autostart run-now."""
        class Boom(OSError):
            def __str__(self):
                raise RecursionError

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            script = home / "Services" / "autostart.sh"
            script.parent.mkdir()
            script.write_text("#!/bin/sh\n")
            with (
                patch.object(autostart_svc, "user_home", return_value=home),
                patch("subprocess.Popen", side_effect=Boom("boom")),
            ):
                out = autostart_svc.run_autostart_now()
            self.assertFalse(out["ok"])
            _starlette(out)

    def test_brew_surrogate_message_does_not_500(self):
        """Leftover ``\\ud800`` in brew stderr used to 500 PUT brew autostart."""
        with (
            patch.object(autostart_svc, "_is_file", return_value=True),
            patch.object(autostart_svc, "run_capped", return_value=(1, "fail\ud800")),
            patch.object(autostart_svc, "invalidate_brew_services"),
        ):
            out = autostart_svc.set_brew_autostart("redis", True)
        self.assertFalse(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        _starlette(out)


class ActionsRegistryLeftoverTests(unittest.TestCase):
    def test_glob_eio_does_not_500_registry(self):
        with (
            patch.object(actions, "cfg", return_value={"apps": [], "scripts": []}),
            patch("hub.actions.glob.glob", side_effect=OSError(5, "I/O error")),
            patch.object(actions, "sh", return_value=(0, "", "")),
        ):
            reg = actions.registry()
        self.assertIsInstance(reg, dict)

    def test_bytes_docker_names_do_not_500_registry(self):
        def fake_sh(cmd, timeout=10):
            joined = " ".join(str(c) for c in cmd)
            if "ps" in joined:
                return 0, b"web\napi\n", b""
            return 1, "", ""

        with (
            patch.object(actions, "cfg", return_value={"apps": [], "scripts": []}),
            patch("hub.actions.glob.glob", return_value=[]),
            patch.object(actions, "sh", side_effect=fake_sh),
        ):
            reg = actions.registry()
        self.assertIn("web", reg)
        self.assertIn("api", reg)

    def test_script_start_popen_valueerror_does_not_500(self):
        """Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError."""
        with (
            patch.object(actions, "registry", return_value={
                "backup": ("script", {"start": "/usr/bin/true"}),
            }),
            patch.object(
                actions.subprocess, "Popen",
                side_effect=UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"),
            ),
        ):
            rc, _out, err = actions.run_action("backup", "start")
        self.assertEqual(rc, 1)
        self.assertNotIn("\ud800", err)
        _starlette({"ok": False, "message": err})

    def test_script_start_passes_utf8_env(self):
        source = Path(actions.__file__).read_text(encoding="utf-8")
        start = source.index("if kind == \"script\":")
        body = source[start: start + 1800]
        self.assertIn("env=utf8_env()", body)

    def test_huge_plist_does_not_oom_registry(self):
        """``open(rb)`` of leftover multi-MB LaunchAgent used to OOM actions.registry."""
        with tempfile.TemporaryDirectory() as tmp:
            huge = Path(tmp) / "huge.plist"
            huge.write_bytes(b"x" * (2 * 1024 * 1024))
            with (
                patch.object(actions, "AGENTS_DIR", tmp),
                patch.object(actions, "cfg", return_value={"apps": [], "scripts": []}),
                patch.object(actions, "sh", return_value=(0, "", "")),
            ):
                reg = actions.registry()
        self.assertEqual(reg["huge"][0], "launchd")
        _json({k: v[0] for k, v in reg.items()})

    def test_surrogate_plist_label_does_not_500_registry(self):
        """Leftover ``\\ud800`` in a LaunchAgent Label used to 500 action JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "job.plist"
            path.write_bytes(plistlib.dumps({
                "Label": "com.example.job",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            with (
                patch.object(actions, "AGENTS_DIR", tmp),
                patch.object(actions, "cfg", return_value={"apps": [], "scripts": []}),
                patch.object(actions, "sh", return_value=(0, "", "")),
                patch.object(actions, "_plist_dict", return_value={"Label": "job\ud800"}),
            ):
                reg = actions.registry()
        self.assertTrue(all("\ud800" not in key for key in reg))
        _starlette({k: v[0] for k, v in reg.items()})

    def test_surrogate_docker_name_does_not_500_registry(self):
        def fake_sh(cmd, timeout=10):
            joined = " ".join(str(c) for c in cmd)
            if "ps" in joined:
                return 0, "web\ud800\n", ""
            return 1, "", ""

        with (
            patch.object(actions, "cfg", return_value={"apps": [], "scripts": []}),
            patch("hub.actions.glob.glob", return_value=[]),
            patch.object(actions, "sh", side_effect=fake_sh),
        ):
            reg = actions.registry()
        self.assertTrue(all("\ud800" not in key for key in reg))
        self.assertTrue(any("web" in key for key in reg))
        _starlette({k: v[0] for k, v in reg.items()})

    def test_surrogate_yaml_app_id_does_not_500_registry(self):
        with (
            patch.object(actions, "cfg", return_value={
                "apps": [{"id": "app\ud800"}],
                "scripts": [{"id": "script\ud800", "start": "/usr/bin/true"}],
            }),
            patch("hub.actions.glob.glob", return_value=[]),
            patch.object(actions, "sh", return_value=(1, "", "")),
        ):
            reg = actions.registry()
        self.assertTrue(all("\ud800" not in key for key in reg))
        _starlette({k: v[0] for k, v in reg.items()})

    def test_inf_target_does_not_500_run_action(self):
        """YAML leftover ``.inf`` used to AttributeError ``startswith`` on start."""
        with (
            patch.object(actions, "registry", return_value={}),
            patch("hub.vms_svc.vm_action", return_value={"ok": False, "message": "no\ud800"}),
        ):
            rc, message, _err = actions.run_action(float("inf"), "start")
        self.assertEqual(rc, 1)
        self.assertNotIn("\ud800", message)
        _starlette({"ok": False, "message": message})


class CredentialsLeftoverTests(unittest.TestCase):
    def test_infinity_index_does_not_500_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "service-credentials.json"
            index.write_text(
                '{"native:x": {"service_id": "native:x", "username": "a",'
                ' "updated_at": Infinity, "url": Infinity,'
                ' "notes": "n", "display_name": "X",'
                ' "adapter": "generic", "applied": true}}\n',
                encoding="utf-8",
            )
            with (
                patch.object(creds, "INDEX_FILE", index),
                patch.object(creds, "_keychain_has", return_value=True),
            ):
                got = creds.get("native:x")
            self.assertIsNone(got["updated_at"])
            self.assertEqual(got["url"], "")
            _json(got)

    def test_public_item_dates_bytes_set_do_not_500_json(self):
        got = creds.public_item({
            "service_id": "x",
            "display_name": {"n": 1},
            "username": b"admin",
            "url": datetime(2026, 1, 1),
            "notes": {"secret"},
            "updated_at": float("inf"),
            "adapter": "generic",
        })
        _json(got)
        self.assertEqual(got["display_name"], "x")
        self.assertIsNone(got["updated_at"])

    def test_filebrowser_exists_eio_is_coded_not_500(self):
        with patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(HTTPException) as ctx:
                creds.apply_filebrowser("admin", "password1")
        self.assertEqual(_code(ctx.exception), "credentials.filebrowser_missing")

    def test_save_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; PUT credentials used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "service-credentials.json"
            with (
                patch.object(creds, "INDEX_FILE", index),
                patch.object(creds.json, "dumps", side_effect=RecursionError),
            ):
                creds._save({"native:x": {"service_id": "native:x"}})
            self.assertFalse(index.exists())

    def test_recursing_index_save_oserror_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 PUT /api/apps/credentials."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "service-credentials.json"
            with (
                patch.object(creds, "INDEX_FILE", index),
                patch.object(creds, "_security", return_value=(0, "ok")),
                patch.object(creds, "_save", side_effect=Recursing(28, "ENOSPC")),
                patch.object(creds, "_delete_keychain"),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    creds.store(
                        "native:native-filebrowser",
                        display_name="FileBrowser",
                        username="admin",
                        password="secret-password",
                    )
        self.assertEqual(_code(ctx.exception), "credentials.index_save_failed")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["error"], "Recursing")

    def test_inf_clock_does_not_500_stamp(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 PUT credentials."""
        with patch.object(creds.time, "time", return_value=float("inf")):
            self.assertEqual(creds._stamp_now(), 0)

    def test_teslamate_is_file_eio_is_coded_not_500(self):
        with patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(HTTPException) as ctx:
                creds.apply_teslamate("teslamate", "password1")
        self.assertEqual(_code(ctx.exception), "credentials.teslamate_gateway_missing")

    def test_filebrowser_bytes_err_is_coded_not_500(self):
        """Leftover bytes from ``filebrowser users update`` used to TypeError ``.replace``."""
        from hub import files_svc

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(files_svc, "filebrowser_status", return_value={"running": False}),
            patch("hub.util.sh", return_value=(1, b"out", b"permission denied")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                creds.apply_filebrowser("admin", "password1")
        self.assertEqual(_code(ctx.exception), "credentials.filebrowser_update_failed")
        _json(ctx.exception.detail)


class ServicesBulkLeftoverTests(unittest.TestCase):
    def test_leftover_inf_and_surrogate_output_do_not_500(self):
        """``sh`` leftover inf / ``\\ud800`` used to 500 POST /api/services/bulk-action."""
        with patch.object(
            actions, "run_action", return_value=(1, float("inf"), "err\ud800"),
        ):
            out = services_bulk(BulkActionBody(action="start", ids=["s1"]))
        _starlette(out)
        self.assertEqual(out["fail_count"], 1)
        self.assertNotIn("\ud800", out["results"][0]["message"])

    def test_leftover_bytes_output_does_not_500(self):
        with patch.object(actions, "run_action", return_value=(0, b"started", None)):
            out = services_bulk(BulkActionBody(action="start", ids=["s1"]))
        _starlette(out)
        self.assertTrue(out["results"][0]["ok"])
        self.assertEqual(out["results"][0]["message"], "started")


class UninstallBootoutLeftoverTests(unittest.TestCase):
    def test_bytes_bootout_detail_does_not_500(self):
        """Leftover ``launchctl bootout`` bytes used to TypeError POST uninstall JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            backups = Path(tmp) / "uninstalled-agents"
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            with (
                patch.object(uns, "AGENTS_DIR", agents),
                patch.object(uns, "BACKUP_DIR", backups),
                patch.object(uns, "_forget_override"),
                patch.object(uns, "sh", return_value=(0, b"booted out", None)),
            ):
                out = uns.uninstall("com.example.app")
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["detail"], str)
        _json(out)

    def test_huge_plist_does_not_oom_preview(self):
        """``Path.read_bytes()`` of leftover multi-MB plist used to OOM uninstall preview."""
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            (agents / "com.example.app.plist").write_bytes(b"x" * (2 * 1024 * 1024))
            with patch.object(uns, "AGENTS_DIR", agents):
                info = uns.preview("com.example.app")
            self.assertEqual(info["label"], "com.example.app")
            self.assertEqual(info["program"], "")
            _json(info)

    def test_recursing_preview_is_file_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 GET uninstall preview."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            real_is_file = Path.is_file

            def boom(self):
                if self.name.endswith(".plist"):
                    raise Recursing(5, "I/O error")
                return real_is_file(self)

            with patch.object(uns, "AGENTS_DIR", agents), patch.object(Path, "is_file", boom):
                with self.assertRaises(HTTPException) as ctx:
                    uns.preview("com.example.app")
        self.assertEqual(_code(ctx.exception), "services.uninstall_failed")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["error"], "Recursing")

    def test_recursing_uninstall_mkdir_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST uninstall backup mkdir."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            backups = Path(tmp) / "uninstalled-agents"
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            with (
                patch.object(uns, "AGENTS_DIR", agents),
                patch.object(uns, "BACKUP_DIR", backups),
                patch.object(Path, "mkdir", side_effect=Recursing(28, "ENOSPC")),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    uns.uninstall("com.example.app")
        self.assertEqual(_code(ctx.exception), "services.uninstall_failed")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["error"], "Recursing")

    def test_recursing_uninstall_move_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST uninstall plist archive."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp) / "LaunchAgents"
            agents.mkdir()
            backups = Path(tmp) / "uninstalled-agents"
            (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
                "Label": "com.example.app",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            with (
                patch.object(uns, "AGENTS_DIR", agents),
                patch.object(uns, "BACKUP_DIR", backups),
                patch.object(uns, "_forget_override"),
                patch.object(uns, "sh", return_value=(0, "booted out", "")),
                patch.object(uns.shutil, "move", side_effect=Recursing(5, "I/O error")),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    uns.uninstall("com.example.app")
        self.assertEqual(_code(ctx.exception), "services.uninstall_failed")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["error"], "Recursing")


if __name__ == "__main__":
    unittest.main()
