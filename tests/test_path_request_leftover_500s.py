"""Leftover Path.exists/is_file/is_dir/resolve 500s on remaining request paths.

``Path.exists`` / ``is_file`` / ``is_dir`` re-raise EIO/ESTALE (pathlib only
swallows ENOENT/ELOOP).  ``Path.resolve`` raises RuntimeError on a leftover
symlink loop.  Those used to 500 GET /api/alerts, GET /api/audit/auth,
GET /api/containers, GET /api/stacks, POST compose create/save, GET
/api/wireguard, PUT /api/settings, and uninstall preview.
"""
from __future__ import annotations

import json
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import (
    alerts,
    audit,
    cloudflared_svc,
    compose_svc,
    config,
    containers_svc,
    services_manage_svc,
    services_uninstall_svc,
    wireguard_svc,
)
from hub.app_factory import create_app
from hub import wireguard_net_svc as wnet
from hub import wireguard_wstunnel as wst


EIO = OSError(5, "I/O error")


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class AlertsAuditPathEioTests(unittest.TestCase):
    def test_list_alerts_exists_eio_does_not_500(self):
        """Dying-mount ``ALERTS_FILE.exists`` EIO used to 500 GET /api/alerts."""
        with mock.patch.object(Path, "exists", side_effect=EIO):
            rows = alerts.list_alerts(20)
        self.assertEqual(rows, [])
        _json(rows)

    def test_load_state_exists_eio_does_not_500(self):
        """Dying-mount ``STATE_FILE.exists`` EIO used to 500 POST /api/alerts/check."""
        with mock.patch.object(Path, "exists", side_effect=EIO):
            self.assertEqual(alerts._load_state(), {})

    def test_audit_recent_exists_eio_does_not_500(self):
        """Dying-mount ``AUDIT_PATH.exists`` EIO used to 500 GET /api/audit/auth."""
        with mock.patch.object(Path, "exists", side_effect=EIO):
            rows = audit.recent(10)
        self.assertEqual(rows, [])
        _json(rows)


class ContainersComposePathLeftoverTests(unittest.TestCase):
    def test_update_status_exists_eio_does_not_500(self):
        """Dying-mount ``docker-update-status.json`` exists EIO used to 500 GET /api/containers."""
        with mock.patch.object(Path, "exists", side_effect=EIO):
            self.assertEqual(containers_svc._load_update_status(), {})

    def test_stack_paths_exists_eio_does_not_500(self):
        """Dying-mount ``compose.exists`` EIO used to 500 GET /api/stacks."""
        with (
            mock.patch.object(
                containers_svc, "cfg",
                return_value={"stacks": [{"id": "x", "name": "x", "path": "/tmp"}]},
            ),
            mock.patch.object(Path, "exists", side_effect=EIO),
            mock.patch.object(Path, "home", return_value=Path("/tmp")),
        ):
            stacks = containers_svc._stack_paths()
        _json(stacks)
        self.assertTrue(any(s.get("id") == "x" for s in stacks))

    def test_stack_paths_resolve_runtimeerror_does_not_500(self):
        """``Path.resolve`` RuntimeError on a leftover loop used to 500 GET /api/stacks."""
        with (
            mock.patch.object(
                containers_svc, "cfg",
                return_value={"stacks": [{"id": "x", "name": "x", "path": "/tmp"}]},
            ),
            mock.patch.object(Path, "resolve", side_effect=RuntimeError("symlink loop")),
            mock.patch.object(Path, "home", return_value=Path("/tmp")),
        ):
            stacks = containers_svc._stack_paths()
        _json(stacks)
        self.assertTrue(any(s.get("id") == "x" for s in stacks))

    def test_create_stack_exists_eio_is_not_500(self):
        """Dying-mount ``root.exists`` EIO used to 500 POST compose create."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        with (
            mock.patch.object(Path, "home", return_value=home),
            mock.patch.object(
                compose_svc, "validate_compose_text", return_value={"ok": True}
            ),
            mock.patch("hub.config.mutate", lambda fn: None),
            mock.patch.object(compose_svc, "inv"),
            mock.patch.object(Path, "exists", side_effect=EIO),
        ):
            out = compose_svc.create_stack(
                "s1", "S1", "services:\n  x:\n    image: a:1\n"
            )
        self.assertTrue(out["ok"])
        _json(out)

    def test_save_compose_resolve_runtimeerror_is_coded_not_500(self):
        """``Path.resolve`` RuntimeError on a leftover loop used to 500 compose save."""
        with mock.patch.object(
            compose_svc, "_find_stack",
            return_value={
                "id": "x", "name": "x", "path": "/tmp/x",
                "compose_path": "/tmp/x/docker-compose.yml",
            },
        ), mock.patch.object(
            Path, "resolve", side_effect=RuntimeError("symlink loop")
        ):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.save_compose("x", "services: {}\n", validate=False)
        self.assertEqual(_code(ctx.exception), "container.no_compose_file")

    def test_stack_paths_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 GET /api/stacks after config rows."""
        with (
            mock.patch.object(
                containers_svc, "cfg",
                return_value={"stacks": [{"id": "x", "name": "x", "path": "/tmp"}]},
            ),
            mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")),
        ):
            stacks = containers_svc._stack_paths()
        _json(stacks)
        self.assertTrue(any(s.get("id") == "x" for s in stacks))

    def test_create_stack_home_runtimeerror_is_coded_not_500(self):
        """``Path.home()`` RuntimeError used to 500 POST /api/compose."""
        with mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.create_stack(
                    "s1", "S1", "services:\n  x:\n    image: a:1\n"
                )
        self.assertEqual(_code(ctx.exception), "compose.invalid")

    def test_save_compose_home_runtimeerror_is_coded_not_500(self):
        """``Path.home()`` leftover used to 500 PUT compose save."""
        with mock.patch.object(
            compose_svc, "_find_stack",
            return_value={
                "id": "x", "name": "x", "path": "/tmp/x",
                "compose_path": "/tmp/x/docker-compose.yml",
            },
        ), mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.save_compose("x", "services: {}\n", validate=False)
        self.assertEqual(_code(ctx.exception), "container.no_compose_file")


class ServicesPathEioTests(unittest.TestCase):
    def test_docker_inspect_exists_eio_does_not_500(self):
        """Dying-mount ``Path(DOCKER).exists`` EIO used to 500 service detail."""
        with mock.patch.object(Path, "exists", side_effect=EIO):
            self.assertEqual(services_manage_svc._docker_inspect("nginx"), {})

    def test_uninstall_preview_tree_exists_eio_does_not_500(self):
        """Dying-mount ``tree.exists`` EIO used to 500 uninstall preview."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        agents = root / "LaunchAgents"
        agents.mkdir()
        services = root / "Services" / "app"
        services.mkdir(parents=True)
        (agents / "com.example.app.plist").write_bytes(plistlib.dumps({
            "Label": "com.example.app",
            "ProgramArguments": [str(services / "bin")],
            "WorkingDirectory": str(services),
        }))
        with (
            mock.patch.object(services_uninstall_svc, "AGENTS_DIR", agents),
            mock.patch.object(services_uninstall_svc, "SERVICES_ROOT", root / "Services"),
            mock.patch.object(Path, "exists", side_effect=EIO),
        ):
            info = services_uninstall_svc.preview("com.example.app")
        self.assertEqual(info["label"], "com.example.app")
        self.assertFalse(info["can_remove_data"])
        _json(info)


class WireGuardPathEioTests(unittest.TestCase):
    def test_installation_is_dir_eio_does_not_500(self):
        """Dying-mount ``conf_dir().is_dir`` EIO used to 500 GET /api/wireguard."""
        with mock.patch.object(Path, "is_dir", side_effect=EIO):
            info = wireguard_svc.installation()
        self.assertIn("installed", info)
        _json(info)

    def test_runtime_state_exists_eio_does_not_500(self):
        with (
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(wireguard_svc, "_sockets", return_value=[]),
            mock.patch.object(Path, "exists", side_effect=EIO),
        ):
            state = wireguard_svc.runtime_state("wg0")
        self.assertFalse(state["name_file_present"])
        self.assertFalse(state["live"])
        _json(state)

    def test_write_conf_exists_eio_does_not_500(self):
        with (
            mock.patch.object(
                wireguard_svc, "server_identity",
                return_value={
                    "private_key": "k", "public_key": "p",
                    "address": "10.10.0.1/24", "listen_port": 51820,
                },
            ),
            mock.patch.object(wireguard_svc, "render_conf", return_value="x"),
            mock.patch.object(
                wireguard_svc, "conf_path", return_value=Path("/tmp/wg0.conf")
            ),
            mock.patch.object(wireguard_svc, "replace_secret_text"),
            mock.patch.object(Path, "exists", side_effect=EIO),
        ):
            path = wireguard_svc._write_conf([])
        self.assertEqual(path, Path("/tmp/wg0.conf"))

    def test_interface_action_exists_eio_is_coded_not_500(self):
        with (
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(
                wireguard_svc, "conf_path", return_value=Path("/tmp/wg0.conf")
            ),
            mock.patch.object(Path, "exists", side_effect=EIO),
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.interface_action("up")
        self.assertEqual(ctx.exception.code, "wg.no_conf")

    def test_wstunnel_is_file_eio_does_not_500(self):
        with (
            mock.patch.object(wst, "live", return_value={
                "pid": 0, "listen": "", "restrict_to": "", "plist": "",
                "binary": "", "running": False,
            }),
            mock.patch.object(wst, "local_ipv4s", return_value=frozenset()),
            mock.patch.object(Path, "is_file", side_effect=EIO),
        ):
            snap = wst.status({**wireguard_svc.DEFAULTS})
        self.assertFalse(snap["binary_ok"])
        _json(snap)

    def test_nat_installed_exists_eio_does_not_500(self):
        with (
            mock.patch.object(Path, "exists", side_effect=EIO),
            mock.patch.object(Path, "read_text", return_value=""),
            mock.patch.object(wnet, "pf_conf_valid", return_value={"ok": True, "message": ""}),
            mock.patch.object(wnet, "nat_active", return_value=False),
        ):
            info = wnet.nat_installed()
        self.assertFalse(info["anchor_exists"])
        _json(info)

    def test_daemon_state_exists_eio_does_not_500(self):
        with (
            mock.patch.object(
                wireguard_svc, "settings", return_value={**wireguard_svc.DEFAULTS}
            ),
            mock.patch.object(wnet, "sh", return_value=(1, "", "")),
            mock.patch.object(wnet, "sudo_capture", return_value=(1, "", "")),
            mock.patch.object(wnet, "loaded_labels", return_value=set()),
            mock.patch.object(Path, "exists", side_effect=EIO),
        ):
            info = wnet.daemon_state()
        self.assertFalse(info["installed"])
        _json(info)

    def test_cloudflared_bin_is_file_eio_is_coded_not_500(self):
        with (
            mock.patch.object(Path, "is_file", side_effect=EIO),
            mock.patch.object(cloudflared_svc, "sh", return_value=(0, "", "")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc._bin()
        self.assertEqual(_code(ctx.exception), "cloudflared.not_installed")


class LegacyIndexReadTextEioTests(unittest.TestCase):
    def test_legacy_index_read_text_eio_does_not_500(self):
        """Dying-mount ``LEGACY_INDEX`` EIO used to 500 GET / without a SPA."""
        from fastapi.testclient import TestClient

        missing = Path("/tmp/serverhub-no-static-leftover")
        # The CSP is derived from the shell on disk and memoised for 30s
        # process-wide, so serving a request with STATIC_DIR pointed at
        # nothing leaves a hash-less policy behind for whoever runs next.
        # That made the CSP suite fail whenever it happened to start inside
        # the window -- a flake that depended only on how fast the run was.
        from hub import app_factory

        app_factory._csp_header.invalidate()
        self.addCleanup(app_factory._csp_header.invalidate)
        with (
            mock.patch("hub.app_factory.STATIC_DIR", missing),
            mock.patch("hub.app_factory.LEGACY_INDEX", missing / "index.html"),
        ):
            app = create_app()
            with mock.patch.object(Path, "is_file", side_effect=EIO):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/")
        self.assertLess(resp.status_code, 500)

    def test_legacy_index_does_not_slurp_the_file(self):
        """``Path.read_text()`` of leftover multi-MB index.html used to OOM GET /."""
        from hub import app_factory

        source = Path(app_factory.__file__).read_text()
        start = source.index("def index_legacy")
        body = source[start: start + 700]
        self.assertIn("FileResponse", body)
        self.assertNotIn("LEGACY_INDEX.read_text", body)


class ConfigBakExistsEioTests(unittest.TestCase):
    def test_save_full_bak_exists_eio_does_not_500(self):
        """Dying-mount ``bak.exists`` EIO used to 500 PUT /api/settings."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfg-bak-eio-"))
        data = root / "data"
        data.mkdir()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        yaml_path = root / "services.yaml"
        yaml_path.write_text("settings: {a: 1}\n")
        lock = data / ".services.yaml.lock"
        with (
            mock.patch.object(config, "YAML_PATH", yaml_path),
            mock.patch.object(config, "DATA_DIR", data),
            mock.patch.object(config, "_LOCK_PATH", lock),
            mock.patch.object(config, "_cfg", {"mtime": None, "data": {}}),
        ):
            self.addCleanup(config.reload_cfg)
            with mock.patch.object(Path, "exists", side_effect=EIO):
                config.save_full({"settings": {"a": 2}})
            self.assertEqual(config.cfg()["settings"]["a"], 2)


if __name__ == "__main__":
    unittest.main()
