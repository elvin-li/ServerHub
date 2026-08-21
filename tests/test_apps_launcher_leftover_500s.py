"""Leftover request-path 500s on Apps inventory and GET /api/launcher.

Dying-mount ``is_dir`` / ``exists`` EIO and a leftover ``\\ud800`` in a
LaunchAgent label or launchctl job state each used to raise on the request
path or fail Starlette's UTF-8 encode (``allow_nan=False``).
"""
from __future__ import annotations

import errno
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import apps_manage_svc, launcher_svc


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class AppsManagedLeftoverTests(unittest.TestCase):
    def test_huge_launchd_plist_does_not_oom_managed(self):
        """``Path.read_bytes()`` of leftover multi-MB plist used to OOM GET /api/apps."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        huge = tmp / "com.example.app.plist"
        huge.write_bytes(b"x" * (2 * 1024 * 1024))
        listing = mock.Mock(pid_for=lambda _l: None, loaded=set(), jobs={})
        with (
            mock.patch("hub.paths.AGENTS_DIR", tmp),
            mock.patch.object(apps_manage_svc, "_catalog_launchd_labels", return_value=set()),
            mock.patch("hub.launchd_cache.listing", return_value=listing),
        ):
            rows = apps_manage_svc._launchd_apps()
        _starlette(rows)

    def test_vm_logs_leftover_inf_does_not_500(self):
        """json.dumps of leftover Infinity used to 500 GET /api/apps/.../logs."""
        with mock.patch.object(apps_manage_svc, "_vm_detail", return_value={
            "name": "box",
            "load": float("inf"),
            "ips": [float("nan")],
        }):
            out = apps_manage_svc._vm_logs("box")
        self.assertTrue(out["ok"])
        self.assertNotIn("Infinity", out["log"])
        _starlette(out)

    def test_safe_payload_strips_surrogates(self):
        """JSON ``\\ud800`` used to UnicodeEncodeError GET /api/apps/managed."""
        out = apps_manage_svc._safe_payload({
            "name": "app\ud800",
            "items": [{"name": "x\ud800", "\ud800": 1}],
        })
        self.assertNotIn("\ud800", out["name"])
        self.assertNotIn("\ud800", out["items"][0]["name"])
        _starlette(out)

    def test_launchd_is_dir_eio_does_not_500(self):
        """Dying-mount ``AGENTS_DIR.is_dir`` EIO used to 500 GET /api/apps/managed."""
        with mock.patch.object(Path, "is_dir", side_effect=OSError(errno.EIO, "I/O error")):
            rows = apps_manage_svc._launchd_apps()
        self.assertEqual(rows, [])
        _starlette(rows)

    def test_compose_exists_eio_does_not_500_stacks(self):
        """Dying-mount ``compose.exists`` EIO used to 500 GET /api/apps/managed."""
        with (
            mock.patch("hub.containers_svc.list_stacks", return_value=[{
                "id": "x", "name": "X", "path": "/tmp/x", "status": "down",
            }]),
            mock.patch("hub.containers_svc.list_containers", return_value={"containers": []}),
            mock.patch.object(Path, "exists", side_effect=OSError(errno.EIO, "I/O error")),
        ):
            rows = apps_manage_svc._docker_stacks()
        _starlette(rows)
        self.assertEqual(rows[0]["source_id"], "x")

    def test_recursing_container_log_does_not_500(self):
        """``str(exc)`` RecursionError used to 500 GET /api/apps/.../logs."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        reader = apps_manage_svc._container_log(20)
        with mock.patch.object(apps_manage_svc, "docker", side_effect=Recursing()):
            text = reader("web")
        _starlette({"log": text})
        self.assertEqual(text, "Recursing")

    def test_overflow_strftime_does_not_500_inventory(self):
        """Leftover inf clock OverflowError'd GET /api/apps/managed ``ts``."""
        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(
                apps_manage_svc, "fan_out",
                return_value=([], [], [], [], False, "127.0.0.1"),
            ),
        ):
            out = apps_manage_svc.inventory(force=True)
        _starlette(out)
        self.assertEqual(out["ts"], "")

    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(apps_manage_svc._utf8_text(Recursing()), "Recursing")
        _starlette({"k": apps_manage_svc._utf8_text(Recursing())})


class LauncherLeftoverTests(unittest.TestCase):
    def test_is_file_eio_does_not_500_status(self):
        """Dying-mount ``plist.is_file`` EIO used to 500 GET /api/launcher."""
        with (
            mock.patch.object(Path, "is_file", side_effect=OSError(errno.EIO, "I/O error")),
            mock.patch.object(Path, "is_dir", side_effect=OSError(errno.EIO, "I/O error")),
            mock.patch.object(launcher_svc, "_job_state", return_value=None),
            mock.patch.object(launcher_svc, "_loaded", return_value=False),
            mock.patch.object(launcher_svc, "_app_running", return_value=False),
        ):
            st = launcher_svc.status()
        _starlette(st)
        self.assertFalse(st["panel_registered"])
        self.assertFalse(st["login_enabled"])
        self.assertFalse(st["app_installed"])

    def test_surrogate_job_state_does_not_500_status(self):
        """A leftover ``\\ud800`` in launchctl state used to 500 GET /api/launcher."""
        with (
            mock.patch.object(launcher_svc, "_job_state", return_value="running\ud800"),
            mock.patch.object(launcher_svc, "_app_path", return_value=None),
            mock.patch.object(launcher_svc, "_loaded", return_value=False),
            mock.patch.object(launcher_svc, "resolve_panel", return_value=(
                Path("/tmp/panel.plist"), "local.serverhub.panel",
            )),
            mock.patch.object(launcher_svc, "resolve_launcher", return_value=(
                Path("/tmp/launcher.plist"), "local.serverhub.launcher",
            )),
            mock.patch.object(launcher_svc, "resolve_legacy_menubar", return_value=(
                Path("/tmp/menubar.plist"), "local.serverhub.menubar",
            )),
        ):
            st = launcher_svc.status()
        self.assertNotIn("\ud800", st["panel_job_state"])
        _starlette(st)

    def test_set_login_home_runtimeerror_is_coded_not_500(self):
        """``Path.home()`` RuntimeError used to 500 PUT /api/launcher/login."""
        with (
            mock.patch.object(
                launcher_svc, "_app_path", return_value=Path("/Applications/ServerHub.app")
            ),
            mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")),
        ):
            out = launcher_svc.set_login_enabled(True)
        self.assertFalse(out["ok"])
        _starlette(out)

    def test_app_candidates_home_runtimeerror_does_not_raise(self):
        """``Path.home()`` leftover used to 500 import of launcher_svc."""
        with mock.patch.object(launcher_svc, "user_home", return_value=None):
            cands = launcher_svc._default_app_candidates()
        self.assertEqual(cands, (Path("/Applications/ServerHub.app"),))
        with (
            mock.patch.object(launcher_svc, "APP_CANDIDATES", cands),
            mock.patch.object(launcher_svc, "_job_state", return_value=None),
            mock.patch.object(launcher_svc, "_loaded", return_value=False),
        ):
            st = launcher_svc.status()
        _starlette(st)


class NativeLogsHomeLeftoverTests(unittest.TestCase):
    def test_native_logs_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 GET /api/apps/.../logs."""
        from hub import native_catalog  # import before Path.home is patched
        assert native_catalog is not None

        with (
            mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")),
            mock.patch.object(apps_manage_svc, "_exists", return_value=False),
            mock.patch.object(apps_manage_svc, "sh", return_value=(1, "", "")),
        ):
            got = apps_manage_svc._native_logs("native-filebrowser")
        self.assertIn("ok", got)
        _starlette(got)

    def test_launchd_logs_expanduser_runtimeerror_does_not_500(self):
        """``Path.expanduser`` RuntimeError used to 500 GET /api/apps/.../logs."""
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "com.ok.plist"
            plist.write_bytes(b"")
            with (
                mock.patch("hub.paths.AGENTS_DIR", Path(tmp)),
                mock.patch.object(
                    apps_manage_svc, "_plist_dict",
                    return_value={"StandardOutPath": "~/Library/Logs/ok.log"},
                ),
                mock.patch.object(Path, "expanduser", side_effect=RuntimeError("no home")),
            ):
                got = apps_manage_svc._launchd_logs("com.ok")
        self.assertTrue(got["ok"])
        self.assertIn("invalid path", got["log"])
        _starlette(got)

    def test_native_logs_recursing_exc_does_not_500(self):
        """leftover ``{e}`` RecursionError used to 500 GET /api/apps/.../logs."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with (
            mock.patch.object(apps_manage_svc, "_exists", return_value=True),
            mock.patch.object(
                apps_manage_svc, "tail_file_lines", side_effect=Recursing(),
            ),
            mock.patch.object(apps_manage_svc, "sh", return_value=(1, "", "")),
        ):
            got = apps_manage_svc._native_logs("native-nginx")
        _starlette(got)
        self.assertTrue(got["ok"])
        self.assertIn("Recursing", got["log"])

    def test_launchd_logs_recursing_exc_does_not_500(self):
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "com.ok.plist"
            plist.write_bytes(b"")
            with (
                mock.patch("hub.paths.AGENTS_DIR", Path(tmp)),
                mock.patch.object(apps_manage_svc, "_is_file", return_value=True),
                mock.patch.object(
                    apps_manage_svc, "_plist_dict",
                    return_value={"StandardOutPath": str(Path(tmp) / "ok.log")},
                ),
                mock.patch.object(
                    apps_manage_svc, "tail_file_lines", side_effect=Recursing(),
                ),
            ):
                got = apps_manage_svc._launchd_logs("com.ok")
        _starlette(got)
        self.assertTrue(got["ok"])
        self.assertIn("Recursing", got["log"])


class PanelActionPopenLeftoverTests(unittest.TestCase):
    def test_popen_valueerror_does_not_500(self):
        """Leftover ``\\ud800`` in the launchctl label UnicodeEncodeError'd Popen."""
        with mock.patch.object(
            launcher_svc.subprocess, "Popen",
            side_effect=UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"),
        ):
            out = launcher_svc.schedule_panel_action("restart")
        self.assertFalse(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        _starlette(out)

    def test_panel_action_passes_utf8_env(self):
        source = Path(launcher_svc.__file__).read_text(encoding="utf-8")
        start = source.index("def schedule_panel_action")
        body = source[start: start + 2500]
        self.assertIn("env=utf8_env()", body)


if __name__ == "__main__":
    unittest.main()
