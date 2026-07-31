from __future__ import annotations

import asyncio
import json
import plistlib
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import call, patch

from fastapi import Depends, FastAPI, HTTPException, Request

from hub import auth, launcher_svc
from hub.auth import require_auth
from hub.routers.launcher_api import (
    LoginItemPatch,
    launcher_login,
    launcher_open,
    launcher_panel,
    launcher_status,
    router as launcher_router,
)


def request() -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/launcher",
        "headers": [],
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": ("127.0.0.1", 12345),
    })


async def _asgi_request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict | None = None,
) -> tuple[int, dict]:
    """Drive the real FastAPI router/dependency chain without TestClient/httpx."""
    app = FastAPI()
    app.include_router(launcher_router, dependencies=[Depends(require_auth)])
    body = json.dumps(payload).encode() if payload is not None else b""
    request_sent = False
    messages: list[dict] = []

    async def receive() -> dict:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (name.lower().encode(), value.encode())
            for name, value in (headers or {}).items()
        ],
        "server": ("localhost", 8086),
        "client": ("127.0.0.1", 12345),
        "state": {},
    }
    await app(scope, receive, send)
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return status, json.loads(response_body or b"{}")


def asgi_request(*args, **kwargs) -> tuple[int, dict]:
    return asyncio.run(_asgi_request(*args, **kwargs))


class LauncherServiceTests(unittest.TestCase):
    def test_http_anonymous_launcher_status_is_rejected(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
        ):
            status, body = asgi_request("GET", "/api/launcher")
        self.assertEqual(status, 401)
        self.assertEqual(body["detail"]["code"], "auth.login_required")

    def test_http_setup_required_blocks_status_and_mutations(self):
        headers = {"content-type": "application/json"}
        with (
            patch("hub.auth.setup_required", return_value=True),
            patch("hub.launcher_svc.status", return_value={"ok": True}) as get_status,
            patch("hub.launcher_svc.open_app", return_value={"ok": True}) as open_app,
            patch("hub.launcher_svc.set_login_enabled", return_value={"ok": True}) as set_login,
            patch("hub.launcher_svc.schedule_panel_action", return_value={"ok": True}) as panel_action,
        ):
            responses = [
                asgi_request("GET", "/api/launcher", headers=headers),
                asgi_request("POST", "/api/launcher/open", headers=headers),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers=headers,
                    payload={"enabled": True},
                ),
                asgi_request(
                    "POST",
                    "/api/launcher/panel/restart",
                    headers=headers,
                ),
            ]

        for status, body in responses:
            self.assertEqual(status, 401)
            self.assertEqual(body["detail"]["code"], "auth.setup_required")
        get_status.assert_not_called()
        open_app.assert_not_called()
        set_login.assert_not_called()
        panel_action.assert_not_called()

    def test_http_anonymous_cannot_mutate_launcher(self):
        headers = {"content-type": "application/json"}
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
            patch("hub.launcher_svc.open_app", return_value={"ok": True}) as open_app,
            patch("hub.launcher_svc.set_login_enabled", return_value={"ok": True}) as set_login,
            patch("hub.launcher_svc.schedule_panel_action", return_value={"ok": True}) as panel_action,
        ):
            responses = [
                asgi_request("POST", "/api/launcher/open", headers=headers),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers=headers,
                    payload={"enabled": True},
                ),
                asgi_request(
                    "POST",
                    "/api/launcher/panel/restart",
                    headers=headers,
                ),
            ]

        for status, body in responses:
            self.assertEqual(status, 401)
            self.assertEqual(body["detail"]["code"], "auth.login_required")
        open_app.assert_not_called()
        set_login.assert_not_called()
        panel_action.assert_not_called()

    def test_http_local_token_can_read_launcher_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "local-token"
            token_file.write_text("menu-token\n", encoding="utf-8")
            expected = {"app_installed": True, "panel_running": True}
            with (
                patch.object(auth, "LOCAL_TOKEN_FILE", token_file),
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.browser_authenticated", return_value=False),
                patch("hub.launcher_svc.status", return_value=expected) as get_status,
            ):
                status, body = asgi_request(
                    "GET",
                    "/api/launcher",
                    headers={auth.LOCAL_TOKEN_HEADER: "menu-token"},
                )
        self.assertEqual(status, 200)
        self.assertEqual(body, expected)
        get_status.assert_called_once_with()

    def test_http_browser_member_can_read_launcher_status(self):
        expected = {"app_installed": True, "panel_running": False}
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.launcher_svc.status", return_value=expected) as get_status,
        ):
            status, body = asgi_request("GET", "/api/launcher")

        self.assertEqual(status, 200)
        self.assertEqual(body, expected)
        get_status.assert_called_once_with()

    def test_http_invalid_local_token_cannot_access_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "local-token"
            token_file.write_text("menu-token\n", encoding="utf-8")
            headers = {
                auth.LOCAL_TOKEN_HEADER: "wrong-token",
                "content-type": "application/json",
            }
            with (
                patch.object(auth, "LOCAL_TOKEN_FILE", token_file),
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.browser_authenticated", return_value=False),
                patch("hub.launcher_svc.status", return_value={"ok": True}) as get_status,
                patch("hub.launcher_svc.open_app", return_value={"ok": True}) as open_app,
                patch("hub.launcher_svc.set_login_enabled", return_value={"ok": True}) as set_login,
                patch("hub.launcher_svc.schedule_panel_action", return_value={"ok": True}) as panel_action,
            ):
                responses = [
                    asgi_request("GET", "/api/launcher", headers=headers),
                    asgi_request("POST", "/api/launcher/open", headers=headers),
                    asgi_request(
                        "PUT",
                        "/api/launcher/login",
                        headers=headers,
                        payload={"enabled": True},
                    ),
                    asgi_request(
                        "POST",
                        "/api/launcher/panel/restart",
                        headers=headers,
                    ),
                ]

        for status, body in responses:
            self.assertEqual(status, 401)
            self.assertEqual(body["detail"]["code"], "auth.login_required")
        get_status.assert_not_called()
        open_app.assert_not_called()
        set_login.assert_not_called()
        panel_action.assert_not_called()

    def test_http_local_token_cannot_mutate_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "local-token"
            token_file.write_text("menu-token\n", encoding="utf-8")
            headers = {
                auth.LOCAL_TOKEN_HEADER: "menu-token",
                "content-type": "application/json",
            }
            with (
                patch.object(auth, "LOCAL_TOKEN_FILE", token_file),
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.browser_authenticated", return_value=False),
                patch("hub.launcher_svc.open_app", return_value={"ok": True}) as open_app,
                patch("hub.launcher_svc.set_login_enabled", return_value={"ok": True}) as set_login,
                patch("hub.launcher_svc.schedule_panel_action", return_value={"ok": True}) as panel_action,
            ):
                responses = [
                    asgi_request("POST", "/api/launcher/open", headers=headers),
                    asgi_request(
                        "PUT",
                        "/api/launcher/login",
                        headers=headers,
                        payload={"enabled": True},
                    ),
                    asgi_request(
                        "POST",
                        "/api/launcher/panel/restart",
                        headers=headers,
                    ),
                ]

        for status, body in responses:
            self.assertEqual(status, 401)
            self.assertEqual(
                body["detail"]["code"],
                "launcher.browser_session_required",
            )
        open_app.assert_not_called()
        set_login.assert_not_called()
        panel_action.assert_not_called()

    def test_http_browser_admin_can_mutate_launcher(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
            patch(
                "hub.launcher_svc.open_app",
                return_value={"ok": True, "message": "opened"},
            ) as open_app,
            patch(
                "hub.launcher_svc.set_login_enabled",
                return_value={"ok": True, "message": "enabled"},
            ) as set_login,
            patch(
                "hub.launcher_svc.schedule_panel_action",
                return_value={"ok": True, "message": "panel restart scheduled"},
            ) as panel_action,
        ):
            responses = [
                asgi_request("POST", "/api/launcher/open"),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers={"content-type": "application/json"},
                    payload={"enabled": True},
                ),
                asgi_request("POST", "/api/launcher/panel/restart"),
            ]

        self.assertEqual([status for status, _ in responses], [200, 200, 200])
        self.assertTrue(all(body["ok"] for _, body in responses))
        open_app.assert_called_once_with()
        set_login.assert_called_once_with(True)
        panel_action.assert_called_once_with("restart")

    def test_http_login_item_requires_a_json_boolean(self):
        headers = {"content-type": "application/json"}
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
            patch("hub.launcher_svc.set_login_enabled") as set_login,
        ):
            responses = [
                asgi_request("PUT", "/api/launcher/login", headers=headers, payload={}),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers=headers,
                    payload={"enabled": "false"},
                ),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers=headers,
                    payload={"enabled": 1},
                ),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers=headers,
                    payload={"enabled": None},
                ),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers=headers,
                    payload={"enabled": True, "unexpected": "ignored"},
                ),
            ]

        self.assertEqual(
            [status for status, _ in responses],
            [422, 422, 422, 422, 422],
        )
        set_login.assert_not_called()

    def test_login_item_uses_launchservices_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            app = base / "ServerHub.app"
            app.mkdir()
            plist = base / "local.serverhub.panel-launcher.plist"
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(
                    launcher_svc,
                    "sh",
                    return_value=(0, "", ""),
                ) as run,
            ):
                result = launcher_svc.set_login_enabled(True)
            self.assertTrue(result["ok"])
            payload = plistlib.loads(plist.read_bytes())
            self.assertEqual(payload["ProgramArguments"], ["/usr/bin/open", "-gj", str(app)])
            self.assertTrue(payload["RunAtLoad"])
            target = f"{launcher_svc.DOMAIN}/{launcher_svc.LAUNCHER_LABEL}"
            self.assertEqual(run.call_args_list, [
                call(["/bin/launchctl", "bootout", target], timeout=8),
                call(["/bin/launchctl", "enable", target], timeout=5),
                call(
                    [
                        "/bin/launchctl",
                        "bootstrap",
                        launcher_svc.DOMAIN,
                        str(plist),
                    ],
                    timeout=10,
                ),
            ])

    def test_disabling_login_item_removes_definition(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "launcher.plist"
            plist.write_text("placeholder", encoding="utf-8")
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "_app_path") as app_path,
                patch.object(
                    launcher_svc,
                    "sh",
                    return_value=(0, "", ""),
                ) as run,
                patch.object(launcher_svc, "_loaded", return_value=False),
            ):
                result = launcher_svc.set_login_enabled(False)
            self.assertTrue(result["ok"])
            self.assertFalse(plist.exists())
            app_path.assert_not_called()
            target = f"{launcher_svc.DOMAIN}/{launcher_svc.LAUNCHER_LABEL}"
            self.assertEqual(run.call_args_list, [
                call(["/bin/launchctl", "bootout", target], timeout=8),
                call(["/bin/launchctl", "disable", target], timeout=5),
            ])

    def test_disabling_missing_login_item_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "launcher.plist"
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(
                    launcher_svc,
                    "sh",
                    return_value=(0, "", ""),
                ) as run,
                patch.object(launcher_svc, "_loaded", return_value=False),
            ):
                result = launcher_svc.set_login_enabled(False)

            self.assertEqual(result, {"ok": True, "message": "disabled"})
            self.assertFalse(plist.exists())
            target = f"{launcher_svc.DOMAIN}/{launcher_svc.LAUNCHER_LABEL}"
            self.assertEqual(run.call_args_list, [
                call(["/bin/launchctl", "bootout", target], timeout=8),
                call(["/bin/launchctl", "disable", target], timeout=5),
            ])

    def test_enabling_login_item_reports_plist_write_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "ServerHub.app"
            app.mkdir()
            with (
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(launcher_svc.Path, "home", return_value=Path(tmp)),
                patch.object(
                    launcher_svc,
                    "_atomic_plist",
                    side_effect=PermissionError("read-only filesystem"),
                ),
                patch.object(launcher_svc, "sh") as run,
            ):
                result = launcher_svc.set_login_enabled(True)
        self.assertFalse(result["ok"])
        self.assertIn("read-only filesystem", result["message"])
        run.assert_not_called()

    def test_atomic_plist_replace_failure_preserves_original_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            plist = directory / "launcher.plist"
            plist.write_bytes(b"original")

            with (
                patch.object(
                    launcher_svc.os,
                    "replace",
                    side_effect=PermissionError("replace denied"),
                ),
                self.assertRaisesRegex(PermissionError, "replace denied"),
            ):
                launcher_svc._atomic_plist(plist, {"Label": "replacement"})

            self.assertEqual(plist.read_bytes(), b"original")
            self.assertEqual(list(directory.glob(".launcher.plist.*")), [])

    def test_atomic_plist_writes_valid_private_definition_without_residue(self):
        payload = {
            "Label": launcher_svc.LAUNCHER_LABEL,
            "ProgramArguments": ["/usr/bin/open", "-gj", "/Applications/ServerHub.app"],
            "RunAtLoad": True,
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            plist = directory / "launcher.plist"

            launcher_svc._atomic_plist(plist, payload)

            self.assertEqual(plistlib.loads(plist.read_bytes()), payload)
            self.assertEqual(plist.stat().st_mode & 0o777, 0o644)
            self.assertEqual(list(directory.glob(".launcher.plist.*")), [])

    def test_atomic_plist_fdopen_failure_closes_descriptor_and_cleans_temporary(self):
        real_mkstemp = launcher_svc.tempfile.mkstemp
        descriptors = []

        def tracked_mkstemp(*args, **kwargs):
            result = real_mkstemp(*args, **kwargs)
            descriptors.append(result[0])
            return result

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            plist = directory / "launcher.plist"
            with (
                patch.object(
                    launcher_svc.tempfile,
                    "mkstemp",
                    side_effect=tracked_mkstemp,
                ),
                patch.object(
                    launcher_svc.os,
                    "fdopen",
                    side_effect=OSError("fdopen failed"),
                ),
                patch.object(launcher_svc.os, "chmod") as chmod,
                patch.object(launcher_svc.os, "replace") as replace,
                self.assertRaisesRegex(OSError, "fdopen failed"),
            ):
                launcher_svc._atomic_plist(plist, {"Label": "replacement"})

            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                launcher_svc.os.fstat(descriptors[0])
            self.assertFalse(plist.exists())
            self.assertEqual(list(directory.glob(".launcher.plist.*")), [])
            chmod.assert_not_called()
            replace.assert_not_called()

    def test_atomic_plist_chmod_failure_closes_and_cleans_temporary(self):
        real_fdopen = launcher_svc.os.fdopen
        handles = []

        def tracked_fdopen(fd, mode):
            handle = real_fdopen(fd, mode)
            handles.append(handle)
            return handle

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            plist = directory / "launcher.plist"
            with (
                patch.object(launcher_svc.os, "fdopen", side_effect=tracked_fdopen),
                patch.object(
                    launcher_svc.os,
                    "chmod",
                    side_effect=PermissionError("chmod denied"),
                ),
                patch.object(launcher_svc.os, "replace") as replace,
                self.assertRaisesRegex(PermissionError, "chmod denied"),
            ):
                launcher_svc._atomic_plist(plist, {"Label": "replacement"})

            self.assertEqual(len(handles), 1)
            self.assertTrue(handles[0].closed)
            self.assertFalse(plist.exists())
            self.assertEqual(list(directory.glob(".launcher.plist.*")), [])
            replace.assert_not_called()

    def test_atomic_plist_fsync_failure_preserves_original_and_cleans_temporary(self):
        real_fdopen = launcher_svc.os.fdopen
        handles = []

        def tracked_fdopen(fd, mode):
            handle = real_fdopen(fd, mode)
            handles.append(handle)
            return handle

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            plist = directory / "launcher.plist"
            plist.write_bytes(b"original")
            with (
                patch.object(launcher_svc.os, "fdopen", side_effect=tracked_fdopen),
                patch.object(
                    launcher_svc.os,
                    "fsync",
                    side_effect=OSError("fsync failed"),
                ),
                patch.object(launcher_svc.os, "chmod") as chmod,
                patch.object(launcher_svc.os, "replace") as replace,
                self.assertRaisesRegex(OSError, "fsync failed"),
            ):
                launcher_svc._atomic_plist(plist, {"Label": "replacement"})

            self.assertEqual(len(handles), 1)
            self.assertTrue(handles[0].closed)
            self.assertEqual(plist.read_bytes(), b"original")
            self.assertEqual(list(directory.glob(".launcher.plist.*")), [])
            chmod.assert_not_called()
            replace.assert_not_called()

    def test_disabling_login_item_reports_plist_delete_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "launcher.plist"
            plist.write_text("placeholder", encoding="utf-8")
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "sh", return_value=(0, "", "")),
                patch.object(
                    launcher_svc.Path,
                    "unlink",
                    side_effect=PermissionError("permission denied"),
                ),
            ):
                result = launcher_svc.set_login_enabled(False)
        self.assertFalse(result["ok"])
        self.assertIn("permission denied", result["message"])

    def test_enabling_login_item_reports_bootstrap_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            app = base / "ServerHub.app"
            app.mkdir()
            plist = base / "launcher.plist"
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(launcher_svc.Path, "home", return_value=base),
                patch.object(
                    launcher_svc,
                    "sh",
                    side_effect=[
                        (0, "", ""),
                        (0, "", ""),
                        (5, "", "bootstrap denied"),
                    ],
                ),
                patch.object(launcher_svc, "_loaded", return_value=False),
            ):
                result = launcher_svc.set_login_enabled(True)
                self.assertTrue(plist.exists())
        self.assertFalse(result["ok"])
        self.assertIn("bootstrap denied", result["message"])

    def test_enabling_login_item_accepts_already_loaded_bootstrap_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            app = base / "ServerHub.app"
            app.mkdir()
            plist = base / "launcher.plist"
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(launcher_svc.Path, "home", return_value=base),
                patch.object(
                    launcher_svc,
                    "sh",
                    side_effect=[
                        (0, "", ""),
                        (0, "", ""),
                        (5, "already bootstrapped", "service already loaded"),
                    ],
                ),
                patch.object(launcher_svc, "_loaded", return_value=True) as loaded,
            ):
                result = launcher_svc.set_login_enabled(True)
                self.assertTrue(plist.exists())

        self.assertEqual(
            result,
            {"ok": True, "message": "already bootstrapped"},
        )
        loaded.assert_called_once_with(launcher_svc.LAUNCHER_LABEL)

    def test_enabling_login_item_reports_silent_bootstrap_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            app = base / "ServerHub.app"
            app.mkdir()
            plist = base / "launcher.plist"
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(launcher_svc.Path, "home", return_value=base),
                patch.object(
                    launcher_svc,
                    "sh",
                    side_effect=[
                        (0, "", ""),
                        (0, "", ""),
                        (5, "", ""),
                    ],
                ),
                patch.object(launcher_svc, "_loaded", return_value=False),
            ):
                result = launcher_svc.set_login_enabled(True)

        self.assertEqual(
            result,
            {"ok": False, "message": "launchctl bootstrap failed with exit 5"},
        )

    def test_disabling_login_item_reports_job_still_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "launcher.plist"
            plist.write_text("placeholder", encoding="utf-8")
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(
                    launcher_svc,
                    "sh",
                    side_effect=[
                        (5, "", "bootout denied"),
                        (0, "", ""),
                    ],
                ),
                patch.object(launcher_svc, "_loaded", return_value=True),
            ):
                result = launcher_svc.set_login_enabled(False)
        self.assertFalse(result["ok"])
        self.assertIn("bootout denied", result["message"])
        self.assertFalse(plist.exists())

    def test_disabling_login_item_reports_silent_bootout_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "launcher.plist"
            plist.write_text("placeholder", encoding="utf-8")
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(
                    launcher_svc,
                    "sh",
                    side_effect=[
                        (5, "", ""),
                        (0, "", ""),
                    ],
                ),
                patch.object(launcher_svc, "_loaded", return_value=True),
            ):
                result = launcher_svc.set_login_enabled(False)

        self.assertEqual(
            result,
            {"ok": False, "message": "launchctl bootout failed with exit 5"},
        )
        self.assertFalse(plist.exists())

    def test_mutations_require_browser_admin(self):
        with patch("hub.auth.browser_authenticated", return_value=False):
            with self.assertRaises(HTTPException) as raised:
                launcher_login(LoginItemPatch(enabled=True), request())
        self.assertEqual(raised.exception.status_code, 401)

        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="member"),
            patch("hub.auth.is_admin", return_value=False),
            patch("hub.launcher_svc.open_app", return_value={"ok": True}) as open_app,
            patch("hub.launcher_svc.set_login_enabled", return_value={"ok": True}) as set_login,
            patch("hub.launcher_svc.schedule_panel_action", return_value={"ok": True}) as panel_action,
        ):
            responses = [
                asgi_request("POST", "/api/launcher/open"),
                asgi_request(
                    "PUT",
                    "/api/launcher/login",
                    headers={"content-type": "application/json"},
                    payload={"enabled": True},
                ),
                asgi_request("POST", "/api/launcher/panel/restart"),
            ]

        for status, body in responses:
            self.assertEqual(status, 403)
            self.assertEqual(body["detail"]["code"], "launcher.admin_required")
        open_app.assert_not_called()
        set_login.assert_not_called()
        panel_action.assert_not_called()

    def test_panel_action_is_allowlisted(self):
        with (
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
        ):
            with self.assertRaises(HTTPException) as raised:
                launcher_panel("arbitrary", request())
        self.assertEqual(raised.exception.status_code, 400)

    def test_http_panel_action_is_allowlisted(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
            patch("hub.launcher_svc.schedule_panel_action") as panel_action,
        ):
            status, body = asgi_request(
                "POST",
                "/api/launcher/panel/arbitrary",
            )

        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "launcher.bad_action")
        self.assertEqual(body["detail"]["params"], {"action": "arbitrary"})
        panel_action.assert_not_called()

    def test_app_discovery_prefers_system_app_then_user_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            system_app = root / "Applications" / "ServerHub.app"
            user_app = root / "Users" / "test" / "Applications" / "ServerHub.app"
            system_app.mkdir(parents=True)
            user_app.mkdir(parents=True)

            with patch.object(
                launcher_svc,
                "APP_CANDIDATES",
                (system_app, user_app),
            ):
                self.assertEqual(launcher_svc._app_path(), system_app)

                system_app.rmdir()
                self.assertEqual(launcher_svc._app_path(), user_app)

    def test_app_discovery_ignores_files_and_reports_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            system_app = root / "Applications" / "ServerHub.app"
            user_app = root / "Users" / "test" / "Applications" / "ServerHub.app"
            system_app.parent.mkdir(parents=True)
            system_app.write_text("not a bundle", encoding="utf-8")

            with patch.object(
                launcher_svc,
                "APP_CANDIDATES",
                (system_app, user_app),
            ):
                self.assertIsNone(launcher_svc._app_path())

    def test_status_reports_app_jobs_and_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "ServerHub.app"
            app.mkdir()
            panel_plist = root / "panel.plist"
            launcher_plist = root / "launcher.plist"
            panel_plist.touch()
            launcher_plist.touch()
            loaded = {
                launcher_svc.PANEL_LABEL: True,
                launcher_svc.LAUNCHER_LABEL: False,
                launcher_svc.LEGACY_MENUBAR_LABEL: False,
            }
            with (
                patch.object(launcher_svc, "PANEL_PLIST", panel_plist),
                patch.object(launcher_svc, "LAUNCHER_PLIST", launcher_plist),
                patch.object(launcher_svc, "BASE", root),
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(launcher_svc, "_app_running", return_value=True),
                patch.object(launcher_svc, "_job_state", return_value="running"),
                patch.object(launcher_svc, "_loaded", side_effect=lambda label: loaded[label]),
            ):
                result = launcher_status()
        self.assertTrue(result["app_installed"])
        self.assertTrue(result["app_running"])
        self.assertTrue(result["panel_running"])
        self.assertEqual(result["panel_job_state"], "running")
        self.assertTrue(result["login_enabled"])
        self.assertFalse(result["launcher_registered"])
        self.assertFalse(result["legacy_menubar_registered"])
        self.assertEqual(result["runtime_path"], str(root))

    def test_panel_job_must_actually_be_running(self):
        with (
            patch.object(launcher_svc, "_app_path", return_value=None),
            patch.object(launcher_svc, "_app_running", return_value=False),
            patch.object(launcher_svc, "_job_state", return_value="exited"),
            patch.object(launcher_svc, "_loaded", return_value=True),
        ):
            result = launcher_svc.status()
        self.assertFalse(result["panel_running"])
        self.assertEqual(result["panel_job_state"], "exited")

    def test_status_resolves_app_path_once(self):
        app = Path("/Applications/ServerHub.app")
        with (
            patch.object(launcher_svc, "_app_path", return_value=app) as app_path,
            patch.object(launcher_svc, "_job_state", return_value="running"),
            patch.object(launcher_svc, "_loaded", return_value=False),
        ):
            result = launcher_svc.status()

        self.assertTrue(result["app_installed"])
        self.assertEqual(result["app_path"], str(app))
        app_path.assert_called_once_with()

    def test_status_resolves_missing_app_path_once(self):
        with (
            patch.object(launcher_svc, "_app_path", return_value=None) as app_path,
            patch.object(launcher_svc, "_app_running", return_value=False) as app_running,
            patch.object(launcher_svc, "_job_state", return_value="running"),
            patch.object(launcher_svc, "_loaded", return_value=False),
            patch.object(launcher_svc, "sh") as run,
        ):
            result = launcher_svc.status()

        self.assertFalse(result["app_installed"])
        self.assertIsNone(result["app_path"])
        self.assertFalse(result["app_running"])
        app_path.assert_called_once_with()
        app_running.assert_not_called()
        run.assert_not_called()

    def test_status_runs_independent_system_probes_concurrently(self):
        barrier = threading.Barrier(4, timeout=1)

        def app_running(_app=None):
            barrier.wait()
            return True

        def job_state(_label):
            barrier.wait()
            return "running"

        def loaded(label):
            barrier.wait()
            return label == launcher_svc.LAUNCHER_LABEL

        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "ServerHub.app"
            app.mkdir()
            with (
                patch.object(launcher_svc, "_app_path", return_value=app),
                patch.object(launcher_svc, "_app_running", side_effect=app_running),
                patch.object(launcher_svc, "_job_state", side_effect=job_state),
                patch.object(launcher_svc, "_loaded", side_effect=loaded),
            ):
                result = launcher_svc.status()

        self.assertTrue(result["app_running"])
        self.assertTrue(result["panel_running"])
        self.assertTrue(result["launcher_registered"])
        self.assertFalse(result["legacy_menubar_registered"])

    def test_status_degrades_failed_probes_without_losing_other_results(self):
        def loaded(label):
            if label == launcher_svc.LAUNCHER_LABEL:
                raise OSError("launchctl unavailable")
            return True

        with (
            patch.object(
                launcher_svc,
                "_app_running",
                side_effect=OSError("pgrep unavailable"),
            ),
            patch.object(launcher_svc, "_job_state", return_value="running"),
            patch.object(launcher_svc, "_loaded", side_effect=loaded),
        ):
            result = launcher_svc.status()

        self.assertFalse(result["app_running"])
        self.assertTrue(result["panel_running"])
        self.assertEqual(result["panel_job_state"], "running")
        self.assertFalse(result["launcher_registered"])
        self.assertTrue(result["legacy_menubar_registered"])

    def test_status_preserves_other_results_when_panel_probe_fails(self):
        with (
            patch.object(launcher_svc, "_app_running", return_value=True),
            patch.object(
                launcher_svc,
                "_job_state",
                side_effect=OSError("panel launchctl unavailable"),
            ),
            patch.object(
                launcher_svc,
                "_loaded",
                side_effect=lambda label: label == launcher_svc.LAUNCHER_LABEL,
            ),
        ):
            result = launcher_svc.status()

        self.assertTrue(result["app_running"])
        self.assertFalse(result["panel_running"])
        self.assertIsNone(result["panel_job_state"])
        self.assertTrue(result["launcher_registered"])
        self.assertFalse(result["legacy_menubar_registered"])

    def test_status_preserves_launcher_when_legacy_probe_fails(self):
        def loaded(label):
            if label == launcher_svc.LEGACY_MENUBAR_LABEL:
                raise OSError("legacy launchctl unavailable")
            return True

        with (
            patch.object(launcher_svc, "_app_running", return_value=True),
            patch.object(launcher_svc, "_job_state", return_value="running"),
            patch.object(launcher_svc, "_loaded", side_effect=loaded),
        ):
            result = launcher_svc.status()

        self.assertTrue(result["app_running"])
        self.assertTrue(result["panel_running"])
        self.assertEqual(result["panel_job_state"], "running")
        self.assertTrue(result["launcher_registered"])
        self.assertFalse(result["legacy_menubar_registered"])

    def test_job_state_uses_top_level_launchd_state(self):
        output = "\n".join((
            "gui/501/local.serverhub.panel = {",
            "\tstate = exited",
            "\tproperties = {",
            "\t\tstate = active",
            "\t}",
            "}",
        ))
        with patch.object(launcher_svc, "sh", return_value=(0, output, "")):
            self.assertEqual(launcher_svc._job_state(launcher_svc.PANEL_LABEL), "exited")

    def test_job_state_accepts_a_separate_root_brace_and_space_indentation(self):
        output = "\n".join((
            "gui/501/local.serverhub.panel =",
            "{",
            "    state = waiting",
            "    properties = {",
            "        state = active",
            "    }",
            "}",
        ))
        with patch.object(launcher_svc, "sh", return_value=(0, output, "")):
            self.assertEqual(launcher_svc._job_state(launcher_svc.PANEL_LABEL), "waiting")

    def test_job_state_ignores_nested_state_when_top_level_is_absent(self):
        output = "\n".join((
            "gui/501/local.serverhub.panel = {",
            "\tproperties = {",
            "\t\tstate = running",
            "\t}",
            "}",
        ))
        with patch.object(launcher_svc, "sh", return_value=(0, output, "")):
            self.assertEqual(launcher_svc._job_state(launcher_svc.PANEL_LABEL), "unknown")

    def test_job_state_reports_unloaded_when_launchctl_print_fails(self):
        with patch.object(launcher_svc, "sh", return_value=(113, "", "not found")) as run:
            state = launcher_svc._job_state(launcher_svc.PANEL_LABEL)

        self.assertIsNone(state)
        run.assert_called_once_with(
            [
                "/bin/launchctl",
                "print",
                f"{launcher_svc.DOMAIN}/{launcher_svc.PANEL_LABEL}",
            ],
            timeout=5,
        )

    def test_app_running_requires_exact_current_user_executable(self):
        app = Path("/Applications/ServerHub.app")
        with (
            patch.object(launcher_svc, "_app_path", return_value=app),
            patch.object(launcher_svc, "sh", return_value=(0, "123", "")) as run,
        ):
            self.assertTrue(launcher_svc._app_running())
        run.assert_called_once_with([
            "/usr/bin/pgrep", "-u", str(launcher_svc.UID), "-f", "-x",
            str(app / "Contents/MacOS/ServerHub"),
        ], timeout=5)

    def test_app_running_skips_process_probe_when_app_is_missing(self):
        with (
            patch.object(launcher_svc, "_app_path", return_value=None) as app_path,
            patch.object(launcher_svc, "sh") as run,
        ):
            self.assertFalse(launcher_svc._app_running())

        app_path.assert_called_once_with()
        run.assert_not_called()

    def test_app_running_reuses_supplied_path_without_resolving_candidates(self):
        app = Path("/Users/test/Applications/ServerHub.app")
        with (
            patch.object(launcher_svc, "_app_path") as app_path,
            patch.object(launcher_svc, "sh", return_value=(1, "", "")) as run,
        ):
            self.assertFalse(launcher_svc._app_running(app))

        app_path.assert_not_called()
        run.assert_called_once_with([
            "/usr/bin/pgrep", "-u", str(launcher_svc.UID), "-f", "-x",
            str(app / "Contents/MacOS/ServerHub"),
        ], timeout=5)

    def test_missing_app_fails_without_writing_login_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "launcher.plist"
            with (
                patch.object(launcher_svc, "LAUNCHER_PLIST", plist),
                patch.object(launcher_svc, "_app_path", return_value=None),
            ):
                login = launcher_svc.set_login_enabled(True)
                opened = launcher_svc.open_app()
        self.assertFalse(login["ok"])
        self.assertFalse(opened["ok"])
        self.assertFalse(plist.exists())

    def test_open_app_uses_launchservices_without_activation(self):
        app = Path("/Applications/ServerHub.app")
        with (
            patch.object(launcher_svc, "_app_path", return_value=app),
            patch.object(launcher_svc, "sh", return_value=(0, "", "")) as run,
        ):
            result = launcher_svc.open_app()

        self.assertEqual(result, {"ok": True, "message": "opened"})
        run.assert_called_once_with(["/usr/bin/open", "-gj", str(app)], timeout=10)

    def test_open_app_reports_launchservices_stderr_on_failure(self):
        app = Path("/Applications/ServerHub.app")
        with (
            patch.object(launcher_svc, "_app_path", return_value=app),
            patch.object(
                launcher_svc,
                "sh",
                return_value=(1, "background output", "application is damaged"),
            ),
        ):
            result = launcher_svc.open_app()

        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "application is damaged")

    def test_open_app_reports_exit_code_when_launchservices_is_silent(self):
        app = Path("/Applications/ServerHub.app")
        with (
            patch.object(launcher_svc, "_app_path", return_value=app),
            patch.object(launcher_svc, "sh", return_value=(7, "", "")),
        ):
            result = launcher_svc.open_app()

        self.assertEqual(
            result,
            {"ok": False, "message": "open failed with exit 7"},
        )

    def test_admin_routes_delegate_to_service_layer(self):
        with (
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
            patch("hub.launcher_svc.open_app", return_value={"ok": True}) as open_app,
            patch("hub.launcher_svc.set_login_enabled", return_value={"ok": True}) as set_login,
            patch("hub.launcher_svc.schedule_panel_action", return_value={"ok": True}) as panel_action,
        ):
            self.assertTrue(launcher_open(request())["ok"])
            self.assertTrue(launcher_login(LoginItemPatch(enabled=False), request())["ok"])
            self.assertTrue(launcher_panel("restart", request())["ok"])
        open_app.assert_called_once_with()
        set_login.assert_called_once_with(False)
        panel_action.assert_called_once_with("restart")

    def test_stop_panel_action_uses_bootout_in_detached_helper(self):
        with patch("hub.launcher_svc.subprocess.Popen") as popen:
            result = launcher_svc.schedule_panel_action("stop")

        self.assertEqual(result, {"ok": True, "message": "panel stop scheduled"})
        popen.assert_called_once()
        command = popen.call_args.args[0]
        self.assertEqual(command[:2], ["/bin/sh", "-c"])
        self.assertEqual(
            command[2],
            "sleep 0.6; exec /bin/launchctl bootout "
            f"{launcher_svc.DOMAIN}/{launcher_svc.PANEL_LABEL}",
        )
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])

    def test_restart_panel_action_uses_kickstart_in_detached_helper(self):
        with patch("hub.launcher_svc.subprocess.Popen") as popen:
            result = launcher_svc.schedule_panel_action("restart")

        self.assertEqual(result, {"ok": True, "message": "panel restart scheduled"})
        popen.assert_called_once()
        command = popen.call_args.args[0]
        self.assertEqual(command[:2], ["/bin/sh", "-c"])
        self.assertEqual(
            command[2],
            "sleep 0.6; exec /bin/launchctl kickstart -k "
            f"{launcher_svc.DOMAIN}/{launcher_svc.PANEL_LABEL}",
        )
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])

    def test_panel_action_reports_helper_spawn_failure(self):
        with patch(
            "hub.launcher_svc.subprocess.Popen",
            side_effect=OSError("process limit reached"),
        ):
            result = launcher_svc.schedule_panel_action("restart")
        self.assertFalse(result["ok"])
        self.assertIn("process limit reached", result["message"])

    def test_panel_action_rejects_unknown_action_without_spawning(self):
        with patch("hub.launcher_svc.subprocess.Popen") as popen:
            result = launcher_svc.schedule_panel_action("arbitrary")
        self.assertFalse(result["ok"])
        self.assertIn("unsupported", result["message"])
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
