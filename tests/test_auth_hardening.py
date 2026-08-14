from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException, Request
from fastapi.security import HTTPBasicCredentials

from hub import auth
from hub.routers.api import Action, api_action
from hub.routers.containers import AllBody, containers_all
from hub.routers.settings_api import AuthPatch, SettingsPatch, put_settings


def request(
    *,
    client="127.0.0.1",
    method="GET",
    path="/api/status",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": (client, 12345),
    })


class AuthHardeningTests(unittest.TestCase):
    def test_authentication_cannot_be_disabled_after_setup(self):
        with patch("hub.auth.setup_required", return_value=False):
            self.assertTrue(auth.auth_enabled())

    def test_settings_reject_disabling_authentication(self):
        body = SettingsPatch(auth=AuthPatch(enabled=False))
        with self.assertRaises(HTTPException) as raised:
            put_settings(body)
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(raised.exception.detail["code"], "auth.cannot_disable")

    def test_loopback_address_alone_is_not_authentication(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
            patch("hub.auth.local_client_authenticated", return_value=False),
        ):
            with self.assertRaises(HTTPException) as raised:
                auth.require_auth(request())
        self.assertEqual(raised.exception.status_code, 401)

    def test_local_client_requires_matching_token_and_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "token"
            token_file.write_text("test-local-token\n", encoding="utf-8")
            headers = [(auth.LOCAL_TOKEN_HEADER.encode(), b"test-local-token")]
            with patch.object(auth, "LOCAL_TOKEN_FILE", token_file):
                self.assertTrue(auth.local_client_authenticated(request(headers=headers)))
                self.assertFalse(auth.local_client_authenticated(request(client="192.0.2.4", headers=headers)))
                self.assertFalse(auth.local_client_authenticated(request(headers=[])))

    def test_member_browser_session_is_limited_to_safe_read_routes(self):
        allowed = [
            "/api/health",
            "/api/status",
            "/api/services",
            "/api/services/jellyfin/detail",
            "/api/launcher",
        ]
        refused = [
            "/api/settings",
            "/api/files/list",
            "/api/services/jellyfin/logs",
            "/api/system/diagnostics",
            "/api/apps/credentials",
        ]
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="member"),
            patch("hub.auth.is_admin", return_value=False),
            patch("hub.auth.may_use_resource", side_effect=lambda _user, sid: sid == "jellyfin"),
        ):
            for path in allowed:
                with self.subTest(allowed=path):
                    self.assertTrue(auth.require_auth(request(method="GET", path=path)))
            for path in refused:
                with self.subTest(refused=path):
                    with self.assertRaises(HTTPException) as raised:
                        auth.require_auth(request(method="GET", path=path))
                    self.assertEqual(raised.exception.status_code, 403)
                    self.assertEqual(
                        raised.exception.detail["code"], "auth.admin_required"
                    )
            with self.assertRaises(HTTPException) as raised:
                auth.require_auth(request(method="POST", path="/api/action"))
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "auth.admin_required")

    def test_admin_browser_session_may_mutate(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
        ):
            self.assertTrue(auth.require_auth(request(method="POST")))

    def test_local_client_token_is_limited_to_menu_bar_routes(self):
        allowed = [
            ("GET", "/api/health"),
            ("GET", "/api/status"),
            ("POST", "/api/action"),
            ("GET", "/api/maintenance"),
            ("GET", "/api/maintenance/daily/log"),
            ("POST", "/api/containers/all"),
            ("GET", "/api/launcher"),
        ]
        refused = [
            ("POST", "/api/maintenance/daily/run"),
            ("POST", "/api/files/delete"),
            ("POST", "/api/terminal/run"),
            ("PUT", "/api/settings"),
            ("GET", "/api/apps/credentials"),
        ]
        # Browser-only launcher mutations intentionally pass this shared boundary
        # so the route can return its stable launcher.browser_session_required
        # error. The HTTP integration tests assert that the action never runs.
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
            patch("hub.auth.local_client_authenticated", return_value=True),
        ):
            for method, path in allowed:
                with self.subTest(method=method, path=path):
                    self.assertTrue(auth.require_auth(request(method=method, path=path)))
            for method, path in refused:
                with self.subTest(method=method, path=path):
                    with self.assertRaises(HTTPException) as raised:
                        auth.require_auth(request(method=method, path=path))
                    self.assertEqual(raised.exception.status_code, 403)
                    self.assertEqual(
                        raised.exception.detail["code"], "auth.admin_required"
                    )

    def test_local_client_service_action_is_limited_to_advertised_safe_actions(self):
        req = request(method="POST", path="/api/action")
        req.state.serverhub_auth_kind = "local-client"
        status = {
            "groups": [{
                "group": "Containers",
                "services": [{
                    "id": "media",
                    "actions": ["stop", "remove"],
                }],
            }],
        }
        with (
            patch("hub.routers.api.full_status", return_value=status),
            patch("hub.routers.api.actions.run_action") as run_action,
        ):
            with self.assertRaises(HTTPException) as raised:
                api_action(Action(target="media", action="remove"), req)
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "auth.admin_required")
        run_action.assert_not_called()

    def test_local_client_service_action_must_be_advertised_for_target(self):
        req = request(method="POST", path="/api/action")
        req.state.serverhub_auth_kind = "local-client"
        status = {
            "groups": [{
                "group": "Services",
                "services": [{"id": "media", "actions": ["start"]}],
            }],
        }
        with (
            patch("hub.routers.api.full_status", return_value=status),
            patch("hub.routers.api.actions.run_action") as run_action,
        ):
            with self.assertRaises(HTTPException):
                api_action(Action(target="media", action="stop"), req)
        run_action.assert_not_called()

    def test_local_client_container_all_is_limited_to_menu_actions(self):
        req = request(method="POST", path="/api/containers/all")
        req.state.serverhub_auth_kind = "local-client"
        with patch("hub.routers.containers.svc.action_all") as action_all:
            with self.assertRaises(HTTPException) as raised:
                containers_all(AllBody(action="pause"), req)
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "auth.admin_required")
        action_all.assert_not_called()

    def test_admin_action_routes_keep_full_capability(self):
        req = request(method="POST", path="/api/action")
        req.state.serverhub_auth_kind = "browser-admin"
        with (
            patch("hub.routers.api.actions.run_action", return_value=(0, "removed", "")) as run_action,
            patch("hub.routers.api.invalidate_status"),
        ):
            response = api_action(Action(target="media", action="remove"), req)
        self.assertEqual(response.status_code, 200)
        run_action.assert_called_once_with("media", "remove")

        container_req = request(method="POST", path="/api/containers/all")
        container_req.state.serverhub_auth_kind = "browser-admin"
        with patch(
            "hub.routers.containers.svc.action_all",
            return_value={"ok": True},
        ) as action_all:
            self.assertEqual(
                containers_all(AllBody(action="pause"), container_req),
                {"ok": True},
            )
        action_all.assert_called_once_with("pause")

    def test_primary_admin_basic_auth_may_mutate(self):
        credentials = HTTPBasicCredentials(username="admin", password="test-password")
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
            patch("hub.auth.local_client_authenticated", return_value=False),
            patch("hub.auth._auth_cfg", return_value={"username": "admin"}),
            patch("hub.auth.verify_password", return_value=True),
        ):
            self.assertTrue(
                auth.require_auth(request(method="POST"), credentials=credentials)
            )

    def test_setup_claim_requires_token_and_consumes_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "setup-token"
            token_file.write_text("a" * 43 + "\n", encoding="utf-8")
            with (
                patch.object(auth, "SETUP_TOKEN_FILE", token_file),
                patch("hub.auth.setup_required", return_value=True),
                patch("hub.auth.set_password") as set_password,
            ):
                self.assertFalse(auth.complete_setup("wrong", "password-123", "admin"))
                self.assertTrue(token_file.exists())
                self.assertTrue(auth.complete_setup("a" * 43, "password-123", "admin"))
                set_password.assert_called_once_with("password-123", "admin", enable=True)
                self.assertFalse(token_file.exists())


if __name__ == "__main__":
    unittest.main()
