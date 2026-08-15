import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi import HTTPException, Request, Response
from pydantic import ValidationError

from hub import audit
from hub.routers.auth_api import ChangePasswordBody, auth_change_password
from hub.routers.settings_api import SettingsPatch


def _request() -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/auth/change-password",
        "headers": [],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    })


def _body(current="old-password") -> ChangePasswordBody:
    return ChangePasswordBody(
        username="admin",
        current_password=current,
        new_password="new-password-123",
    )


class PasswordManagementTests(unittest.TestCase):
    def setUp(self):
        # The change-password path is audited, and two tests below drive it far
        # enough to emit a record.  Without redirecting the log those records land
        # in the real data/auth-audit.jsonl: a full test run added two lines every
        # time, and because the trail is capped and evicts from the front, fixture
        # usernames like "new-admin" were steadily pushing genuine security events
        # out of it.  44% of the production log was test noise before this.
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(audit, "AUDIT_PATH", Path(self._tmp.name) / "audit.jsonl")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_change_password_requires_browser_session(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=False),
        ):
            with self.assertRaises(HTTPException) as raised:
                auth_change_password(_body(), _request(), Response())
        self.assertEqual(raised.exception.status_code, 401)

    def test_change_password_allows_a_member_to_rotate_their_own(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="member"),
            patch("hub.auth.is_admin", return_value=False),
            patch("hub.auth.login_allowed", return_value=(True, 0)),
            patch(
                "hub.auth.verify_account_password",
                side_effect=lambda username, password: (
                    username == "member" and password == "old-password"
                ),
            ),
            patch("hub.auth.set_account_password") as set_account_password,
            patch("hub.auth.set_password") as set_password,
            patch("hub.auth.clear_login_failures"),
            patch("hub.auth.create_session", return_value="rotated-session"),
        ):
            response = Response()
            result = auth_change_password(ChangePasswordBody(
                username="member",
                current_password="old-password",
                new_password="new-password-123",
            ), _request(), response)
        self.assertTrue(result["ok"])
        self.assertEqual(result["username"], "member")
        set_account_password.assert_called_once_with("member", "new-password-123")
        set_password.assert_not_called()

    def test_change_password_refuses_a_member_changing_another_account(self):
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="member"),
            patch("hub.auth.is_admin", return_value=False),
            patch("hub.auth.login_allowed", return_value=(True, 0)),
            patch(
                "hub.auth.verify_account_password",
                side_effect=lambda username, password: password == "old-password",
            ),
            patch("hub.auth.set_account_password") as set_account_password,
            patch("hub.auth.set_password") as set_password,
        ):
            with self.assertRaises(HTTPException) as raised:
                auth_change_password(_body(), _request(), Response())
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "auth.admin_required")
        set_account_password.assert_not_called()
        set_password.assert_not_called()

    def test_change_password_verifies_current_password(self):
        # Re-authentication is per-account since multi-user login: the check
        # runs against the caller's own hash, not the legacy admin credential.
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
            patch("hub.auth.login_allowed", return_value=(True, 0)),
            patch("hub.auth.verify_account_password", return_value=False),
            patch("hub.auth.record_login_failure") as failure,
        ):
            with self.assertRaises(HTTPException) as raised:
                auth_change_password(_body("wrong-password"), _request(), Response())
        self.assertEqual(raised.exception.status_code, 401)
        failure.assert_called_once()

    def test_change_password_rotates_credentials_and_session(self):
        # username != the signed-in name: the admin-only rename path, which
        # still writes through the legacy set_password pair.
        with (
            patch("hub.auth.setup_required", return_value=False),
            patch("hub.auth.browser_authenticated", return_value=True),
            patch("hub.auth.request_username", return_value="admin"),
            patch("hub.auth.is_admin", return_value=True),
            patch("hub.auth.login_allowed", return_value=(True, 0)),
            patch(
                "hub.auth.verify_account_password",
                side_effect=lambda username, password: password == "old-password",
            ),
            patch("hub.auth.set_password") as set_password,
            patch("hub.auth.clear_login_failures"),
            patch("hub.auth.create_session", return_value="rotated-session"),
        ):
            response = Response()
            result = auth_change_password(ChangePasswordBody(
                username="new-admin",
                current_password="old-password",
                new_password="new-password-123",
            ), _request(), response)
        self.assertTrue(result["ok"])
        set_password.assert_called_once_with("new-password-123", "new-admin", enable=True)
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("serverhub_session=rotated-session", cookie)
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)

    def test_general_settings_rejects_password_and_username_fields(self):
        for field in ("password", "username"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                SettingsPatch.model_validate({"auth": {field: "not-allowed"}})


if __name__ == "__main__":
    unittest.main()
