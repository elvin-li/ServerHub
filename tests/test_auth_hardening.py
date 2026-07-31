from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException, Request

from hub import auth
from hub.routers.settings_api import AuthPatch, SettingsPatch, put_settings


def request(*, client="127.0.0.1", headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/status",
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
