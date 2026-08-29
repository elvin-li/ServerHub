"""Stays-immune pins for the login/auth leftover-500 classes, over the real app.

A fourth sweep of the sign-in surface found no live 500 left, so this module
pins the corners that were previously only covered by unit-level ``_auth_cfg``
mocks (or not at all) at the HTTP layer, where the middleware, the body parse
and Starlette's allow_nan=False encoder all take part:

* junk ``Origin`` headers on POST /api/auth/login cross the same-origin
  middleware — ``urlsplit("http://[")`` raises ValueError on 3.12, and a
  ``javascript://`` / userinfo / latin-1 / over-huge-port Origin must each
  stay the coded 403, never a 500 raised inside the middleware;
* junk credential carriers (multi-KB or %-junk session cookies, a latin-1
  0xFF byte in the local-token header or a Bearer value, non-ASCII Basic
  credentials) each answer their coded 401 — ``secrets.compare_digest``
  TypeErrors on non-ASCII str, the trap constant_time_equals exists for;
* a numeric YAML account name (``username: 2024`` round-trips as an *int*,
  and its ``session_epochs`` row as an int key) signs in and — critically —
  logout still revokes its cookie: the epoch bump must land past the
  int-keyed row rather than writing a second, lower string-keyed counter;
* >4300-digit number literals in the two mutating bodies the earlier sweep
  did not pin (change-password, TOTP confirm/accounts create) stay 400 —
  ``json.loads`` raises plain ValueError there, not JSONDecodeError;
* a >4300-digit literal in a *sibling* api-keys.json row neither 500s the
  key listing/revoke over HTTP nor wipes the healthy sibling key.
"""
from __future__ import annotations

import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
HUGE_LITERAL = "9" * 4400

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.data = data
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", data / "twofa.json"),
            (api_keys, "STORE_FILE", data / "api-keys.json"),
            (audit, "AUDIT_PATH", data / "auth-audit.jsonl"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        config.reload_cfg()
        self.client = TestClient(app())

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def claim(self) -> None:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")

    def login(self, password=PASSWORD, username="admin"):
        return self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )


class CrossSiteGuardJunkHeaderTests(_AppSandbox):
    """The same-origin middleware runs before auth on every login POST."""

    def test_junk_origin_headers_stay_coded_403_not_500(self):
        self.claim()
        for label, origin in (
            ("torn ipv6", b"http://["),
            ("javascript scheme", b"javascript://testserver"),
            ("empty netloc", b"http://"),
            ("userinfo", b"http://a:b@testserver"),
            ("latin-1 junk", b"\xff\xfe"),
            ("huge port", b"http://testserver:99999999999999999999999999"),
        ):
            with self.subTest(origin=label):
                auth._login_attempts.clear()
                response = self.client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "wrong-password"},
                    headers={b"origin": origin, b"host": b"testserver"},
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(
                    response.json()["detail"]["code"], "auth.cross_site_denied"
                )

    def test_junk_host_headers_stay_coded_401_not_500(self):
        """request_host_name / is_direct_loopback parse whatever Host holds."""
        self.claim()
        for label, host in (
            ("torn ipv6", b"[::1"),
            ("many colons", b"a:b:c:d"),
            ("latin-1 junk", b"\xff"),
        ):
            with self.subTest(host=label):
                auth._login_attempts.clear()
                response = self.client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "wrong-password"},
                    headers={b"host": host},
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.json()["detail"]["code"], "auth.bad_credentials"
                )


class JunkCredentialCarrierTests(_AppSandbox):
    """Every carrier a request can present arrives attacker-controlled."""

    def test_junk_session_cookies_do_not_500_status(self):
        self.claim()
        junk_payload = base64.urlsafe_b64encode(
            b"admin|x|" + b"\xff" * 40
        ).decode().rstrip("=")
        for label, cookie in (
            ("multi-KB", "A" * 5000),
            ("percent junk", "%ff%fe"),
            ("junk signed shape", junk_payload),
        ):
            with self.subTest(cookie=label):
                response = self.client.get(
                    "/api/auth/status",
                    headers={"cookie": f"{auth.COOKIE_NAME}={cookie}"},
                )
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.json()["authenticated"])

    def test_latin1_local_token_header_is_401(self):
        """A 0xFF byte decodes to U+00FF; compare_digest on str would raise."""
        self.claim()
        response = self.client.get(
            "/api/status", headers={b"x-serverhub-local-token": b"\xff\xfe"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "auth.login_required")

    def test_latin1_bearer_key_is_coded_401(self):
        self.claim()
        response = self.client.get(
            "/api/status",
            headers={b"authorization": b"Bearer shk_" + b"\xff" * 30},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "auth.bad_api_key")

    def test_non_ascii_basic_credentials_are_401(self):
        self.claim()
        encoded = base64.b64encode("adm\u0131n:pa\u00dfword-long".encode()).decode()
        response = self.client.get(
            "/api/status", headers={"authorization": f"Basic {encoded}"}
        )
        self.assertEqual(response.status_code, 401)


class NumericYamlUsernameLiveTests(_AppSandbox):
    """``username: 2024`` round-trips as int; the str() probe must hold live."""

    def _claim_with_numeric_member(self) -> None:
        self.write_config(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            "    accounts:\n"
            "      - username: 2024\n"
            f'        password_hash: "{auth.hash_password("kid-password-12")}"\n'
            "        role: member\n"
            "        resources: [svc]\n"
            "    session_epochs:\n"
            "      2024: 3\n"
        )

    def test_numeric_account_signs_in_over_http(self):
        self._claim_with_numeric_member()
        response = self.login("kid-password-12", "2024")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["username"], "2024")
        self.assertEqual(body["role"], "member")
        self.assertIn(auth.COOKIE_NAME, response.cookies)

    def test_logout_revokes_past_the_int_keyed_epoch_row(self):
        """The bump must land at 4 on the string spelling, not write a lower
        second counter beside the int-keyed leftover (which would leave the
        'revoked' cookie verifying for its full TTL)."""
        self._claim_with_numeric_member()
        response = self.login("kid-password-12", "2024")
        token = response.cookies[auth.COOKIE_NAME]
        self.assertTrue(auth.verify_session(token))
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)
        self.assertFalse(auth.verify_session(token))
        stored = yaml.safe_load(self.yaml_path.read_text())["settings"]["auth"]
        epochs = stored["session_epochs"]
        self.assertEqual(epochs.get("2024"), 4)
        self.assertNotIn(2024, epochs)


class HugeIntBodyRemainingRoutePins(_AppSandbox):
    """Digit-cap literals on the mutating bodies the earlier sweep skipped."""

    def _post_raw(self, path: str, payload: str):
        return self.client.post(
            path,
            content=payload.encode(),
            headers={"content-type": "application/json"},
        )

    def test_change_password_huge_literal_is_400_not_500(self):
        self.claim()
        self.assertEqual(self.login().status_code, 200)
        auth._login_attempts.clear()
        for field_json in (
            '{"username": ' + HUGE_LITERAL + ', "current_password": "x", "new_password": "0123456789"}',
            '{"username": "admin", "current_password": ' + HUGE_LITERAL + ', "new_password": "0123456789"}',
        ):
            with self.subTest(payload=field_json[:30]):
                response = self._post_raw("/api/auth/change-password", field_json)
                self.assertEqual(response.status_code, 400)

    def test_totp_confirm_and_accounts_create_huge_literals_are_400(self):
        self.claim()
        self.assertEqual(self.login().status_code, 200)
        auth._login_attempts.clear()
        for path, payload in (
            ("/api/auth/totp/confirm", '{"code": ' + HUGE_LITERAL + "}"),
            (
                "/api/auth/accounts",
                '{"username": "kid", "password": "kid-password-12", "resources": [' + HUGE_LITERAL + "]}",
            ),
        ):
            with self.subTest(path=path):
                response = self._post_raw(path, payload)
                self.assertEqual(response.status_code, 400)


class ApiKeysPoisonedStoreHttpTests(_AppSandbox):
    def test_huge_sibling_row_does_not_500_or_wipe_over_http(self):
        """The digit-cap ValueError out of ``json.loads`` is not
        JSONDecodeError; reading the store as ``[]`` used to 401 every Bearer
        request and the next write wiped the healthy sibling key."""
        self.claim()
        self.assertEqual(self.login().status_code, 200)
        created = self.client.post(
            "/api/api-keys", json={"name": "mon", "role": "admin"}
        )
        self.assertEqual(created.status_code, 200)
        token = created.json()["key"]
        key_id = created.json()["record"]["id"]
        raw = api_keys.STORE_FILE.read_text()
        poisoned = raw.replace(
            '"keys": [',
            '"keys": [{"id": "ak_junk", "name": "junk", "role": "member", '
            '"digest": "ff", "created": ' + HUGE_LITERAL + "}, ",
            1,
        )
        api_keys.STORE_FILE.write_text(poisoned)
        listing = self.client.get("/api/api-keys")
        self.assertEqual(listing.status_code, 200)
        ids = {row["id"] for row in listing.json()["keys"]}
        self.assertIn(key_id, ids)
        # The healthy key still authenticates a Bearer request...
        bare = TestClient(app())
        status = bare.get(
            "/api/status", headers={"authorization": f"Bearer {token}"}
        )
        self.assertEqual(status.status_code, 200)
        # ...and revoking the poisoned row neither 500s nor drops the sibling.
        revoked = self.client.delete("/api/api-keys/ak_junk")
        self.assertEqual(revoked.status_code, 200)
        self.assertIsNotNone(api_keys.verify(token))


if __name__ == "__main__":
    unittest.main()
