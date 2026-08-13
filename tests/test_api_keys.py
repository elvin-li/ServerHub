"""API keys: hashed storage, role boundaries, expiry, and the browser wall.

Two layers under test:

* :mod:`hub.api_keys` — the store (digests at rest, constant-time lookup,
  expiry, throttled last_used persistence);
* :func:`hub.auth.require_auth` — how a presented ``Bearer shk_…`` maps onto
  the existing roles, and the guarantee that keys never satisfy the
  browser-session-only guards.
"""
from __future__ import annotations

import json
import os
import stat
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException, Request

from hub import api_keys, auth
from hub.routers import nas_common


def request(
    *,
    token: str | None = None,
    method: str = "GET",
    path: str = "/api/status",
    client: str = "203.0.113.9",
) -> Request:
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": (client, 12345),
    })


class _Store(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "api-keys.json"
        patcher = mock.patch.object(api_keys, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        api_keys._last_seen.clear()


class StoreTests(_Store):
    def test_create_returns_plaintext_once_and_stores_only_the_digest(self):
        record, token = api_keys.create("monitoring", "member")
        self.assertTrue(token.startswith(api_keys.PREFIX))
        raw = self.store.read_text()
        self.assertNotIn(token, raw)
        stored = json.loads(raw)["keys"][0]
        self.assertEqual(stored["digest"], api_keys._digest(token))
        self.assertEqual(record["name"], "monitoring")
        self.assertNotIn("digest", record, "public view must not expose the digest")

    def test_store_file_is_owner_only(self):
        api_keys.create("k", "member")
        self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o600)

    def test_verify_resolves_only_the_exact_token(self):
        _, token = api_keys.create("mon", "member")
        self.assertIsNotNone(api_keys.verify(token))
        for bad in (token[:-1] + ("A" if token[-1] != "A" else "B"),
                    api_keys.PREFIX + "0" * 43, "not-a-key", "", None):
            with self.subTest(bad=bad):
                self.assertIsNone(api_keys.verify(bad))

    def test_revoked_key_stops_verifying(self):
        record, token = api_keys.create("mon", "member")
        self.assertIsNotNone(api_keys.verify(token))
        revoked = api_keys.revoke(record["id"])
        self.assertEqual(revoked["id"], record["id"])
        self.assertIsNone(api_keys.verify(token))
        self.assertIsNone(api_keys.revoke(record["id"]))

    def test_expiry_is_enforced_at_verify_time(self):
        _, token = api_keys.create("short", "member", expires_days=1)
        self.assertIsNotNone(api_keys.verify(token))
        future = time.time() + 2 * 86400
        with mock.patch("hub.api_keys.time.time", return_value=future):
            self.assertIsNone(api_keys.verify(token))

    def test_validation_rejects_bad_input(self):
        cases = [
            (dict(name="", role="member"), "bad_name"),
            (dict(name="x" * 65, role="member"), "bad_name"),
            (dict(name="ok", role="root"), "bad_role"),
            (dict(name="ok", role="member", expires_days=0), "bad_expiry"),
            (dict(name="ok", role="member", expires_days=99999), "bad_expiry"),
        ]
        for kwargs, reason in cases:
            with self.subTest(reason=reason):
                expires = kwargs.pop("expires_days", None)
                with self.assertRaises(ValueError) as raised:
                    api_keys.create(kwargs["name"], kwargs["role"], expires_days=expires)
                self.assertEqual(str(raised.exception), reason)

    def test_key_count_is_capped(self):
        with mock.patch.object(api_keys, "MAX_KEYS", 2):
            api_keys.create("a", "member")
            api_keys.create("b", "member")
            with self.assertRaises(ValueError) as raised:
                api_keys.create("c", "member")
        self.assertEqual(str(raised.exception), "too_many")

    def test_last_used_persists_at_most_hourly(self):
        _, token = api_keys.create("mon", "member")
        with mock.patch.object(api_keys, "_save", wraps=api_keys._save) as save:
            for _ in range(5):
                self.assertIsNotNone(api_keys.verify(token))
            # First hit persists (stored last_used was empty); the next four
            # land inside the throttle window and must not touch the disk.
            self.assertEqual(save.call_count, 1)
        listed = api_keys.list_public()[0]
        self.assertIsNotNone(listed["last_used"], "in-memory freshness still shows")


class RequireAuthRoleTests(_Store):
    """How require_auth maps keys onto the existing roles."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch("hub.auth.setup_required", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_admin_key_may_read_and_mutate(self):
        _, token = api_keys.create("automation", "admin")
        for method, path in (
            ("GET", "/api/status"),
            ("POST", "/api/action"),
            ("GET", "/api/settings"),
        ):
            with self.subTest(method=method, path=path):
                req = request(token=token, method=method, path=path)
                self.assertTrue(auth.require_auth(req))
                self.assertEqual(req.state.serverhub_auth_kind, "api-key-admin")

    def test_member_key_gets_the_member_read_surface_only(self):
        _, token = api_keys.create("mon", "member")
        for path in ("/api/health", "/api/status", "/api/services", "/api/launcher"):
            with self.subTest(allowed=path):
                req = request(token=token, path=path)
                self.assertTrue(auth.require_auth(req))
                self.assertEqual(req.state.serverhub_auth_kind, "api-key-member")
        refused = [
            ("GET", "/api/settings"),
            ("GET", "/api/services/jellyfin/detail"),
            ("GET", "/api/files/list"),
            ("POST", "/api/action"),
            ("POST", "/api/containers/all"),
        ]
        for method, path in refused:
            with self.subTest(refused=path, method=method):
                with self.assertRaises(HTTPException) as raised:
                    auth.require_auth(request(token=token, method=method, path=path))
                self.assertEqual(raised.exception.status_code, 403)
                self.assertEqual(
                    raised.exception.detail["code"], "auth.admin_required"
                )

    def test_unknown_or_expired_key_is_named_as_such(self):
        with self.assertRaises(HTTPException) as raised:
            auth.require_auth(request(token=api_keys.PREFIX + "x" * 43))
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.detail["code"], "auth.bad_api_key")

        _, token = api_keys.create("short", "admin", expires_days=1)
        future = time.time() + 2 * 86400
        with mock.patch("hub.api_keys.time.time", return_value=future):
            with self.assertRaises(HTTPException) as raised:
                auth.require_auth(request(token=token))
        self.assertEqual(raised.exception.detail["code"], "auth.bad_api_key")

    def test_non_shk_bearer_tokens_fall_through_to_the_existing_chain(self):
        with self.assertRaises(HTTPException) as raised:
            auth.require_auth(request(token="some-oauth-token"))
        self.assertEqual(raised.exception.detail["code"], "auth.login_required")

    def test_request_username_reports_member_keys_and_hides_admin_keys(self):
        _, member_token = api_keys.create("mon", "member")
        req = request(token=member_token)
        auth.require_auth(req)
        self.assertEqual(auth.request_username(req), "key:mon")
        # The synthetic identity is not an account: fails closed everywhere.
        self.assertFalse(auth.is_admin("key:mon"))
        self.assertEqual(auth.allowed_resources("key:mon"), [])

        _, admin_token = api_keys.create("automation", "admin")
        req = request(token=admin_token, method="POST", path="/api/action")
        auth.require_auth(req)
        self.assertEqual(auth.request_username(req), "")


class BrowserWallTests(_Store):
    """Keys must never satisfy the browser-session-only guards."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch("hub.auth.setup_required", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_admin_key_does_not_pass_require_admin_browser(self):
        _, token = api_keys.create("automation", "admin")
        req = request(token=token, method="POST", path="/api/nfs/exports")
        # require_auth itself admits the admin key…
        self.assertTrue(auth.require_auth(req))
        # …but the route-level browser guard still refuses it: there is no
        # session cookie, and a bearer header can never produce one.
        with self.assertRaises(HTTPException) as raised:
            nas_common.require_admin_browser(req)
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(
            raised.exception.detail["code"], "admin.browser_session_required"
        )

    def test_admin_key_is_not_a_browser_session(self):
        _, token = api_keys.create("automation", "admin")
        req = request(token=token)
        self.assertTrue(auth.require_auth(req))
        self.assertFalse(auth.browser_authenticated(req))


class ManagementEndpointTests(unittest.TestCase):
    """Full-stack: /api/api-keys is reachable only by an admin browser session."""

    PASSWORD = "correct-horse-battery"

    @classmethod
    def setUpClass(cls):
        from hub.app_factory import create_app

        cls.app = create_app()

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub import audit, config

        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        data = root / "data"
        data.mkdir()
        self.audit_path = data / "auth-audit.jsonl"
        for target, attr, value in (
            (config, "YAML_PATH", root / "services.yaml"),
            (config, "DATA_DIR", data),
            (config, "BASE", root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (api_keys, "STORE_FILE", data / "api-keys.json"),
            (audit, "AUDIT_PATH", self.audit_path),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        auth._login_attempts.clear()
        api_keys._last_seen.clear()
        auth.set_password(self.PASSWORD, "admin")
        self.client = TestClient(self.app)

    def sign_in(self):
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": self.PASSWORD}
        )
        assert response.status_code == 200

    def test_management_needs_an_admin_browser_session(self):
        self.assertEqual(self.client.get("/api/api-keys").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/api-keys", json={"name": "x", "role": "member"}
            ).status_code,
            401,
        )

    def test_an_admin_key_cannot_manage_keys(self):
        """A credential must not be able to mint or destroy credentials."""
        _, token = api_keys.create("automation", "admin")
        headers = {"Authorization": f"Bearer {token}"}
        listed = self.client.get("/api/api-keys", headers=headers)
        self.assertEqual(listed.status_code, 401)
        self.assertEqual(
            listed.json()["detail"]["code"], "admin.browser_session_required"
        )
        created = self.client.post(
            "/api/api-keys", json={"name": "evil", "role": "admin"}, headers=headers
        )
        self.assertEqual(created.status_code, 401)

    def test_admin_key_cannot_reach_browser_only_routes_full_stack(self):
        _, token = api_keys.create("automation", "admin")
        response = self.client.post(
            "/api/launcher/open", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json()["detail"]["code"], "launcher.browser_session_required"
        )

    def test_member_key_is_refused_on_admin_endpoints_full_stack(self):
        _, token = api_keys.create("mon", "member")
        response = self.client.get(
            "/api/settings", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["code"], "auth.admin_required")

    def test_create_list_revoke_lifecycle_with_audit(self):
        self.sign_in()
        created = self.client.post(
            "/api/api-keys",
            json={"name": "backup-script", "role": "admin", "expires_days": 30},
        )
        self.assertEqual(created.status_code, 200)
        body = created.json()
        token = body["key"]
        self.assertTrue(token.startswith(api_keys.PREFIX))
        record = body["record"]
        self.assertEqual(record["role"], "admin")
        self.assertIsNotNone(record["expires"])

        listed = self.client.get("/api/api-keys").json()["keys"]
        self.assertEqual([k["id"] for k in listed], [record["id"]])
        self.assertNotIn("digest", listed[0])

        # The minted key authenticates a plain API request.
        status = self.client.get(
            "/api/auth/status", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(status.status_code, 200)

        revoked = self.client.delete(f"/api/api-keys/{record['id']}")
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(self.client.get("/api/api-keys").json()["keys"], [])
        missing = self.client.delete(f"/api/api-keys/{record['id']}")
        self.assertEqual(missing.status_code, 404)

        raw = self.audit_path.read_text()
        self.assertIn("apikey.created", raw)
        self.assertIn("apikey.revoked", raw)
        self.assertNotIn(token, raw)
        self.assertNotIn(api_keys._digest(token), raw)
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        for entry in records:
            if entry["event"].startswith("apikey."):
                self.assertEqual(entry["username"], "admin")
                self.assertEqual(entry["name"], "backup-script")
                self.assertTrue(entry["kid"].startswith("ak_"))
                self.assertNotIn("key", entry)
                self.assertNotIn("digest", entry)


if __name__ == "__main__":
    unittest.main()
