"""Member accounts actually signing in: the multi-user flow end to end.

Before this feature the login endpoint compared the submitted name against the
single configured administrator, so a member account existed in config but
could never authenticate.  These tests run the real FastAPI app against a
scratch config/data sandbox (same rig as test_twofa_login) and cover:

* member password sign-in, wrong-password failures and the shared rate limit,
* the two-step TOTP sign-in for a member account,
* the role boundary: a member session on admin endpoints, one per router
  family (scheduler / notify / api-keys / shares / terminal / files / audit),
* member self-service password rotation with epoch/session semantics,
* the administrator accounts CRUD API and its audit trail.
"""
from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, totp, twofa_svc
from hub.app_factory import create_app

ADMIN_PASSWORD = "correct-horse-battery"
MEMBER_PASSWORD = "member-passphrase-1"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _MultiUserSandbox(unittest.TestCase):
    """Scratch services.yaml with one admin and one member account."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        data = root / "data"
        data.mkdir()
        self.data = data
        self.audit_path = data / "auth-audit.jsonl"
        for target, attr, value in (
            (config, "YAML_PATH", root / "services.yaml"),
            (config, "DATA_DIR", data),
            (config, "BASE", root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", data / "twofa.json"),
            (api_keys, "STORE_FILE", data / "api-keys.json"),
            (audit, "AUDIT_PATH", self.audit_path),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        auth._login_attempts.clear()
        auth.set_password(ADMIN_PASSWORD, "admin")
        auth.create_account(
            "mom", MEMBER_PASSWORD, role=auth.ROLE_MEMBER, resources=["jellyfin"]
        )
        self.client = TestClient(app())

    # ── helpers ──────────────────────────────────────────────────────────

    def login(self, username, password, client=None):
        return (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    def login_member(self, client=None):
        return self.login("mom", MEMBER_PASSWORD, client=client)

    def member_session(self):
        client = TestClient(app())
        response = self.login_member(client=client)
        assert response.status_code == 200, response.text
        return client

    def admin_session(self):
        client = TestClient(app())
        response = self.login("admin", ADMIN_PASSWORD, client=client)
        assert response.status_code == 200, response.text
        return client

    def audit_records(self):
        if not self.audit_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.audit_path.read_text().splitlines()
            if line.strip()
        ]

    def enable_twofa(self, username):
        then = int(time.time()) - 120
        secret = twofa_svc.begin_enrollment(username)["secret"]
        codes = twofa_svc.confirm_enrollment(
            username, totp.totp_at(secret, then), timestamp=then
        )
        assert codes is not None
        return secret, codes


class MemberLoginTests(_MultiUserSandbox):
    def test_member_signs_in_and_the_session_carries_their_identity(self):
        response = self.login_member()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["username"], "mom")
        self.assertEqual(body["role"], "member")
        self.assertEqual(body["resources"], ["jellyfin"])
        self.assertFalse(body["can_manage"])
        self.assertIn(auth.COOKIE_NAME, response.cookies)

        status = self.client.get("/api/auth/status").json()
        self.assertTrue(status["authenticated"])
        self.assertEqual(status["username"], "mom")
        self.assertEqual(status["role"], "member")
        self.assertEqual(status["resources"], ["jellyfin"])
        self.assertFalse(status["can_manage"])

        ok = [r for r in self.audit_records() if r["event"] == audit.LOGIN_OK]
        self.assertEqual(ok[-1]["username"], "mom")

    def test_admin_login_is_unchanged(self):
        response = self.login("admin", ADMIN_PASSWORD)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["role"], "admin")
        self.assertTrue(body["can_manage"])

    def test_wrong_member_password_fails_and_is_audited_with_the_name(self):
        response = self.login("mom", "not-her-password")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "auth.bad_credentials")
        failed = [r for r in self.audit_records() if r["event"] == audit.LOGIN_FAILED]
        self.assertEqual(failed[-1]["username"], "mom")

    def test_a_members_password_does_not_open_the_admin_account(self):
        response = self.login("admin", MEMBER_PASSWORD)
        self.assertEqual(response.status_code, 401)

    def test_an_unknown_username_is_a_plain_credential_failure(self):
        response = self.login("stranger", "whatever-password")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "auth.bad_credentials")

    def test_rate_limiting_covers_member_attempts_too(self):
        for _ in range(5):
            self.login("mom", "wrong-password")
        limited = self.login_member()
        self.assertEqual(limited.status_code, 429)
        events = [r["event"] for r in self.audit_records()]
        self.assertIn(audit.LOGIN_RATE_LIMITED, events)

    def test_member_totp_two_step_yields_a_member_session(self):
        secret, _ = self.enable_twofa("mom")
        first = self.login_member()
        self.assertEqual(first.status_code, 200)
        body = first.json()
        self.assertFalse(body["ok"])
        self.assertTrue(body["totp_required"])

        second = self.client.post(
            "/api/auth/totp/verify",
            json={"pending": body["pending"], "code": totp.totp_at(secret, time.time())},
        )
        self.assertEqual(second.status_code, 200)
        result = second.json()
        self.assertEqual(result["username"], "mom")
        self.assertEqual(result["role"], "member")
        status = self.client.get("/api/auth/status").json()
        self.assertTrue(status["authenticated"])
        self.assertEqual(status["username"], "mom")

    def test_member_recovery_code_signs_in(self):
        _, codes = self.enable_twofa("mom")
        pending = self.login_member().json()["pending"]
        response = self.client.post(
            "/api/auth/totp/verify", json={"pending": pending, "code": codes[0]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "mom")


class MemberBoundaryTests(_MultiUserSandbox):
    """A member session must stay inside the read-only member surface."""

    def test_whitelisted_reads_answer_a_member(self):
        client = self.member_session()
        snapshot = {
            "system": {"hostname": "x"},
            "links": [],
            "groups": [
                {"group": "Media", "services": [
                    {"id": "jellyfin", "state": "ok"},
                    {"id": "postgres", "state": "ok"},
                ]},
            ],
        }
        with mock.patch("hub.routers.api.full_status", return_value=snapshot):
            status = client.get("/api/status")
        self.assertEqual(status.status_code, 200)
        body = status.json()
        ids = [
            svc["id"] for group in body["groups"] for svc in group["services"]
        ]
        self.assertEqual(ids, ["jellyfin"])
        self.assertEqual(body["system"], {})

        listing = {"groups": [{"group": "Media", "services": [
            {"id": "jellyfin", "state": "ok"}, {"id": "postgres", "state": "ok"},
        ]}]}
        with mock.patch(
            "hub.routers.services_api.services_manage_svc.list_manageable",
            return_value=listing,
        ):
            services = client.get("/api/services")
        self.assertEqual(services.status_code, 200)
        ids = [
            svc["id"]
            for group in services.json()["groups"]
            for svc in group["services"]
        ]
        self.assertEqual(ids, ["jellyfin"])

    def test_member_cannot_reach_admin_endpoints(self):
        client = self.member_session()
        # One representative per admin router family.  Every one of these must
        # be refused by require_auth (or the route's own stricter guard)
        # before any handler logic runs.
        refusals = [
            ("GET", "/api/scheduler/jobs", None),
            ("POST", "/api/scheduler/jobs", {}),
            ("GET", "/api/alerts/channels", None),
            ("GET", "/api/api-keys", None),
            # Bodies are schema-valid so the refusal is the guard, not a 422.
            ("POST", "/api/api-keys", {"name": "probe", "role": "admin"}),
            ("GET", "/api/auth/accounts", None),
            (
                "POST", "/api/auth/accounts",
                {"username": "probe", "password": "long-enough-pass-1"},
            ),
            ("GET", "/api/shares", None),
            # Bodyless share mutation: the refusal is the route's own
            # browser-admin guard (create_share would 422 on the body first).
            ("POST", "/api/shares/open-system-settings", None),
            ("POST", "/api/terminal/run", {"command": "id"}),
            ("GET", "/api/terminal", None),
            ("GET", "/api/files", None),
            ("GET", "/api/audit/auth", None),
            ("GET", "/api/settings", None),
            ("POST", "/api/action", {"target": "jellyfin", "action": "stop"}),
            ("GET", "/api/metrics", None),
        ]
        for method, path, body in refusals:
            with self.subTest(f"{method} {path}"):
                response = client.request(method, path, json=body)
                self.assertIn(
                    response.status_code,
                    (401, 403),
                    f"{method} {path} answered {response.status_code}",
                )

    def test_member_cannot_read_an_unassigned_service_detail(self):
        client = self.member_session()
        response = client.get("/api/services/postgres/detail")
        self.assertEqual(response.status_code, 403)

    def test_member_logout_revokes_their_sessions(self):
        client = self.member_session()
        cookie = client.cookies[auth.COOKIE_NAME]
        client.post("/api/auth/logout")
        stale = TestClient(app())
        stale.cookies.set(auth.COOKIE_NAME, cookie)
        self.assertFalse(stale.get("/api/auth/status").json()["authenticated"])


class MemberPasswordChangeTests(_MultiUserSandbox):
    def test_member_rotates_their_own_password(self):
        client = self.member_session()
        old_cookie = client.cookies[auth.COOKIE_NAME]
        response = client.post("/api/auth/change-password", json={
            "username": "mom",
            "current_password": MEMBER_PASSWORD,
            "new_password": "her-new-passphrase-9",
        })
        self.assertEqual(response.status_code, 200, response.text)

        # The old hash is gone: old sessions die, the new password signs in.
        stale = TestClient(app())
        stale.cookies.set(auth.COOKIE_NAME, old_cookie)
        self.assertFalse(stale.get("/api/auth/status").json()["authenticated"])
        self.assertTrue(client.get("/api/auth/status").json()["authenticated"])
        self.assertEqual(
            self.login("mom", "her-new-passphrase-9").status_code, 200
        )
        changed = [
            r for r in self.audit_records() if r["event"] == audit.PASSWORD_CHANGED
        ]
        self.assertEqual(changed[-1]["username"], "mom")
        # The admin credential is untouched.
        self.assertTrue(auth.verify_password(ADMIN_PASSWORD))

    def test_member_needs_their_own_current_password(self):
        client = self.member_session()
        response = client.post("/api/auth/change-password", json={
            "username": "mom",
            "current_password": ADMIN_PASSWORD,  # not hers
            "new_password": "her-new-passphrase-9",
        })
        self.assertEqual(response.status_code, 401)
        denied = [
            r for r in self.audit_records()
            if r["event"] == audit.PASSWORD_CHANGE_DENIED
        ]
        self.assertEqual(denied[-1]["username"], "mom")

    def test_member_cannot_rename_or_touch_another_account(self):
        client = self.member_session()
        for target in ("admin", "other-name"):
            response = client.post("/api/auth/change-password", json={
                "username": target,
                "current_password": MEMBER_PASSWORD,
                "new_password": "her-new-passphrase-9",
            })
            self.assertEqual(response.status_code, 403, target)

    def test_member_cannot_reuse_their_current_password(self):
        client = self.member_session()
        response = client.post("/api/auth/change-password", json={
            "username": "mom",
            "current_password": MEMBER_PASSWORD,
            "new_password": MEMBER_PASSWORD,
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "auth.password_reused")

    def test_admin_change_password_keeps_working(self):
        client = self.admin_session()
        response = client.post("/api/auth/change-password", json={
            "username": "admin",
            "current_password": ADMIN_PASSWORD,
            "new_password": "new-admin-passphrase",
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.login("admin", "new-admin-passphrase").status_code, 200)
        # Member account unaffected by the admin rotation.
        self.assertEqual(self.login_member().status_code, 200)


class AccountsApiTests(_MultiUserSandbox):
    def test_admin_lists_accounts_without_hashes(self):
        client = self.admin_session()
        response = client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        listed = response.json()["accounts"]
        self.assertEqual(
            [(a["username"], a["role"]) for a in listed],
            [("admin", "admin"), ("mom", "member")],
        )
        self.assertNotIn("password_hash", response.text)
        self.assertNotIn("scrypt$", response.text)
        self.assertEqual(listed[1]["resources"], ["jellyfin"])

    def test_admin_creates_a_member_who_can_then_sign_in(self):
        client = self.admin_session()
        response = client.post("/api/auth/accounts", json={
            "username": "kid",
            "password": "kid-passphrase-77",
            "resources": ["jellyfin", "minecraft"],
        })
        self.assertEqual(response.status_code, 200, response.text)
        account = response.json()["account"]
        self.assertEqual(account["role"], "member")
        self.assertEqual(account["resources"], ["jellyfin", "minecraft"])

        login = self.login("kid", "kid-passphrase-77")
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json()["role"], "member")

        created = [
            r for r in self.audit_records() if r["event"] == audit.ACCOUNT_CREATED
        ]
        self.assertEqual(created[-1]["username"], "admin")
        self.assertEqual(created[-1]["target"], "kid")
        # The password never reaches the trail.
        self.assertNotIn("kid-passphrase-77", self.audit_path.read_text())

    def test_creation_validates_username_password_and_duplicates(self):
        client = self.admin_session()
        bad_name = client.post("/api/auth/accounts", json={
            "username": "no spaces", "password": "long-enough-pass-1",
        })
        self.assertEqual(bad_name.json()["detail"]["code"], "accounts.bad_username")
        short = client.post("/api/auth/accounts", json={
            "username": "ok", "password": "short",
        })
        self.assertEqual(short.json()["detail"]["code"], "auth.password_too_short")
        duplicate = client.post("/api/auth/accounts", json={
            "username": "MOM", "password": "long-enough-pass-1",
        })
        self.assertEqual(duplicate.json()["detail"]["code"], "accounts.exists")

    def test_admin_updates_member_resources(self):
        client = self.admin_session()
        response = client.put("/api/auth/accounts/mom/resources", json={
            "resources": ["jellyfin", "immich"],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(auth.allowed_resources("mom"), ["jellyfin", "immich"])
        # Takes effect on the next request of an existing session.
        member = self.member_session()
        self.assertEqual(
            member.get("/api/auth/status").json()["resources"],
            ["jellyfin", "immich"],
        )
        changed = [
            r for r in self.audit_records()
            if r["event"] == audit.ACCOUNT_RESOURCES_CHANGED
        ]
        self.assertEqual(changed[-1]["target"], "mom")

    def test_admin_resets_a_member_password_killing_their_sessions(self):
        member = self.member_session()
        client = self.admin_session()
        response = client.post("/api/auth/accounts/mom/password", json={
            "new_password": "rescued-passphrase-3",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(member.get("/api/auth/status").json()["authenticated"])
        self.assertEqual(self.login("mom", "rescued-passphrase-3").status_code, 200)
        self.assertEqual(self.login("mom", MEMBER_PASSWORD).status_code, 401)
        events = [r["event"] for r in self.audit_records()]
        self.assertIn(audit.ACCOUNT_PASSWORD_RESET, events)

    def test_admin_password_cannot_be_reset_through_the_list(self):
        client = self.admin_session()
        response = client.post("/api/auth/accounts/admin/password", json={
            "new_password": "hijacked-passphrase-1",
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "accounts.not_member")

    def test_deleting_a_member_revokes_access_and_cleans_twofa(self):
        self.enable_twofa("mom")
        member = self.member_session()
        client = self.admin_session()
        response = client.request("DELETE", "/api/auth/accounts/mom")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(auth.account("mom"))
        self.assertFalse(member.get("/api/auth/status").json()["authenticated"])
        self.assertFalse(twofa_svc.enabled("mom"))
        self.assertEqual(self.login_member().status_code, 401)
        deleted = [
            r for r in self.audit_records() if r["event"] == audit.ACCOUNT_DELETED
        ]
        self.assertEqual(deleted[-1]["target"], "mom")

    def test_admin_account_cannot_be_deleted(self):
        client = self.admin_session()
        response = client.request("DELETE", "/api/auth/accounts/admin")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "accounts.not_member")

    def test_member_and_api_key_sessions_cannot_manage_accounts(self):
        member = self.member_session()
        self.assertEqual(member.get("/api/auth/accounts").status_code, 403)
        self.assertEqual(
            member.post("/api/auth/accounts", json={
                "username": "x", "password": "long-enough-pass-1",
            }).status_code,
            403,
        )
        # An admin *API key* is not a browser session; the accounts surface
        # must refuse it exactly like key management does.
        _, plaintext = api_keys.create("ci", "admin")
        bare = TestClient(app())
        response = bare.get(
            "/api/auth/accounts", headers={"Authorization": f"Bearer {plaintext}"}
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
