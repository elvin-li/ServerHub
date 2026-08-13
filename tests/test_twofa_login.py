"""The TOTP sign-in flow end to end: pending state, second step, lifecycle.

Runs the real FastAPI app against a scratch config/data directory, so the
signed pending tokens, session cookies, epoch bumps and audit records are the
production code paths — nothing is stubbed except the filesystem locations.
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

PASSWORD = "correct-horse-battery"

#: One app for the whole module.  create_app() wires several hundred routes
#: and costs seconds; every filesystem location it touches is read per-request
#: through module globals, so the per-test sandbox patches below apply to a
#: shared instance just as well.
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
        auth.set_password(PASSWORD, "admin")
        self.client = TestClient(app())

    # ── helpers ──────────────────────────────────────────────────────────

    def login(self, password=PASSWORD, client=None):
        return (client or self.client).post(
            "/api/auth/login", json={"username": "admin", "password": password}
        )

    def enable_twofa(self, username="admin"):
        """Enable 2FA at the service level, two windows in the past.

        Confirming in the past keeps the *current* window unspent, so the test
        can immediately sign in with a fresh code without tripping the replay
        guard — the same situation as a real user who enrolled minutes ago.
        """
        then = int(time.time()) - 120
        secret = twofa_svc.begin_enrollment(username)["secret"]
        codes = twofa_svc.confirm_enrollment(
            username, totp.totp_at(secret, then), timestamp=then
        )
        assert codes is not None
        return secret, codes

    def current_code(self, secret):
        return totp.totp_at(secret, time.time())

    def audit_records(self):
        if not self.audit_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.audit_path.read_text().splitlines()
            if line.strip()
        ]


class LoginStepTests(_AppSandbox):
    def test_login_without_twofa_still_issues_the_session_directly(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertIn(auth.COOKIE_NAME, response.cookies)

    def test_login_with_twofa_withholds_the_session(self):
        self.enable_twofa()
        response = self.login()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["ok"])
        self.assertTrue(body["totp_required"])
        self.assertTrue(body["pending"])
        # The half-signed-in state must not carry a cookie of any kind.
        self.assertNotIn("set-cookie", {k.lower() for k in response.headers})
        # And the pending token is not a session, no matter where it is put.
        self.assertFalse(auth.verify_session(body["pending"]))

    def test_second_step_trades_pending_plus_code_for_a_session(self):
        secret, _ = self.enable_twofa()
        pending = self.login().json()["pending"]
        response = self.client.post(
            "/api/auth/totp/verify",
            json={"pending": pending, "code": self.current_code(secret)},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertIn(auth.COOKIE_NAME, response.cookies)
        status = self.client.get("/api/auth/status").json()
        self.assertTrue(status["authenticated"])
        self.assertEqual(status["username"], "admin")
        events = [r["event"] for r in self.audit_records()]
        self.assertIn(audit.LOGIN_OK, events)
        ok = [r for r in self.audit_records() if r["event"] == audit.LOGIN_OK][-1]
        self.assertEqual(ok["method"], "totp")

    def test_wrong_code_fails_and_burns_the_shared_budget(self):
        self.enable_twofa()
        pending = self.login().json()["pending"]
        for _ in range(5):
            response = self.client.post(
                "/api/auth/totp/verify", json={"pending": pending, "code": "000000"}
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"]["code"], "auth.bad_totp")
        limited = self.client.post(
            "/api/auth/totp/verify", json={"pending": pending, "code": "000000"}
        )
        self.assertEqual(limited.status_code, 429)
        failures = [
            r for r in self.audit_records() if r["event"] == audit.LOGIN_FAILED
        ]
        self.assertEqual(len(failures), 5)
        self.assertTrue(all(r["method"] == "totp" for r in failures))

    def test_password_success_does_not_reset_the_code_budget(self):
        """Knowing the password must not buy unlimited code guesses."""
        self.enable_twofa()
        for _ in range(5):
            pending = self.login().json()["pending"]
            self.client.post(
                "/api/auth/totp/verify", json={"pending": pending, "code": "000000"}
            )
        # The next *login* is rate-limited too: the counter survived every
        # correct-password call in the loop above.
        response = self.login()
        self.assertEqual(response.status_code, 429)

    def test_garbage_expired_and_revoked_pending_tokens_are_refused(self):
        secret, _ = self.enable_twofa()
        code = self.current_code(secret)
        response = self.client.post(
            "/api/auth/totp/verify", json={"pending": "garbage", "code": code}
        )
        self.assertEqual(response.json()["detail"]["code"], "auth.totp_pending_invalid")

        with mock.patch.object(auth, "PENDING_TOTP_TTL", -1):
            expired = self.login().json()["pending"]
        response = self.client.post(
            "/api/auth/totp/verify", json={"pending": expired, "code": code}
        )
        self.assertEqual(response.json()["detail"]["code"], "auth.totp_pending_invalid")

        pending = self.login().json()["pending"]
        auth.bump_session_epoch("admin")  # logout-everywhere / password rotation
        response = self.client.post(
            "/api/auth/totp/verify", json={"pending": pending, "code": code}
        )
        self.assertEqual(response.json()["detail"]["code"], "auth.totp_pending_invalid")

    def test_a_session_token_is_not_a_pending_token(self):
        self.assertEqual(auth.pending_totp_username(auth.create_session("admin")), "")

    def test_recovery_code_signs_in_once_and_leaves_a_trail(self):
        _, codes = self.enable_twofa()
        pending = self.login().json()["pending"]
        response = self.client.post(
            "/api/auth/totp/verify", json={"pending": pending, "code": codes[0]}
        )
        self.assertEqual(response.status_code, 200)
        used = [
            r for r in self.audit_records() if r["event"] == audit.TWOFA_RECOVERY_USED
        ]
        self.assertEqual(len(used), 1)
        self.assertEqual(used[0]["remaining"], len(codes) - 1)
        ok = [r for r in self.audit_records() if r["event"] == audit.LOGIN_OK][-1]
        self.assertEqual(ok["method"], "recovery")

        # One-time: the same code on a fresh pending token is refused.
        pending = self.login().json()["pending"]
        response = self.client.post(
            "/api/auth/totp/verify", json={"pending": pending, "code": codes[0]}
        )
        self.assertEqual(response.status_code, 401)


class ManagementTests(_AppSandbox):
    def signed_in(self):
        self.assertEqual(self.login().status_code, 200)

    def test_management_requires_a_browser_session(self):
        self.assertEqual(self.client.get("/api/auth/totp").status_code, 401)
        self.assertEqual(self.client.post("/api/auth/totp/enroll").status_code, 401)

    def test_enroll_confirm_over_http_enables_and_kicks_old_sessions(self):
        self.signed_in()
        old_cookie = self.client.cookies[auth.COOKIE_NAME]

        enrollment = self.client.post("/api/auth/totp/enroll").json()
        self.assertIn("secret", enrollment)
        self.assertIn("otpauth://totp/", enrollment["otpauth_uri"])
        # Pairing not proven yet: nothing enabled, sign-in unchanged.
        self.assertFalse(twofa_svc.enabled("admin"))

        wrong = self.client.post("/api/auth/totp/confirm", json={"code": "000000"})
        self.assertEqual(wrong.status_code, 401)
        self.assertFalse(twofa_svc.enabled("admin"))

        good = self.client.post(
            "/api/auth/totp/confirm",
            json={"code": totp.totp_at(enrollment["secret"], time.time())},
        )
        self.assertEqual(good.status_code, 200)
        codes = good.json()["recovery_codes"]
        self.assertEqual(len(codes), twofa_svc.RECOVERY_CODES)
        self.assertTrue(twofa_svc.enabled("admin"))

        # Epoch linkage: the pre-enable session is dead, this browser's fresh
        # cookie (set by the confirm response) keeps working.
        stale = TestClient(app())
        stale.cookies.set(auth.COOKIE_NAME, old_cookie)
        self.assertFalse(stale.get("/api/auth/status").json()["authenticated"])
        self.assertTrue(self.client.get("/api/auth/status").json()["authenticated"])
        status = self.client.get("/api/auth/totp").json()
        self.assertTrue(status["enabled"])
        self.assertEqual(status["recovery_remaining"], len(codes))

    def test_disable_needs_a_valid_code_and_bumps_the_epoch(self):
        secret, _ = self.enable_twofa()
        pending = self.login().json()["pending"]
        self.client.post(
            "/api/auth/totp/verify",
            json={"pending": pending, "code": self.current_code(secret)},
        )
        old_cookie = self.client.cookies[auth.COOKIE_NAME]

        refused = self.client.post("/api/auth/totp/disable", json={"code": "000000"})
        self.assertEqual(refused.status_code, 401)
        self.assertTrue(twofa_svc.enabled("admin"))

        # The sign-in above spent the current window; wait out the counter by
        # using a recovery code instead — disable accepts either factor.
        _, codes = twofa_svc.status("admin"), None
        recovery = twofa_svc.regenerate_recovery("admin")
        done = self.client.post(
            "/api/auth/totp/disable", json={"code": recovery[0]}
        )
        self.assertEqual(done.status_code, 200)
        self.assertFalse(twofa_svc.enabled("admin"))

        stale = TestClient(app())
        stale.cookies.set(auth.COOKIE_NAME, old_cookie)
        self.assertFalse(stale.get("/api/auth/status").json()["authenticated"])
        self.assertTrue(self.client.get("/api/auth/status").json()["authenticated"])
        events = [r["event"] for r in self.audit_records()]
        self.assertIn(audit.TWOFA_DISABLED, events)

    def test_recovery_regeneration_requires_a_code_and_is_audited(self):
        secret, codes = self.enable_twofa()
        pending = self.login().json()["pending"]
        self.client.post(
            "/api/auth/totp/verify",
            json={"pending": pending, "code": self.current_code(secret)},
        )
        refused = self.client.post("/api/auth/totp/recovery", json={"code": "000000"})
        self.assertEqual(refused.status_code, 401)

        response = self.client.post(
            "/api/auth/totp/recovery", json={"code": codes[0]}
        )
        self.assertEqual(response.status_code, 200)
        new_codes = response.json()["recovery_codes"]
        self.assertEqual(len(new_codes), twofa_svc.RECOVERY_CODES)
        self.assertFalse(twofa_svc.use_recovery_code("admin", codes[1]))
        events = [r["event"] for r in self.audit_records()]
        self.assertIn(audit.TWOFA_RECOVERY_REGENERATED, events)

    def test_admin_can_force_disable_another_account(self):
        def add_member(data):
            data["settings"]["auth"]["accounts"] = [
                {"username": "kid", "password_hash": "scrypt$x", "role": "member"}
            ]
        config.mutate(add_member)
        self.enable_twofa("kid")
        self.signed_in()

        response = self.client.post(
            "/api/auth/totp/admin-disable", json={"username": "kid"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(twofa_svc.enabled("kid"))
        forced = [
            r for r in self.audit_records() if r["event"] == audit.TWOFA_FORCE_DISABLED
        ]
        self.assertEqual(len(forced), 1)
        self.assertEqual(forced[0]["username"], "admin")
        self.assertEqual(forced[0]["target"], "kid")

        again = self.client.post(
            "/api/auth/totp/admin-disable", json={"username": "kid"}
        )
        self.assertEqual(again.json()["detail"]["code"], "auth.totp_not_enabled")

    def test_member_cannot_force_disable(self):
        def add_member(data):
            data["settings"]["auth"]["accounts"] = [
                {"username": "kid", "password_hash": "scrypt$x", "role": "member"}
            ]
        config.mutate(add_member)
        self.enable_twofa("admin")
        member = TestClient(app())
        member.cookies.set(auth.COOKIE_NAME, auth.create_session("kid"))
        response = member.post(
            "/api/auth/totp/admin-disable", json={"username": "admin"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(twofa_svc.enabled("admin"))

    def test_member_can_manage_their_own_second_factor(self):
        def add_member(data):
            data["settings"]["auth"]["accounts"] = [
                {"username": "kid", "password_hash": "scrypt$x", "role": "member"}
            ]
        config.mutate(add_member)
        member = TestClient(app())
        member.cookies.set(auth.COOKIE_NAME, auth.create_session("kid"))
        enrollment = member.post("/api/auth/totp/enroll")
        self.assertEqual(enrollment.status_code, 200)
        confirmed = member.post(
            "/api/auth/totp/confirm",
            json={"code": totp.totp_at(enrollment.json()["secret"], time.time())},
        )
        self.assertEqual(confirmed.status_code, 200)
        self.assertTrue(twofa_svc.enabled("kid"))


class AuditHygieneTests(_AppSandbox):
    def test_the_trail_never_contains_secret_material(self):
        """Drive the full lifecycle, then audit the audit."""
        self.signed = self.login()
        enrollment = self.client.post("/api/auth/totp/enroll").json()
        secret = enrollment["secret"]
        confirm = self.client.post(
            "/api/auth/totp/confirm", json={"code": totp.totp_at(secret, time.time())}
        )
        recovery_codes = confirm.json()["recovery_codes"]
        # Sign in again with a recovery code from a second browser.
        other = TestClient(app())
        pending = self.login(client=other).json()["pending"]
        other.post(
            "/api/auth/totp/verify",
            json={"pending": pending, "code": recovery_codes[0]},
        )

        raw = self.audit_path.read_text()
        self.assertIn(audit.TWOFA_ENABLED, raw)
        self.assertNotIn(secret, raw)
        for code in recovery_codes:
            self.assertNotIn(code, raw)
            self.assertNotIn(code.replace("-", ""), raw)
        for record in self.audit_records():
            self.assertNotIn("code", record)
            self.assertNotIn("secret", record)
            self.assertNotIn("pending", record)


if __name__ == "__main__":
    unittest.main()
