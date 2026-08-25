"""Account-domain stays-immune pins over the real ASGI app (2FA + API keys).

A third sweep of the Account surface (Account.vue's endpoints: TOTP
self-service, key management, member accounts) found no live 500 left — every
poisoned-store and junk-body corner already answers a coded status.  This
module pins those outcomes at the HTTP layer, where the body parse, the
same-origin middleware, the route guards and Starlette's allow_nan=False
encoder all take part, because most of them were previously proven only by
unit-level calls with ``require_admin_browser`` mocked out:

* poisoned twofa.json shapes (a >4300-digit ``last_counter`` literal, a lone
  surrogate in a row *key* and a value, an entry that is a list, a huge int
  where the secret should be) keep GET /api/auth/totp at 200 and the two-step
  sign-in completing — the digit-cap ValueError out of ``json.loads`` is not
  JSONDecodeError, and reading the store as ``{}`` used to silently switch
  2FA off panel-wide;
* an enroll → confirm cycle beside a poisoned sibling row persists without
  wiping that sibling;
* a numeric YAML account (``username: 2024`` round-trips as an *int*) walks
  the full 2FA lifecycle over HTTP — enroll, confirm, second-step sign-in
  with a recovery code, admin rescue — through the ``str()``-keyed store;
* junk bodies on the TOTP routes the earlier HTTP sweep skipped (verify /
  disable / recovery / admin-disable) stay coded 4xx: lone-surrogate strings
  are rejected by the body model, >4300-digit number literals by the body
  parse (plain ValueError, not JSONDecodeError — FastAPI maps it to 400);
* leftover api-keys.json rows with a numeric id, a lone-surrogate id, or
  wrong-typed digests (dict / int) never 500 the listing, a revoke by the
  id's string spelling, or Bearer authentication of the healthy sibling;
* deleting a member account over HTTP drops its 2FA row (a recreated
  namesake must not inherit the old authenticator).

One behavioural fix rides along (pinned in RecoveryRemainingCountTests):
``status()`` counted leftover non-string recovery rows — a huge JSON int
literal degraded to ``None``, numbers, nested objects — that
``use_recovery_code`` can never spend, overstating ``recovery_remaining``.
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
MEMBER_PASSWORD = "kid-password-12"
HUGE_LITERAL = "9" * 4400

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh signed-in client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.data = data
        self.twofa_store = data / "twofa.json"
        self.keys_store = data / "api-keys.json"
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", self.twofa_store),
            (api_keys, "STORE_FILE", self.keys_store),
            (audit, "AUDIT_PATH", data / "auth-audit.jsonl"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        api_keys._last_seen.clear()
        config.reload_cfg()
        self.client = TestClient(app())

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def claim(self) -> None:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")

    def claim_with_numeric_member(self) -> None:
        self.write_config(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            "    accounts:\n"
            "      - username: 2024\n"
            f'        password_hash: "{auth.hash_password(MEMBER_PASSWORD)}"\n'
            "        role: member\n"
        )

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response

    def raw_post(self, path: str, payload: str):
        return self.client.post(
            path,
            content=payload.encode("utf-8", "surrogatepass"),
            headers={"content-type": "application/json"},
        )


def _code_at(secret: str, timestamp=None) -> str:
    return totp.totp_at(secret, int(time.time()) if timestamp is None else timestamp)


class PoisonedTwofaStoreHttpTests(_AppSandbox):
    """Leftover twofa.json shapes over the mounted routes."""

    def _poisons(self, secret: str):
        enrolled = {
            "admin": {"enabled": True, "secret": secret, "last_counter": 0}
        }
        return (
            (
                "huge last_counter literal",
                json.dumps(enrolled).replace(
                    '"last_counter": 0', '"last_counter": ' + HUGE_LITERAL
                ),
            ),
            (
                "surrogate row key and value",
                '{"adm\\ud800in": {"enabled": true}, '
                '"admin": {"enabled": true, "secret": "' + secret + '", '
                '"last_counter": 0, "note": "\\udfff"}}',
            ),
            ("huge secret literal",
             '{"admin": {"enabled": true, "secret": ' + HUGE_LITERAL + ', '
             '"last_counter": 0}}'),
        )

    def test_status_stays_200_and_enabled(self):
        """Reading the poisoned document as {} silently disabled 2FA."""
        self.claim()
        self.sign_in()
        secret = totp.generate_secret()
        for label, document in self._poisons(secret):
            with self.subTest(poison=label):
                self.twofa_store.write_text(document, encoding="utf-8")
                response = self.client.get("/api/auth/totp")
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json()["enabled"])

    def test_two_step_sign_in_completes_where_the_secret_survives(self):
        self.claim()
        self.sign_in()
        secret = totp.generate_secret()
        for label, document in self._poisons(secret):
            if "huge secret" in label:
                continue  # an unreadable secret can never verify — but see below
            with self.subTest(poison=label):
                self.twofa_store.write_text(document, encoding="utf-8")
                fresh = TestClient(app())
                auth._login_attempts.clear()
                first = fresh.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": PASSWORD},
                )
                self.assertEqual(first.status_code, 200)
                self.assertTrue(first.json()["totp_required"])
                second = fresh.post(
                    "/api/auth/totp/verify",
                    json={"pending": first.json()["pending"], "code": _code_at(secret)},
                )
                self.assertEqual(second.status_code, 200)
                self.assertTrue(second.json()["ok"])

    def test_huge_secret_literal_fails_coded_not_500(self):
        """A secret the digit-cap hook degraded can never verify — the second
        step must answer the coded 401, never raise."""
        self.claim()
        self.sign_in()
        self.twofa_store.write_text(
            '{"admin": {"enabled": true, "secret": ' + HUGE_LITERAL + ', '
            '"last_counter": 0}}',
            encoding="utf-8",
        )
        fresh = TestClient(app())
        auth._login_attempts.clear()
        first = fresh.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["totp_required"])
        second = fresh.post(
            "/api/auth/totp/verify",
            json={"pending": first.json()["pending"], "code": "123456"},
        )
        self.assertEqual(second.status_code, 401)
        self.assertEqual(second.json()["detail"]["code"], "auth.bad_totp")

    def test_list_shaped_entry_reads_as_disabled_not_500(self):
        self.claim()
        self.sign_in()
        self.twofa_store.write_text('{"admin": [1, 2]}', encoding="utf-8")
        response = self.client.get("/api/auth/totp")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["enabled"])
        auth._login_attempts.clear()
        disable = self.client.post("/api/auth/totp/disable", json={"code": "000000"})
        self.assertEqual(disable.status_code, 400)
        self.assertEqual(disable.json()["detail"]["code"], "auth.totp_not_enabled")

    def test_enroll_confirm_does_not_wipe_the_poisoned_sibling(self):
        """The next write used to rewrite twofa.json from the empty read."""
        self.claim()
        self.sign_in()
        self.twofa_store.write_text(
            '{"kid": {"enabled": true, "secret": "AAAA", '
            '"last_counter": ' + HUGE_LITERAL + "}}",
            encoding="utf-8",
        )
        enrolled = self.client.post("/api/auth/totp/enroll")
        self.assertEqual(enrolled.status_code, 200)
        secret = enrolled.json()["secret"]
        auth._login_attempts.clear()
        confirmed = self.client.post(
            "/api/auth/totp/confirm", json={"code": _code_at(secret)}
        )
        self.assertEqual(confirmed.status_code, 200)
        self.assertEqual(len(confirmed.json()["recovery_codes"]), twofa_svc.RECOVERY_CODES)
        stored = json.loads(self.twofa_store.read_text())
        self.assertIn("kid", stored)
        self.assertTrue(stored["admin"]["enabled"])
        json.dumps(stored, ensure_ascii=False, allow_nan=False)

    def test_poisoned_pending_secret_is_coded_not_pending(self):
        """A huge-literal / list pending_secret must answer the coded 400."""
        self.claim()
        self.sign_in()
        for label, document in (
            ("huge literal", '{"admin": {"enabled": false, '
             '"pending_secret": ' + HUGE_LITERAL + "}}"),
            ("list", '{"admin": {"enabled": false, "pending_secret": ["A"]}}'),
        ):
            with self.subTest(pending=label):
                self.twofa_store.write_text(document, encoding="utf-8")
                auth._login_attempts.clear()
                response = self.client.post(
                    "/api/auth/totp/confirm", json={"code": "123456"}
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.json()["detail"]["code"], "auth.totp_not_pending"
                )


class TotpJunkBodyHttpTests(_AppSandbox):
    """Junk bodies on the TOTP routes the earlier HTTP sweep did not pin."""

    def test_surrogate_strings_stay_coded_4xx(self):
        self.claim()
        self.sign_in()
        for path, payload in (
            ("/api/auth/totp/verify", '{"pending": "x", "code": "\\ud800"}'),
            ("/api/auth/totp/confirm", '{"code": "\\ud800"}'),
            ("/api/auth/totp/disable", '{"code": "\\ud800"}'),
            ("/api/auth/totp/recovery", '{"code": "\\ud800"}'),
            ("/api/auth/totp/admin-disable", '{"username": "\\ud800"}'),
        ):
            with self.subTest(path=path):
                auth._login_attempts.clear()
                response = self.raw_post(path, payload)
                self.assertGreaterEqual(response.status_code, 400)
                self.assertLess(response.status_code, 500)

    def test_huge_number_literals_stay_400(self):
        """Plain ValueError out of the body parse is not JSONDecodeError."""
        self.claim()
        self.sign_in()
        for path, payload in (
            ("/api/auth/totp/verify",
             '{"pending": ' + HUGE_LITERAL + ', "code": "123456"}'),
            ("/api/auth/totp/disable", '{"code": ' + HUGE_LITERAL + "}"),
            ("/api/auth/totp/recovery", '{"code": ' + HUGE_LITERAL + "}"),
            ("/api/auth/totp/admin-disable",
             '{"username": ' + HUGE_LITERAL + "}"),
        ):
            with self.subTest(path=path):
                auth._login_attempts.clear()
                response = self.raw_post(path, payload)
                self.assertEqual(response.status_code, 400)

    def test_surrogate_pending_token_is_coded_401(self):
        self.claim()
        self.sign_in()
        auth._login_attempts.clear()
        response = self.raw_post(
            "/api/auth/totp/verify",
            '{"pending": "\\ud800\\udfff", "code": "123456"}',
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json()["detail"]["code"], "auth.totp_pending_invalid"
        )


class NumericAccountTwofaLifecycleTests(_AppSandbox):
    """``username: 2024`` (an int in YAML) through the whole 2FA lifecycle."""

    def test_numeric_member_enrolls_verifies_and_is_rescued(self):
        self.claim_with_numeric_member()
        member = TestClient(app())
        self.sign_in(member, "2024", MEMBER_PASSWORD)
        enrolled = member.post("/api/auth/totp/enroll")
        self.assertEqual(enrolled.status_code, 200)
        secret = enrolled.json()["secret"]
        auth._login_attempts.clear()
        confirmed = member.post(
            "/api/auth/totp/confirm", json={"code": _code_at(secret)}
        )
        self.assertEqual(confirmed.status_code, 200)
        recovery = confirmed.json()["recovery_codes"]
        # The store is keyed by the str spelling, encodable by json.dumps.
        stored = json.loads(self.twofa_store.read_text())
        self.assertEqual(list(stored), ["2024"])

        # A fresh sign-in demands the second step; a recovery code passes it.
        fresh = TestClient(app())
        auth._login_attempts.clear()
        first = fresh.post(
            "/api/auth/login",
            json={"username": "2024", "password": MEMBER_PASSWORD},
        )
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["totp_required"])
        auth._login_attempts.clear()
        second = fresh.post(
            "/api/auth/totp/verify",
            json={"pending": first.json()["pending"], "code": recovery[0]},
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["username"], "2024")

        # Admin rescue names the numeric account by its string spelling.
        self.sign_in()
        listing = self.client.get("/api/auth/accounts")
        self.assertEqual(listing.status_code, 200)
        rows = {row["username"]: row for row in listing.json()["accounts"]}
        self.assertTrue(rows["2024"]["twofa_enabled"])
        rescued = self.client.post(
            "/api/auth/totp/admin-disable", json={"username": "2024"}
        )
        self.assertEqual(rescued.status_code, 200)
        self.assertEqual(json.loads(self.twofa_store.read_text()), {})

    def test_deleting_the_member_drops_its_twofa_row(self):
        """A recreated namesake must not inherit the old authenticator."""
        self.claim_with_numeric_member()
        twofa_svc.begin_enrollment("2024")
        self.assertIn("2024", json.loads(self.twofa_store.read_text()))
        self.sign_in()
        deleted = self.client.request("DELETE", "/api/auth/accounts/2024")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(json.loads(self.twofa_store.read_text()), {})


class ApiKeysLeftoverRowsHttpTests(_AppSandbox):
    """Leftover api-keys.json row shapes over the mounted management routes."""

    def _create_key(self):
        created = self.client.post(
            "/api/api-keys", json={"name": "mon", "role": "member"}
        )
        self.assertEqual(created.status_code, 200)
        return created.json()["record"]["id"], created.json()["key"]

    def _splice_rows(self, rows: list[dict]) -> None:
        stored = json.loads(self.keys_store.read_text())
        stored["keys"].extend(rows)
        self.keys_store.write_text(json.dumps(stored, ensure_ascii=True))

    def test_numeric_and_surrogate_id_rows_stay_coded(self):
        self.claim()
        self.sign_in()
        key_id, token = self._create_key()
        self._splice_rows([
            {"id": 2024, "name": "numeric", "role": "member", "digest": "ff"},
            {"id": "\ud800", "name": "surr", "role": "member", "digest": "ff"},
        ])
        listing = self.client.get("/api/api-keys")
        self.assertEqual(listing.status_code, 200)
        ids = {row["id"] for row in listing.json()["keys"]}
        self.assertIn(key_id, ids)
        self.assertIn("2024", ids)  # str() probe, not isinstance(id, str)
        # Revoke by the string spelling of the numeric id.
        revoked = self.client.delete("/api/api-keys/2024")
        self.assertEqual(revoked.status_code, 200)
        # Junk ids in the path answer the coded 404.
        for junk in ("%ED%A0%80", "%00", "9" * 4300):
            with self.subTest(key_id=junk):
                response = self.client.delete(f"/api/api-keys/{junk}")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(
                    response.json()["detail"]["code"], "apikeys.not_found"
                )
        # The healthy sibling still authenticates through the poison.
        bare = TestClient(app())
        status = bare.get(
            "/api/status", headers={"authorization": f"Bearer {token}"}
        )
        self.assertEqual(status.status_code, 200)

    def test_wrong_typed_digests_do_not_500_bearer_or_listing(self):
        self.claim()
        self.sign_in()
        _, token = self._create_key()
        self._splice_rows([
            {"id": "ak_bad", "name": "bad", "role": "member", "digest": {"a": 1}},
            {"id": "ak_bad2", "name": "bad2", "role": "member", "digest": 12345},
        ])
        bare = TestClient(app())
        status = bare.get(
            "/api/status", headers={"authorization": f"Bearer {token}"}
        )
        self.assertEqual(status.status_code, 200)
        listing = self.client.get("/api/api-keys")
        self.assertEqual(listing.status_code, 200)


class RecoveryRemainingCountTests(_AppSandbox):
    """recovery_remaining must count only rows a spend could ever match."""

    def test_unspendable_junk_rows_are_not_counted(self):
        """A huge int literal (degraded to None by the digit-cap hook), a
        number and a nested object can never satisfy ``_digest_eq`` — the
        count is the operator's cue to regenerate, so junk inflating it hid
        that the real codes had run out."""
        self.claim()
        self.sign_in()
        digest = twofa_svc._hash_recovery("ABCDE-FGHJK")
        self.twofa_store.write_text(
            '{"admin": {"enabled": true, "secret": "AAAA", "last_counter": 0, '
            '"recovery": [' + HUGE_LITERAL + ', 42, {"x": 1}, "' + digest + '"]}}',
            encoding="utf-8",
        )
        response = self.client.get("/api/auth/totp")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["recovery_remaining"], 1)

    def test_string_rows_still_count_and_spend(self):
        self.claim()
        self.sign_in()
        codes = [twofa_svc._hash_recovery("AAAAA-BBBBB"),
                 twofa_svc._hash_recovery("CCCCC-DDDDD")]
        self.twofa_store.write_text(
            json.dumps({"admin": {
                "enabled": True, "secret": "AAAA", "last_counter": 0,
                "recovery": codes,
            }}),
            encoding="utf-8",
        )
        self.assertEqual(twofa_svc.status("admin")["recovery_remaining"], 2)
        self.assertTrue(twofa_svc.use_recovery_code("admin", "AAAAA-BBBBB"))
        self.assertEqual(twofa_svc.status("admin")["recovery_remaining"], 1)


if __name__ == "__main__":
    unittest.main()
