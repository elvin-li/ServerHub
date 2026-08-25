"""Leftover over-cap ints in ``settings.auth`` vs the login/setup/2FA write path.

YAML hex (``0x…``) loads through ``int(x, 16)``, which CPython's 4300-digit
str<->int cap does not bound, so a leftover huge int *anywhere* in the auth
block (a stray hand-edited field, an explicit-key ``? 0x…`` mapping key)
parsed fine and then ValueError'd ``yaml.safe_dump`` inside every auth write.
``config._dump`` degrades that to a coded 503, which meant:

* POST /api/auth/setup and /api/auth/change-password could never succeed —
  the panel was permanently unclaimable / the password unrotatable;
* POST /api/auth/totp/confirm enabled 2FA in twofa.json and *then* 503'd,
  losing the one-time recovery codes for good;
* POST /api/auth/logout answered 200 while the epoch bump silently failed,
  so the "revoked" cookie stayed valid for its full 7-day TTL.

Also pinned here (stays-immune classes, reproduced against the real app):

* lone-surrogate leftovers in auth-block keys AND values (the YAML
  ``"\\uD800"`` escape loads back into a real surrogate) never 500 the
  status/setup/login/logout round trip;
* a >4300-digit number literal in a request body is a 400, not a 500
  (``json.loads`` raises plain ValueError there, not JSONDecodeError);
* a >4300-digit literal in twofa.json degrades that one field instead of
  reading the store as ``{}`` — 2FA stays enforced and the enrollment
  journal is not wiped by the next save.
"""
from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, totp, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
#: What a leftover ``0xF…`` (5000 hex digits) in services.yaml loads as.
HUGE_HEX = "0x" + "F" * 5000
HUGE_INT = int("F" * 5000, 16)

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def _claimed_yaml_with_huge_leftovers(password_hash: str) -> str:
    """A claimed auth block carrying over-cap ints as a value AND a key."""
    return (
        "settings:\n"
        "  auth:\n"
        "    enabled: true\n"
        "    username: admin\n"
        f'    password_hash: "{password_hash}"\n'
        f"    legacy_junk: {HUGE_HEX}\n"
        f"    ? {HUGE_HEX}\n"
        "    : keyed\n"
        "    session_epochs:\n"
        f"      admin: {HUGE_HEX}\n"
        f"      ? {HUGE_HEX}\n"
        "      : 3\n"
    )


SURROGATE_UNCLAIMED_YAML = (
    "settings:\n"
    "  auth:\n"
    "    enabled: true\n"
    '    username: "adm\\uD800in"\n'
    '    setup_token_mode: "\\uD800"\n'
    '    "\\uD800": "junk-key"\n'
    '    note: "\\uDFFF"\n'
)


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
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
        self.yaml_path.write_text(text)
        config.reload_cfg()

    def claim_with_huge_leftovers(self) -> None:
        self.write_config(_claimed_yaml_with_huge_leftovers(auth.hash_password(PASSWORD)))

    def login(self, password=PASSWORD, username="admin"):
        return self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    def stored_auth(self) -> dict:
        return yaml.safe_load(self.yaml_path.read_text())["settings"]["auth"]


class HugeLeftoverWritePathTests(_AppSandbox):
    def test_logout_revocation_lands_despite_huge_auth_leftovers(self):
        """Logout said 200 while the epoch bump silently failed: the cookie
        it claimed to revoke kept verifying for its full 7-day TTL."""
        self.claim_with_huge_leftovers()
        response = self.login()
        self.assertEqual(response.status_code, 200)
        token = response.cookies[auth.COOKIE_NAME]
        self.assertTrue(auth.verify_session(token))
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)
        self.assertFalse(auth.verify_session(token))
        stored = self.stored_auth()
        # The bump actually reached disk, past the corrupt epoch window (the
        # huge leftover reads back as 1, so the landed counter is 2)...
        self.assertEqual(stored["session_epochs"]["admin"], 2)
        # ...and the unrenderable junk that blocked the save is gone.
        self.assertNotIn("legacy_junk", stored)
        self.assertNotIn(HUGE_INT, stored)

    def test_change_password_succeeds_despite_huge_auth_leftovers(self):
        """The rotation 503'd (settings.save_failed) on the leftover forever."""
        self.claim_with_huge_leftovers()
        self.assertEqual(self.login().status_code, 200)
        response = self.client.post(
            "/api/auth/change-password",
            json={
                "username": "admin",
                "current_password": PASSWORD,
                "new_password": PASSWORD + "2",
            },
        )
        self.assertEqual(response.status_code, 200)
        auth._login_attempts.clear()
        self.assertEqual(self.login(PASSWORD + "2").status_code, 200)
        self.assertNotIn("legacy_junk", self.stored_auth())

    def test_setup_claims_despite_huge_auth_leftovers(self):
        """An unclaimed panel with the leftover could never be claimed (503)."""
        self.write_config(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            f"    legacy_junk: {HUGE_HEX}\n"
            f"    ? {HUGE_HEX}\n"
            "    : keyed\n"
        )
        self.assertTrue(auth.setup_required())
        response = self.client.post(
            "/api/auth/setup",
            json={
                "username": "admin",
                "password": PASSWORD,
                "setup_token": auth.setup_token(),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.login().status_code, 200)
        stored = self.stored_auth()
        self.assertTrue(str(stored["password_hash"]).startswith("scrypt$"))
        self.assertNotIn("legacy_junk", stored)

    def test_totp_confirm_returns_recovery_codes_despite_huge_auth_leftovers(self):
        """Confirm enabled 2FA, then 503'd on the epoch bump: the one-time
        recovery codes never reached the browser and were lost for good."""
        self.claim_with_huge_leftovers()
        self.assertEqual(self.login().status_code, 200)
        enroll = self.client.post("/api/auth/totp/enroll")
        self.assertEqual(enroll.status_code, 200)
        secret = enroll.json()["secret"]
        confirm = self.client.post(
            "/api/auth/totp/confirm",
            json={"code": totp.totp_at(secret, time.time())},
        )
        self.assertEqual(confirm.status_code, 200)
        codes = confirm.json()["recovery_codes"]
        self.assertEqual(len(codes), twofa_svc.RECOVERY_CODES)
        self.assertTrue(twofa_svc.enabled("admin"))

    def test_totp_confirm_survives_a_failing_epoch_bump(self):
        """Any save failure (EIO, junk outside the auth block) raising out of
        the bump used to withhold the recovery codes after 2FA was enabled."""
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")
        client = TestClient(app(), raise_server_exceptions=False)
        self.assertEqual(
            client.post(
                "/api/auth/login", json={"username": "admin", "password": PASSWORD}
            ).status_code,
            200,
        )
        enroll = client.post("/api/auth/totp/enroll")
        secret = enroll.json()["secret"]
        with mock.patch.object(
            auth, "bump_session_epoch", side_effect=RuntimeError("save died")
        ):
            confirm = client.post(
                "/api/auth/totp/confirm",
                json={"code": totp.totp_at(secret, time.time())},
            )
        self.assertEqual(confirm.status_code, 200)
        self.assertEqual(
            len(confirm.json()["recovery_codes"]), twofa_svc.RECOVERY_CODES
        )
        self.assertTrue(twofa_svc.enabled("admin"))

    def test_totp_disable_survives_a_failing_epoch_bump(self):
        """The disable had already persisted; a 503 only misreported it."""
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")
        client = TestClient(app(), raise_server_exceptions=False)
        client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
        then = int(time.time()) - 120
        secret = twofa_svc.begin_enrollment("admin")["secret"]
        self.assertIsNotNone(
            twofa_svc.confirm_enrollment("admin", totp.totp_at(secret, then), timestamp=then)
        )
        with mock.patch.object(
            auth, "bump_session_epoch", side_effect=RuntimeError("save died")
        ):
            response = client.post(
                "/api/auth/totp/disable",
                json={"code": totp.totp_at(secret, time.time())},
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(twofa_svc.enabled("admin"))


class RenderableScrubUnitTests(unittest.TestCase):
    def test_auth_block_drops_unrenderable_int_leftovers(self):
        data = {
            "settings": {
                "auth": {
                    "username": "admin",
                    "password_hash": "scrypt$x",
                    "legacy_junk": HUGE_INT,
                    HUGE_INT: "keyed",
                    "accounts": [
                        {"username": "mom", "password_hash": "x", "note": HUGE_INT},
                    ],
                    "session_epochs": {"kid": HUGE_INT},
                }
            }
        }
        _, cleaned = auth._auth_block(data)
        yaml.safe_dump({"settings": {"auth": cleaned}})
        self.assertNotIn("legacy_junk", cleaned)
        self.assertNotIn(HUGE_INT, cleaned)
        self.assertNotIn("note", cleaned["accounts"][0])
        self.assertEqual(cleaned["accounts"][0]["username"], "mom")
        # _clean_epochs semantics still win: the corrupt epoch reads as 1
        # (logged out at least once), it is not dropped to 0.
        self.assertEqual(cleaned["session_epochs"], {"kid": 1})

    def test_renderable_preserves_normal_and_surrogate_data(self):
        block = {
            "enabled": True,
            "username": "adm\ud800in",
            "note": "\udfff",
            "count": 7,
            "accounts": [{"resources": ["jellyfin", 3]}],
        }
        self.assertEqual(auth._renderable(dict(block)), block)


class StaysImmuneSurrogateRoundTripTests(_AppSandbox):
    def test_surrogate_auth_keys_and_values_do_not_500_the_first_run(self):
        """YAML ``"\\uD800"`` escapes load back into real lone surrogates; the
        status probe, the setup mutate that carries them along, login and
        logout must all keep answering, and status stays JSON-encodable."""
        self.write_config(SURROGATE_UNCLAIMED_YAML)
        status = self.client.get("/api/auth/status")
        self.assertEqual(status.status_code, 200)
        body = status.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(body["username"], "admin")
        self.assertTrue(body["setup_required"])
        response = self.client.post(
            "/api/auth/setup",
            json={
                "username": "admin",
                "password": PASSWORD,
                "setup_token": auth.setup_token(),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)


class StaysImmuneRequestBodyDigitCapTests(_AppSandbox):
    def _post_raw(self, path: str, payload: str):
        return self.client.post(
            path,
            content=payload.encode(),
            headers={"content-type": "application/json"},
        )

    def test_huge_number_literals_in_bodies_are_4xx_not_500(self):
        """``json.loads`` of a >4300-digit literal raises plain ValueError,
        not JSONDecodeError; the body parse must still answer 400."""
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")
        huge = "1" * 4400
        for path, payload in (
            ("/api/auth/login", '{"username": ' + huge + ', "password": "x"}'),
            ("/api/auth/login", '{"username": "admin", "password": "x", "e": ' + huge + "}"),
            ("/api/auth/totp/verify", '{"pending": "x", "code": ' + huge + "}"),
            (
                "/api/auth/setup",
                '{"username": "a", "password": "0123456789", "setup_token": ' + huge + "}",
            ),
        ):
            with self.subTest(path=path):
                response = self._post_raw(path, payload)
                self.assertEqual(response.status_code, 400)

    def test_surrogate_username_in_body_is_coded_not_500(self):
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")
        response = self._post_raw(
            "/api/auth/login", '{"username": "\\ud800", "password": "x-wrong-pass"}'
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "auth.bad_credentials")


class StaysImmuneTwofaJournalTests(_AppSandbox):
    def test_huge_literal_in_twofa_json_does_not_wipe_the_journal(self):
        """The digit-cap ValueError out of ``json.loads`` is not
        JSONDecodeError; reading the store as ``{}`` used to silently turn
        2FA off and the next save rewrote the file without the enrollment."""
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")
        then = int(time.time()) - 120
        secret = twofa_svc.begin_enrollment("admin")["secret"]
        self.assertIsNotNone(
            twofa_svc.confirm_enrollment("admin", totp.totp_at(secret, then), timestamp=then)
        )
        raw = twofa_svc.STORE_FILE.read_text()
        twofa_svc.STORE_FILE.write_text(raw[: raw.rindex("}")] + ', "junk": ' + "9" * 4400 + "}")
        response = self.login()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # 2FA is still enforced: the login answers a pending token, no cookie.
        self.assertTrue(body["totp_required"])
        verify = self.client.post(
            "/api/auth/totp/verify",
            json={"pending": body["pending"], "code": totp.totp_at(secret, time.time())},
        )
        self.assertEqual(verify.status_code, 200)
        # The save that spent the code kept the enrollment on disk.
        stored = json.loads(twofa_svc.STORE_FILE.read_text())
        self.assertTrue(stored["admin"]["enabled"])


if __name__ == "__main__":
    unittest.main()
