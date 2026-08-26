"""Stays-immune HTTP pins for the login / auth / session / 2FA surface (sixth sweep).

A sixth sweep of the sign-in surface (login/login2..5 came before) found no
live unhandled 500 left.  This module pins, over the *real* app with
``TestClient(raise_server_exceptions=False)``, the corners the earlier sweeps
covered only at the unit level (direct ``twofa_svc`` / ``auth`` calls) or not
at the HTTP layer at all — the layer where the middleware, the body parse and
Starlette's ``allow_nan=False`` encoder all take part:

* a leftover **FIFO** squatting a token/store/journal/lock path must not *hang*
  the request (the ``O_NONBLOCK`` + ``S_ISREG`` guards in ``util`` / ``secure_io``)
  and must not 500: enroll over a FIFO ``twofa.json`` still succeeds, an
  api-keys create over a FIFO store still mints a key, the audit read over a
  FIFO journal answers an empty trail, a logout mutate over a FIFO
  ``.services.yaml.lock`` still bumps the epoch, and status/logout over a FIFO
  ``services.yaml`` degrade rather than park;
* the whole **TOTP self-service lifecycle** (status/enroll/confirm/disable/
  recovery) over HTTP survives a poisoned ``twofa.json`` (a >4300-digit int
  field, a lone surrogate, a list-shaped row, a sibling ``1e309``) with a
  coded 4xx or a 200, never a 500, and every body stays UTF-8-renderable;
* ``POST /api/auth/totp/admin-disable`` with a numeric / surrogate / colon /
  over-long target stays the coded 400, never a 500 in the ``disable`` /
  epoch-bump path;
* ``GET /api/audit/auth`` over a poisoned ``auth-audit.jsonl`` (a digit-cap int
  line, a surrogate field, a 400-deep nest, a 200 KB fat line, torn non-UTF-8
  bytes, a FIFO) stays 200 with a UTF-8-renderable body;
* a numeric account name (``username: 2024`` round-trips as an int) that *also*
  has 2FA enrolled, sitting beside a digit-cap ``session_epochs`` leftover,
  signs in to the pending-TOTP step (200) and a wrong code stays the coded 401;
* first-run ``POST /api/auth/setup`` with the correct token and a pathological
  username: numeric succeeds, a colon name is the coded 400, a lone-surrogate
  name is the 422 Pydantic rejects it with — never a 500;
* an oversize / torn ``services.yaml`` degrades the auth surface (status,
  login, logout) to a coded response, never a 500 raised inside a handler.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, totp, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
HUGE_LITERAL = "9" * 4400
#: A stable TOTP secret so the pending-step tests are deterministic.
SECRET = "JBSWY3DPEHPK3PXP"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def _raw(obj) -> bytes:
    """JSON bytes preserving lone surrogates a real client can put on the wire."""
    return json.dumps(obj, ensure_ascii=False).encode("utf-8", "surrogatepass")


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
        self.client = TestClient(app(), raise_server_exceptions=False)

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def claim(self) -> None:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")

    def login_admin(self) -> dict:
        if auth.setup_required():
            self.claim()
        auth._login_attempts.clear()
        r = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(r.status_code, 200)
        return {auth.COOKIE_NAME: r.cookies.get(auth.COOKIE_NAME)}

    def assertRenderable(self, response) -> None:
        # Starlette encodes with allow_nan=False + strict UTF-8; a leftover
        # surrogate or Infinity in the body is exactly what used to 500 here.
        self.assertNotEqual(response.status_code, 500, response.text[:300])
        response.content.decode("utf-8")


class LeftoverFifoDoesNotHangTests(_AppSandbox):
    """A leftover FIFO must raise (via O_NONBLOCK), never park the request."""

    def _mkfifo(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            path.unlink()
        os.mkfifo(path)

    def test_fifo_twofa_store_does_not_hang_status_or_enroll(self):
        cookie = self.login_admin()
        self._mkfifo(self.data / "twofa.json")
        status = self.client.get("/api/auth/totp", cookies=cookie)
        self.assertEqual(status.status_code, 200)
        self.assertRenderable(status)
        # enroll clears the FIFO (drop_leftover_nonfile) and writes a real store.
        enroll = self.client.post("/api/auth/totp/enroll", cookies=cookie)
        self.assertEqual(enroll.status_code, 200)
        self.assertTrue(enroll.json()["secret"])
        self.assertTrue((self.data / "twofa.json").is_file())

    def test_fifo_api_keys_store_does_not_hang_list_or_create(self):
        cookie = self.login_admin()
        self._mkfifo(self.data / "api-keys.json")
        listing = self.client.get("/api/api-keys", cookies=cookie)
        self.assertEqual(listing.status_code, 200)
        created = self.client.post(
            "/api/api-keys", json={"name": "mon", "role": "admin"}, cookies=cookie
        )
        self.assertEqual(created.status_code, 200)
        self.assertTrue((self.data / "api-keys.json").is_file())

    def test_fifo_audit_journal_does_not_hang_read(self):
        cookie = self.login_admin()
        self._mkfifo(self.data / "auth-audit.jsonl")
        read = self.client.get("/api/audit/auth", cookies=cookie)
        self.assertEqual(read.status_code, 200)
        self.assertEqual(read.json()["entries"], [])

    def test_fifo_config_lock_does_not_hang_logout_mutate(self):
        cookie = self.login_admin()
        self._mkfifo(config._LOCK_PATH)
        logout = self.client.post("/api/auth/logout", cookies=cookie)
        self.assertEqual(logout.status_code, 200)
        # The mutate cleared the FIFO and wrote a real lock file + config.
        self.assertTrue(self.yaml_path.is_file())

    def test_fifo_services_yaml_does_not_hang_status_or_logout(self):
        cookie = self.login_admin()
        self.yaml_path.unlink()
        os.mkfifo(self.yaml_path)
        config.reload_cfg()
        status = self.client.get("/api/auth/status")
        self.assertEqual(status.status_code, 200)
        self.assertRenderable(status)
        logout = self.client.post("/api/auth/logout", cookies=cookie)
        self.assertNotEqual(logout.status_code, 500)


class TotpSelfServiceHttpPoisonTests(_AppSandbox):
    """The whole TOTP management surface over HTTP with a poisoned store."""

    POISONS = (
        ("huge secret", '{"admin": {"enabled": true, "secret": ' + HUGE_LITERAL + "}}"),
        ("huge last_counter", '{"admin": {"enabled": true, "secret": "JBSW", "last_counter": ' + HUGE_LITERAL + "}}"),
        ("surrogate secret", '{"admin": {"enabled": true, "secret": "\\ud800"}}'),
        ("huge recovery row", '{"admin": {"enabled": true, "recovery": [' + HUGE_LITERAL + ', "x"]}}'),
        ("list document", "[1, 2, 3]"),
        ("row not a dict", '{"admin": "not-a-dict"}'),
        ("sibling infinity", '{"kid": 1e309, "admin": {"enabled": true, "confirmed_at": 1e309}}'),
    )

    def _write(self, poison: str) -> None:
        (self.data / "twofa.json").write_text(poison, encoding="utf-8")

    def test_status_enroll_confirm_disable_recovery_never_500(self):
        cookie = self.login_admin()
        for label, poison in self.POISONS:
            with self.subTest(poison=label):
                self._write(poison)
                self.assertRenderable(self.client.get("/api/auth/totp", cookies=cookie))
                self._write(poison)
                self.assertRenderable(self.client.post("/api/auth/totp/enroll", cookies=cookie))
                self._write(poison)
                self.assertRenderable(
                    self.client.post("/api/auth/totp/confirm", json={"code": "123456"}, cookies=cookie)
                )
                self._write(poison)
                self.assertRenderable(
                    self.client.post("/api/auth/totp/disable", json={"code": "123456"}, cookies=cookie)
                )
                self._write(poison)
                self.assertRenderable(
                    self.client.post("/api/auth/totp/recovery", json={"code": "123456"}, cookies=cookie)
                )


class TotpAdminDisableHttpTests(_AppSandbox):
    """admin-disable a target that never had 2FA stays the coded 400."""

    def test_pathological_targets_stay_coded_400(self):
        cookie = self.login_admin()
        for target in ("ghost", "2024", "\udce4nk", "key:mon", "x" * 64):
            with self.subTest(target=target):
                response = self.client.post(
                    "/api/auth/totp/admin-disable",
                    content=_raw({"username": target}),
                    headers={"content-type": "application/json"},
                    cookies=cookie,
                )
                # A lone-surrogate name is rejected by Pydantic as a 422; every
                # other shape reaches the route and is the coded 400.  Neither
                # is ever a 500 in the disable / epoch-bump path.
                self.assertIn(response.status_code, (400, 422), response.text[:200])
                if response.status_code == 400:
                    self.assertEqual(
                        response.json()["detail"]["code"], "auth.totp_not_enabled"
                    )


class AuditTrailReadHttpPoisonTests(_AppSandbox):
    """GET /api/audit/auth tolerates every leftover shape in the journal."""

    def test_poisoned_journal_reads_200_and_renderable(self):
        cookie = self.login_admin()
        journal = self.data / "auth-audit.jsonl"
        lines = [
            '{"ts": "x", "event": "x", "n": ' + HUGE_LITERAL + "}",
            '{"ts": "x", "event": "x", "u": "\\ud800"}',
            "{" * 400 + "}" * 400,
            '{"ts": "x", "event": "x", "big": "' + "z" * 200_000 + '"}',
            "not json at all",
            # Healthy row last, so even a limit=1 tail still returns it.
            '{"ts": "x", "event": "auth.login.ok", "username": "admin"}',
        ]
        journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
        for limit in (1, 100, 500):
            with self.subTest(limit=limit):
                response = self.client.get(f"/api/audit/auth?limit={limit}", cookies=cookie)
                self.assertEqual(response.status_code, 200)
                self.assertRenderable(response)
                # The one intact healthy row is never lost behind the poison.
                events = [e.get("event") for e in response.json()["entries"]]
                self.assertIn("auth.login.ok", events)

    def test_torn_non_utf8_journal_reads_200(self):
        cookie = self.login_admin()
        journal = self.data / "auth-audit.jsonl"
        journal.write_bytes(b'{"event": "x"}\n\xff\xfe torn line\n')
        response = self.client.get("/api/audit/auth", cookies=cookie)
        self.assertEqual(response.status_code, 200)
        self.assertRenderable(response)


class NumericMember2faHttpTests(_AppSandbox):
    """A numeric account name with 2FA + a digit-cap epoch leftover signs in."""

    def _claim_numeric_2fa_member(self) -> None:
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
            "      2024: 0x" + "a" * 5000 + "\n"
        )
        (self.data / "twofa.json").write_text(
            json.dumps({"2024": {"enabled": True, "secret": SECRET, "recovery": [], "last_counter": 0}}),
            encoding="utf-8",
        )

    def test_numeric_member_login_reaches_totp_step_and_wrong_code_is_401(self):
        self._claim_numeric_2fa_member()
        auth._login_attempts.clear()
        login = self.client.post(
            "/api/auth/login", json={"username": "2024", "password": "kid-password-12"}
        )
        self.assertEqual(login.status_code, 200)
        body = login.json()
        self.assertTrue(body["totp_required"])
        pending = body["pending"]
        self.assertTrue(pending)
        # Deterministically wrong code: shift the real one by one.
        correct = totp.totp_at(SECRET, 0)
        wrong = str((int(correct) + 1) % 1_000_000).zfill(6)
        auth._login_attempts.clear()
        verify = self.client.post(
            "/api/auth/totp/verify", json={"pending": pending, "code": wrong}
        )
        self.assertEqual(verify.status_code, 401, verify.text[:200])
        self.assertEqual(verify.json()["detail"]["code"], "auth.bad_totp")


class SetupUsernameHttpTests(_AppSandbox):
    """First-run setup with the correct token and a pathological username."""

    def _fresh_unclaimed_token(self) -> str:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        return auth.setup_token()

    def _setup(self, username: str):
        token = self._fresh_unclaimed_token()
        return self.client.post(
            "/api/auth/setup",
            content=_raw({"username": username, "password": "brand-new-pass-1", "setup_token": token}),
            headers={"content-type": "application/json"},
        )

    def test_numeric_username_setup_succeeds(self):
        response = self._setup("2024")
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertTrue(response.json()["ok"])

    def test_colon_username_is_coded_400(self):
        response = self._setup("key:x")
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "accounts.bad_username")

    def test_surrogate_username_is_422_not_500(self):
        response = self._setup("adm\udce4in")
        self.assertEqual(response.status_code, 422, response.text[:200])
        self.assertRenderable(response)


class OversizeTornConfigAuthSurfaceTests(_AppSandbox):
    """An unreadable services.yaml degrades the auth surface, never 500s it."""

    def test_oversize_config_does_not_500_status_or_login(self):
        self.claim()
        self.yaml_path.write_text(
            "settings:\n  auth:\n    username: admin\n    pad: " + "a" * (1024 * 1024 + 16) + "\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        self.assertRenderable(self.client.get("/api/auth/status"))
        auth._login_attempts.clear()
        self.assertRenderable(
            self.client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
        )

    def test_torn_non_utf8_config_does_not_500_logout(self):
        cookie = self.login_admin()
        self.yaml_path.write_bytes(b"settings:\n  auth:\n    username: \xff\xfe x\n")
        config.reload_cfg()
        logout = self.client.post("/api/auth/logout", cookies=cookie)
        self.assertNotEqual(logout.status_code, 500)


if __name__ == "__main__":
    unittest.main()
