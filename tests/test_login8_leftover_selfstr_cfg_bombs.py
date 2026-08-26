"""Eighth leftover-500s sweep of the Login / auth-config surface.

The find: the login7 hardening laundered the ``settings.auth`` *mappings*
(unbound ``dict.get`` / ``dict.items`` / ``list.__iter__``) but every
*text field* still flowed through ``_cfg_text``'s bare ``str(raw)`` — and
``str(x)`` of a str **subclass whose __str__ returns itself** keeps the
subclass (the json6 ``panel_locale`` / settings-sanitizer class, sealed
elsewhere on this tree but never here).  Every downstream bound dispatch
then reflected into leftover overrides, and driven through ``create_app()``
+ ``TestClient(raise_server_exceptions=False)`` these were live raw HTTP
500s on the pre-fix tree:

* a strip-bombed ``username`` 500'd POST /api/auth/login and every
  session-cookie check (``accounts()``'s ``.strip()`` on the legacy name);
* a strip/lower-bombed ``setup_token_mode`` 500'd the unauthenticated
  GET /api/auth/status (``setup_token_mode()``'s ``.strip().lower()``);
* a reflected-``__eq__``-bombed legacy ``password`` 500'd status
  (``_auth_is_claimed``'s ``not in ("", "change-me")``);
* a ``startswith``-bombed ``password_hash`` 500'd every admin login
  (``verify_password``'s ``encoded.startswith("scrypt$")``), and the same
  bomb in an accounts-row hash 500'd that member's login
  (``verify_account_password``);
* a strip-bombed ``session_epochs`` *key* 500'd every login and cookie
  check (``_epoch_key``'s ``.strip()`` past the login7 ``__str__`` guard);
* a strip-bombed accounts-row ``username``, a reflected-``__eq__``-bombed
  row ``role`` (``role not in ROLES``), and a strip/encode-bombed
  ``resources`` entry each 500'd every login out of ``accounts()``.

Fixes, all in hub/auth.py, all the json6 conventions: ``_cfg_text``
launders to an *exact* str via ``str.__str__`` (the C-level copy keeps the
real text underneath the poisoned override), ``_utf8_ok`` moves to unbound
``str.encode`` with a broad fail-closed catch, and ``_utf8`` launders and
encodes unbound so a subclass ``encode`` bomb cannot raise out of
``account_session_version`` past ``verify_session``'s catch list.

Stays-immune semantics pinned alongside: the laundering *keeps the data* —
the admin still signs in when their stored username is the bombed
spelling, a member row with a bombed name/role/resources still signs in
with its real grants, and a bombed epoch key still revokes pre-logout
cookies through its real counter.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
MEMBER_PASSWORD = "kid-password-12"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _SelfStr(str):
    """The json6 class: ``__str__`` returns self, bound methods bomb."""

    def __str__(self):
        return self

    def strip(self, *a):
        raise RuntimeError("leftover strip bomb")

    def lower(self):
        raise RuntimeError("leftover lower bomb")

    def encode(self, *a, **k):
        raise RuntimeError("leftover encode bomb")

    def startswith(self, *a):
        raise RuntimeError("leftover startswith bomb")

    def split(self, *a):
        raise RuntimeError("leftover split bomb")


class _EqStr(str):
    """Reflected ``__eq__`` bomb (hash intact so it can sit anywhere)."""

    def __str__(self):
        return self

    def __eq__(self, other):
        raise RuntimeError("leftover eq bomb")

    def __hash__(self):
        return str.__hash__(self)


class _StartsStr(str):
    def __str__(self):
        return self

    def startswith(self, *a):
        raise RuntimeError("leftover startswith bomb")


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
        self.yaml_path.write_text(
            "settings:\n  auth:\n    enabled: true\n", encoding="utf-8"
        )
        config.reload_cfg()
        auth.set_password(PASSWORD, "admin")
        self.admin_hash = auth._auth_cfg()["password_hash"]
        self.member_hash = auth.hash_password(MEMBER_PASSWORD)
        self.client = TestClient(app(), raise_server_exceptions=False)

    def base_auth(self, **extra) -> dict:
        block = {
            "enabled": True,
            "username": "admin",
            "password_hash": self.admin_hash,
        }
        block.update(extra)
        return {"settings": {"auth": block}}

    def member_row(self, **extra) -> dict:
        row = {
            "username": "kid",
            "password_hash": self.member_hash,
            "role": "member",
            "resources": ["svc"],
        }
        row.update(extra)
        return row

    def cfg_patch(self, shape):
        return mock.patch.object(auth, "cfg", lambda: shape)

    def login(self, username: str, password: str):
        auth._login_attempts.clear()
        return self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    def admin_cookie(self) -> dict:
        response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 200)
        return {auth.COOKIE_NAME: response.cookies.get(auth.COOKIE_NAME)}

    def assertRenderable(self, response) -> None:
        # Starlette encodes with allow_nan=False + strict UTF-8; a raised
        # subclass bomb is exactly what used to turn these into raw 500s.
        self.assertNotEqual(response.status_code, 500, response.text[:300])
        response.content.decode("utf-8")


class _Shapes:
    """The pre-fix live-500 shapes, shared by the status/login/cookie pins."""

    def shapes(self):
        return (
            ("username strip bomb", self.base_auth(username=_SelfStr("admin"))),
            ("password_hash startswith bomb", {
                "settings": {"auth": {"enabled": True, "username": "admin",
                                      "password_hash": _StartsStr("x")}},
            }),
            ("legacy password eq bomb", {
                "settings": {"auth": {"enabled": True,
                                      "password": _EqStr("legacy-pw-1")}},
            }),
            ("setup_token_mode strip bomb",
             self.base_auth(setup_token_mode=_SelfStr("auto"))),
            ("epoch key strip bomb",
             self.base_auth(session_epochs={_SelfStr("admin"): 0})),
            ("row username strip bomb",
             self.base_auth(accounts=[self.member_row(username=_SelfStr("kid"))])),
            ("row role eq bomb",
             self.base_auth(accounts=[self.member_row(role=_EqStr("member"))])),
            ("row hash startswith bomb",
             self.base_auth(accounts=[self.member_row(password_hash=_StartsStr("x"))])),
            ("row resources strip bomb",
             self.base_auth(accounts=[self.member_row(resources=[_SelfStr("svc")])])),
        )


class StatusSelfStrBombTests(_AppSandbox, _Shapes):
    """GET /api/auth/status answers 200 under every self-__str__ shape."""

    def test_status_stays_200_under_every_shape(self):
        for label, shape in self.shapes():
            with self.subTest(shape=label):
                with self.cfg_patch(shape):
                    response = self.client.get("/api/auth/status")
                self.assertEqual(response.status_code, 200, response.text[:300])
                self.assertRenderable(response)

    def test_eq_bombed_legacy_password_still_reads_claimed(self):
        # str.__str__ keeps the real text, so the credential stays a
        # credential: status reports claimed, not "setup required".
        shape = {"settings": {"auth": {"enabled": True,
                                       "password": _EqStr("legacy-pw-1")}}}
        with self.cfg_patch(shape):
            response = self.client.get("/api/auth/status")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["setup_required"])


class LoginSelfStrBombTests(_AppSandbox, _Shapes):
    """POST /api/auth/login: the laundering keeps the real data."""

    def test_admin_login_never_500s_under_any_shape(self):
        for label, shape in self.shapes():
            with self.subTest(shape=label):
                with self.cfg_patch(shape):
                    response = self.login("admin", PASSWORD)
                self.assertRenderable(response)

    def test_admin_signs_in_when_their_stored_name_is_the_bomb(self):
        # accounts()'s ``.strip()`` on the legacy name was the 500; the
        # exact-str copy keeps "admin" so the real hash still verifies.
        with self.cfg_patch(self.base_auth(username=_SelfStr("admin"))):
            response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])

    def test_admin_signs_in_past_an_epoch_key_strip_bomb(self):
        shape = self.base_auth(session_epochs={_SelfStr("admin"): 0})
        with self.cfg_patch(shape):
            response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_eq_bombed_legacy_password_still_signs_in(self):
        shape = {"settings": {"auth": {"enabled": True,
                                       "password": _EqStr("legacy-pw-1")}}}
        with self.cfg_patch(shape):
            response = self.login("admin", "legacy-pw-1")
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_startswith_bombed_hash_is_the_coded_401_not_500(self):
        # A junk non-scrypt hash cannot verify anything — but it must fail
        # as credentials, not as a startswith raise.
        shape = {"settings": {"auth": {"enabled": True, "username": "admin",
                                       "password_hash": _StartsStr("x")}}}
        with self.cfg_patch(shape):
            response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 401, response.text[:300])
        self.assertRenderable(response)

    def test_member_login_keeps_real_grants_under_row_bombs(self):
        for label, accounts in (
            ("strip-bombed name", [self.member_row(username=_SelfStr("kid"))]),
            ("eq-bombed role", [self.member_row(role=_EqStr("member"))]),
            ("strip-bombed resources",
             [self.member_row(resources=[_SelfStr("svc")])]),
        ):
            with self.subTest(accounts=label):
                with self.cfg_patch(self.base_auth(accounts=accounts)):
                    response = self.login("kid", MEMBER_PASSWORD)
                self.assertEqual(response.status_code, 200, response.text[:300])
                body = response.json()
                self.assertEqual(body["role"], "member")
                # The exact-str copies kept the row's real grant list.
                self.assertEqual(body["resources"], ["svc"])

    def test_member_with_startswith_bombed_hash_is_401_not_500(self):
        shape = self.base_auth(
            accounts=[self.member_row(password_hash=_StartsStr("x"))]
        )
        with self.cfg_patch(shape):
            response = self.login("kid", MEMBER_PASSWORD)
        self.assertEqual(response.status_code, 401, response.text[:300])
        self.assertRenderable(response)


class SessionCookieSelfStrBombTests(_AppSandbox, _Shapes):
    """A bombed config must not 500 (or wrongly extend) existing sessions."""

    def test_cookie_check_never_500s_under_any_shape(self):
        cookie = self.admin_cookie()
        for label, shape in self.shapes():
            with self.subTest(shape=label):
                with self.cfg_patch(shape):
                    response = self.client.get("/api/audit/auth", cookies=cookie)
                self.assertRenderable(response)

    def test_cookie_still_verifies_past_a_zero_epoch_key_bomb(self):
        cookie = self.admin_cookie()
        shape = self.base_auth(session_epochs={_SelfStr("admin"): 0})
        with self.cfg_patch(shape):
            response = self.client.get("/api/audit/auth", cookies=cookie)
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_bombed_epoch_key_keeps_its_real_logout_counter(self):
        # The exact-str copy reads the bombed key as "admin", so the recorded
        # logout still counts: pre-logout cookies stay revoked, never 500.
        cookie = self.admin_cookie()
        shape = self.base_auth(session_epochs={_SelfStr("admin"): 3})
        with self.cfg_patch(shape):
            self.assertEqual(auth._session_epoch("admin"), 3)
            response = self.client.get("/api/audit/auth", cookies=cookie)
        self.assertEqual(response.status_code, 401, response.text[:300])


class SanitizerUnitPins(_AppSandbox):
    """The laundering helpers themselves, pinned at the unit level."""

    def test_cfg_text_returns_an_exact_str_copy(self):
        out = auth._cfg_text(_SelfStr("admin"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "admin")

    def test_utf8_ok_sidesteps_an_encode_bomb(self):
        # The unbound str.encode reads the real text underneath the bombed
        # override, so a clean name still answers True — it used to raise.
        self.assertTrue(auth._utf8_ok(_SelfStr("x")))
        self.assertTrue(auth._utf8_ok("x"))
        self.assertFalse(auth._utf8_ok("\ud800"))

    def test_utf8_survives_a_subclass_encode_bomb(self):
        self.assertEqual(auth._utf8(_SelfStr("abc")), b"abc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
