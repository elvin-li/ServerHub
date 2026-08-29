"""Seventh leftover-500s sweep of the Login / auth / session surface.

The find: the ``settings.auth`` readers in hub/auth.py never got the
tree-wide subclass-bomb hardening the rest of the tree standardized on
(``config.settings_section``'s unbound ``dict.get`` + ``dict(...)``
laundering, ``hub.ups_svc._mapping_get``, ``hub.jobs._truthy``, the
modules5 unbound ``dict.items`` / ``list.__iter__``).  Driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)``, thirteen
junk shapes were live raw HTTP 500s on the pre-fix tree:

* a dict-subclass ``.get`` bomb as the config root, the ``settings`` block,
  or the ``settings.auth`` block 500'd GET /api/auth/status, POST
  /api/auth/login **and every route behind a session cookie** (the
  ``verify_session`` → ``accounts()`` path; GET /api/auth/totp was the
  probe) all at once;
* a dict-subclass ``__bool__`` bomb as the auth block detonated the
  ``(_auth_cfg() or {})`` truth test in ``setup_token_mode`` and 500'd the
  unauthenticated GET /api/auth/status;
* a ``__bool__``-bomb *value* in ``username`` / ``password_hash`` /
  ``password`` / ``setup_token_mode`` detonated the truth test hidden in
  ``a.get(key) or default`` — status, login and cookie checks 500'd;
* a dict-subclass ``items()`` bomb as ``session_epochs``, and an
  int-subclass ``__str__``-bomb *key* inside it (raises past the digit-cap
  ``ValueError`` guard in ``_cfg_text``), each 500'd every login through
  ``account_session_version`` → ``_session_epoch``;
* a list-subclass ``__iter__`` bomb as the ``accounts`` list, a
  dict-subclass ``.get`` bomb as one row, and a list-subclass ``__iter__``
  bomb as one row's ``resources`` each 500'd every login out of
  ``accounts()``.

Fixes, all in hub/auth.py, all the established conventions: ``_mapping_get``
(ups_svc) for the root/settings/auth/row reads, ``dict(...)`` laundering of
the auth block (settings_section), ``_mapping_items`` for the epoch walks,
unbound ``list.__iter__`` for the accounts/resources walks, ``_truthy`` /
``_pick`` (jobs) for the ``or`` truth tests, a broad catch in ``_cfg_text``
(backups) for ``__str__`` bombs, and a broad catch on ``_epoch_count``'s
``int()`` for ``__int__`` bombs.

Stays-immune semantics pinned alongside: the unbound reads keep the *real*
data underneath a poisoned override (login still succeeds against the real
hash inside a ``.get``-bombed block; a member row inside an ``__iter__``
-bombed list still signs in with its real resources; a real logout epoch
inside an ``items()``-bombed mapping still revokes pre-logout cookies).
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


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover .items bomb")


class _DictBoolBomb(dict):
    def __bool__(self):
        raise RuntimeError("leftover dict __bool__ bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _IntOfBomb:
    def __int__(self):
        raise RuntimeError("leftover __int__ bomb")


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

    def member_row(self) -> dict:
        return {
            "username": "kid",
            "password_hash": self.member_hash,
            "role": "member",
            "resources": ["svc"],
        }

    def cfg_patch(self, shape):
        return mock.patch.object(auth, "cfg", lambda: shape)

    def login(self, username: str, password: str):
        auth._login_attempts.clear()
        return self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    def assertRenderable(self, response) -> None:
        # Starlette encodes with allow_nan=False + strict UTF-8; a raised
        # subclass bomb is exactly what used to turn these into raw 500s.
        self.assertNotEqual(response.status_code, 500, response.text[:300])
        response.content.decode("utf-8")


class StatusCfgBombTests(_AppSandbox):
    """GET /api/auth/status answers 200 under every hostile config shape."""

    def shapes(self):
        return (
            ("root get bomb", _DictGetBomb()),
            ("settings get bomb", {"settings": _DictGetBomb()}),
            ("auth get bomb", {
                "settings": {"auth": _DictGetBomb(
                    self.base_auth()["settings"]["auth"])},
            }),
            ("auth bool bomb", {
                "settings": {"auth": _DictBoolBomb(
                    self.base_auth()["settings"]["auth"])},
            }),
            ("username bool bomb", self.base_auth(username=_BoolBomb())),
            ("password_hash bool bomb", {
                "settings": {"auth": {"enabled": True, "username": "admin",
                                      "password_hash": _BoolBomb()}},
            }),
            ("password bool bomb", {
                "settings": {"auth": {"enabled": True,
                                      "password": _BoolBomb()}},
            }),
            ("setup_token_mode bool bomb",
             self.base_auth(setup_token_mode=_BoolBomb())),
            ("epochs items bomb",
             self.base_auth(session_epochs=_DictItemsBomb({}))),
            ("epochs intstr key",
             self.base_auth(session_epochs={_IntStrBomb(1): 1})),
            ("accounts iter bomb",
             self.base_auth(accounts=_ListIterBomb([]))),
            ("account row get bomb",
             self.base_auth(accounts=[_DictGetBomb(self.member_row())])),
            ("resources iter bomb", self.base_auth(accounts=[
                dict(self.member_row(), resources=_ListIterBomb(["svc"]))])),
        )

    def test_status_stays_200_under_every_shape(self):
        for label, shape in self.shapes():
            with self.subTest(shape=label):
                with self.cfg_patch(shape):
                    response = self.client.get("/api/auth/status")
                self.assertEqual(response.status_code, 200, response.text[:300])
                self.assertRenderable(response)

    def test_bool_bomb_credentials_read_as_unclaimed_not_500(self):
        # A junk bomb value is not a usable credential: status reports setup
        # required (fail-closed, same as any other unusable leftover) — it
        # used to 500 instead.
        shape = {"settings": {"auth": {"enabled": True, "password": _BoolBomb()}}}
        with self.cfg_patch(shape):
            response = self.client.get("/api/auth/status")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["setup_required"])


class LoginCfgBombTests(_AppSandbox):
    """POST /api/auth/login: the unbound reads keep the real data."""

    def test_login_succeeds_inside_a_get_bombed_auth_block(self):
        # dict.get / dict(...) read the storage underneath the override, so
        # the real hash inside the poisoned block still verifies.
        shape = {"settings": {"auth": _DictGetBomb(
            self.base_auth()["settings"]["auth"])}}
        with self.cfg_patch(shape):
            response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])

    def test_login_succeeds_inside_get_bombed_root_and_settings(self):
        real = self.base_auth()
        for label, shape in (
            ("root", _DictGetBomb(real)),
            ("settings", {"settings": _DictGetBomb(real["settings"])}),
        ):
            with self.subTest(level=label):
                with self.cfg_patch(shape):
                    response = self.login("admin", PASSWORD)
                self.assertEqual(response.status_code, 200, response.text[:300])

    def test_username_bool_bomb_falls_back_to_admin_and_signs_in(self):
        with self.cfg_patch(self.base_auth(username=_BoolBomb())):
            response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_password_hash_bool_bomb_is_the_coded_401_not_500(self):
        shape = {"settings": {"auth": {"enabled": True, "username": "admin",
                                       "password_hash": _BoolBomb()}}}
        with self.cfg_patch(shape):
            response = self.login("admin", PASSWORD)
        self.assertIn(response.status_code, (400, 401), response.text[:300])
        self.assertRenderable(response)

    def test_epoch_bombs_do_not_500_login(self):
        for label, epochs in (
            ("items bomb", _DictItemsBomb({})),
            ("intstr key", {_IntStrBomb(1): 1}),
            ("int-of bomb value", {"admin": _IntOfBomb()}),
        ):
            with self.subTest(epochs=label):
                with self.cfg_patch(self.base_auth(session_epochs=epochs)):
                    response = self.login("admin", PASSWORD)
                self.assertEqual(response.status_code, 200, response.text[:300])

    def test_items_bombed_epochs_keep_the_real_logout_counter(self):
        # dict.items reads the real storage underneath the poisoned items():
        # the recorded logout still counts, so pre-logout cookies stay revoked.
        with self.cfg_patch(
            self.base_auth(session_epochs=_DictItemsBomb({"admin": 3}))
        ):
            self.assertEqual(auth._session_epoch("admin"), 3)

    def test_member_login_survives_accounts_and_resources_bombs(self):
        for label, accounts in (
            ("iter-bombed list", _ListIterBomb([self.member_row()])),
            ("get-bombed row", [_DictGetBomb(self.member_row())]),
            ("iter-bombed resources",
             [dict(self.member_row(), resources=_ListIterBomb(["svc"]))]),
        ):
            with self.subTest(accounts=label):
                with self.cfg_patch(self.base_auth(accounts=accounts)):
                    response = self.login("kid", MEMBER_PASSWORD)
                self.assertEqual(response.status_code, 200, response.text[:300])
                body = response.json()
                self.assertEqual(body["role"], "member")
                # The unbound reads kept the row's real grant list.
                self.assertEqual(body["resources"], ["svc"])

    def test_bomb_row_beside_a_healthy_row_costs_only_itself(self):
        accounts = [
            {"username": _BoolBomb(), "password_hash": "x", "role": "member"},
            self.member_row(),
        ]
        with self.cfg_patch(self.base_auth(accounts=accounts)):
            response = self.login("kid", MEMBER_PASSWORD)
        self.assertEqual(response.status_code, 200, response.text[:300])


class SessionCookieCfgBombTests(_AppSandbox):
    """A bombed config must not 500 (or wrongly kill) existing sessions."""

    def _cookie(self) -> dict:
        response = self.login("admin", PASSWORD)
        self.assertEqual(response.status_code, 200)
        return {auth.COOKIE_NAME: response.cookies.get(auth.COOKIE_NAME)}

    def test_cookie_check_never_500s_under_any_shape(self):
        cookie = self._cookie()
        shapes = StatusCfgBombTests.shapes(self)
        for label, shape in shapes:
            with self.subTest(shape=label):
                with self.cfg_patch(shape):
                    response = self.client.get("/api/auth/totp", cookies=cookie)
                self.assertRenderable(response)

    def test_cookie_still_verifies_inside_a_get_bombed_auth_block(self):
        cookie = self._cookie()
        shape = {"settings": {"auth": _DictGetBomb(
            self.base_auth()["settings"]["auth"])}}
        with self.cfg_patch(shape):
            response = self.client.get("/api/auth/totp", cookies=cookie)
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_epoch_key_str_bomb_does_not_500_or_unrevoke(self):
        # A __str__-bomb epoch key reads as "" and is dropped; the sibling
        # string spelling keeps revoking pre-logout cookies.
        cookie = self._cookie()
        shape = self.base_auth(session_epochs={_IntStrBomb(7): 9, "admin": 1})
        with self.cfg_patch(shape):
            response = self.client.get("/api/auth/totp", cookies=cookie)
        self.assertEqual(response.status_code, 401, response.text[:300])


class ChangePasswordCfgBombTests(_AppSandbox):
    """POST /api/auth/change-password survives bombed sibling rows."""

    def test_change_password_with_a_bomb_row_in_accounts(self):
        cookie_response = self.login("admin", PASSWORD)
        self.assertEqual(cookie_response.status_code, 200)
        cookie = {auth.COOKIE_NAME: cookie_response.cookies.get(auth.COOKIE_NAME)}
        shape = self.base_auth(accounts=[
            {"username": _BoolBomb(), "password_hash": "x", "role": "member"},
        ])
        auth._login_attempts.clear()
        with self.cfg_patch(shape):
            response = self.client.post(
                "/api/auth/change-password",
                json={
                    "username": "admin",
                    "current_password": PASSWORD,
                    "new_password": "brand-new-pass-1",
                },
                cookies=cookie,
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
