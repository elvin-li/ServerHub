"""Ninth Account-domain sweep: lying ``__class__`` *impostors* over ``list``.

account8 sealed the two shapes that dodge a method-override net: the raising
``__class__``-*property* bomb that detonates a bare ``isinstance`` gate, and
the str-subclass mapping key whose ``__eq__`` raises from inside a plain dict.
Its guards route every leftover-reachable ``isinstance`` through ``_isinst``
(fails closed) and launder ``settings.auth`` through unbound ``dict`` reads.

This sweep re-drove the same auth read path with the *third* face of the
``__class__`` class — the **lying impostor** that answers ``__class__`` with a
built-in type it is not, so it *passes* ``_isinst`` and then blows the unbound
descriptor one line later — and found one live raw 500 (the users9 / modules
rule):

* **fixed — a ``list``-lying impostor as ``accounts`` or a row's
  ``resources`` 500'd every login and session-cookie check.**  ``_iter_list``
  called unbound ``list.__iter__(value)`` with no catch, trusting the
  ``_isinst(value, list)`` gate one line up.  A leftover whose ``__class__``
  property answers ``list`` while its real type is not a list underneath
  passes that gate, then TypeError's the descriptor call itself
  (``descriptor '__iter__' requires a 'list' object``) — and rode that raise
  straight out of ``accounts()`` / ``_account_rows``, 500ing POST
  /api/auth/login and, through ``verify_session`` → ``accounts()``, every
  route behind a session cookie, while the admin credential beside the
  impostor was perfectly usable.  ``_iter_list`` now fails closed to an empty
  walk (the ``_mapping_get`` / ``_mapping_items`` rule): a real list
  *subclass* whose ``__iter__`` override is a bomb still yields its C-level
  elements, but a value that only pretends to be a list is treated as no
  list at all.

Plus stays-immune pins for the neighbours re-probed with the impostor shape
and found already coded: a ``dict``-lying impostor at ``settings`` /
``settings.auth`` / row rank (``_mapping_get`` / ``_mapping_items`` already
fall through the guarded unbound reads), a ``dict``-subclass ``.get`` / bare
list-subclass ``__iter__`` bomb (the account6/8 union guards), and a
``bool``-lying scalar (``_truthy``).  Everything is driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)``.
"""
from __future__ import annotations

import json
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


class _ListLiar:
    """Real type is a plain object; ``__class__`` lies ``list``.

    Passes ``isinstance(x, list)`` (CPython falls back to ``__class__`` when
    the real-type check misses) but is not a list underneath, so unbound
    ``list.__iter__(x)`` TypeError's the descriptor call.
    """

    @property
    def __class__(self):  # noqa: D105
        return list


class _DictLiar:
    """``__class__`` lies ``dict``; unbound ``dict.get`` / ``dict.items``
    TypeError on it, and the real type has no such methods to bind."""

    @property
    def __class__(self):  # noqa: D105
        return dict


class _BoolLiar:
    """``__class__`` lies ``bool`` yet ``bool(x)`` still runs object truthiness."""

    @property
    def __class__(self):  # noqa: D105
        return bool


class _IterBombList(list):
    """A genuine list subclass whose ``__iter__`` override raises.

    The account8 shape ``_iter_list`` must still read past: unbound
    ``list.__iter__`` reaches the C-level storage, so the real elements come
    through even though the override is a bomb.
    """

    def __iter__(self):  # noqa: D105
        raise RuntimeError("leftover subclass __iter__ bomb")


class _GetBombDict(dict):
    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover .get bomb")

    def items(self):  # noqa: D102
        raise RuntimeError("leftover items bomb")


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
        self.addCleanup(auth._token_fallbacks.clear)
        auth._secret_cache = None
        auth._token_fallbacks.clear()
        auth._login_attempts.clear()
        api_keys._last_seen.clear()
        self.admin_hash = auth.hash_password(PASSWORD)
        self.member_hash = auth.hash_password(MEMBER_PASSWORD)
        self.yaml_path.write_text(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{self.admin_hash}"\n',
            encoding="utf-8",
        )
        config.reload_cfg()
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
            "resources": [],
        }
        row.update(extra)
        return row

    def poisoned(self, cfg_value):
        """Serve *cfg_value* to every hub.auth reader (auth imports cfg)."""
        return mock.patch.object(auth, "cfg", return_value=cfg_value)

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json().get("ok"), response.text[:300])
        return response

    def assertJsonEncodable(self, response):
        """Starlette already encoded it; re-encode to prove no inf/surrogate."""
        json.dumps(response.json(), ensure_ascii=False, allow_nan=False)

    def assertCoded(self, response):
        """No raw 500: either below 500, or a *coded* dependency status."""
        if response.status_code < 500:
            return
        detail = response.json().get("detail")
        self.assertIsInstance(detail, dict, response.text[:300])
        self.assertTrue(detail.get("code"), response.text[:300])


class ListImpostorHttpTests(_AppSandbox):
    """The fixed leak: a ``list``-lying impostor at ``accounts`` or
    ``resources`` rank used to 500 login and every session-cookie check."""

    def test_impostor_accounts_value_keeps_admin_login_and_status_up(self):
        with self.poisoned(self.base_auth(accounts=_ListLiar())):
            # accounts() → _iter_list(rows) used to TypeError out of login.
            self.sign_in()
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            self.assertTrue(status.json()["authenticated"])

    def test_impostor_resources_value_keeps_the_row_and_the_table(self):
        shape = self.base_auth(
            accounts=[self.member_row(resources=_ListLiar())]
        )
        with self.poisoned(shape):
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertJsonEncodable(listing)
            kid = next(
                a for a in listing.json()["accounts"] if a["username"] == "kid"
            )
            # A value that only pretends to be a list is no grant list at
            # all: fails closed to no resources, never a 500.
            self.assertEqual(kid["resources"], [])

    def test_impostor_accounts_keeps_a_sibling_member_signing_in(self):
        # The list-liar as the whole accounts value collapses to an empty
        # walk; the legacy admin credential beside it still verifies, and a
        # real member row served instead of the impostor still resolves.
        shape = self.base_auth(accounts=[self.member_row()])
        with self.poisoned(shape):
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)
            status = member.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertEqual(status.json()["username"], "kid")

    def test_impostor_accounts_keeps_member_mutations_coded(self):
        # Every account writer walks _account_rows → _iter_list; the impostor
        # as the accounts value must degrade, not 500, on each verb.
        with self.poisoned(self.base_auth(accounts=_ListLiar())):
            self.sign_in()
            for method, path, body in (
                ("POST", "/api/auth/accounts",
                 {"username": "z9", "password": "x" * 12, "resources": []}),
                ("PUT", "/api/auth/accounts/kid/resources",
                 {"resources": ["plex"]}),
                ("POST", "/api/auth/accounts/kid/password",
                 {"new_password": "y" * 12}),
                ("DELETE", "/api/auth/accounts/kid", None),
            ):
                with self.subTest(path=f"{method} {path}"):
                    auth._login_attempts.clear()
                    response = self.client.request(method, path, json=body)
                    self.assertCoded(response)
                    self.assertLess(response.status_code, 500,
                                    response.text[:300])

    def test_subclass_iter_bomb_still_yields_its_real_elements(self):
        # account8's shape: unbound list.__iter__ reads the C storage, so a
        # real list subclass whose __iter__ override is a bomb keeps working.
        rows = _IterBombList([self.member_row()])
        with self.poisoned(self.base_auth(accounts=rows)):
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertEqual(names, {"admin", "kid"})


class StaysImmunePinTests(_AppSandbox):
    """Neighbours re-probed with the impostor shape and found already coded."""

    def test_dict_impostor_at_settings_and_auth_rank_stays_coded(self):
        # _mapping_get / _mapping_items already fall through the guarded
        # unbound dict reads, so a dict-lying impostor there reads as "no
        # config" rather than 500ing status and login.
        for label, shape in (
            ("settings impostor", {"settings": _DictLiar()}),
            ("auth block impostor", {"settings": {"auth": _DictLiar()}}),
        ):
            with self.subTest(shape=label), self.poisoned(shape):
                auth._login_attempts.clear()
                status = self.client.get("/api/auth/status")
                self.assertEqual(status.status_code, 200, status.text[:300])
                self.assertJsonEncodable(status)
                login = self.client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": PASSWORD},
                )
                self.assertCoded(login)
                self.assertLess(login.status_code, 500, login.text[:300])

    def test_dict_impostor_account_row_drops_and_siblings_survive(self):
        # A dict-lying impostor row passes _isinst(raw, dict) then reads
        # empty through _mapping_get; the row is dropped, the real member
        # beside it keeps signing in.
        shape = self.base_auth(accounts=[_DictLiar(), self.member_row()])
        with self.poisoned(shape):
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertEqual(names, {"admin", "kid"})

    def test_get_bomb_dict_block_still_reads_its_real_storage(self):
        # account6/8 union guard: a dict-subclass .get/items bomb as the
        # auth block still reads through unbound dict reads.
        block = _GetBombDict({
            "enabled": True,
            "username": "admin",
            "password_hash": self.admin_hash,
            "accounts": [self.member_row()],
        })
        with self.poisoned({"settings": {"auth": block}}):
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertEqual(names, {"admin", "kid"})

    def test_bool_liar_scalar_field_stays_coded(self):
        # _truthy / _pick already survive an object whose __class__ lies bool.
        shape = self.base_auth(setup_token_mode=_BoolLiar())
        with self.poisoned(shape):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)


class IterListUnitTests(unittest.TestCase):
    """The sealed helper's contract, in isolation."""

    def test_list_liar_fails_closed_to_empty(self):
        # Passes the isinstance gate, is not a list underneath: no walk, no
        # raise.
        self.assertTrue(auth._isinst(_ListLiar(), list))
        self.assertEqual(auth._iter_list(_ListLiar()), [])

    def test_real_list_and_subclass_bomb_yield_real_elements(self):
        self.assertEqual(auth._iter_list([1, 2, 3]), [1, 2, 3])
        self.assertEqual(auth._iter_list(_IterBombList(["a", "b"])), ["a", "b"])

    def test_non_list_junk_fails_closed(self):
        for junk in (None, 5, "abc", {"a": 1}, object()):
            with self.subTest(junk=junk):
                self.assertEqual(auth._iter_list(junk), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
