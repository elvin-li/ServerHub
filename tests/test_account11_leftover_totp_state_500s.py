"""Eleventh Account-domain sweep: the per-account 2FA *state* the listing reads.

account3-9 sealed ``hub.auth``'s config readers — the accounts list, role
resolution, the session-cookie and login paths — against every leftover shape
the earlier waves carried, and account9 closed the last one there (a ``list``-
lying ``__class__`` impostor as the accounts value).  Re-driving GET
/api/auth/accounts and GET /api/auth/status through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` with the wave-10/11 shape battery
planted at every ``settings.auth`` rank now finds that surface fully immune.

But the admin **Users** table shows a ``twofa_enabled`` column, so
``accounts_api._public_view`` calls :func:`hub.twofa_svc.enabled` once per
listed account, and GET /api/auth/totp answers :func:`hub.twofa_svc.status`.
Those readers — never hardened by the auth waves — trusted their store rows to
be plain, JSON-shaped dicts.  A leftover 2FA store carrying an *object* row
(the shared-process / hand-restored / corrupted-in-memory shapes the task
plants against our own handlers) blew them field-first, and every raise rode
straight out of the two routes as a raw HTTP 500 while the account beside the
poisoned row was perfectly usable:

* **fixed — a dict-subclass row whose ``keys()`` / ``__iter__`` bombs, or a
  lying ``__class__`` that answers ``dict`` while its real type is neither,
  500'd both routes.**  ``_user_entry`` did ``dict(raw)``, which takes its
  *slow* path (calling ``keys()`` / ``__getitem__``) on such a subclass and
  rejects the impostor's unbound-descriptor probe outright.  It now laundities
  through unbound ``dict.items`` (:func:`hub.twofa_svc._plain_dict`) — the
  C-level storage, so a method-override subclass keeps its data and a true
  impostor drops to an empty row.
* **fixed — a ``__class__``-property bomb planted as one row, or as the whole
  ``_load`` result, 500'd both routes** out of the bare ``isinstance`` gates
  in ``_user_entry`` / ``_mapping_get``; now fail-closed via ``_isinst``.
* **fixed — a store mapping whose ``.get`` bombs, or a hash-shadowing
  ``__eq__`` key it holds, 500'd the row lookup.**  ``_mapping_get`` reads the
  real storage underneath the override (``dict.get``) and fails closed.
* **fixed — an ``enabled`` / ``pending_secret`` whose ``__bool__`` bombs**
  detonated the ``bool(...)`` truth tests in ``enabled`` / ``status``; now
  ``_truthy`` (a bomb flag reads as off).
* **fixed — a ``recovery`` list-subclass whose ``__iter__`` / ``__len__``
  bombs (or a ``list``-lying impostor)** 500'd ``status`` out of
  ``_stored_recovery``; now the unbound-``list.__iter__`` walk (the account9
  rule) reads its real rows or an empty walk.
* **fixed — a ``confirmed_at`` int-*subclass* whose ``__str__`` raises a
  non-ValueError** rode past ``_as_int``'s ValueError-only digit-cap catch and
  500'd ``status``; now coerced through an exact ``int()`` under a broad catch.

A poisoned 2FA row degrades field-level: the account still lists, its
``twofa_enabled`` simply reads False (fail-closed — a row nobody can parse is
not a second factor), and the response is valid, re-encodable UTF-8 JSON.
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


# ── leftover shapes (wave-10/11) ─────────────────────────────────────────────
class ClassBomb:
    """``__class__`` is a raising property: detonates any bare ``isinstance``."""

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("leftover __class__ bomb")


class DictLiar:
    """``__class__`` lies ``dict``; passes ``isinstance`` then blows the unbound
    ``dict.items`` descriptor (real type is not a dict)."""

    @property
    def __class__(self):  # noqa: D105
        return dict


class GetBombDict(dict):
    """Real dict subclass whose method overrides bomb.  ``dict(x)`` takes its
    slow, ``keys()``-calling path on such a subclass; unbound ``dict.items``
    reads the C-level storage past the overrides."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover .get bomb")

    def keys(self):  # noqa: D102
        raise RuntimeError("leftover keys bomb")

    def items(self):  # noqa: D102
        raise RuntimeError("leftover items bomb")

    def __iter__(self):  # noqa: D105
        raise RuntimeError("leftover __iter__ bomb")

    def __bool__(self):  # noqa: D105
        raise RuntimeError("leftover __bool__ bomb")


class BoolBomb:
    """``__bool__`` raises: detonates a ``bool(value)`` truth test."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("leftover __bool__ bomb")


class RecoveryIterBomb(list):
    """Real list subclass whose walk bombs; unbound ``list.__iter__`` reads its
    real rows anyway (the account9 rule)."""

    def __iter__(self):  # noqa: D105
        raise RuntimeError("leftover recovery __iter__ bomb")

    def __len__(self):  # noqa: D105
        raise RuntimeError("leftover recovery __len__ bomb")


class ListLiar:
    """``__class__`` lies ``list``; passes ``isinstance`` then blows the
    unbound ``list.__iter__`` descriptor."""

    @property
    def __class__(self):  # noqa: D105
        return list


class IntStrBomb(int):
    """Real int subclass whose ``__str__`` raises a *non*-ValueError."""

    def __str__(self):  # noqa: D105
        raise RuntimeError("leftover int __str__ bomb")

    def __repr__(self):  # noqa: D105
        raise RuntimeError("leftover int __repr__ bomb")


class ShadowKey(str):
    """A store key whose ``__eq__`` bombs while its hash matches its text — a
    plain-dict lookup that lands on its slot detonates the comparison."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover key __eq__ bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir with one admin + one member account."""

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
            f'    password_hash: "{self.admin_hash}"\n'
            "    accounts:\n"
            "    - username: kid\n"
            f'      password_hash: "{self.member_hash}"\n'
            "      role: member\n"
            "      resources: []\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        self.sign_in()

    def sign_in(self):
        auth._login_attempts.clear()
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json().get("ok"), response.text[:300])

    def poisoned_store(self, store):
        """Serve *store* as the whole 2FA store to every twofa_svc reader."""
        return mock.patch.object(twofa_svc, "_load", return_value=store)

    def assertJsonEncodable(self, response):
        """Starlette already encoded it; re-encode to prove no inf/surrogate."""
        json.dumps(response.json(), ensure_ascii=False, allow_nan=False)

    def assertListingClean(self):
        listing = self.client.get("/api/auth/accounts")
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        self.assertLess(listing.status_code, 500, listing.text[:300])
        self.assertJsonEncodable(listing)
        names = {a["username"] for a in listing.json()["accounts"]}
        self.assertEqual(names, {"admin", "kid"})
        return listing

    def assertTotpClean(self):
        st = self.client.get("/api/auth/totp")
        self.assertEqual(st.status_code, 200, st.text[:300])
        self.assertLess(st.status_code, 500, st.text[:300])
        self.assertJsonEncodable(st)
        return st


class ListingRowBombTests(_AppSandbox):
    """A poisoned admin 2FA row must not 500 the Users table read."""

    def test_dict_subclass_keysbomb_row_degrades_field_level(self):
        store = {"admin": GetBombDict({"enabled": True, "recovery": ["A"]})}
        with self.poisoned_store(store):
            listing = self.assertListingClean()
        admin = next(a for a in listing.json()["accounts"] if a["username"] == "admin")
        # Unbound dict.items reads past the method bombs, so a real enabled row
        # still reports True — the table keeps its honest column.
        self.assertTrue(admin["twofa_enabled"])

    def test_dict_liar_row_reads_as_no_second_factor(self):
        store = {"admin": DictLiar()}
        with self.poisoned_store(store):
            listing = self.assertListingClean()
        admin = next(a for a in listing.json()["accounts"] if a["username"] == "admin")
        # A value that only pretends to be a dict is no 2FA row at all.
        self.assertFalse(admin["twofa_enabled"])

    def test_class_bomb_row_reads_as_no_second_factor(self):
        store = {"admin": ClassBomb()}
        with self.poisoned_store(store):
            listing = self.assertListingClean()
        admin = next(a for a in listing.json()["accounts"] if a["username"] == "admin")
        self.assertFalse(admin["twofa_enabled"])

    def test_bool_bomb_enabled_flag_reads_as_off(self):
        store = {"admin": {"enabled": BoolBomb()}}
        with self.poisoned_store(store):
            listing = self.assertListingClean()
        admin = next(a for a in listing.json()["accounts"] if a["username"] == "admin")
        self.assertFalse(admin["twofa_enabled"])

    def test_whole_store_is_a_get_bomb_mapping(self):
        # _load itself returning a subclass whose .get bombs — the row lookup
        # must read the real storage or fail closed, not 500 the table.
        store = GetBombDict({"admin": {"enabled": True}})
        with self.poisoned_store(store):
            self.assertListingClean()

    def test_whole_store_is_a_class_bomb(self):
        with self.poisoned_store(ClassBomb()):
            listing = self.assertListingClean()
        for a in listing.json()["accounts"]:
            self.assertFalse(a["twofa_enabled"])

    def test_hash_shadow_key_in_store_degrades(self):
        # A key whose __eq__ bombs, landing on the "admin" hash slot.
        store = {ShadowKey("admin"): {"enabled": True}}
        with self.poisoned_store(store):
            self.assertListingClean()


class TotpStatusBombTests(_AppSandbox):
    """GET /api/auth/totp answers status() — the same row readers."""

    def test_recovery_iter_bomb_does_not_500_status(self):
        store = {"admin": {"enabled": True, "recovery": RecoveryIterBomb(["a", "b"])}}
        with self.poisoned_store(store):
            st = self.assertTotpClean()
        # Unbound list.__iter__ reads the two real rows back.
        self.assertEqual(st.json()["recovery_remaining"], 2)

    def test_recovery_list_liar_reads_empty(self):
        store = {"admin": {"enabled": True, "recovery": ListLiar()}}
        with self.poisoned_store(store):
            st = self.assertTotpClean()
        self.assertEqual(st.json()["recovery_remaining"], 0)

    def test_confirmed_at_int_str_bomb_does_not_500_status(self):
        store = {"admin": {"enabled": True, "confirmed_at": IntStrBomb(5)}}
        with self.poisoned_store(store):
            st = self.assertTotpClean()
        # A subclass whose __str__ bombs is coerced through an exact int().
        self.assertEqual(st.json()["confirmed_at"], 5)

    def test_pending_bool_bomb_does_not_500_status(self):
        store = {"admin": {"pending_secret": BoolBomb()}}
        with self.poisoned_store(store):
            st = self.assertTotpClean()
        self.assertFalse(st.json()["enabled"])
        self.assertFalse(st.json()["pending"])

    def test_enabled_bool_bomb_does_not_500_status(self):
        store = {"admin": {"enabled": BoolBomb()}}
        with self.poisoned_store(store):
            st = self.assertTotpClean()
        self.assertFalse(st.json()["enabled"])

    def test_row_is_a_dict_liar(self):
        with self.poisoned_store({"admin": DictLiar()}):
            st = self.assertTotpClean()
        self.assertFalse(st.json()["enabled"])


class HelperUnitTests(unittest.TestCase):
    """The sealed helpers' contracts, in isolation."""

    def test_plain_dict_launders_method_bomb_subclass(self):
        out = twofa_svc._plain_dict(GetBombDict({"enabled": True}))
        self.assertEqual(out, {"enabled": True})
        self.assertIs(type(out), dict)

    def test_plain_dict_drops_liars_and_junk(self):
        for junk in (DictLiar(), ClassBomb(), None, 5, "abc", [1, 2]):
            with self.subTest(junk=type(junk).__name__):
                self.assertEqual(twofa_svc._plain_dict(junk), {})

    def test_mapping_get_reads_past_get_bomb(self):
        d = GetBombDict({"k": "v"})
        self.assertEqual(twofa_svc._mapping_get(d, "k"), "v")

    def test_mapping_get_fails_closed_on_liar(self):
        self.assertIsNone(twofa_svc._mapping_get(DictLiar(), "k"))
        self.assertIsNone(twofa_svc._mapping_get(ClassBomb(), "k"))

    def test_stored_recovery_reads_past_iter_bomb(self):
        self.assertEqual(
            twofa_svc._stored_recovery(RecoveryIterBomb(["a", "b", 3])), ["a", "b"]
        )

    def test_stored_recovery_list_liar_is_empty(self):
        self.assertEqual(twofa_svc._stored_recovery(ListLiar()), [])

    def test_as_int_survives_int_str_bomb(self):
        self.assertEqual(twofa_svc._as_int(IntStrBomb(9)), 9)

    def test_as_int_class_bomb_is_default(self):
        self.assertEqual(twofa_svc._as_int(ClassBomb(), default=None), None)

    def test_truthy_fails_closed_on_bool_bomb(self):
        self.assertFalse(twofa_svc._truthy(BoolBomb()))
        self.assertTrue(twofa_svc._truthy(1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
