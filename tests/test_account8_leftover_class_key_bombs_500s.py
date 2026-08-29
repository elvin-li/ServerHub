"""Eighth Account-domain sweep: ``__class__``-property and mapping-key bombs.

account3-7 hardened the member-account CRUD, the sign-in surface, the role
gates and the three mode-0600 token files against method-override bombs
(``.get``/``items``/``__iter__``/``__bool__``/``__str__``), bad token *files*
(FIFOs, directories, unwritable parents) and unrenderable YAML scalars.  This
sweep re-drove the same surfaces with the two shapes that dodge every one of
those nets, and found live raw 500s (the maint8/modules8 ``_isinst`` rule):

* **fixed — ``__class__``-property bombs.**  CPython's ``isinstance`` reads
  the operand's ``__class__`` whenever the real-type fast check misses, so a
  leftover whose ``__class__`` is a raising property detonated every bare
  ``isinstance`` gate in ``hub/auth.py`` from *outside* its try/except nets:
  at cfg-root / ``settings`` / ``settings.auth`` rank (``_mapping_get`` /
  ``_auth_cfg``) it 500'd GET /api/auth/status, POST /api/auth/login and the
  ``require_auth`` local-client path — every protected route a loopback
  menu-bar client calls — at once; at ``accounts``-list, row, ``resources``
  and ``session_epochs``-mapping/value rank (``accounts()`` /
  ``_account_rows`` / ``_session_epoch`` / ``_epoch_count``) it 500'd every
  login and session-cookie check through ``verify_session``.  Every
  leftover-reachable ``isinstance`` now routes through a guarded ``_isinst``
  that fails closed to False, so a bomb costs only its own entry.

* **fixed — str-subclass mapping keys with raising ``__eq__``.**  The old
  ``dict(auth)`` copy went through the C level for an exact-dict source and
  *preserved* a leftover str-subclass key, so a later ``a.get("username")``
  landing on its hash slot detonated the comparison from inside a plain
  dict — no method override left to launder around — and 500'd login and
  every cookie check.  ``_auth_cfg`` now rebuilds the block with keys
  laundered through unbound ``str.__str__`` to exact str (non-str top-level
  keys are junk for its string-keyed readers and drop), so the real text
  under the override keeps its value readable.

* **fixed — a raising ``cfg()`` provider.**  ``_auth_cfg`` called ``cfg()``
  unguarded while ``config.settings_section`` already wrapped the very same
  call; the raise escaped through every auth reader.  The union guard
  (try/except around ``cfg()`` + unbound ``dict`` reads) now holds here too.

Plus stays-immune pins for the neighbours probed and found already coded:
``setup_token_mode``/legacy-field ``__class__`` and ``__bool__`` bombs
(``_pick``/``_cfg_text``), the account6 dict-subclass ``.get`` union guard,
int-subclass ``__int__`` epoch bombs (``_epoch_count``'s broad catch), a
date-like isoformat-bomb username, torn-IPv6 Host headers on the setup-token
loopback gate, and a huge JSON number literal in ``twofa.json`` behind the
admin Users table (``ValueError``, not ``JSONDecodeError``).  Everything is
driven through ``create_app()`` + ``TestClient(raise_server_exceptions=
False)``.
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
HUGE_LITERAL = "9" * 4400

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _ClassBomb:
    """Real type is a plain object; reading ``__class__`` raises.

    The exact shape that blew every bare ``isinstance`` gate: the real-type
    fast check misses (object subclasses nothing interesting), so CPython
    falls back to reading ``__class__`` — and detonates.
    """

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("leftover __class__ bomb")


class _EqBombKey(str):
    """Exact-dict key whose comparison raises; the hash slot still matches."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover key eq bomb")

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("leftover key ne bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _HashBombKey(str):
    """Key whose *re*-hash raises; the insert that planted it hashed fine.

    The old ``dict(auth)`` copy of a dict-subclass source re-hashes every
    key; the launder now hashes only the exact-str copy, so the second call
    never happens.
    """

    _armed = False

    def __hash__(self):  # noqa: D105
        if self._armed:
            raise RuntimeError("leftover key re-hash bomb")
        object.__setattr__(self, "_armed", True)
        return str.__hash__(self)


class _BoolBomb:
    def __bool__(self):  # noqa: D105
        raise RuntimeError("leftover __bool__ bomb")


class _IntBomb(int):
    def __int__(self):  # noqa: D105
        raise RuntimeError("leftover __int__ bomb")

    def __index__(self):  # noqa: D105
        raise RuntimeError("leftover __index__ bomb")


class _IsoBomb:
    """Date-like leftover whose isoformat raises; str() still answers."""

    def isoformat(self):  # noqa: D102
        raise RuntimeError("leftover isoformat bomb")


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


class CfgRootClassBombHttpTests(_AppSandbox):
    """The fixed leak, root side: a ``__class__`` bomb at cfg-root /
    ``settings`` / ``settings.auth`` rank (or a raising provider) used to
    500 status, login and the ``require_auth`` local-client path at once."""

    def _shapes(self):
        return {
            "cfg root bomb": _ClassBomb(),
            "settings bomb": {"settings": _ClassBomb()},
            "auth block bomb": {"settings": {"auth": _ClassBomb()}},
        }

    def test_status_login_and_local_client_stay_coded(self):
        for label, shape in self._shapes().items():
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
                # The menu-bar header path walks setup_required → _auth_cfg
                # inside require_auth on every protected route.
                local = self.client.get(
                    "/api/status", headers={auth.LOCAL_TOKEN_HEADER: "junk"}
                )
                self.assertCoded(local)
                self.assertLess(local.status_code, 500, local.text[:300])

    def test_raising_cfg_provider_stays_coded(self):
        with mock.patch.object(auth, "cfg", side_effect=RuntimeError("cfg down")):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            local = self.client.get(
                "/api/status", headers={auth.LOCAL_TOKEN_HEADER: "junk"}
            )
            self.assertLess(local.status_code, 500, local.text[:300])


class AccountsRankClassBombHttpTests(_AppSandbox):
    """The fixed leak, accounts side: a ``__class__`` bomb at list / row /
    resources / epochs rank used to 500 every login and cookie check while
    the admin credential beside it was perfectly usable."""

    def test_bomb_accounts_value_keeps_admin_login_up(self):
        with self.poisoned(self.base_auth(accounts=_ClassBomb())):
            self.sign_in()
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])

    def test_bomb_row_costs_itself_and_siblings_keep_signing_in(self):
        shape = self.base_auth(accounts=[_ClassBomb(), self.member_row()])
        with self.poisoned(shape):
            # The poisoned row is dropped; the sibling member still exists.
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)
            status = member.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertEqual(status.json()["username"], "kid")
            # And the admin's Users table lists the survivor, coded.
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertJsonEncodable(listing)
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertEqual(names, {"admin", "kid"})

    def test_bomb_resources_value_keeps_the_row_and_the_table(self):
        shape = self.base_auth(
            accounts=[self.member_row(resources=_ClassBomb())]
        )
        with self.poisoned(shape):
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertJsonEncodable(listing)
            kid = next(
                a for a in listing.json()["accounts"] if a["username"] == "kid"
            )
            # The bomb is junk, not a grant list: fails closed to no resources.
            self.assertEqual(kid["resources"], [])

    def test_bomb_resource_element_costs_only_itself(self):
        shape = self.base_auth(
            accounts=[self.member_row(resources=["plex", _ClassBomb()])]
        )
        with self.poisoned(shape):
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertJsonEncodable(listing)
            kid = next(
                a for a in listing.json()["accounts"] if a["username"] == "kid"
            )
            self.assertIn("plex", kid["resources"])

    def test_bomb_epochs_keep_login_cookie_checks_and_logout_up(self):
        for label, extra in (
            ("epochs mapping bomb", {"session_epochs": _ClassBomb()}),
            ("epoch value bomb", {"session_epochs": {"admin": _ClassBomb()}}),
        ):
            with self.subTest(shape=label):
                self.setUp()  # fresh sandbox per shape
                with self.poisoned(self.base_auth(**extra)):
                    self.sign_in()
                    status = self.client.get("/api/auth/status")
                    self.assertEqual(status.status_code, 200, status.text[:300])
                    self.assertTrue(status.json()["authenticated"])
                    logout = self.client.post("/api/auth/logout")
                    self.assertEqual(logout.status_code, 200, logout.text[:300])

    def test_member_account_mutations_stay_coded_beside_a_bomb_row(self):
        shape = self.base_auth(accounts=[_ClassBomb(), self.member_row()])
        with self.poisoned(shape):
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


class MappingKeyBombHttpTests(_AppSandbox):
    """The fixed leak, key side: a str-subclass key whose ``__eq__`` raises
    survived the old ``dict(auth)`` C-level copy, so a later ``.get`` probe
    on its hash slot detonated from inside a plain dict."""

    def test_eq_bomb_username_key_keeps_its_real_value_readable(self):
        block = {
            _EqBombKey("username"): "admin",
            "enabled": True,
            "password_hash": self.admin_hash,
        }
        with self.poisoned({"settings": {"auth": block}}):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            # The laundered key reads the real text under the override, so
            # the credential it names still signs in.
            self.sign_in()

    def test_eq_bomb_accounts_key_keeps_the_member_signing_in(self):
        block = {
            "enabled": True,
            "username": "admin",
            "password_hash": self.admin_hash,
            _EqBombKey("accounts"): [self.member_row()],
        }
        with self.poisoned({"settings": {"auth": block}}):
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)
            self.sign_in()
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertEqual(names, {"admin", "kid"})

    def test_hash_bomb_key_costs_nothing_but_itself(self):
        block = {
            "enabled": True,
            "username": "admin",
            "password_hash": self.admin_hash,
            # The insert consumes the one good hash; any later re-hash of
            # this key (the shape dict(auth) used to perform) detonates.
            _HashBombKey("session_epochs"): {"admin": 1},
        }
        with self.poisoned({"settings": {"auth": block}}):
            self.sign_in()
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])


class AuthCfgLaunderUnitTests(unittest.TestCase):
    """The rebuilt block's contract: exact-str keys, nested values untouched."""

    def test_keys_are_laundered_to_exact_str(self):
        block = {
            _EqBombKey("username"): "admin",
            "password_hash": "h",
            3: "int-keyed junk",
            _ClassBomb(): "unanswerable key",
        }
        with mock.patch.object(
            auth, "cfg", return_value={"settings": {"auth": block}}
        ):
            out = auth._auth_cfg()
        self.assertEqual(out.get("username"), "admin")
        self.assertEqual(out.get("password_hash"), "h")
        for key in out:
            self.assertIs(type(key), str)
        # Non-str top-level keys are junk for the string-keyed readers.
        self.assertEqual(len(out), 2)

    def test_nested_epoch_int_keys_survive_the_launder(self):
        # session_epochs' own numeric-account int keys live one level down
        # and must keep round-tripping through _epoch_key untouched.
        block = {"username": "2024", "password_hash": "h",
                 "session_epochs": {2024: 5}}
        with mock.patch.object(
            auth, "cfg", return_value={"settings": {"auth": block}}
        ):
            self.assertEqual(auth._auth_cfg()["session_epochs"], {2024: 5})
            self.assertEqual(auth._session_epoch("2024"), 5)

    def test_isinst_fails_closed_and_passes_subclasses(self):
        self.assertFalse(auth._isinst(_ClassBomb(), dict))
        self.assertTrue(auth._isinst({}, dict))
        self.assertTrue(auth._isinst(_EqBombKey("x"), str))


class StaysImmunePinTests(_AppSandbox):
    """Neighbours probed and found already coded — pinned so they stay so."""

    def test_class_and_bool_bombs_in_scalar_fields_stay_coded(self):
        # _pick/_cfg_text already guard the scalar slots; a __class__ or
        # __bool__ bomb there must keep degrading, never 500.
        for label, extra in (
            ("setup_token_mode class bomb", {"setup_token_mode": _ClassBomb()}),
            ("legacy username class bomb", {"username": _ClassBomb()}),
            ("legacy username bool bomb", {"username": _BoolBomb()}),
            ("password_hash bool bomb", {"password_hash": _BoolBomb()}),
        ):
            with self.subTest(shape=label):
                shape = self.base_auth(**extra)
                with self.poisoned(shape):
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

    def test_account6_get_bomb_union_guard_still_holds(self):
        # The conflict-policy union: a dict-subclass .get/items bomb as the
        # auth block still reads its real storage through the unbound copy.
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

    def test_int_subclass_epoch_bomb_reads_as_junk_not_500(self):
        # _epoch_count's broad catch already drops a raising __int__.
        shape = self.base_auth(session_epochs={"admin": _IntBomb(3)})
        with self.poisoned(shape):
            self.sign_in()
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])

    def test_isoformat_bomb_username_stays_coded(self):
        # _cfg_text never calls isoformat; str() of the leftover answers.
        shape = self.base_auth(username=_IsoBomb())
        with self.poisoned(shape):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)

    def test_torn_ipv6_host_headers_on_setup_token_stay_coded(self):
        # request_host_name parses the Host header by hand (no urlsplit), so
        # a torn bracket cannot raise; it simply fails the loopback gate.
        self.yaml_path.write_text(
            "settings:\n  auth:\n    enabled: true\n", encoding="utf-8"
        )
        config.reload_cfg()
        for host in ("[::1", "::1]", "[::1]:", "[", "[]", "[::1]:8086:9"):
            with self.subTest(host=host):
                response = self.client.get(
                    "/api/auth/setup-token", headers={"host": host}
                )
                self.assertCoded(response)
                self.assertLess(response.status_code, 500, response.text[:300])

    def test_huge_json_number_in_twofa_store_keeps_the_users_table_up(self):
        # json.loads of a >4300-digit literal raises plain ValueError (not
        # JSONDecodeError); the twofa digit-cap hook already degrades it, so
        # the admin Users table (twofa_enabled per row) must stay 200.
        (self.data / "twofa.json").write_text(
            '{"admin": {"enabled": ' + HUGE_LITERAL + "}}\n", encoding="utf-8"
        )
        self.sign_in()
        listing = self.client.get("/api/auth/accounts")
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        self.assertJsonEncodable(listing)
        row = next(
            a for a in listing.json()["accounts"] if a["username"] == "admin"
        )
        self.assertIn(row["twofa_enabled"], (True, False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
