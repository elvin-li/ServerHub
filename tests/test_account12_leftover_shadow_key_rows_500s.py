"""Twelfth Account-domain sweep: the row *copies* the password-change walk reads.

account3-9 sealed ``hub.auth``'s config readers — the accounts list, role
resolution, the session-cookie and login paths — and account11 sealed the
per-account store reader beside the admin listing.  Re-driving the profile /
session / password-change surfaces (GET /api/auth/status, POST /api/auth/login,
GET /api/auth/accounts, every session-cookie check) through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` with the established shape
battery finds those readers immune.

But the password-change writers read the snapshot through a different door:
:func:`hub.auth.set_account_password` decides legacy-pair vs accounts-list by
walking ``_account_rows(_auth_cfg())``, and ``_account_rows`` copied each row
with ``dict(e)``.  That copy takes CPython's *fast* path on an exact-dict row:
entries move over with their **cached hashes**, no ``__hash__`` / ``__eq__``
ever runs — so a leftover str-subclass row key whose hash shadows
``"username"`` while its ``__eq__`` raises survived the copy intact.  The
membership walk's plain ``raw.get("username")`` then landed on its slot and
detonated the comparison from inside the C-level lookup of an *exact* dict,
with no method override left to bypass, and the raise rode straight out as a
raw HTTP 500 while the account beside the poisoned row was perfectly usable:

* **fixed — a hash-shadowing ``__eq__``-bomb row key 500'd POST
  /api/auth/change-password** (the signed-in account's own rotation): the
  caller is the legacy administrator, so the membership walk crosses *every*
  row before answering False, poisoned one included.
* **fixed — the same row planted ahead of the target 500'd POST
  /api/auth/accounts/{username}/password** (the administrator reset of a
  member's forgotten password): ``any()`` short-circuits, so the leak only
  fired when the walk reached the bomb before a match — which is exactly the
  ordering an operator cannot control.

``_account_rows`` now launders row keys to *exact* str (the ``_auth_cfg``
rule this copy never got): ``str.__str__`` reads the real text underneath the
override, so a bombed-but-clean key keeps its field, a lying ``__class__``
key drops its one field, and non-str keys (YAML int/bool spellings) pass
through — they cannot shadow a string probe.  A poisoned row degrades
row-level: the rotation still lands on disk and the response stays coded
2xx/4xx JSON.

Plus stays-immune pins for the neighbours re-probed with the same shape and
found already coded: the shadow key as a row of the *listing* read (dropped
by ``_mapping_get``, siblings intact), at the auth-block rank (laundered by
``_auth_cfg``), and the account8/9 method-bomb / impostor rows crossing the
same membership walk.
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
NEW_PASSWORD = "rotated-password-99"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


# ── leftover shapes ───────────────────────────────────────────────────────────
class ShadowKey(str):
    """A row key whose ``__eq__`` bombs while its hash matches its text.

    ``dict(e)``'s fast path copies it with its cached hash, so a plain
    ``.get("username")`` probing that slot detonates the comparison from
    inside the C-level lookup — no method override left to bypass.
    """

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover key __eq__ bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class StrLiarKey:
    """``__class__`` lies ``str``; the unbound ``str.__str__`` copy rejects it."""

    @property
    def __class__(self):  # noqa: D105
        return str


class ClassBomb:
    """``__class__`` is a raising property: detonates any bare ``isinstance``."""

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("leftover __class__ bomb")


class DictLiar:
    """``__class__`` lies ``dict``; passes the gate, answers no real pairs."""

    @property
    def __class__(self):  # noqa: D105
        return dict


class MethodBombRow(dict):
    """Real dict subclass whose method overrides bomb; the C-level storage
    underneath still holds the honest row (the account6/8 union shape)."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover .get bomb")

    def keys(self):  # noqa: D102
        raise RuntimeError("leftover keys bomb")

    def items(self):  # noqa: D102
        raise RuntimeError("leftover items bomb")

    def __iter__(self):  # noqa: D105
        raise RuntimeError("leftover __iter__ bomb")


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


class PasswordChangeShadowRowTests(_AppSandbox):
    """The fixed leak: a hash-shadowing row key crossing the membership walk."""

    def test_own_rotation_survives_shadow_key_row_and_lands_on_disk(self):
        # The legacy administrator is not in the accounts list, so the walk
        # crosses *every* row — poisoned one included — before answering.
        shape = self.base_auth(
            accounts=[{ShadowKey("username"): "ghost"}, self.member_row()]
        )
        with self.poisoned(shape):
            auth._login_attempts.clear()
            response = self.client.post(
                "/api/auth/change-password",
                json={
                    "username": "admin",
                    "current_password": PASSWORD,
                    "new_password": NEW_PASSWORD,
                },
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)
            self.assertTrue(response.json().get("ok"))
        # The rotation was written through mutate() to the real file: once
        # the snapshot poison is gone, only the new credential signs in.
        config.reload_cfg()
        self.sign_in(password=NEW_PASSWORD)

    def test_admin_reset_survives_shadow_key_row_ahead_of_the_target(self):
        # any() short-circuits, so the leak only fired when the walk reached
        # the bomb *before* the match — plant it first.
        shape = self.base_auth(
            accounts=[{ShadowKey("username"): "ghost"}, self.member_row()]
        )
        with self.poisoned(shape):
            auth._login_attempts.clear()
            response = self.client.post(
                "/api/auth/accounts/kid/password",
                json={"new_password": NEW_PASSWORD},
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)
            self.assertTrue(response.json().get("ok"))
        config.reload_cfg()
        member = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(member, "kid", NEW_PASSWORD)

    def test_method_bomb_row_still_answers_the_walk_with_its_real_name(self):
        # account6/8 union shape at this new seam: a real dict subclass whose
        # overrides bomb keeps its C-level storage, so the membership walk
        # still sees the honest row and the reset rewrites the on-disk twin.
        shape = self.base_auth(accounts=[MethodBombRow(self.member_row())])
        with self.poisoned(shape):
            auth._login_attempts.clear()
            response = self.client.post(
                "/api/auth/accounts/kid/password",
                json={"new_password": NEW_PASSWORD},
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
        config.reload_cfg()
        member = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(member, "kid", NEW_PASSWORD)

    def test_impostor_and_class_bomb_rows_cost_only_themselves(self):
        # account9's impostor faces, re-driven through the membership walk:
        # a dict-lying __class__ answers no pairs, a raising __class__ fails
        # the row gate — both drop and the rotation still answers coded.
        shape = self.base_auth(
            accounts=[DictLiar(), ClassBomb(), self.member_row()]
        )
        with self.poisoned(shape):
            auth._login_attempts.clear()
            response = self.client.post(
                "/api/auth/change-password",
                json={
                    "username": "admin",
                    "current_password": PASSWORD,
                    "new_password": NEW_PASSWORD,
                },
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)


class StaysImmunePinTests(_AppSandbox):
    """Neighbours re-probed with the shadow-key shape and found already coded."""

    def test_shadow_key_row_keeps_the_listing_and_login_up(self):
        # The *reader* path (accounts()/_mapping_get) already fails the
        # poisoned row closed: it lists nothing, its siblings list fine.
        shape = self.base_auth(
            accounts=[{ShadowKey("username"): "ghost"}, self.member_row()]
        )
        with self.poisoned(shape):
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertJsonEncodable(listing)
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertEqual(names, {"admin", "kid"})
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)

    def test_shadow_key_at_auth_block_rank_stays_laundered(self):
        # account8's rule at the block rank: _auth_cfg copies keys through
        # str.__str__, so the shadow spelling keeps its real field and the
        # rotation still reads a usable block.
        block = {
            "enabled": True,
            "username": "admin",
            "password_hash": self.admin_hash,
            ShadowKey("accounts"): [self.member_row()],
        }
        with self.poisoned({"settings": {"auth": block}}):
            auth._login_attempts.clear()
            response = self.client.post(
                "/api/auth/change-password",
                json={
                    "username": "admin",
                    "current_password": PASSWORD,
                    "new_password": NEW_PASSWORD,
                },
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            names = {a["username"] for a in listing.json()["accounts"]}
            self.assertIn("kid", names)


class AccountRowsUnitTests(unittest.TestCase):
    """The sealed copy's contract, in isolation."""

    def test_shadow_key_launders_to_exact_str_and_keeps_its_field(self):
        rows = auth._account_rows({"accounts": [{ShadowKey("username"): "ghost"}]})
        self.assertEqual(rows, [{"username": "ghost"}])
        (key,) = rows[0].keys()
        self.assertIs(type(key), str)
        # The laundered copy answers a plain probe without detonating.
        self.assertEqual(rows[0].get("username"), "ghost")

    def test_method_bomb_row_reads_its_real_storage(self):
        row = MethodBombRow({"username": "kid", "role": "member"})
        rows = auth._account_rows({"accounts": [row]})
        self.assertEqual(rows, [{"username": "kid", "role": "member"}])

    def test_liar_and_class_bomb_rows_drop_and_siblings_survive(self):
        rows = auth._account_rows(
            {"accounts": [DictLiar(), ClassBomb(), {"username": "kid"}]}
        )
        self.assertEqual(rows, [{"username": "kid"}])

    def test_genuinely_empty_row_is_kept(self):
        # Matches the old dict(e) copy: an empty mapping is a row, junk that
        # cannot answer its items is not.
        self.assertEqual(auth._account_rows({"accounts": [{}]}), [{}])

    def test_str_liar_key_drops_its_one_field_only(self):
        rows = auth._account_rows(
            {"accounts": [{StrLiarKey(): "junk", "username": "kid"}]}
        )
        self.assertEqual(rows, [{"username": "kid"}])

    def test_non_str_keys_pass_through(self):
        # YAML int/bool spellings cannot shadow a string probe; they ride
        # along untouched so a write-back does not reshape the row.
        rows = auth._account_rows({"accounts": [{1: "x", "username": "kid"}]})
        self.assertEqual(rows, [{1: "x", "username": "kid"}])
        self.assertEqual(rows[0].get("username"), "kid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
