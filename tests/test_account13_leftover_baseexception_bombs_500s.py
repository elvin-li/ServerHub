"""Thirteenth Account-domain sweep: BaseException-shaped bombs past the guards.

account3-9/11/12 sealed ``hub.auth``'s config readers against the leftover
bomb shapes — raising ``__class__`` properties, ``__bool__`` / ``__str__`` /
``.get`` / ``items()`` overrides, shadow row keys — but every one of those
guards stopped at ``except Exception``.  A leftover whose hook raises a
*BaseException* subclass instead (the watchdog/timeout shape the
modules12/logs12/json13/notify12 sweeps sealed on their own surfaces) sailed
past all of them at once, because each sibling guard in the module stopped at
``Exception`` too, and rode straight out as a raw HTTP 500 across the whole
account surface:

* **fixed — a ``__class__``-property bomb raising a BaseException subclass
  planted as the accounts value 500'd GET /api/auth/status (with a session
  cookie), POST /api/auth/login and POST /api/auth/change-password** through
  the ``_isinst`` rank gates.
* **fixed — a ``__bool__`` bomb of the same base on the stored username slot
  500'd the profile read and login** through ``_pick`` / ``_truthy``.
* **fixed — a ``.get`` bomb of the same base as the ``settings`` block 500'd
  status/login/cookie checks** one line ahead of the ``dict.get`` salvage in
  ``_mapping_get``.
* **fixed — an ``items()`` bomb of the same base as the ``session_epochs``
  mapping, and an ``__int__`` bomb as one epoch value, each 500'd every login
  and session-cookie check** through ``account_session_version``.
* **fixed — a ``__str__`` bomb of the same base on the stored hash slot
  500'd status/login/cookie checks** past ``_cfg_text``'s broad catch.
* **fixed — a snapshot provider raising the same base 500'd the profile
  read** past ``_auth_cfg``'s ``cfg()`` guard.
* **fixed — a row key whose re-hash bombs with the same base 500'd the
  password-change writers** out of ``_account_rows``' laundering copy.

Every guard in the module now stops at ``BaseException`` while real control
flow (KeyboardInterrupt, SystemExit) keeps propagating — the
modules12/logs12 convention.  The fallbacks are unchanged: each shape
degrades exactly as its ``Exception``-flavoured twin always has (junk value,
empty block, dropped field), so the responses stay coded 2xx/4xx JSON and a
poisoned row costs at most itself.

Plus stays-immune pins: the account12 shadow-key row re-probed with the
BaseException-flavoured ``__eq__``, the laundering copy that keeps the walk
off row-key overrides entirely, and the control-flow passthrough on every
hardened helper.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, auth, config
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
class _Boom(BaseException):
    """Not an Exception subclass: the shape every prior guard let through."""


class ClassBomb:
    """``__class__`` raises a BaseException subclass: detonates isinstance."""

    @property
    def __class__(self):  # noqa: D105
        raise _Boom("leftover __class__ bomb")


class BoolBomb:
    """``__bool__`` raises a BaseException subclass: detonates truth tests."""

    def __bool__(self):  # noqa: D105
        raise _Boom("leftover __bool__ bomb")


class GetBombMap(dict):
    """Real dict subclass whose ``get`` raises a BaseException subclass; the
    C-level storage underneath still holds the honest block."""

    def get(self, *a, **k):  # noqa: D102
        raise _Boom("leftover .get bomb")


class ItemsBombMap(dict):
    """Real dict subclass whose ``items`` raises a BaseException subclass."""

    def items(self):  # noqa: D102
        raise _Boom("leftover items bomb")


class StrBomb:
    """``__str__`` raises a BaseException subclass: detonates text reads."""

    def __str__(self):  # noqa: D105
        raise _Boom("leftover __str__ bomb")


class IntBomb:
    """``__int__``/``__index__`` raise a BaseException subclass."""

    def __int__(self):  # noqa: D105
        raise _Boom("leftover __int__ bomb")

    def __index__(self):  # noqa: D105
        raise _Boom("leftover __index__ bomb")


class ShadowKeyBase(str):
    """The account12 shadow row key, re-armed on the other base.

    Hash matches its text so a plain ``.get("username")`` probe lands on its
    slot; the comparison then raises a *BaseException* subclass, which used
    to sail past ``_mapping_get``'s catch on the reader walk.
    """

    def __eq__(self, other):  # noqa: D105
        raise _Boom("leftover key __eq__ bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class LateHashBomb:
    """Hashes once (into the config literal), then raises the other base.

    ``_account_rows``' rebuild re-hashes every non-str key into the fresh
    row (``row[k] = v``), and that second call is where this one detonates —
    past the copy loop's old ``except Exception``.
    """

    def __init__(self):
        self._armed = False

    def __hash__(self):  # noqa: D105
        if self._armed:
            raise _Boom("leftover re-hash bomb")
        self._armed = True
        return 1


class CtrlC:
    """``__class__`` raises KeyboardInterrupt: genuine control flow."""

    @property
    def __class__(self):  # noqa: D105
        raise KeyboardInterrupt


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

    def change_password(self, current=PASSWORD, new=NEW_PASSWORD):
        auth._login_attempts.clear()
        return self.client.post(
            "/api/auth/change-password",
            json={
                "username": "admin",
                "current_password": current,
                "new_password": new,
            },
        )


class ProfileAndSessionBombTests(_AppSandbox):
    """The profile read and session checks over each fixed shape."""

    def test_class_bomb_accounts_rank_keeps_status_login_and_cookie_up(self):
        # isinstance consults __class__ when the exact-type check misses, so
        # this used to raise out of _isinst's rank gate at the accounts value
        # on every read of the registry.
        with self.poisoned(self.base_auth(accounts=ClassBomb())):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            self.assertTrue(status.json()["authenticated"])
            self.sign_in()

    def test_bool_bomb_username_slot_answers_the_profile_read(self):
        # _pick's truth test used to detonate; the junk slot now reads as the
        # default name and the admin keeps signing in under it.
        with self.poisoned(self.base_auth(username=BoolBomb())):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            self.sign_in()

    def test_get_bomb_settings_block_reads_its_real_storage(self):
        # The dict.get salvage reads the honest block underneath the
        # override, so the session survives the poisoned method untouched.
        shape = {"settings": GetBombMap(
            {"auth": self.base_auth()["settings"]["auth"]}
        )}
        with self.poisoned(shape):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            self.assertTrue(status.json()["authenticated"])

    def test_items_bomb_epochs_mapping_keeps_login_up(self):
        # account_session_version walks session_epochs on every login and
        # cookie check; the unbound dict.items salvage keeps the counters.
        with self.poisoned(self.base_auth(session_epochs=ItemsBombMap({"admin": 1}))):
            self.sign_in()
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])

    def test_int_bomb_epoch_value_counts_as_zero_not_a_500(self):
        with self.poisoned(self.base_auth(session_epochs={"admin": IntBomb()})):
            self.sign_in()
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])

    def test_str_bomb_hash_slot_costs_the_credential_not_the_route(self):
        # The unreadable hash reads as "": sessions against it stop
        # verifying (coded, fail-closed), but the profile read stays JSON.
        with self.poisoned(self.base_auth(password_hash=StrBomb())):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)
            self.assertFalse(status.json()["setup_required"])

    def test_snapshot_provider_raising_the_other_base_degrades_coded(self):
        # _auth_cfg's cfg() guard: an Exception-flavoured raise always read
        # as an empty block; the BaseException flavour now does the same.
        with mock.patch.object(auth, "cfg", side_effect=_Boom("cfg bomb")):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertJsonEncodable(status)


class PasswordChangeBombTests(_AppSandbox):
    """The password-change walk over the fixed shapes, writes landing."""

    def test_own_rotation_survives_class_bomb_accounts_and_lands_on_disk(self):
        with self.poisoned(self.base_auth(accounts=ClassBomb())):
            response = self.change_password()
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)
            self.assertTrue(response.json().get("ok"))
        # The rotation was written through mutate() to the real file: once
        # the snapshot poison is gone, only the new credential signs in.
        config.reload_cfg()
        self.sign_in(password=NEW_PASSWORD)

    def test_admin_reset_survives_items_bomb_epochs(self):
        with self.poisoned(self.base_auth(
            accounts=[self.member_row()],
            session_epochs=ItemsBombMap({"kid": 1}),
        )):
            auth._login_attempts.clear()
            response = self.client.post(
                "/api/auth/accounts/kid/password",
                json={"new_password": NEW_PASSWORD},
            )
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)
        config.reload_cfg()
        member = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(member, "kid", NEW_PASSWORD)

    def test_rehash_bomb_row_key_costs_its_field_not_the_rotation(self):
        # The laundering copy re-hashes non-str keys into the fresh row;
        # this key's second hash raises the other base and used to ride out
        # of the copy loop as a raw 500 on both password-change routes.
        bombed_row = {"username": "ghost"}
        dict.__setitem__(bombed_row, LateHashBomb(), "junk")
        with self.poisoned(self.base_auth(
            accounts=[bombed_row, self.member_row()]
        )):
            response = self.change_password()
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)
            self.assertTrue(response.json().get("ok"))


class ShadowKeyOtherBaseTests(_AppSandbox):
    """The account12 shadow row key, re-armed on the other base.

    The reader walk was a *fixed* leak here: ``_mapping_get``'s catch
    stopped at Exception, so the re-armed ``__eq__`` rode out of
    ``raw.get("username")`` as a raw 500 on login/status.  The rotation walk
    stays immune either way — pinned so the laundering copy is not weakened.
    """

    def test_shadow_key_row_on_the_other_base_keeps_login_and_status_up(self):
        # fixed: the poisoned slot's comparison now fails closed inside
        # _mapping_get whatever base it raises on — the row lists nothing,
        # its siblings stay usable.
        shape = self.base_auth(
            accounts=[{ShadowKeyBase("username"): "ghost"}, self.member_row()]
        )
        with self.poisoned(shape):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"])
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)

    def test_shadow_key_row_on_the_other_base_keeps_the_rotation_coded(self):
        # The account12 laundering copy reads the key through str.__str__,
        # so the membership walk never runs the override at all — pinned
        # here so the stronger union guard is not weakened later.
        shape = self.base_auth(
            accounts=[{ShadowKeyBase("username"): "ghost"}, self.member_row()]
        )
        with self.poisoned(shape):
            response = self.change_password()
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertJsonEncodable(response)
            self.assertTrue(response.json().get("ok"))


class GuardUnitTests(unittest.TestCase):
    """The hardened helpers' contracts, in isolation."""

    def test_isinst_fails_closed_on_the_other_base(self):
        self.assertFalse(auth._isinst(ClassBomb(), dict))

    def test_truthy_fails_closed_on_the_other_base(self):
        self.assertFalse(auth._truthy(BoolBomb()))

    def test_mapping_get_salvages_real_storage_past_the_bomb(self):
        block = GetBombMap({"username": "admin"})
        self.assertEqual(auth._mapping_get(block, "username"), "admin")

    def test_mapping_items_salvages_real_storage_past_the_bomb(self):
        block = ItemsBombMap({"admin": 3})
        self.assertEqual(auth._mapping_items(block), [("admin", 3)])

    def test_cfg_text_reads_bomb_as_empty(self):
        self.assertEqual(auth._cfg_text(StrBomb()), "")

    def test_epoch_count_reads_bomb_as_zero(self):
        self.assertEqual(auth._epoch_count(IntBomb()), 0)

    def test_account_rows_drops_the_rehash_bombed_field_only(self):
        row = {"username": "kid"}
        dict.__setitem__(row, LateHashBomb(), "junk")
        rows = auth._account_rows({"accounts": [row, {"username": "pal"}]})
        self.assertEqual(rows, [{"username": "kid"}, {"username": "pal"}])

    def test_auth_cfg_reads_a_raising_provider_as_empty(self):
        with mock.patch.object(auth, "cfg", side_effect=_Boom("cfg bomb")):
            self.assertEqual(auth._auth_cfg(), {})

    def test_control_flow_keeps_propagating(self):
        # The union guards must not swallow a Ctrl-C: genuine control flow
        # crosses every hardened helper untouched.
        with self.assertRaises(KeyboardInterrupt):
            auth._isinst(CtrlC(), dict)
        with self.assertRaises(KeyboardInterrupt):
            auth._truthy(_KIBoolBomb())
        with self.assertRaises(KeyboardInterrupt):
            auth._cfg_text(_KIStrBomb())
        with mock.patch.object(auth, "cfg", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                auth._auth_cfg()


class _KIBoolBomb:
    def __bool__(self):  # noqa: D105
        raise KeyboardInterrupt


class _KIStrBomb:
    def __str__(self):  # noqa: D105
        raise KeyboardInterrupt


if __name__ == "__main__":
    unittest.main(verbosity=2)
