"""Users-page leftover sweep #8: the grp membership walk and ACL stays-immune.

Sweep 7 sealed the ``gr_gid`` ``__hash__`` bomb in ``admin_gids.add``, the
bound ``__int__``/``__index__`` coercion bombs on ``pw_uid``/``pw_gid`` (a
poisoned id costs its own row only), and the share-ACL error funnel's
``__bool__``/``__eq__`` subclass bombs.  Driving GET /api/users and the
share-ACL routes again through ``create_app()`` + ``TestClient(
raise_server_exceptions=False)`` found one more live leftover in the same
"a poisoned Open Directory value must cost only itself" class, this time one
rank deeper — inside the per-user group-membership walk:

* **A poisoned gid from ``os.getgrouplist`` wiped the user's *remaining*
  group memberships and its ``admin`` flag.**  ``list_users`` looks each
  membership up with ``grp.getgrgid(g).gr_name`` under a narrow ``(KeyError,
  OSError, TypeError, OverflowError)`` catch.  A leftover Open Directory gid
  whose lookup raises something else — a ``RuntimeError`` from an
  int-subclass ``__index__``/``__hash__``, an ``AttributeError`` on a struct
  missing ``gr_name`` — escaped that net into the walk's *outer* ``except
  Exception``, which aborts the whole membership loop.  Every group after the
  poisoned gid was dropped, and because the ``admin``/``wheel`` group can sit
  anywhere in the list, the classification silently flipped off: an actual
  administrator answered GET /api/users as a plain user with an empty
  ``groups`` list.  The broadened per-gid catch now costs only the one
  unanswerable entry, matching the users7 rule at row rank.

The remaining cases below are **stays-immune pins**: the group-membership
walk and the share-ACL surfaces already answer these leftovers coded / 200,
and no prior users test exercises them at group rank.  They lock the seal so
a future refactor cannot quietly reopen it.
"""
from __future__ import annotations

import unittest
from collections import namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, share_acl_svc, twofa_svc, users_svc
from hub.app_factory import create_app
from hub.routers import shares as shares_router

PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class IndexBombInt(int):
    """int subclass whose bound ``__int__``/``__index__`` both raise."""

    def __int__(self):
        raise RuntimeError("int bomb")

    def __index__(self):
        raise RuntimeError("index bomb")


class HashBombInt(int):
    """int subclass whose ``__hash__`` raises — detonates a keyed lookup."""

    def __hash__(self):
        raise RuntimeError("hash bomb")


class SelfStrEncodeBomb(str):
    """str subclass whose ``__str__`` answers *self* so the bound ``.encode``
    bomb survives ``str()`` (the modules6 self-``__str__`` class)."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("bound encode bomb")


class IterBombList(list):
    """list subclass whose walk dies at ``iter()``."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a signed-in admin client per test."""

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
        api_keys._last_seen.clear()
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def claim_and_sign_in(self) -> None:
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n',
            encoding="utf-8",
        )
        config.reload_cfg()
        auth._login_attempts.clear()
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200)


# ── GET /api/users: the per-user group-membership walk ───────────────────────

_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
_Gr = namedtuple("Gr", "gr_name gr_passwd gr_gid gr_mem")
GOOD = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")


class GroupMembershipWalkTests(_AppSandbox):
    def _get_users(self, grouplist, getgrgid):
        self.claim_and_sign_in()
        gg = (
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=getgrgid)
            if callable(getgrgid) or isinstance(getgrgid, type)
            else mock.patch.object(users_svc.grp, "getgrgid", return_value=getgrgid)
        )
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[GOOD]),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            gg,
            mock.patch.object(
                users_svc.os, "getgrouplist", return_value=grouplist
            ),
        ):
            return self.client.get("/api/users")

    def test_poison_gid_keeps_the_remaining_groups_and_admin_flag(self):
        """The live leftover: a gid whose ``getgrgid`` raises outside the old
        narrow net aborted the whole membership walk, so a later ``admin``
        group was never seen — the user lost every remaining group and its
        admin classification silently flipped off."""

        def getgrgid(g):
            if g == 777:
                # RuntimeError is outside (KeyError, OSError, TypeError,
                # OverflowError): the class the narrow catch used to miss.
                raise RuntimeError("open directory bomb")
            if g == 80:
                return _Gr("admin", "*", 80, [])
            raise KeyError(g)

        response = self._get_users([777, 80], getgrgid)
        self.assertEqual(response.status_code, 200)
        user = response.json()["users"][0]
        self.assertEqual(user["groups"], ["admin"])
        self.assertTrue(user["admin"])

    def test_attributeerror_on_missing_gr_name_costs_only_its_entry(self):
        """A struct with no ``gr_name`` raises AttributeError — also outside
        the old net — and must not cost the sibling membership either."""
        NoName = namedtuple("NoName", "gr_gid")

        def getgrgid(g):
            if g == 777:
                return NoName(777)
            if g == 80:
                return _Gr("wheel", "*", 80, [])
            raise KeyError(g)

        response = self._get_users([777, 80], getgrgid)
        self.assertEqual(response.status_code, 200)
        user = response.json()["users"][0]
        self.assertEqual(user["groups"], ["wheel"])
        self.assertTrue(user["admin"])

    # ── stays-immune pins on the same walk ───────────────────────────────────

    def test_index_bomb_gid_stays_immune(self):
        """A leftover int-subclass gid whose ``__index__`` bombs when
        ``getgrgid`` coerces it stays a coded 200 with the sibling intact."""

        def getgrgid(g):
            # Touching the value the way the C lookup would detonates the bomb.
            int(g)
            return _Gr("staff", "*", int(g), [])

        response = self._get_users([IndexBombInt(777), 80], getgrgid)
        self.assertEqual(response.status_code, 200)
        # The poisoned gid is skipped; the plain 80 answers "staff".
        user = response.json()["users"][0]
        self.assertIn("staff", user["groups"])

    def test_hash_bomb_gid_stays_immune(self):
        def getgrgid(g):
            hash(g)
            return _Gr("staff", "*", int(g), [])

        response = self._get_users([HashBombInt(777), 80], getgrgid)
        self.assertEqual(response.status_code, 200)

    def test_selfstr_encode_bomb_gr_name_stays_200_scrubbed(self):
        """``gr_name`` as a self-``__str__`` encode bomb is field-scrubbed by
        the unbound ``_pwd_text``; the membership still lands, never a 500."""
        response = self._get_users(
            [80], _Gr(SelfStrEncodeBomb("admin"), "*", 80, [])
        )
        self.assertEqual(response.status_code, 200)
        user = response.json()["users"][0]
        self.assertIn("admin", user["groups"])
        self.assertTrue(user["admin"])

    def test_getgrouplist_iterbomb_stays_immune(self):
        """A membership list whose ``__iter__`` bombs at the walk is caught by
        the surrounding guard; the user still lists with no groups, not a 500."""
        response = self._get_users(IterBombList([20]), side_effect_keyerror())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )


def side_effect_keyerror():
    def _raise(*_a, **_k):
        raise KeyError
    return _raise


# ── GET/PUT /api/shares/acl: stays-immune pins ───────────────────────────────

def _ls_listing(path: str, extra: str = "") -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: group:everyone deny delete\n"
        + extra
    )


class ShareAclStaysImmuneTests(_AppSandbox):
    """The ACL surfaces already answer these coded; lock the seal."""

    def setUp(self):
        super().setUp()
        self.share_dir = self.root / "share"
        self.share_dir.mkdir()
        patcher = mock.patch.object(
            shares_router.shares_svc,
            "list_smb_shares",
            return_value=[{"path": str(self.share_dir)}],
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.claim_and_sign_in()

    def test_get_acl_over_cap_index_line_is_skipped_not_500(self):
        """An ACL line whose index runs past CPython's int->str digit cap is
        skipped like any unparsable row instead of 500'ing the GET."""
        big = "9" * 4400
        poisoned = _ls_listing(
            str(self.share_dir), f" {big}: user:alice allow read\n"
        )

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return 0, poisoned, ""
            if argv[0] == share_acl_svc.DSCL and "-list" in argv:
                return 0, "alice 501\n", ""
            return 1, "", ""

        with mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh):
            response = self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )
        self.assertEqual(response.status_code, 200)
        names = [e["name"] for e in response.json()["entries"]]
        self.assertNotIn("alice", names)
        self.assertIn("everyone", names)


if __name__ == "__main__":
    unittest.main()
