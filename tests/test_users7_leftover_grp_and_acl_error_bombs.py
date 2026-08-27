"""Users-page leftover sweep #7: grp id bombs and the ACL error funnel.

Sweep 6 sealed the self-``__str__`` encode bombs and the subclass gates on
GET /api/users, /api/identity and the share-ACL routes.  Driving the same
surfaces again through ``create_app()`` + ``TestClient(
raise_server_exceptions=False)`` found three live leftovers plus one
sibling-wipe, all in the dict-subclass / unbound-coercion class this wave
hunts:

* **GET /api/users 500'd on a ``__hash__``-bomb ``gr_gid``.**
  ``list_users`` seeds ``admin_gids`` from ``grp.getgrnam("admin"/"staff")``
  under a narrow ``(KeyError, OSError, TypeError)`` catch; a leftover
  int-subclass gid whose ``__hash__`` raises detonated ``set.add`` itself —
  a raw 500 before the first pwd row was even read.

* **PUT /api/shares/acl 500'd on a ``__bool__``-bomb error field.**
  ``set_user_access`` probed ``isinstance(raw_error, str) and raw_error``:
  the truth test fired the subclass ``__bool__`` and the raise escaped the
  routers' ShareAclError handler untyped.

* **PUT /api/shares/acl 500'd on an ``__eq__``-bomb error field.**  The
  same funnel kept the subclass *instance* and compared ``error ==
  "failed"`` for the vanished-chmod probe — the reflected ``__eq__`` bomb
  blew the probe itself.  The unbound ``_as_text`` scrub now launders the
  field to an exact str first, which also means a bombed-but-legible
  ``"cancelled"`` keeps its coded 409 instead of degrading to the generic
  authorization failure.

* **A bound ``__int__``/``__index__`` bomb uid wiped every healthy row.**
  ``int(u.pw_uid)`` raising outside the row's ``(TypeError, ValueError,
  OverflowError, AttributeError)`` net escaped into the walk's
  mid-iteration catch: GET /api/users answered 200 with an *empty* list
  instead of skipping just the poisoned Open Directory record.
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


class BoolBombStr(str):
    """str subclass detonating any truth test while ``__str__`` keeps self."""

    def __str__(self):
        return self

    def __bool__(self):
        raise RuntimeError("bool bomb")


class EqBombStr(str):
    """str subclass whose ``==`` raises (reflected into ``in`` / mapping probes)."""

    def __str__(self):
        return self

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = str.__hash__


class HashBombInt(int):
    """int subclass whose ``__hash__`` raises — detonates ``set.add``."""

    def __hash__(self):
        raise RuntimeError("hash bomb")


class IntCoercionBomb(int):
    """int subclass whose bound ``__int__``/``__index__`` both raise."""

    def __int__(self):
        raise RuntimeError("int bomb")

    def __index__(self):
        raise RuntimeError("index bomb")


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


# ── GET /api/users: grp / pwd id bombs ────────────────────────────────────────

_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
_Gr = namedtuple("Gr", "gr_name gr_passwd gr_gid gr_mem")
GOOD = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")


class UsersGrpIdBombTests(_AppSandbox):
    def _get_users(self, entries, getgrnam=None):
        self.claim_and_sign_in()
        grnam = (
            mock.patch.object(users_svc.grp, "getgrnam", return_value=getgrnam)
            if getgrnam is not None
            else mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError)
        )
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            grnam,
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            return self.client.get("/api/users")

    def test_hash_bomb_gr_gid_keeps_the_page_not_500(self):
        """``admin_gids.add`` detonated the subclass ``__hash__`` outside the
        old (KeyError, OSError, TypeError) net — a raw 500 before any row."""
        response = self._get_users(
            [GOOD], getgrnam=_Gr("admin", "*", HashBombInt(80), [])
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_int_coercion_bomb_uid_costs_its_row_only(self):
        """``int(u.pw_uid)`` raising RuntimeError escaped into the walk's
        mid-iteration catch and wiped every healthy row (200 with [])."""
        bomb = _Pw("eve", "x", IntCoercionBomb(501), 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_int_coercion_bomb_gid_costs_its_row_only(self):
        bomb = _Pw("eve", "x", 501, IntCoercionBomb(20), "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )


# ── PUT /api/shares/acl: the privileged-failure error funnel ─────────────────

def _ls_listing(path: str, extra: str = "") -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: group:everyone deny delete\n"
        + extra
    )


class ShareAclErrorFunnelBombTests(_AppSandbox):
    """set_user_access's failure shaping must survive subclass error fields."""

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

    def _put(self, admin_result, chmod=(0, "", "")):
        listing = _ls_listing(str(self.share_dir), " 1: user:alice allow read\n")

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return 0, listing, ""
            if argv[0] == share_acl_svc.DSCL:
                if "-list" in argv:
                    return 0, "alice 501\n", ""
                return 1, "", ""
            if argv[0] == share_acl_svc.CHMOD:
                return chmod
            return 0, "", ""

        with (
            mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh),
            mock.patch.object(
                share_acl_svc.macos_admin,
                "run_admin_sequence",
                return_value=admin_result,
            ),
            # The panel does not own the directory, so the privileged path
            # (run_admin_sequence) is the one that answers.
            mock.patch.object(share_acl_svc.os, "getuid", return_value=99999999),
        ):
            return self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "read",
                },
            )

    def test_bool_bomb_error_field_is_the_coded_failure_not_raw_500(self):
        """``isinstance(raw_error, str) and raw_error`` detonated the truth
        test itself; the raise escaped the router's handler untyped."""
        response = self._put({"ok": False, "error": BoolBombStr("failed")})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_eq_bomb_error_field_is_the_coded_failure_not_raw_500(self):
        """Keeping the subclass instance let ``error == "failed"`` fire the
        reflected ``__eq__`` bomb inside the vanished-chmod probe."""
        response = self._put({"ok": False, "error": EqBombStr("failed")})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_bombed_but_legible_cancelled_keeps_its_coded_409(self):
        """The unbound scrub reads the real text underneath the override, so
        a poisoned "cancelled" still maps to authorization_cancelled instead
        of degrading to the generic failure."""
        response = self._put({"ok": False, "error": BoolBombStr("cancelled")})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled"
        )

    def test_owner_needs_root_funnel_survives_the_bomb_too(self):
        """The owner-run chmod escalating to run_admin_sequence goes through
        the same shaping; the bomb must not 500 that leg either."""
        listing = _ls_listing(str(self.share_dir), " 1: user:alice allow read\n")

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return 0, listing, ""
            if argv[0] == share_acl_svc.DSCL:
                if "-list" in argv:
                    return 0, "alice 501\n", ""
                return 1, "", ""
            if argv[0] == share_acl_svc.CHMOD:
                return 1, "", "Operation not permitted"
            return 0, "", ""

        with (
            mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh),
            mock.patch.object(
                share_acl_svc.macos_admin,
                "run_admin_sequence",
                return_value={"ok": False, "error": EqBombStr("failed")},
            ),
        ):
            response = self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "read",
                },
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_vanish_classification_still_works_on_a_bombed_failed(self):
        """Laundering must run *before* the vanished-chmod probe: a bombed
        generic failure with a vanish-marker message and chmod gone from
        disk keeps the coded 503."""
        with mock.patch.object(
            share_acl_svc, "_tool_on_disk", return_value=False
        ):
            response = self._put(
                {
                    "ok": False,
                    "error": EqBombStr("failed"),
                    "message": "sh: /bin/chmod: command not found",
                }
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_tool_missing"
        )


if __name__ == "__main__":
    unittest.main()
