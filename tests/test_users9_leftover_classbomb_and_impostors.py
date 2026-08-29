"""Users-page leftover sweep #9: ``__class__``-property bombs and impostors.

Sweep 8 sealed the grp membership walk (a poisoned gid costs only its own
entry).  Driving GET /api/users and the share-ACL routes again through
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` found six
live leftovers, all in the ``__class__`` class this wave hunts — the raising
*property* that detonates a bare ``isinstance`` gate, and the *lying*
impostor that passes the gate but is not the type underneath:

* **A ``__class__``-property bomb in any ``pw_*`` text field wiped every
  healthy row after it.**  ``_pwd_text``'s bare ``isinstance(value, (bytes,
  bytearray))`` consulted the raising property, and the raise rode into the
  walk's mid-iteration catch: one poisoned Open Directory record answered
  GET /api/users with the rows after it silently gone.  ``users_svc`` now
  carries the fail-closed ``_isa`` its siblings already had, and each pwd
  record gets its own catch (``_user_row``) so *any* hostile field costs the
  poisoned row only.

* **A bytes-lying impostor field rode the unbound decode out of the walk.**
  A value whose ``__class__`` property answers ``bytes`` passed the gate but
  is no bytes underneath, so ``bytes.decode(value, ...)`` TypeError'd down
  the same row-wiping path.  The decode is try-wrapped and falls through to
  the str() rank, so a legible impostor still renders.

* **GET /api/shares/acl answered a raw 500 on a bytes-lying impostor in the
  ``ls`` output.**  ``share_acl_svc._as_text`` had the same bare inner gate
  and unguarded unbound decode; the TypeError escaped ``parse_acl_listing``
  untyped, past every coded refusal.

* **The same impostor in the ``dscl`` output 500'd the GET through
  ``local_users``.**  Now the picker degrades to empty and the ACL half of
  the payload still answers.

* **PUT /api/shares/acl answered a raw 500 on a ``__class__``-bomb error
  value from the privileged helper.**  ``set_user_access``'s failure funnel
  gated the scrub with a bare ``isinstance(raw_error, str)`` — the bomb blew
  the gate one line ahead of the laundering built for exactly this field
  (the users7 ``__bool__``/``__eq__`` seals).  A bombed *message* field on a
  generic failure detonated the same funnel one line later, inside
  ``_as_text``.  Both now keep the coded refusal.

* **A hostile share row hid the real share points from the ACL gate.**
  ``_share_directory``'s walk gated rows with a bare ``isinstance(share,
  dict)``: a ``__class__``-property bomb blew the gate into the walk-level
  catch, and a dict-lying impostor TypeError'd the unbound ``dict.get`` the
  same way — every share point after the hostile row was lost and a
  legitimately shared directory answered the acl_not_share /
  sharing_missing lie on GET and PUT alike.

All tests drive the real app; the closing pins lock the seals so a refactor
cannot quietly reopen them.
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


class ClassBomb:
    """Object whose ``__class__`` is a raising property: a bare isinstance
    gate detonates instead of answering False.  ``__str__`` still works, so
    the value is legible once the gate survives."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")

    def __str__(self):
        return "bombed"


class BytesImpostor:
    """Lies that it is ``bytes``; the unbound ``bytes.decode`` then
    TypeErrors because there is no bytes underneath."""

    @property
    def __class__(self):
        return bytes

    def __str__(self):
        return "impostor"


class DictImpostor:
    """Lies that it is ``dict``; the unbound ``dict.get`` then TypeErrors."""

    @property
    def __class__(self):
        return dict


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


# ── GET /api/users: __class__ bombs / impostors in pwd fields ─────────────────

_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
_Gr = namedtuple("Gr", "gr_name gr_passwd gr_gid gr_mem")
GOOD = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")


class UsersClassBombFieldTests(_AppSandbox):
    def _get_users(self, entries, getgrnam=None, getgrgid=None):
        self.claim_and_sign_in()
        grnam = (
            mock.patch.object(users_svc.grp, "getgrnam", return_value=getgrnam)
            if getgrnam is not None
            else mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError)
        )
        grgid = (
            mock.patch.object(users_svc.grp, "getgrgid", return_value=getgrgid)
            if getgrgid is not None
            else mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError)
        )
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            grnam,
            grgid,
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            return self.client.get("/api/users")

    def test_classbomb_pw_name_costs_its_row_only(self):
        """The live leftover: the raising ``__class__`` property blew
        ``_pwd_text``'s bare bytes gate into the walk's mid-iteration catch —
        200 with every healthy row after the poisoned one gone."""
        bomb = _Pw(ClassBomb(), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        # The healthy sibling survives; the poisoned row renders through the
        # str() rank instead of costing the page.
        self.assertIn("dave", names)

    def test_classbomb_pw_shell_keeps_the_healthy_rows(self):
        """Same bomb, planted past the name filters — it used to detonate at
        the ``pw_shell`` read and wipe the rows after it just the same."""
        bomb = _Pw("eve", "x", 501, 20, "", "/", ClassBomb())
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertIn("eve", names)
        self.assertIn("dave", names)

    def test_classbomb_pw_gecos_keeps_the_healthy_rows(self):
        """And once more at the last field read of the row build."""
        bomb = _Pw("eve", "x", 501, 20, ClassBomb(), "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertIn("eve", names)
        self.assertIn("dave", names)

    def test_bytes_impostor_pw_name_renders_and_keeps_the_sibling(self):
        """The lying impostor passed the bytes gate; the unbound decode's
        TypeError rode the same row-wiping path out of the walk."""
        bomb = _Pw(BytesImpostor(), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertIn("dave", names)
        # Legible underneath the lie: the str() rank renders it.
        self.assertIn("impostor", names)

    def test_bytes_impostor_pw_dir_keeps_its_row_and_the_sibling(self):
        bomb = _Pw("eve", "x", 501, 20, "", BytesImpostor(), "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertEqual(sorted(names), ["dave", "eve"])

    # ── stays-immune pins at group rank ───────────────────────────────────────

    def test_classbomb_gr_name_in_membership_walk_stays_200(self):
        """A ``__class__``-bomb ``gr_name`` inside the per-gid catch already
        costs at most its own entry; pin it so the seal holds."""
        response = self._get_users(
            [GOOD], getgrgid=_Gr(ClassBomb(), "*", 20, [])
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_classbomb_gr_gid_from_getgrnam_stays_200(self):
        """The admin-gid seed reads ``gr_gid`` under its broad catch; a
        ``__class__`` bomb there stays a 200 before the first row."""
        response = self._get_users(
            [GOOD], getgrnam=_Gr("admin", "*", ClassBomb(), [])
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )


# ── GET/PUT /api/shares/acl: __class__ bombs / impostors ─────────────────────

def _ls_listing(path: str, extra: str = "") -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: user:alice allow read\n"
        + extra
    )


class ShareAclClassBombTests(_AppSandbox):
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

    def _fake_sh(self, ls_output=None, dscl_output="alice 501\n"):
        listing = (
            ls_output if ls_output is not None
            else _ls_listing(str(self.share_dir))
        )

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return 0, listing, ""
            if argv[0] == share_acl_svc.DSCL and "-list" in argv:
                return 0, dscl_output, ""
            return 1, "", ""

        return fake_sh

    def test_bytes_impostor_ls_output_is_the_coded_read_failure(self):
        """The live leftover: the impostor blew ``_as_text``'s unbound decode
        inside ``parse_acl_listing`` — a raw 500 past every coded refusal."""
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(ls_output=BytesImpostor())
        ):
            response = self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed"
        )

    def test_bytes_impostor_dscl_output_keeps_the_acl_and_empty_picker(self):
        """The same impostor in the dscl listing 500'd the GET through
        ``local_users``; now the picker degrades to empty and the ACL half
        still answers."""
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(dscl_output=BytesImpostor())
        ):
            response = self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["users"], [])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])

    def _put(self, admin_result):
        with (
            mock.patch.object(share_acl_svc, "sh", side_effect=self._fake_sh()),
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
                    "level": "readwrite",
                },
            )

    def test_classbomb_error_value_is_the_coded_refusal_not_raw_500(self):
        """The live leftover: the bare ``isinstance(raw_error, str)`` gate
        consulted the raising ``__class__`` one line ahead of the scrub the
        users7 seals put there — a raw 500 out of the failure funnel."""
        response = self._put({"ok": False, "error": ClassBomb()})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_bytes_impostor_message_keeps_the_coded_refusal(self):
        """A generic failure with an impostor ``message`` detonated the same
        funnel one line later, inside ``_as_text``'s unbound decode."""
        response = self._put(
            {"ok": False, "error": "failed", "message": BytesImpostor()}
        )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def _get_with_rows(self, rows):
        with (
            mock.patch.object(
                shares_router.shares_svc, "list_smb_shares", return_value=rows
            ),
            mock.patch.object(share_acl_svc, "sh", side_effect=self._fake_sh()),
        ):
            return self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )

    def test_classbomb_share_row_does_not_hide_the_real_share_point(self):
        """The live leftover: the bare ``isinstance(share, dict)`` gate blew
        into the walk-level catch, so the real share point after the hostile
        row was never collected and this legitimately shared directory
        answered the sharing_missing / acl_not_share lie."""
        response = self._get_with_rows([ClassBomb(), {"path": str(self.share_dir)}])
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "alice", [e["name"] for e in response.json()["entries"]]
        )

    def test_dict_impostor_share_row_does_not_hide_the_real_share_point(self):
        """The lying impostor passed the dict gate and the unbound
        ``dict.get`` TypeError'd down the same walk-aborting path."""
        response = self._get_with_rows(
            [DictImpostor(), {"path": str(self.share_dir)}]
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "alice", [e["name"] for e in response.json()["entries"]]
        )


if __name__ == "__main__":
    unittest.main()
