"""Users-page leftover sweep #6: self-``__str__`` bombs and subclass gates.

Sweeps 1-5 hardened GET /api/users, the panel-accounts CRUD, the 2FA store,
the identity write path and the share-ACL grants.  Driving the same surfaces
again through ``create_app()`` + ``TestClient(raise_server_exceptions=False)``
found five live leftovers, all in the class the modules6 sweep just fixed in
``hub/modules.py`` (bound-method calls on values that survive ``str()`` /
``isinstance`` as hostile subclasses):

* **GET and PUT /api/shares/acl 500'd on a self-``__str__`` encode bomb in
  sh output.**  ``share_acl_svc._as_text`` wrapped only ``str(value)`` in its
  try; the final scrub was a bound ``value.encode(...)``.  A str subclass
  whose ``__str__`` answers *self* skips CPython's exact-str copy, so its
  ``encode`` bomb rode that line out of ``parse_acl_listing`` /
  ``local_users`` untyped — a raw 500 past the routers' ShareAclError
  handler.  Unbound ``str.encode`` now scrubs it field-level.

* **The share-ACL failure funnels detonated a ``__bool__``-bomb stderr.**
  ``_as_text(error or output)`` (read_acl) and ``_as_text(err or out or
  "failed")`` (_run_unprivileged) put the truth test *before* the scrub, so
  the bomb raised out of the ``or`` chain itself — a raw 500 in place of the
  coded ``shares.acl_read_failed`` / ``shares.authorization_failed``.

* **GET /api/identity 500'd on encode/decode bombs in sh output.**  Same
  class in ``identity_svc._as_text``: the bound final encode, plus a bound
  ``value.decode`` on the bytes branch (the brew6 rule its share-ACL sibling
  already had).

* **GET /api/identity 500'd on a dict-subclass config block.**  It read
  ``cfg().get("settings")`` with the *bound* ``.get`` and then ``s.get(...)``
  on a block that passed ``isinstance`` — the exact class
  ``config.settings_section`` exists to launder.  A ``__bool__``-bomb
  ``server_comment`` value additionally blew the bare
  ``s.get(...) or s.get(...)`` chain.

* **GET and PUT /api/shares/acl 500'd on a list-subclass share listing.**
  ``_share_directory`` walked ``list_smb_shares()`` with a bare ``for``; a
  leftover whose ``__iter__`` bomb fired at the walk raised out of the gate
  itself (the users5 ``iter()`` rule the dict-subclass *row* guard beside it
  already followed).

One same-class degradation rode along on GET /api/users: ``_pwd_text``'s
bound encode/decode meant a poisoned pwd row cost every healthy row *after*
it (the walk's mid-iteration catch ate the raise).  Rows now survive
field-scrubbed, siblings intact.
"""
from __future__ import annotations

import json
import unittest
from collections import namedtuple
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, identity_svc, share_acl_svc, twofa_svc, users_svc
from hub.app_factory import create_app
from hub.routers import shares as shares_router

PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class EncodeBomb(str):
    """str subclass whose ``__str__`` answers *self*, so ``str()`` keeps the
    subclass and the bound ``.encode`` bomb survives to the final scrub."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("bound encode bomb")


class BoolBomb(str):
    """str subclass detonating the truth test hidden in ``a or b``."""

    def __str__(self):
        return self

    def __bool__(self):
        raise RuntimeError("bool bomb")


class DecodeBombBytes(bytes):
    """bytes subclass whose bound ``.decode`` raises (the brew6 class)."""

    def decode(self, *args, **kwargs):
        raise RuntimeError("bound decode bomb")


class GetBombDict(dict):
    """dict subclass passing ``isinstance`` whose ``.get`` raises."""

    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class IterBombList(list):
    """list subclass whose directory walk dies at ``iter()``."""

    def __iter__(self):
        raise OSError(5, "EIO")


class _DiesAfterFirst(list):
    """list subclass whose iterator yields its first row then dies."""

    def __iter__(self):
        rows = list.__iter__(self)

        def gen():
            yield next(rows)
            raise OSError(5, "EIO mid-walk")

        return gen()


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

    def claim(self) -> None:
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n',
            encoding="utf-8",
        )
        config.reload_cfg()

    def sign_in(self) -> None:
        auth._login_attempts.clear()
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200)


# ── GET/PUT /api/shares/acl: self-__str__ bombs in sh output ─────────────────

def _ls_listing(path: str, extra: str = "") -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: group:everyone deny delete\n"
        + extra
    )


class _ShareAclSandbox(_AppSandbox):
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
        self.claim()
        self.sign_in()

    def _sh(self, ls=(None, None, None), dscl_list=(0, "alice 501\n", ""),
            chmod=(0, "", "")):
        listing = _ls_listing(str(self.share_dir))
        default_ls = (0, listing, "")

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return ls if ls[0] is not None else default_ls
            if argv[0] == share_acl_svc.DSCL:
                if "-list" in argv:
                    return dscl_list
                return 1, "", ""
            if argv[0] == share_acl_svc.CHMOD:
                return chmod
            return 0, "", ""

        return mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh)

    def _get(self):
        return self.client.get(
            "/api/shares/acl", params={"path": str(self.share_dir)}
        )


class ShareAclEncodeBombTests(_ShareAclSandbox):
    """The live leftovers: bound encode / ``or``-chain bombs 500'd the ACL."""

    def test_encode_bomb_ls_output_keeps_the_page_not_500(self):
        """``str()`` of the self-__str__ subclass keeps the subclass; the
        bound encode bomb used to raise out of parse_acl_listing untyped."""
        listing = EncodeBomb(_ls_listing(str(self.share_dir)))
        with self._sh(ls=(0, listing, "")):
            response = self._get()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["owner"], "a0000")
        self.assertEqual(len(body["entries"]), 1)
        self.assertEqual(body["entries"][0]["effect"], "deny")

    def test_surrogate_riding_the_bomb_degrades_to_replacement(self):
        """The unbound scrub still applies utf-8/"replace": a lone surrogate
        inside the bombed listing reads back as "?", never a 500."""
        poisoned = _ls_listing(str(self.share_dir)).replace(
            "everyone", "every\ud800one"
        )
        with self._sh(ls=(0, EncodeBomb(poisoned), "")):
            response = self._get()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["entries"][0]["name"], "every?one")
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))

    def test_encode_bomb_dscl_output_keeps_the_picker_not_500(self):
        with self._sh(dscl_list=(0, EncodeBomb("alice 501\n"), "")):
            response = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["username"] for u in response.json()["users"]], ["alice"]
        )

    def test_bool_bomb_ls_stderr_is_the_coded_read_failure_not_raw_500(self):
        """``_as_text(error or output)`` detonated the truth test itself;
        the vanish-marker probe never ran and the raise escaped untyped."""
        with self._sh(ls=(1, "", BoolBomb("boom"))):
            response = self._get()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed"
        )

    def test_bool_bomb_chmod_stderr_is_the_coded_failure_not_raw_500(self):
        """PUT: the owner-run chmod failure funnel read ``err or out or
        "failed"`` — the bomb raised out of the chain before _as_text.  Junk
        stderr degrades to the coded failure."""
        listing = _ls_listing(
            str(self.share_dir), " 1: user:alice allow read\n"
        )
        with self._sh(
            ls=(0, listing, ""),
            chmod=(1, "", BoolBomb("Operation not permitted")),
        ):
            response = self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "none",
                },
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_vanish_classification_still_works_beside_the_pick(self):
        """The _pick rewrite must not cost the confirmed-vanished 503."""
        with (
            self._sh(ls=(-1, "", "not found")),
            mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
        ):
            response = self._get()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_tool_missing"
        )


class ShareAclListingIterBombTests(_AppSandbox):
    """The gate's walk over list_smb_shares() was a bare ``for``."""

    def setUp(self):
        super().setUp()
        self.share_dir = self.root / "share"
        self.share_dir.mkdir()
        self.claim()
        self.sign_in()

    def _get_with_listing(self, listing, sharing_on_disk=True):
        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return 0, _ls_listing(str(self.share_dir)), ""
            return 1, "", ""

        with (
            mock.patch.object(
                shares_router.shares_svc, "list_smb_shares", return_value=listing
            ),
            mock.patch.object(
                shares_router.shares_svc,
                "_sharing_on_disk",
                return_value=sharing_on_disk,
            ),
            mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh),
        ):
            return self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )

    def test_iter_bomb_listing_is_the_coded_refusal_not_500(self):
        """A walk that cannot start collects nothing; with the sharing CLI
        still on disk that is the honest not-a-share refusal."""
        response = self._get_with_listing(
            IterBombList([{"path": str(self.share_dir)}])
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_not_share"
        )

    def test_iter_bomb_with_vanished_sharing_cli_is_the_coded_503(self):
        response = self._get_with_listing(
            IterBombList([{"path": str(self.share_dir)}]), sharing_on_disk=False
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.sharing_missing"
        )

    def test_mid_walk_death_keeps_the_share_points_already_collected(self):
        """The first row names the requested directory; the walk dying after
        it must not cost the match."""
        response = self._get_with_listing(
            _DiesAfterFirst([{"path": str(self.share_dir)}, {"path": "/x"}])
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["owner"], "a0000")


# ── GET /api/identity: subclass bombs in sh output and the config block ──────

class IdentitySubclassBombTests(_AppSandbox):
    def setUp(self):
        super().setUp()
        self.claim()
        self.sign_in()

    def _get(self, sh_result=(0, "host", ""), cfg_root=None):
        patches = [
            mock.patch.object(identity_svc, "sh", return_value=sh_result),
            mock.patch.object(identity_svc, "time_zone", return_value=""),
            mock.patch.object(identity_svc, "platform_string", return_value="mac"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value=""),
        ]
        if cfg_root is not None:
            patches.append(
                mock.patch.object(identity_svc, "cfg", return_value=cfg_root)
            )
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return self.client.get("/api/identity")

    def test_encode_bomb_sh_output_stays_200_scrubbed(self):
        response = self._get(sh_result=(0, EncodeBomb("h\ud800ost"), ""))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["hostname"], "h?ost")
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))

    def test_decode_bomb_bytes_sh_output_stays_200(self):
        response = self._get(sh_result=(0, DecodeBombBytes(b"host"), ""))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["hostname"], "host")

    def test_cfg_root_get_bomb_keeps_the_page_and_the_comment(self):
        """dict.get reads the real storage under the override, so the sane
        data a poisoned root still carries survives."""
        root = GetBombDict({"settings": {"server_comment": "the lab"}})
        response = self._get(cfg_root=root)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["comment"], "the lab")

    def test_settings_block_get_bomb_keeps_the_page_and_the_comment(self):
        settings = GetBombDict({"server_comment": "the lab"})
        response = self._get(cfg_root={"settings": settings})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["comment"], "the lab")

    def test_bool_bomb_comment_falls_through_to_the_description(self):
        """_pick, not ``or``: the bomb value is junk and the legacy
        ``description`` field must still answer."""
        response = self._get(
            cfg_root={
                "settings": {
                    "server_comment": BoolBomb("c"),
                    "description": "backup box",
                }
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["comment"], "backup box")

    def test_put_with_bool_bomb_scutil_stderr_stays_200_not_500(self):
        """set_identity's privileges message read ``err or out`` — the bomb
        raised out of the chain on the rename failure path."""
        with (
            mock.patch.object(
                identity_svc, "sh", return_value=(1, "", BoolBomb("denied"))
            ),
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            response = self.client.put(
                "/api/identity", json={"computer_name": "HomeLab"}
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["ok"])
        self.assertIn("administrator privileges", body["message"])


# ── GET /api/users: poisoned row fields must not cost healthy siblings ───────

_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
GOOD = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")


class UsersSiblingSurvivalTests(_AppSandbox):
    """The bound encode/decode in _pwd_text ate every row after the poison."""

    def _get_users(self, entries):
        self.claim()
        self.sign_in()
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            return self.client.get("/api/users")

    def test_encode_bomb_name_row_keeps_itself_and_its_siblings(self):
        bomb = _Pw(EncodeBomb("eve"), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertEqual(sorted(names), ["dave", "eve"])

    def test_surrogate_riding_the_bomb_is_scrubbed_not_leaked(self):
        bomb = _Pw(EncodeBomb("e\ud800ve"), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("e?ve", [u["name"] for u in body["users"]])
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))

    def test_decode_bomb_bytes_name_row_keeps_itself_and_its_siblings(self):
        bomb = _Pw(DecodeBombBytes(b"eve"), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertEqual(sorted(names), ["dave", "eve"])


if __name__ == "__main__":
    unittest.main()
