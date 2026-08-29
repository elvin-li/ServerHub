"""Users-page leftover sweep #5: dscl grants and the iterator-death gap.

Sweeps 1-4 hardened GET /api/users row-by-row (surrogates, over-cap
already-int uids, getpwall raising, an iterator dying *mid*-walk), the
panel-accounts CRUD, the 2FA store and the identity write path.  Driving the
same surfaces again through ``create_app()`` + ``TestClient
(raise_server_exceptions=False)`` found two live leftovers:

* **GET /api/users answered a raw 500 when the directory listing died at
  ``iter()``.**  ``list_users`` caught only TypeError around
  ``iter(entries)`` (a non-iterable getpwall result), but a directory-service
  handle that dies at the *start* of the walk raises OSError(EIO) from
  ``__iter__`` — one step earlier than the mid-iteration death the loop
  already tolerates — and that raise escaped as an unhandled 500 instead of
  the empty page every sibling failure already answers.

* **PUT /api/shares/acl blamed the picked user for a vanished dscl.**
  ``local_users`` degrades any dscl failure to ``[]`` (correct for the GET,
  whose picker just shows empty), but ``_validate_username`` then read the
  empty picker as "unknown local macOS user" — a coded 400 pointing the
  operator at a username that exists, while the actual failure is the CLI
  being gone.  Now: when the picker is empty AND a fresh on-disk probe of
  the exact dscl path the spawn used confirms the binary is gone (failure
  path only — a listed user never pays the stat), the grant answers the
  coded 503 ``shares.acl_tool_missing``.  An honestly empty picker with
  dscl still on disk keeps the honest 400, and a listed user proceeds
  without any probe.

Everything else probed was already immune and is pinned here at the HTTP
layer: attribute-level death of one pwd row costs only the rows after it,
an unhashable-str-subclass name is scrubbed before the dedupe set, a
``getgrouplist`` result that refuses iteration costs only the groups list,
a leftover FIFO occupying twofa.json or the audit trail neither hangs nor
500s the accounts routes, JSON ``Infinity``/``NaN`` literal bodies stay
coded 422s with renderable bodies, and a torn-IPv6 Host / Origin header on
an accounts write stays coded.
"""
from __future__ import annotations

import json
import os
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
#: >4300 digits: json.loads raises the digit-cap ValueError (not
#: JSONDecodeError) when converting the literal.
HUGE_LITERAL = "9" * 4400

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


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

    def raw_json(self, method: str, path: str, payload: str):
        return self.client.request(
            method,
            path,
            content=payload.encode("utf-8", "surrogatepass"),
            headers={"content-type": "application/json"},
        )


# ── GET /api/users: the iterator-death gap ───────────────────────────────────

_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
GOOD = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")


class _DiesAtIter:
    """getpwall result whose directory service dies at the start of the walk."""

    def __iter__(self):
        raise OSError(5, "EIO at iteration start")


class _ListDiesAtIter(list):
    """Same death, but on an object that still isinstance-checks as a list."""

    def __iter__(self):
        raise OSError(5, "EIO")


class _AttrBombRow:
    """pwd row whose name field raises when read (EIO on one OD record)."""

    pw_uid = 505
    pw_gid = 20
    pw_dir = "/"
    pw_shell = "/bin/zsh"
    pw_gecos = ""

    @property
    def pw_name(self):
        raise OSError(5, "EIO reading pw_name")


class _UnhashableName(str):
    """str subclass a poisoned OD binding could hand back for pw_name."""

    __hash__ = None


class _GidsRefuseIteration:
    """getgrouplist result that raises the moment it is walked."""

    def __iter__(self):
        raise OSError(5, "EIO")


class UsersIteratorDeathTests(_AppSandbox):
    """The live leftover: only TypeError was caught around ``iter(entries)``."""

    def _get_users(self, entries, gids=(20,)):
        self.claim()
        self.sign_in()
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=gids),
        ):
            return self.client.get("/api/users")

    def test_listing_that_dies_at_iter_is_the_empty_page_not_500(self):
        response = self._get_users(_DiesAtIter())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["users"], [])
        self.assertEqual(response.json()["count"], 0)

    def test_list_subclass_dying_at_iter_is_the_empty_page_not_500(self):
        """isinstance(list) passing does not make the walk safe."""
        response = self._get_users(_ListDiesAtIter([GOOD]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["users"], [])

    def test_attribute_death_keeps_the_rows_already_collected(self):
        """One record whose field read raises costs only itself and what
        follows — the mid-walk-death rule, at attribute rank."""
        response = self._get_users([GOOD, _AttrBombRow()])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_unhashable_name_subclass_is_scrubbed_not_500(self):
        """The dedupe set keys on (name, uid); ``_pwd_text`` must hand it a
        plain str even when pw_name arrives as an unhashable subclass."""
        poisoned = _Pw(_UnhashableName("eve"), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([poisoned, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertEqual(sorted(names), ["dave", "eve"])

    def test_getgrouplist_refusing_iteration_costs_only_the_groups(self):
        response = self._get_users([GOOD], gids=_GidsRefuseIteration())
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["name"] for u in rows], ["dave"])
        self.assertEqual(rows[0]["groups"], [])


# ── PUT /api/shares/acl: vanished dscl must not blame the user ───────────────

def _ls_listing(path: str) -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: group:everyone deny delete\n"
    )


class ShareAclVanishedDsclTests(_AppSandbox):
    """The second live leftover: 400 acl_bad_user for a gone CLI."""

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

    def _sh(self, dscl_list=(0, "", ""), realname=(1, "", "")):
        listing = _ls_listing(str(self.share_dir))

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.DSCL:
                if "-list" in argv:
                    return dscl_list
                return realname
            if argv[0] == share_acl_svc.LS:
                return 0, listing, ""
            return 0, "", ""

        return mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh)

    def _put(self, username="alice", level="read"):
        return self.client.put(
            "/api/shares/acl",
            json={"path": str(self.share_dir), "username": username, "level": level},
        )

    def test_vanished_dscl_is_the_coded_503_not_the_bad_user_lie(self):
        """sh's FileNotFoundError sentinel plus the binary really absent:
        the grant must answer 503 acl_tool_missing, not 400 acl_bad_user."""
        with (
            self._sh(dscl_list=(-1, "", "not found")),
            mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
        ):
            response = self._put()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_tool_missing"
        )

    def test_honestly_empty_picker_with_dscl_on_disk_keeps_the_400(self):
        """rc 0 with no human accounts (all uid<500 / _service) is a real
        "unknown user"; the still-present binary must keep the honest code."""
        with (
            self._sh(dscl_list=(0, "_spotlight 89\nroot 0\n", "")),
            mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=True),
        ):
            response = self._put()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_bad_user")

    def test_dscl_failure_with_binary_on_disk_keeps_the_400(self):
        """A plain dscl error (rc 1, no vanish shape) is not a vanished CLI."""
        with (
            self._sh(dscl_list=(1, "", "err")),
            mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=True),
        ):
            response = self._put()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_bad_user")

    def test_listed_user_never_pays_the_disk_probe(self):
        """Success path: alice is in the picker, the grant proceeds (level
        "none" with no entries is the no-op early return) and the fresh
        stat never runs."""
        with (
            self._sh(dscl_list=(0, "alice 501\n", "")),
            mock.patch.object(share_acl_svc, "_tool_on_disk") as probe,
        ):
            response = self._put(level="none")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        probe.assert_not_called()

    def test_get_acl_with_vanished_dscl_keeps_the_page_and_empties_the_picker(self):
        """The read side degrades, same rule as GET /api/identity: the ACL
        data is still served, only the picker is empty."""
        with (
            self._sh(dscl_list=(-1, "", "not found")),
            mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
        ):
            response = self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["users"], [])
        self.assertEqual(body["owner"], "a0000")
        self.assertEqual(len(body["entries"]), 1)


# ── stays-immune pins over the accounts routes ───────────────────────────────

class AccountsStoreFifoTests(_AppSandbox):
    """Leftover FIFOs on the stores the accounts routes read/write."""

    def setUp(self):
        super().setUp()
        self.claim()
        self.sign_in()

    def test_twofa_fifo_neither_hangs_nor_500s_the_listing(self):
        store = self.data / "twofa.json"
        os.mkfifo(store)
        self.addCleanup(store.unlink)
        response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        rows = {r["username"]: r for r in response.json()["accounts"]}
        self.assertFalse(rows["admin"]["twofa_enabled"])

    def test_twofa_invalid_utf8_reads_as_disabled_not_500(self):
        (self.data / "twofa.json").write_bytes(b"\xff\xfe not json")
        response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        rows = {r["username"]: r for r in response.json()["accounts"]}
        self.assertFalse(rows["admin"]["twofa_enabled"])

    def test_audit_fifo_neither_hangs_nor_loses_the_create(self):
        trail = self.data / "auth-audit.jsonl"
        # The sign-in above already wrote the trail; the FIFO replaces it.
        if trail.exists():
            trail.unlink()
        os.mkfifo(trail)
        self.addCleanup(trail.unlink)
        response = self.client.post(
            "/api/auth/accounts",
            json={"username": "aud1", "password": "aud1-password-12"},
        )
        self.assertEqual(response.status_code, 200)
        listing = self.client.get("/api/auth/accounts")
        self.assertIn(
            "aud1", [r["username"] for r in listing.json()["accounts"]]
        )


class AccountsBodyAndHeaderZooTests(_AppSandbox):
    """Junk that reaches the routes before any handler code."""

    def setUp(self):
        super().setUp()
        self.claim()
        self.sign_in()

    def test_json_infinity_and_nan_literals_stay_coded_422(self):
        """json.loads accepts Infinity/NaN; the body models must refuse them
        with a renderable detail, never hand them to the encoder."""
        for label, method, path, payload in (
            ("Infinity resource", "PUT", "/api/auth/accounts/kid/resources",
             '{"resources": [Infinity]}'),
            ("NaN username", "POST", "/api/auth/accounts",
             '{"username": NaN, "password": "x-password-12"}'),
        ):
            with self.subTest(body=label):
                response = self.raw_json(method, path, payload)
                self.assertEqual(response.status_code, 422)
                response.json()  # the detail body itself must stay renderable

    def test_huge_number_literal_body_stays_coded_400(self):
        """json.loads of the >4300-digit literal raises plain ValueError,
        not JSONDecodeError — still the coded body-parse 400."""
        response = self.raw_json(
            "POST", "/api/auth/accounts",
            '{"username": ' + HUGE_LITERAL + ', "password": "x-password-12"}',
        )
        self.assertEqual(response.status_code, 400)

    def test_torn_ipv6_host_header_does_not_500_an_accounts_write(self):
        response = self.client.post(
            "/api/auth/accounts",
            json={"username": "hh1", "password": "hh1-password-12"},
            headers={"host": "[::1"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["account"]["username"], "hh1")

    def test_torn_ipv6_origin_is_the_coded_cross_site_refusal(self):
        response = self.client.post(
            "/api/auth/accounts",
            json={"username": "hh2", "password": "hh2-password-12"},
            headers={"origin": "http://[::1", "host": "localhost"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json()["detail"]["code"], "auth.cross_site_denied"
        )

    def test_users_page_body_never_carries_a_lone_surrogate(self):
        """End-to-end UTF-8 pin over a fully poisoned row set."""
        poisoned = _Pw("e\ud800ve", "x", 501, 20, "G\ud800", "/U/\ud800", "/bin/z\ud800")
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[poisoned, GOOD]),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            response = self.client.get("/api/users")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(
            "\ud800", json.dumps(response.json(), ensure_ascii=False)
        )


if __name__ == "__main__":
    unittest.main()
