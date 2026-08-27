"""Users-page leftover sweep #11: ``sh``-answer unwrap bombs and rc liars.

Sweep 10/9 sealed the ``__class__``-property bombs and lying impostors in
the pwd/grp fields and the ACL text seams.  Driving GET /api/users and the
share-ACL routes again through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` found one whole *class* of
live leftovers this module had never met — the sequence-unwrap family its
vms10/network10 siblings already guard:

* **Every ``rc, out, err = sh(...)`` unpack in ``share_acl_svc`` dispatched
  into the answer's own iteration.**  A tuple-subclass whose bound
  ``__iter__`` bombs, a list-subclass whose ``__getitem__``/``__iter__``
  bombs, a lying ``__class__`` impostor claiming tuple over no real
  sequence storage, a wrong-arity tuple, or a bare ``None`` raised straight
  out of ``read_acl`` (raw 500 on GET and PUT /api/shares/acl before any
  gate ran), out of both dscl reads in ``local_users`` (raw 500 through the
  picker half of the GET), and out of ``_run_unprivileged`` (raw 500 on the
  PUT's owner-run path one line ahead of its failure funnel).  ``_sh3``
  now reads the real C-level storage: an honest answer inside a subclass
  wrapper survives untouched — the ``-1`` vanished-spawn sentinel included —
  while junk degrades to ``(-255, "", "")``, which is nonzero (a poisoned
  answer is not consent to claim success) and never the ``-1`` sentinel (an
  unusable answer cannot forge the vanished-CLI 503).

* **``_rc_int``'s bool arm ran a bool-liar's own ``__int__``.**  ``bool``
  is final, so a value that answers ``isinstance(rc, bool)`` without being
  one is a lying-``__class__`` impostor — and ``int(rc)`` dispatched into
  its override, so a liar answering ``0`` forged a *success* exit status
  for a spawn that never succeeded.  Identity checks (``rc is True`` /
  ``rc is False``) keep the two real singletons; everything else must carry
  real int storage or read as ``-255``.

The GET /api/users pins lock the already-immune walk against the same
wave's vectors (over-cap already-ints, lying sequence answers from the
directory seams, self-``__str__`` encode bombs), so a refactor cannot
quietly reopen them.
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


class Liar:
    """Lying ``__class__`` impostor: claims *claimed* with no real storage."""

    def __init__(self, claimed):
        self._claimed = claimed

    @property
    def __class__(self):
        return self._claimed

    def __str__(self):
        return "liar"


class BoolLiarZero:
    """Claims ``bool``; its own ``__int__`` answers 0 — a forged success."""

    @property
    def __class__(self):
        return bool

    def __int__(self):
        return 0


class IterBombTuple(tuple):
    """Honest 3-tuple storage underneath a bound ``__iter__`` bomb."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class IterBombList(list):
    """Honest list storage underneath bound ``__iter__``/``__getitem__`` bombs."""

    def __getitem__(self, item):
        raise RuntimeError("getitem bomb")

    def __iter__(self):
        raise RuntimeError("iter bomb")


class EqBombInt(int):
    """Real int storage; the comparison operators are bombs."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class IndexBombInt(int):
    """Real int storage; the bound coercion hooks are bombs."""

    def __index__(self):
        raise RuntimeError("index bomb")

    def __int__(self):
        raise RuntimeError("int bomb")

    def __float__(self):
        raise RuntimeError("float bomb")


class SelfStr(str):
    """``str(x)`` answers *self*, so a bound ``.encode`` bomb stays live."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


#: Past CPython's int->str digit cap; built arithmetically because the
#: parse-time cap refuses the literal form.
HUGE_INT = 10 ** 5000


# ── unit pins: _sh3 / _rc_int ────────────────────────────────────────────────


class Sh3UnitTests(unittest.TestCase):
    def test_honest_answers_pass_through_untouched(self):
        self.assertEqual(share_acl_svc._sh3((0, "out", "err")), (0, "out", "err"))
        # The vanished-spawn sentinel must survive so the confirmed-vanished
        # 503 classification (marker + fresh disk probe) still works.
        self.assertEqual(
            share_acl_svc._sh3((-1, "", "not found")), (-1, "", "not found")
        )

    def test_subclass_wrappers_answer_their_real_storage(self):
        self.assertEqual(
            share_acl_svc._sh3(IterBombTuple((0, "out", "err"))), (0, "out", "err")
        )
        self.assertEqual(
            share_acl_svc._sh3(IterBombList([1, "o", "e"])), (1, "o", "e")
        )

    def test_junk_degrades_to_minus_255_never_the_sentinel(self):
        for junk in (
            Liar(tuple),
            Liar(list),
            None,
            "junk",
            (0, "only-two"),
            (0, "a", "b", "c"),
        ):
            self.assertEqual(share_acl_svc._sh3(junk), (-255, "", ""))

    def test_rc_int_keeps_the_real_bool_singletons(self):
        self.assertEqual(share_acl_svc._rc_int(True), 1)
        self.assertEqual(share_acl_svc._rc_int(False), 0)

    def test_rc_int_bool_liar_cannot_forge_success(self):
        """The live leftover: ``isinstance(rc, bool)`` passed the liar and
        ``int(rc)`` ran its own ``__int__`` — a forged 0 read as success."""
        self.assertEqual(share_acl_svc._rc_int(BoolLiarZero()), -255)

    def test_rc_int_reads_storage_under_subclass_bombs(self):
        self.assertEqual(share_acl_svc._rc_int(EqBombInt(1)), 1)
        self.assertEqual(share_acl_svc._rc_int(IndexBombInt(0)), 0)

    def test_rc_int_overcap_int_is_junk(self):
        self.assertEqual(share_acl_svc._rc_int(HUGE_INT), -255)

    def test_rc_int_int_liar_is_junk(self):
        self.assertEqual(share_acl_svc._rc_int(Liar(int)), -255)


# ── app sandbox ──────────────────────────────────────────────────────────────


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


# ── GET/PUT /api/shares/acl: unwrap bombs on every sh seam ───────────────────


def _ls_listing(path: str) -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: user:alice allow read\n"
    )


class ShareAclUnwrapTests(_AppSandbox):
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

    _UNSET = object()

    def _fake_sh(self, ls=_UNSET, dscl=_UNSET, dscl_read=_UNSET, chmod=_UNSET):
        # A sentinel default, not ``None``: bare ``None`` is itself one of
        # the junk answers under test.
        unset = self._UNSET
        listing = _ls_listing(str(self.share_dir))
        answers = {
            "ls": ls if ls is not unset else (0, listing, ""),
            "dscl": dscl if dscl is not unset else (0, "alice 501\n", ""),
            "dscl_read": dscl_read if dscl_read is not unset else (0, "RealName: Alice\n", ""),
            "chmod": chmod if chmod is not unset else (0, "", ""),
        }

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return answers["ls"]
            if argv[0] == share_acl_svc.DSCL and "-list" in argv:
                return answers["dscl"]
            if argv[0] == share_acl_svc.DSCL:
                return answers["dscl_read"]
            if argv[0] == share_acl_svc.CHMOD:
                return answers["chmod"]
            return (1, "", "")

        return fake_sh

    def _get(self, **answers):
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(**answers)
        ):
            return self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )

    def test_iter_bomb_ls_answer_serves_its_honest_storage(self):
        """The live leftover: ``rc, output, error = sh(...)`` in read_acl
        dispatched into the wrapper's own ``__iter__`` — a raw 500 on GET
        /api/shares/acl before any gate ran.  The honest 3-tuple underneath
        now answers the page."""
        listing = _ls_listing(str(self.share_dir))
        response = self._get(ls=IterBombTuple((0, listing, "")))
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice", [e["name"] for e in response.json()["entries"]])

    def test_getitem_bomb_list_ls_answer_serves_its_honest_storage(self):
        listing = _ls_listing(str(self.share_dir))
        response = self._get(ls=IterBombList([0, listing, ""]))
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice", [e["name"] for e in response.json()["entries"]])

    def test_junk_ls_answers_are_the_coded_read_failure(self):
        """A tuple-liar / wrong-arity / None answer used to blow the unpack
        as a raw uncoded 500; junk now reads as the coded read failure."""
        for junk in (Liar(tuple), (0, "only-two"), None):
            response = self._get(ls=junk)
            self.assertEqual(response.status_code, 500)
            self.assertEqual(
                response.json()["detail"]["code"], "shares.acl_read_failed"
            )

    def test_iter_bomb_dscl_answer_keeps_the_picker(self):
        """The same unpack in local_users used to 500 the whole GET; the
        honest storage underneath now still fills the picker."""
        response = self._get(dscl=IterBombTuple((0, "alice 501\n", "")))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("alice", [u["username"] for u in payload["users"]])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])

    def test_junk_dscl_answer_degrades_to_the_empty_picker(self):
        """Junk with no honest storage empties the picker only — the ACL
        half of the payload still answers."""
        response = self._get(dscl=(0, "x"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["users"], [])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])

    def test_iter_bomb_realname_answer_keeps_the_picker_row(self):
        """One poisoned per-user RealName answer used to cost the whole
        picker as a raw 500; its honest storage now answers the row."""
        response = self._get(dscl_read=IterBombTuple((0, "RealName: Alice\n", "")))
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["username"] for u in rows], ["alice"])
        self.assertEqual(rows[0]["real_name"], "Alice")

    def test_junk_realname_answer_costs_the_real_name_only(self):
        response = self._get(dscl_read=Liar(tuple))
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["username"] for u in rows], ["alice"])
        self.assertEqual(rows[0]["real_name"], "")

    def test_bool_liar_rc_is_the_coded_read_failure_not_success(self):
        """A bool-liar rc whose ``__int__`` answers 0 used to forge a
        successful ls; junk now reads as failure — the coded refusal."""
        listing = _ls_listing(str(self.share_dir))
        response = self._get(ls=(BoolLiarZero(), listing, ""))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed"
        )

    def test_overcap_int_rc_is_the_coded_read_failure(self):
        """An over-cap already-int rc (YAML/plist hex loads dodge the parse
        cap) cannot be rendered by any encoder — junk, reads as failure."""
        listing = _ls_listing(str(self.share_dir))
        response = self._get(ls=(HUGE_INT, listing, ""))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed"
        )

    # ── PUT owner-run path: the _run_unprivileged unpack ─────────────────────

    def _put(self, **answers):
        # The scratch share directory is owned by this process, so the PUT
        # takes the owner-run path straight into _run_unprivileged.
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(**answers)
        ):
            return self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "readwrite",
                },
            )

    def test_iter_bomb_chmod_answer_keeps_the_coded_outcome(self):
        """The live leftover: the unpack in _run_unprivileged blew one line
        ahead of the failure funnel — a raw 500 on PUT /api/shares/acl.  The
        honest success underneath now rides to the read-back verification,
        whose 409 is the coded answer for a listing that never changed."""
        response = self._put(chmod=IterBombTuple((0, "", "")))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.verification_failed"
        )

    def test_junk_chmod_answer_is_the_coded_failure_never_success(self):
        response = self._put(chmod=Liar(tuple))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_junk_chmod_answer_cannot_forge_the_vanished_cli_503(self):
        """-255 is never the -1 spawn sentinel and carries no marker text,
        so a poisoned answer cannot mint the acl_tool_missing 503."""
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._put(chmod=(None,))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_honest_vanished_chmod_still_earns_the_coded_503(self):
        """The seal must not cost the confirmed-vanished classification:
        the -1 sentinel plus the marker plus the fresh disk probe."""
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._put(chmod=(-1, "", "not found"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_tool_missing"
        )


# ── GET /api/users: stays-immune pins against the same wave ─────────────────

_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
_Gr = namedtuple("Gr", "gr_name gr_passwd gr_gid gr_mem")
GOOD = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")


class UsersStaysImmuneTests(_AppSandbox):
    def _get_users(self, entries, getgrouplist=None):
        self.claim_and_sign_in()
        gl = getgrouplist if getgrouplist is not None else [20]
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=gl),
        ):
            return self.client.get("/api/users")

    def test_overcap_already_int_uid_costs_its_row_only(self):
        """An already-int uid past the digit cap sails through int() and
        would only explode at the encoder; the str() probe drops the row."""
        bomb = _Pw("eve", "x", HUGE_INT, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_coercion_bomb_int_subclass_uid_costs_its_row_only(self):
        """int() of an int subclass dispatches into a bound ``__int__``
        bomb; the broad per-row catch drops the poisoned row and keeps the
        healthy sibling — never a 500."""
        bomb = _Pw("eve", "x", IndexBombInt(501), 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_eq_bomb_int_subclass_uid_renders_its_storage(self):
        """A comparison-bomb uid whose coercions are honest renders through
        the exact-int copy; the ``uid < 500`` probes never run the bombs."""
        bomb = _Pw("eve", "x", EqBombInt(501), 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertEqual(sorted(names), ["dave", "eve"])

    def test_bool_liar_uid_costs_its_row_only(self):
        bomb = _Pw("eve", "x", Liar(bool), 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [u["name"] for u in response.json()["users"]], ["dave"]
        )

    def test_selfstr_encode_bomb_name_renders_and_keeps_the_sibling(self):
        """``str()`` of a self-``__str__`` subclass keeps the subclass, so
        only the unbound ``str.encode`` rank keeps the bomb dormant."""
        bomb = _Pw(SelfStr("eve"), "x", 501, 20, "", "/", "/bin/zsh")
        response = self._get_users([bomb, GOOD])
        self.assertEqual(response.status_code, 200)
        names = [u["name"] for u in response.json()["users"]]
        self.assertEqual(sorted(names), ["dave", "eve"])

    def test_tuple_liar_getpwall_answer_is_the_empty_page(self):
        response = self._get_users(Liar(tuple))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["users"], [])

    def test_iter_bomb_getpwall_answer_is_the_empty_page(self):
        response = self._get_users(IterBombTuple([GOOD]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["users"], [])

    def test_list_liar_grouplist_costs_the_groups_only(self):
        response = self._get_users([GOOD], getgrouplist=Liar(list))
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["name"] for u in rows], ["dave"])
        self.assertEqual(rows[0]["groups"], [])

    def test_iter_bomb_grouplist_costs_the_groups_only(self):
        response = self._get_users([GOOD], getgrouplist=IterBombList([20]))
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["name"] for u in rows], ["dave"])
        self.assertEqual(rows[0]["groups"], [])


if __name__ == "__main__":
    unittest.main()
