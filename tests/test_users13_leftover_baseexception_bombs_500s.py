"""Users-page leftover sweep #13: BaseException-shaped bombs past ``except Exception``.

Sweep 12 sealed the raising-runner and raising-admin seams: every spawn rides
``_sh_call`` and both escalation seams ride ``_admin_sequence``.  Driving GET
and PUT /api/shares/acl again through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` found the class one exception
rank *over* all of that — every guard in ``hub.share_acl_svc`` stopped at
``except Exception``, so a leftover whose hooks raise a *BaseException*
subclass (the watchdog/timeout shape the modules12/jobs13/apps13 sweeps
sealed on their own surfaces) sailed past every catch at once:

* a runner raising a BaseException subclass blew ``_sh_call`` past the
  users12 guard built for it — raw detonations out of ``read_acl`` (GET and
  PUT before any gate ran), both dscl reads in ``local_users`` (one bombed
  per-user RealName read cost the whole picker) and ``_run_unprivileged``
  (the PUT's owner-run path one line ahead of its failure funnel);
* the same shape out of ``run_admin_sequence`` blew ``_admin_sequence`` on
  both escalation seams in place of the coded authorization failure;
* a ``__class__``-property bomb raising a BaseException subclass blew
  ``_isa`` — the gate every sanitizer arm in this module stands on — and
  ``_rc_int``'s bare isinstance probes; ``__bool__`` / ``__str__`` /
  ``__int__`` bombs blew ``_truthy`` / ``_pick`` / ``_as_text`` /
  ``_rc_int``; a result subclass whose ``keys()`` / ``__iter__`` raises the
  same shape took ``dict()``'s slow path past ``_plain_result``'s net.
* Decode fidelity (the jobs13/modules12/apps13 both-bases rule): the
  claimed-base decode handed a genuine ``bytearray`` whose ``__class__``
  lied ``bytes`` to ``bytes.decode``, the descriptor rejected it, and the
  perfectly decodable ls text fell to the str() rank — a ``bytearray(b'…')``
  repr where the honest listing should have parsed.

The fixes follow the module-local ``_CONTROL_FLOW`` convention: every guard
re-raises KeyboardInterrupt / SystemExit and launders everything else
BaseException-shaped exactly like its Exception twin — swallowing a Ctrl-C
to save one JSON field would turn the sanitizer into a hang, so control
flow is pinned propagating.  The stronger users11/users12 union guards are
kept and pinned: junk never reads as success, never the ``-1`` spawn
sentinel, and can never mint the disk-confirmed vanished-CLI 503; honest
answers — the ``-1`` sentinel, ``cancelled`` shapes — ride untouched.
No new error codes; product version stays 3.9.3.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import auth, share_acl_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402
from hub.routers import shares as shares_router  # noqa: E402

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        # The routers mount behind require_auth; the browser-session and
        # admin reads inside the routes are stubbed per-test instead.
        _APP.dependency_overrides[require_auth] = lambda: None
    return _APP


# ─── leftover zoo ─────────────────────────────────────────────────────────────


class LeftoverBaseBomb(BaseException):
    """BaseException-shaped, but *not* control flow — a bomb like any other."""


def _boom(*args, **kwargs):
    raise LeftoverBaseBomb("leftover base bomb")


def _base_raising_property():
    return property(lambda self: (_ for _ in ()).throw(LeftoverBaseBomb("class base bomb")))


class _ClassPropBaseBomb:
    """``__class__`` property raising a BaseException subclass — blew ``_isa``
    itself, the gate every sanitizer arm stands on, and ``_rc_int``'s bare
    isinstance probes."""

    __class__ = _base_raising_property()

    def __str__(self):
        return "still-renderable"


class _BoolBaseBomb:
    """A stderr slot whose ``__bool__`` raises a BaseException subclass —
    detonated ``_pick``'s truth test on the read-failure funnel."""

    def __bool__(self):
        raise LeftoverBaseBomb("bool base bomb")


class _StrBaseBomb:
    """A field whose ``__str__`` raises a BaseException subclass."""

    def __str__(self):
        raise LeftoverBaseBomb("str base bomb")


class _IntBaseBomb:
    """An rc slot whose ``__int__`` raises a BaseException subclass."""

    def __int__(self):
        raise LeftoverBaseBomb("int base bomb")


class _RcClassBaseBomb(int):
    """An rc whose ``__class__`` property raises a BaseException subclass:
    the bare isinstance probes inside ``_rc_int`` read the property."""

    __class__ = _base_raising_property()


class _KeysBaseBombResult(dict):
    """An admin result whose ``keys()``/``__iter__`` raise a BaseException
    subclass: ``dict(result)`` takes the slow path into the bomb, past
    ``_plain_result``'s Exception-shaped net."""

    def keys(self):
        raise LeftoverBaseBomb("keys base bomb")

    def __iter__(self):
        raise LeftoverBaseBomb("iter base bomb")


class _LyingBytesArray(bytearray):
    """A genuine ``bytearray`` whose ``__class__`` lies ``bytes``: the
    claimed-base decode handed it to ``bytes.decode``, the descriptor
    rejected it, and the honest ls text degraded to a ``bytearray(b'…')``
    repr instead of parsing."""

    __class__ = property(lambda self: bytes)


# ─── unit pins: every guard launders the BaseException rank, control flow rides ──


class GuardRankUnitTests(unittest.TestCase):
    def test_isa_survives_a_baseexception_class_property(self):
        self.assertFalse(share_acl_svc._isa(_ClassPropBaseBomb(), dict))

    def test_truthy_survives_a_baseexception_bool_bomb(self):
        self.assertFalse(share_acl_svc._truthy(_BoolBaseBomb()))

    def test_pick_falls_back_past_a_baseexception_bool_bomb(self):
        self.assertEqual(share_acl_svc._pick(_BoolBaseBomb(), "fallback"), "fallback")

    def test_as_text_scrubs_a_baseexception_str_bomb_to_empty(self):
        self.assertEqual(share_acl_svc._as_text(_StrBaseBomb()), "")

    def test_as_text_survives_a_baseexception_class_property(self):
        self.assertEqual(share_acl_svc._as_text(_ClassPropBaseBomb()), "still-renderable")

    def test_as_text_keeps_honest_content_of_a_lying_bytearray(self):
        """The both-bases first-come decode rule: a genuine bytearray whose
        __class__ lies bytes keeps its decodable text instead of degrading
        to its repr."""
        self.assertEqual(
            share_acl_svc._as_text(_LyingBytesArray(b"honest listing")),
            "honest listing",
        )

    def test_rc_int_reads_baseexception_bombs_as_junk(self):
        self.assertEqual(share_acl_svc._rc_int(_RcClassBaseBomb()), -255)
        self.assertEqual(share_acl_svc._rc_int(_IntBaseBomb()), -255)

    def test_plain_result_reads_a_keys_bombed_subclass_as_the_coded_failure(self):
        self.assertEqual(
            share_acl_svc._plain_result(_KeysBaseBombResult(ok=True)),
            {"ok": False, "error": "failed"},
        )

    def test_sh_call_reads_a_baseexception_runner_as_junk_never_the_sentinel(self):
        with mock.patch.object(share_acl_svc, "sh", side_effect=_boom):
            self.assertEqual(
                share_acl_svc._sh_call(["/bin/ls"], timeout=1), (-255, "", "")
            )

    def test_sh_call_keeps_the_honest_sentinel_untouched(self):
        """users12 pin, kept: the -1 vanished-spawn sentinel must survive so
        the disk-confirmed 503 classification still works."""
        with mock.patch.object(share_acl_svc, "sh", return_value=(-1, "", "not found")):
            self.assertEqual(
                share_acl_svc._sh_call(["/bin/ls"], timeout=1), (-1, "", "not found")
            )

    def test_admin_sequence_reads_a_baseexception_helper_as_the_coded_failure(self):
        with mock.patch.object(
            share_acl_svc.macos_admin, "run_admin_sequence", side_effect=_boom
        ):
            self.assertEqual(
                share_acl_svc._admin_sequence([["/bin/chmod"]]),
                {"ok": False, "error": "failed"},
            )

    def test_admin_sequence_keeps_honest_cancelled_shapes(self):
        """users12 pin, kept: guarding the rank must not flatten refusals."""
        with mock.patch.object(
            share_acl_svc.macos_admin,
            "run_admin_sequence",
            return_value={"ok": False, "error": "cancelled"},
        ):
            self.assertEqual(
                share_acl_svc._admin_sequence([["/bin/chmod"]]),
                {"ok": False, "error": "cancelled"},
            )


class ControlFlowStillPropagatesTests(unittest.TestCase):
    """Swallowing a Ctrl-C to save one JSON field would turn the sanitizer
    into a hang: genuine control flow must keep riding through every guard."""

    def test_sh_call_reraises_keyboard_interrupt(self):
        with mock.patch.object(share_acl_svc, "sh", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                share_acl_svc._sh_call(["/bin/ls"], timeout=1)

    def test_admin_sequence_reraises_system_exit(self):
        with mock.patch.object(
            share_acl_svc.macos_admin, "run_admin_sequence", side_effect=SystemExit
        ):
            with self.assertRaises(SystemExit):
                share_acl_svc._admin_sequence([["/bin/chmod"]])

    def test_truthy_reraises_keyboard_interrupt(self):
        class _CtrlC:
            def __bool__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            share_acl_svc._truthy(_CtrlC())

    def test_isa_reraises_keyboard_interrupt(self):
        class _CtrlCClass:
            __class__ = property(
                lambda self: (_ for _ in ()).throw(KeyboardInterrupt())
            )

        with self.assertRaises(KeyboardInterrupt):
            share_acl_svc._isa(_CtrlCClass(), dict)


# ─── route sandbox: signed-in admin without touching real panel state ─────────


def _ls_listing(path: str) -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: user:alice allow read\n"
    )


class _RouteSandbox(unittest.TestCase):
    """A scratch share directory and an authenticated admin, hermetically:
    the auth reads and the audit sink are stubbed at the router's own seams,
    so no panel state file is ever touched."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.share_dir = Path(tmp.name) / "share"
        self.share_dir.mkdir()
        for target, attr, value in (
            (auth, "browser_authenticated", lambda request: True),
            (auth, "request_username", lambda request: "admin"),
            (auth, "is_admin", lambda username: True),
            (auth, "request_client_id", lambda request: "tests"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        audit_patch = mock.patch.object(shares_router.audit, "record")
        audit_patch.start()
        self.addCleanup(audit_patch.stop)
        listing_patch = mock.patch.object(
            shares_router.shares_svc,
            "list_smb_shares",
            return_value=[{"path": str(self.share_dir)}],
        )
        listing_patch.start()
        self.addCleanup(listing_patch.stop)
        self.client = TestClient(app(), raise_server_exceptions=False)

    def _fake_sh(self, raising=(), answers=None):
        """An ``sh`` stub whose named seams raise the BaseException bomb."""
        overrides = dict(answers or {})
        table = {
            "ls": (0, _ls_listing(str(self.share_dir)), ""),
            "dscl": (0, "alice 501\n", ""),
            "dscl_read": (0, "RealName: Alice\n", ""),
            "chmod": (0, "", ""),
        }
        table.update(overrides)

        def seam(argv):
            if argv[0] == share_acl_svc.LS:
                return "ls"
            if argv[0] == share_acl_svc.DSCL and "-list" in argv:
                return "dscl"
            if argv[0] == share_acl_svc.DSCL:
                return "dscl_read"
            if argv[0] == share_acl_svc.CHMOD:
                return "chmod"
            return ""

        def fake_sh(argv, timeout=0, **kwargs):
            name = seam(argv)
            if name in raising:
                raise LeftoverBaseBomb(f"raising {name} leftover")
            return table.get(name, (1, "", ""))

        return fake_sh

    def _get(self, raising=(), answers=None):
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(raising, answers)
        ):
            return self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )

    def _put(self, raising=(), answers=None):
        # The scratch share directory is owned by this process, so the PUT
        # takes the owner-run path straight into _run_unprivileged.
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(raising, answers)
        ):
            return self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "readwrite",
                },
            )


# ─── GET /api/shares/acl: BaseException bombs at every spawn seam ─────────────


class ShareAclGetBaseBombTests(_RouteSandbox):
    def test_base_raising_ls_is_the_coded_read_failure_not_a_raw_detonation(self):
        """The live leftover: a runner raising a BaseException subclass blew
        read_acl past the users12 guard — an uncoded detonation on GET
        /api/shares/acl before any gate ran."""
        response = self._get(raising={"ls"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_base_raising_ls_cannot_forge_the_vanished_cli_503(self):
        """A bombed runner carries no marker text and never the -1 sentinel,
        so it cannot mint acl_tool_missing even with the tool honestly gone."""
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._get(raising={"ls"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_base_raising_dscl_list_degrades_to_the_empty_picker(self):
        """The same bomb out of local_users used to detonate the whole GET;
        it now costs the picker only — the ACL half still answers."""
        response = self._get(raising={"dscl"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["users"], [])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])

    def test_base_raising_realname_read_costs_the_real_name_only(self):
        response = self._get(raising={"dscl_read"})
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["username"] for u in rows], ["alice"])
        self.assertEqual(rows[0]["real_name"], "")

    def test_bool_base_bomb_stderr_keeps_the_coded_read_failure(self):
        """A failed ls whose stderr slot is a ``__bool__`` BaseException bomb
        used to detonate _pick's truth test on the failure funnel itself."""
        response = self._get(answers={"ls": (1, "", _BoolBaseBomb())})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_rc_class_base_bomb_keeps_the_coded_read_failure(self):
        """An rc whose ``__class__`` property raises a BaseException subclass
        used to blow _rc_int's bare isinstance probes out of the ``!= 0``
        gate itself."""
        listing = _ls_listing(str(self.share_dir))
        response = self._get(answers={"ls": (_RcClassBaseBomb(), listing, "")})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_lying_bytearray_listing_keeps_its_honest_entries(self):
        """Decode fidelity through the route: a genuine bytearray ls answer
        whose ``__class__`` lies bytes parses as the honest listing instead
        of degrading to its repr and answering the read failure."""
        listing = _LyingBytesArray(_ls_listing(str(self.share_dir)).encode())
        response = self._get(answers={"ls": (0, listing, "")})
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice", [e["name"] for e in response.json()["entries"]])

    def test_clean_spawn_chain_still_answers_the_page(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("alice", [u["username"] for u in payload["users"]])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])


# ─── PUT /api/shares/acl: BaseException bombs on the write path ───────────────


class ShareAclPutBaseBombTests(_RouteSandbox):
    def test_base_raising_chmod_is_the_coded_failure_never_success(self):
        """The live leftover: a runner raising a BaseException subclass blew
        _run_unprivileged past the users12 guard, one line ahead of its
        failure funnel."""
        response = self._put(raising={"chmod"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_base_raising_chmod_cannot_forge_the_vanished_cli_503(self):
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._put(raising={"chmod"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_honest_vanished_chmod_still_earns_the_coded_503(self):
        """users12 pin, kept: the -1 sentinel plus the marker plus the fresh
        disk probe still classify the confirmed-vanished CLI."""
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._put(answers={"chmod": (-1, "", "not found")})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_tool_missing")

    def _put_needs_root(self, admin):
        """Drive the owner needs-root retry into the admin helper *admin*."""
        refused = {"chmod": (1, "", "chmod: Operation not permitted")}
        with mock.patch.object(
            share_acl_svc.macos_admin, "run_admin_sequence", admin
        ):
            return self._put(answers=refused)

    def test_base_raising_admin_helper_is_the_coded_failure(self):
        """The live leftover: a helper raising a BaseException subclass blew
        the escalation seam past the users12 _admin_sequence guard."""
        response = self._put_needs_root(mock.Mock(side_effect=_boom))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_keys_bombed_admin_answer_is_the_coded_failure(self):
        """An answer subclass whose keys()/__iter__ raise a BaseException
        subclass took dict()'s slow path into the bomb past _plain_result's
        Exception-shaped net."""
        response = self._put_needs_root(
            mock.Mock(return_value=_KeysBaseBombResult(ok=True))
        )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_honest_cancelled_admin_answer_keeps_its_coded_409(self):
        """users12 pin, kept: guarding the rank must not flatten honest
        refusals — a cancelled authorization still answers its own shape."""
        response = self._put_needs_root(
            mock.Mock(return_value={"ok": False, "error": "cancelled"})
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled"
        )

    def test_clean_write_chain_still_answers_the_grant(self):
        listing_after = (
            f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {self.share_dir}\n"
            " 0: user:alice allow read,write,delete\n"
        )
        response = self._put(answers={"ls": (0, listing_after, "")})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])


if __name__ == "__main__":
    unittest.main()
