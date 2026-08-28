"""Users-page leftover sweep #14: repr heap-address leaks and wrong-rank degrades.

Sweep 13 sealed the BaseException-shaped bombs: every guard in
``hub.share_acl_svc`` launders that rank and re-raises only genuine control
flow.  Driving GET and PUT /api/shares/acl again through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` found the next class one arm
over, both inside ``_as_text``'s free-text coercion:

* **Default ``object.__repr__`` heap-address leaks** (the
  bookmarks/assistant/files13 address-leak rule): ``_as_text`` ran ``str()``
  on any leftover shape, and for a type that never overrode
  ``__str__``/``__repr__`` the answer is ``<X object at 0x7f...>`` — a raw
  heap address.  A junk ``ls`` answer carried it verbatim into the GET
  /api/shares/acl body (``parse_acl_listing`` split the repr into the
  mode/owner/group header, so the ``group`` field answered ``0x7f...>``),
  and a junk per-user RealName read carried the full repr into every picker
  row's ``real_name``.  A slot probe on the real ``type(value)`` now refuses
  the default-render shape, and a regex belt catches what the probe cannot
  see (C-level ``__repr__`` overrides and renderings that embed a default
  repr).  Only the coercion arm is scrubbed — real str/bytes storage is
  data and stays verbatim.

* **Wrong-rank degrade for honest str storage behind a lying-bytes
  ``__class__``** (the files13/notify13/logs13 recover-the-real-storage
  rule): the bytes gate matches through the *lie*, both base decodes reject
  the str layout, and the old flow fell to the *dispatching* ``str(value)``
  — so a bombed ``__str__`` vanished the perfectly readable text to ``""``.
  GET /api/shares/acl answered the coded read failure where the honest
  listing should have parsed, and a legible coded ``error`` ("cancelled")
  on PUT degraded to the generic authorization failure in place of its own
  409.  Real str storage now reads through the unbound ``str.encode`` no
  matter what the claim says.

The stronger users9..13 guards are kept and pinned: a legible impostor
(``__str__`` override) still renders, a genuine bytearray lying ``bytes``
still decodes first-come, exact str storage — address-shaped text included
— stays verbatim, and self-rendering types (Path, int) keep coercing.
No new error codes; product version stays 3.9.3.

The other hinted classes were hunted and found already sealed on this
surface: every container walk snapshots or launders before iterating
(``_sh3``'s unbound tuple/list snapshots, ``_plain_result``'s ``dict()``
copy, the router walk's mid-iteration catch), and the GET/PUT payloads
reach ``_jsonable`` fully laundered.
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


class _DefaultRenderJunk:
    """Never overrode ``__str__``/``__repr__``: coercion answers the default
    ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap address."""


class _EmbeddedReprJunk:
    """A rendering that *embeds* a default repr: the slot probe passes (the
    type renders itself) so only the regex belt can catch the address."""

    def __str__(self):
        return f"{{'inner': {object.__repr__(self)}}}"


class _LyingStrBombed(str):
    """Genuine str storage; ``__class__`` lies ``bytes``; bound ``__str__``
    raises.  The claimed arm rejects the real layout (both base decodes
    TypeError) and the old dispatching ``str()`` rank detonated — the honest
    text vanished at the wrong rank."""

    __class__ = property(lambda self: bytes)

    def __str__(self):
        raise RuntimeError("leftover str bomb")


class _LyingBytesClaimingStr(bytes):
    """Genuine bytes storage whose ``__class__`` lies ``str``: the real-type
    gate wins before the lie is consulted, so the decode arm keeps it."""

    __class__ = property(lambda self: str)


class _LegibleBytesImpostor:
    """Claims bytes over no byte storage but renders itself: the users9
    legible-impostor pin — it must keep rendering through the coercion arm."""

    @property
    def __class__(self):
        return bytes

    def __str__(self):
        return "legible impostor"


# ─── unit pins: the coercion arm cannot leak an address, real storage recovers ──


class AsTextUnitTests(unittest.TestCase):
    def test_default_render_junk_reads_as_empty_never_an_address(self):
        """The live leftover: the coercion arm answered the default
        ``object.__repr__`` — a raw heap address."""
        self.assertEqual(share_acl_svc._as_text(_DefaultRenderJunk()), "")

    def test_embedded_default_repr_is_belt_scrubbed(self):
        """The slot probe passes (the type renders itself); the regex belt
        must still refuse the embedded heap address."""
        self.assertEqual(share_acl_svc._as_text(_EmbeddedReprJunk()), "")

    def test_lying_str_with_a_bombed_str_keeps_its_real_storage(self):
        """The live leftover: the claimed (bytes) arm rejected the real str
        layout and the dispatching ``str()`` vanished the honest text."""
        self.assertEqual(
            share_acl_svc._as_text(_LyingStrBombed("honest listing")),
            "honest listing",
        )

    def test_exact_str_storage_stays_verbatim_address_shape_included(self):
        """Real str storage is data, never belt-scrubbed: an ls line may
        legitimately contain the angle-repr pattern."""
        line = "weird file at 0x1f> name"
        self.assertEqual(share_acl_svc._as_text(line), line)

    def test_genuine_bytes_claiming_str_still_decodes(self):
        """The other lying direction: real bytes storage wins the decode arm
        through the real-type gate before the lie is consulted."""
        self.assertEqual(
            share_acl_svc._as_text(_LyingBytesClaimingStr(b"honest bytes")),
            "honest bytes",
        )

    def test_legible_impostor_still_renders(self):
        """users9 pin, kept: a total impostor with a ``__str__`` override
        keeps rendering through the coercion arm."""
        self.assertEqual(
            share_acl_svc._as_text(_LegibleBytesImpostor()), "legible impostor"
        )

    def test_self_rendering_types_keep_coercing(self):
        """The slot probe refuses only default-render shapes: Path and int
        overrode their renderers and must keep answering."""
        self.assertEqual(share_acl_svc._as_text(Path("/tmp/share")), "/tmp/share")
        self.assertEqual(share_acl_svc._as_text(123), "123")
        self.assertEqual(share_acl_svc._as_text(None), "")


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

    def _fake_sh(self, answers=None):
        table = {
            "ls": (0, _ls_listing(str(self.share_dir)), ""),
            "dscl": (0, "alice 501\n", ""),
            "dscl_read": (0, "RealName: Alice\n", ""),
            "chmod": (0, "", ""),
        }
        table.update(answers or {})

        def fake_sh(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.LS:
                return table["ls"]
            if argv[0] == share_acl_svc.DSCL and "-list" in argv:
                return table["dscl"]
            if argv[0] == share_acl_svc.DSCL:
                return table["dscl_read"]
            if argv[0] == share_acl_svc.CHMOD:
                return table["chmod"]
            return (1, "", "")

        return fake_sh

    def _get(self, answers=None):
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(answers)
        ):
            return self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )

    def _put(self, answers=None):
        # The scratch share directory is owned by this process, so the PUT
        # takes the owner-run path straight into _run_unprivileged.
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(answers)
        ):
            return self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "readwrite",
                },
            )

    def assertNoAddress(self, response):
        self.assertNotRegex(response.text, r" at 0x[0-9a-fA-F]+>")
        self.assertNotRegex(response.text, r"0x[0-9a-fA-F]{6,}")


# ─── GET /api/shares/acl: no heap address on the wire, honest storage parses ──


class ShareAclGetTests(_RouteSandbox):
    def test_junk_ls_answer_never_leaks_a_heap_address(self):
        """The live leftover: the default repr of a junk ls answer split
        into the mode/owner/group header, so the GET body's ``group`` field
        carried ``0x7f...>`` verbatim.  An unreadable listing is the coded
        read failure, never an address."""
        response = self._get(answers={"ls": (0, _DefaultRenderJunk(), "")})
        self.assertNoAddress(response)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_junk_realname_answer_never_leaks_into_the_picker(self):
        """The same repr rode a junk per-user RealName read into every
        picker row's ``real_name`` on an otherwise healthy page."""
        response = self._get(answers={"dscl_read": (0, _DefaultRenderJunk(), "")})
        self.assertNoAddress(response)
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["username"] for u in rows], ["alice"])
        self.assertEqual(rows[0]["real_name"], "")

    def test_lying_str_listing_with_a_bombed_str_still_parses(self):
        """The wrong-rank degrade: a genuine str ls answer whose
        ``__class__`` lies bytes and whose ``__str__`` bombs used to answer
        the coded read failure where its honest storage parses verbatim."""
        listing = _LyingStrBombed(_ls_listing(str(self.share_dir)))
        response = self._get(answers={"ls": (0, listing, "")})
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice", [e["name"] for e in response.json()["entries"]])

    def test_junk_stderr_on_a_failed_ls_keeps_the_coded_failure(self):
        """The failure funnel's marker probe reads the scrubbed text: junk
        stderr is no vanish marker and never an address."""
        response = self._get(answers={"ls": (1, "", _DefaultRenderJunk())})
        self.assertNoAddress(response)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_clean_spawn_chain_still_answers_the_page(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("alice", [u["username"] for u in payload["users"]])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])
        self.assertEqual(payload["users"][0]["real_name"], "Alice")


# ─── PUT /api/shares/acl: coded refusals recover their real error text ────────


class ShareAclPutTests(_RouteSandbox):
    def _put_needs_root(self, admin):
        """Drive the owner needs-root retry into the admin helper *admin*."""
        refused = {"chmod": (1, "", "chmod: Operation not permitted")}
        with mock.patch.object(
            share_acl_svc.macos_admin, "run_admin_sequence", admin
        ):
            return self._put(answers=refused)

    def test_lying_str_cancelled_keeps_its_coded_409(self):
        """The wrong-rank degrade on the write path: an admin ``error``
        whose real storage reads "cancelled" behind a lying-bytes
        ``__class__`` and a bombed ``__str__`` used to vanish to "" and
        answer the generic authorization failure in place of its own 409."""
        response = self._put_needs_root(
            mock.Mock(return_value={"ok": False, "error": _LyingStrBombed("cancelled")})
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled"
        )

    def test_junk_admin_error_field_never_leaks_an_address(self):
        """A default-render junk ``error`` reads as the generic coded
        failure — never its repr, never an address on the wire."""
        response = self._put_needs_root(
            mock.Mock(return_value={"ok": False, "error": _DefaultRenderJunk()})
        )
        self.assertNoAddress(response)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
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
