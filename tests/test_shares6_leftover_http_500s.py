"""Sixth leftover-500s sweep of the Shares / share-ACL surfaces.

The shares5/nas5 sweeps pinned non-dict service results, items-*raise*
subclasses (whose ``.get`` still answers), over-cap already-int error fields
and lone surrogates.  This hunt reproduced the remaining subclass-bomb zoo
over ``create_app()`` + ``TestClient(raise_server_exceptions=False)`` and
found these live raw HTTP 500s (traceback, no JSON body) pre-fix:

* **bytes-subclass ``.decode`` bombs** — three private ``_as_text`` /
  ``_utf8_text`` copies (``shares_svc``, ``share_acl_svc``,
  ``routers/nas_common``) called the *bound* ``.decode``, so a leftover
  bytes-subclass ``sharing -l`` / ``ls -lde`` stream — or a bytes error /
  message field in a privileged result — raised straight out of
  GET /api/shares/acl, PUT /api/shares/acl and every mutation's failure
  funnel.  Fixed with the unbound base decode (the brew6 rule).

* **dict-subclass ``.get`` bombs from run_admin / run_admin_sequence** —
  ``create/update/remove_smb_share``, ``set_system_service`` and
  ``set_user_access`` read ``result.get("ok")`` on the raw helper result; a
  subclass whose ``.get`` raises (the jobs/metrics row-bomb class: passes
  every isinstance gate) 500'd POST/PUT/DELETE /api/shares/smb,
  PUT /api/shares/system/{id} and PUT /api/shares/acl.  The router's
  ``_service_result`` had the same hole one layer up, and the shared NAS
  funnels ``raise_for_admin_result`` / ``raise_service_error`` the same one
  layer down.  Fixed with a ``_plain_result`` C-level-storage copy.

* **``__bool__`` bombs on the ``ok`` / ``error`` / ``message`` values** —
  ``if not result.get("ok")`` and the ``result.get("error") or "failed"``
  fallback chains called ``bool()`` on the raw leftover.  Fixed with the
  jobs-style ``_truthy`` that fails closed.

* **nested ``_jsonable`` gaps in nas_common (the modules5 zoo)** — an ok
  payload carrying an int subclass whose ``__str__`` raises a
  non-ValueError, a float subclass whose ``__eq__`` raises, a bytes
  subclass whose ``.decode`` raises, a dict subclass whose ``items()``
  yields *non-pairs* (the raise was caught; the two-target unpack happened
  outside the try), or any object whose ``__getattr__`` raises out of the
  bare ``getattr(value, "isoformat", None)`` probe each 500'd the encoder
  walk behind POST /api/shares/open-system-settings and every other
  ``_ok_payload`` route.  Fixed by porting the hardened modules5 pattern
  (``int.__index__`` / ``float.__float__`` base coercion, unbound
  ``dict.items``, guarded getattr).

* **dict-subclass rows in the ACL share gate** — ``_share_directory`` read
  ``share.get("path")`` on each listing row; one hostile row 500'd GET and
  PUT /api/shares/acl.  Fixed with ``dict.get`` + ``_truthy``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import auth, share_acl_svc, shares_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import nas_common

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


@contextmanager
def _admin_browser():
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(auth, "browser_authenticated", return_value=True))
        stack.enter_context(
            mock.patch.object(auth, "request_username", return_value="admin"))
        stack.enter_context(mock.patch.object(auth, "is_admin", return_value=True))
        yield


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


# ── the zoo ──────────────────────────────────────────────────────────────────


class _DecodeBombBytes(bytes):
    """Passes ``isinstance(x, bytes)``; the bound ``.decode`` raises."""

    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; ``.get`` raises the moment it is read."""

    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _NonPairItemsDict(dict):
    """items() *returns* instead of raising — non-pairs blow the unpack."""

    def items(self):
        return [1, 2]


class _StrBombInt(int):
    """__str__ raises a non-ValueError, dodging the bare digit-cap probe."""

    def __str__(self):
        raise TypeError("str bomb")


class _EqBombFloat(float):
    __hash__ = float.__hash__

    def __eq__(self, other):
        raise RuntimeError("eq bomb")


class _GetattrBomb:
    """getattr's three-arg default only swallows AttributeError."""

    def __getattr__(self, name):
        raise RuntimeError("getattr bomb")


class _HugeIntSub(int):
    """An over-cap already-int that also dodges the exact-type fast path."""


# ── bytes-subclass sh streams ────────────────────────────────────────────────


class AsTextBytesSubclassTests(unittest.TestCase):
    """A bytes-subclass command stream decodes; it must never raise."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())

    def test_acl_get_survives_bytes_subclass_sharing_listing(self):
        """Pre-fix the bound ``.decode`` raised out of list_smb_shares'
        parse guards (they only catch TypeError/ValueError) and 500'd the
        unguarded share gate on GET /api/shares/acl."""
        listing = json.dumps({
            "Media": {"path": self.share_dir, "smb_name": "Media", "smb_shared": 1},
        })

        def shares_sh(cmd, timeout=10, **kwargs):
            if list(cmd[:4]) == [shares_svc.SHARING, "-l", "-f", "json"]:
                return 0, _DecodeBombBytes(listing.encode()), ""
            return 1, "", "unavailable"

        def acl_sh(cmd, timeout=10, **kwargs):
            if cmd[0] == share_acl_svc.LS:
                return 0, "drwxr-xr-x 2 me staff 64 Jan 1 x\n", ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=shares_sh),
            mock.patch.object(share_acl_svc, "sh", side_effect=acl_sh),
        ):
            response = _client().get(
                "/api/shares/acl", params={"path": self.share_dir})
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["mode"], "drwxr-xr-x")

    def test_acl_get_survives_bytes_subclass_ls_output(self):
        """Pre-fix read_acl's ``_as_text(output)`` raised untyped past the
        route's ShareAclError handler."""
        def acl_sh(cmd, timeout=10, **kwargs):
            if cmd[0] == share_acl_svc.LS:
                return 0, _DecodeBombBytes(
                    b"drwxr-xr-x 2 me staff 64 Jan 1 x\n"
                    b" 0: user:alice allow read\n"
                ), ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[{"record_name": "Media", "path": self.share_dir}],
            ),
            mock.patch.object(share_acl_svc, "sh", side_effect=acl_sh),
        ):
            response = _client().get(
                "/api/shares/acl", params={"path": self.share_dir})
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["entries"][0]["name"], "alice")


# ── dict-subclass / __bool__ bombs from the privileged helpers ───────────────


class RunAdminSubclassResultTests(unittest.TestCase):
    """run_admin(_sequence) leftovers answer coded, never a raw 500."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())
        self.listing = json.dumps({
            "Media": {"path": self.share_dir, "smb_name": "Media", "smb_shared": 1},
        })

    def _sh(self, listing: str):
        def fake_sh(cmd, timeout=10, **kwargs):
            if list(cmd[:4]) == [shares_svc.SHARING, "-l", "-f", "json"]:
                return 0, listing, ""
            return 1, "", "unavailable"
        return fake_sh

    def _assert_coded_500(self, response):
        self.assertEqual(response.status_code, 500, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_create_with_get_bomb_admin_result_is_coded(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=self._sh("{}")),
            mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value=_GetBombDict({"ok": False})),
        ):
            response = _client().post("/api/shares/smb", json={
                "path": self.share_dir, "name": "Media", "smb_name": "Media",
            })
        self._assert_coded_500(response)

    def test_update_with_get_bomb_admin_result_is_coded(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=self._sh(self.listing)),
            mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value=_GetBombDict({"ok": False})),
        ):
            response = _client().put(
                "/api/shares/smb/Media", json={"smb_name": "Media"})
        self._assert_coded_500(response)

    def test_delete_with_get_bomb_admin_result_is_coded(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=self._sh(self.listing)),
            mock.patch.object(
                shares_svc, "run_admin",
                return_value=_GetBombDict({"ok": False})),
        ):
            response = _client().delete("/api/shares/smb/Media?confirm=true")
        self._assert_coded_500(response)

    def test_system_toggle_with_bool_bomb_ok_is_coded(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=self._sh("{}")),
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value={"ok": _BoolBomb()}),
        ):
            response = _client().put(
                "/api/shares/system/remote_login", json={"enabled": True})
        self._assert_coded_500(response)

    def test_cancelled_authorization_keeps_its_shape_through_the_laundering(self):
        with (
            _admin_browser(),
            mock.patch.object(shares_svc, "sh", side_effect=self._sh("{}")),
            mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value={"ok": False, "error": "cancelled"}),
        ):
            response = _client().post("/api/shares/smb", json={
                "path": self.share_dir, "name": "Media", "smb_name": "Media",
            })
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled")


class RouterServiceResultBombTests(unittest.TestCase):
    """The router's own ``result.get`` / ``or`` reads survive the zoo."""

    def _toggle(self, result):
        with ExitStack() as stack:
            stack.enter_context(_admin_browser())
            stack.enter_context(mock.patch.object(
                shares_svc, "set_system_service", return_value=result))
            return _client().put(
                "/api/shares/system/remote_login", json={"enabled": True})

    def test_get_bomb_service_result_is_coded(self):
        response = self._toggle(_GetBombDict({"ok": False, "error": "failed"}))
        self.assertEqual(response.status_code, 500, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_bool_bomb_ok_value_is_coded(self):
        response = self._toggle({"ok": _BoolBomb()})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_bool_bomb_error_value_keeps_the_coded_fallback(self):
        # Pre-fix ``result.get("error") or "failed"`` called bool() on the
        # leftover and raised out of the fallback chain itself.
        response = self._toggle({"ok": False, "error": _BoolBomb()})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_bytes_subclass_error_still_maps_to_its_coded_refusal(self):
        # The unbound decode reads the real payload: b"exists" must earn the
        # 409 it names, not a generic answer (and never the raw 500 the bound
        # ``.decode`` used to raise).
        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "create_smb_share",
                return_value={"ok": False, "error": _DecodeBombBytes(b"exists")}),
        ):
            response = _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "Media", "smb_name": "Media",
            })
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "shares.exists")


# ── nested _jsonable bombs in a privileged ok payload ────────────────────────


class OkPayloadJsonableBombTests(unittest.TestCase):
    """The modules5 zoo through ``_ok_payload``: field degrades, route answers."""

    def _post(self, payload):
        with ExitStack() as stack:
            stack.enter_context(_admin_browser())
            stack.enter_context(mock.patch.object(
                shares_svc, "open_system_settings", return_value=payload))
            return _client().post("/api/shares/open-system-settings")

    def _ok_body(self, payload) -> dict:
        response = self._post(payload)
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        return body

    def test_getattr_bomb_field_degrades_to_text(self):
        body = self._ok_body({"ok": True, "leftover": _GetattrBomb()})
        self.assertIsInstance(body["leftover"], str)

    def test_non_pair_items_dict_salvages_the_real_storage(self):
        body = self._ok_body(
            {"ok": True, "leftover": _NonPairItemsDict({"kept": "yes"})})
        self.assertEqual(body["leftover"], {"kept": "yes"})

    def test_str_bomb_int_subclass_survives_as_its_value(self):
        body = self._ok_body({"ok": True, "leftover": _StrBombInt(7)})
        self.assertEqual(body["leftover"], 7)

    def test_over_cap_int_subclass_drops_only_itself(self):
        body = self._ok_body(
            {"ok": True, "leftover": _HugeIntSub(10 ** 5000), "kept": 1})
        self.assertIsNone(body["leftover"])
        self.assertEqual(body["kept"], 1)

    def test_eq_bomb_float_subclass_survives_as_its_value(self):
        body = self._ok_body({"ok": True, "leftover": _EqBombFloat(1.5)})
        self.assertEqual(body["leftover"], 1.5)

    def test_decode_bomb_bytes_subclass_decodes_through_the_base(self):
        body = self._ok_body({"ok": True, "leftover": _DecodeBombBytes(b"x")})
        self.assertEqual(body["leftover"], "x")


# ── the ACL share gate and set_user_access ───────────────────────────────────


class AclShareGateRowBombTests(unittest.TestCase):
    """Hostile listing rows must not 500 the gate on GET/PUT /api/shares/acl."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())

    def test_get_bomb_row_still_matches_through_its_storage(self):
        def acl_sh(cmd, timeout=10, **kwargs):
            if cmd[0] == share_acl_svc.LS:
                return 0, "drwxr-xr-x 2 me staff 64 Jan 1 x\n", ""
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[
                    _GetBombDict({"record_name": "Media", "path": self.share_dir}),
                ],
            ),
            mock.patch.object(share_acl_svc, "sh", side_effect=acl_sh),
        ):
            response = _client().get(
                "/api/shares/acl", params={"path": self.share_dir})
        self.assertEqual(response.status_code, 200, response.text[:200])
        _starlette(response.json())

    def test_bool_bomb_path_row_is_skipped_not_a_500(self):
        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[{"record_name": "Media", "path": _BoolBomb()}],
            ),
            mock.patch.object(shares_svc, "_sharing_on_disk", return_value=True),
        ):
            response = _client().get(
                "/api/shares/acl", params={"path": self.share_dir})
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_not_share")


class SetUserAccessHostileAdminResultTests(unittest.TestCase):
    """PUT /api/shares/acl survives hostile run_admin_sequence leftovers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())

    def _put(self, admin_result, *, chmod_on_disk: bool = True):
        acl_out = (
            "drwxr-xr-x 2 me staff 64 Jan 1 x\n"
            " 0: user:alice allow read\n"
        )

        def acl_sh(cmd, timeout=10, **kwargs):
            if cmd[0] == share_acl_svc.LS:
                return 0, acl_out, ""
            if cmd[0] == share_acl_svc.DSCL and cmd[2] == "-list":
                return 0, "alice  501\n", ""
            if cmd[0] == share_acl_svc.DSCL:
                return 0, "RealName: Alice", ""
            if cmd[0] == share_acl_svc.CHMOD:
                # The owner-run refusal that escalates to the admin path.
                return 1, "", "chmod: Operation not permitted"
            return 1, "", "unavailable"

        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[{"record_name": "Media", "path": self.share_dir}],
            ),
            mock.patch.object(share_acl_svc, "sh", side_effect=acl_sh),
            mock.patch.object(
                share_acl_svc, "_tool_on_disk", return_value=chmod_on_disk),
            mock.patch.object(
                share_acl_svc.macos_admin, "run_admin_sequence",
                return_value=admin_result),
        ):
            return _client().put("/api/shares/acl", json={
                "path": self.share_dir, "username": "alice", "level": "read",
            })

    def test_get_bomb_admin_result_is_coded(self):
        response = self._put(_GetBombDict({"ok": False}))
        self.assertEqual(response.status_code, 500, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_bool_bomb_ok_value_is_coded(self):
        response = self._put({"ok": _BoolBomb()})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_non_str_error_field_degrades_to_the_coded_failure(self):
        response = self._put({"ok": False, "error": 7})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_bytes_subclass_message_still_answers_coded(self):
        response = self._put(
            {"ok": False, "error": "failed", "message": _DecodeBombBytes(b"x")})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_bytes_subclass_vanish_message_still_earns_the_503(self):
        # The unbound decode reads the real sentinel, so the confirmed-vanish
        # classification keeps working on a hostile stream.
        response = self._put(
            {
                "ok": False,
                "error": "failed",
                "message": _DecodeBombBytes(b"sh: /bin/chmod: command not found"),
            },
            chmod_on_disk=False,
        )
        self.assertEqual(response.status_code, 503, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_tool_missing")

    def test_plain_ok_result_still_verifies_and_answers_200(self):
        response = self._put({"ok": True})
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["entries"][0]["name"], "alice")


# ── the shared NAS funnels (one layer below every nas_storage route) ─────────


class NasCommonFunnelLaunderingTests(unittest.TestCase):
    """raise_for_admin_result / raise_service_error survive the same zoo."""

    def test_get_bomb_result_keeps_its_mapped_code(self):
        with self.assertRaises(HTTPException) as caught:
            nas_common.raise_for_admin_result(
                _GetBombDict({"ok": False, "error": "cancelled"}))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(caught.exception.detail["code"], "admin.cancelled")

    def test_bool_bomb_ok_and_fields_degrade_to_admin_failed(self):
        with self.assertRaises(HTTPException) as caught:
            nas_common.raise_for_admin_result(
                {"ok": False, "error": _BoolBomb(), "message": _BoolBomb()})
        self.assertEqual(caught.exception.status_code, 500)
        self.assertEqual(caught.exception.detail["code"], "admin.failed")

    def test_bool_bomb_ok_value_is_a_failure_not_a_raise(self):
        with self.assertRaises(HTTPException) as caught:
            nas_common.raise_for_admin_result({"ok": _BoolBomb()})
        self.assertEqual(caught.exception.detail["code"], "admin.failed")

    def test_ok_subclass_result_answers_its_cleaned_storage(self):
        cleaned = nas_common.raise_for_admin_result(
            _GetBombDict({"ok": True, "device": "disk4"}))
        _starlette(cleaned)
        self.assertEqual(cleaned, {"ok": True, "device": "disk4"})

    def test_service_error_mapping_survives_a_get_bomb_result(self):
        with self.assertRaises(HTTPException) as caught:
            nas_common.raise_service_error(
                _GetBombDict({"ok": False, "error": "bad_action"}),
                {"bad_action": "nfs.bad_action"},
            )
        self.assertEqual(caught.exception.detail["code"], "nfs.bad_action")


if __name__ == "__main__":
    unittest.main(verbosity=2)
