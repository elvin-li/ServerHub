"""Seventh leftover-500s sweep of the Shares / share-ACL JSON surfaces.

shares6 sealed the dict-subclass ``.get`` / ``items()`` / ``__bool__`` bombs
and the first nested ``_jsonable`` zoo.  This hunt reproduced the remaining
bombs over ``create_app()`` + ``TestClient(raise_server_exceptions=False)``
and found these live raw HTTP 500s (traceback, no JSON body) pre-fix:

* **``__eq__`` bombs on the error-string probes** — routers/shares'
  ``open_system_settings`` compared ``result.get("error") ==
  "system_tool_missing"`` on the raw leftover, so a str-subclass error whose
  ``__eq__`` raises detonated the probe itself.  Fixed by laundering through
  ``_utf8_text`` (exact str out) before the ``==``.

* **self-``__str__`` ``encode`` bombs in nas_common._utf8_text** — ``str()``
  of a subclass whose ``__str__`` answers *self* skips CPython's exact-str
  copy, so the bound ``text.encode`` bomb dropped a coded error string
  ("exists", "cancelled") to ``""`` and every funnel degraded it to the
  generic 500 in place of its mapped 409.  Fixed with the unbound
  ``str.encode`` (the modules6 rule share_acl_svc._as_text already follows).

* **hostile extra fields through raise_service_error's params** — the old
  comprehension probed ``k not in ("ok", "error")`` first (a subclass key's
  ``__eq__`` fired inside the tuple contains), and str-subclass /
  int-subclass values rode the isinstance gate into errors._jsonable_param's
  bound ``value.encode`` / bare ``str(value)`` — each 500'd the coded refusal
  while its own body was being built.  Fixed with per-field laundering
  (``_utf8_text`` keys, ``_jsonable`` values) before ``api_error``.

* **GET /api/shares/acl pasted the service state verbatim** — a dict-subclass
  state whose overridden ``__iter__``/``keys`` sends dict-unpacking down the
  slow path 500'd the ``{**state}`` merge; a ``None`` state TypeError'd it;
  a lone ``\\ud800`` / over-cap already-int in the state or a list-subclass
  ``local_users()`` whose ``__iter__`` raises 500'd Starlette's encoder.
  Fixed with ``_plain_result`` + the shared ``_jsonable`` (the _ok_payload
  rule this GET missed).

* **sequence-subclass ``__iter__`` bombs in nas_common._jsonable** — the
  guarded bound iteration dropped the whole field to None even though the
  real C-level storage still held every element.  Fixed with the unbound
  base ``__iter__`` salvage.

* **share-gate walk aborted by one hostile row** — ``_share_directory``'s
  inner catch listed four exception types, so a row ``__str__`` bomb raising
  anything else escaped into the outer catch and every share point *after*
  it was lost: a legitimate directory answered the acl_not_share lie.
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

from hub import auth, nfs_svc, share_acl_svc, shares_svc
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


class _EqBombStr(str):
    """Passes ``isinstance(x, str)``; any ``==`` probe on it raises."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("eq bomb")


class _SelfStrEncodeBombStr(str):
    """``__str__`` answers *self*, so the bound ``encode`` bomb survives str()."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _EncodeBombStr(str):
    """Default ``__str__``; the bound ``.encode`` raises."""

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _StrBombInt(int):
    """__str__ raises a non-ValueError, dodging the bare digit-cap probe."""

    def __str__(self):
        raise TypeError("str bomb")


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; the bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _MidIterBombList(list):
    """The bound ``__iter__`` answers a generator that dies mid-walk."""

    def __iter__(self):
        def rows():
            yield list.__getitem__(self, 0)
            raise RuntimeError("mid-iter bomb")
        return rows()


class _KeysIterBombDict(dict):
    """Overridden ``keys``/``__iter__`` send dict merges down the slow path."""

    def keys(self):
        raise RuntimeError("keys bomb")

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; ``.get`` raises the moment it is read."""

    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _OddStrBomb:
    """``str()`` raises an exception outside the four Path shapes."""

    def __str__(self):
        raise ZeroDivisionError("str bomb")


# ── the == probes on error strings ───────────────────────────────────────────


class OpenSettingsEqBombTests(unittest.TestCase):
    """The system_tool_missing probe survives an ``__eq__``-bomb error value."""

    def _post(self, result):
        with ExitStack() as stack:
            stack.enter_context(_admin_browser())
            stack.enter_context(mock.patch.object(
                shares_svc, "open_system_settings", return_value=result))
            return _client().post("/api/shares/open-system-settings")

    def test_eq_bomb_error_still_earns_its_503(self):
        # Pre-fix the raw ``==`` fired the subclass __eq__ and 500'd the route.
        response = self._post(
            {"ok": False, "error": _EqBombStr("system_tool_missing")})
        self.assertEqual(response.status_code, 503, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.system_tool_missing")

    def test_eq_bomb_other_error_keeps_the_coded_fallback(self):
        response = self._post({"ok": False, "error": _EqBombStr("nope")})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.settings_open_failed")


# ── self-__str__ encode bombs: the coded mapping must survive ────────────────


class SelfStrEncodeBombErrorMappingTests(unittest.TestCase):
    """The unbound str.encode reads the real error string, not ``""``."""

    def test_exists_error_keeps_its_409_through_the_router_funnel(self):
        # Pre-fix _utf8_text dropped the text to "" and the funnel answered
        # the generic 500 shares.operation_failed in place of the 409.
        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "create_smb_share",
                return_value={"ok": False, "error": _SelfStrEncodeBombStr("exists")}),
        ):
            response = _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "Media", "smb_name": "Media",
            })
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "shares.exists")

    def test_system_tool_missing_error_keeps_its_503(self):
        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "open_system_settings",
                return_value={
                    "ok": False,
                    "error": _SelfStrEncodeBombStr("system_tool_missing"),
                }),
        ):
            response = _client().post("/api/shares/open-system-settings")
        self.assertEqual(response.status_code, 503, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.system_tool_missing")

    def test_cancelled_error_keeps_its_409_through_the_nas_funnel(self):
        with self.assertRaises(HTTPException) as caught:
            nas_common.raise_for_admin_result(
                {"ok": False, "error": _SelfStrEncodeBombStr("cancelled")})
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(caught.exception.detail["code"], "admin.cancelled")

    def test_ok_payload_keeps_the_real_text_of_a_self_str_encode_bomb(self):
        cleaned = nas_common.raise_for_admin_result(
            {"ok": True, "label": _SelfStrEncodeBombStr("Media")})
        _starlette(cleaned)
        self.assertEqual(cleaned["label"], "Media")


# ── raise_service_error's params laundering ──────────────────────────────────


class ServiceErrorParamsLaunderingTests(unittest.TestCase):
    """Hostile extra result fields cannot 500 the coded refusal."""

    _MAPPING = {"bad_action": "nfs.bad_action"}

    def _raise(self, result) -> HTTPException:
        with self.assertRaises(HTTPException) as caught:
            nas_common.raise_service_error(result, self._MAPPING)
        return caught.exception

    def test_eq_bomb_key_still_rides_as_a_laundered_param(self):
        # Pre-fix ``k not in ("ok", "error")`` fired the subclass __eq__ and
        # the RuntimeError escaped the funnel as a raw 500.
        error = self._raise({
            "ok": False, "error": "bad_action", _EqBombStr("field"): "x",
        })
        self.assertEqual(error.detail["code"], "nfs.bad_action")
        self.assertEqual(error.detail["params"]["field"], "x")

    def test_encode_bomb_str_value_is_scrubbed_not_a_raise(self):
        # Pre-fix errors._jsonable_param called the bound ``value.encode``.
        error = self._raise({
            "ok": False, "error": "bad_action", "detail": _EncodeBombStr("boom"),
        })
        self.assertEqual(error.detail["code"], "nfs.bad_action")
        self.assertEqual(error.detail["params"]["detail"], "boom")

    def test_str_bomb_int_value_survives_as_its_value(self):
        # Pre-fix the bare ``str(value)`` digit-cap probe only caught
        # ValueError, so the TypeError escaped as a raw 500.
        error = self._raise({
            "ok": False, "error": "bad_action", "count": _StrBombInt(7),
        })
        self.assertEqual(error.detail["code"], "nfs.bad_action")
        self.assertEqual(error.detail["params"]["count"], 7)

    def test_over_cap_int_value_drops_only_itself(self):
        error = self._raise({
            "ok": False, "error": "bad_action",
            "huge": 10 ** 5000, "kept": "yes",
        })
        self.assertEqual(error.detail["code"], "nfs.bad_action")
        self.assertEqual(error.detail["params"]["kept"], "yes")
        self.assertNotIn("huge", error.detail["params"])
        _starlette(error.detail)

    def test_http_route_answers_coded_with_a_hostile_extra_field(self):
        with (
            _admin_browser(),
            mock.patch.object(
                nfs_svc, "server_action",
                return_value={
                    "ok": False, "error": "bad_action",
                    "detail": _EncodeBombStr("boom"),
                }),
        ):
            response = _client().post(
                "/api/nfs/server", json={"action": "explode"})
        self.assertEqual(response.status_code, 400, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "nfs.bad_action")


# ── GET /api/shares/acl payload laundering ───────────────────────────────────


class AclGetPayloadTests(unittest.TestCase):
    """The GET response goes through _plain_result + _jsonable, never raw."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())

    def _get(self, state, users=None):
        with ExitStack() as stack:
            stack.enter_context(_admin_browser())
            stack.enter_context(mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[{"record_name": "Media", "path": self.share_dir}],
            ))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "read_acl", return_value=state))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "local_users",
                return_value=[] if users is None else users))
            return _client().get(
                "/api/shares/acl", params={"path": self.share_dir})

    def test_keys_iter_bomb_state_answers_the_coded_read_failure(self):
        # Pre-fix ``{**state}`` took dict-unpacking's slow path into the
        # overridden keys() and the RuntimeError 500'd the route raw.
        response = self._get(_KeysIterBombDict({"mode": "drwx"}))
        self.assertEqual(response.status_code, 500, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.acl_read_failed")

    def test_none_state_answers_the_coded_read_failure(self):
        # Pre-fix ``{**None}`` TypeError'd the route raw.
        response = self._get(None)
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_get_bomb_state_still_answers_its_cleaned_storage(self):
        response = self._get(_GetBombDict({"mode": "drwx", "entries": []}))
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["mode"], "drwx")
        self.assertEqual(body["users"], [])

    def test_surrogate_and_over_cap_int_state_fields_are_scrubbed(self):
        # Pre-fix Starlette's UTF-8 encode / allow_nan=False dumps 500'd on
        # the verbatim paste.
        response = self._get({
            "mode": "drwx", "entries": [],
            "leftover": "x\ud800y", "huge": 10 ** 5000,
        })
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["leftover"], "x?y")
        self.assertIsNone(body["huge"])

    def test_iter_bomb_local_users_salvages_the_real_rows(self):
        # Pre-fix json.dumps iterated the bound __iter__ and 500'd the route;
        # the unbound base walk keeps every real row.
        users = _IterBombList([
            {"username": "alice", "uid": 501, "real_name": "Alice"},
        ])
        response = self._get({"mode": "drwx", "entries": []}, users=users)
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertEqual(body["users"][0]["username"], "alice")


# ── the share gate keeps walking past one hostile row ────────────────────────


class ShareGateSiblingSalvageTests(unittest.TestCase):
    """One row's odd ``__str__`` bomb must not lose the share points after it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())

    def test_later_share_point_still_matches(self):
        # Pre-fix the ZeroDivisionError escaped the four-shape inner catch,
        # the outer catch aborted the walk, and the legitimate directory
        # answered the acl_not_share / sharing_missing lie.
        with (
            _admin_browser(),
            mock.patch.object(
                shares_svc, "list_smb_shares",
                return_value=[
                    {"record_name": "Bad", "path": _OddStrBomb()},
                    {"record_name": "Media", "path": self.share_dir},
                ],
            ),
            mock.patch.object(
                share_acl_svc, "read_acl",
                return_value={"mode": "drwx", "entries": []}),
            mock.patch.object(share_acl_svc, "local_users", return_value=[]),
        ):
            response = _client().get(
                "/api/shares/acl", params={"path": self.share_dir})
        self.assertEqual(response.status_code, 200, response.text[:200])
        _starlette(response.json())


# ── sequence-subclass salvage through the shared _jsonable ───────────────────


class OkPayloadSequenceSalvageTests(unittest.TestCase):
    """A list-subclass __iter__ bomb keeps its elements, not a None drop."""

    def _ok_body(self, payload) -> dict:
        with ExitStack() as stack:
            stack.enter_context(_admin_browser())
            stack.enter_context(mock.patch.object(
                shares_svc, "open_system_settings", return_value=payload))
            response = _client().post("/api/shares/open-system-settings")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        return body

    def test_iter_bomb_list_subclass_salvages_its_storage(self):
        body = self._ok_body({"ok": True, "leftover": _IterBombList(["a", "b"])})
        self.assertEqual(body["leftover"], ["a", "b"])

    def test_mid_iter_bomb_never_reaches_the_hostile_generator(self):
        body = self._ok_body(
            {"ok": True, "leftover": _MidIterBombList(["a", "b"])})
        self.assertEqual(body["leftover"], ["a", "b"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
