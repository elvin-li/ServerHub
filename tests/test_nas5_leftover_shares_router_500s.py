"""Fifth leftover-500s sweep of the NAS / Time Machine surfaces.

The nas/nas2/nas3/nas4 sweeps hardened the newer feature routers
(``nas_storage`` via ``nas_common``) and every NAS service's own sanitizer.
This hunt found the seam they all stepped around: ``hub/routers/shares.py`` —
the *older* SMB / Time Machine share router whose guards ``nas_common`` was
extracted from — never adopted the shared versions, and each of these was a
live raw HTTP 500 (traceback, no JSON body) on the mounted app pre-fix:

* ``_raise_service_error`` rendered the failure result's ``error`` field with
  a bare ``str()`` — an over-cap *already-int* error (YAML/plist hex loads
  uncapped through ``int(x, 16)``) raised the digit-cap ValueError out of
  POST /api/shares/smb, PUT /api/shares/smb/{name}, DELETE, PUT
  /api/shares/system/{id} and PUT /api/shares/acl in place of the coded
  refusal;
* every mutation route read ``result.get("ok")`` on the raw service result —
  a leftover ``None`` from a privileged helper AttributeError'd the route
  (the ``nas_common.raise_for_admin_result`` non-dict guard);
* successful results were pasted into the response body verbatim — a lone
  ``\\ud800`` in a key or value 500'd Starlette's UTF-8 encode, an over-cap
  already-int 500'd ``json.dumps`` under the digit cap, and a dict subclass
  whose ``items()`` raises (passes ``isinstance``, refuses iteration) 500'd
  the encoder walk (the ``nas_common._jsonable`` rule the newer routers
  already carry).

The fix imports the shared ``nas_common`` sanitizers instead of growing a
third copy: ``_service_result`` coerces a non-dict to the coded failure,
``_ok_payload`` cleans a successful body, and ``_raise_service_error`` probes
the error field with ``_utf8_text``.
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import share_acl_svc  # noqa: E402
from hub.routers import shares as shares_router  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ItemsBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment items() is read."""

    def items(self):
        raise ValueError("items bomb")


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as the shares router resolves one."""
    stack.enter_context(mock.patch.object(
        shares_router.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        shares_router.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        shares_router.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        shares_router.auth, "request_client_id", return_value="127.0.0.1"))
    stack.enter_context(mock.patch.object(
        shares_router.audit, "record", lambda *a, **k: {}))


_CREATE = {"path": "/tmp", "name": "media", "smb_name": "media"}


def _create(result):
    with ExitStack() as stack:
        _admin_browser(stack)
        stack.enter_context(mock.patch.object(
            shares_router.shares_svc, "create_smb_share",
            return_value=result))
        return _client().post("/api/shares/smb", json=_CREATE)


class FailureResultHostileShapeTests(unittest.TestCase):
    """Hostile failure results must keep their coded answer, never a raw 500."""

    def test_over_cap_int_error_field_degrades_to_coded_failure(self):
        # Pre-fix: the bare str(result["error"]) raised the digit-cap
        # ValueError out of the route — an unhandled 500 with no JSON body.
        resp = _create({"ok": False, "error": _HUGE_INT})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_over_cap_int_error_on_system_service_toggle(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "set_system_service",
                return_value={"ok": False, "error": _HUGE_INT}))
            resp = _client().put(
                "/api/shares/system/remote_login", json={"enabled": True})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_surrogate_error_field_stays_coded_and_utf8_clean(self):
        resp = _create({"ok": False, "error": "fail\ud800ed"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.operation_failed")
        self.assertNotIn("\ud800", resp.text)

    def test_items_bomb_failure_result_keeps_the_coded_answer(self):
        # ``.get`` still answers on the subclass; the coded refusal must not
        # lose to the hostile shape.
        resp = _create(_ItemsBombDict({"ok": False, "error": "exists"}))
        self.assertEqual(resp.status_code, 409, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.exists")

    def test_known_error_codes_keep_their_mapped_shapes(self):
        for error, code, status in (
            ("cancelled", "shares.authorization_cancelled", 409),
            ("not_found", "shares.not_found", 404),
            ("sharing_missing", "shares.sharing_missing", 503),
            ("password_required", "admin.password_required", 409),
        ):
            with self.subTest(error=error):
                resp = _create({"ok": False, "error": error})
                self.assertEqual(resp.status_code, status, resp.text[:200])
                self.assertEqual(resp.json()["detail"]["code"], code)


class NonDictResultTests(unittest.TestCase):
    """A leftover None / non-dict service result answers coded, never a 500.

    Pre-fix ``result.get("ok")`` AttributeError'd the route unhandled — the
    exact class ``nas_common.raise_for_admin_result`` guards for the newer
    NAS routers.
    """

    def test_none_result_on_create_degrades_to_coded_failure(self):
        resp = _create(None)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_none_result_on_update_delete_and_system_toggle(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "update_smb_share",
                return_value=None))
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "remove_smb_share",
                return_value=None))
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "set_system_service",
                return_value=None))
            client = _client()
            for label, resp in (
                ("update", client.put(
                    "/api/shares/smb/media", json={"smb_name": "media"})),
                ("delete", client.delete("/api/shares/smb/media?confirm=true")),
                ("system", client.put(
                    "/api/shares/system/remote_login", json={"enabled": True})),
            ):
                with self.subTest(route=label):
                    self.assertEqual(resp.status_code, 500, resp.text[:200])
                    body = resp.json()
                    _starlette(body)
                    self.assertEqual(
                        body["detail"]["code"], "shares.authorization_failed")

    def test_none_result_on_open_system_settings(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "open_system_settings",
                return_value=None))
            resp = _client().post("/api/shares/open-system-settings")
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.settings_open_failed")


class OkPayloadHostileShapeTests(unittest.TestCase):
    """Successful results through the shared sanitizer, never verbatim.

    Pre-fix each of these shapes 500'd the encoder on the mounted route; the
    unusable field must collapse (None / scrubbed text) while its siblings —
    including ``ok`` itself — survive.
    """

    def test_surrogate_value_in_ok_payload_is_scrubbed(self):
        resp = _create({"ok": True, "share": {"name": "media\ud800"}})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertNotIn("\ud800", resp.text)
        self.assertTrue(body["share"]["name"].startswith("media"))

    def test_surrogate_key_in_ok_payload_is_scrubbed(self):
        resp = _create({"ok": True, "de\ud800tail": "fine"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)
        self.assertIn("fine", resp.text)

    def test_over_cap_int_ok_value_collapses_the_field_not_the_route(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "update_smb_share",
                return_value={"ok": True, "share": {"size_mb": _HUGE_INT}}))
            resp = _client().put(
                "/api/shares/smb/media", json={"smb_name": "media"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["share"]["size_mb"])

    def test_items_bomb_ok_result_still_answers_ok(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "remove_smb_share",
                return_value=_ItemsBombDict({"ok": True})))
            resp = _client().delete("/api/shares/smb/media?confirm=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body, {"ok": True})

    def test_iter_bomb_sequence_value_salvages_its_storage(self):
        # shares7 upgraded the sanitizer to the unbound base ``__iter__``
        # walk: the hostile override cannot fire, so the real C-level
        # storage survives instead of collapsing to None.  The original
        # point stands either way: the route answers 200.
        resp = _create({"ok": True, "members": _IterBombList(["a"]), "count": 1})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["members"], ["a"])
        self.assertEqual(body["count"], 1)

    def test_system_service_ok_payload_is_cleaned(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "set_system_service",
                return_value={"ok": True, "service": {"detail": "up\ud800"}}))
            resp = _client().put(
                "/api/shares/system/remote_login", json={"enabled": True})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)

    def test_open_system_settings_ok_payload_is_cleaned(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "open_system_settings",
                return_value={"ok": True, "message": "opened\ud800"}))
            resp = _client().post("/api/shares/open-system-settings")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


class ShareAclPutHostileResultTests(unittest.TestCase):
    """PUT /api/shares/acl rides the same guards as the share mutations."""

    def _acl_put(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "list_smb_shares",
                return_value=[{"path": "/tmp"}]))
            stack.enter_context(mock.patch.object(
                share_acl_svc, "set_user_access", return_value=result))
            return _client().put("/api/shares/acl", json={
                "path": "/tmp", "username": "alice", "level": "read",
            })

    def test_surrogate_ok_payload_is_scrubbed(self):
        resp = self._acl_put({"ok": True, "owner": "alice\ud800"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertNotIn("\ud800", resp.text)

    def test_none_result_degrades_to_coded_failure(self):
        resp = self._acl_put(None)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_over_cap_int_error_degrades_to_coded_failure(self):
        resp = self._acl_put({"ok": False, "error": _HUGE_INT})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "shares.authorization_failed")

    def test_vanished_chmod_keeps_its_coded_503(self):
        resp = self._acl_put({"ok": False, "error": "acl_tool_missing"})
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "shares.acl_tool_missing")


class OrdinaryFlowRegressionTests(unittest.TestCase):
    """The healthy shapes keep working exactly as before the guards."""

    def test_ordinary_ok_share_payload_passes_through_intact(self):
        share = {
            "record_name": "media", "name": "media", "path": "/tmp",
            "smb_name": "media", "shared": True, "guest": False,
            "readonly": False, "encrypted": False, "size_mb": None,
            "url": "smb://192.0.2.7/media", "time_machine": True,
            "tm_quota_gb": 500,
        }
        resp = _create({"ok": True, "share": share})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body, {"ok": True, "share": share})

    def test_unknown_service_still_carries_the_service_param(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_router.shares_svc, "set_system_service",
                return_value={"ok": False, "error": "unknown_service"}))
            resp = _client().put(
                "/api/shares/system/bogus", json={"enabled": True})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        detail = resp.json()["detail"]
        _starlette(detail)
        self.assertEqual(detail["code"], "shares.unknown_service")
        self.assertEqual(detail["params"]["service"], "bogus")


if __name__ == "__main__":
    unittest.main(verbosity=2)
