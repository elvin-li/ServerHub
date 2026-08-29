"""Fourth leftover-500s sweep of the Host / power routes, over the real app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the YAML/plist hex form that loads uncapped
through ``int(x, 16)`` and so arrives *already-int* — huge-number JSON bodies
where ``json.loads`` raises ValueError not JSONDecodeError, vanished-CLI
classification, sibling-row wipes) were re-reproduced against the mounted
power / host routes through ``create_app()``.  Three live leftovers were
found and are fixed alongside this file:

* POST /api/system/screensharing/enable|disable's *failure* branch coerced
  the service error with a bare ``str()``.  A leftover over-cap int error
  raised CPython's int->str digit-cap ValueError and a recursive ``__str__``
  raised RecursionError — both answered a raw uncoded 500, one branch below
  the ok path that host3 had already routed through ``power_svc._jsonable``.
  The coercion now goes through ``power_svc._as_text`` (which also lets a
  leftover bytes ``b"cancelled"`` match its coded 409 instead of turning
  into the repr ``"b'cancelled'"``).

* PUT /api/system/power/wol with a pmset that vanished from disk answered
  ``200 {"ok": false, "message": "not found · run manually: sudo pmset …"}``
  — blaming privileges for a binary that is gone (the sudo fallback cannot
  spawn it either).  Now the identity ``_scutil_missing`` rule: the spawn
  sentinel ``(-1, "", "not found")`` plus a fresh on-disk probe *on the
  failure path only* raises the coded 503 ``power.pmset_missing``.  A
  timeout sentinel or a real pmset exit keeps the old ok:false shape.

* PUT /api/identity persisted ``comment`` / ``host_ip`` into services.yaml
  unbounded.  A multi-MB value was refused only by the whole-file save cap
  as a ``settings.save_failed`` 503 — blaming the disk for oversized input —
  and a value just under that cap crowded every sibling writer toward the
  read cap (the sibling-wipe class the vms rename fix documents).  Now the
  coded 400 ``identity.value_too_long``, raised before anything is written.

The rest pins HTTP-layer corners of the same domain that the service-layer
suites never cross (request routing, body parsing, strict UTF-8 render).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest import mock

from fastapi.testclient import TestClient

from hub import identity_svc, power_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import power as power_router

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 16 ** 5000
_HUGE_DIGITS = "9" * 5000

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


def _clean(response) -> None:
    """The body decoded, carries no lone surrogate, and re-encodes as UTF-8."""
    text = response.text
    assert "\ud800" not in text and "\udc80" not in text, text[:300]
    text.encode("utf-8")


class _Recursing:
    def __str__(self):
        raise RecursionError("nested")


class ScreensharingFailurePathRenderTests(unittest.TestCase):
    """The live leak: the failure branch's bare ``str()`` on the error."""

    def _toggle(self, error, *, enable=True):
        patches = (
            mock.patch.object(power_router.auth, "browser_authenticated", return_value=True),
            mock.patch.object(power_router.auth, "request_username", return_value="admin"),
            mock.patch.object(power_router.auth, "is_admin", return_value=True),
            mock.patch.object(power_router.auth, "request_client_id", return_value="127.0.0.1"),
            mock.patch.object(power_router.audit, "record", lambda *a, **k: {}),
            mock.patch.object(
                power_router.shares_svc, "set_system_service",
                return_value={"ok": False, "error": error},
            ),
        )
        path = "/api/system/screensharing/" + ("enable" if enable else "disable")
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return _client().post(path)

    def test_over_cap_int_error_is_a_coded_body_not_a_raw_500(self):
        # Pre-fix: str(16**5000) ValueError'd inside the handler and the
        # client got the uncoded plain-text "Internal Server Error".
        response = self._toggle(_HUGE_INT)
        self.assertEqual(response.status_code, 500, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "shares.operation_failed")

    def test_recursive_str_error_is_a_coded_body_not_a_raw_500(self):
        response = self._toggle(_Recursing(), enable=False)
        self.assertEqual(response.status_code, 500, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "shares.operation_failed")

    def test_bytes_cancelled_matches_its_coded_409(self):
        # str(b"cancelled") is the repr "b'cancelled'", which missed the code
        # map and answered the generic 500; the decode restores the 409.
        response = self._toggle(b"cancelled")
        self.assertEqual(response.status_code, 409, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled",
        )

    def test_surrogate_error_stays_a_clean_coded_body(self):
        response = self._toggle("boom\ud800")
        self.assertEqual(response.status_code, 500, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "shares.operation_failed")

    def test_plain_unavailable_keeps_its_coded_503(self):
        response = self._toggle("unavailable")
        self.assertEqual(response.status_code, 503, response.text[:300])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_unavailable",
        )


class WolPmsetMissingTests(unittest.TestCase):
    """PUT /api/system/power/wol: vanished-CLI 503 after the disk confirm."""

    def _put(self, sh_result, *, on_disk):
        fake_path = mock.Mock()
        fake_path.return_value.is_file.return_value = on_disk
        with (
            mock.patch.object(power_svc, "sh", return_value=sh_result),
            mock.patch.object(power_svc, "Path", fake_path),
            mock.patch.object(power_router.audit, "record", lambda *a, **k: {}),
        ):
            return _client().put("/api/system/power/wol", json={"enabled": True})

    def test_vanished_pmset_is_the_coded_503(self):
        # Pre-fix: 200 ok:false telling the operator to run sudo pmset by
        # hand — for a binary the disk probe just proved is gone.
        response = self._put((-1, "", "not found"), on_disk=False)
        self.assertEqual(response.status_code, 503, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "power.pmset_missing")

    def test_sentinel_with_pmset_on_disk_keeps_the_ok_false_answer(self):
        # A transient spawn failure while the binary is present must not be
        # upgraded: the sentinel alone does not classify.
        response = self._put((-1, "", "not found"), on_disk=True)
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        self.assertIs(body["ok"], False)
        self.assertIn("sudo pmset -a womp 1", body["message"])

    def test_timeout_sentinel_is_never_classified(self):
        fake_path = mock.Mock()
        with (
            mock.patch.object(power_svc, "sh", return_value=(-1, "", "timeout")),
            mock.patch.object(power_svc, "Path", fake_path),
            mock.patch.object(power_router.audit, "record", lambda *a, **k: {}),
        ):
            response = _client().put("/api/system/power/wol", json={"enabled": True})
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIs(response.json()["ok"], False)
        # Timeouts do not pay the stat — the disk probe is failure-path only.
        fake_path.assert_not_called()

    def test_real_pmset_exit_keeps_the_ok_false_answer(self):
        response = self._put((1, "", "denied"), on_disk=False)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIs(response.json()["ok"], False)


class IdentityValueCapTests(unittest.TestCase):
    """PUT /api/identity: oversized persisted values are a 400, not a save 503."""

    def _put(self, body):
        with (
            mock.patch.object(identity_svc, "update_settings") as saved,
            mock.patch.object(identity_svc, "get_identity", return_value={}),
            mock.patch("hub.routers.unraid_parity.audit.record", lambda *a, **k: {}),
        ):
            response = _client().put("/api/identity", json=body)
        return response, saved

    def test_oversized_comment_is_refused_before_anything_is_written(self):
        response, saved = self._put({"comment": "x" * (identity_svc.MAX_COMMENT + 1)})
        self.assertEqual(response.status_code, 400, response.text[:300])
        _clean(response)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "identity.value_too_long")
        self.assertEqual(detail["params"]["field"], "comment")
        # The refusal happens before the config write — no sibling settings
        # were re-serialized, let alone crowded toward the file's read cap.
        saved.assert_not_called()

    def test_oversized_host_ip_is_refused_before_anything_is_written(self):
        response, saved = self._put({"host_ip": "9" * (identity_svc.MAX_HOST_IP + 1)})
        self.assertEqual(response.status_code, 400, response.text[:300])
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "identity.value_too_long")
        self.assertEqual(detail["params"]["field"], "host_ip")
        saved.assert_not_called()

    def test_boundary_comment_still_persists(self):
        comment = "x" * identity_svc.MAX_COMMENT
        response, saved = self._put({"comment": comment})
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIs(response.json()["ok"], True)
        saved.assert_called_once_with({"server_comment": comment})

    def test_surrogate_comment_is_scrubbed_before_the_cap_and_the_write(self):
        # "\ud800" is legal JSON text and decodes to a real lone surrogate.
        with (
            mock.patch.object(identity_svc, "update_settings") as saved,
            mock.patch.object(identity_svc, "get_identity", return_value={}),
            mock.patch("hub.routers.unraid_parity.audit.record", lambda *a, **k: {}),
        ):
            response = _client().put(
                "/api/identity",
                content=b'{"comment": "rack\\ud800 one"}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        saved.assert_called_once_with({"server_comment": "rack? one"})


class PowerHttpLayerStaysImmunePins(unittest.TestCase):
    """Body-parse and routing corners the service-layer suites never cross."""

    def test_huge_digit_json_body_is_the_parse_400_not_a_500(self):
        # json.loads of a >4300-digit literal raises ValueError, *not*
        # JSONDecodeError; the framework's body guard must still answer 400.
        response = _client().put(
            "/api/system/power/wol",
            content=('{"enabled": ' + _HUGE_DIGITS + "}").encode(),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])
        _clean(response)

    def test_escaped_surrogate_action_keeps_the_coded_400(self):
        # "\ud800" is legal JSON text and decodes to a real lone surrogate;
        # the coded error body itself must stay UTF-8 with it in hand.
        with mock.patch.object(power_router.audit, "record", lambda *a, **k: {}):
            response = _client().post(
                "/api/system/power/action",
                content=b'{"action": "slee\\ud800p", "confirm": true}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 400, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "power.unknown_action")

    def test_unconfirmed_action_keeps_the_coded_400_and_schedules_nothing(self):
        with mock.patch.object(power_svc.threading, "Thread") as thread:
            response = _client().post(
                "/api/system/power/action",
                json={"action": "shutdown", "confirm": False},
            )
        self.assertEqual(response.status_code, 400, response.text[:300])
        self.assertEqual(response.json()["detail"]["code"], "power.confirm_required")
        thread.assert_not_called()


if __name__ == "__main__":
    unittest.main()
