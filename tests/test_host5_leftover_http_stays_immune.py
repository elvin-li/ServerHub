"""Fifth leftover-500s sweep of the Host / identity / screensharing / pmset
routes, over the real app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap, huge-number JSON bodies where ``json.loads`` raises
ValueError not JSONDecodeError, numeric YAML settings reaching a ``str()``
probe, vanished-CLI classification after a fresh disk confirm on the failure
path, non-string error values in the screensharing code map) were
re-reproduced against the mounted routes through ``create_app()`` +
``TestClient(raise_server_exceptions=False)``.  One live leftover was found
and is fixed alongside this file:

* POST /api/settings/power (the Settings page's pmset writer) with a pmset
  that vanished from disk answered ``200 {"ok": false, "message":
  "not found · run manually: sudo pmset -a sleep 10"}`` — blaming privileges
  for a binary that is gone (the sudo fallback cannot spawn it either).  The
  identical leftover was fixed for PUT /api/system/power/wol in the host4
  sweep, but this second pmset writer kept the old shape.  Now the identity
  ``_scutil_missing`` / power ``_pmset_missing`` rule: the spawn sentinel
  ``(-1, "", "not found")`` plus a fresh on-disk probe *on the failure path
  only* raises the coded 503 ``power.pmset_missing``.  A timeout sentinel or
  a real pmset exit keeps the old ok:false shape, and the sentinel with the
  binary still on disk is never upgraded.

The rest pins HTTP-layer corners of the same domain that the host3/host4
suites never crossed (the /api/settings/power body parse and render, the
screensharing failure branch fed non-string error containers, numeric YAML
identity settings).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest import mock

from fastapi.testclient import TestClient

from hub import identity_svc, power_svc, system_settings_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import power as power_router

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
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


class SettingsPowerPmsetMissingTests(unittest.TestCase):
    """POST /api/settings/power: vanished-CLI 503 after the disk confirm.

    The live leftover: the Settings page's pmset writer kept the pre-host4
    ok:false shape for a binary the disk probe proves is gone.
    """

    def _post(self, sh_result, *, on_disk):
        fake_path = mock.Mock()
        fake_path.return_value.is_file.return_value = on_disk
        with (
            mock.patch.object(system_settings_svc, "sh", return_value=sh_result),
            mock.patch.object(power_svc, "Path", fake_path),
            mock.patch("hub.routers.unraid_parity.audit.record", lambda *a, **k: {}),
        ):
            response = _client().post(
                "/api/settings/power", json={"key": "sleep", "value": 10},
            )
        return response, fake_path

    def test_vanished_pmset_is_the_coded_503(self):
        # Pre-fix: 200 ok:false telling the operator to run sudo pmset by
        # hand — for a binary the disk probe just proved is gone.
        response, _ = self._post((-1, "", "not found"), on_disk=False)
        self.assertEqual(response.status_code, 503, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "power.pmset_missing")

    def test_sentinel_with_pmset_on_disk_keeps_the_ok_false_answer(self):
        # A transient spawn failure while the binary is present must not be
        # upgraded: the sentinel alone does not classify.
        response, _ = self._post((-1, "", "not found"), on_disk=True)
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        self.assertIs(body["ok"], False)
        self.assertIn("sudo pmset -a sleep 10", body["message"])

    def test_timeout_sentinel_is_never_classified(self):
        response, fake_path = self._post((-1, "", "timeout"), on_disk=False)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIs(response.json()["ok"], False)
        # Timeouts do not pay the stat — the disk probe is failure-path only.
        fake_path.assert_not_called()

    def test_real_pmset_exit_keeps_the_ok_false_answer(self):
        response, fake_path = self._post((1, "", "denied"), on_disk=False)
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        self.assertIs(body["ok"], False)
        self.assertIn("denied", body["message"])
        fake_path.assert_not_called()

    def test_successful_write_keeps_the_ok_true_answer(self):
        response, fake_path = self._post((0, "", ""), on_disk=True)
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["key"], "sleep")
        self.assertEqual(body["value"], 10)
        # The ok path never pays the stat either.
        fake_path.assert_not_called()


class SettingsPowerHttpStaysImmunePins(unittest.TestCase):
    """Body-parse and render corners of the /api/settings/power surface."""

    def test_huge_digit_json_body_is_the_parse_400_not_a_500(self):
        # json.loads of a >4300-digit literal raises ValueError, *not*
        # JSONDecodeError; the framework's body guard must still answer 400.
        response = _client().post(
            "/api/settings/power",
            content=('{"key": "sleep", "value": ' + _HUGE_DIGITS + "}").encode(),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])
        _clean(response)

    def test_huge_digit_string_value_is_the_validation_422_not_a_500(self):
        # A >4300-digit *string* value reaches pydantic's lax int coercion,
        # whose own parse cap must answer 422 — int("9"*5000) is ValueError.
        with mock.patch("hub.routers.unraid_parity.audit.record", lambda *a, **k: {}):
            response = _client().post(
                "/api/settings/power", json={"key": "sleep", "value": _HUGE_DIGITS},
            )
        self.assertEqual(response.status_code, 422, response.text[:300])
        _clean(response)

    def test_huge_float_value_is_the_validation_422_not_a_500(self):
        # 1e400 parses to JSON inf; 1e308 is finite but int(1e308) would be a
        # 309-digit int — both must stay coded validation refusals.
        for literal in (b'{"key": "sleep", "value": 1e400}',
                        b'{"key": "sleep", "value": 1e308}'):
            with mock.patch(
                "hub.routers.unraid_parity.audit.record", lambda *a, **k: {},
            ):
                response = _client().post(
                    "/api/settings/power",
                    content=literal,
                    headers={"content-type": "application/json"},
                )
            self.assertEqual(response.status_code, 422, response.text[:300])
            _clean(response)

    def test_escaped_surrogate_key_keeps_the_coded_soft_fail(self):
        # "\ud800" is legal JSON text and decodes to a real lone surrogate;
        # the soft-fail body (a 200 dict contract) must itself stay UTF-8.
        with mock.patch("hub.routers.unraid_parity.audit.record", lambda *a, **k: {}):
            response = _client().post(
                "/api/settings/power",
                content=b'{"key": "sle\\ud800ep", "value": 3}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        body = response.json()
        self.assertIs(body["ok"], False)
        self.assertEqual(body["code"], "power.bad_key")

    def test_surrogate_and_huge_digit_pmset_output_render_clean(self):
        # GET /api/settings/power: pmset stdout with a lone surrogate in a
        # key and a >4300-digit value must render as clean UTF-8 JSON —
        # int(val) of the huge probe is ValueError (str->int cap), and the
        # raw string must survive _json_tree without tripping the encoder.
        system_settings_svc.get_power_info.invalidate()
        self.addCleanup(system_settings_svc.get_power_info.invalidate)
        with mock.patch.object(
            system_settings_svc, "sh",
            return_value=(0, f"womp\ud800 1\n sleep {_HUGE_DIGITS}\n", ""),
        ):
            response = _client().get("/api/settings/power")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        body = response.json()
        # The huge probe passes isdigit() but not int(); it survives as the
        # raw string rather than crashing the render.
        self.assertEqual(body["settings"].get("sleep"), _HUGE_DIGITS)
        # The surrogate-keyed row fails the parser's isalpha() gate and is
        # dropped before it can reach the encoder (the UPS leg's raw echo of
        # the same probe output carries only the scrubbed "womp?").
        self.assertNotIn("womp", body["settings"])
        self.assertNotIn("womp?", body["settings"])


class ScreensharingErrorContainerPins(unittest.TestCase):
    """The failure branch fed non-string error containers.

    host4 pinned over-cap ints, recursive ``__str__`` and bytes; these pin
    dict/list leftovers, whose ``str()`` is a Python repr that must miss the
    code map and answer the generic coded 500 — never crash the lookup.
    """

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

    def test_dict_error_is_a_coded_body_not_a_raw_500(self):
        response = self._toggle({"un": "hashable"})
        self.assertEqual(response.status_code, 500, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "shares.operation_failed")

    def test_list_error_never_matches_its_element_codes(self):
        # ["cancelled"] must not be treated as "cancelled": the repr misses
        # the map and answers the generic coded 500, not the 409.
        response = self._toggle(["cancelled"], enable=False)
        self.assertEqual(response.status_code, 500, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["detail"]["code"], "shares.operation_failed")

    def test_bytes_unavailable_matches_its_coded_503(self):
        # The sibling of host4's b"cancelled" pin: the decode, not the repr,
        # is what reaches the code map.
        response = self._toggle(b"unavailable")
        self.assertEqual(response.status_code, 503, response.text[:300])
        _clean(response)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_unavailable",
        )


class IdentityHttpStaysImmunePins(unittest.TestCase):
    """Numeric YAML settings and body-parse corners of /api/identity."""

    def test_huge_digit_json_body_is_the_parse_400_not_a_500(self):
        response = _client().put(
            "/api/identity",
            content=('{"comment": ' + _HUGE_DIGITS + "}").encode(),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400, response.text[:300])
        _clean(response)

    def test_numeric_computer_name_is_the_validation_422_not_a_500(self):
        # A numeric YAML-style id must be refused by validation before any
        # str() probe can run against it.
        with mock.patch("hub.routers.unraid_parity.audit.record", lambda *a, **k: {}):
            response = _client().put("/api/identity", json={"computer_name": 12345})
        self.assertEqual(response.status_code, 422, response.text[:300])
        _clean(response)

    def test_over_cap_int_yaml_comment_renders_empty_not_a_500(self):
        # A leftover >4300-digit int under settings.server_comment reaches
        # identity_svc._as_text, whose str() probe is ValueError (CPython's
        # int->str digit cap); the field must degrade to "" rather than 500.
        with mock.patch.object(
            identity_svc, "cfg",
            return_value={"settings": {"server_comment": 16 ** 5000}},
        ):
            response = _client().get("/api/identity")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["comment"], "")

    def test_small_numeric_yaml_comment_renders_as_text(self):
        # The str() probe exists to keep ordinary numeric YAML working.
        with mock.patch.object(
            identity_svc, "cfg", return_value={"settings": {"server_comment": 42}},
        ):
            response = _client().get("/api/identity")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["comment"], "42")


if __name__ == "__main__":
    unittest.main()
