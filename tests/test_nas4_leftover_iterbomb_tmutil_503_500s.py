"""Fourth leftover-500s sweep of the NAS routes, over the real mounted app.

The hunted classes (collections that pass ``isinstance`` but refuse
*iteration*, already-int over-cap numbers, vanished-CLI 503-vs-500) were
re-reproduced against ``create_app()`` with ``raise_server_exceptions=False``.
NAS3 (test_nas3_leftover_common_hexint_asgi_pins) sealed the over-cap int
*values*; this hunt found the seams it stepped around.  Each of these was a
live HTTP 500 on the pre-fix tree:

* every NAS ``_jsonable`` copy (``nas_common``, ``snapshots_svc``,
  ``raid_svc``, ``smart_test_svc``) iterated ``value.items()`` and sequence
  members unguarded — the exact class the UPS/Gateway sweeps fixed in
  ``ups_svc``/``ups_policy``/``nginx_svc``: a dict subclass whose ``items()``
  raises, or a list subclass whose ``__iter__`` raises, passed the
  ``isinstance`` gate inside a privileged ok payload and 500'd
  POST /api/snapshots/*, /api/raid/*, /api/smart/abort and every other route
  whose response body is the cleaned result.  Fixed by materializing the
  iteration under its own guard: the unreadable field collapses to None, its
  siblings survive;
* ``nas_common.raise_for_admin_result`` / ``raise_service_error`` rendered
  the failure result's ``error`` field with a bare ``str()`` — an over-cap
  *already-int* error (YAML/plist hex loads uncapped through ``int(x, 16)``)
  raised the digit-cap ValueError out of the route as an unhandled 500 in
  place of the coded ``admin.failed``; ``raise_service_error`` additionally
  iterated ``result.items()`` for the coded error's extras, so an items-bomb
  failure dict 500'd the coded refusal itself;
* a vanished ``tmutil`` (OS update mid-flight, dying system volume) surfaced
  as the generic 500 ``admin.failed`` — "the privileged macOS operation
  failed" sends the operator back to a password dialog that cannot help.
  Every sibling NAS CLI (nfsd, diskutil, smartctl, mdutil) already answers a
  coded 503 after a fresh disk probe on the failure path only;
  ``snapshots_svc`` now classifies ``tmutil_missing`` the same way and the
  router maps it to the new ``snapshot.tmutil_missing`` (503);
* in-process str() probes the sibling services already carry
  (``raid_svc._req_text`` / ``smart_test_svc._schedule_text``):
  ``usage_svc.set_spotlight`` str()'d an over-cap volume (digit-cap
  ValueError), ``snapshots_svc.delete_snapshot`` TypeError'd fullmatch on a
  non-str token, and ``macos_admin._validate`` str()'d each argv part — all
  now earn their coded refusals.
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

from hub import macos_admin, raid_svc, smart_test_svc, snapshots_svc, usage_svc  # noqa: E402
from hub.routers import nas_common, nas_storage  # noqa: E402

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


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


class _ItemsBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment items() is read."""

    def items(self):
        raise ValueError("items bomb")


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as nas_common resolves one."""
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))
    stack.enter_context(mock.patch.object(
        nas_storage.audit, "record", lambda *a, **k: {}))


class OkPayloadIterationBombTests(unittest.TestCase):
    """Iteration-refusing collections in a privileged ok payload: the fix.

    Pre-fix, both shapes raised out of ``nas_common._jsonable`` and 500'd
    the mounted route.  The unreadable field must collapse to None while its
    siblings — including ``ok`` itself — survive.
    """

    def _create(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "create_snapshot",
                return_value=result))
            return _client().post("/api/snapshots/create")

    def test_items_bomb_value_salvages_its_storage_not_a_500(self):
        # shares6 upgraded the sanitizer to the modules5 unbound
        # ``dict.items`` view: the hostile override cannot fire, so the real
        # C-level storage survives instead of collapsing to None.  The
        # original point stands either way: the route answers 200.
        resp = self._create({
            "ok": True, "name": "com.apple.TimeMachine.2026-08-25",
            "log": _ItemsBombDict({"a": 1}),
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["log"], {"a": 1})
        self.assertEqual(body["name"], "com.apple.TimeMachine.2026-08-25")

    def test_iter_bomb_sequence_value_salvages_its_storage(self):
        # shares7 upgraded the sanitizer to the unbound base ``__iter__``
        # walk: the hostile override cannot fire, so the real C-level
        # storage survives instead of collapsing to None.  The original
        # point stands either way: the route answers 200.
        resp = self._create({"ok": True, "tokens": _IterBombList(["x"])})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["tokens"], ["x"])


class FailureResultHostileShapeTests(unittest.TestCase):
    """Hostile failure results must keep their coded answer, never a 500."""

    def _tm_action(self, result):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "time_machine_action",
                return_value=result))
            return _client().post(
                "/api/timemachine/action", json={"action": "start"})

    def test_items_bomb_failure_result_keeps_the_coded_400(self):
        # Pre-fix: raise_service_error iterated result.items() for the coded
        # error's extras and the bomb 500'd the refusal itself.
        resp = self._tm_action(_ItemsBombDict({
            "ok": False, "error": "bad_action",
        }))
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "snapshot.bad_action")

    def test_over_cap_int_error_field_degrades_to_coded_admin_failed(self):
        # Pre-fix: the bare str(result["error"]) raised the digit-cap
        # ValueError out of the route — an unhandled 500 with no JSON body.
        resp = self._tm_action({"ok": False, "error": _HUGE_INT})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")

    def test_over_cap_int_error_field_through_raise_for_admin_result(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nas_storage.snapshots_svc, "create_snapshot",
                return_value={"ok": False, "error": _HUGE_INT}))
            resp = _client().post("/api/snapshots/create")
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")

    def test_surrogate_error_field_stays_coded_and_utf8_clean(self):
        resp = self._tm_action({"ok": False, "error": "fail\ud800ed"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "admin.failed")
        self.assertNotIn("\ud800", resp.text)


class ServiceJsonableIterationBombTests(unittest.TestCase):
    """The service-level _jsonable copies own the same guard: run_admin's
    result is cleaned in snapshots_svc/raid_svc/smart_test_svc before the
    router ever sees it, and each copy 500'd its mutation pre-fix."""

    def test_snapshots_delete_survives_an_items_bomb_run_admin_result(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "snapshot_mounts", return_value=["/"]))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True, "detail": _ItemsBombDict({"a": 1})}))
            resp = _client().post("/api/snapshots/delete", json={
                "mount": "/", "date_token": "2026-08-01-120000",
                "confirm": True,
            })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["detail"])

    def test_raid_delete_survives_an_items_bomb_run_admin_result(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                raid_svc, "list_sets",
                return_value=[{"uuid": "ABCDEF01-1111", "name": "tank",
                               "level": "mirror", "members": [],
                               "member_count": 0}]))
            stack.enter_context(mock.patch.object(
                raid_svc, "run_admin",
                return_value={"ok": True, "detail": _ItemsBombDict({"a": 1})}))
            resp = _client().post("/api/raid/delete", json={
                "set_uuid": "ABCDEF01-1111", "confirm": True,
                "confirm_phrase": "tank",
            })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        # nas8 upgraded raid_svc._jsonable to the unbound ``dict.items``
        # view (the nas_common rule): the bomb's override no longer fires
        # at all, so the field's real C-level storage is salvaged rather
        # than dropped.
        self.assertEqual(body["detail"], {"a": 1})

    def test_smart_abort_survives_an_iter_bomb_run_admin_result(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes",
                return_value=["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", return_value=()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh",
                return_value=(1, "", "permission denied")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin",
                return_value={"ok": True, "rows": _IterBombList(["x"])}))
            resp = _client().post(
                "/api/smart/abort", json={"device": "/dev/disk0"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["rows"])

    def test_jsonable_field_isolation_contract(self):
        for mod in (snapshots_svc, raid_svc, smart_test_svc):
            with self.subTest(module=mod.__name__):
                row = mod._jsonable({
                    "id": "tank",
                    "extras": _ItemsBombDict({"x": 1}),
                    "members": _IterBombList(["a"]),
                    "count": 2,
                })
                _starlette(row)
                self.assertEqual(row["id"], "tank")
                if mod is raid_svc:
                    # nas8: raid reads the unbound ``dict.items`` view, so
                    # the bomb's own storage is salvaged, not dropped.
                    self.assertEqual(row["extras"], {"x": 1})
                else:
                    self.assertIsNone(row["extras"])
                self.assertIsNone(row["members"])
                self.assertEqual(row["count"], 2)


class VanishedTmutilTests(unittest.TestCase):
    """tmutil confirmed vanished answers the coded 503, not admin.failed.

    Every sibling NAS CLI (nfsd, diskutil, smartctl, mdutil) already had the
    confirmed-vanished classification; snapshots_svc was the leftover.  The
    disk probe runs on the failure path only, and only the generic ``failed``
    shape is eligible — an on-disk tmutil, a cancelled sheet or a password
    failure keeps its original answer.
    """

    def _create_with_sh(self, sh_result, *, on_disk=False):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh", return_value=sh_result))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tmutil_on_disk", return_value=on_disk))
            return _client().post("/api/snapshots/create")

    def test_vanished_tmutil_on_create_answers_the_coded_503(self):
        # sh() collapses a FileNotFoundError spawn into (-1, "", "not found").
        resp = self._create_with_sh((-1, "", "not found"))
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "snapshot.tmutil_missing")

    def test_vanished_tmutil_on_time_machine_action_answers_503(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={
                    "ok": False, "error": "failed",
                    "message": "sh: /usr/bin/tmutil: command not found",
                }))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tmutil_on_disk", return_value=False))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "snapshot.tmutil_missing")

    def test_vanished_tmutil_on_snapshot_delete_and_thin_answers_503(self):
        gone = {
            "ok": False, "error": "failed",
            "message": "sh: /usr/bin/tmutil: No such file or directory",
        }
        for path, payload in (
            ("/api/snapshots/delete",
             {"mount": "/", "date_token": "2026-08-01-120000",
              "confirm": True}),
            ("/api/snapshots/thin", {"mount": "/", "urgency": 1}),
        ):
            with self.subTest(path=path):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        snapshots_svc, "snapshot_mounts",
                        return_value=["/"]))
                    stack.enter_context(mock.patch.object(
                        snapshots_svc, "run_admin", return_value=gone))
                    stack.enter_context(mock.patch.object(
                        snapshots_svc, "_tmutil_on_disk",
                        return_value=False))
                    resp = _client().post(path, json=payload)
                self.assertEqual(resp.status_code, 503, resp.text[:200])
                self.assertEqual(
                    resp.json()["detail"]["code"],
                    "snapshot.tmutil_missing")

    def test_on_disk_tmutil_keeps_the_raw_failure(self):
        # The message pattern alone must not classify: with tmutil still on
        # disk the raw failure is the truth (the disk-confirm rule).
        resp = self._create_with_sh((-1, "", "not found"), on_disk=True)
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")

    def test_ordinary_failure_keeps_admin_failed_without_probing(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "sh",
                return_value=(1, "", "tmutil: operation not permitted")))
            probe = stack.enter_context(mock.patch.object(
                snapshots_svc, "_tmutil_on_disk", return_value=False))
            resp = _client().post("/api/snapshots/create")
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.failed")
        # Failure path only, and only for a vanished-looking message.
        probe.assert_not_called()

    def test_cancelled_sheet_keeps_its_409_shape(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": False, "error": "cancelled"}))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tmutil_on_disk", return_value=False))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "stop"})
        self.assertEqual(resp.status_code, 409, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "admin.cancelled")


class InProcessStrProbeTests(unittest.TestCase):
    """The str() probes the sibling services already carry (raid_svc._req_text
    / smart_test_svc._schedule_text convention): the routes hand these over as
    str through Pydantic, but the services are also called in-process."""

    def test_set_spotlight_over_cap_volume_earns_bad_volume(self):
        # Pre-fix: the bare str(volume) raised the digit-cap ValueError.
        result = usage_svc.set_spotlight(_HUGE_INT, True)
        self.assertEqual(result, {"ok": False, "error": "bad_volume"})

    def test_set_spotlight_numeric_volume_behaves_as_its_string_form(self):
        # A finite numeric keeps behaving as its string form and earns the
        # same coded refusal path (never a crash).
        with mock.patch.object(usage_svc, "spotlight_status", return_value=[]):
            result = usage_svc.set_spotlight(7, True)
        self.assertEqual(result, {"ok": False, "error": "bad_volume"})

    def test_delete_snapshot_non_str_token_earns_bad_token(self):
        # Pre-fix: fullmatch(int) was TypeError, fullmatch(huge int) never
        # even got that far — str() in the old ``or ""`` path could not run.
        # subTest label, not the value: unittest renders params with str(),
        # which the over-cap int itself would trip.
        for label, token in (
            ("over_cap_int", _HUGE_INT),
            ("int", 123456),
            ("none", None),
            ("object", object()),
        ):
            with self.subTest(token=label):
                result = snapshots_svc.delete_snapshot("/", token)
                self.assertEqual(result, {"ok": False, "error": "bad_token"})

    def test_run_admin_over_cap_argv_part_earns_invalid_command(self):
        # Pre-fix: _validate's bare str(part) raised the digit-cap
        # ValueError out of run_admin instead of the coded refusal.
        result = macos_admin.run_admin(["/usr/bin/tmutil", _HUGE_INT])
        self.assertEqual(result, {"ok": False, "error": "invalid_command"})

    def test_validate_still_joins_an_ordinary_sequence(self):
        joined = macos_admin._validate(
            [["/usr/bin/tmutil", "localsnapshot"], ["/bin/chmod", "644", "/etc/exports"]]
        )
        self.assertEqual(
            joined,
            "/usr/bin/tmutil localsnapshot; /bin/chmod 644 /etc/exports",
        )


class NasCommonJsonableIterationContractTests(unittest.TestCase):
    """The shared sanitizer's field-isolation contract (fails pre-fix)."""

    def test_items_bomb_salvages_the_field_not_the_row(self):
        # shares6 upgraded the sanitizer to the modules5 unbound
        # ``dict.items`` view: the hostile override cannot fire, so the real
        # C-level storage survives instead of collapsing to None.
        row = nas_common._jsonable({
            "ok": True,
            "extras": _ItemsBombDict({"x": 1}),
            "port": 2049,
        })
        _starlette(row)
        self.assertIs(row["ok"], True)
        self.assertEqual(row["extras"], {"x": 1})
        self.assertEqual(row["port"], 2049)

    def test_iter_bomb_salvages_the_field_not_the_row(self):
        # shares7 upgraded the sanitizer to the unbound base ``__iter__``
        # walk: the hostile override cannot fire, so the real C-level
        # storage survives instead of collapsing to None.
        row = nas_common._jsonable({
            "ok": True,
            "clients": _IterBombList(["10.0.0.0/24"]),
            "count": 1,
        })
        _starlette(row)
        self.assertIs(row["ok"], True)
        self.assertEqual(row["clients"], ["10.0.0.0/24"])
        self.assertEqual(row["count"], 1)

    def test_top_level_items_bomb_ok_result_still_answers_ok(self):
        # raise_for_admin_result: .get() works on the subclass and the route
        # must answer ok rather than 500.  Since shares6 the unbound
        # ``dict.items`` view salvages the real storage, so the sibling key
        # rides along instead of being collapsed away with the bomb.
        cleaned = nas_common.raise_for_admin_result(
            _ItemsBombDict({"ok": True, "x": 1}))
        self.assertEqual(cleaned, {"ok": True, "x": 1})
        _starlette(cleaned)


if __name__ == "__main__":
    unittest.main(verbosity=2)
