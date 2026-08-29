"""Eighth leftover-500s sweep of the NAS / shares-adjacent surfaces.

nas7 sealed the NFS admin-result laundering and the read-route renders.
This hunt found the class *below* every guard those sweeps installed: a
leftover whose ``__class__`` is a **raising property**.  ``isinstance``
consults ``value.__class__`` when the exact-type check misses, so such a
value detonates the very gates the prior fixes hid behind — every
``isinstance(x, dict)`` / ``isinstance(x, list)`` run against it raises
raw, one step ahead of the laundering built to absorb junk shapes.  Each
of these was a live raw HTTP 500 (traceback, no JSON body) on the mounted
app pre-fix:

* ``nas_common._jsonable``'s rank gates blew ``_rendered`` — a bomb nested
  as a dict *value* 500'd GET /api/nfs, /api/raid, /api/snapshots,
  /api/smart and /api/storage/usage at once;
* ``nas_common._plain_result``'s dict gate blew ``result_ok`` at the
  routes' audit line and both error funnels, and the coded-refusal params
  walk in ``raise_service_error`` blew on a bomb key riding a failure;
* ``nfs_svc._admin_result`` / ``snapshots_svc._admin_result`` /
  ``raid_svc._admin_result`` / ``usage_svc.set_spotlight`` /
  ``smart_test_svc.start_test``/``abort_test`` each gated the raw
  privileged result with a bare ``isinstance`` — a bomb result 500'd the
  mutation after the operator had already typed the admin password;
* ``smart_test_svc.history``'s row gate 500'd GET /api/smart/history,
  ``_schedule_cfg``'s cfg() read 500'd GET /api/smart (and the same raise
  escaped ``schedule_due()`` inside the scheduler tick),
  ``snapshots_svc.list_snapshots``' entry gate 500'd GET /api/snapshots
  out of a poisoned plist row, and ``usage_svc.scan_roots``' per-row gates
  500'd all four usage routes on one poisoned root row;
* ``nfs_svc._validate_entry``'s entry gate raised raw past the router's
  NfsConfigError catch, and ``shares_svc._plain_result`` /
  ``share_acl_svc._plain_result`` blew the share funnels the same way.

The fix is one shared rule (``_isa``): try the gate, and a value that
cannot even answer what it is takes the non-matching branch.  A real
subclass still matches through the C-level type check without touching
``__class__``, so every prior row-bomb guard keeps its salvage semantics.
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

from hub import macos_admin, nfs_svc, raid_svc, smart_test_svc, snapshots_svc, usage_svc  # noqa: E402
from hub import share_acl_svc, shares_svc  # noqa: E402
from hub.routers import nas_common  # noqa: E402

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


class _ClassBomb:
    """A leftover whose ``__class__`` is a raising property.

    ``isinstance(bomb, dict)`` (or any gate the value does not match at the
    C level) raises out of the gate itself — the exact shape the prior
    subclass row-bombs could not reach.
    """

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _StrBombKey:
    """An unrenderable mapping key: ``str()`` raises, hash stays real."""

    def __str__(self):
        raise RuntimeError("str bomb")


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


class ReadRoutesClassBombTests(unittest.TestCase):
    """A __class__ bomb nested in any NAS read payload must render degraded.

    Pre-fix ``nas_common._jsonable``'s first bare gate raised raw and all
    five read pages 500'd (traceback, no JSON body) while every sibling
    field was droppable collateral.
    """

    def test_class_bomb_value_degrades_and_siblings_survive(self):
        payload = {"server": {"detail": _ClassBomb()}, "count": 3, "rows": ["ok"]}
        for label, module, route in (
            ("nfs", nfs_svc, "/api/nfs"),
            ("raid", raid_svc, "/api/raid"),
            ("snapshots", snapshots_svc, "/api/snapshots"),
            ("smart", smart_test_svc, "/api/smart"),
            ("usage", usage_svc, "/api/storage/usage"),
        ):
            with self.subTest(route=label):
                with mock.patch.object(module, "overview", lambda force=False: payload):
                    resp = _client().get(route)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                _starlette(body)
                # The bomb degrades to text; its siblings keep their values.
                self.assertIsInstance(body["server"]["detail"], str)
                self.assertEqual(body["count"], 3)
                self.assertEqual(body["rows"], ["ok"])

    def test_class_bomb_element_in_a_list_still_renders(self):
        # Sequence rank of the same class: the bomb element coerces to text
        # instead of costing the walk.
        cleaned = nas_common._jsonable({"entries": [_ClassBomb(), "real"]})
        _starlette(cleaned)
        self.assertEqual(cleaned["entries"][1], "real")
        self.assertIsInstance(cleaned["entries"][0], str)

    def test_class_bomb_key_drops_alone_and_str_bomb_key_drops_silently(self):
        cleaned = nas_common._jsonable({"good": 1, _StrBombKey(): 2})
        _starlette(cleaned)
        self.assertEqual(cleaned["good"], 1)
        self.assertNotIn("2", json.dumps(cleaned))


class MutationFunnelClassBombTests(unittest.TestCase):
    """A __class__ bomb privileged result answers coded, never raw.

    Pre-fix the bare ``isinstance(result, dict)`` gates in the services'
    ``_admin_result`` launderers — and ``nas_common._plain_result`` under
    the routes' audit line — raised the bomb raw out of every mutation.
    """

    def test_nfs_server_class_bomb_admin_result_answers_coded(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "run_admin_sequence", return_value=_ClassBomb()))
            stack.enter_context(mock.patch.object(
                nfs_svc, "_nfsd_on_disk", return_value=True))
            resp = _client().post("/api/nfs/server", json={"action": "start"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_nfs_server_class_bomb_service_result_survives_the_audit_line(self):
        # result_ok(bomb) is the first read the route makes; pre-fix the
        # audit line 500'd before raise_service_error could answer coded.
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "server_action", return_value=_ClassBomb()))
            resp = _client().post("/api/nfs/server", json={"action": "start"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_nfs_server_class_bomb_param_key_keeps_the_coded_refusal(self):
        # raise_service_error builds the coded body's params from the raw
        # result; pre-fix a bomb key detonated the walk mid-refusal.
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "server_action",
                return_value={"ok": False, "error": "bad_action", _ClassBomb(): 1}))
            resp = _client().post("/api/nfs/server", json={"action": "start"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "nfs.bad_action")

    def test_timemachine_class_bomb_admin_result_answers_coded(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin", return_value=_ClassBomb()))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tmutil_on_disk", return_value=True))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_timemachine_class_bomb_value_in_ok_payload_degrades(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True, "info": _ClassBomb()}))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertIsInstance(payload["info"], str)

    def test_spotlight_class_bomb_admin_result_answers_coded(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status", return_value=[]))
            stack.enter_context(mock.patch.object(
                macos_admin, "run_admin", return_value=_ClassBomb()))
            stack.enter_context(mock.patch.object(
                usage_svc, "_mdutil_on_disk", return_value=True))
            resp = _client().post(
                "/api/storage/spotlight", json={"volume": "/", "enabled": True})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")


class SmartClassBombTests(unittest.TestCase):
    def test_history_class_bomb_row_drops_and_siblings_render(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[_ClassBomb(), {"ts": 5, "device": "/dev/disk0"}],
        ):
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(len(payload["history"]), 1)
        self.assertEqual(payload["history"][0]["device"], "/dev/disk0")

    def test_overview_class_bomb_cfg_falls_back_to_the_default_schedule(self):
        smart_test_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "cfg", return_value=_ClassBomb()))
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "_device_nodes", return_value=[]))
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "passwordless_available", return_value=False))
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "_load_history", return_value=[]))
                resp = _client().get("/api/smart?force=1")
        finally:
            smart_test_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["schedule"]["interval"], "off")

    def test_schedule_cfg_that_raises_outright_falls_back_too(self):
        # The try/except-around-cfg() union guard: a provider that raises
        # instead of answering junk costs the schedule, never the page.
        with mock.patch.object(
            smart_test_svc, "cfg", side_effect=RuntimeError("cfg gone"),
        ):
            self.assertEqual(smart_test_svc._schedule_cfg(), {})


class SnapshotsAndUsageClassBombTests(unittest.TestCase):
    def test_snapshots_class_bomb_plist_row_drops_alone(self):
        snapshots_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_plist",
                    return_value={"Snapshots": [_ClassBomb()]}))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "snapshot_mounts", return_value=["/"]))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_latest_backup", return_value=""))
                resp = _client().get("/api/snapshots?force=1")
        finally:
            snapshots_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["volumes"][0]["mount"], "/")
        self.assertEqual(payload["volumes"][0]["count"], 0)

    def test_usage_class_bomb_root_row_earns_the_coded_no_roots(self):
        # Pre-fix the per-row gate raised raw out of scan_roots and all
        # four usage routes 500'd on the one poisoned row.
        with mock.patch.object(
            usage_svc.files_svc, "default_roots", return_value=[_ClassBomb()],
        ):
            resp = _client().get("/api/storage/usage/tree")
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "files.no_roots")

    def test_usage_class_bomb_root_row_keeps_its_real_siblings(self):
        home = str(Path.home())
        with mock.patch.object(
            usage_svc.files_svc, "default_roots",
            return_value=[_ClassBomb(), {"id": "home", "name": "Home", "path": home}],
        ):
            roots = usage_svc.scan_roots()
        self.assertIn(home, [r["path"] for r in roots])


class ServiceContractClassBombTests(unittest.TestCase):
    """The in-process laundering contracts each service publishes."""

    def test_nfs_validate_entry_class_bomb_earns_the_coded_refusal(self):
        with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
            nfs_svc._validate_entry(_ClassBomb())
        self.assertEqual(ctx.exception.code, "nfs.bad_path")

    def test_admin_result_launderers_degrade_the_bomb_to_coded_failure(self):
        self.assertEqual(
            nfs_svc._admin_result(_ClassBomb()), {"ok": False, "error": "failed"})
        # snapshots/raid answer their pre-existing non-dict shape ({});
        # raise_service_error downstream reads it as the coded failure.
        self.assertEqual(snapshots_svc._admin_result(_ClassBomb()), {})
        self.assertEqual(raid_svc._admin_result(_ClassBomb()), {})
        self.assertEqual(
            shares_svc._plain_result(_ClassBomb()),
            {"ok": False, "error": "failed"})
        self.assertEqual(
            share_acl_svc._plain_result(_ClassBomb()),
            {"ok": False, "error": "failed"})
        self.assertIsNone(nas_common._plain_result(_ClassBomb()))
        self.assertIs(nas_common.result_ok(_ClassBomb()), False)

    def test_real_subclasses_still_match_through_the_c_level_check(self):
        # _isa must not weaken the row-bomb guards: a genuine dict subclass
        # (whose __class__ is never consulted) still matches and its real
        # storage still launders through.
        class _GetBombDict(dict):
            def get(self, *a, **k):
                raise ValueError("get bomb")

        self.assertEqual(
            nfs_svc._admin_result(_GetBombDict({"ok": True})), {"ok": True})
        self.assertEqual(
            nas_common._plain_result(_GetBombDict({"ok": True})), {"ok": True})

    def test_smart_gates_degrade_the_bomb(self):
        self.assertEqual(smart_test_svc._utf8_text(_ClassBomb()), "")
        # A bomb *limit* falls back to the default instead of raising.
        with mock.patch.object(smart_test_svc, "_load_history", return_value=[]):
            self.assertEqual(smart_test_svc.history(_ClassBomb()), [])
        self.assertEqual(snapshots_svc._xid(_ClassBomb()), None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
