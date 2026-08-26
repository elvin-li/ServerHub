"""Leftover UPS 500s: values that pass the isinstance gates but refuse
*iteration*, and over-cap int rows that wiped their sane siblings.

Prior UPS sweeps sealed the payloads field by field — surrogate keys and
values, already-int over-cap numbers, inf/NaN floats, poisoned state files
(test_ups_leftover_hexint_surrogate_vanish_500s,
test_ups_leftover_stays_immune_pins) — and the state machine itself
(test_ups_policy).  A fresh hunt over the same mounted routes found the
shape all of those passes stepped around, the same class the Gateway sweep
fixed in ``nginx_svc`` (test_leftover_gateway_iterbomb_sibling_wipe_500s):
collections that pass ``isinstance`` but raise the moment they are
iterated.  The seams these routes consume (``ups_policy._list_stacks``,
``cfg()``, ``ups_svc.ups_snapshot``) are exactly what tests and odd
deployments replace, so the consumer owns the guard.  Confirmed against the
mounted app before fixing — each of these was an HTTP 500:

* a list *subclass* whose ``__iter__`` raises from ``_list_stacks()``: it
  passed the seam call inside ``build_plan``/``_catalog``'s ``try`` without
  raising (returning does not iterate) and blew up the scrub comprehension
  *outside* it — 500ing GET /api/ups/shutdown/plan and
  POST /api/ups/shutdown/drill, i.e. the whole UPS settings form;
* the same shape under ``cfg()["scripts"]``: ``isinstance(raw, list)``
  passes for the subclass and the picker loop 500'd the catalog;
* a dict-subclass whose ``items()`` raises as a snapshot value
  (``halt_levels``), as ``settings.ups``, or as its ``shutdown`` block:
  both ``_jsonable`` copies and the ``ups_settings`` merge comprehensions
  called ``items()`` unguarded and 500'd GET /api/ups;
* an already-int over-cap stack ``id``/``name`` in one listing row (YAML
  hex loads through ``int(raw, 16)``, exempt from CPython's digit cap):
  the bare ``str()`` renders in ``build_plan``/``_catalog`` raised the
  digit-cap ValueError and wiped every sane sibling stack out of the plan
  with the 500 — the exact sibling-row wipe this sweep hunts.

The fix keeps the blast radius one field/row wide: both ``_jsonable``
copies materialize mapping items and sequence iteration under their own
guard (an unreadable collection collapses to None, its siblings survive);
``build_plan``/``_catalog`` materialize the stack listing inside the
existing ``try`` and render ids/names through the ``_cfg_text`` str()
probe so a poisoned row drops alone; ``ups_settings`` and
``_normalized_shutdown`` fall back to the defaults when the stored
mapping refuses iteration; ``_service_states`` isolates hostile groups
and rows instead of losing every sibling's state.

The rest of this battery pins vectors the same hunt found already immune,
held at the HTTP layer so a refactor cannot quietly reopen them: an
items-bomb stack *row* (only ``.get`` is consumed, so its readable id
survives), hostile values inside the drill's status dict, inf floats in
the snapshot, and a surrogate stack name riding the plan catalog.
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

import hub.config as config  # noqa: E402
from hub import ups_policy, ups_svc  # noqa: E402

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


def _get_plan(stacks=None, scripts_cfg=None):
    """GET /api/ups/shutdown/plan with the seams replaced."""
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(
            ups_policy, "_list_stacks",
            mock.Mock(return_value=[] if stacks is None else stacks),
        ))
        stack.enter_context(mock.patch.object(
            config, "cfg",
            lambda: {"scripts": [] if scripts_cfg is None else scripts_cfg},
        ))
        stack.enter_context(mock.patch.object(
            ups_policy, "_ups_status", lambda: {"present": False},
        ))
        stack.enter_context(mock.patch.object(
            ups_svc, "cfg", lambda: {"settings": {}},
        ))
        return _client().get("/api/ups/shutdown/plan")


def _get_ups(snapshot=None, cfg_doc=None):
    """GET /api/ups with the snapshot and config seams replaced."""
    snap = snapshot if snapshot is not None else {
        "present": False, "halt_levels": None,
    }
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(
            ups_svc, "ups_snapshot", lambda force=False: snap,
        ))
        stack.enter_context(mock.patch.object(
            ups_svc, "cfg",
            lambda: {"settings": {}} if cfg_doc is None else cfg_doc,
        ))
        return _client().get("/api/ups")


class PlanIterationBombTests(unittest.TestCase):
    """Iteration-refusing collections from the seams: the fix."""

    def test_iter_bomb_stack_listing_reads_as_empty_not_500(self):
        # Pre-fix: the subclass passed the try (returning does not iterate)
        # and the scrub comprehension outside it 500'd the mounted route.
        resp = _get_plan(stacks=_IterBombList([{"id": "immich"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["steps"], [])
        self.assertEqual(body["catalog"]["stacks"], [])

    def test_drill_route_survives_the_iter_bomb_listing(self):
        from hub.routers import ups_api

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_api, "require_admin_browser", lambda request: "admin",
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks",
                mock.Mock(return_value=_IterBombList([])),
            ))
            stack.enter_context(mock.patch.object(
                config, "cfg", lambda: {"scripts": []},
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {"present": False},
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {}},
            ))
            resp = _client().post("/api/ups/shutdown/drill")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_iter_bomb_scripts_config_drops_the_picker_not_the_route(self):
        resp = _get_plan(
            stacks=[{"id": "sane", "name": "Sane", "status": "ok"}],
            scripts_cfg=_IterBombList([{"id": "gravity"}]),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["catalog"]["scripts"], [])
        # The unreadable scripts list must not take the stacks down with it.
        self.assertEqual(
            [s["id"] for s in body["catalog"]["stacks"]], ["sane"],
        )


class PlanOverCapRowSiblingWipeTests(unittest.TestCase):
    """One poisoned listing row used to wipe every sane sibling: the fix."""

    def test_over_cap_int_stack_id_row_drops_alone(self):
        resp = _get_plan(stacks=[
            {"id": _HUGE_INT, "name": "poison", "status": "ok"},
            {"id": "sane", "name": "Sane", "status": "ok"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [s["id"] for s in body["catalog"]["stacks"]], ["sane"],
        )
        # Policy defaults to stacks="all": the plan steps survive too.
        self.assertEqual([s["id"] for s in body["steps"]], ["sane"])
        self.assertTrue(body["steps"][0]["running"])

    def test_over_cap_int_stack_name_falls_back_to_the_id(self):
        resp = _get_plan(stacks=[
            {"id": "ok1", "name": _HUGE_INT, "status": "ok"},
            {"id": "sane", "name": "Sane", "status": "idle"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {s["id"]: s for s in body["catalog"]["stacks"]}
        self.assertEqual(rows["ok1"]["name"], "ok1")
        self.assertEqual(rows["sane"]["name"], "Sane")
        steps = {s["id"]: s for s in body["steps"]}
        self.assertEqual(steps["ok1"]["name"], "ok1")


class ServiceStatesSiblingIsolationTests(unittest.TestCase):
    """One hostile status group must not erase every sibling's state."""

    def _states(self, groups):
        with mock.patch(
            "hub.status.full_status", return_value={"groups": groups},
        ):
            return ups_policy._service_states()

    def test_iter_bomb_services_group_drops_alone(self):
        # Pre-fix the raise escaped mid-scan and build_plan's fallback
        # blanked *all* states — every service step then read not-running.
        states = self._states([
            {"services": _IterBombList([{"id": "poisoned", "state": "ok"}])},
            {"services": [{"id": "gravity", "state": "ok"}]},
        ])
        self.assertEqual(states, {"gravity": "ok"})

    def test_iter_bomb_groups_list_reads_as_empty(self):
        states = self._states(_IterBombList([{"services": []}]))
        self.assertEqual(states, {})

    def test_over_cap_int_service_id_row_drops_alone(self):
        states = self._states([{"services": [
            {"id": _HUGE_INT, "state": "ok"},
            {"id": "gravity", "state": "warn"},
        ]}])
        self.assertEqual(states, {"gravity": "warn"})

    def test_over_cap_int_state_reads_as_unknown_not_fatal(self):
        states = self._states([{"services": [
            {"id": "gravity", "state": _HUGE_INT},
        ]}])
        self.assertEqual(states, {"gravity": "unknown"})


class UpsStatusIterationBombTests(unittest.TestCase):
    """GET /api/ups over mappings/sequences that refuse iteration: the fix."""

    def test_items_bomb_halt_levels_collapses_the_field_not_the_route(self):
        resp = _get_ups(snapshot={
            "present": True, "kind": "ups", "name": "APC", "source": "ups",
            "on_ac": False, "on_battery": True, "battery_percent": 42,
            "charging": False, "time_remaining_min": 30,
            "halt_levels": _ItemsBombDict({"haltlevel": 50}),
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["halt_levels"])
        # The unreadable mapping drops alone; its siblings survive.
        self.assertTrue(body["present"])
        self.assertEqual(body["battery_percent"], 42)

    def test_iter_bomb_sequence_value_collapses_the_field(self):
        resp = _get_ups(snapshot={
            "present": True, "halt_levels": None,
            "junk": _IterBombList([1, 2]),
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["junk"])
        self.assertTrue(body["present"])

    def test_items_bomb_settings_ups_falls_back_to_defaults(self):
        resp = _get_ups(cfg_doc={
            "settings": {"ups": _ItemsBombDict({"low_battery_pct": 55})},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["settings"]["low_battery_pct"], 20)
        self.assertFalse(body["settings"]["shutdown"]["enabled"])

    def test_items_bomb_shutdown_block_falls_back_to_defaults(self):
        resp = _get_ups(cfg_doc={
            "settings": {"ups": {
                "low_battery_pct": 33,
                "shutdown": _ItemsBombDict({"enabled": True}),
            }},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The readable flat key beside the bomb still applies.
        self.assertEqual(body["settings"]["low_battery_pct"], 33)
        shutdown = body["settings"]["shutdown"]
        self.assertFalse(shutdown["enabled"])
        self.assertEqual(shutdown["trigger_pct"], 25)


class JsonableFieldIsolationPinTests(unittest.TestCase):
    """Both _jsonable copies collapse the unreadable field, not the row."""

    def test_nested_items_bomb_collapses_the_field_not_the_row(self):
        for mod in (ups_svc, ups_policy):
            with self.subTest(module=mod.__name__):
                row = mod._jsonable({
                    "id": "immich",
                    "extras": _ItemsBombDict({"x": 1}),
                    "steps": [1, 2],
                })
                _starlette(row)
                self.assertEqual(row["id"], "immich")
                self.assertIsNone(row["extras"])
                self.assertEqual(row["steps"], [1, 2])

    def test_nested_iter_bomb_sequence_collapses_the_field_not_the_row(self):
        for mod in (ups_svc, ups_policy):
            with self.subTest(module=mod.__name__):
                row = mod._jsonable({
                    "id": "immich",
                    "targets": _IterBombList(["a"]),
                    "pct": 42,
                })
                _starlette(row)
                self.assertEqual(row["id"], "immich")
                self.assertIsNone(row["targets"])
                self.assertEqual(row["pct"], 42)


class AlreadyImmuneRoutePinTests(unittest.TestCase):
    """Vectors the hunt found already immune, pinned at the HTTP layer."""

    def test_items_bomb_stack_row_keeps_its_readable_id_and_sibling(self):
        # The plan consumes rows through .get() only, so an items-bomb row
        # with a readable id still renders — and must not 500 the route.
        resp = _get_plan(stacks=[
            _ItemsBombDict({"id": "poison", "status": "ok"}),
            {"id": "sane", "name": "Sane", "status": "ok"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [s["id"] for s in body["catalog"]["stacks"]], ["poison", "sane"],
        )

    def test_hostile_values_inside_the_drill_status_drop_field_level(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", mock.Mock(return_value=[]),
            ))
            stack.enter_context(mock.patch.object(
                config, "cfg", lambda: {"scripts": []},
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {
                    "present": True, "on_battery": True,
                    "battery_percent": float("inf"),
                    "time_remaining_min": _ItemsBombDict({"m": 1}),
                },
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {}},
            ))
            resp = _client().get("/api/ups/shutdown/plan")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # Starlette renders with allow_nan=False: the inf percent must be
        # gone by encode time, and the unreadable mapping collapses.
        self.assertIsNone(body["battery_percent"])
        self.assertIsNone(body["time_remaining_min"])
        self.assertTrue(body["on_battery"])

    def test_surrogate_stack_name_rides_the_plan_scrubbed(self):
        resp = _get_plan(stacks=[
            {"id": "sane", "name": "gra\ud800v", "status": "ok"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
