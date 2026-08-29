"""UPS leftover sweep #5: dict-subclass ``.get``/``items``/``__bool__`` bombs
and unhashable keys that survived the ups/ups2/ups3/ups4 passes.

The earlier sweeps guarded *iteration* — ``list(raw.items())`` in
``ups_settings`` / ``_normalized_shutdown``, the materialize-under-guard in
``build_plan`` / ``_catalog`` — but left three sibling reads of the very same
objects bare, so one odd dict subclass (the disk_power_svc "pool5" class,
already accepted as a real leftover shape by those guards) still 500'd every
UPS route at once:

* **``.get`` bombs.**  ``ups_settings()`` read ``cfg().get("settings")``,
  ``settings.get("ups")`` and ``raw.get("shutdown")`` bare; a subclass whose
  ``get`` raises passed the ``isinstance(..., dict)`` gates and 500'd
  GET /api/ups, GET /api/ups/shutdown/plan, POST /api/ups/shutdown/drill and
  PUT /api/ups/settings (its effective-merge read) in one shot.  The same
  class in a stack/script/status row from the seams 500'd the plan/drill
  routes out of ``build_plan`` / ``_catalog`` / ``_service_states`` with
  every sane sibling row.  ``_mapping_get`` / ``_row_get`` now fall back to
  ``dict.get``, so a subclass that only poisoned its method keeps its data.
* **Unhashable keys / torn pairs from a subclass ``items()``.**  The guarded
  materialize succeeded, but the filter comprehension right after it hashed
  each key (``k in UPS_DEFAULTS`` / ``k in SHUTDOWN_DEFAULTS``) and unpacked
  each pair *outside* the try — one unhashable key or a one-element row
  raised TypeError/ValueError and 500'd GET /api/ups while every sane
  sibling key died with it.  Now a per-pair guard drops only the junk pair.
* **``__bool__`` bombs.**  ``bool(out["alerts_enabled"])``,
  ``bool(s.get("stop"))`` in the picker catalog, and ``bool(stack and …)``
  in ``build_plan`` all truth-tested raw leftovers; one raising ``__bool__``
  500'd GET /api/ups or the plan/drill pair.  The reads are now guarded and
  the plan uses ``stack is not None`` instead of truth-testing the row.

Stays-immune pins ride along: a leftover FIFO at the policy state file must
answer (read_text_capped's O_NONBLOCK + EINVAL contract), and invalid-UTF-8
or oversize state degrades to idle — never a hang, never a 500.  The policy
sweep itself must also survive the poisoned store: pre-fix the raise escaped
``sweep()`` into check_once's containment and silently killed the UPS tick.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import hub.config as config  # noqa: E402
import hub.routers.ups_api as ups_api  # noqa: E402
from hub import ups_policy, ups_svc  # noqa: E402


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class GetBomb(dict):
    """Passes ``isinstance(x, dict)``; every ``.get`` raises."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("get bomb")


class ItemsUnhashableKeys(dict):
    """items() hands back an unhashable key beside a sane pair."""

    def items(self):  # noqa: D102
        return [(["junk"], 1), ("low_battery_pct", 50)]


class ItemsTornPairs(dict):
    """items() hands back a one-element row that cannot unpack."""

    def items(self):  # noqa: D102
        return [("solo",), ("low_battery_pct", 50)]


class BoolBomb:
    """A value whose truth test raises."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("bool bomb")


class BoolBombRow(dict):
    """Passes ``isinstance(x, dict)``; truth-testing the row raises."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("bool bomb row")


_SANE_SNAPSHOT = {"present": False, "halt_levels": None}


class UpsAppBase(unittest.TestCase):
    """create_app-wired client + policy state redirected into a temp dir."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.state_file = self.tmp / "ups-policy-state.json"
        for patched in (
            mock.patch.object(ups_policy, "STATE_FILE", self.state_file),
            mock.patch.object(ups_policy, "_LOCK_PATH", self.tmp / "s.lock"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def _request(self, method: str, path: str, *, cfg_data=None, stacks=None,
                 body=None, admin: bool = False, saved: list | None = None):
        with ExitStack() as stack:
            if cfg_data is not None:
                stack.enter_context(mock.patch.object(
                    ups_svc, "cfg", lambda: cfg_data,
                ))
                # ups_policy._catalog resolves ``from hub.config import cfg``
                # at call time, so the module attribute needs the same patch.
                stack.enter_context(mock.patch.object(
                    config, "cfg", lambda: cfg_data,
                ))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot", lambda force=False: dict(_SANE_SNAPSHOT),
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: stacks if stacks is not None else [],
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {"present": False},
            ))
            stack.enter_context(mock.patch.object(
                ups_svc, "update_settings",
                lambda patch: (saved.append(patch) if saved is not None else None),
            ))
            if admin:
                stack.enter_context(mock.patch.object(
                    ups_api, "require_admin_browser", lambda request: "admin",
                ))
                stack.enter_context(mock.patch.object(
                    ups_api.audit, "record", lambda *a, **k: None,
                ))
            if method == "GET":
                return self.client.get(path)
            if method == "PUT":
                return self.client.put(path, json=body)
            return self.client.post(path, json=body)

    def _get_ups(self, cfg_data):
        return self._request("GET", "/api/ups", cfg_data=cfg_data)

    def _plan(self, cfg_data, stacks=None):
        return self._request(
            "GET", "/api/ups/shutdown/plan", cfg_data=cfg_data, stacks=stacks,
        )


class SettingsGetBombTests(UpsAppBase):
    """.get bombs at every rank of the settings chain answer 200."""

    def test_ups_block_get_bomb_keeps_its_sane_data(self):
        # dict.get salvage: the subclass only poisoned its method; the flat
        # key it actually stores must survive beside the degraded shutdown.
        resp = self._get_ups(
            {"settings": {"ups": GetBomb({"low_battery_pct": 30})}},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        settings = resp.json()["settings"]
        self.assertEqual(settings["low_battery_pct"], 30)
        self.assertEqual(settings["shutdown"]["enabled"], False)

    def test_settings_get_bomb_degrades_to_defaults(self):
        resp = self._get_ups({"settings": GetBomb()})
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["settings"]["low_battery_pct"], 20)

    def test_cfg_root_get_bomb_degrades_to_defaults(self):
        resp = self._get_ups(GetBomb())
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["settings"]["alerts_enabled"], True)

    def test_plan_route_survives_the_same_store(self):
        resp = self._plan({"settings": {"ups": GetBomb()}, "scripts": []})
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())

    def test_put_settings_effective_merge_survives_the_bombed_store(self):
        # The shutdown patch forces the effective-merge read of the stored
        # policy; pre-fix that read raised out of ups_settings() as a 500.
        saved: list = []
        resp = self._request(
            "PUT", "/api/ups/settings",
            cfg_data={"settings": {"ups": GetBomb()}},
            body={"shutdown": {"enabled": False}}, admin=True, saved=saved,
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(saved, [{"ups": {"shutdown": {"enabled": False}}}])


class UnhashableItemsTests(UpsAppBase):
    """Unhashable keys / torn pairs from a subclass items() drop alone."""

    def test_ups_level_unhashable_key_keeps_the_sane_sibling(self):
        resp = self._get_ups({"settings": {"ups": ItemsUnhashableKeys()}})
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        # ``k in UPS_DEFAULTS`` hashed the junk key and used to take the
        # sane sibling pair down with the 500.
        self.assertEqual(resp.json()["settings"]["low_battery_pct"], 50)

    def test_ups_level_torn_pair_keeps_the_sane_sibling(self):
        resp = self._get_ups({"settings": {"ups": ItemsTornPairs()}})
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["settings"]["low_battery_pct"], 50)

    def test_shutdown_level_unhashable_key_degrades_to_defaults(self):
        resp = self._get_ups(
            {"settings": {"ups": {"shutdown": ItemsUnhashableKeys()}}},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["settings"]["shutdown"]["enabled"], False)

    def test_shutdown_level_torn_pair_degrades_to_defaults(self):
        resp = self._get_ups(
            {"settings": {"ups": {"shutdown": ItemsTornPairs()}}},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())

    def test_drill_route_survives_the_same_store(self):
        resp = self._request(
            "POST", "/api/ups/shutdown/drill", admin=True,
            cfg_data={"settings": {"ups": {"shutdown": ItemsUnhashableKeys()}},
                      "scripts": []},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())


class BoolBombTests(UpsAppBase):
    """Truth-tested leftovers must degrade, never 500."""

    def test_alerts_enabled_bool_bomb_falls_back_to_the_default(self):
        resp = self._get_ups({"settings": {"ups": {"alerts_enabled": BoolBomb()}}})
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["settings"]["alerts_enabled"], True)

    def test_script_stop_bool_bomb_reads_as_no_stop(self):
        resp = self._plan(
            {"settings": {}, "scripts": [{"id": "g", "stop": BoolBomb()}]},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        scripts = resp.json()["catalog"]["scripts"]
        self.assertEqual(
            scripts, [{"id": "g", "name": "g", "has_stop": False}],
        )

    def test_bool_bomb_stack_row_does_not_500_the_plan(self):
        # build_plan's old ``bool(stack and …)`` truth-tested the row; the
        # ``stack is not None`` form must not.
        cfg_data = {
            "settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 25, "stacks": ["s1"],
            }}},
            "scripts": [],
        }
        row = BoolBombRow({"id": "s1", "status": "ok", "name": "S1"})
        resp = self._plan(cfg_data, stacks=[row])
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        steps = resp.json()["steps"]
        self.assertEqual([s["id"] for s in steps], ["s1"])
        self.assertTrue(steps[0]["running"])


class PlanRowGetBombTests(UpsAppBase):
    """.get bomb rows from the stack/script seams drop alone."""

    def test_stack_row_get_bomb_keeps_its_siblings(self):
        resp = self._plan(
            {"settings": {}, "scripts": []},
            stacks=[GetBomb({"id": "poisoned"}),
                    {"id": "sane", "name": "Sane", "status": "ok"}],
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        ids = [s["id"] for s in resp.json()["catalog"]["stacks"]]
        # dict.get salvage keeps the bombed row's real id beside the sibling.
        self.assertIn("sane", ids)
        self.assertIn("poisoned", ids)

    def test_stacks_all_policy_over_a_get_bomb_row_still_plans(self):
        cfg_data = {
            "settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 25, "stacks": "all",
            }}},
            "scripts": [],
        }
        resp = self._plan(cfg_data, stacks=[
            GetBomb({"id": "poisoned", "status": "ok"}),
            {"id": "sane", "status": "ok"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        ids = [s["id"] for s in resp.json()["steps"]]
        self.assertIn("sane", ids)

    def test_script_row_get_bomb_keeps_its_siblings(self):
        resp = self._plan({
            "settings": {},
            "scripts": [GetBomb({"id": "poisoned"}),
                        {"id": "gravity", "name": "G", "stop": "g stop"}],
        })
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        scripts = {s["id"]: s for s in resp.json()["catalog"]["scripts"]}
        self.assertIn("gravity", scripts)
        self.assertTrue(scripts["gravity"]["has_stop"])


class ServiceStatesRowBombTests(unittest.TestCase):
    """_service_states keeps sane siblings beside bombed groups/rows."""

    def _states(self, groups):
        import hub.status as status

        with mock.patch.object(
            status, "full_status", lambda force=False: {"groups": groups},
        ):
            return ups_policy._service_states()

    def test_get_bomb_group_drops_alone(self):
        states = self._states([
            GetBomb({"services": [{"id": "poisoned", "state": "ok"}]}),
            {"services": [{"id": "sane", "state": "ok"}]},
        ])
        self.assertEqual(states.get("sane"), "ok")

    def test_get_bomb_service_row_drops_alone(self):
        states = self._states([{"services": [
            GetBomb({"id": "poisoned", "state": "ok"}),
            {"id": "sane", "state": "warn"},
        ]}])
        self.assertEqual(states.get("sane"), "warn")
        # dict.get salvage: the bombed row's real data still reads.
        self.assertEqual(states.get("poisoned"), "ok")

    def test_bool_bomb_services_value_drops_the_group_alone(self):
        # The old ``_row_get(g, "services") or []`` shape would truth-test
        # the value; the isinstance gate must not.
        states = self._states([
            {"services": BoolBomb()},
            {"services": [{"id": "sane", "state": "ok"}]},
        ])
        self.assertEqual(states, {"sane": "ok"})


class SweepOverPoisonedStoreTests(unittest.TestCase):
    """The policy tick must survive the same store, not abort silently."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state_file = Path(tmp.name) / "ups-policy-state.json"
        for patched in (
            mock.patch.object(ups_policy, "STATE_FILE", self.state_file),
            mock.patch.object(
                ups_policy, "_LOCK_PATH", Path(tmp.name) / "s.lock",
            ),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_sweep_does_not_raise_over_a_get_bomb_ups_block(self):
        # Pre-fix shutdown_settings() raised out of sweep(); check_once's
        # containment ate it and the whole UPS tick silently aborted.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: {"settings": {"ups": GetBomb()}},
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {
                    "present": True, "on_battery": True, "on_ac": False,
                    "battery_percent": 10, "time_remaining_min": 5,
                },
            ))
            emitted = ups_policy.sweep(1_800_000_100)
        # The salvaged shutdown block reads as defaults (disabled): no
        # engage, no raise.
        self.assertEqual(emitted, [])


class StateFileStaysImmuneTests(UpsAppBase):
    """Leftover FIFO / invalid-UTF-8 / oversize state never hangs or 500s."""

    def _get_ups_plain(self):
        return self._get_ups({"settings": {}})

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_fifo_state_file_answers_instead_of_hanging(self):
        # read_text_capped opens O_NONBLOCK and refuses non-regular files
        # with OSError(EINVAL); a plain open() of a FIFO would park GET
        # /api/ups until a writer appeared.
        os.mkfifo(self.state_file)
        resp = self._get_ups_plain()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["shutdown_state"]["phase"], "idle")

    def test_invalid_utf8_state_degrades_to_idle(self):
        self.state_file.write_bytes(b'\xff\xfe{"phase": "engaged"}')
        resp = self._get_ups_plain()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["shutdown_state"]["phase"], "idle")

    def test_oversize_state_degrades_to_idle(self):
        self.state_file.write_text(
            '{"phase": "engaged", "pad": "' + "x" * 300_000 + '"}',
        )
        resp = self._get_ups_plain()
        self.assertEqual(resp.status_code, 200, resp.text)
        _starlette(resp.json())
        self.assertEqual(resp.json()["shutdown_state"]["phase"], "idle")


if __name__ == "__main__":
    unittest.main(verbosity=2)
