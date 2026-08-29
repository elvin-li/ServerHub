"""UPS leftover sweep #7: seam eq/hash bombs and the state-file digit wipe
that survived the ups5/ups6 passes.

ups5 guarded the mapping reads (``.get``/``items``/``__bool__`` bombs) and
ups6 sealed the *scalar* dunders inside the two ``_jsonable`` copies with
unbound base coercions.  A fresh hunt over the same mounted routes found the
seams still running raw dunders on the way *into* those sanitizers — each of
these was confirmed an HTTP 500 against the mounted app before the fix:

* **A subclass eq-bomb ``status`` in a stack seam row.**  ``build_plan`` and
  ``_catalog`` compared ``_row_get(stack, "status") == "ok"`` bare; ``==``
  dispatches to the value's own ``__eq__`` first, so one bombed row 500'd
  GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill with every
  sane sibling — and the same raise escaped ``_engage``'s plan build out of
  ``sweep()`` during a real outage.  ``_seam_eq`` reads a bomb as
  not-running, the direction that never stops or restore-starts it.
* **A str subclass whose ``__str__`` returns itself.**  ``str(x)`` hands
  back whatever a subclass ``__str__`` returns, so ``_cfg_text``'s "base
  copy" kept the subclass — its ``__hash__``/``__eq__`` bombs then blew up
  ``build_plan``'s dedupe set, its by-id index, and the ``state in ("ok",
  "warn")`` compare fed from ``_service_states``, 500ing plan/drill.  The
  unbound ``str.__str__`` base copy strips the subclass and keeps its text
  (the ups6 unbound-base rule, one seam deeper).
* **A dict-subclass ``.get`` bomb as the whole ``_ups_status`` return.**
  ``drill()`` and ``_condition()`` read ``status.get(...)`` bare after the
  guarded seam call, so the bomb passed the ``try`` (returning does not
  read) and 500'd plan/drill — and ``_sweep_locked``'s ``not status`` /
  ``status.get("present")`` reads raised out of ``sweep()`` into
  check_once's containment, silently killing every UPS policy tick.
* **A >4300-digit int literal in the policy state file.**  ``json.loads``
  raises the digit-cap ValueError — *not* JSONDecodeError — so
  ``_load_state`` read the whole document as ``{}``: mid-outage the latched
  ``engaged`` phase and every recorded stop marker read as idle (restore
  never ran) and the next ``_mutate`` persisted the wipe.  The parse_int
  hook (the alerts/twofa/backups rule) loads the one huge number as None.

Stays-immune pins ride along: surrogate ids from the same seams stay
laundered, and the config-mutate contract on PUT /api/ups/settings keeps
answering the coded 503 with the file byte-identical.
"""
from __future__ import annotations

import json
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


class EqBomb:
    """Any equality probe raises (a raw seam value, not a str)."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("eq bomb")

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("ne bomb")

    __hash__ = object.__hash__


class SelfStrHashBomb(str):
    """``__str__`` returns *itself*, so str() keeps the subclass; hashing raises."""

    def __str__(self):  # noqa: D105
        return self

    def __hash__(self):  # noqa: D105
        raise RuntimeError("hash bomb")


class SelfStrEqBomb(str):
    """``__str__`` returns *itself*; any equality probe raises."""

    def __str__(self):  # noqa: D105
        return self

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("eq bomb")

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("ne bomb")

    __hash__ = str.__hash__


class GetBomb(dict):
    """Passes ``isinstance(x, dict)``; every ``.get`` raises."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("get bomb")


class BoolBombDict(dict):
    """Passes ``isinstance(x, dict)``; truth-testing the mapping raises."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("bool bomb")


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
                 status=None, groups=None, body=None, admin: bool = False):
        with ExitStack() as stack:
            if cfg_data is not None:
                stack.enter_context(mock.patch.object(
                    ups_svc, "cfg", lambda: cfg_data,
                ))
                stack.enter_context(mock.patch.object(
                    config, "cfg", lambda: cfg_data,
                ))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot", lambda force=False: dict(_SANE_SNAPSHOT),
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks",
                lambda: stacks if stacks is not None else [],
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status",
                lambda: status if status is not None else {"present": False},
            ))
            if groups is not None:
                import hub.status as status_mod
                stack.enter_context(mock.patch.object(
                    status_mod, "full_status",
                    lambda force=False: {"groups": groups},
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

    def _plan(self, **kw):
        return self._request("GET", "/api/ups/shutdown/plan", **kw)

    def _drill(self, **kw):
        return self._request("POST", "/api/ups/shutdown/drill", admin=True, **kw)

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


_ENABLED_ALL = {"settings": {"ups": {"shutdown": {
    "enabled": True, "trigger_pct": 25, "stacks": "all",
}}}, "scripts": []}


class SeamStatusEqBombTests(UpsAppBase):
    """Eq-bomb ``status`` values in stack seam rows drop to not-running."""

    def test_plan_survives_the_eq_bomb_row_beside_a_sane_sibling(self):
        resp = self._plan(cfg_data=_ENABLED_ALL, stacks=[
            {"id": "poisoned", "status": EqBomb()},
            {"id": "sane", "status": "ok"},
        ])
        self._assert_clean(resp)
        steps = {s["id"]: s for s in resp.json()["steps"]}
        # The bombed row reads as not-running (never stopped, never
        # restore-started); the sane sibling keeps its real state.
        self.assertFalse(steps["poisoned"]["running"])
        self.assertTrue(steps["sane"]["running"])
        rows = {s["id"]: s for s in resp.json()["catalog"]["stacks"]}
        self.assertFalse(rows["poisoned"]["running"])
        self.assertTrue(rows["sane"]["running"])

    def test_drill_survives_the_same_row(self):
        self._assert_clean(self._drill(
            cfg_data=_ENABLED_ALL,
            stacks=[{"id": "s1", "status": EqBomb()}],
        ))

    def test_sweep_engage_survives_the_same_row(self):
        # Pre-fix the raise escaped _engage's build_plan out of sweep();
        # check_once's containment ate it and the outage never latched.
        import hub.alerts as alerts

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: _ENABLED_ALL,
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: {
                    "present": True, "on_battery": True, "on_ac": False,
                    "battery_percent": 10, "time_remaining_min": 5,
                },
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks",
                lambda: [{"id": "s1", "status": EqBomb()}],
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_spawn", lambda target: True,
            ))
            stack.enter_context(mock.patch.object(
                alerts, "emit_alert",
                lambda **k: {"id": k.get("alert_id")},
            ))
            emitted = ups_policy.sweep(1_800_000_100)
        self.assertEqual(len(emitted), 1)
        self.assertEqual(
            ups_policy._load_state().get("phase"), ups_policy.PHASE_ENGAGED,
        )


class SelfStrSubclassBombTests(UpsAppBase):
    """str subclasses whose ``__str__`` returns itself stay behind _cfg_text."""

    def test_hash_bomb_stack_id_renders_its_text(self):
        resp = self._plan(cfg_data=_ENABLED_ALL, stacks=[
            {"id": SelfStrHashBomb("pihole"), "status": "ok"},
            {"id": "sane", "status": "ok"},
        ])
        self._assert_clean(resp)
        # The unbound base copy keeps the rendered text; pre-fix the dedupe
        # set hashed the subclass and 500'd the plan with the sane sibling.
        self.assertEqual(
            [s["id"] for s in resp.json()["steps"]], ["pihole", "sane"],
        )

    def test_eq_bomb_stack_id_renders_its_text(self):
        resp = self._plan(cfg_data=_ENABLED_ALL, stacks=[
            {"id": SelfStrEqBomb("pihole"), "status": "ok"},
            {"id": "sane", "status": "ok"},
        ])
        self._assert_clean(resp)
        self.assertEqual(
            [s["id"] for s in resp.json()["steps"]], ["pihole", "sane"],
        )

    def test_eq_bomb_service_state_reads_through_the_base_copy(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            "enabled": True, "trigger_pct": 25, "stacks": [],
            "stop_scripts": ["svc1"],
        }}}, "scripts": [{"id": "svc1"}]}
        resp = self._plan(cfg_data=cfg_data, groups=[{"services": [
            {"id": "svc1", "state": SelfStrEqBomb("ok")},
        ]}])
        self._assert_clean(resp)
        steps = {s["id"]: s for s in resp.json()["steps"]}
        # Pre-fix ``state in ("ok", "warn")`` ran the subclass __eq__ and
        # 500'd; the base copy keeps the real "ok" text, so it still plans.
        self.assertTrue(steps["svc1"]["running"])

    def test_drill_survives_the_same_rows(self):
        self._assert_clean(self._drill(
            cfg_data=_ENABLED_ALL,
            stacks=[{"id": SelfStrHashBomb("x"), "status": "ok"}],
        ))


class UpsStatusSeamBombTests(UpsAppBase):
    """A hostile mapping as the whole _ups_status return degrades, never 500s."""

    def test_plan_survives_a_get_bomb_status(self):
        resp = self._plan(
            cfg_data={"settings": {}, "scripts": []},
            status=GetBomb({"present": True}),
        )
        self._assert_clean(resp)
        # dict.get salvage under the poisoned method: the sensor still reads.
        self.assertTrue(resp.json()["sensor_present"])

    def test_drill_survives_a_get_bomb_status(self):
        self._assert_clean(self._drill(
            cfg_data={"settings": {}, "scripts": []},
            status=GetBomb({"present": True, "on_battery": False}),
        ))

    def test_drill_survives_a_bool_bomb_status(self):
        self._assert_clean(self._drill(
            cfg_data={"settings": {}, "scripts": []},
            status=BoolBombDict({"present": True, "on_battery": False}),
        ))

    def test_sweep_does_not_raise_over_a_get_bomb_status(self):
        # Pre-fix ``status.get("present")`` raised out of sweep() and
        # check_once's containment silently killed the whole UPS tick.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: _ENABLED_ALL,
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status",
                lambda: GetBomb({"present": True, "on_battery": True}),
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: [],
            ))
            emitted = ups_policy.sweep(1_800_000_100)
        self.assertIsInstance(emitted, list)


class StateFileDigitCapSalvageTests(UpsAppBase):
    """One >4300-digit literal drops alone instead of wiping the state."""

    def _get_ups(self):
        return self._request("GET", "/api/ups",
                             cfg_data={"settings": {}, "scripts": []})

    def test_engaged_phase_survives_a_huge_engaged_at(self):
        self.state_file.write_text(
            '{"phase": "engaged", "engaged_at": ' + "9" * 5000
            + ', "reason": "battery 10% \u2264 25%",'
            ' "steps": [{"kind": "stack", "id": "immich", "running": true}]}',
        )
        resp = self._get_ups()
        self._assert_clean(resp)
        state = resp.json()["shutdown_state"]
        # Pre-fix json.loads raised the digit-cap ValueError and the whole
        # document read as {}: the latched outage looked idle and the
        # recorded steps were gone.  Now only the huge number drops.
        self.assertEqual(state["phase"], "engaged")
        self.assertIsNone(state["engaged_at"])
        self.assertEqual([s["id"] for s in state["steps"]], ["immich"])

    def test_mutate_over_the_poisoned_file_keeps_the_siblings(self):
        self.state_file.write_text(
            '{"phase": "engaged", "stop_done": false,'
            ' "junk": ' + "9" * 5000 + "}",
        )
        ups_policy._mutate(lambda s: s.update(stop_done=True))
        reread = ups_policy._load_state()
        # Pre-fix the mutate rewrote the file from {}, persisting the wipe.
        self.assertEqual(reread.get("phase"), "engaged")
        self.assertTrue(reread.get("stop_done"))
        self.assertIsNone(reread.get("junk"))


class StaysImmunePinTests(UpsAppBase):
    """Vectors this hunt probed and found already immune, pinned."""

    def test_surrogate_seam_ids_stay_laundered(self):
        resp = self._plan(cfg_data=_ENABLED_ALL, stacks=[
            {"id": "gra\ud800v", "name": "n\ud800m", "status": "ok"},
        ])
        self._assert_clean(resp)

    def test_eq_bomb_status_value_never_leaks_raw_into_the_body(self):
        resp = self._plan(cfg_data=_ENABLED_ALL, stacks=[
            {"id": "s1", "status": EqBomb()},
        ])
        self._assert_clean(resp)


class ConfigMutateContractTests(unittest.TestCase):
    """PUT /api/ups/settings over unreadable services.yaml: coded 503,
    file byte-identical — never a 200 that rewrote the config from {}."""

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
        try:
            self._orig_yaml = config.YAML_PATH.read_bytes()
        except OSError:
            self._orig_yaml = None
        self.addCleanup(self._restore_yaml)

    def _restore_yaml(self):
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass
        if self._orig_yaml is not None:
            config.YAML_PATH.write_bytes(self._orig_yaml)
        config.reload_cfg()

    def test_unreadable_config_refuses_503_and_stays_intact(self):
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_bytes(b"\xff\xfesettings:\n  ups: {}\n")
        config.reload_cfg()
        before = config.YAML_PATH.read_bytes()
        with mock.patch.object(ups_svc, "ups_snapshot",
                               lambda force=False: dict(_SANE_SNAPSHOT)), \
                mock.patch.object(ups_policy, "_ups_status",
                                  lambda: {"present": False}), \
                mock.patch.object(ups_api.audit, "record", lambda *a, **k: None):
            resp = self.client.put(
                "/api/ups/settings", json={"alerts_enabled": False},
            )
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "settings.config_unreadable",
        )
        self.assertEqual(config.YAML_PATH.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
