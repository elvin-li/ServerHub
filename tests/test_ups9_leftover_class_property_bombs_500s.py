"""UPS leftover sweep #9: ``__class__``-property / impostor / rc bombs.

ups5 guarded the ``_ups_status`` seam's mapping reads, ups6 sealed the scalar
dunders inside the two ``_jsonable`` copies, ups7 wrapped the seam ``==``/hash
compares, and ups8 sealed ``_condition``'s float coercion and reason render.
A fresh hunt over the same mounted routes found the sanitizer *gates
themselves* still running a raw leftover's dunders — each shape below
confirmed an HTTP 500 against the mounted app before the fix:

* **A leftover whose ``__class__`` is a raising property.**  ``isinstance``
  consults ``value.__class__`` when the exact-type check misses, so one such
  value detonated every bare isinstance rank gate one step ahead of the
  scrub it fronted: ``_jsonable``'s heads (a poisoned ``shutdown.stacks`` or
  snapshot field), ``_finite_int``'s bool/float gates (``low_battery_pct``),
  ``_mapping_get``'s dict gate (the settings block, or the whole config
  root), ``_normalized_shutdown``'s and ``ups_settings``'s dict gates, and —
  on the policy side — ``_row_get``'s dict gate, ``drill()``'s status gate,
  ``_cfg_text``'s rank gates (a stack-row id) and ``_catalog``'s script-row
  gate.  Each 500'd GET /api/ups and/or the plan/drill routes, and the
  status-gate copy raised out of ``sweep()`` into check_once's containment,
  silently killing every UPS policy tick.
* **A *lying* ``__class__`` (claims bytes, is not).**  ``isinstance`` says
  bytes, so the unbound base decode ran — and TypeError'd outside any try in
  both ``_jsonable`` copies (value and key branches) and both ``_as_text``
  copies.  Junk now drops or renders as text; siblings survive.
* **An rc-subclass ``__eq__`` bomb from the ``sh`` seam.**  ``ups_snapshot``
  compared ``rc == 0`` bare, so one poisoned exit status 500'd
  GET /api/ups?force=true; ``_rc_int`` reads a bomb as failure (the host9
  identity_svc rule) and pmset output degrades to empty.

Stays-immune pins ride along for the shapes the hunt re-probed and found
already sealed: a FIFO planted at the policy state file (read_text_capped's
O_NONBLOCK + S_ISREG refusal), a >4300-digit number inside the state file
(``_capped_json_int`` drops it alone, siblings survive), and an
``isoformat()`` that returns inf (the nested ``_jsonable`` pass drops it).
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
from hub import ups_policy, ups_svc  # noqa: E402


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ClassPropertyBomb:
    """``isinstance`` against any class runs the property — and it raises."""

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("__class__ bomb")


class LyingBytes:
    """Claims to be bytes; the unbound base decode TypeErrors on it."""

    @property
    def __class__(self):  # noqa: D105
        return bytes


class LyingStr:
    """Claims to be str; the unbound base encode TypeErrors on it."""

    @property
    def __class__(self):  # noqa: D105
        return str


class RcEqBomb(int):
    """Passes isinstance(int); its own ``__eq__`` raises."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("rc eq bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class IsoInf:
    """``isoformat()`` reads fine but returns inf — must not leak or 500."""

    def isoformat(self):  # noqa: D102
        return float("inf")


_SANE_SNAPSHOT = {"present": False, "halt_levels": None}

_ENABLED_PCT = {"settings": {"ups": {"shutdown": {
    "enabled": True, "trigger_pct": 25, "stacks": "all",
}}}, "scripts": []}


def _on_battery(**over) -> dict:
    st = {"present": True, "on_battery": True, "on_ac": False,
          "battery_percent": 10, "time_remaining_min": 3}
    st.update(over)
    return st


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
        for patched in (
            mock.patch.object(ups_policy, "STATE_FILE",
                              self.tmp / "ups-policy-state.json"),
            mock.patch.object(ups_policy, "_LOCK_PATH", self.tmp / "s.lock"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def _get(self, path: str, *, cfg_data=None, snapshot=None, status=None,
             sh=None, stacks=None):
        cfg_data = cfg_data if cfg_data is not None else {"settings": {}, "scripts": []}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(ups_svc, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(config, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks",
                (lambda: stacks) if stacks is not None else (lambda: []),
            ))
            if sh is not None:
                stack.enter_context(mock.patch.object(ups_svc, "sh", sh))
                ups_svc.ups_snapshot.invalidate()
                self.addCleanup(ups_svc.ups_snapshot.invalidate)
            else:
                stack.enter_context(mock.patch.object(
                    ups_svc, "ups_snapshot",
                    lambda force=False: snapshot if snapshot is not None
                    else dict(_SANE_SNAPSHOT),
                ))
            if status is not None:
                stack.enter_context(mock.patch.object(
                    ups_policy, "_ups_status", lambda: status,
                ))
            return self.client.get(path)

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", resp.text)
        return body


class GetUpsClassBombTests(UpsAppBase):
    """A ``__class__``-property bomb anywhere in cfg/snapshot cannot 500."""

    def test_shutdown_stacks_class_bomb_degrades_and_keeps_siblings(self):
        # Pre-fix: _jsonable's bare ``isinstance(value, bool)`` head ran the
        # property and 500'd GET /api/ups.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 30,
                "stacks": ClassPropertyBomb(),
            }}},
        }))
        shutdown = body["settings"]["shutdown"]
        # The sane siblings survive the bomb key.
        self.assertTrue(shutdown["enabled"])
        self.assertEqual(shutdown["trigger_pct"], 30)

    def test_low_battery_pct_class_bomb_falls_back_to_default(self):
        # Pre-fix: _finite_int's bare ``isinstance(raw, bool)`` gate 500'd.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"low_battery_pct": ClassPropertyBomb()}},
        }))
        self.assertEqual(body["settings"]["low_battery_pct"], 20)

    def test_settings_block_class_bomb_reads_as_defaults(self):
        # Pre-fix: _mapping_get's bare ``isinstance(mapping, dict)`` 500'd.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": ClassPropertyBomb(),
        }))
        self.assertEqual(body["settings"]["low_battery_pct"], 20)
        self.assertFalse(body["settings"]["shutdown"]["enabled"])

    def test_config_root_class_bomb_reads_as_defaults(self):
        body = self._assert_clean(self._get("/api/ups",
                                            cfg_data=ClassPropertyBomb()))
        self.assertTrue(body["settings"]["alerts_enabled"])

    def test_snapshot_value_and_key_class_bombs_keep_siblings(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "name": ClassPropertyBomb(),
            ClassPropertyBomb(): 1, "battery_percent": 55,
            "halt_levels": None,
        }))
        # The bomb value renders as junk text or drops; the sane sibling
        # fields survive on the same row.
        self.assertEqual(body["battery_percent"], 55)
        self.assertTrue(body["present"])


class GetUpsImpostorTests(UpsAppBase):
    """A lying ``__class__`` (claims bytes/str, is not) cannot 500."""

    def test_lying_bytes_value_drops_and_keeps_siblings(self):
        # Pre-fix: _jsonable's bytes branch ran the unbound base decode
        # outside any try and TypeError'd into a 500.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"shutdown": {
                "enabled": True, "stacks": LyingBytes(), "trigger_pct": 40,
            }}},
        }))
        shutdown = body["settings"]["shutdown"]
        self.assertIsNone(shutdown["stacks"])
        self.assertEqual(shutdown["trigger_pct"], 40)

    def test_lying_bytes_snapshot_key_keeps_siblings(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, LyingBytes(): 1, "battery_percent": 42,
            "halt_levels": None,
        }))
        self.assertEqual(body["battery_percent"], 42)


class UpsSnapshotSeamBombTests(UpsAppBase):
    """Poison through the ``sh`` seam (rc / stdout) cannot 500 the force read."""

    def test_rc_eq_bomb_reads_as_pmset_failure(self):
        # Pre-fix: ups_snapshot's bare ``rc == 0`` ran the subclass __eq__
        # and 500'd GET /api/ups?force=true.
        body = self._assert_clean(self._get(
            "/api/ups?force=true", sh=lambda *a, **k: (RcEqBomb(0), "", ""),
        ))
        self.assertFalse(body["present"])

    def test_stdout_class_bomb_reads_as_empty_output(self):
        body = self._assert_clean(self._get(
            "/api/ups?force=true",
            sh=lambda *a, **k: (0, ClassPropertyBomb(), ""),
        ))
        self.assertFalse(body["present"])

    def test_stdout_lying_str_impostor_cannot_blow_the_launder(self):
        # Pre-fix: _as_text took the str branch on the lying __class__ and
        # the unbound ``str.encode`` TypeError'd into a 500.
        body = self._assert_clean(self._get(
            "/api/ups?force=true", sh=lambda *a, **k: (0, LyingStr(), ""),
        ))
        self.assertFalse(body["present"])


class PlanDrillClassBombTests(UpsAppBase):
    """The plan route survives the same bombs one seam over."""

    def test_status_object_class_bomb_reads_as_no_sensor(self):
        # Pre-fix: drill()'s bare ``isinstance(status, dict)`` 500'd.
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=_ENABLED_PCT,
            status=ClassPropertyBomb(),
        ))
        self.assertFalse(body["sensor_present"])
        self.assertFalse(body["would_trigger_now"])

    def test_battery_percent_class_bomb_never_triggers_or_500s(self):
        # Pre-fix: the raw value rode into _jsonable and detonated its head.
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=_ENABLED_PCT,
            status=_on_battery(battery_percent=ClassPropertyBomb()),
        ))
        # An unreadable sensor fails its condition — the conservative
        # direction that never stops workloads on the unknown.
        self.assertFalse(body["would_trigger_now"])

    def test_battery_percent_lying_bytes_never_500s(self):
        self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=_ENABLED_PCT,
            status=_on_battery(battery_percent=LyingBytes()),
        ))

    def test_stack_row_id_class_bomb_keeps_sane_sibling(self):
        # Pre-fix: build_plan's bare ``_cfg_text`` call detonated
        # _cfg_text's ``isinstance(value, bool)`` gate and 500'd the plan.
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=_ENABLED_PCT,
            status={"present": False},
            stacks=[{"id": ClassPropertyBomb(), "name": "x", "status": "ok"},
                    {"id": "web", "name": "web", "status": "ok"}],
        ))
        self.assertIn("web", [s["id"] for s in body["steps"]])

    def test_stack_row_class_bomb_drops_alone(self):
        # Pre-fix the bomb row tripped the materialize guard and wiped the
        # sane sibling out of the plan with it.
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=_ENABLED_PCT,
            status={"present": False},
            stacks=[ClassPropertyBomb(),
                    {"id": "web", "name": "web", "status": "ok"}],
        ))
        self.assertEqual([s["id"] for s in body["steps"]], ["web"])

    def test_script_row_class_bomb_keeps_sane_sibling(self):
        # Pre-fix: _catalog's bare ``isinstance(s, dict)`` row gate 500'd
        # the plan with every sane sibling script entry.
        cfg_data = {"settings": _ENABLED_PCT["settings"],
                    "scripts": [ClassPropertyBomb(),
                                {"id": "backup", "name": "backup", "stop": "x"}]}
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=cfg_data,
            status={"present": False},
        ))
        self.assertEqual([s["id"] for s in body["catalog"]["scripts"]],
                         ["backup"])


class SweepClassBombTests(UpsAppBase):
    """The same bombs must not raise out of sweep() into check_once."""

    def _sweep_over(self, status):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: _ENABLED_PCT))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: status))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: []))
            stack.enter_context(mock.patch.object(
                ups_policy, "_spawn", lambda target: True))
            return ups_policy.sweep(1_800_000_100)

    def test_sweep_survives_a_status_object_class_bomb(self):
        # Pre-fix _sweep_locked's bare isinstance raised out of sweep() and
        # check_once's containment silently killed every UPS policy tick.
        emitted = self._sweep_over(ClassPropertyBomb())
        self.assertEqual(emitted, [])
        self.assertNotEqual(
            ups_policy._load_state().get("phase"), ups_policy.PHASE_ENGAGED,
        )

    def test_sweep_survives_a_battery_percent_class_bomb(self):
        emitted = self._sweep_over(
            _on_battery(battery_percent=ClassPropertyBomb()))
        self.assertIsInstance(emitted, list)
        self.assertNotEqual(
            ups_policy._load_state().get("phase"), ups_policy.PHASE_ENGAGED,
        )


class SanitizerUnitTests(unittest.TestCase):
    """The helpers read the bombs as unknowns while keeping sane values."""

    def test_condition_reads_a_class_bomb_percent_as_not_met(self):
        hit, reason = ups_policy._condition(
            _on_battery(battery_percent=ClassPropertyBomb()),
            {"trigger_pct": 25, "trigger_remaining_min": None,
             "require_both": False},
        )
        self.assertFalse(hit)
        self.assertEqual(reason, "")

    def test_ups_settings_survives_a_class_bomb_ups_block(self):
        with mock.patch.object(ups_svc, "cfg",
                               lambda: {"settings": {"ups": ClassPropertyBomb()}}):
            out = ups_svc.ups_settings()
        self.assertEqual(out["low_battery_pct"], 20)
        _starlette(out)

    def test_jsonable_renders_a_class_bomb_as_encodable(self):
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            _starlette(scrub({"k": ClassPropertyBomb(), "sane": 1}))
            self.assertEqual(scrub({"k": ClassPropertyBomb(), "sane": 1})["sane"], 1)

    def test_jsonable_drops_a_lying_bytes_value(self):
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            out = scrub({"k": LyingBytes(), "sane": 1})
            self.assertIsNone(out["k"])
            self.assertEqual(out["sane"], 1)

    def test_rc_int_reads_bombs_as_failure_and_sane_ints_exactly(self):
        self.assertEqual(ups_svc._rc_int(RcEqBomb(0)), 0)
        self.assertEqual(ups_svc._rc_int(0), 0)
        self.assertEqual(ups_svc._rc_int(1), 1)
        self.assertEqual(ups_svc._rc_int(ClassPropertyBomb()), -255)
        self.assertEqual(ups_svc._rc_int(None), -255)

    def test_cfg_text_renders_sane_rows_and_degrades_bombs(self):
        self.assertEqual(ups_policy._cfg_text("web"), "web")
        self.assertEqual(ups_policy._cfg_text(7), "7")
        text = ups_policy._cfg_text(ClassPropertyBomb())
        self.assertIsInstance(text, str)


class StaysImmunePinTests(UpsAppBase):
    """Shapes the hunt re-probed and found already sealed stay that way."""

    def test_a_fifo_planted_at_the_state_file_reads_as_idle(self):
        # read_text_capped opens O_NONBLOCK and refuses non-regular files,
        # so GET /api/ups answers instead of parking on the FIFO forever.
        os.mkfifo(ups_policy.STATE_FILE)
        body = self._assert_clean(self._get("/api/ups"))
        self.assertEqual(body["shutdown_state"]["phase"], "idle")

    def test_a_huge_number_in_the_state_file_drops_alone(self):
        # _capped_json_int: the >4300-digit leftover drops to null while the
        # latched phase and its siblings survive the parse.
        ups_policy.STATE_FILE.write_text(
            '{"phase": "engaged", "engaged_at": %s, "reason": "r"}'
            % ("9" * 5000), encoding="utf-8",
        )
        body = self._assert_clean(self._get("/api/ups"))
        state = body["shutdown_state"]
        self.assertEqual(state["phase"], "engaged")
        self.assertIsNone(state["engaged_at"])
        self.assertEqual(state["reason"], "r")

    def test_isoformat_returning_inf_drops_instead_of_leaking(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "name": IsoInf(), "halt_levels": None,
        }))
        self.assertIsNone(body["name"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
