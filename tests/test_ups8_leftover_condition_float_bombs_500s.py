"""UPS leftover sweep #8: numeric-floor coercion bombs in ``_condition``.

ups5 guarded the mapping *reads* on the ``_ups_status`` seam (``.get``/
``items``/``__bool__`` bombs), ups6 sealed the scalar dunders inside the two
``_jsonable`` copies with unbound base coercions, and ups7 wrapped the seam
``==``/hash compares plus the state-file digit wipe.  A fresh hunt over the
same mounted routes found the *trigger evaluation* still running a raw seam
value's own ``__float__`` / ``__format__`` one dunder deeper — each confirmed
an HTTP 500 against the mounted app before the fix:

* **A ``battery_percent`` / ``time_remaining_min`` subclass whose
  ``__float__`` raises.**  ``_condition`` compared ``float(pct) <=
  float(floor)`` under a narrow ``except (TypeError, ValueError,
  OverflowError)``; a seam value whose ``__float__`` raises RuntimeError
  escaped it and 500'd GET /api/ups/shutdown/plan and
  POST /api/ups/shutdown/drill — and raised out of ``sweep()`` into
  check_once's containment, silently killing the UPS policy tick.
  ``_below_floor`` reads a bomb as "condition not met", the module's
  documented "never fires on the unknown".
* **The fired-condition reason f-string interpolated that same raw value.**
  Once a condition held, ``f"battery {pct}% ≤ {floor}%"`` ran the raw seam
  value's ``__format__``/``__str__``; a bomb there blew the label *after* the
  trigger had fired and 500'd the same two routes.  ``_reason`` degrades an
  unrenderable label to empty; the trigger it describes still fires.

Stays-immune pins ride along: a hand-edited string / over-cap / inf floor
still reads as "condition off" (the ``_condition`` edge tests already lean on
that fall-through) and a sane percent still renders its integer label.
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


class FloatFloatBomb(float):
    """Passes ``isinstance(x, float)``; its own ``__float__`` raises."""

    def __float__(self):  # noqa: D105
        raise RuntimeError("float() bomb")


class IntFloatBomb(int):
    """Passes ``isinstance(x, int)``; coercion to float raises."""

    def __float__(self):  # noqa: D105
        raise RuntimeError("int float() bomb")


class FloatFormatBomb(float):
    """``__float__`` reads fine (inherited); rendering the value raises."""

    def __format__(self, spec):  # noqa: D105
        raise RuntimeError("format bomb")

    def __str__(self):  # noqa: D105
        raise RuntimeError("str bomb")

    __repr__ = __str__


_SANE_SNAPSHOT = {"present": False, "halt_levels": None}

_ENABLED_PCT = {"settings": {"ups": {"shutdown": {
    "enabled": True, "trigger_pct": 25, "stacks": "all",
}}}, "scripts": []}
_ENABLED_MIN = {"settings": {"ups": {"shutdown": {
    "enabled": True, "trigger_remaining_min": 5, "stacks": "all",
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

    def _request(self, method: str, path: str, *, cfg_data, status,
                 admin: bool = False):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(ups_svc, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(config, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(
                ups_svc, "ups_snapshot", lambda force=False: dict(_SANE_SNAPSHOT),
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: [],
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: status,
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
            return self.client.post(path, json={})

    def _plan(self, **kw):
        return self._request("GET", "/api/ups/shutdown/plan", **kw)

    def _drill(self, **kw):
        return self._request("POST", "/api/ups/shutdown/drill", admin=True, **kw)

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


class ConditionFloatBombRouteTests(UpsAppBase):
    """A ``__float__`` bomb in the trigger sensor never 500s plan/drill."""

    def test_plan_survives_a_float_bomb_percent(self):
        self._assert_clean(self._plan(
            cfg_data=_ENABLED_PCT, status=_on_battery(battery_percent=FloatFloatBomb(10.0)),
        ))

    def test_drill_survives_a_float_bomb_percent(self):
        resp = self._drill(
            cfg_data=_ENABLED_PCT, status=_on_battery(battery_percent=FloatFloatBomb(10.0)),
        )
        self._assert_clean(resp)
        # An unreadable sensor fails its condition — the conservative
        # direction that never stops workloads on the unknown.
        self.assertFalse(resp.json()["would_trigger_now"])

    def test_drill_survives_an_int_subclass_float_bomb_percent(self):
        self._assert_clean(self._drill(
            cfg_data=_ENABLED_PCT, status=_on_battery(battery_percent=IntFloatBomb(10)),
        ))

    def test_drill_survives_a_float_bomb_remaining(self):
        # Percent held above the default floor so only the remaining check
        # meets the bomb; pre-fix ``float(remain)`` still 500'd the route.
        resp = self._drill(
            cfg_data=_ENABLED_MIN,
            status=_on_battery(battery_percent=90,
                               time_remaining_min=FloatFloatBomb(3.0)),
        )
        self._assert_clean(resp)
        self.assertFalse(resp.json()["would_trigger_now"])

    def test_drill_survives_a_reason_render_bomb_that_still_fires(self):
        # __float__ reads fine (inherited) so the condition *fires*, but
        # rendering the value into the reason f-string used to 500 after.
        resp = self._drill(
            cfg_data=_ENABLED_PCT,
            status=_on_battery(battery_percent=FloatFormatBomb(10.0)),
        )
        self._assert_clean(resp)
        # The trigger it describes still fires; only its label degrades.
        self.assertTrue(resp.json()["would_trigger_now"])
        self.assertEqual(resp.json()["reason"], "")


class ConditionSweepBombTests(UpsAppBase):
    """The same bomb must not raise out of sweep() into check_once."""

    def _sweep_over(self, cfg_data, status):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(ups_svc, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: status,
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: [],
            ))
            stack.enter_context(mock.patch.object(
                ups_policy, "_spawn", lambda target: True,
            ))
            return ups_policy.sweep(1_800_000_100)

    def test_sweep_does_not_raise_over_a_float_bomb_percent(self):
        # Pre-fix ``float(pct)`` raised out of sweep() and check_once's
        # containment silently killed every UPS policy tick.
        emitted = self._sweep_over(
            _ENABLED_PCT, _on_battery(battery_percent=FloatFloatBomb(10.0)),
        )
        self.assertIsInstance(emitted, list)
        # An unreadable sensor never latches the outage.
        self.assertNotEqual(
            ups_policy._load_state().get("phase"), ups_policy.PHASE_ENGAGED,
        )

    def test_sweep_does_not_raise_over_a_float_bomb_remaining(self):
        emitted = self._sweep_over(
            _ENABLED_MIN,
            _on_battery(battery_percent=90, time_remaining_min=FloatFloatBomb(3.0)),
        )
        self.assertIsInstance(emitted, list)


class ConditionUnitTests(unittest.TestCase):
    """``_condition`` reads bombs as unmet while keeping sane behaviour."""

    @staticmethod
    def _status(**over):
        return _on_battery(**over)

    @staticmethod
    def _policy(**over):
        p = {"trigger_pct": None, "trigger_remaining_min": None,
             "require_both": False}
        p.update(over)
        return p

    def test_float_bomb_percent_reads_as_not_met(self):
        hit, reason = ups_policy._condition(
            self._status(battery_percent=FloatFloatBomb(10.0)),
            self._policy(trigger_pct=25),
        )
        self.assertFalse(hit)
        self.assertEqual(reason, "")

    def test_reason_bomb_still_fires_with_empty_label(self):
        hit, reason = ups_policy._condition(
            self._status(battery_percent=FloatFormatBomb(10.0)),
            self._policy(trigger_pct=25),
        )
        self.assertTrue(hit)
        self.assertEqual(reason, "")

    def test_sane_percent_keeps_its_integer_label(self):
        hit, reason = ups_policy._condition(
            self._status(battery_percent=18),
            self._policy(trigger_pct=25),
        )
        self.assertTrue(hit)
        # Behaviour preserved: the raw integer renders, not "18.0".
        self.assertEqual(reason, "battery 18% ≤ 25%")

    def test_sane_remaining_keeps_its_integer_label(self):
        hit, reason = ups_policy._condition(
            self._status(time_remaining_min=4),
            self._policy(trigger_remaining_min=5),
        )
        self.assertTrue(hit)
        self.assertEqual(reason, "≈4 min left ≤ 5 min")


class StaysImmunePinTests(unittest.TestCase):
    """Floor shapes the hunt re-probed and found already immune."""

    @staticmethod
    def _policy(**over):
        p = {"trigger_pct": None, "trigger_remaining_min": None,
             "require_both": False}
        p.update(over)
        return p

    def test_hand_edited_string_floor_reads_as_condition_off(self):
        hit, _ = ups_policy._condition(
            _on_battery(battery_percent=10), self._policy(trigger_pct="25%"),
        )
        self.assertFalse(hit)

    def test_over_cap_floor_reads_as_condition_off(self):
        # ``float(10 ** 400)`` OverflowErrors; _below_floor falls through to
        # "not met" rather than 500ing, matching the _condition edge tests.
        hit, _ = ups_policy._condition(
            _on_battery(battery_percent=18), self._policy(trigger_pct=10 ** 400),
        )
        self.assertFalse(hit)


if __name__ == "__main__":
    unittest.main(verbosity=2)
