"""UPS leftover-500 sweep #10: bool-liars, shadow keys, torn sh results.

ups9 sealed the raising-``__class__``-property zoo and taught the launders to
refuse *lying* impostors on the str/bytes ranks.  Re-running the wave-10 zoo
(the wg10/host10 classes) over the mounted UPS routes — real ``create_app()``
+ ``TestClient(raise_server_exceptions=False)`` — surfaced four more raw 500s:

* **Bool-liars rode out of both ``_jsonable`` copies as themselves.**  bool
  cannot be subclassed, so a real flag is one of the two singletons — but a
  plain object whose ``__class__`` property *returns* bool passed the
  ``_isa(value, bool)`` gate and was returned unscrubbed.  Planted as
  ``settings.ups.shutdown.enabled`` (or any snapshot field) it 500'd
  GET /api/ups straight out of Starlette's encoder; carrying a ``__bool__``
  bomb it also detonated ``drill()``'s bare ``bool(policy.get("enabled"))``
  and ``_condition``'s bare ``require_both`` truth-test — 500ing
  GET /api/ups/shutdown/plan and POST /api/ups/shutdown/drill, blowing the
  effective-merge truth-test inside PUT /api/ups/settings, and raising out
  of ``sweep()`` into check_once's containment (every policy tick silently
  dead).  The bool gates are identity now (``type(x) is bool``) and the
  policy truth-tests go through ``_truthy``; a liar falls to the int rank,
  where the unbound base coercion refuses it and it drops like any other
  unrenderable.
* **A hash-shadowing snapshot key detonated the ``settings`` insert.**
  ``merged["settings"] = ups_settings()`` probes every stored key sharing
  the hash of ``"settings"``, so a leftover key whose ``__hash__`` matches
  and whose ``__eq__`` raises 500'd GET /api/ups *before* ``_jsonable`` ever
  saw the mapping.  ``ups_status`` launders first and inserts after, so the
  insert only ever compares honest exact-str keys and the sane snapshot
  siblings survive.
* **A torn ``sh`` seam result blew the unpack in ``ups_snapshot``.**
  ``rc, out, _ = sh(...)`` iterates whatever the seam handed back: a
  two-field result, a sequence subclass whose ``__iter__`` raises, and a
  patched ``sh`` that raises outright each 500'd GET /api/ups?force=true one
  step ahead of the ``_rc_int`` field guards.  ``_sh_triple`` reads an
  unreadable result as pmset failure — ``present: false``, never a 500.
* **A raising ``cfg()`` escaped ``ups_settings`` entirely.**  The call sat
  outside any try, ahead of every ``_mapping_get``, so a config root that
  raises on read 500'd GET /api/ups, the plan/drill routes and
  PUT /api/ups/settings at once.  No config now reads as the defaults.

No new error codes: everything degrades to defaults or drops field-level,
so no locale keys move.
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
from hub import ups_policy, ups_svc  # noqa: E402
from hub.routers import ups_api  # noqa: E402


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _liar(claimed):
    """A lying impostor: ``isinstance`` answers *claimed*, the object is not one."""

    class _Liar:
        @property
        def __class__(self):  # noqa: D105
            return claimed

    return _Liar()


def _bool_liar_bomb():
    """Claims bool through ``__class__`` *and* raises on the truth test."""

    class _LiarBB:
        @property
        def __class__(self):  # noqa: D105
            return bool

        def __bool__(self):  # noqa: D105
            raise RuntimeError("bool bomb")

    return _LiarBB()


class ShadowKey(str):
    """Hashes like its text; comparing it (any dict probe) raises."""

    def __hash__(self):  # noqa: D105
        return hash(str(self))

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("shadow eq bomb")

    __ne__ = __eq__


class IterBombSeq(tuple):
    """A real 3-tuple underneath; unpacking it runs the raising ``__iter__``."""

    def __iter__(self):  # noqa: D105
        raise RuntimeError("iter bomb")


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

    def _request(self, method: str, path: str, *, cfg_data=None, snapshot=None,
                 status=None, sh=None, body=None, saved=None):
        cfg_data = cfg_data if cfg_data is not None else {"settings": {}, "scripts": []}
        cfg_fn = cfg_data if callable(cfg_data) else (lambda: cfg_data)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(ups_svc, "cfg", cfg_fn))
            stack.enter_context(mock.patch.object(config, "cfg", cfg_fn))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: [],
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
            if method == "PUT":
                stack.enter_context(mock.patch.object(
                    ups_svc, "update_settings",
                    lambda patch: (saved.append(patch)
                                   if saved is not None else None),
                ))
                stack.enter_context(mock.patch.object(
                    ups_api.audit, "record", lambda *a, **k: None,
                ))
                return self.client.put(path, json=body)
            return self.client.get(path)

    def _get(self, path: str, **kw):
        return self._request("GET", path, **kw)

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", resp.text)
        return body


class GetUpsBoolLiarTests(UpsAppBase):
    """A bool-liar stored flag or snapshot field cannot 500 GET /api/ups."""

    def test_shutdown_enabled_bool_liar_drops_and_keeps_siblings(self):
        # Pre-fix: _jsonable's ``_isa(value, bool)`` gate returned the liar
        # as itself and Starlette's json.dumps 500'd GET /api/ups.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"shutdown": {
                "enabled": _liar(bool), "trigger_pct": 30,
            }}},
        }))
        shutdown = body["settings"]["shutdown"]
        self.assertIsNone(shutdown["enabled"])
        self.assertEqual(shutdown["trigger_pct"], 30)

    def test_snapshot_charging_bool_liar_drops_and_keeps_siblings(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "charging": _liar(bool),
            "battery_percent": 55, "halt_levels": None,
        }))
        self.assertIsNone(body["charging"])
        self.assertEqual(body["battery_percent"], 55)
        self.assertTrue(body["present"])

    def test_real_flags_stay_exact_booleans(self):
        # The identity gate must not change honest flags: True/False pass
        # through both scrub copies untouched.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"alerts_enabled": False, "shutdown": {
                "enabled": True, "trigger_pct": 30,
            }}},
        }))
        self.assertIs(body["settings"]["alerts_enabled"], False)
        self.assertIs(body["settings"]["shutdown"]["enabled"], True)


class PlanDrillBoolLiarTests(UpsAppBase):
    """A bool-liar ``__bool__`` bomb cannot 500 the plan/drill payload."""

    def test_enabled_bool_liar_bomb_reads_as_disabled(self):
        # Pre-fix: the liar leaked through _jsonable and drill()'s bare
        # ``bool(policy.get("enabled"))`` detonated into a 500.
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan",
            cfg_data={"settings": {"ups": {"shutdown": {
                "enabled": _bool_liar_bomb(), "trigger_pct": 25,
            }}}, "scripts": []},
            status=_on_battery(),
        ))
        self.assertFalse(body["enabled"])
        self.assertFalse(body["would_trigger_now"])

    def test_require_both_bool_liar_bomb_cannot_500_the_condition(self):
        # Pre-fix: _condition's bare ``policy.get("require_both")`` truth
        # test ran the bomb and 500'd the plan/drill routes.
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan",
            cfg_data={"settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 25, "trigger_remaining_min": 720,
                "require_both": _bool_liar_bomb(),
            }}}, "scripts": []},
            status=_on_battery(),
        ))
        # Both configured conditions hold, so the trigger fires whichever
        # way the unreadable flag degrades — the payload just must render.
        self.assertTrue(body["would_trigger_now"])


class PutSettingsBoolLiarTests(UpsAppBase):
    """The effective-merge validation survives a bool-liar stored flag."""

    def test_put_shutdown_patch_over_bool_liar_bomb_store_saves(self):
        # Pre-fix: ``effective.get("enabled")`` truth-tested the leaked
        # liar and its ``__bool__`` bomb 500'd PUT /api/ups/settings.
        saved: list = []
        resp = self._request(
            "PUT", "/api/ups/settings",
            cfg_data={"settings": {"ups": {"shutdown": {
                "enabled": _bool_liar_bomb(), "trigger_pct": 25,
            }}}},
            body={"shutdown": {"trigger_pct": 30}}, saved=saved,
        )
        self._assert_clean(resp)
        self.assertEqual(saved, [{"ups": {"shutdown": {"trigger_pct": 30}}}])


class ShadowKeyTests(UpsAppBase):
    """A hash-shadowing snapshot key cannot detonate the settings insert."""

    def test_snapshot_key_shadowing_settings_keeps_siblings(self):
        # Pre-fix: ``merged["settings"] = ...`` probed the stored key that
        # hashes like "settings"; its raising __eq__ 500'd GET /api/ups.
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, ShadowKey("settings"): 1,
            "battery_percent": 50, "halt_levels": None,
        }))
        self.assertEqual(body["battery_percent"], 50)
        self.assertTrue(body["present"])
        # The laundered shadow key was overwritten by the real block.
        self.assertEqual(body["settings"]["low_battery_pct"], 20)

    def test_snapshot_key_shadowing_a_sibling_field_still_renders(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, ShadowKey("battery_percent"): 77,
            "halt_levels": None,
        }))
        self.assertTrue(body["present"])
        self.assertIn("settings", body)


class ShSeamTornResultTests(UpsAppBase):
    """A torn / iteration-refusing / raising sh result reads as pmset failure."""

    def test_two_field_sh_result_reads_as_no_ups(self):
        # Pre-fix: the ``rc, out, _`` unpack ValueError'd out of
        # ups_snapshot and 500'd GET /api/ups?force=true.
        body = self._assert_clean(self._get(
            "/api/ups?force=true", sh=lambda *a, **k: (0, ""),
        ))
        self.assertFalse(body["present"])

    def test_iter_bomb_sh_result_reads_as_no_ups(self):
        body = self._assert_clean(self._get(
            "/api/ups?force=true",
            sh=lambda *a, **k: IterBombSeq((0, "", "")),
        ))
        self.assertFalse(body["present"])

    def test_raising_sh_seam_reads_as_no_ups(self):
        def boom(*a, **k):
            raise RuntimeError("sh bomb")

        body = self._assert_clean(self._get("/api/ups?force=true", sh=boom))
        self.assertFalse(body["present"])


class CfgRaisesTests(UpsAppBase):
    """A raising config root reads as the defaults, never a 500."""

    def _raising_cfg(self):
        def boom():
            raise RuntimeError("cfg bomb")
        return boom

    def test_get_ups_over_raising_cfg_answers_defaults(self):
        body = self._assert_clean(self._get("/api/ups",
                                            cfg_data=self._raising_cfg()))
        self.assertEqual(body["settings"]["low_battery_pct"], 20)
        self.assertFalse(body["settings"]["shutdown"]["enabled"])

    def test_plan_over_raising_cfg_still_renders(self):
        body = self._assert_clean(self._get(
            "/api/ups/shutdown/plan", cfg_data=self._raising_cfg(),
            status={"present": False},
        ))
        self.assertFalse(body["enabled"])
        self.assertFalse(body["would_trigger_now"])


class SweepBoolLiarTests(UpsAppBase):
    """The same bombs must not raise out of sweep() into check_once."""

    def _sweep_over(self, cfg_data, status):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                ups_svc, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(
                ups_policy, "_ups_status", lambda: status))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks", lambda: []))
            stack.enter_context(mock.patch.object(
                ups_policy, "_spawn", lambda target: True))
            return ups_policy.sweep(1_800_000_100)

    def test_sweep_survives_a_bool_liar_bomb_enabled_flag(self):
        # Pre-fix the bare ``policy.get("enabled")`` truth-test raised out
        # of _sweep_locked and silently killed every UPS policy tick.
        emitted = self._sweep_over(
            {"settings": {"ups": {"shutdown": {
                "enabled": _bool_liar_bomb(), "trigger_pct": 25,
            }}}},
            _on_battery(),
        )
        self.assertEqual(emitted, [])
        # An unreadable flag never fires the policy — the conservative
        # direction the module documents.
        self.assertNotEqual(
            ups_policy._load_state().get("phase"), ups_policy.PHASE_ENGAGED,
        )

    def test_sweep_survives_a_bool_liar_bomb_require_both(self):
        emitted = self._sweep_over(
            {"settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 25, "trigger_remaining_min": 720,
                "require_both": _bool_liar_bomb(),
            }}}},
            _on_battery(),
        )
        self.assertIsInstance(emitted, list)


class SanitizerUnitTests(unittest.TestCase):
    """The helpers degrade the wave-10 shapes while keeping sane values."""

    def test_jsonable_drops_bool_liars_and_keeps_real_flags(self):
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            out = scrub({"flag": _liar(bool), "on": True, "off": False})
            self.assertIsNone(out["flag"])
            self.assertIs(out["on"], True)
            self.assertIs(out["off"], False)
            _starlette(out)

    def test_ups_settings_reads_a_bool_liar_enabled_as_unset(self):
        with mock.patch.object(ups_svc, "cfg", lambda: {
            "settings": {"ups": {"shutdown": {
                "enabled": _bool_liar_bomb(), "trigger_pct": 25,
            }}},
        }):
            out = ups_svc.ups_settings()
        self.assertIsNone(out["shutdown"]["enabled"])
        self.assertEqual(out["shutdown"]["trigger_pct"], 25)
        _starlette(out)

    def test_sh_triple_passes_sane_results_exactly(self):
        with mock.patch.object(ups_svc, "sh", lambda *a, **k: (0, "out", "err")):
            self.assertEqual(
                ups_svc._sh_triple(["/usr/bin/pmset", "-g", "batt"], timeout=5),
                (0, "out", "err"),
            )

    def test_sh_triple_reads_torn_results_as_failure(self):
        for result in ((0, ""), IterBombSeq((0, "", "")), None):
            with mock.patch.object(ups_svc, "sh", lambda *a, **k: result):
                rc, out, err = ups_svc._sh_triple(["x"], timeout=5)
            self.assertEqual((rc, out, err), (-255, "", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
