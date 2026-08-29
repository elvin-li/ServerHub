"""UPS leftover-500 sweep #11: the wave-11 zoo over the mounted UPS routes.

ups10 sealed the bool-liars (identity ``type(x) is bool`` gates), the
hash-shadowing ``settings`` insert (launder-before-insert in
``ups_status``), the torn ``sh`` result (``_sh_triple``) and the raising
``cfg()`` (guarded read in ``ups_settings``).  This sweep re-ran the
wave-11 zoo -- the honest-hash *hash-shadow* / *eq-ne* key shape
(health11/wg11/dash11), the *answer-shape* ``sh`` bombs (docker11/dash11),
the *nested unbound-base* scalar bombs (modules/host9), the *lying*
``__class__`` impostors, the ``dict``-subclass ``get``/``items``/``__bool__``
bombs (pool5) and the state-file *huge-int* / *FIFO* leftovers (ups7 /
metrics-sampler) -- across every UPS JSON route with the real
``create_app()`` + ``TestClient(raise_server_exceptions=False)``:

* GET /api/ups
* PUT /api/ups/settings
* GET /api/ups/shutdown/plan
* POST /api/ups/shutdown/drill

and the ``sweep()`` tick that ``hub.alerts.check_once`` drives.

Every shape degrades -- a bomb field drops to ``None`` and its siblings
survive, a bomb seam reads as "no UPS present" / "condition not met", a
FIFO at the state path reads as ``idle`` instead of parking the request,
an over-cap integer in the state file drops alone while the latched phase
survives -- and no route answers 5xx or emits a payload Starlette's
``allow_nan=False`` encoder chokes on.

Nothing here changes hub/ups_svc.py or hub/ups_policy.py: the ups5-ups10
union guards already hold against the whole zoo, and this sweep pins that
so a later refactor cannot quietly reopen a seam.  The conflict policy is
honoured, not re-claimed -- ``_isa`` stays fail-closed, the bool gates stay
identity, ``_sh_triple`` reads a torn/iteration-refusing result as failure
(never a phantom success), ``_mapping_get`` / the guarded ``cfg()`` /
``items()`` reads stay pinned, and the product version stays 3.9.3.
"""
from __future__ import annotations

import json
import os
import signal
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
import hub.status as hub_status  # noqa: E402


# --------------------------------------------------------------------------- #
# The wave-11 zoo                                                             #
# --------------------------------------------------------------------------- #

def _class_prop_bomb():
    """A leftover that cannot answer what it is: ``isinstance`` raises."""

    class _CP:
        @property
        def __class__(self):  # noqa: D105
            raise RuntimeError("class-property bomb")

    return _CP()


def _liar(claimed):
    """A lying impostor: ``isinstance`` answers *claimed*, the object is not."""

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
    """Hashes like its text; any dict probe against it raises (wg11 shape)."""

    def __hash__(self):  # noqa: D105
        return hash(str(self))

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("shadow eq bomb")

    __ne__ = __eq__


class NeBombKey(str):
    """Honest hash, but ``==``/``!=`` raise (dash11 StampLocale shape)."""

    __hash__ = str.__hash__

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("ne bomb")

    __eq__ = __ne__


class GetBombDict(dict):
    """A dict subclass whose bound ``get`` raises (disk_power pool5 shape)."""

    def get(self, *a, **k):  # noqa: D105
        raise RuntimeError("get bomb")


class ItemsBombDict(dict):
    """A dict subclass whose bound ``items`` raises."""

    def items(self):  # noqa: D105
        raise RuntimeError("items bomb")


class BoolBombDict(dict):
    """A dict subclass whose truth test raises."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("dict bool bomb")


class IterBombList(list):
    """A real list underneath; iterating it runs the raising ``__iter__``."""

    def __iter__(self):  # noqa: D105
        raise RuntimeError("iter bomb")


class IterBombTuple(tuple):
    """A real 3-tuple underneath; iterating it runs the raising ``__iter__``."""

    def __iter__(self):  # noqa: D105
        raise RuntimeError("iter bomb")


class TupleLiar:
    """Claims tuple through ``__class__``; has no real sequence storage."""

    @property
    def __class__(self):  # noqa: D105
        return tuple


class EqBomb:
    """A non-str value whose ``==`` raises (seam status shape)."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("eq bomb")

    __hash__ = object.__hash__


class FloatEqBomb(float):
    """A float subclass whose ``__float__`` raises (ups8 shape)."""

    def __float__(self):  # noqa: D105
        raise RuntimeError("float bomb")


class IntStrBomb(int):
    """An int subclass whose ``__str__`` raises (ups6 shape)."""

    def __str__(self):  # noqa: D105
        raise RuntimeError("int str bomb")


class StrEncodeBomb(str):
    """A str subclass whose ``encode`` raises (ups6 shape)."""

    def encode(self, *a, **k):  # noqa: D105
        raise RuntimeError("encode bomb")


class BytesDecodeBomb(bytes):
    """A bytes subclass whose ``decode`` raises (ups6 shape)."""

    def decode(self, *a, **k):  # noqa: D105
        raise RuntimeError("decode bomb")


#: Past CPython's int->str digit cap: valid ``int``, unrenderable number.
HUGE_INT = 10 ** 5000
INF = float("inf")
NAN = float("nan")

#: What hub.util.sh / run_capped return when the binary is gone (sentinel).
MISSING = (-1, "", "not found")

_SANE_SNAPSHOT = {"present": False, "halt_levels": None}


def _on_battery(**over) -> dict:
    st = {"present": True, "on_battery": True, "on_ac": False,
          "battery_percent": 10, "time_remaining_min": 3}
    st.update(over)
    return st


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


# --------------------------------------------------------------------------- #
# Harness                                                                     #
# --------------------------------------------------------------------------- #

class UpsAppBase(unittest.TestCase):
    """create_app-wired client + policy state redirected into a temp dir."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        # raise_server_exceptions=False: a real 500 arrives as HTTP 500, not
        # a re-raised exception that would mask which route crashed.
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

    def _request(self, method: str, path: str, *, cfg_data=None, snapshot=None,
                 status=None, sh=None, full_status=None, list_stacks=None,
                 body=None, saved=None, state_text=None):
        cfg_data = cfg_data if cfg_data is not None else {"settings": {}, "scripts": []}
        cfg_fn = cfg_data if callable(cfg_data) else (lambda: cfg_data)
        if state_text is not None:
            self.state_file.write_text(state_text)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(ups_svc, "cfg", cfg_fn))
            stack.enter_context(mock.patch.object(config, "cfg", cfg_fn))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks",
                list_stacks if list_stacks is not None else (lambda: []),
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
            if full_status is not None:
                stack.enter_context(mock.patch.object(
                    hub_status, "full_status", lambda force=False: full_status,
                ))
            if method in ("PUT", "POST"):
                stack.enter_context(mock.patch.object(
                    ups_api.audit, "record", lambda *a, **k: None,
                ))
            if method == "PUT":
                stack.enter_context(mock.patch.object(
                    ups_svc, "update_settings",
                    lambda patch: (saved.append(patch)
                                   if saved is not None else None),
                ))
                return self.client.put(path, json=body)
            if method == "POST":
                stack.enter_context(mock.patch.object(
                    ups_api, "require_admin_browser", lambda req: "operator",
                ))
                return self.client.post(path)
            return self.client.get(path)

    def _get(self, path: str, **kw):
        return self._request("GET", path, **kw)

    def _assert_clean(self, resp, status=200):
        # < 500 is the contract: a coded 4xx/503 is a fine degrade, a 5xx is
        # the leftover this sweep hunts.
        self.assertLess(resp.status_code, 500, resp.text[:300])
        if status is not None:
            self.assertEqual(resp.status_code, status, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", resp.text)
        return body

    def _plan(self, **kw):
        return self._get("/api/ups/shutdown/plan", **kw)

    def _drill(self, **kw):
        return self._request("POST", "/api/ups/shutdown/drill", **kw)


_ENABLED_PCT = {"settings": {"ups": {"shutdown": {
    "enabled": True, "trigger_pct": 25, "stacks": "all",
}}}, "scripts": []}


def _enabled_with(**shutdown):
    base = {"enabled": True, "trigger_pct": 25, "stacks": "all"}
    base.update(shutdown)
    return {"settings": {"ups": {"shutdown": base}}, "scripts": []}


# --------------------------------------------------------------------------- #
# Hash-shadow / eq-ne key seams                                               #
# --------------------------------------------------------------------------- #

class HashShadowKeyTests(UpsAppBase):
    """Honest-hash shadow / eq-ne keys cannot 500 any UPS route."""

    def test_snapshot_key_shadowing_settings_keeps_siblings(self):
        # The ups10 launder-before-insert seam, re-pinned: the shadow key
        # that hashes like the inserted "settings" cannot detonate the
        # merged["settings"] write.
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, ShadowKey("settings"): 1,
            "battery_percent": 50, "halt_levels": None,
        }))
        self.assertEqual(body["battery_percent"], 50)
        self.assertEqual(body["settings"]["low_battery_pct"], 20)

    def test_snapshot_key_shadowing_shutdown_state_keeps_route(self):
        # get_ups inserts "shutdown_state" into the laundered payload; a
        # snapshot key that hashes like it must not detonate that insert.
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, ShadowKey("shutdown_state"): 1,
            "battery_percent": 42, "halt_levels": None,
        }))
        self.assertEqual(body["battery_percent"], 42)
        self.assertIn("shutdown_state", body)

    def test_ne_bomb_settings_key_reads_as_defaults(self):
        # An eq/ne str-subclass key in settings.ups: the per-pair guard in
        # ups_settings catches the ``k in UPS_DEFAULTS`` / ``k != "shutdown"``
        # compare and the sane sibling survives.
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {NeBombKey("alerts_enabled"): True,
                                  "low_battery_pct": 33}},
        }))
        self.assertEqual(body["settings"]["low_battery_pct"], 33)

    def test_shadow_shutdown_key_in_settings_survives(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {ShadowKey("shutdown"): 1,
                                 "low_battery_pct": 40}},
        }))
        self.assertEqual(body["settings"]["low_battery_pct"], 40)
        # The real shutdown block still resolves to its defaults.
        self.assertFalse(body["settings"]["shutdown"]["enabled"])

    def test_ne_bomb_shutdown_key_on_plan_and_drill(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            NeBombKey("enabled"): True, "trigger_pct": 25,
        }}}, "scripts": []}
        self._assert_clean(self._plan(cfg_data=cfg_data, status=_on_battery()))
        self._assert_clean(self._drill(cfg_data=cfg_data, status=_on_battery()))


# --------------------------------------------------------------------------- #
# sh() answer-shape                                                           #
# --------------------------------------------------------------------------- #

class ShAnswerShapeTests(UpsAppBase):
    """A torn/scalar/impostor sh result reads as "no UPS present" (200)."""

    def _no_ups(self, answer):
        body = self._assert_clean(self._get(
            "/api/ups?force=true", sh=lambda *a, **k: answer))
        self.assertFalse(body["present"])
        return body

    def test_two_tuple(self):
        self._no_ups((0, ""))

    def test_one_tuple(self):
        self._no_ups((0,))

    def test_four_tuple(self):
        self._no_ups((0, "", "", ""))

    def test_scalar_object(self):
        self._no_ups(object())

    def test_none(self):
        self._no_ups(None)

    def test_tuple_liar(self):
        self._no_ups(TupleLiar())

    def test_iter_bomb_tuple(self):
        self._no_ups(IterBombTuple((0, "x", "")))

    def test_dict_answer(self):
        self._no_ups({"rc": 0})

    def test_raising_sh(self):
        def boom(*a, **k):
            raise RuntimeError("sh spawn bomb")

        self._no_ups(boom)

    def test_missing_pmset_sentinel_is_not_present_not_503(self):
        # The "vanished CLI" pin for UPS: a missing pmset is "no UPS", a 200
        # (never a 503 or 500), matching test_cli_missing_leftover_503.
        self._no_ups(lambda *a, **k: MISSING)

    def test_honest_three_tuple_still_parses_a_present_ups(self):
        text = ("Now drawing from 'UPS Power'\n"
                " -APC Back-UPS ES 750 (id=1)\t80%; discharging present: true")
        body = self._assert_clean(self._get(
            "/api/ups?force=true",
            sh=lambda cmd, **k: (0, text, "") if cmd[-1] == "batt" else (0, "", ""),
        ))
        self.assertTrue(body["present"])
        self.assertEqual(body["battery_percent"], 80)


class ShRcAndTextBombTests(UpsAppBase):
    """rc bombs and over-cap pmset text degrade rather than 500."""

    def test_rc_int_junk_reads_minus_255(self):
        class RcBomb:
            def __index__(self):
                raise RuntimeError("rc boom")

        self.assertEqual(ups_svc._rc_int(RcBomb()), -255)
        self.assertEqual(ups_svc._rc_int(0), 0)
        self.assertEqual(ups_svc._rc_int(True), 1)
        self.assertEqual(ups_svc._rc_int(-1), -1)

    def test_over_cap_remaining_and_percent_text(self):
        text = ("Now drawing from 'UPS Power'\n -APC UPS (id=1)\t"
                "50%; discharging; " + ("9" * 9000) + ":00 remaining present: true")
        body = self._assert_clean(self._get(
            "/api/ups?force=true",
            sh=lambda cmd, **k: (0, text, "") if cmd[-1] == "batt" else (0, "", ""),
        ))
        self.assertTrue(body["present"])
        # The unrenderable runtime dropped; the route still answers.
        self.assertIsNone(body["time_remaining_min"])

    def test_over_cap_haltlevel_text(self):
        def sh(cmd, **k):
            if cmd[-1] == "batt":
                return (0, "Now drawing from 'UPS Power'\n -APC UPS (id=1)"
                           "\t50%; discharging present: true", "")
            return (0, "haltlevel " + ("9" * 9000), "")

        body = self._assert_clean(self._get("/api/ups?force=true", sh=sh))
        self.assertTrue(body["present"])
        _starlette(body)


# --------------------------------------------------------------------------- #
# Nested unbound-base scalar bombs + lying impostors                          #
# --------------------------------------------------------------------------- #

class NestedScalarBombTests(UpsAppBase):
    """Subclass scalar bombs nested in the snapshot drop, siblings survive."""

    def test_nested_bombs_in_a_list_field(self):
        # The unbound-base rule salvages a subclass scalar's real value while
        # dropping the genuinely unrenderable siblings — all without ever
        # running the bombed dunder into Starlette's encoder.
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 5,
            "junk": [IntStrBomb(3), FloatEqBomb(1.0), StrEncodeBomb("z"),
                     BytesDecodeBomb(b"z"), HUGE_INT, INF, NAN,
                     _class_prop_bomb(), _bool_liar_bomb()],
        }))
        self.assertEqual(body["battery_percent"], 5)
        junk = body["junk"]
        # int/float/str/bytes subclass bombs render their real value through
        # the unbound base coercion (int.__index__, float.__float__,
        # str.encode, bytes.decode) rather than their poisoned dunder.
        self.assertEqual(junk[0], 3)
        self.assertEqual(junk[1], 1.0)
        self.assertEqual(junk[2], "z")
        self.assertEqual(junk[3], "z")
        # The over-cap int and the non-finite floats have no renderable
        # value and drop to null; the __class__-property bomb renders as
        # harmless fallback text (_as_text); the bool-liar drops.
        self.assertIsNone(junk[4])   # HUGE_INT
        self.assertIsNone(junk[5])   # INF
        self.assertIsNone(junk[6])   # NAN
        self.assertIsInstance(junk[7], str)  # __class__-property bomb
        self.assertIsNone(junk[8])   # bool-liar

    def test_nested_bombs_in_a_dict_field(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 7,
            "sub": {"a": HUGE_INT, "b": INF, "c": _class_prop_bomb(),
                    "d": 12, "e": "ok"},
        }))
        self.assertEqual(body["battery_percent"], 7)
        self.assertEqual(body["sub"]["d"], 12)
        self.assertEqual(body["sub"]["e"], "ok")
        self.assertIsNone(body["sub"]["a"])
        self.assertIsNone(body["sub"]["b"])

    def test_huge_and_inf_thresholds_degrade_to_defaults(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {
                "low_battery_pct": HUGE_INT,
                "shutdown": {"enabled": True, "trigger_pct": INF,
                             "trigger_remaining_min": HUGE_INT},
            }},
        }))
        # low_battery_pct falls back to its default; the inf/huge triggers
        # drop to None (condition off) rather than leaking into the encoder.
        self.assertEqual(body["settings"]["low_battery_pct"], 20)
        self.assertIsNone(body["settings"]["shutdown"]["trigger_pct"])
        self.assertIsNone(body["settings"]["shutdown"]["trigger_remaining_min"])


class LyingImpostorTests(UpsAppBase):
    """Lying-``__class__`` impostors at value and whole-object seams."""

    def test_impostor_whole_snapshot(self):
        for claimed in (dict, list, str, int):
            body = self._assert_clean(self._get("/api/ups", snapshot=_liar(claimed)))
            # A non-mapping snapshot yields the settings-only payload.
            self.assertIn("settings", body)

    def test_impostor_values_in_snapshot(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 9,
            "x": _liar(bytes), "y": _liar(int), "z": _liar(float),
        }))
        self.assertEqual(body["battery_percent"], 9)

    def test_class_prop_bomb_whole_status_on_plan_drill(self):
        self._assert_clean(self._plan(cfg_data=_ENABLED_PCT,
                                      status=_class_prop_bomb()))
        self._assert_clean(self._drill(cfg_data=_ENABLED_PCT,
                                       status=_class_prop_bomb()))


# --------------------------------------------------------------------------- #
# bool-liar / type(x) is bool                                                 #
# --------------------------------------------------------------------------- #

class BoolLiarTests(UpsAppBase):
    """A bool-liar flag drops (identity gate); real flags stay exact."""

    def test_bool_liar_snapshot_and_settings_flags(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"alerts_enabled": _liar(bool), "shutdown": {
                "enabled": _liar(bool), "trigger_pct": 30,
            }}},
        }, snapshot={"present": True, "charging": _liar(bool),
                     "battery_percent": 60, "halt_levels": None}))
        self.assertIsNone(body["charging"])
        self.assertEqual(body["battery_percent"], 60)
        self.assertEqual(body["settings"]["shutdown"]["trigger_pct"], 30)

    def test_real_flags_stay_exact_booleans(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"alerts_enabled": False, "shutdown": {
                "enabled": True, "trigger_pct": 30,
            }}},
        }))
        self.assertIs(body["settings"]["alerts_enabled"], False)
        self.assertIs(body["settings"]["shutdown"]["enabled"], True)

    def test_bool_liar_bomb_on_plan_drill_and_put(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            "enabled": _bool_liar_bomb(), "trigger_pct": 25,
        }}}, "scripts": []}
        plan = self._assert_clean(self._plan(cfg_data=cfg_data,
                                             status=_on_battery()))
        self.assertFalse(plan["enabled"])
        saved: list = []
        resp = self._request("PUT", "/api/ups/settings", cfg_data=cfg_data,
                             body={"shutdown": {"trigger_pct": 30}}, saved=saved)
        self._assert_clean(resp)
        self.assertEqual(saved, [{"ups": {"shutdown": {"trigger_pct": 30}}}])


# --------------------------------------------------------------------------- #
# dict-subclass get / items / __bool__                                        #
# --------------------------------------------------------------------------- #

class DictSubclassBombTests(UpsAppBase):
    """get/items/__bool__ bombs as whole seams and as rows cannot 500."""

    def test_whole_cfg_and_snapshot_bombs(self):
        for snap in (GetBombDict({"present": True, "battery_percent": 5, "halt_levels": None}),
                     ItemsBombDict({"present": True, "battery_percent": 5, "halt_levels": None}),
                     BoolBombDict({"present": True, "battery_percent": 5, "halt_levels": None})):
            self._assert_clean(self._get("/api/ups", snapshot=snap))
        for cfgd in (GetBombDict({"settings": {}}),
                     ItemsBombDict({"settings": {}}),
                     {"settings": {"ups": GetBombDict({"low_battery_pct": 40})}},
                     {"settings": {"ups": ItemsBombDict({"low_battery_pct": 40})}},
                     {"settings": {"ups": {"shutdown": GetBombDict({"enabled": True})}}}):
            self._assert_clean(self._get("/api/ups", cfg_data=cfgd))

    def test_status_bombs_on_plan_and_drill(self):
        for status in (GetBombDict(_on_battery()),
                       ItemsBombDict(_on_battery()),
                       BoolBombDict(_on_battery())):
            self._assert_clean(self._plan(cfg_data=_ENABLED_PCT, status=status))
            self._assert_clean(self._drill(cfg_data=_ENABLED_PCT, status=status))

    def test_stack_and_service_row_bombs_on_plan(self):
        cfg_data = _enabled_with(stop_scripts=["svc1"])
        for stacks in ([_class_prop_bomb()],
                       [GetBombDict({"id": "web", "status": "ok"})],
                       [{"id": "web", "status": EqBomb()}],
                       [{"id": IntStrBomb(7), "status": "ok"}],
                       [{"id": HUGE_INT, "status": "ok"}],
                       IterBombList([{"id": "web"}])):
            self._assert_clean(self._plan(
                cfg_data=cfg_data, status=_on_battery(),
                list_stacks=(lambda s=stacks: s)))

    def test_service_state_row_bombs_on_plan(self):
        cfg_data = _enabled_with(stop_scripts=["svc1"])
        for full in ({"groups": [{"services": [{"id": "svc1", "state": EqBomb()}]}]},
                     {"groups": [{"services": [GetBombDict({"id": "svc1", "state": "ok"})]}]},
                     {"groups": [{"services": IterBombList([{"id": "svc1", "state": "ok"}])}]},
                     {"groups": [GetBombDict({"services": []})]},
                     {"groups": IterBombList([{"services": []}])},
                     GetBombDict({"groups": []})):
            self._assert_clean(self._plan(
                cfg_data=cfg_data, status=_on_battery(), full_status=full))

    def test_catalog_script_row_bombs_on_plan(self):
        for scripts in ([{"id": "a", "stop": BoolBombDict({})}],
                        [{"id": HUGE_INT}],
                        [_class_prop_bomb()],
                        IterBombList([{"id": "a"}])):
            cfg_data = {"settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 25,
            }}}, "scripts": scripts}
            self._assert_clean(self._plan(cfg_data=cfg_data, status=_on_battery()))


# --------------------------------------------------------------------------- #
# state file: huge int, deep nest, surrogate keys, FIFO                        #
# --------------------------------------------------------------------------- #

class StateFileLeftoverTests(UpsAppBase):
    """The policy state file's leftovers degrade GET /api/ups, never 500."""

    def _body(self, text):
        return self._assert_clean(self._get("/api/ups", state_text=text))

    def test_over_cap_engaged_at_keeps_the_latch(self):
        # The ups7 digit-wipe pin: an over-cap engaged_at drops to null but
        # the latched phase and the sibling step survive, so a restart mid
        # outage still resumes instead of reading the whole state as idle.
        text = ('{"phase":"engaged","engaged_at":' + ("9" * 6000) +
                ',"stop_done":false,"steps":[{"kind":"stack","id":"web",'
                '"running":true,"stop_issued":true}]}')
        body = self._body(text)
        state = body["shutdown_state"]
        self.assertEqual(state["phase"], "engaged")
        self.assertIsNone(state["engaged_at"])
        self.assertEqual(len(state["steps"]), 1)

    def test_deeply_nested_state_reads_as_idle(self):
        text = '{"phase":"idle","d":' + ("[" * 400) + ("]" * 400) + "}"
        body = self._body(text)
        self.assertEqual(body["shutdown_state"]["phase"], "idle")

    def test_infinity_and_surrogate_state_render(self):
        for text in ('{"phase":"engaged","engaged_at":Infinity,"steps":[]}',
                     '{"phase":"idle","steps":[{"\\ud800x":"y"}]}',
                     '{"phase":123,"steps":{"a":1}}',
                     '[1,2,3]', 'not json {'):
            body = self._body(text)
            self.assertIn("shutdown_state", body)

    def test_fifo_at_state_path_reads_as_idle_without_hanging(self):
        # The metrics-sampler FIFO leftover: open() of a FIFO parks until a
        # writer appears.  read_text_capped's O_NONBLOCK + S_ISREG guard
        # turns it into an OSError that _load_state swallows, so the route
        # answers idle instead of wedging the request forever.
        self.state_file.unlink(missing_ok=True)
        os.mkfifo(self.state_file)
        self.addCleanup(lambda: self.state_file.exists()
                        and self.state_file.unlink())

        def _bail(sig, frame):
            raise TimeoutError("public_state hung on the FIFO")

        old = signal.signal(signal.SIGALRM, _bail)
        signal.alarm(5)
        try:
            body = self._assert_clean(self._get("/api/ups"))
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        self.assertEqual(body["shutdown_state"]["phase"], "idle")


# --------------------------------------------------------------------------- #
# sweep(): the same bombs must stay contained (never raise into check_once)    #
# --------------------------------------------------------------------------- #

class SweepStaysContainedTests(UpsAppBase):
    """The zoo through sweep() returns a list; a raise would kill the tick."""

    def _sweep(self, cfg_data, status, *, list_stacks=None, state_text=None):
        if state_text is not None:
            self.state_file.write_text(state_text)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(ups_svc, "cfg", lambda: cfg_data))
            stack.enter_context(mock.patch.object(ups_policy, "_ups_status", lambda: status))
            stack.enter_context(mock.patch.object(
                ups_policy, "_list_stacks",
                list_stacks if list_stacks is not None else (lambda: [])))
            stack.enter_context(mock.patch.object(ups_policy, "_spawn", lambda t: True))
            return ups_policy.sweep(1_800_000_100)

    def test_bool_liar_bomb_enabled_stays_contained(self):
        out = self._sweep(
            {"settings": {"ups": {"shutdown": {
                "enabled": _bool_liar_bomb(), "trigger_pct": 25}}}},
            _on_battery())
        self.assertEqual(out, [])
        self.assertNotEqual(ups_policy._load_state().get("phase"),
                            ups_policy.PHASE_ENGAGED)

    def test_dict_bomb_status_stays_contained(self):
        for status in (GetBombDict(_on_battery()), BoolBombDict(_on_battery()),
                       _class_prop_bomb()):
            self.assertIsInstance(self._sweep(
                {"settings": {"ups": {"shutdown": {
                    "enabled": True, "trigger_pct": 25}}}}, status), list)

    def test_ne_bomb_settings_key_stays_contained(self):
        out = self._sweep(
            {"settings": {"ups": {"shutdown": {
                NeBombKey("enabled"): True, "trigger_pct": 25}}}},
            _on_battery())
        self.assertIsInstance(out, list)

    def test_over_cap_worker_pid_on_ac_stays_contained(self):
        # os.kill of an over-cap pid raises OverflowError, not OSError; a bare
        # probe would abort the whole tick.  _worker_busy reads it as free.
        text = ('{"phase":"engaged","worker_owner":{"pid":' + ("9" * 6000) +
                ',"ts":1},"steps":[]}')
        out = self._sweep(
            {"settings": {"ups": {"shutdown": {"enabled": True, "trigger_pct": 25}}}},
            _on_battery(on_battery=False, on_ac=True),
            state_text=text)
        self.assertIsInstance(out, list)


# --------------------------------------------------------------------------- #
# Conflict-policy pins: the union guards stay exactly where prior sweeps put   #
# them, and the product version does not drift.                                #
# --------------------------------------------------------------------------- #

class UnionGuardPins(unittest.TestCase):
    """ups5-ups10 guards must not be weakened by any later refactor."""

    def test_isa_is_fail_closed_on_a_class_prop_bomb(self):
        for isa in (ups_svc._isa, ups_policy._isa):
            self.assertFalse(isa(_class_prop_bomb(), dict))
            self.assertTrue(isa({}, dict))
            self.assertTrue(isa(5, int))

    def test_jsonable_bool_gates_stay_identity(self):
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            self.assertIsNone(scrub(_liar(bool)))
            self.assertIs(scrub(True), True)
            self.assertIs(scrub(False), False)

    def test_jsonable_drops_huge_int_and_inf(self):
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            self.assertIsNone(scrub(HUGE_INT))
            self.assertIsNone(scrub(INF))
            self.assertIsNone(scrub(NAN))
            self.assertEqual(scrub(42), 42)

    def test_sh_triple_reads_torn_results_as_failure(self):
        for result in ((0, ""), IterBombTuple((0, "", "")), None, object()):
            with mock.patch.object(ups_svc, "sh", lambda *a, **k: result):
                self.assertEqual(
                    ups_svc._sh_triple(["x"], timeout=5), (-255, "", ""))
        with mock.patch.object(ups_svc, "sh", lambda *a, **k: (0, "o", "e")):
            self.assertEqual(
                ups_svc._sh_triple(["x"], timeout=5), (0, "o", "e"))

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[ShadowKey("gone")] = 1
        # The shadowed field cannot be read (the compare raises both ways);
        # its sane sibling still resolves.
        self.assertEqual(ups_svc._mapping_get(d, "keep"), 2)
        self.assertIsNone(ups_svc._mapping_get(d, "gone"))
        # A subclass that only poisoned its ``get`` keeps its real storage,
        # read through the unbound ``dict.get`` fallback.
        self.assertEqual(ups_svc._mapping_get(GetBombDict({"x": 1}), "x"), 1)
        self.assertIsNone(ups_svc._mapping_get(object(), "x"))

    def test_raising_cfg_reads_as_defaults(self):
        def boom():
            raise RuntimeError("cfg bomb")

        with mock.patch.object(ups_svc, "cfg", boom):
            out = ups_svc.ups_settings()
        self.assertEqual(out["low_battery_pct"], 20)
        self.assertFalse(out["shutdown"]["enabled"])
        _starlette(out)

    def test_row_get_and_seam_helpers_stay_fail_closed(self):
        # A get-bomb row keeps its real storage via the unbound fallback; a
        # shadow-keyed lookup and a non-mapping both read as None.
        self.assertEqual(ups_policy._row_get(GetBombDict({"x": 1}), "x"), 1)
        shadowed = {"x": 1}
        shadowed[ShadowKey("gone")] = 2
        self.assertIsNone(ups_policy._row_get(shadowed, "gone"))
        self.assertIsNone(ups_policy._row_get(object(), "x"))
        self.assertFalse(ups_policy._seam_eq(EqBomb(), "ok"))
        self.assertTrue(ups_policy._seam_eq("ok", "ok"))
        self.assertFalse(ups_policy._truthy(_bool_liar_bomb()))
        self.assertFalse(ups_policy._below_floor(FloatEqBomb(1.0), 25))

    def test_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
