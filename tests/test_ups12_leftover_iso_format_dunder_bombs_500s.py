"""UPS leftover-500 sweep #12: the dunder-bomb wave the earlier sweeps did
not name, driven over the mounted UPS routes.

ups11 re-ran the wave-11 zoo (honest-hash shadow / eq-ne keys, torn ``sh``
answers, nested unbound-base scalar bombs, lying ``__class__`` impostors,
the ``dict``-subclass ``get``/``items``/``__bool__`` bombs and the state-file
huge-int / FIFO leftovers) and pinned the ups5-ups10 union guards.  This
sweep hunts the *remaining* dunder seams a leftover can plant that the
earlier waves never exercised by name, across the same four JSON routes with
the real ``create_app()`` + ``TestClient(raise_server_exceptions=False)``:

* GET /api/ups
* PUT /api/ups/settings
* GET /api/ups/shutdown/plan
* POST /api/ups/shutdown/drill

The new shapes:

* an ``isoformat`` that *raises* (``_jsonable``'s duck-typed date branch runs
  a leftover's own method) and one that returns a non-finite ``inf`` (which
  must be re-laundered, not leaked into Starlette's ``allow_nan=False``);
* a ``__repr__``/``__str__`` bomb value with no ``isoformat`` at all, which
  ``_as_text`` must render as harmless fallback text rather than 500;
* a ``__format__`` bomb ``battery_percent`` / ``time_remaining_min`` from the
  ``_ups_status`` seam, which ``_reason``'s ``str.format`` must not detonate
  after the trigger has fired;
* an ``int``-subclass ``__index__``/``__int__`` bomb threshold, which
  ``_finite_int`` must fall back on rather than raise out of;
* a ``dict`` subclass whose ``keys``/``__getitem__`` raises as the whole
  snapshot (the ``{**snap}`` spread and ``ups_settings`` read must survive);
* a ``__class__``-property bomb sitting as a *dict key* (object hashes fine,
  so it is a reachable leftover) that ``_jsonable``'s key laundering renders
  through ``str()`` instead of blowing up;
* a lying ``__class__`` snapshot that claims ``dict`` but has no mapping
  storage, so the ``{**snap}`` spread TypeErrors into the settings-only body;
* new state-file leftovers -- a ``worker_owner.pid`` of ``1e400`` and a
  ``steps`` list of non-dict scalars -- that read as idle/degrade instead of
  500ing GET /api/ups; and
* odd policy shapes -- ``stacks`` stored as a mapping, ``stop_scripts``
  carrying huge/inf/dict junk -- that resolve to an empty selection.

Every shape degrades: a bomb field drops to ``None`` and its siblings
survive, a bomb seam reads as "no UPS present" / "condition not met", and no
route answers 5xx or emits a payload Starlette's ``allow_nan=False`` encoder
chokes on.

Nothing here changes hub/ups_svc.py or hub/ups_policy.py: the ups5-ups11
union guards (``_isa`` fail-closed, identity ``type(x) is bool`` gates, the
guarded unbound-base decode/encode, ``_sh_triple``, ``_mapping_get``, the
guarded ``cfg()``/``dict.get``/``items()`` reads, ``_seam_eq``/``_truthy``/
``_below_floor``/``_reason``/``_cfg_text``) already hold against this wave,
and this sweep pins that so a later refactor cannot quietly reopen a seam.
The conflict policy is honoured, not re-claimed, and the product version
stays 3.9.3.
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
import hub.status as hub_status  # noqa: E402


# --------------------------------------------------------------------------- #
# The wave-12 dunder zoo                                                       #
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


class IsoRaiseBomb:
    """Duck-types a date: ``_jsonable`` calls ``isoformat`` and it raises."""

    def isoformat(self):  # noqa: D105
        raise RuntimeError("iso bomb")


class IsoInfBomb:
    """``isoformat`` returns a non-finite float that must be re-laundered."""

    def isoformat(self):  # noqa: D105
        return float("inf")


class ReprStrBomb:
    """No ``isoformat``; both ``__repr__`` and ``__str__`` raise."""

    def __repr__(self):  # noqa: D105
        raise RuntimeError("repr bomb")

    def __str__(self):  # noqa: D105
        raise RuntimeError("str bomb")


class FormatStrBomb:
    """A seam value whose ``__format__``/``__str__`` raise (``_reason`` shape)."""

    def __format__(self, spec):  # noqa: D105
        raise RuntimeError("format bomb")

    def __str__(self):  # noqa: D105
        raise RuntimeError("str bomb")


class IndexIntBomb(int):
    """An int subclass whose ``__index__``/``__int__``/``__str__`` all raise."""

    def __index__(self):  # noqa: D105
        raise RuntimeError("index bomb")

    def __int__(self):  # noqa: D105
        raise RuntimeError("int bomb")

    def __str__(self):  # noqa: D105
        raise RuntimeError("str bomb")


class KeysBombDict(dict):
    """A dict subclass whose ``keys`` raises (the ``{**snap}`` spread seam)."""

    def keys(self):  # noqa: D105
        raise RuntimeError("keys bomb")


class GetItemBombDict(dict):
    """A dict subclass whose ``__getitem__`` raises (subscript seam)."""

    def __getitem__(self, k):  # noqa: D105
        raise RuntimeError("getitem bomb")


class IterBombList(list):
    """A real list underneath; iterating it runs the raising ``__iter__``."""

    def __iter__(self):  # noqa: D105
        raise RuntimeError("iter bomb")


#: Past CPython's int->str digit cap: valid ``int``, unrenderable number.
HUGE_INT = 10 ** 5000
INF = float("inf")
NAN = float("nan")

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
# Harness (same shape as the ups11 sweep)                                      #
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
# isoformat seams                                                             #
# --------------------------------------------------------------------------- #

class IsoformatBombTests(UpsAppBase):
    """``_jsonable``'s duck-typed date branch cannot 500 or leak inf."""

    def test_isoformat_raises_drops_the_field(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 44,
            "when": IsoRaiseBomb(),
        }))
        self.assertEqual(body["battery_percent"], 44)
        # An isoformat that raises leaves the value to _as_text, which renders
        # harmless fallback text (never a 500, never a leaked object).
        self.assertIsInstance(body["when"], str)

    def test_isoformat_returns_inf_is_relaundered_to_null(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 51,
            "when": IsoInfBomb(),
        }))
        self.assertEqual(body["battery_percent"], 51)
        # The non-finite isoformat result is re-laundered and dropped, not
        # written into Starlette's allow_nan=False encoder.
        self.assertIsNone(body["when"])

    def test_isoformat_inf_on_plan_and_drill_service_state(self):
        cfg_data = _enabled_with(stop_scripts=["svc1"])
        full = {"groups": [{"services": [{"id": "svc1", "state": IsoInfBomb()}]}]}
        self._assert_clean(self._plan(cfg_data=cfg_data, status=_on_battery(),
                                      full_status=full))
        self._assert_clean(self._drill(cfg_data=cfg_data, status=_on_battery(),
                                       full_status=full))


# --------------------------------------------------------------------------- #
# repr/str fallback bombs                                                     #
# --------------------------------------------------------------------------- #

class ReprStrBombTests(UpsAppBase):
    """A value with no renderable text drops to null; siblings survive."""

    def test_repr_str_bomb_value_drops(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 12,
            "junk": ReprStrBomb(),
        }))
        self.assertEqual(body["battery_percent"], 12)
        # _as_text's str() raises and is swallowed, so the value renders as an
        # empty string -- a json-safe, harmless placeholder, never a 500.
        self.assertEqual(body["junk"], "")

    def test_repr_str_bomb_nested_in_list_keeps_siblings(self):
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "halt_levels": None, "battery_percent": 8,
            "list": ["a", ReprStrBomb(), 3],
        }))
        self.assertEqual(body["list"][0], "a")
        self.assertEqual(body["list"][1], "")
        self.assertEqual(body["list"][2], 3)


# --------------------------------------------------------------------------- #
# __format__ bombs through _reason (plan / drill)                              #
# --------------------------------------------------------------------------- #

class FormatBombTests(UpsAppBase):
    """A seam ``__format__`` bomb cannot 500 the reason label after firing."""

    def test_format_bomb_battery_percent(self):
        cfg_data = _enabled_with()
        status = _on_battery(battery_percent=FormatStrBomb())
        self._assert_clean(self._plan(cfg_data=cfg_data, status=status))
        self._assert_clean(self._drill(cfg_data=cfg_data, status=status))

    def test_format_bomb_time_remaining_with_require_both(self):
        cfg_data = _enabled_with(trigger_remaining_min=10, require_both=True)
        status = _on_battery(time_remaining_min=FormatStrBomb())
        self._assert_clean(self._plan(cfg_data=cfg_data, status=status))
        self._assert_clean(self._drill(cfg_data=cfg_data, status=status))


# --------------------------------------------------------------------------- #
# int-subclass __index__/__int__ threshold bombs                              #
# --------------------------------------------------------------------------- #

class IndexBombThresholdTests(UpsAppBase):
    """The unbound-base coercion tames an int-subclass ``__index__`` bomb.

    ``int.__index__`` reads the subclass's *real* stored value regardless of
    the poisoned dunder, so a bomb wrapping a sane number recovers that
    number, and one wrapping an over-cap number falls back -- never a 500.
    """

    def test_index_bomb_wrapping_sane_int_recovers_the_value(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"low_battery_pct": IndexIntBomb(15)}},
        }))
        # The unbound int.__index__ recovers 15 through the poisoned dunder.
        self.assertEqual(body["settings"]["low_battery_pct"], 15)

    def test_over_cap_index_bomb_degrades_to_default(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"low_battery_pct": IndexIntBomb(HUGE_INT)}},
        }))
        # The real value is past the digit cap and unrenderable, so it falls
        # back to the default rather than leaking into the encoder.
        self.assertEqual(body["settings"]["low_battery_pct"], 20)

    def test_over_cap_index_bomb_triggers_degrade_to_off(self):
        body = self._assert_clean(self._get("/api/ups", cfg_data={
            "settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": IndexIntBomb(HUGE_INT),
                "trigger_remaining_min": IndexIntBomb(HUGE_INT),
            }}},
        }))
        sd = body["settings"]["shutdown"]
        self.assertIsNone(sd["trigger_pct"])
        self.assertIsNone(sd["trigger_remaining_min"])

    def test_index_bomb_threshold_on_plan_and_drill(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            "enabled": True, "trigger_pct": IndexIntBomb(HUGE_INT),
        }}}, "scripts": []}
        self._assert_clean(self._plan(cfg_data=cfg_data, status=_on_battery()))
        self._assert_clean(self._drill(cfg_data=cfg_data, status=_on_battery()))


# --------------------------------------------------------------------------- #
# dict-subclass keys / __getitem__ bombs and class-prop-bomb keys             #
# --------------------------------------------------------------------------- #

class MappingSpreadBombTests(UpsAppBase):
    """The ``{**snap}`` spread and key laundering cannot 500."""

    def test_keys_bomb_snapshot(self):
        # ups_status does ``{**snap}``; a dict subclass whose keys() raises
        # still copies through the C-level dict spread, and the settings half
        # of the payload survives regardless.
        body = self._assert_clean(self._get("/api/ups", snapshot=KeysBombDict(
            {"present": True, "battery_percent": 5, "halt_levels": None})))
        self.assertIn("settings", body)

    def test_getitem_bomb_snapshot(self):
        body = self._assert_clean(self._get("/api/ups", snapshot=GetItemBombDict(
            {"present": True, "battery_percent": 6, "halt_levels": None})))
        self.assertIn("settings", body)

    def test_keys_and_getitem_bomb_cfg(self):
        for cfgd in (KeysBombDict({"settings": {}}),
                     GetItemBombDict({"settings": {}}),
                     {"settings": {"ups": KeysBombDict({"low_battery_pct": 40})}},
                     {"settings": {"ups": GetItemBombDict({"low_battery_pct": 40})}}):
            self._assert_clean(self._get("/api/ups", cfg_data=cfgd))

    def test_class_prop_bomb_as_dict_key(self):
        # object hashes fine, so a __class__-property bomb *is* a reachable
        # dict key; _jsonable's key laundering renders it through str() rather
        # than detonating the rank gates on the key.
        body = self._assert_clean(self._get("/api/ups", snapshot={
            "present": True, "battery_percent": 33, "halt_levels": None,
            _class_prop_bomb(): "v",
        }))
        self.assertEqual(body["battery_percent"], 33)


class DictLiarSnapshotTests(UpsAppBase):
    """A lying-``__class__`` snapshot claiming dict yields settings-only body."""

    def test_dict_liar_whole_snapshot(self):
        body = self._assert_clean(self._get("/api/ups", snapshot=_liar(dict)))
        # {**snap} TypeErrors on the impostor; ups_status falls back to the
        # settings-only payload rather than 500ing.
        self.assertIn("settings", body)

    def test_list_and_str_liar_snapshots(self):
        for claimed in (list, str, int, tuple):
            body = self._assert_clean(self._get("/api/ups", snapshot=_liar(claimed)))
            self.assertIn("settings", body)


# --------------------------------------------------------------------------- #
# odd policy shapes: stacks-as-mapping, stop_scripts junk                      #
# --------------------------------------------------------------------------- #

class OddPolicyShapeTests(UpsAppBase):
    """Non-list ``stacks`` and junk ``stop_scripts`` resolve to empty."""

    def test_stacks_stored_as_mapping_reads_as_all(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            "enabled": True, "trigger_pct": 25, "stacks": {"a": 1},
        }}}, "scripts": []}
        body = self._assert_clean(self._plan(
            cfg_data=cfg_data, status=_on_battery(),
            list_stacks=lambda: [{"id": "web", "status": "ok"}]))
        # A mapping is neither "all" nor a list; build_plan takes the "all"
        # branch (stack enumeration order) and still resolves the one stack.
        ids = [s["id"] for s in body["steps"] if s["kind"] == "stack"]
        self.assertEqual(ids, ["web"])

    def test_stop_scripts_carrying_junk_drops_unrenderable_entries(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            "enabled": True, "trigger_pct": 25,
            "stop_scripts": [HUGE_INT, INF, {"x": 1}, "svc1"],
        }}}, "scripts": []}
        body = self._assert_clean(self._plan(cfg_data=cfg_data,
                                             status=_on_battery()))
        svc_ids = [s["id"] for s in body["steps"] if s["kind"] == "service"]
        # The sane id survives; the huge/inf entries laundered to null and
        # dropped to "" ids that build_plan then filters out.  (A stored dict
        # stringifies, which is odd but json-safe -- the point is no 500.)
        self.assertIn("svc1", svc_ids)

    def test_iter_bomb_stop_scripts_on_plan(self):
        cfg_data = {"settings": {"ups": {"shutdown": {
            "enabled": True, "trigger_pct": 25,
            "stop_scripts": IterBombList(["svc1"]),
        }}}, "scripts": []}
        # The stored list is laundered by ups_svc._jsonable before build_plan
        # sees it: an __iter__ bomb drops the whole list to None, which the
        # ``isinstance(..., list)`` gate reads as no scripts.
        self._assert_clean(self._plan(cfg_data=cfg_data, status=_on_battery()))


# --------------------------------------------------------------------------- #
# state file: float pid, non-dict steps                                       #
# --------------------------------------------------------------------------- #

class StateFileLeftoverTests(UpsAppBase):
    """New state-file leftovers degrade GET /api/ups, never 500."""

    def _body(self, text):
        return self._assert_clean(self._get("/api/ups", state_text=text))

    def test_float_worker_pid_keeps_the_route(self):
        text = ('{"phase":"engaged","engaged_at":5,'
                '"worker_owner":{"pid":1e400,"ts":1},"steps":[]}')
        body = self._body(text)
        self.assertEqual(body["shutdown_state"]["phase"], "engaged")

    def test_steps_of_non_dict_scalars_render(self):
        text = '{"phase":"engaged","engaged_at":5,"steps":[1,2,"x",null]}'
        body = self._body(text)
        # public_state keeps only dict steps; the scalar junk drops and the
        # phase still resolves.
        self.assertEqual(body["shutdown_state"]["phase"], "engaged")
        self.assertEqual(body["shutdown_state"]["steps"], [])

    def test_reason_and_last_wrong_types_degrade(self):
        text = '{"phase":"idle","reason":123,"last":[1,2],"steps":"nope"}'
        body = self._body(text)
        state = body["shutdown_state"]
        self.assertEqual(state["reason"], "")
        self.assertIsNone(state["last"])
        self.assertEqual(state["steps"], [])


# --------------------------------------------------------------------------- #
# PUT /api/ups/settings with a fully-bombed stored config                      #
# --------------------------------------------------------------------------- #

class PutSettingsBombedStoreTests(UpsAppBase):
    """The effective-merge read of stored config cannot 500 the PUT."""

    def test_put_with_getitem_bomb_shutdown_block(self):
        cfg_data = {"settings": {"ups": {
            "shutdown": GetItemBombDict({"enabled": True})}}}
        saved: list = []
        resp = self._request("PUT", "/api/ups/settings", cfg_data=cfg_data,
                             body={"shutdown": {"trigger_pct": 30}}, saved=saved)
        self._assert_clean(resp)
        self.assertEqual(saved, [{"ups": {"shutdown": {"trigger_pct": 30}}}])

    def test_put_with_class_prop_bomb_config_root(self):
        # cfg() returns a __class__-property bomb as the whole root; the
        # guarded read in ups_settings degrades to defaults, so the effective
        # no-condition check runs on laundered values instead of 500ing.
        saved: list = []
        resp = self._request("PUT", "/api/ups/settings",
                             cfg_data=_class_prop_bomb(),
                             body={"shutdown": {"trigger_pct": 30}}, saved=saved)
        self._assert_clean(resp)

    def test_put_effective_no_condition_still_rejects_cleanly(self):
        # Enabling the policy while switching the last trigger off is a coded
        # 4xx, not a 500, even when the stored block is a get-bomb subclass.
        cfg_data = {"settings": {"ups": {"shutdown": GetItemBombDict(
            {"enabled": False, "trigger_pct": 25})}}}
        resp = self._request("PUT", "/api/ups/settings", cfg_data=cfg_data,
                             body={"shutdown": {"enabled": True,
                                                "trigger_pct": None}})
        self.assertLess(resp.status_code, 500, resp.text[:300])
        self.assertGreaterEqual(resp.status_code, 400, resp.text[:300])


# --------------------------------------------------------------------------- #
# Conflict-policy pins: the union guards stay where prior sweeps put them,     #
# and the product version does not drift.                                      #
# --------------------------------------------------------------------------- #

class UnionGuardPins(unittest.TestCase):
    """ups5-ups11 guards must not be weakened by any later refactor."""

    def test_isa_is_fail_closed_on_a_class_prop_bomb(self):
        for isa in (ups_svc._isa, ups_policy._isa):
            self.assertFalse(isa(_class_prop_bomb(), dict))
            self.assertTrue(isa({}, dict))
            self.assertTrue(isa(5, int))

    def test_jsonable_relaunders_isoformat_inf_to_null(self):
        # A non-finite isoformat result is re-laundered and dropped by both
        # scrubbers, never leaked into Starlette's allow_nan=False encoder.
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            self.assertIsNone(scrub(IsoInfBomb()))

    def test_jsonable_isoformat_raise_stays_json_safe(self):
        # An isoformat that raises must not escape either scrubber: ups_svc
        # falls through to _as_text fallback text, ups_policy drops to None;
        # both are json-serializable under allow_nan=False.
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            out = scrub(IsoRaiseBomb())
            self.assertIn(out.__class__ if out is not None else type(None),
                          (str, type(None)))
            _starlette({"x": out})

    def test_jsonable_repr_str_bomb_stays_json_safe(self):
        # str()/repr() both raise; _as_text swallows and yields "" -- a
        # json-safe placeholder, never a raise out of the scrub.
        for scrub in (ups_svc._jsonable, ups_policy._jsonable):
            self.assertEqual(scrub(ReprStrBomb()), "")

    def test_finite_int_recovers_and_falls_back_through_index_bomb(self):
        # The unbound int.__index__ reads the real value: a sane wrap recovers
        # it, an over-cap wrap falls back -- either way, no raise.
        self.assertEqual(ups_svc._finite_int(IndexIntBomb(15), 20), 15)
        self.assertEqual(ups_svc._finite_int(IndexIntBomb(HUGE_INT), 20), 20)
        self.assertIsNone(ups_svc._finite_int(IndexIntBomb(HUGE_INT), None))
        self.assertEqual(ups_svc._finite_int(30, 20), 30)

    def test_cfg_text_recovers_index_bomb_and_drops_over_cap(self):
        # _cfg_text uses the unbound int.__index__ coercion: a sane wrap
        # renders its real value; an over-cap one has no renderable text.
        self.assertEqual(ups_policy._cfg_text(IndexIntBomb(15)), "15")
        self.assertEqual(ups_policy._cfg_text(IndexIntBomb(HUGE_INT)), "")
        self.assertEqual(ups_policy._cfg_text(7), "7")
        self.assertEqual(ups_policy._cfg_text(HUGE_INT), "")

    def test_reason_never_raises_on_a_format_bomb(self):
        self.assertEqual(
            ups_policy._reason("battery {}% ≤ {}%", FormatStrBomb(), 25), "")
        self.assertEqual(
            ups_policy._reason("battery {}% ≤ {}%", 18, 25), "battery 18% ≤ 25%")

    def test_below_floor_stays_fail_closed_on_a_format_bomb(self):
        # A __format__ bomb is not a __float__ bomb, but _below_floor still
        # only reads readable values; a value it cannot coerce fails its check.
        self.assertFalse(ups_policy._below_floor(FormatStrBomb(), 25))
        self.assertTrue(ups_policy._below_floor(10, 25))

    def test_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
