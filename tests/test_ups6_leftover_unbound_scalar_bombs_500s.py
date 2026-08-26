"""UPS leftover sweep #6: subclass scalar dunder bombs past the ups5 guards.

The ups5 pass guarded the *mapping* reads (``.get`` bombs, torn ``items()``
pairs, ``__bool__`` bombs), but every scalar that survived those guards was
still run through its own dunders by the two ``_jsonable`` copies, by
``_finite_int`` and by ``_cfg_text`` — the hub.modules "unbound base" rule at
UPS rank.  One subclass scalar in the stored settings or a seam row 500'd the
whole surface:

* **``_jsonable`` scalar probes ran subclass dunders.**  An int subclass
  whose ``__str__`` raises blew the digit-cap probe (only ValueError was
  caught); a float subclass whose ``__eq__`` raises blew the NaN/inf probe;
  a bytes subclass ``decode`` bomb and a str subclass ``encode`` bomb (as a
  value *or* as a key) raised out of the laundering itself; a torn non-pair
  row from a nested dict-subclass ``items()`` ValueError'd the ``for k, v``
  loop head; and the bare ``getattr(value, "isoformat", None)`` probe ran a
  property bomb.  Each of these, planted in ``settings.ups.shutdown.stacks``,
  500'd GET /api/ups — and through ``ups_settings()`` also
  GET /api/ups/shutdown/plan, POST /api/ups/shutdown/drill and
  PUT /api/ups/settings (its effective-merge read).  Now: unbound
  ``int.__index__`` / ``float.__float__`` / ``bytes.decode`` / ``str.encode``
  base coercions, a per-pair unpack guard, and a guarded getattr.
* **``_finite_int`` probes ran subclass dunders.**  The NaN/inf check
  (``raw != raw``) sat *outside* the try, so a float-subclass ``__eq__``
  bomb in ``low_battery_pct`` or ``shutdown.trigger_pct`` 500'd GET /api/ups;
  an object whose ``__int__`` raises RuntimeError escaped the
  ``(TypeError, ValueError, OverflowError)`` clause the same way.
* **``_cfg_text``'s str() probe ran a subclass ``__str__``.**  The probe was
  built for the *digit-cap* ValueError of an already-int over-cap YAML id;
  an int-subclass ``__str__`` bomb in a script/stack id or name raised
  RuntimeError instead and 500'd GET /api/ups/shutdown/plan and
  POST /api/ups/shutdown/drill out of ``build_plan`` / ``_catalog`` — and
  aborted ``_service_states``'s whole scan.  ``str(int.__index__(value))``
  renders the real number; only the digit cap still reads as "no text".

Stays-immune pins ride along: the config-*mutate* contract on
PUT /api/ups/settings (unreadable services.yaml answers the coded 503
``settings.config_unreadable`` and the file stays byte-identical), the
already-int >4300-digit seam id (drops alone), nested lone surrogates
(laundered), and a vanished pmset (GET /api/ups answers present:false).
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


class IntStrBomb(int):
    """Passes ``isinstance(x, int)``; rendering it raises (not ValueError)."""

    def __str__(self):  # noqa: D105
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class IntIntBomb:
    """An object whose ``__int__`` raises outside Type/Value/OverflowError."""

    def __int__(self):  # noqa: D105
        raise RuntimeError("int() bomb")


class FloatEqBomb(float):
    """Passes ``isinstance(x, float)``; any equality probe raises."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("float eq bomb")

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("float ne bomb")

    __hash__ = float.__hash__


class BytesDecodeBomb(bytes):
    """Passes ``isinstance(x, bytes)``; its own ``decode`` raises."""

    def decode(self, *a, **k):  # noqa: D102
        raise RuntimeError("bytes decode bomb")


class StrEncodeBomb(str):
    """Passes ``isinstance(x, str)``; its own ``encode`` raises."""

    def encode(self, *a, **k):  # noqa: D102
        raise RuntimeError("str encode bomb")


class ItemsTornPairs(dict):
    """items() hands back a one-element row beside a sane pair."""

    def items(self):  # noqa: D102
        return [("solo",), ("sane", 1)]


class IsoPropertyBomb:
    """The bare ``getattr(value, "isoformat", None)`` probe used to raise."""

    @property
    def isoformat(self):  # noqa: D102
        raise RuntimeError("isoformat bomb")


_SANE_SNAPSHOT = {"present": False, "halt_levels": None}

#: 5001 digits: exempt from the str->int cap when built by arithmetic (the
#: YAML hex loophole produces the same already-int shape), but str() of it
#: raises the digit-cap ValueError.
_HUGE_INT = 10 ** 5000


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
                ups_policy, "_list_stacks",
                lambda: stacks if stacks is not None else [],
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

    def _assert_clean(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.text[:200])
        _starlette(resp.json())
        self.assertNotIn("\ud800", resp.text)


def _shutdown_cfg(**kw):
    kw.setdefault("trigger_pct", 30)
    return {"settings": {"ups": {"shutdown": dict(kw)}}, "scripts": []}


class JsonableScalarBombTests(UpsAppBase):
    """Subclass scalar bombs in the stored shutdown block answer 200."""

    BOMBS = {
        "int __str__ bomb": IntStrBomb(5),
        "float __eq__ bomb": FloatEqBomb(1.5),
        "bytes decode bomb": BytesDecodeBomb(b"x"),
        "str encode bomb": StrEncodeBomb("x"),
        "torn-pairs nested dict": ItemsTornPairs(),
        "isoformat property bomb": IsoPropertyBomb(),
        "str-subclass encode-bomb key": {StrEncodeBomb("k"): 1},
    }

    def test_get_ups_survives_every_scalar_bomb(self):
        for label, bomb in self.BOMBS.items():
            with self.subTest(case=label):
                resp = self._get_ups(_shutdown_cfg(stacks=bomb))
                self._assert_clean(resp)
                # The bombed field degrades alone; its sane sibling key in
                # the very same shutdown block survives the scrub.
                shutdown = resp.json()["settings"]["shutdown"]
                self.assertEqual(shutdown["trigger_pct"], 30)

    def test_sane_subclass_scalars_keep_their_real_values(self):
        # The unbound base coercions salvage, not just drop: a subclass
        # carrying sane data renders that data.
        resp = self._get_ups(_shutdown_cfg(stacks=[IntStrBomb(5), "web"]))
        self._assert_clean(resp)
        # The bombed int's real value (5) survives via int.__index__.
        self.assertEqual(resp.json()["settings"]["shutdown"]["stacks"], [5, "web"])

    def test_torn_pair_keeps_the_sane_sibling_pair(self):
        resp = self._get_ups(_shutdown_cfg(stacks=ItemsTornPairs()))
        self._assert_clean(resp)
        self.assertEqual(
            resp.json()["settings"]["shutdown"]["stacks"], {"sane": 1},
        )

    def test_plan_and_drill_survive_the_same_store(self):
        cfg_data = _shutdown_cfg(stacks=IntStrBomb(5))
        self._assert_clean(self._plan(cfg_data))
        self._assert_clean(self._request(
            "POST", "/api/ups/shutdown/drill", cfg_data=cfg_data, admin=True,
        ))

    def test_put_settings_effective_merge_survives_the_bombed_store(self):
        saved: list = []
        resp = self._request(
            "PUT", "/api/ups/settings",
            cfg_data=_shutdown_cfg(stacks=FloatEqBomb(1.5)),
            body={"shutdown": {"enabled": False}}, admin=True, saved=saved,
        )
        self._assert_clean(resp)
        self.assertEqual(saved, [{"ups": {"shutdown": {"enabled": False}}}])


class FiniteIntBombTests(UpsAppBase):
    """_finite_int probes must not run subclass dunders bare."""

    def test_float_eq_bomb_low_battery_pct_salvages_its_value(self):
        # Pre-fix ``raw != raw`` ran the subclass __eq__ *outside* the try
        # and 500'd GET /api/ups.  float.__float__ reads the real storage
        # under the poisoned probe, so the sane value underneath survives.
        resp = self._get_ups(
            {"settings": {"ups": {"low_battery_pct": FloatEqBomb(50.0)}}},
        )
        self._assert_clean(resp)
        self.assertEqual(resp.json()["settings"]["low_battery_pct"], 50)

    def test_int_conversion_bomb_low_battery_pct_falls_back(self):
        # int() runs the object's own __int__; a RuntimeError from it used
        # to escape the (TypeError, ValueError, OverflowError) clause.
        resp = self._get_ups(
            {"settings": {"ups": {"low_battery_pct": IntIntBomb()}}},
        )
        self._assert_clean(resp)
        self.assertEqual(resp.json()["settings"]["low_battery_pct"], 20)

    def test_trigger_pct_float_eq_bomb_salvages_its_value(self):
        resp = self._get_ups(_shutdown_cfg(trigger_pct=FloatEqBomb(25.0)))
        self._assert_clean(resp)
        self.assertEqual(resp.json()["settings"]["shutdown"]["trigger_pct"], 25)

    def test_trigger_pct_conversion_bomb_reads_as_condition_off(self):
        resp = self._get_ups(_shutdown_cfg(trigger_pct=IntIntBomb()))
        self._assert_clean(resp)
        self.assertIsNone(resp.json()["settings"]["shutdown"]["trigger_pct"])


class CfgTextBombTests(UpsAppBase):
    """Int-subclass __str__ bombs in seam/config rows render their value."""

    def test_script_row_id_and_name_bombs_keep_the_picker(self):
        resp = self._plan({
            "settings": {},
            "scripts": [{"id": IntStrBomb(7)},
                        {"id": "g", "name": IntStrBomb(8)},
                        {"id": "sane", "name": "Sane"}],
        })
        self._assert_clean(resp)
        scripts = {s["id"]: s for s in resp.json()["catalog"]["scripts"]}
        # int.__index__ renders the real number under the bombed __str__.
        self.assertIn("7", scripts)
        self.assertEqual(scripts["g"]["name"], "8")
        self.assertIn("sane", scripts)

    def test_stack_row_id_and_name_bombs_keep_the_catalog(self):
        resp = self._plan(
            {"settings": {}, "scripts": []},
            stacks=[{"id": IntStrBomb(7), "status": "ok"},
                    {"id": "s", "name": IntStrBomb(8), "status": "ok"},
                    {"id": "sane", "name": "Sane", "status": "ok"}],
        )
        self._assert_clean(resp)
        rows = {s["id"]: s for s in resp.json()["catalog"]["stacks"]}
        self.assertIn("7", rows)
        self.assertEqual(rows["s"]["name"], "8")
        self.assertIn("sane", rows)

    def test_drill_survives_the_same_rows(self):
        resp = self._request(
            "POST", "/api/ups/shutdown/drill", admin=True,
            cfg_data={"settings": {}, "scripts": [{"id": IntStrBomb(7)}]},
        )
        self._assert_clean(resp)

    def test_service_states_salvages_the_bombed_id(self):
        import hub.status as status_mod

        with mock.patch.object(
            status_mod, "full_status",
            lambda force=False: {"groups": [{"services": [
                {"id": IntStrBomb(3), "state": "ok"},
                {"id": "sane", "state": "warn"},
            ]}]},
        ):
            states = ups_policy._service_states()
        # Pre-fix the bombed id aborted the scan and wiped both entries.
        self.assertEqual(states, {"3": "ok", "sane": "warn"})


class StaysImmunePinTests(UpsAppBase):
    """Vectors the hunt found already immune, pinned at the HTTP layer."""

    def test_already_int_overcap_seam_id_drops_alone(self):
        cfg_data = {
            "settings": {"ups": {"shutdown": {
                "enabled": True, "trigger_pct": 25, "stacks": "all",
            }}},
            "scripts": [],
        }
        resp = self._plan(cfg_data, stacks=[
            {"id": _HUGE_INT, "status": "ok"},
            {"id": "sane", "status": "ok"},
        ])
        self._assert_clean(resp)
        # Past the digit cap there is no renderable text: the row drops
        # alone and the sane sibling still plans.
        self.assertEqual([s["id"] for s in resp.json()["steps"]], ["sane"])

    def test_overcap_int_settings_value_drops_from_the_body(self):
        resp = self._get_ups(_shutdown_cfg(stacks=_HUGE_INT))
        self._assert_clean(resp)
        self.assertIsNone(resp.json()["settings"]["shutdown"]["stacks"])

    def test_nested_surrogate_keys_and_values_are_laundered(self):
        resp = self._get_ups(_shutdown_cfg(stacks={"\ud800k": "\ud800v"}))
        self._assert_clean(resp)

    def test_vanished_pmset_reads_as_not_detected(self):
        # sh() answers (-1, "", "not found") when the CLI vanished; the
        # snapshot degrades to "no UPS", never a 500 and never a fake 400.
        with mock.patch.object(ups_svc, "sh", lambda *a, **k: (-1, "", "not found")), \
                mock.patch.object(ups_svc, "cfg", lambda: {"settings": {}}), \
                mock.patch.object(ups_policy, "_ups_status", lambda: {"present": False}):
            resp = self.client.get("/api/ups?force=true")
        self._assert_clean(resp)
        self.assertFalse(resp.json()["present"])


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
        # Torn non-UTF-8 bytes: readers fall back to {} (GET stays 200),
        # but the mutate must refuse rather than rewrite from that {}.
        config.YAML_PATH.write_bytes(b"\xff\xfesettings:\n  ups: {}\n")
        config.reload_cfg()
        before = config.YAML_PATH.read_bytes()
        with mock.patch.object(ups_svc, "ups_snapshot",
                               lambda force=False: dict(_SANE_SNAPSHOT)), \
                mock.patch.object(ups_policy, "_ups_status",
                                  lambda: {"present": False}), \
                mock.patch.object(ups_api.audit, "record", lambda *a, **k: None):
            read = self.client.get("/api/ups")
            self.assertEqual(read.status_code, 200, read.text[:200])
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
