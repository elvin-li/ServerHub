"""Host10 leftover sweep: bool-liar / hash-shadowing-key / rc-``__ne__`` bombs
on the host identity, scheduler and settings-diag routes, over the mounted app.

host9 sealed the ``__class__``-property and lying-bytes impostors in the
``_json_tree`` family and identity's config/rc reads.  Re-running the wave-10
bomb zoo against the *survivors* of those seams found four fresh families of
live raw 500s:

* **Bool-liars needed ``type(x) is bool``.**  A leftover whose lying
  ``__class__`` *returns* ``bool`` (without being one) passed every
  ``_isa``/``isinstance`` bool gate in ``_json_tree`` / ``_json_atom`` /
  ``_json_bool`` / ``_truthy`` and was returned raw into the payload —
  Starlette's C encoder checks the *exact* type, refused it with a TypeError,
  and 500'd GET /api/scheduler, /api/system/scheduler, /api/settings/other
  and the whole GET /api/settings/system bundle.  ``type(x) is bool`` never
  dispatches into the leftover; the liar now falls to the int gate (bool
  subclasses int), where ``int.__index__`` refuses it and it drops to null.

* **Hash-shadowing mapping keys detonated the C-level compare.**  The
  laundered plain-dict copies (``_as_map`` / ``dict(raw)`` /
  ``settings_section``) bypass a subclass's bound ``.get``, but the lookup
  still calls the *stored* key's ``__eq__`` when the probe's hash lands on
  its slot.  A leftover key carrying ``hash("label")`` /
  ``hash("server_comment")`` / ``hash("adaptive")`` / ``hash("id")`` /
  ``hash("settings")`` with a raising ``__eq__`` 500'd
  GET /api/settings/scheduler, /api/identity, /api/settings/other,
  /api/settings/disk and /api/settings/thresholds straight out of ``.get`` —
  the alerts/notify_channels ``_mapping_get`` rule these surfaces never got.

* **``set_identity`` kept two bare rc probes.**  An rc-*subclass*
  ``__ne__``/``__eq__`` bomb from a patched/odd ``sh`` detonated the bare
  ``rc != 0`` after the scutil spawn and the ``rc != -1`` inside
  ``_scutil_missing`` — a raw 500 on PUT /api/identity where GET was
  already ``_rc_int``-guarded.

* **Bare isinstance row/key gates one step ahead of the scrubs.**  A
  ``__class__``-property bomb as a timer row, a power-disk row, a thresholds
  key, a thresholds ``enabled`` value, a ``metrics_interval`` value or an
  ``ip_aliases.ips`` value blew ``isinstance`` itself in ``_finite_number``,
  ``_as_map``, ``get_thresholds``, ``get_scheduler_summary`` and
  ``get_disk_settings`` — 500ing /api/settings/thresholds, /other,
  /scheduler and /disk before any sanitizer ran.

Fixes follow the union conventions: ``type(x) is bool`` for the bool gates,
``_mapping_get`` (unbound ``dict.get`` inside a try) for every stored-field
read, ``_isa`` on the remaining bare gates, and ``_rc_int`` on the rc probes
— with the vanished-scutil 503 still raised only after the honest -1
sentinel plus the on-disk confirm.

Stays-immune pins ride along: real bools pass through untouched, `_rc_int`
still salvages honest exit statuses, and the huge-int drop holds.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config as hub_config
from hub import disk_power_svc, identity_svc, system_settings_svc, tools_svc
from hub.auth import require_auth
from hub.routers import unraid_parity

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _BoolLiar:
    """A lying ``__class__`` that *returns* bool: passes every isinstance
    bool gate while the C encoder's exact-type check refuses it."""

    @property
    def __class__(self):
        return bool


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _ShadowKey(str):
    """A str subclass shadowing another key's hash slot; ``__eq__`` raises.

    Planted in a dict, any later ``.get(<shadowed>)`` probe whose hash lands
    on this slot runs the *stored* key's ``__eq__`` inside the C lookup.
    """

    def __new__(cls, shadow: str):
        self = str.__new__(cls, "shadow:" + shadow)
        self._h = hash(shadow)
        return self

    def __hash__(self):
        return self._h

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")


class _EqBombInt(int):
    """An rc whose comparison raises — ``rc == 0`` / ``rc != 0`` detonate."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class _HttpPin(unittest.TestCase):
    def setUp(self):
        self.client = _client()

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        _starlette(body)
        return body


# ---------------------------------------------------------------------------
# Scheduler trio: bool-liar values and hash-shadowing keys in timer rows
# ---------------------------------------------------------------------------


class _SchedulerTrioPin(_HttpPin):
    """Drive all three scheduler views over one leftover timers answer."""

    def _bodies(self, timers) -> dict[str, dict]:
        with (
            mock.patch.object(tools_svc, "launchd_timers", return_value=timers),
            mock.patch.object(
                unraid_parity, "launchd_timers", return_value=timers,
            ),
        ):
            return {
                path: self._ok_body(self.client.get(path))
                for path in (
                    "/api/scheduler",
                    "/api/system/scheduler",
                    "/api/settings/scheduler",
                )
            }


class SchedulerBoolLiarHttpTests(_SchedulerTrioPin):
    """The ex-500s: a bool-liar passing every isinstance bool gate."""

    def test_bool_liar_value_drops_and_its_siblings_survive(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "program": _BoolLiar()},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler"):
            row = bodies[path]["timers"][0]
            self.assertIsNone(row["program"])
            self.assertEqual(row["label"], "com.example.job")
            self.assertEqual(row["interval_sec"], 60)

    def test_bool_liar_calendar_entry_keeps_the_row(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "calendar": {"Minute": _BoolLiar()}},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler",
                     "/api/settings/scheduler"):
            row = bodies[path]["timers"][0]
            self.assertIsNone(row["calendar"]["Minute"])
            self.assertEqual(row["label"], "com.example.job")


class SchedulerShadowKeyHttpTests(_SchedulerTrioPin):
    """The ex-500: a hash-shadowing "label" key under _first_truthy's .get."""

    def test_shadow_label_key_costs_only_its_own_field(self):
        bodies = self._bodies([
            {_ShadowKey("label"): "x", "interval_sec": 60},
        ])
        row = bodies["/api/settings/scheduler"]["timers"][0]
        self.assertIsNone(row["label"])
        # The raw views render the shadow key as its own text and survive.
        self.assertEqual(
            bodies["/api/scheduler"]["timers"][0]["interval_sec"], 60,
        )

    def test_class_bomb_row_is_skipped_and_its_sibling_survives(self):
        bodies = self._bodies([
            _ClassBomb(),
            {"label": "com.example.job", "interval_sec": 60},
        ])
        rows = bodies["/api/settings/scheduler"]["timers"]
        self.assertEqual(rows[0]["label"], "com.example.job")


# ---------------------------------------------------------------------------
# GET /api/identity: hash-shadowing settings key
# PUT /api/identity: rc-subclass __ne__ bombs (and the 503 stays disk-confirmed)
# ---------------------------------------------------------------------------


class IdentityShadowKeyTests(_HttpPin):
    def test_shadow_server_comment_key_degrades_to_empty(self):
        with mock.patch.object(
            identity_svc, "cfg",
            return_value={"settings": {_ShadowKey("server_comment"): "x"}},
        ):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["comment"], "")
        self.assertIsInstance(body["hostname"], str)


class IdentityPutRcBombTests(_HttpPin):
    def test_rc_ne_bomb_from_a_patched_sh_keeps_the_route(self):
        with mock.patch.object(
            identity_svc, "sh", return_value=(_EqBombInt(1), "", "denied"),
        ):
            body = self._ok_body(self.client.put(
                "/api/identity", json={"computer_name": "box"},
            ))
        # A bomb reads as failure: the privileges message, never a 500 and
        # never the vanished-CLI 503 (whose sentinel is an honest -1).
        self.assertIn("administrator privileges", body["message"])

    def test_unreadable_rc_never_classifies_as_scutil_missing(self):
        # Fail-closed: an rc whose value cannot be read at all coerces to
        # -255, which is not the spawn sentinel, so the disk probe is never
        # consulted and the 503 cannot fire off a bomb.  (An honest int
        # *subclass* carrying -1 is deliberately still salvaged by _rc_int
        # — the sentinel value itself is trustworthy.)
        class _UnreadableRc:
            def __int__(self):
                raise RuntimeError("int bomb")

        self.assertFalse(
            identity_svc._scutil_missing(_UnreadableRc(), "not found"),
        )

    def test_vanished_scutil_503_only_after_disk_confirm(self):
        # The honest sentinel plus a confirmed-missing binary still answers
        # the coded 503 — the host7/vms rule this sweep must not regress.
        with (
            mock.patch.object(
                identity_svc, "sh", return_value=(-1, "", "not found"),
            ),
            mock.patch.object(identity_svc, "SCUTIL", "/nonexistent/scutil"),
        ):
            resp = self.client.put(
                "/api/identity", json={"computer_name": "box"},
            )
        self.assertEqual(resp.status_code, 503, resp.text[:400])
        self.assertEqual(resp.json()["detail"]["code"], "identity.scutil_missing")


# ---------------------------------------------------------------------------
# GET /api/settings/other and /thresholds: settings bombs
# ---------------------------------------------------------------------------


def _cfg_with(settings) -> dict:
    return {"settings": settings}


class _SettingsPin(_HttpPin):
    def _with_settings(self, settings, path: str) -> dict:
        payload = _cfg_with(settings)
        with (
            mock.patch.object(hub_config, "cfg", return_value=payload),
            mock.patch.object(
                system_settings_svc, "cfg", return_value=payload,
            ),
        ):
            return self._ok_body(self.client.get(path))


class OtherSettingsBombTests(_SettingsPin):
    """The ex-500s on GET /api/settings/other."""

    def test_bool_liar_adaptive_degrades_to_the_default(self):
        body = self._with_settings(
            {"adaptive": _BoolLiar()}, "/api/settings/other",
        )
        self.assertIs(body["adaptive"], True)

    def test_shadow_adaptive_key_degrades_to_the_default(self):
        body = self._with_settings(
            {_ShadowKey("adaptive"): 1}, "/api/settings/other",
        )
        self.assertIs(body["adaptive"], True)

    def test_class_bomb_metrics_interval_degrades_to_the_default(self):
        body = self._with_settings(
            {"metrics_interval": _ClassBomb()}, "/api/settings/other",
        )
        self.assertEqual(body["metrics_interval"], 90)

    def test_class_bomb_alias_ips_degrades_to_an_empty_list(self):
        body = self._with_settings(
            {"ip_aliases": {"ips": _ClassBomb()}}, "/api/settings/other",
        )
        self.assertEqual(body["ip_aliases"]["ips"], [])


class ThresholdsBombTests(_SettingsPin):
    """The ex-500s on GET /api/settings/thresholds."""

    def test_shadow_settings_root_key_answers_the_defaults(self):
        payload = {_ShadowKey("settings"): {}}
        with (
            mock.patch.object(hub_config, "cfg", return_value=payload),
            mock.patch.object(
                system_settings_svc, "cfg", return_value=payload,
            ),
        ):
            body = self._ok_body(self.client.get("/api/settings/thresholds"))
            other = self._ok_body(self.client.get("/api/settings/other"))
        self.assertEqual(
            body["cpu_pct"], system_settings_svc.DEFAULT_THRESHOLDS["cpu_pct"],
        )
        self.assertIs(other["adaptive"], True)

    def test_class_bomb_threshold_key_keeps_its_siblings(self):
        body = self._with_settings(
            {"thresholds": {_ClassBomb(): 5, "cpu_pct": 50}},
            "/api/settings/thresholds",
        )
        self.assertEqual(body["cpu_pct"], 50)

    def test_class_bomb_enabled_value_keeps_the_default(self):
        body = self._with_settings(
            {"thresholds": {"enabled": _ClassBomb()}},
            "/api/settings/thresholds",
        )
        self.assertIs(body["enabled"], True)

    def test_bool_liar_enabled_value_keeps_the_default(self):
        body = self._with_settings(
            {"thresholds": {"enabled": _BoolLiar()}},
            "/api/settings/thresholds",
        )
        self.assertIs(body["enabled"], True)


# ---------------------------------------------------------------------------
# GET /api/settings/disk: power-disk row bombs
# ---------------------------------------------------------------------------


class DiskSettingsBombTests(_HttpPin):
    def _rows(self, rows) -> dict:
        with mock.patch.object(
            disk_power_svc, "list_power_disks", return_value=rows,
        ):
            return self._ok_body(self.client.get("/api/settings/disk"))

    def test_shadow_id_key_costs_only_its_own_field(self):
        body = self._rows([{_ShadowKey("id"): "disk9", "name": "d"}])
        row = body["power_disks"][0]
        self.assertIsNone(row["id"])
        self.assertEqual(row["name"], "d")

    def test_class_bomb_row_is_skipped_and_its_sibling_survives(self):
        body = self._rows([_ClassBomb(), {"id": "d1", "name": "x"}])
        self.assertEqual(body["power_disks"][0]["id"], "d1")


# ---------------------------------------------------------------------------
# GET /api/settings/system: the bundle over a bool-liar auth flag
# ---------------------------------------------------------------------------


class BundleBoolLiarTests(_HttpPin):
    def test_bool_liar_auth_enabled_becomes_an_honest_bool(self):
        with mock.patch.object(
            hub_config, "cfg",
            return_value=_cfg_with({"auth": {"enabled": _BoolLiar()}}),
        ):
            body = self._ok_body(
                self.client.get("/api/settings/system?force=true"),
            )
        # _truthy coerces the liar through bool() — an exact True, which
        # both the bundle's final _json_tree and the encoder accept.
        self.assertIs(body["management"]["auth_enabled"], True)


# ---------------------------------------------------------------------------
# Unit pins on the sanitizers themselves
# ---------------------------------------------------------------------------


class SanitizerUnitPins(unittest.TestCase):
    def test_json_tree_bool_liar_drops_to_null(self):
        self.assertIsNone(system_settings_svc._json_tree(_BoolLiar()))
        _starlette(system_settings_svc._json_tree({"x": _BoolLiar(), "y": 2}))

    def test_json_atom_bool_liar_drops_to_null(self):
        self.assertIsNone(system_settings_svc._json_atom(_BoolLiar()))

    def test_json_bool_refuses_liars_and_class_bombs(self):
        self.assertIs(system_settings_svc._json_bool(_BoolLiar(), True), True)
        self.assertIs(system_settings_svc._json_bool(_ClassBomb(), False), False)

    def test_truthy_answers_an_exact_bool_for_a_liar(self):
        out = system_settings_svc._truthy(_BoolLiar())
        self.assertIs(type(out), bool)

    def test_finite_number_class_bomb_degrades_to_the_default(self):
        self.assertEqual(system_settings_svc._finite_number(_ClassBomb(), 7), 7)

    def test_as_map_class_bomb_degrades_to_empty(self):
        self.assertEqual(system_settings_svc._as_map(_ClassBomb()), {})

    def test_mapping_get_absorbs_shadow_keys_and_get_bombs(self):
        shadowed = {_ShadowKey("label"): "x"}
        self.assertIsNone(
            system_settings_svc._mapping_get(shadowed, "label"),
        )
        self.assertIsNone(identity_svc._mapping_get(shadowed, "label"))

        class _GetBombDict(dict):
            def get(self, *a, **k):
                raise RuntimeError("get bomb")

        # The unbound read salvages the real C-level storage underneath.
        self.assertEqual(
            system_settings_svc._mapping_get(_GetBombDict(a=1), "a"), 1,
        )

    def test_settings_section_absorbs_a_shadow_root_key(self):
        with mock.patch.object(
            hub_config, "cfg", return_value={_ShadowKey("settings"): {}},
        ):
            self.assertEqual(hub_config.settings_section("thresholds"), {})


class StaysImmunePins(unittest.TestCase):
    """Already-immune behaviour, pinned so the host10 edits cannot regress it."""

    def test_real_bools_still_pass_through_untouched(self):
        self.assertIs(system_settings_svc._json_tree(True), True)
        self.assertIs(system_settings_svc._json_atom(False), False)
        self.assertIs(system_settings_svc._json_bool(False, True), False)
        self.assertIs(system_settings_svc._truthy(True), True)

    def test_rc_int_still_salvages_honest_statuses(self):
        self.assertEqual(identity_svc._rc_int(_EqBombInt(0)), 0)
        self.assertEqual(identity_svc._rc_int(_EqBombInt(-1)), -1)

    def test_json_tree_huge_int_still_drops(self):
        self.assertIsNone(system_settings_svc._json_tree(10 ** 5000))

    def test_thresholds_defaults_survive_a_sane_config(self):
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"settings": {"thresholds": {"cpu_pct": 42}}},
        ):
            out = system_settings_svc.get_thresholds()
        self.assertEqual(out["cpu_pct"], 42)
        self.assertIs(out["enabled"], True)


if __name__ == "__main__":
    unittest.main()
