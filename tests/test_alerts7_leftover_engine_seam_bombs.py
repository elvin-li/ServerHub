"""Alerts sweep #7: the engine-side seam bombs the route sweeps never drove.

A fresh hostile matrix over the mounted alerts routes (create_app +
TestClient, raise_server_exceptions=False: journal/state/secrets node zoo,
huge-digit json.loads ValueError documents, surrogate bodies and stores,
unreadable services.yaml, subclass-bomb feeders and cfg sections) found
every HTTP answer already coded — alerts4-6 and notify5-7 sealed the
routes.  What was still live sat one seam *before* the sanitizers, on the
values the check feeders hand back (``ups_svc.ups_status()``,
``metrics.latest_sample()``, ``system_settings_svc.get_thresholds()``,
``storage_svc.smart_devices()``) and on :func:`hub.alerts.emit_alert`'s own
flag reads.  Each of these was confirmed detonating on the pre-fix tree:

* ``emit_alert`` ran ``bool(n.get("enabled"))`` / bare ``.get`` truth tests
  on the notify flags: a ``__bool__`` bomb value raised *out of the public
  entry* into its callers — the UPS shutdown policy had already latched
  ENGAGED and never reached its stop sequence, and the scheduler's
  containment swallowed the alert its failure streak had earned;
* every ``_check_*`` pass read its feeder snapshot with bound ``.get`` /
  ``or`` / ``bool()``: a dict-subclass ``.get`` bomb wrapper (or one
  ``__bool__``-bomb flag) raised into check_once's containment and the
  whole pass died silently — every disk unwatched, the on-battery
  countdown unannounced — while the real readings sat intact in the
  wrapper's C-level storage;
* ``float()`` in the resource/UPS coercions dispatches into a subclass
  value's own ``__float__``, and a RuntimeError there escaped the old
  ``(TypeError, ValueError, OverflowError)`` nets;
* ``_smart_num`` ran bare ``str()``/``float()`` on subclass smart fields,
  and the SMART device walk ran ``devices or []`` / ``not smart`` — a
  ``__bool__``/``__iter__`` bomb killed the pass before any disk was read.

Fixed with the module's own conventions (``_mapping_get`` / ``_truthy`` /
``_pick``, unbound ``list.__iter__`` / ``dict.__len__``, base int/float
coercion in ``_smart_num``): junk degrades field-level and fails closed,
the sane data under a poisoned wrapper still alerts, and emit_alert never
raises.  Route-level stays-immune pins for the extended feeder scalar zoo
(tuple/set/frozenset ``__iter__`` bombs, a bytearray ``decode`` bomb, an
int ``__index__`` bomb, a str ``strip``/``isdigit`` bomb stamp) ride along.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import alerts, audit, auth, config, notify_channels
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _BoolBomb:
    """A stored flag value whose truth test raises."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _DictGetBomb(dict):
    def get(self, *a):
        raise RuntimeError("get bomb")


class _DictBoolBomb(dict):
    def __bool__(self):
        raise RuntimeError("dict bool bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _ListBoolBomb(list):
    def __bool__(self):
        raise RuntimeError("list bool bomb")


class _TupleIterBomb(tuple):
    def __iter__(self):
        raise RuntimeError("tuple iter bomb")


class _SetIterBomb(set):
    def __iter__(self):
        raise RuntimeError("set iter bomb")


class _FrozensetIterBomb(frozenset):
    def __iter__(self):
        raise RuntimeError("frozenset iter bomb")


class _BytearrayDecodeBomb(bytearray):
    def decode(self, *a, **k):
        raise RuntimeError("bytearray decode bomb")


class _IntIndexBomb(int):
    """Raises from both dunders the sanitizers probe on ints."""

    def __index__(self):
        raise RuntimeError("index bomb")

    def __str__(self):
        raise RuntimeError("int str bomb")


class _StrStripBomb(str):
    """Self-``__str__`` keeps the subclass alive through a bare str() copy."""

    def __str__(self):
        return self

    def strip(self, *a):
        raise RuntimeError("strip bomb")

    def isdigit(self):
        raise RuntimeError("isdigit bomb")


class _FloatBomb:
    """A sample value whose ``__float__`` raises a non-enumerated error."""

    def __float__(self):
        raise RuntimeError("float bomb")


class _StrBombNum:
    """battery_percent leftover: float()s fine, but its str render bombs."""

    def __float__(self):
        return 42.0

    def __str__(self):
        raise RuntimeError("str bomb")


class _Alerts7Sandbox(unittest.TestCase):
    """Scratch config/journal/state plus the mounted app's TestClient."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-alerts7-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = Path(tmp)
        self.data = self.root / "data"
        self.data.mkdir()
        self.journal = self.data / "alerts.jsonl"
        for target, attr, value in (
            (config, "YAML_PATH", self.root / "services.yaml"),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (alerts, "ALERTS_FILE", self.journal),
            (alerts, "STATE_FILE", self.data / "alert_state.json"),
            (notify_channels, "SECRETS_FILE", self.data / "notify-credentials.json"),
            (audit, "AUDIT_PATH", self.data / "auth-audit.jsonl"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def patch(self, target, attr, value):
        patched = mock.patch.object(target, attr, value)
        patched.start()
        self.addCleanup(patched.stop)

    def journal_rows(self) -> list:
        if not self.journal.exists():
            return []
        return [json.loads(ln) for ln in self.journal.read_text().splitlines() if ln.strip()]

    def assert_check_200(self) -> list:
        r = self.client.post("/api/alerts/check")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body["emitted"]


class EmitAlertNeverRaisesPins(_Alerts7Sandbox):
    """emit_alert is the public entry the UPS policy, the scheduler engine
    and the backup recovery call; a bomb flag must never raise out of it."""

    def _emit(self, settings, **kw):
        sent = []
        self.patch(alerts, "notify_settings", lambda: settings)
        self.patch(alerts, "send_ha_notify",
                   lambda *a, **k: sent.append((a, k)) or {"ok": True})
        args = {"kind": "ups", "level": "down", "alert_id": "ups:x", "message": "m"}
        args.update(kw)
        return alerts.emit_alert(**args), sent

    def test_bool_bomb_enabled_records_but_never_raises_or_notifies(self):
        alert, sent = self._emit({"enabled": _BoolBomb()})
        self.assertEqual(alert["id"], "ups:x")
        # The journal row landed before the flag was ever read.
        self.assertEqual(self.journal_rows()[0]["id"], "ups:x")
        # A bomb flag is junk, not consent to notify.
        self.assertEqual(sent, [])

    def test_bool_bomb_include_warn_on_a_warn_alert(self):
        alert, sent = self._emit(
            {"enabled": True, "include_warn": _BoolBomb()}, level="warn")
        self.assertEqual(alert["level"], "warn")
        self.assertEqual(sent, [])

    def test_bool_bomb_notify_resolve_on_a_resolved_alert(self):
        alert, sent = self._emit(
            {"enabled": True, "notify_resolve": _BoolBomb()},
            level="ok", event="resolved")
        self.assertEqual(alert["event"], "resolved")
        self.assertEqual(sent, [])

    def test_get_bomb_settings_wrapper_reads_the_real_flags(self):
        # dict.get reads the C-level storage under the override: the real
        # ``enabled: True`` still consents, and nothing raises.
        alert, sent = self._emit(_DictGetBomb({"enabled": True}))
        self.assertEqual(alert["id"], "ups:x")
        self.assertEqual(len(sent), 1)

    def test_get_bomb_settings_wrapper_with_no_consent_stays_silent(self):
        alert, sent = self._emit(_DictGetBomb({}))
        self.assertEqual(alert["id"], "ups:x")
        self.assertEqual(sent, [])

    def test_bool_bomb_title_falls_back_to_alert_id(self):
        alert, _ = self._emit({"enabled": False}, title=_BoolBomb())
        self.assertEqual(alert["name"], "ups:x")

    def test_sane_flags_still_notify(self):
        _, sent = self._emit({"enabled": True})
        self.assertEqual(len(sent), 1)


class UpsFeederWrapperPins(_Alerts7Sandbox):
    """A poisoned ups_status() wrapper must degrade field-level: the real
    on-battery readings in its C-level storage still announce the outage."""

    _REAL = {
        "present": True, "on_battery": True, "battery_percent": 42,
        "name": "MyUPS",
        "settings": {"alerts_enabled": True, "low_battery_pct": 20},
    }

    def _emitted(self, status) -> list:
        import hub.ups_svc as ups_svc
        self.patch(ups_svc, "ups_status", lambda: status)
        emitted = self.assert_check_200()
        return [a for a in emitted if isinstance(a, dict) and a.get("kind") == "ups"]

    def test_get_bomb_wrapper_still_alerts_power_loss(self):
        rows = self._emitted(_DictGetBomb(dict(self._REAL)))
        self.assertEqual([a["id"] for a in rows], ["ups:power"])
        self.assertEqual(rows[0]["level"], "down")

    def test_bool_bomb_dict_wrapper_still_alerts(self):
        rows = self._emitted(_DictBoolBomb(dict(self._REAL)))
        self.assertEqual([a["id"] for a in rows], ["ups:power"])

    def test_str_bomb_battery_percent_renders_from_the_float(self):
        status = dict(self._REAL)
        status["battery_percent"] = _StrBombNum()
        rows = self._emitted(status)
        self.assertEqual(rows[0]["detail"], "on battery · 42%")

    def test_float_bomb_battery_percent_degrades_to_unknown(self):
        status = dict(self._REAL)
        status["battery_percent"] = _FloatBomb()
        rows = self._emitted(status)
        self.assertIn("unknown charge", rows[0]["detail"])

    def test_bool_bomb_alerts_enabled_reads_junk_off(self):
        status = dict(self._REAL)
        status["settings"] = {"alerts_enabled": _BoolBomb()}
        self.assertEqual(self._emitted(status), [])

    def test_float_bomb_low_battery_floor_falls_back_to_default(self):
        status = dict(self._REAL)
        status["battery_percent"] = 5
        status["settings"] = {"alerts_enabled": True,
                              "low_battery_pct": _FloatBomb()}
        rows = self._emitted(status)
        self.assertEqual({a["id"] for a in rows}, {"ups:power", "ups:battery"})
        self.assertIn("threshold 20%", [a for a in rows if a["id"] == "ups:battery"][0]["message"])


class ResourceFeederWrapperPins(_Alerts7Sandbox):
    """Poisoned latest_sample()/get_thresholds() wrappers must degrade
    field-level; the sane readings still trip their thresholds."""

    def _emitted(self, latest, th=None) -> list:
        import hub.metrics as metrics
        import hub.system_settings_svc as sss
        self.patch(metrics, "latest_sample", lambda: latest)
        if th is not None:
            self.patch(sss, "get_thresholds", lambda: th)
        emitted = self.assert_check_200()
        return [a for a in emitted if isinstance(a, dict) and a.get("kind") == "resource"]

    def test_get_bomb_sample_wrapper_still_alerts_cpu(self):
        rows = self._emitted(_DictGetBomb({"cpu_used_pct": 99.0}))
        self.assertEqual([a["id"] for a in rows], ["resource:cpu"])

    def test_get_bomb_thresholds_wrapper_still_alerts(self):
        rows = self._emitted({"cpu_used_pct": 99.0},
                             th=_DictGetBomb({"enabled": True, "cpu_pct": 90}))
        self.assertEqual([a["id"] for a in rows], ["resource:cpu"])

    def test_bool_bomb_enabled_flag_reads_junk_disabled(self):
        rows = self._emitted({"cpu_used_pct": 99.0},
                             th={"enabled": _BoolBomb(), "cpu_pct": 90})
        self.assertEqual(rows, [])

    def test_float_bomb_value_skips_its_check_not_the_pass(self):
        rows = self._emitted({"cpu_used_pct": _FloatBomb(), "mem_used_pct": 99.0})
        self.assertEqual([a["id"] for a in rows], ["resource:mem"])

    def test_bool_bomb_cooldown_falls_back_to_default(self):
        rows = self._emitted({"cpu_used_pct": 99.0},
                             th={"enabled": True, "cpu_pct": 90,
                                 "cooldown_sec": _BoolBomb()})
        self.assertEqual([a["id"] for a in rows], ["resource:cpu"])


class SmartFeederWrapperPins(_Alerts7Sandbox):
    """One poisoned device row must never kill the SMART pass; a failing
    disk wrapped in a bomb still pages, and its sane siblings still sweep."""

    _FAILING = {
        "id": "disk4", "name": "EvilDisk", "device": "/dev/disk4",
        "size_bytes": 1000,
        "smart": {"health": "FAILED!", "serial": "SER123", "model": "MDL"},
    }

    def _emitted(self, devices) -> list:
        import hub.storage_svc as storage_svc
        self.patch(storage_svc, "smart_devices", lambda: devices)
        emitted = self.assert_check_200()
        return [a for a in emitted if isinstance(a, dict) and a.get("kind") == "smart"]

    def test_get_bomb_dev_row_still_alerts_down(self):
        rows = self._emitted([_DictGetBomb(dict(self._FAILING))])
        self.assertEqual([(a["id"], a["level"]) for a in rows],
                         [("smart:SER123", "down")])

    def test_get_bomb_smart_dict_still_alerts_down(self):
        dev = dict(self._FAILING)
        dev["smart"] = _DictGetBomb(dict(self._FAILING["smart"]))
        rows = self._emitted([dev])
        self.assertEqual([(a["id"], a["level"]) for a in rows],
                         [("smart:SER123", "down")])

    def test_iter_bomb_devices_list_still_walks_the_real_rows(self):
        rows = self._emitted(_ListIterBomb([dict(self._FAILING)]))
        self.assertEqual([a["id"] for a in rows], ["smart:SER123"])

    def test_bool_bomb_devices_list_still_walks(self):
        rows = self._emitted(_ListBoolBomb([dict(self._FAILING)]))
        self.assertEqual([a["id"] for a in rows], ["smart:SER123"])

    def test_bool_bomb_error_flag_never_kills_the_pass(self):
        poisoned = dict(self._FAILING)
        poisoned["error"] = _BoolBomb()
        sibling = {
            "id": "disk5", "name": "GoodDisk", "device": "/dev/disk5",
            "size_bytes": 1,
            "smart": {"health": "FAILED!", "serial": "SIB1", "model": "M2"},
        }
        rows = self._emitted([poisoned, sibling])
        # The bombed flag reads as junk (no error): the disk's failing SMART
        # data still pages — the safe direction — and the sibling still sweeps.
        self.assertEqual([a["id"] for a in rows],
                         ["smart:SER123", "smart:SIB1"])

    def test_iter_bomb_attrs_table_keeps_the_health_verdict(self):
        dev = dict(self._FAILING)
        dev["smart"] = dict(self._FAILING["smart"])
        dev["smart"]["attrs"] = _ListIterBomb([
            {"type": "Pre-fail", "value": "5", "thresh": "10", "name": "A"},
        ])
        rows = self._emitted([dev])
        self.assertEqual([(a["id"], a["level"]) for a in rows],
                         [("smart:SER123", "down")])
        # The real pre-fail row under the bombed wrapper still contributes.
        self.assertIn("below vendor threshold", rows[0]["detail"])


class SmartNumSeamPins(unittest.TestCase):
    """_smart_num ran bare str()/float() on whatever a cached smart row
    carries; subclass bombs must degrade to None, real values must parse."""

    class _FloatFloatBomb(float):
        def __float__(self):
            raise RuntimeError("float bomb")

    class _IntFloatBomb(int):
        def __index__(self):
            raise RuntimeError("index bomb")

    def test_subclass_bombs_keep_their_real_value(self):
        # The unbound base coercions read the real number underneath the
        # override: the bomb never runs and the reading is not lost.
        self.assertEqual(alerts._smart_num(self._FloatFloatBomb(1.5)), 1.5)
        self.assertEqual(alerts._smart_num(self._IntFloatBomb(5)), 5.0)
        self.assertEqual(alerts._smart_num(_StrStripBomb("37")), 37.0)
        self.assertEqual(alerts._smart_num(_IntIndexBomb(7)), 7.0)

    def test_unrenderable_object_degrades_to_none(self):
        class _StrBombObj:
            def __str__(self):
                raise RuntimeError("str bomb")

        self.assertIsNone(alerts._smart_num(_StrBombObj()))

    def test_real_fields_still_parse(self):
        self.assertEqual(alerts._smart_num("37 Celsius"), 37.0)
        self.assertEqual(alerts._smart_num("0x02"), 2.0)
        self.assertEqual(alerts._smart_num(b"1,234"), 1234.0)
        self.assertEqual(alerts._smart_num(41), 41.0)

    def test_smart_key_survives_a_bombed_dev_row(self):
        key = alerts._smart_key(_DictGetBomb({
            "id": "disk9", "smart": {"serial": "ABC 123"},
        }))
        self.assertEqual(key, "ABC-123")
        # A dev row with nothing readable still yields the last-resort key.
        self.assertEqual(alerts._smart_key(_DictGetBomb({})), "disk")


class ExtendedFeederScalarZooPins(_Alerts7Sandbox):
    """Scalar bomb classes beyond the alerts6 matrix, riding feeder rows
    through check_once's final sanitize: each degrades field-level."""

    def test_extended_zoo_scrubs_and_answers_200(self):
        from hub import ups_policy
        rows = [
            {"t": 1, "id": "a", "s": _SetIterBomb({1})},
            {"t": 1, "id": "b", "f": _FrozensetIterBomb({2})},
            {"t": 1, "id": "c", "tu": _TupleIterBomb((3,))},
            {"t": 1, "id": "d", "ba": _BytearrayDecodeBomb(b"x")},
            {"t": _IntIndexBomb(7), "id": "e"},
            {"t": _StrStripBomb("5"), "id": "f"},
            {"t": 1, "id": "g", "bo": _DictBoolBomb({"x": 1})},
        ]
        self.patch(ups_policy, "sweep", lambda now: rows)
        emitted = self.assert_check_200()
        by_id = {a.get("id"): a for a in emitted if isinstance(a, dict)}
        self.assertEqual(by_id["a"]["s"], [1])       # set iter bomb
        self.assertEqual(by_id["b"]["f"], [2])       # frozenset iter bomb
        self.assertEqual(by_id["c"]["tu"], [3])      # tuple iter bomb
        self.assertEqual(by_id["d"]["ba"], "x")      # bytearray decode bomb
        # int.__index__ (unbound) reads the real 7 underneath the override.
        self.assertEqual(by_id["e"]["t"], 7)
        # str.__str__ (unbound) keeps the real text; the strip/isdigit
        # bombs never run on the emitted view's sanitize.
        self.assertEqual(by_id["f"]["t"], "5")
        self.assertEqual(by_id["g"]["bo"], {"x": 1})  # dict __bool__ bomb


if __name__ == "__main__":
    unittest.main()
