"""Leftover numeric-id / over-cap-int silent losses in the alert sweep.

The Alerts page's backends were already hardened against surrogate and
digit-cap 500s at the HTTP encode boundary, but the sweep itself still had
``isinstance`` gates and bare ``str()`` calls that CPython's 4300-digit
int<->str conversion cap (and numeric YAML ids) turned into silent loss:

* ``_jsonable_alert``'s ``isinstance(k, str)`` key gate silently dropped
  every numeric YAML/plist dict key from alerts.jsonl and alert_state.json.
* ``check_once`` / ``_loop`` used the same gate on service ids, so a numeric
  YAML ``id: 123`` never alerted and never persisted state.
* A leftover over-cap int (YAML hex ``0xFF…`` loads uncapped — ``int(x, 16)``
  is exempt from the digit cap) in a service ``name``/``detail``, a SMART
  ``serial``/``model``/``health``/attribute name, or the UPS ``name`` made a
  bare ``str()`` / f-string raise the digit-cap ValueError mid-loop, silently
  aborting the rest of that sweep pass — services, disks and the UPS after
  the poisoned row all went unwatched.
"""
from __future__ import annotations

import datetime
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import alerts

#: Past CPython's default 4300-digit str<->int conversion limit, as the
#: already-parsed int a YAML/plist hex leftover loads into.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class JsonableAlertKeyProbeTests(unittest.TestCase):
    def test_numeric_key_survives_the_str_probe(self):
        """The ``isinstance(k, str)`` gate silently dropped ``{123: …}``."""
        out = alerts._jsonable_alert({123: "x", "ok": 1, "nest": {8080: "y"}})
        _starlette(out)
        self.assertEqual(out["123"], "x")
        self.assertEqual(out["ok"], 1)
        self.assertEqual(out["nest"]["8080"], "y")

    def test_over_cap_int_key_drops_entry_not_dict(self):
        """str() of a >4300-digit key is the digit-cap ValueError; only the
        poisoned entry may vanish, never the dict or the route."""
        out = alerts._jsonable_alert({_HUGE_INT: "x", "ok": 1})
        _starlette(out)
        self.assertEqual(out, {"ok": 1})

    def test_date_key_coerces_to_isoformat(self):
        out = alerts._jsonable_alert({datetime.date(2026, 8, 19): "x"})
        _starlette(out)
        self.assertEqual(out, {"2026-08-19": "x"})

    def test_surrogate_keys_stay_scrubbed(self):
        """Both a raw surrogate str key and a coerced key whose str() carries
        one must come out UTF-8 encodable."""
        class K:
            def __str__(self):
                return "k\ud800"

        out = alerts._jsonable_alert({"\ud800": 1, K(): 2})
        _starlette(out)
        for key in out:
            self.assertNotIn("\ud800", key)


class NumericServiceIdSweepTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.state_file = root / "alert_state.json"
        for name, value in (
            ("ALERTS_FILE", root / "alerts.jsonl"),
            ("STATE_FILE", self.state_file),
        ):
            patched = mock.patch.object(alerts, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _check(self, status, prev):
        with (
            mock.patch.object(alerts, "full_status", return_value=status),
            mock.patch.object(alerts, "_load_state", return_value=prev),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
            mock.patch.object(alerts, "_check_resource_thresholds", return_value=[]),
            mock.patch.object(alerts, "_check_smart_health", return_value=[]),
            mock.patch.object(alerts, "_check_ups", return_value=[]),
            mock.patch("hub.ups_policy.sweep", return_value=[]),
            mock.patch("hub.freshness_svc.check_freshness", return_value=[]),
            mock.patch("hub.stale_runtime.remediate", return_value=[]),
        ):
            return alerts.check_once()

    def test_numeric_service_id_alerts_and_keeps_state(self):
        """YAML ``id: 123`` used to be silently invisible to the sweep."""
        status = {"groups": [{"group": "Core", "services": [
            {"id": 123, "name": "numeric", "state": "down", "kind": "launchd",
             "detail": "exit 1"},
        ]}]}
        emitted = self._check(status, {"123": "warn"})
        _starlette({"emitted": emitted})
        self.assertEqual([a["id"] for a in emitted], ["123"])
        saved = json.loads(self.state_file.read_text())
        self.assertEqual(saved["123"], "down")

    def test_over_cap_hex_service_id_drops_row_not_route(self):
        """A YAML-hex over-cap id has no renderable form; the row is dropped,
        the sibling service still alerts, and the check does not 500."""
        status = {"groups": [{"group": "Core", "services": [
            {"id": _HUGE_INT, "name": "poison", "state": "down", "kind": "launchd"},
            {"id": "ok", "name": "ok", "state": "down", "kind": "launchd",
             "detail": "exit 1"},
        ]}]}
        emitted = self._check(status, {"ok": "warn"})
        _starlette({"emitted": emitted})
        self.assertEqual([a["id"] for a in emitted], ["ok"])

    def test_unhashable_service_id_stays_dropped(self):
        """Stays-immune pin: leftover ``id: [foo]`` must not TypeError the
        sweep and must not become an alert id."""
        status = {"groups": [{"group": "Core", "services": [
            {"id": ["bad"], "name": "x", "state": "down", "kind": "launchd"},
        ]}]}
        emitted = self._check(status, {})
        _starlette({"emitted": emitted})
        self.assertEqual(emitted, [])


class ServiceSweepOverCapFieldTests(unittest.TestCase):
    def _sweep(self, services, prev):
        new_state = {"_service_pending": {}}
        with (
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
            mock.patch.object(alerts, "_append_alert"),
        ):
            return alerts._service_transition_alerts(prev, new_state, services, 100)

    def test_over_cap_name_does_not_abort_sweep(self):
        """The message f-string ran str() on a >4300-digit ``name`` and the
        digit-cap ValueError silently killed the rest of the service sweep —
        every service after the poisoned one lost its alert that pass."""
        services = {
            "a": {"id": "a", "name": _HUGE_INT, "state": "down",
                  "kind": "launchd", "detail": "x"},
            "b": {"id": "b", "name": "second", "state": "down",
                  "kind": "launchd", "detail": "y"},
        }
        emitted = self._sweep(services, {"a": "warn", "b": "warn"})
        self.assertEqual([a["id"] for a in emitted], ["a", "b"])
        # The unrenderable name falls back to the service id in the prose.
        self.assertTrue(emitted[0]["message"].startswith("a changed to down"))
        _starlette({"emitted": [alerts._jsonable_alert(a) for a in emitted]})

    def test_over_cap_detail_does_not_abort_sweep(self):
        services = {
            "a": {"id": "a", "name": "svc", "state": "down",
                  "kind": "launchd", "detail": _HUGE_INT},
        }
        emitted = self._sweep(services, {"a": "warn"})
        self.assertEqual(len(emitted), 1)
        self.assertIn("svc changed to down", emitted[0]["message"])

    def test_over_cap_name_recovery_does_not_abort_sweep(self):
        services = {
            "a": {"id": "a", "name": _HUGE_INT, "state": "ok",
                  "kind": "launchd", "detail": ""},
        }
        emitted = self._sweep(services, {"a": "down"})
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["event"], "resolved")
        self.assertIn("a has recovered", emitted[0]["message"])


class SmartSweepOverCapTests(unittest.TestCase):
    def test_smart_key_over_cap_serial_and_size_fall_back(self):
        """Bare str() on an over-cap plist serial raised the digit-cap
        ValueError and silently aborted the whole SMART pass."""
        key = alerts._smart_key({"smart": {"serial": _HUGE_INT}, "id": "disk4"})
        self.assertEqual(key, "disk4")
        key = alerts._smart_key({
            "smart": {"serial": "", "model": "SSD X"},
            "size_bytes": _HUGE_INT, "id": "disk5",
        })
        self.assertEqual(key, "disk5")

    def test_over_cap_model_does_not_abort_smart_pass(self):
        """One disk with an over-cap model/serial must not silence the
        sibling disk's failing-health alert."""
        devices = [
            {"id": "disk4", "device": "/dev/disk4", "size_bytes": 1000,
             "smart": {"health": "FAILED", "model": _HUGE_INT, "serial": _HUGE_INT}},
            {"id": "disk5", "device": "/dev/disk5", "size_bytes": 2000,
             "smart": {"health": "FAILED", "model": "Good SSD", "serial": "S2"}},
        ]
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with (
            mock.patch.object(alerts, "ALERTS_FILE", Path(tmp.name) / "alerts.jsonl"),
            mock.patch.object(alerts, "_resource_thresholds",
                              return_value={"smart_enabled": True}),
            mock.patch("hub.storage_svc.smart_devices", return_value=devices),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
        ):
            emitted = alerts._check_smart_health({}, {}, 100)
        rows = [alerts._jsonable_alert(a) for a in emitted]
        _starlette({"emitted": rows})
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["level"] for r in rows}, {"down"})
        self.assertTrue(any("Good SSD" in (r.get("message") or "") for r in rows))

    def test_over_cap_health_attr_name_and_critical_warning_do_not_raise(self):
        smart = {
            "health": _HUGE_INT,
            "critical_warning": _HUGE_INT,
            "attrs": [{
                "type": "Pre-fail", "value": "5", "thresh": "10",
                "name": _HUGE_INT,
            }],
        }
        down, warn = alerts._smart_reasons(smart, {})
        self.assertEqual(warn, [])
        # Only the prefail check trips; its unrenderable name falls to "?".
        self.assertEqual(len(down), 1)
        self.assertIn("?", down[0][0])
        _starlette({"reasons": down})


class UpsOverCapNameTests(unittest.TestCase):
    def test_over_cap_ups_name_does_not_abort_ups_alerts(self):
        """Bare str() on an over-cap UPS name raised the digit-cap ValueError
        and silently disabled power-loss alerting entirely."""
        st = {
            "present": True,
            "settings": {"alerts_enabled": True},
            "name": _HUGE_INT,
            "battery_percent": 42,
            "on_battery": True,
        }
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with (
            mock.patch.object(alerts, "ALERTS_FILE", Path(tmp.name) / "alerts.jsonl"),
            mock.patch("hub.ups_svc.ups_status", return_value=st),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
        ):
            emitted = alerts._check_ups({}, {}, 100)
        rows = [alerts._jsonable_alert(a) for a in emitted]
        _starlette({"emitted": rows})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["level"], "down")
        self.assertIn("42%", rows[0]["message"])


if __name__ == "__main__":
    unittest.main()
