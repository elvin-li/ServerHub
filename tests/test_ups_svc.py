"""UPS monitoring: pmset parsing and the power-loss alert state machine.

Parsing is table-driven against verbatim ``pmset -g batt`` shapes from real
machines — a desktop with no battery, a MacBook on its internal battery, and
an external USB UPS on both wall and battery power.  The alert tests drive
``alerts._check_ups`` through the three transitions the design calls for
(power lost, battery low, power restored) with the snapshot mocked, so no
test ever runs pmset or writes the real alerts file.
"""
from __future__ import annotations

import datetime
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import alerts, ups_svc  # noqa: E402

DESKTOP_AC = "Now drawing from 'AC Power'\n"

UPS_ON_AC = (
    "Now drawing from 'AC Power'\n"
    " -Back-UPS ES 750 \t100%; charging present: true\n"
)

UPS_ON_BATTERY = (
    "Now drawing from 'UPS Power'\n"
    " -Back-UPS ES 750 \t42%; discharging; 0:25 remaining present: true\n"
)

MACBOOK_ON_BATTERY = (
    "Now drawing from 'Battery Power'\n"
    " -InternalBattery-0 (id=4653155)\t85%; discharging; 3:12 remaining present: true\n"
)

MACBOOK_NOT_CHARGING = (
    "Now drawing from 'AC Power'\n"
    " -InternalBattery-0 (id=4653155)\t100%; AC attached; not charging present: true\n"
)


class ParseBattTests(unittest.TestCase):
    def test_desktop_without_ups_reports_not_present(self):
        st = ups_svc._parse_batt(DESKTOP_AC)
        self.assertFalse(st["present"])
        self.assertEqual(st["source"], "ac")
        self.assertIsNone(st["battery_percent"])

    def test_empty_output_is_not_an_error(self):
        st = ups_svc._parse_batt("")
        self.assertFalse(st["present"])
        self.assertEqual(st["source"], "unknown")

    def test_none_bytes_and_int_payloads_do_not_500(self):
        self.assertFalse(ups_svc._parse_batt(None)["present"])
        self.assertFalse(ups_svc._parse_batt(8)["present"])
        st = ups_svc._parse_batt(UPS_ON_BATTERY.encode())
        self.assertEqual(st["battery_percent"], 42)
        self.assertIsNone(ups_svc._parse_ups_thresholds(None))
        self.assertIsNone(ups_svc._parse_ups_thresholds(0))

    def test_external_ups_on_wall_power(self):
        st = ups_svc._parse_batt(UPS_ON_AC)
        self.assertTrue(st["present"])
        self.assertEqual(st["kind"], "ups")
        self.assertEqual(st["name"], "Back-UPS ES 750")
        self.assertTrue(st["on_ac"])
        self.assertFalse(st["on_battery"])
        self.assertEqual(st["battery_percent"], 100)
        self.assertTrue(st["charging"])
        self.assertIsNone(st["time_remaining_min"])

    def test_external_ups_on_battery(self):
        st = ups_svc._parse_batt(UPS_ON_BATTERY)
        self.assertTrue(st["present"])
        self.assertEqual(st["source"], "ups")
        self.assertTrue(st["on_battery"])
        self.assertEqual(st["battery_percent"], 42)
        self.assertFalse(st["charging"], "discharging must not read as charging")
        self.assertEqual(st["time_remaining_min"], 25)

    def test_internal_battery_is_classified_and_timed(self):
        st = ups_svc._parse_batt(MACBOOK_ON_BATTERY)
        self.assertEqual(st["kind"], "internal_battery")
        self.assertTrue(st["on_battery"])
        self.assertEqual(st["battery_percent"], 85)
        self.assertEqual(st["time_remaining_min"], 3 * 60 + 12)

    def test_not_charging_is_not_charging(self):
        st = ups_svc._parse_batt(MACBOOK_NOT_CHARGING)
        self.assertTrue(st["on_ac"])
        self.assertFalse(st["charging"])

    def test_huge_remaining_estimate_does_not_500(self):
        """pmset ``999…:00 remaining`` used to leak a 400-digit int into GET /api/ups."""
        import json

        hours = "9" * 400
        st = ups_svc._parse_batt(
            "Now drawing from 'UPS Power'\n"
            f" -Back-UPS ES 750 \t42%; discharging; {hours}:00 remaining present: true\n"
        )
        json.dumps(st, allow_nan=False)
        self.assertEqual(st["battery_percent"], 42)
        self.assertIsNone(st["time_remaining_min"])


class ParseUpsThresholdTests(unittest.TestCase):
    def test_configured_levels_are_reported_and_minus_one_dropped(self):
        text = "UPS settings:\n haltlevel\t20\n haltafter\t-1\n haltremain\t-1\n"
        self.assertEqual(ups_svc._parse_ups_thresholds(text), {"haltlevel": 20})

    def test_no_settings_yields_none(self):
        self.assertIsNone(ups_svc._parse_ups_thresholds(""))
        self.assertIsNone(ups_svc._parse_ups_thresholds("UPS settings:\n"))


class UpsSettingsTests(unittest.TestCase):
    def test_defaults_and_override_merge(self):
        with mock.patch.object(ups_svc, "cfg", lambda: {"settings": {}}):
            self.assertEqual(ups_svc.ups_settings(), ups_svc.UPS_DEFAULTS)
        with mock.patch.object(
            ups_svc, "cfg", lambda: {"settings": {"ups": {"low_battery_pct": 35, "junk": 1}}}
        ):
            s = ups_svc.ups_settings()
        self.assertEqual(s["low_battery_pct"], 35)
        self.assertTrue(s["alerts_enabled"])
        self.assertNotIn("junk", s, "unknown keys must not leak into the policy")

    def test_non_dict_settings_does_not_500(self):
        """``(cfg().get("settings") or {}).get("ups")`` 500'd on a leftover list/string."""
        for settings in ("nope", [1], 3, True):
            with mock.patch.object(ups_svc, "cfg", lambda s=settings: {"settings": s}):
                self.assertEqual(ups_svc.ups_settings()["low_battery_pct"], 20)

    def test_infinite_policy_numbers_do_not_500(self):
        """YAML ``.inf`` became a float inf; Starlette allow_nan=False 500'd GET /api/ups."""
        import json

        with mock.patch.object(ups_svc, "cfg", lambda: {"settings": {"ups": {
            "low_battery_pct": float("inf"),
            "alerts_enabled": True,
            "shutdown": {
                "enabled": True,
                "trigger_pct": float("inf"),
                "trigger_remaining_min": float("nan"),
            },
        }}}):
            s = ups_svc.ups_settings()
        json.dumps(s, allow_nan=False)
        self.assertEqual(s["low_battery_pct"], 20)
        self.assertIsNone(s["shutdown"]["trigger_pct"])
        self.assertIsNone(s["shutdown"]["trigger_remaining_min"])

    def test_huge_policy_integers_do_not_500(self):
        """A 400-digit leftover YAML int is a valid int; ``float()`` OverflowError'd the plan."""
        import json

        huge = 10 ** 400
        with mock.patch.object(ups_svc, "cfg", lambda: {"settings": {"ups": {
            "low_battery_pct": huge,
            "shutdown": {"trigger_pct": huge, "trigger_remaining_min": huge},
        }}}):
            s = ups_svc.ups_settings()
        json.dumps(s, allow_nan=False)
        self.assertEqual(s["low_battery_pct"], 20)
        self.assertIsNone(s["shutdown"]["trigger_pct"])
        self.assertIsNone(s["shutdown"]["trigger_remaining_min"])

    def test_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/ups."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(ups_svc._jsonable(_Stamp()))
        out = ups_svc._jsonable({"name": _Stamp(), "ok": True})
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["name"])
        self.assertIs(out["ok"], True)

    def test_yaml_date_bytes_and_set_do_not_500_jsonable(self):
        """Leftover YAML dates/!!binary/!!set used to leak into GET /api/ups."""
        payload = {
            "name": datetime.date(2026, 8, 19),
            "note": b"ups",
            "tags": {"ac", "usb"},
            "nested": {"when": datetime.datetime(2026, 8, 19, 12, 0, 0)},
        }
        out = ups_svc._jsonable(payload)
        json.dumps(out, allow_nan=False)
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["note"], "ups")
        self.assertCountEqual(out["tags"], ["ac", "usb"])
        self.assertTrue(out["nested"]["when"].startswith("2026-08-19"))

    def test_as_text_recursing_does_not_500(self):
        """leftover ``str()`` RecursionError used to 500 GET /api/ups."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(ups_svc._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": ups_svc._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")


def _status(*, present=True, on_battery=False, pct=100, name="Back-UPS ES 750",
            alerts_enabled=True, low=20):
    return {
        "present": present,
        "kind": "ups",
        "name": name,
        "source": "ups" if on_battery else "ac",
        "on_ac": not on_battery,
        "on_battery": on_battery,
        "battery_percent": pct,
        "charging": not on_battery,
        "time_remaining_min": None,
        "halt_levels": None,
        "settings": {"alerts_enabled": alerts_enabled, "low_battery_pct": low},
    }


class UpsAlertStateMachineTests(unittest.TestCase):
    """Edge-triggered: state changes announce, steady states stay quiet."""

    def setUp(self):
        self.appended: list = []
        self.notified: list = []
        patches = [
            mock.patch.object(alerts, "_append_alert", self.appended.append),
            mock.patch.object(
                alerts, "notify_settings",
                lambda: {"enabled": True, "include_warn": True, "notify_resolve": True},
            ),
            mock.patch.object(
                alerts, "send_ha_notify",
                lambda title, message, **kw: self.notified.append((title, message, kw)) or {"ok": True},
            ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _sweep(self, prev: dict, status: dict) -> tuple[list, dict]:
        new_state: dict = {}
        with mock.patch.object(ups_svc, "ups_status", lambda force=False: status):
            emitted = alerts._check_ups(prev, new_state, now=1_700_000_000)
        return emitted, new_state

    def test_no_ups_tracks_nothing(self):
        emitted, state = self._sweep({}, _status(present=False))
        self.assertEqual(emitted, [])
        self.assertEqual(state, {})

    def test_power_loss_fires_once_and_only_on_the_edge(self):
        emitted, state = self._sweep({"ups:power": "ok"}, _status(on_battery=True, pct=80))
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["id"], "ups:power")
        self.assertEqual(emitted[0]["level"], "down")
        self.assertEqual(emitted[0]["event"], "problem")
        self.assertEqual(state["ups:power"], "down")
        self.assertEqual(self.notified[0][2].get("level"), "down")

        # Still on battery next sweep: silence, but the state is carried.
        emitted, state = self._sweep(state, _status(on_battery=True, pct=70))
        self.assertEqual(emitted, [])
        self.assertEqual(state["ups:power"], "down")

    def test_first_ever_sweep_on_battery_still_alerts(self):
        # A fresh state file (new install, wiped data/) must not mute a
        # machine that is already running on battery.
        emitted, _ = self._sweep({}, _status(on_battery=True, pct=90))
        self.assertEqual([a["id"] for a in emitted], ["ups:power"])

    def test_low_battery_fires_at_the_floor_once(self):
        prev = {"ups:power": "down"}
        emitted, state = self._sweep(prev, _status(on_battery=True, pct=20, low=20))
        self.assertEqual([a["id"] for a in emitted], ["ups:battery"])
        self.assertEqual(emitted[0]["level"], "down")
        self.assertIn("20%", emitted[0]["message"])
        self.assertEqual(state["ups:battery"], "down")

        # Battery keeps draining: no re-announce, the siren already fired.
        emitted, state = self._sweep(state, _status(on_battery=True, pct=12, low=20))
        self.assertEqual(emitted, [])

    def test_restore_resolves_power_and_clears_battery_silently(self):
        prev = {"ups:power": "down", "ups:battery": "down"}
        emitted, state = self._sweep(prev, _status(on_battery=False, pct=55))
        self.assertEqual([a["id"] for a in emitted], ["ups:power"],
                         "battery must clear without a second resolved ping")
        self.assertEqual(emitted[0]["event"], "resolved")
        self.assertEqual(state["ups:power"], "ok")
        self.assertEqual(state["ups:battery"], "ok")
        titles = [t for t, _, _ in self.notified]
        self.assertIn("ServerHub UPS recovered", titles)

    def test_disabled_policy_tracks_nothing(self):
        emitted, state = self._sweep(
            {"ups:power": "ok"}, _status(on_battery=True, alerts_enabled=False)
        )
        self.assertEqual(emitted, [])
        self.assertEqual(state, {})

    def test_snapshot_failure_never_raises_into_the_sweep(self):
        new_state: dict = {}
        with mock.patch.object(ups_svc, "ups_status", side_effect=RuntimeError("pmset broke")):
            emitted = alerts._check_ups({}, new_state, now=0)
        self.assertEqual(emitted, [])


class UpsApiTests(unittest.TestCase):
    def _client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hub.routers.ups_api import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_empty_patch_is_a_machine_readable_error(self):
        """The SPA translates {code, params}; a bare-string HTTPException was
        the one endpoint here outside that contract."""
        with mock.patch.object(ups_svc, "save_ups_settings") as save:
            r = self._client().put("/api/ups/settings", json={})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "ups.empty_patch")
        save.assert_not_called()

    def test_valid_patch_is_saved(self):
        with mock.patch.object(ups_svc, "save_ups_settings") as save, \
             mock.patch.object(ups_svc, "ups_status", lambda force=False: {"present": False}):
            r = self._client().put("/api/ups/settings", json={"low_battery_pct": 30})
        self.assertEqual(r.status_code, 200)
        save.assert_called_once_with({"low_battery_pct": 30})


if __name__ == "__main__":
    unittest.main(verbosity=2)
