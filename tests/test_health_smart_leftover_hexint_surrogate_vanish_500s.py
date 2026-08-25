"""Leftover Health/SMART 500s, silent journal loss and vanished-smartctl mis-answers.

Prior passes hardened the encoder-facing sanitizers (``_jsonable`` in
hub/health_svc.py and hub/smart_test_svc.py) and the digit *parsers* on these
paths, but four leftovers survived around them:

* ``smart_test_svc.get_schedule`` ran bare ``str()`` over the YAML
  ``smart_schedule`` fields.  ``interval: 0xFFF…`` (hex YAML loads through
  ``int(x, 16)``, a power-of-two base the 4300-digit cap does not apply to)
  ValueError'd GET /api/smart through ``overview()``, and the same raise
  escaped ``schedule_due()`` inside the SMART scheduler tick, so scheduled
  self-tests silently stopped for as long as the leftover sat in settings.
* one >4300-digit number inside ``data/smart-tests.json`` made
  ``json.loads`` raise ValueError (not JSONDecodeError) for the *whole*
  document: ``_load_history`` returned ``[]``, GET /api/smart/history went
  silently empty, and the next ``_append_history`` rewrote the journal with
  only its own record — every prior result silently lost.
* one poisoned brew row (an over-cap int name/status) raised out of the
  loop-wide try in ``health_svc._collect_checks`` and silently dropped every
  later brew check — postgresql@18 included, the exact row the page exists
  to show when Immich's database is down.
* a vanished smartctl binary answered POST /api/smart/test with the coded
  400 "this disk does not offer SMART self-tests" (and abort with the macOS
  admin-password dance) instead of the tool-absent 503 the other vanished
  CLIs use (files.fb_missing, photoshub.ctl_missing, backup.tool_missing).
  The 503 fires only after a fresh disk probe confirms the binary is gone —
  a spawn glitch with smartctl still on disk keeps the old answers.
* ``overview()`` echoed ``SMARTCTL`` verbatim; PATH decodes with
  surrogateescape, so a mojibake PATH entry put a lone surrogate on the
  GET /api/smart payload and Starlette's UTF-8 encode 500'd it.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import health_svc, smart_test_svc
from hub.errors import CODES

#: Over CPython's 4300-digit str<->int cap: renders neither via str() nor json.
_HUGE_INT = int("9" * 4300) + int("9" * 4300)
#: A lone surrogate, as os.environ/PATH produce for undecodable bytes.
_SURROGATE = "\udce6"


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ScheduleHexIntTests(unittest.TestCase):
    """get_schedule must coerce YAML leftovers via a str() probe, not raise."""

    def _schedule(self, stored: dict) -> dict:
        with mock.patch.object(smart_test_svc, "_schedule_cfg", return_value=stored):
            return smart_test_svc.get_schedule()

    def test_over_cap_interval_falls_back_to_off(self):
        out = self._schedule({"interval": _HUGE_INT, "kind": "short"})
        self.assertEqual(out["interval"], "off")
        _starlette(out)

    def test_over_cap_kind_falls_back_to_short(self):
        out = self._schedule({"interval": "daily", "kind": _HUGE_INT})
        self.assertEqual(out["kind"], "short")
        _starlette(out)

    def test_over_cap_device_drops_only_its_entry(self):
        out = self._schedule({"devices": [_HUGE_INT, "/dev/disk0"]})
        self.assertEqual(out["devices"], ["/dev/disk0"])
        _starlette(out)

    def test_renderable_numeric_fields_still_coerce_not_raise(self):
        # An already-int YAML leftover under the cap must go through the same
        # str() probe (an unknown value, so the safe fallback) — not raise and
        # not be hidden behind an isinstance(str) gate.
        out = self._schedule({"interval": 86400, "kind": 12, "devices": ["/dev/disk1"]})
        self.assertEqual(out["interval"], "off")
        self.assertEqual(out["kind"], "short")
        self.assertEqual(out["devices"], ["/dev/disk1"])

    def test_surrogate_fields_replace_encode(self):
        out = self._schedule({
            "interval": "daily" + _SURROGATE,
            "kind": "short",
            "devices": ["/dev/disk0" + _SURROGATE],
        })
        self.assertEqual(out["interval"], "off")
        self.assertEqual(out["devices"], [])
        _starlette(out)

    def test_schedule_due_survives_poisoned_settings(self):
        # The scheduler tick swallows exceptions, so this raise silently
        # stopped every scheduled self-test rather than 500ing anything.
        with mock.patch.object(
            smart_test_svc, "_schedule_cfg",
            return_value={"interval": _HUGE_INT, "kind": "short", "devices": ["/dev/disk0"]},
        ):
            self.assertFalse(smart_test_svc.schedule_due())


class HistoryJournalDigitTests(unittest.TestCase):
    """One over-cap number must cost its own field, never the whole journal."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "smart-tests.json"
        self.path.write_text(
            '[{"ts": 1000, "device": "/dev/disk0", "kind": "short", "ok": true},\n'
            ' {"ts": 2000, "device": "/dev/disk0", "kind": "long", "ok": true,'
            '  "power_on_hours": ' + "9" * 5000 + "}]",
            encoding="utf-8",
        )

    def test_load_history_keeps_rows_and_drops_only_the_field(self):
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", self.path):
            rows = smart_test_svc._load_history()
        self.assertEqual([r.get("ts") for r in rows], [1000, 2000])
        self.assertIsNone(rows[1].get("power_on_hours"))
        _starlette(rows)

    def test_history_endpoint_payload_is_not_silently_empty(self):
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", self.path):
            rows = smart_test_svc.history(10)
        self.assertEqual(len(rows), 2)
        _starlette(rows)

    def test_append_does_not_wipe_prior_rows(self):
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", self.path):
            smart_test_svc._append_history(
                {"ts": 3000, "device": "/dev/disk1", "kind": "short", "ok": False}
            )
        kept = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual([r.get("ts") for r in kept], [1000, 2000, 3000])


class BrewRowDigitTests(unittest.TestCase):
    """One poisoned brew row must not drop every later brew check."""

    def _collect(self, brew_rows):
        def serial_fan_out(fn, items, max_workers=None):
            return [fn(item) for item in items]

        with (
            mock.patch.object(health_svc, "fan_out", serial_fan_out),
            mock.patch.object(health_svc, "brew_services_list", return_value=brew_rows),
            mock.patch.object(health_svc, "engine_up", return_value=True),
            mock.patch.object(health_svc, "nginx_overview", side_effect=RuntimeError("no nginx")),
            mock.patch.object(health_svc, "port_open", return_value=True),
            mock.patch.object(health_svc, "launchd_running_labels", return_value=frozenset()),
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            # `import glob` happens inside _collect_checks; patch the stdlib.
            mock.patch("glob.glob", return_value=[]),
        ):
            return health_svc._collect_checks()

    def test_over_cap_status_keeps_the_healthy_sibling(self):
        out = self._collect([
            {"name": "mosquitto", "status": _HUGE_INT},
            {"name": "postgresql@18", "status": "started"},
        ])
        ids = [c["id"] for c in out["checks"]]
        self.assertIn("brew_postgresql@18", ids)
        # The poisoned row itself still renders (status unknown) instead of
        # vanishing with everything after it.
        self.assertIn("brew_mosquitto", ids)
        _starlette(out)

    def test_over_cap_name_skips_only_its_entry(self):
        out = self._collect([
            {"name": _HUGE_INT, "status": "started"},
            {"name": "grafana", "status": "started"},
        ])
        ids = [c["id"] for c in out["checks"]]
        self.assertIn("brew_grafana", ids)
        _starlette(out)


class VanishedSmartctlTests(unittest.TestCase):
    """The tool-absent 503 fires only after a fresh disk probe confirms it."""

    def test_error_code_is_a_503(self):
        self.assertEqual(CODES["smart.smartctl_missing"][0], 503)

    def test_start_test_maps_confirmed_vanish_to_smartctl_missing(self):
        with (
            mock.patch.object(smart_test_svc, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(smart_test_svc, "_smartctl_installed", return_value=False),
            mock.patch.dict(smart_test_svc._device_type_cache, {"/dev/disk0": ()}, clear=True),
        ):
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertEqual(result.get("error"), "smartctl_missing")
        _starlette(result)

    def test_start_test_keeps_unsupported_when_binary_is_on_disk(self):
        # A spawn glitch with smartctl still installed is NOT the vanished-CLI
        # case: keep the existing no-passthrough answer.
        with (
            mock.patch.object(smart_test_svc, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(smart_test_svc, "_smartctl_installed", return_value=True),
            mock.patch.dict(smart_test_svc._device_type_cache, {"/dev/disk0": ()}, clear=True),
        ):
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertEqual(result.get("error"), "unsupported")

    def test_start_test_spawn_failure_probes_before_the_admin_sheet(self):
        # Capabilities pass (probed earlier, cached), then smartctl vanishes
        # before the sudo spawn: the answer must be the confirmed 503, not a
        # macOS authorization prompt for a binary that no longer exists.
        caps = {
            "readable": True, "available": True, "supported": ["short"],
            "reason": "", "device_type": "auto", "estimated_minutes": {}, "detail": "",
        }
        with (
            mock.patch.object(smart_test_svc, "_capabilities", return_value=caps),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(smart_test_svc, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(smart_test_svc, "_smartctl_installed", return_value=False),
            mock.patch.object(smart_test_svc, "run_admin") as admin,
            mock.patch.dict(smart_test_svc._device_type_cache, {"/dev/disk0": ()}, clear=True),
        ):
            result = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertEqual(result.get("error"), "smartctl_missing")
        admin.assert_not_called()

    def test_abort_maps_confirmed_vanish_to_smartctl_missing(self):
        with (
            mock.patch.object(smart_test_svc, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(smart_test_svc, "_smartctl_installed", return_value=False),
            mock.patch.object(smart_test_svc, "run_admin") as admin,
            mock.patch.dict(smart_test_svc._device_type_cache, {"/dev/disk0": ()}, clear=True),
        ):
            result = smart_test_svc.abort_test("/dev/disk0")
        self.assertEqual(result.get("error"), "smartctl_missing")
        admin.assert_not_called()

    def test_abort_keeps_admin_fallback_when_binary_is_on_disk(self):
        with (
            mock.patch.object(smart_test_svc, "sh", return_value=(1, "", "denied")),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(smart_test_svc, "_smartctl_installed", return_value=True),
            mock.patch.object(
                smart_test_svc, "run_admin",
                return_value={"ok": False, "error": "password_required"},
            ) as admin,
            mock.patch.dict(smart_test_svc._device_type_cache, {"/dev/disk0": ()}, clear=True),
        ):
            result = smart_test_svc.abort_test("/dev/disk0")
        admin.assert_called_once()
        self.assertEqual(result.get("error"), "password_required")

    def test_route_mapping_carries_the_code(self):
        from hub.routers.nas_storage import _SMART_ERRORS
        self.assertEqual(_SMART_ERRORS.get("smartctl_missing"), "smart.smartctl_missing")


class SurrogateSmartOverviewTests(unittest.TestCase):
    """GET /api/smart must replace-encode a surrogate smartctl path."""

    def test_overview_payload_utf8_encodes(self):
        tmp = Path(tempfile.mkdtemp()) / "smart-tests.json"
        with (
            mock.patch.object(smart_test_svc, "SMARTCTL", "/opt/homebrew/bin/" + _SURROGATE + "smartctl"),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=[]),
            mock.patch.object(smart_test_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(smart_test_svc, "HISTORY_PATH", tmp),
            mock.patch.object(smart_test_svc, "_schedule_cfg", return_value={}),
        ):
            data = smart_test_svc.overview(force=True)
        smart_test_svc.invalidate()
        self.assertIn("smartctl", data["smartctl"])
        self.assertNotIn(_SURROGATE, data["smartctl"])
        _starlette(data)


class SurrogateSanitizerKeyPins(unittest.TestCase):
    """Already safe — pinned: surrogate JSON *keys* and values replace-encode."""

    def test_health_jsonable_replace_encodes_keys_and_values(self):
        cleaned = health_svc._jsonable({("k" + _SURROGATE): ("v" + _SURROGATE)})
        self.assertEqual(cleaned, {"k?": "v?"})
        _starlette(cleaned)

    def test_smart_jsonable_replace_encodes_keys_and_values(self):
        cleaned = smart_test_svc._jsonable({("k" + _SURROGATE): ("v" + _SURROGATE)})
        self.assertEqual(cleaned, {"k?": "v?"})
        _starlette(cleaned)

    def test_worker_health_snapshot_replace_encodes_names(self):
        from hub import worker_health
        name = "sampler" + _SURROGATE
        worker_health.register(name, 60)
        try:
            rows = worker_health.snapshot()
            names = [r["name"] for r in rows]
            self.assertIn("sampler?", names)
            _starlette(rows)
        finally:
            worker_health.unregister(name)


if __name__ == "__main__":
    unittest.main()
