"""A one-sweep launchd flicker must not write a down/recover pair.

OneDrive Share went ``Not loaded`` for one 90s alert tick after a panel
kickstart, then came back ``ok``.  The journal grew a false outage.  The
service sweep now holds the first bad observation in ``_service_pending``
and only pages if the next sweep is still bad.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hub import alerts


def _svc(sid, state, detail="Not loaded"):
    return {sid: {"id": sid, "name": sid, "kind": "launchd",
                  "group": "native", "state": state, "detail": detail}}


def _run(prev, services, now=1_000_000):
    new_state = {}
    if isinstance(prev.get("_service_pending"), dict):
        new_state["_service_pending"] = dict(prev["_service_pending"])
    with (
        patch.object(alerts, "notify_settings", return_value={"enabled": False}),
        patch.object(alerts, "_append_alert", lambda alert: None),
    ):
        emitted = alerts._service_transition_alerts(prev, new_state, services, now)
    return emitted, new_state


class ServiceAlertDebounceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        p = patch.object(alerts, "ALERTS_FILE", Path(self._tmp.name) / "alerts.jsonl")
        p.start()
        self.addCleanup(p.stop)

    def test_a_one_sweep_flap_is_silent(self):
        emitted, state = _run({"local.onedrive-share": "ok"}, _svc("local.onedrive-share", "down"))
        self.assertEqual(emitted, [])
        self.assertEqual(state["local.onedrive-share"], "down")
        self.assertEqual(state["_service_pending"]["local.onedrive-share"], 1)

        emitted, state = _run(state, _svc("local.onedrive-share", "ok", "Running"))
        self.assertEqual(emitted, [])
        self.assertNotIn("local.onedrive-share", state.get("_service_pending") or {})

    def test_a_confirmed_outage_fires_on_the_second_sweep(self):
        _, state = _run({"local.onedrive-share": "ok"}, _svc("local.onedrive-share", "down"))
        emitted, state = _run(state, _svc("local.onedrive-share", "down"))
        self.assertEqual([a["event"] for a in emitted], ["problem"])
        self.assertEqual(emitted[0]["id"], "local.onedrive-share")
        self.assertNotIn("local.onedrive-share", state.get("_service_pending") or {})

    def test_an_announced_outage_still_resolves(self):
        prev = {"local.onedrive-share": "down"}
        emitted, state = _run(
            prev, _svc("local.onedrive-share", "ok", "Running · pid 1"),
        )
        self.assertEqual([a["event"] for a in emitted], ["resolved"])
        self.assertEqual(state["local.onedrive-share"], "ok")

    def test_a_known_down_stays_quiet(self):
        emitted, _ = _run(
            {"local.onedrive-share": "down"},
            _svc("local.onedrive-share", "down"),
        )
        self.assertEqual(emitted, [])

    def test_first_seen_service_is_not_an_outage(self):
        emitted, state = _run({}, _svc("brand-new", "down"))
        self.assertEqual(emitted, [])
        self.assertEqual(state["brand-new"], "down")
        self.assertNotIn("brand-new", state.get("_service_pending") or {})

    def test_warn_to_down_on_an_announced_fault_fires(self):
        emitted, _ = _run(
            {"svc": "warn"},
            _svc("svc", "down", "Not loaded"),
        )
        self.assertEqual([a["event"] for a in emitted], ["problem"])
        self.assertEqual(emitted[0]["level"], "down")

    def test_junk_service_rows_do_not_abort_the_sweep(self):
        emitted, state = _run(
            {"ok-svc": "ok"},
            {"ok-svc": "not-a-row", "other": {"id": "other", "state": "ok"}},
        )
        self.assertEqual(emitted, [])
        self.assertNotIn("ok-svc", state)
        emitted, _ = _run({"x": "ok"}, ["not-a-map"])
        self.assertEqual(emitted, [])


if __name__ == "__main__":
    unittest.main()
