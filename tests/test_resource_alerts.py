"""CPU/mem/disk threshold alerts must not flap across a busy host's 88–100% band."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hub import alerts


class _IsolateAlertsFile(unittest.TestCase):
    """The first draft of these tests wrote fabricated CPU flaps into the
    operator's live ``data/alerts.jsonl``.  Pin the journal to a temp file
    even though ``_run`` also stubs ``_append_alert``.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._alerts_patch = patch.object(
            alerts, "ALERTS_FILE", Path(self._tmp.name) / "alerts.jsonl",
        )
        self._alerts_patch.start()
        self.addCleanup(self._alerts_patch.stop)


def _run(prev, cpu, now=1_000_000, cooldown=1800):
    new_state = dict(prev)
    with (
        patch.object(alerts, "_resource_thresholds", return_value={
            "enabled": True, "cpu_pct": 90, "mem_pct": 90, "disk_pct": 90,
            "cooldown_sec": cooldown,
        }),
        patch.object(alerts, "notify_settings", return_value={"enabled": False}),
        patch.object(alerts, "_append_alert", lambda alert: None),
        patch("hub.metrics.latest_sample", return_value={"cpu_used_pct": cpu}),
    ):
        emitted = alerts._check_resource_thresholds(prev, new_state, now)
    return emitted, new_state


class ResourceThresholdHysteresisTests(_IsolateAlertsFile):
    def test_a_spike_fires_once(self):
        emitted, state = _run({}, 100)
        self.assertEqual([a["event"] for a in emitted], ["problem"])
        self.assertEqual(state["resource:cpu"], "warn")

    def test_a_dip_inside_the_gap_does_not_resolve(self):
        prev = {"resource:cpu": "warn", "_resource_last": {"cpu": 1_000_000}}
        emitted, state = _run(prev, 88, now=1_000_060)
        self.assertEqual(emitted, [])
        self.assertEqual(state["resource:cpu"], "warn")

    def test_a_real_drop_resolves(self):
        prev = {"resource:cpu": "warn", "_resource_last": {"cpu": 1_000_000}}
        emitted, state = _run(prev, 70, now=1_000_060)
        self.assertEqual([a["event"] for a in emitted], ["resolved"])
        self.assertEqual(state["resource:cpu"], "ok")

    def test_a_reentry_inside_cooldown_is_silent(self):
        prev = {
            "resource:cpu": "ok",
            "_resource_last": {"cpu": 1_000_000},
        }
        emitted, state = _run(prev, 100, now=1_000_300)
        self.assertEqual(emitted, [])
        self.assertEqual(state["resource:cpu"], "ok")

    def test_a_reentry_after_cooldown_fires_again(self):
        prev = {
            "resource:cpu": "ok",
            "_resource_last": {"cpu": 1_000_000},
        }
        emitted, state = _run(prev, 100, now=1_001_900)
        self.assertEqual([a["event"] for a in emitted], ["problem"])
        self.assertEqual(state["resource:cpu"], "warn")


if __name__ == "__main__":
    unittest.main()
