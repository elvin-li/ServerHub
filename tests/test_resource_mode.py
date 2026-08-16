"""High/low panel load profile: quiet idle vs fresher UI."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hub import metrics, resource_mode, sensors_svc
from hub.routers.modules_api import sensors


class ResourceModeHelperTests(unittest.TestCase):
    def test_default_is_low(self):
        with patch("hub.resource_mode.cfg", return_value={"settings": {}}):
            self.assertEqual(resource_mode.resource_mode(), "low")
            self.assertFalse(resource_mode.is_high())

    def test_high_is_recognized(self):
        with patch("hub.resource_mode.cfg", return_value={"settings": {"resource_mode": "high"}}):
            self.assertEqual(resource_mode.resource_mode(), "high")
            self.assertTrue(resource_mode.is_high())

    def test_garbage_falls_back_to_low(self):
        with patch("hub.resource_mode.cfg", return_value={"settings": {"resource_mode": "turbo"}}):
            self.assertEqual(resource_mode.resource_mode(), "low")
            self.assertFalse(resource_mode.is_high())


class ResourceModeSettingsTests(unittest.TestCase):
    def test_saving_the_mode_busts_the_status_cache(self):
        from hub.routers.settings_api import SettingsPatch, put_settings

        with (
            patch("hub.routers.settings_api.update_settings", return_value={}),
            patch("hub.routers.settings_api._public_settings", return_value={"resource_mode": "high"}),
            patch("hub.status.invalidate_status") as bust,
            patch("hub.tools_svc.start_updates_warmer") as warm,
            patch("hub.tools_svc.stop_updates_warmer"),
        ):
            out = put_settings(SettingsPatch(resource_mode="high"))
        self.assertTrue(out["ok"])
        bust.assert_called_once()
        warm.assert_called_once()


class ResourceModePathTests(unittest.TestCase):
    def test_light_sensors_api_is_ignored_in_high_mode(self):
        with (
            patch("hub.resource_mode.is_high", return_value=True),
            patch.object(sensors_svc, "collect_sensors", return_value={"full": True}),
            patch.object(sensors_svc, "collect_light", side_effect=AssertionError("light")),
        ):
            out = sensors(force=False, light=True)
        self.assertTrue(out.get("full"))

    def test_light_sensors_api_stays_light_in_low_mode(self):
        with (
            patch("hub.resource_mode.is_high", return_value=False),
            patch.object(sensors_svc, "peek_sensors", return_value=None),
            patch.object(sensors_svc, "collect_light", return_value={"light": True}),
            patch.object(sensors_svc, "collect_sensors", side_effect=AssertionError("full")),
        ):
            out = sensors(force=False, light=True)
        self.assertTrue(out.get("light"))

    def test_metrics_uses_full_sensors_in_high_mode(self):
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=None),
            patch("hub.resource_mode.is_high", return_value=True),
            patch("hub.sensors_svc.collect_sensors", return_value={
                "cpu_used_pct": 11.0,
                "memory": {"pressure_used_pct": 40, "pressure_free_pct": 60},
            }),
            patch("hub.sensors_svc.collect_light", side_effect=AssertionError("light")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        self.assertEqual(sample["cpu_used_pct"], 11.0)

    def test_metrics_stays_light_in_low_mode(self):
        with (
            patch("hub.sensors_svc.peek_sensors", return_value=None),
            patch("hub.resource_mode.is_high", return_value=False),
            patch("hub.sensors_svc.collect_light", return_value={
                "cpu_used_pct": 8.0,
                "memory": {"pressure_used_pct": 33, "pressure_free_pct": 67},
            }),
            patch("hub.sensors_svc.collect_sensors", side_effect=AssertionError("full")),
            patch("hub.metrics.os.getloadavg", return_value=(0.5, 0.4, 0.3)),
            patch("hub.metrics.shutil.disk_usage", return_value=type(
                "DU", (), {"used": 50 * 2**30, "total": 100 * 2**30}
            )()),
            patch("hub.metrics._ncpu", return_value=8),
        ):
            sample = metrics._sample()
        self.assertEqual(sample["cpu_used_pct"], 8.0)

    def test_low_mode_host_skips_docker_info(self):
        from hub.routers import system_extra

        probes = []

        def fake_docker(*args, **kwargs):
            probes.append(args)
            return (0, "ok", "")

        with (
            patch.object(system_extra, "is_high", return_value=False),
            patch("hub.docker_cli.docker", side_effect=fake_docker),
            patch.object(system_extra, "sh", return_value=(0, "8", "")),
            patch.object(system_extra, "default_interface", return_value="en0"),
            patch.object(system_extra, "interface_address", return_value="192.168.1.1"),
            patch.object(system_extra, "host_ip", return_value="192.168.1.1"),
            patch.object(system_extra, "peek_engine", return_value=True),
        ):
            snap = system_extra._host_snapshot(True)
        self.assertEqual(probes, [])
        self.assertTrue(snap["orbstack"])

    def test_high_mode_host_still_probes_docker(self):
        from hub.docker_cli import invalidate_engine_state
        from hub.routers import system_extra

        probes = []

        def fake_docker(*args, **kwargs):
            probes.append(args)
            return (0, "ok", "")

        # engine_up keeps a process-wide TTL.  A earlier test in the full
        # suite can leave a hit, and this assertion then sees no docker call
        # even though high mode did ask for a live engine probe.
        invalidate_engine_state()
        with (
            patch.object(system_extra, "is_high", return_value=True),
            patch("hub.docker_cli.docker", side_effect=fake_docker),
            patch.object(system_extra, "sh", return_value=(0, "8", "")),
            patch.object(system_extra, "default_interface", return_value="en0"),
            patch.object(system_extra, "interface_address", return_value="192.168.1.1"),
            patch.object(system_extra, "host_ip", return_value="192.168.1.1"),
        ):
            snap = system_extra._host_snapshot(True)
        self.assertTrue(probes)
        self.assertTrue(snap["orbstack"])


if __name__ == "__main__":
    unittest.main()
