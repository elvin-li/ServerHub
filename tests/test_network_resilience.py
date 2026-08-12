import unittest
from unittest.mock import patch

from hub import network_svc


class NetworkResilienceTests(unittest.TestCase):
    def setUp(self):
        network_svc._failover_state.update(
            mode="starting",
            wired_failures=0,
            wired_successes=0,
            last_action=None,
            last_action_at=None,
            last_check_at=None,
            last_result=None,
        )

    def test_alias_route_requires_loopback_and_local_flag(self):
        output = """route to: 192.0.2.204
  interface: lo0
      flags: <UP,HOST,DONE,LOCAL,IFSCOPE>
"""
        with patch.object(network_svc, "sh", return_value=(0, output, "")):
            self.assertTrue(network_svc._alias_local_route("192.0.2.204")["ok"])

        rejected = """route to: 192.0.2.204
  interface: en7
      flags: <UP,HOST,REJECT,DONE>
"""
        with patch.object(network_svc, "sh", return_value=(0, rejected, "")):
            self.assertFalse(network_svc._alias_local_route("192.0.2.204")["ok"])

    def test_existing_alias_with_broken_local_route_is_rebuilt(self):
        conf = {
            "auto_bind": True,
            "ips": ["192.0.2.204"],
            "netmask": "255.255.255.255",
            "interval": 60,
            "prefer_wired": True,
        }
        preferred = {"device": "en7", "service": "USB LAN"}
        locations = [{"device": "en7", "alias": True, "netmask": "255.255.255.255", "up": True}]
        with (
            patch.object(network_svc, "_alias_settings", return_value=conf),
            patch.object(network_svc, "preferred_active_device", return_value=preferred),
            patch.object(network_svc, "find_ip_locations", return_value=locations),
            patch.object(network_svc, "_alias_local_route", side_effect=[{"ok": False}, {"ok": True}]),
            patch.object(network_svc, "remove_ip_alias", return_value={"ok": True}) as remove_alias,
            patch.object(network_svc, "add_ip_alias", return_value={"ok": True}) as add_alias,
        ):
            result = network_svc.ensure_aliases_on_preferred()

        self.assertTrue(result["ok"])
        self.assertEqual(result["actions"][0]["status"], "repaired")
        remove_alias.assert_called_once_with("en7", "192.0.2.204")
        add_alias.assert_called_once_with("en7", "192.0.2.204", "255.255.255.255")

    def test_wifi_turns_off_only_after_stable_wired_recovery(self):
        conf = {
            "enabled": True,
            "power_save_wifi": True,
            "interval": 15,
            "fail_threshold": 2,
            "recover_threshold": 2,
            "probe_timeout_ms": 1200,
        }
        probe = {"ok": True, "device": "en7", "ip": "198.51.100.206", "gateway": "198.51.100.1"}
        with (
            patch.object(network_svc, "_failover_settings", return_value=conf),
            patch.object(network_svc, "_wired_devices", return_value=[{"device": "en7"}]),
            patch.object(network_svc, "_probe_wired_device", return_value=probe),
            patch.object(network_svc, "wifi_power_status", return_value={"ok": True, "on": True, "device": "en0"}),
            patch.object(network_svc, "set_wifi_power", return_value={"ok": True}) as set_power,
        ):
            first = network_svc.network_failover_tick()
            second = network_svc.network_failover_tick()

        self.assertIsNone(first["action"])
        self.assertEqual(second["action"], "wifi_off")
        set_power.assert_called_once_with(False)

    def test_wifi_turns_on_only_after_stable_wired_failure(self):
        conf = {
            "enabled": True,
            "power_save_wifi": True,
            "interval": 15,
            "fail_threshold": 2,
            "recover_threshold": 2,
            "probe_timeout_ms": 1200,
        }
        probe = {"ok": False, "device": "en7", "reason": "链路或 IPv4 未就绪"}
        with (
            patch.object(network_svc, "_failover_settings", return_value=conf),
            patch.object(network_svc, "_wired_devices", return_value=[{"device": "en7"}]),
            patch.object(network_svc, "_probe_wired_device", return_value=probe),
            patch.object(network_svc, "wifi_power_status", return_value={"ok": True, "on": False, "device": "en0"}),
            patch.object(network_svc, "set_wifi_power", return_value={"ok": True}) as set_power,
        ):
            first = network_svc.network_failover_tick()
            second = network_svc.network_failover_tick()

        self.assertIsNone(first["action"])
        self.assertEqual(second["action"], "wifi_on")
        set_power.assert_called_once_with(True)

    def test_profile_switch_refuses_missing_target_without_mutating(self):
        services = [{
            "name": "Wi-Fi", "hardware_port": "Wi-Fi", "device": "en0",
        }]
        with (
            patch.object(network_svc, "network_services", return_value=services),
            patch.object(network_svc, "set_service_enabled") as set_enabled,
            patch.object(network_svc, "set_service_order") as set_order,
        ):
            result = network_svc.switch_profile("ethernet")

        self.assertFalse(result["ok"])
        self.assertIn("No usable wired network service", result["message"])
        set_enabled.assert_not_called()
        set_order.assert_not_called()

    def test_profile_switch_reports_any_failed_step(self):
        services = [
            {"name": "USB LAN", "hardware_port": "USB LAN", "device": "en7"},
            {"name": "Wi-Fi", "hardware_port": "Wi-Fi", "device": "en0"},
        ]
        with (
            patch.object(network_svc, "network_services", return_value=services),
            patch.object(
                network_svc, "set_service_enabled",
                return_value={"ok": False, "message": "enable failed"},
            ),
            patch.object(
                network_svc, "set_service_order",
                return_value={"ok": True, "message": "ordered"},
            ),
            patch.object(
                network_svc, "ensure_aliases_on_preferred",
                return_value={"ok": True, "message": "aliases moved"},
            ),
            patch.object(network_svc.time, "sleep"),
        ):
            result = network_svc.switch_profile("ethernet")

        self.assertFalse(result["ok"])
        self.assertTrue(any(step["ok"] is False for step in result["steps"]))
        self.assertIn("enable failed", result["message"])

    def test_profile_switch_keeps_best_effort_failures_separate(self):
        services = [
            {"name": "USB LAN", "hardware_port": "USB LAN", "device": "en7"},
            {"name": "Wi-Fi", "hardware_port": "Wi-Fi", "device": "en0"},
        ]
        with (
            patch.object(network_svc, "network_services", return_value=services),
            patch.object(
                network_svc, "set_service_enabled",
                return_value={"ok": True, "message": "enabled"},
            ),
            patch.object(
                network_svc, "set_wifi_power",
                return_value={"ok": False, "message": "radio failed"},
            ),
            patch.object(
                network_svc, "set_service_order",
                return_value={"ok": True, "message": "ordered"},
            ),
            patch.object(
                network_svc, "ensure_aliases_on_preferred",
                return_value={"ok": False, "message": "alias failed"},
            ),
            patch.object(network_svc, "_bust"),
            patch.object(network_svc.time, "sleep"),
        ):
            result = network_svc.switch_profile("wifi")

        self.assertTrue(result["ok"])
        failed_steps = [step for step in result["steps"] if step.get("ok") is False]
        self.assertEqual(
            {step["step"] for step in failed_steps},
            {"enable Wi-Fi radio", "rebind aliases"},
        )
        self.assertTrue(all(step["critical"] is False for step in failed_steps))
        self.assertFalse(result["alias_rebind"]["ok"])

    def test_profile_switch_reports_service_order_failure(self):
        services = [
            {"name": "USB LAN", "hardware_port": "USB LAN", "device": "en7"},
            {"name": "Wi-Fi", "hardware_port": "Wi-Fi", "device": "en0"},
        ]
        with (
            patch.object(network_svc, "network_services", return_value=services),
            patch.object(
                network_svc, "set_service_enabled",
                return_value={"ok": True, "message": "enabled"},
            ),
            patch.object(
                network_svc, "set_service_order",
                return_value={"ok": False, "message": "order failed"},
            ),
            patch.object(
                network_svc, "ensure_aliases_on_preferred",
                return_value={"ok": True, "message": "aliases moved"},
            ),
            patch.object(network_svc, "_bust"),
            patch.object(network_svc.time, "sleep"),
        ):
            result = network_svc.switch_profile("ethernet")

        self.assertFalse(result["ok"])
        order_step = next(
            step for step in result["steps"] if step["step"] == "set service order"
        )
        self.assertTrue(order_step["critical"])
        self.assertFalse(order_step["ok"])


if __name__ == "__main__":
    unittest.main()
