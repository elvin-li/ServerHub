"""The Health page must see a dead WireGuard tunnel and a defective boot daemon.

This host ran two full days with the tunnel down and every health light green:
wg-quick is not a daemon, so when wireguard-go died nothing restarted it and
nothing reported it.  These tests pin the check that closes that hole.
"""
import unittest
from pathlib import Path
from unittest.mock import patch

from hub import health_svc


def _by_id(checks):
    return {c["id"]: c for c in checks}


class WireguardHealthTests(unittest.TestCase):
    def test_absent_wireguard_reports_nothing(self):
        """No wireguard-tools -> no checks, so unrelated hosts stay quiet."""
        with patch("hub.wireguard_svc.installation", return_value={"installed": False}):
            self.assertEqual(health_svc._wireguard_checks(), [])

    def test_unconfigured_tunnel_reports_nothing(self):
        """Tools present but no wg0.conf -> the feature is unused, not broken."""
        with patch("hub.wireguard_svc.installation", return_value={"installed": True}), \
             patch("hub.wireguard_svc.settings", return_value={"interface": "wg0"}), \
             patch("hub.wireguard_svc.conf_path", return_value=Path("/nonexistent/wg0.conf")):
            self.assertEqual(health_svc._wireguard_checks(), [])

    def test_dead_tunnel_and_defective_daemon_are_both_flagged(self):
        """The exact state this machine was found in."""
        with patch("hub.wireguard_svc.installation", return_value={"installed": True}), \
             patch("hub.wireguard_svc.settings", return_value={"interface": "wg0"}), \
             patch("hub.wireguard_svc.conf_path", return_value=Path(__file__)), \
             patch("hub.wireguard_svc.live_interface", return_value=("", [], "not running")), \
             patch("hub.wireguard_net_svc.daemon_state", return_value={
                 "healthy": False, "defects": ["bad_sleep", "unsupervised"],
             }):
            checks = _by_id(health_svc._wireguard_checks())

        tunnel = checks["wg_tunnel"]
        self.assertFalse(tunnel["ok"])
        self.assertEqual(tunnel["level"], "error")
        self.assertIn("not running", tunnel["detail"])
        self.assertTrue(tunnel["fix"])

        daemon = checks["wg_daemon"]
        self.assertFalse(daemon["ok"])
        self.assertEqual(daemon["level"], "warn")
        self.assertIn("bad_sleep", daemon["detail"])
        self.assertIn("repair-wireguard", daemon["fix"])

    def test_healthy_tunnel_and_daemon_are_green(self):
        with patch("hub.wireguard_svc.installation", return_value={"installed": True}), \
             patch("hub.wireguard_svc.settings", return_value={"interface": "wg0"}), \
             patch("hub.wireguard_svc.conf_path", return_value=Path(__file__)), \
             patch("hub.wireguard_svc.live_interface", return_value=("utun4", [["r"]], "")), \
             patch("hub.wireguard_net_svc.daemon_state", return_value={
                 "healthy": True, "defects": [],
             }):
            checks = _by_id(health_svc._wireguard_checks())

        self.assertTrue(checks["wg_tunnel"]["ok"])
        self.assertIn("utun4", checks["wg_tunnel"]["detail"])
        self.assertTrue(checks["wg_daemon"]["ok"])
        self.assertEqual(checks["wg_daemon"]["fix"], "")

    def test_probe_failure_degrades_to_a_warning(self):
        """A crashed probe must show up as a warn, never take the page down."""
        with patch("hub.wireguard_svc.installation", side_effect=RuntimeError("boom")):
            checks = _by_id(health_svc._wireguard_checks())
        self.assertIn("wg_check", checks)
        self.assertEqual(checks["wg_check"]["level"], "warn")


if __name__ == "__main__":
    unittest.main()
