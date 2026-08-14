"""Contract tests for install.sh / uninstall.sh hardening."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.install = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")

    def test_app_default_bind_is_loopback(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn('os.environ.get("SERVERHUB_HOST") or "127.0.0.1"', source)
        self.assertNotIn('or "0.0.0.0"', source)

    def test_port_is_range_checked(self):
        self.assertIn("65535", self.install)
        self.assertIn("--port must be an integer between 1 and 65535", self.install)

    def test_launch_agent_pins_loopback_bind(self):
        self.assertIn("SERVERHUB_HOST</key><string>127.0.0.1</string>", self.install)

    def test_leftover_panel_labels_are_retired(self):
        for label in (
            "local.serverhub.watchdog",
            "local.serverhub",
            "com.elvin.serverhub",
        ):
            self.assertIn(label, self.install)

    def test_uninstall_stops_every_label_generation(self):
        for label in (
            "local.serverhub.panel",
            "local.serverhub.watchdog",
            "local.serverhub",
            "com.elvin.serverhub",
            "local.serverhub-launcher",
            "com.elvin.serverhub-launcher",
        ):
            self.assertIn(label, self.uninstall)

    def test_uninstall_undoes_wireguard_pf_and_sudoers(self):
        self.assertIn("com.wireguard.wg0", self.uninstall)
        self.assertIn("serverhub-wireguard", self.uninstall)
        self.assertIn("/etc/sudoers.d/serverhub", self.uninstall)
        self.assertIn("/usr/local/libexec/serverhub", self.uninstall)
        self.assertIn("sed -i.bak '/serverhub-wireguard/d'", self.uninstall)

    def test_uninstall_removes_filebrowser_hub_log(self):
        self.assertIn("filebrowser-hub.log", self.uninstall)

    def test_uninstall_clears_static_prev_and_compose_validate_temps(self):
        self.assertIn("static.prev", self.uninstall)
        self.assertIn(".static-deploy-pending", self.uninstall)
        self.assertIn(".compose-validate-", self.uninstall)

    def test_install_token_writer_uses_o_excl(self):
        self.assertIn("O_EXCL", self.install)
        self.assertIn("refusing symlink", self.install)


if __name__ == "__main__":
    unittest.main()
