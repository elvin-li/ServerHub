"""Guards on the panel watchdog.

The watchdog restarts the panel unattended, so the properties that keep it from
becoming a restart loop are the ones worth pinning.  These are static checks on
the script and plist rather than behavioural runs: exercising the real thing
would kickstart the live panel.
"""
import plistlib
import re
import subprocess
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SCRIPT = BASE / "deploy" / "panel-watchdog.sh"
PLIST = BASE / "deploy" / "local.serverhub.watchdog.plist"


class WatchdogScript(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text()

    def test_script_is_valid_bash(self):
        proc = subprocess.run(
            ["bash", "-n", str(SCRIPT)], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_script_is_executable(self):
        self.assertTrue(SCRIPT.stat().st_mode & 0o111, "watchdog must be executable")

    def test_requires_consecutive_failures_before_acting(self):
        # A single missed probe must never restart the panel: a deliberate
        # restart or a slow boot would otherwise trigger a second restart on
        # top of it.
        self.assertIn("FAIL_THRESHOLD", self.text)
        self.assertRegex(
            self.text,
            r'FAIL_THRESHOLD="\$\{SERVERHUB_WATCHDOG_THRESHOLD:-(\d+)\}"',
        )
        default = int(
            re.search(
                r'FAIL_THRESHOLD="\$\{SERVERHUB_WATCHDOG_THRESHOLD:-(\d+)\}"',
                self.text,
            ).group(1)
        )
        self.assertGreaterEqual(default, 3, "grace window is too short")
        self.assertIn('[ "$fails" -lt "$FAIL_THRESHOLD" ] && exit 0', self.text)

    def test_counter_is_cleared_after_a_restart(self):
        # Without this the next tick would already sit at the threshold and
        # restart again while the panel is still coming up.
        tail = self.text.split("kickstart -k", 1)[1]
        self.assertIn('rm -f "$STATE_FILE"', tail)

    def test_does_nothing_when_no_panel_label_is_loaded(self):
        # Booting the job out on purpose must not be undone by the watchdog.
        self.assertIn('if [ -z "$LABEL" ]; then', self.text)
        block = self.text.split('if [ -z "$LABEL" ]; then', 1)[1].split("fi", 1)[0]
        self.assertIn("exit 0", block)

    def test_any_http_status_counts_as_healthy(self):
        # /api/health answers 401 when signed out.  Treating that as "down"
        # would restart a perfectly healthy panel every three minutes.
        self.assertIn("curl -sS -o /dev/null", self.text)
        self.assertNotIn("curl -fsS", self.text)

    def test_prefers_elvin_label_and_skips_kickstart_if_port_listens(self):
        elvin = self.text.index("com.elvin.serverhub")
        local = self.text.index("local.serverhub.panel")
        self.assertLess(elvin, local, "must prefer com.elvin.serverhub")
        self.assertIn('lsof -nP -iTCP:"$PORT" -sTCP:LISTEN', self.text)

    def test_clears_a_wedged_xpcproxy_before_kickstart(self):
        # The failure this exists for: xpcproxy holds the job's pid, so launchd
        # reports the job running and kickstart cannot make progress until the
        # stuck process is gone.  Compare positions in the code alone -- the
        # header comment names both steps while explaining them.
        code = "\n".join(
            line for line in self.text.splitlines() if not line.lstrip().startswith("#")
        )
        idx_kill = code.index("xpcproxy $LABEL")
        idx_kick = code.index("kickstart -k")
        self.assertLess(idx_kill, idx_kick, "must clear xpcproxy before kickstart")

    def test_log_is_rotated(self):
        self.assertIn("tail -n 500", self.text)


class PanelProcessType(unittest.TestCase):
    """The panel must not be classified as a background job.

    launchd throttles ProcessType=Background on CPU *and* disk I/O.  The panel
    serves the HTTP UI, so on a busy host that throttle turned an 8.5s start
    into 35-110s and the SPA reported the restart as failed.  Measured on a
    host at load ~40: 35s as Background, 0.8-11s as Interactive.
    """

    def test_installer_classifies_the_panel_with_the_apps(self):
        body = (BASE / "install.sh").read_text()
        self.assertIn("<key>ProcessType</key><string>Interactive</string>", body)
        self.assertNotIn(
            "<key>ProcessType</key><string>Background</string>",
            body,
            "the installer only writes the panel and menu-bar agents",
        )

    def test_native_launcher_classifies_the_panel_with_the_apps(self):
        swift = (BASE / "macos" / "ServerHubLauncher.swift").read_text()
        # The launcher writes two plists: the panel and its own login item.
        # Neither should be Background.
        self.assertNotIn(
            "<key>ProcessType</key><string>Background</string>",
            swift,
            "the panel plist was written as a throttled background job",
        )
        self.assertGreaterEqual(
            swift.count("<key>ProcessType</key><string>Interactive</string>"), 2
        )

    def test_the_watchdog_itself_stays_background(self):
        # Opposite reasoning: a once-a-minute probe should be throttled, and it
        # must not compete with the panel it is there to protect.
        data = plistlib.loads(PLIST.read_bytes())
        self.assertEqual(data.get("ProcessType"), "Background")


class WatchdogPlist(unittest.TestCase):
    def setUp(self):
        self.data = plistlib.loads(PLIST.read_bytes())

    def test_is_periodic_not_keepalive(self):
        # KeepAlive on a script that exits immediately is a spawn loop.
        self.assertNotIn("KeepAlive", self.data)
        self.assertIn("StartInterval", self.data)
        self.assertGreaterEqual(self.data["StartInterval"], 30)

    def test_placeholders_are_substituted_by_the_installer(self):
        raw = PLIST.read_text()
        for token in ("__WATCHDOG__", "__LOG__", "__PORT__"):
            self.assertIn(token, raw)
        installer = (BASE / "install.sh").read_text()
        for token in ("__WATCHDOG__", "__LOG__", "__PORT__"):
            self.assertIn(token, installer, f"install.sh never replaces {token}")

    def test_label_matches_installer_and_uninstaller(self):
        label = self.data["Label"]
        self.assertEqual(label, "local.serverhub.watchdog")
        self.assertIn(label, (BASE / "install.sh").read_text())
        # A watchdog left behind would keep resurrecting a removed panel.
        self.assertIn(label, (BASE / "uninstall.sh").read_text())


if __name__ == "__main__":
    unittest.main()
