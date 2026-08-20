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

    def _code(self) -> str:
        """The script with comment lines dropped, for position assertions
        that must not match the prose explaining the code."""
        return "\n".join(
            line for line in self.text.splitlines()
            if not line.lstrip().startswith("#")
        )

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
        # Garbage or 0 must not skip the comparison and kickstart on miss 1.
        self.assertIn('*[!0-9]*|0) FAIL_THRESHOLD=3', self.text)

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

    def test_overlapping_ticks_do_not_race_the_fail_counter(self):
        # util-linux flock is not on stock macOS / launchd PATH. mkdir is.
        self.assertIn('mkdir "$LOCK_DIR"', self.text)
        self.assertNotIn("flock -n 9", self.text)
        self.assertIn('trap ', self.text)

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
        self.assertNotIn('pgrep -f', code)
        idx_kill = code.index("awk -v label=")
        idx_kick = code.index("kickstart -k")
        self.assertLess(idx_kill, idx_kick, "must clear xpcproxy before kickstart")
        self.assertIn("xpcproxy", code)
        # PATH-relative so tests can shim them; absolute /bin/ps would
        # SIGKILL a live xpcproxy on the machine running the suite.
        self.assertIn('ps -u', code)
        self.assertNotIn("/bin/ps", code)

    def test_log_is_rotated(self):
        self.assertIn("tail -n 500", self.text)

    def test_fail_counter_is_scoped_to_the_probed_port(self):
        # One shared counter let a manual SERVERHUB_PORT=59999 test run feed
        # its misses into the production 8086 probe's arithmetic (2026-08-13
        # 03:49: a healthy panel was kickstarted twice).  The state file must
        # embed the port, and the pre-scoping shared path must be cleaned up
        # rather than left behind as a stale input.
        self.assertIn(
            'STATE_FILE="${TMPDIR:-/tmp}/serverhub-watchdog.${PORT}.state"',
            self.text,
        )
        self.assertIn(
            'rm -f "${TMPDIR:-/tmp}/serverhub-watchdog.state"', self.text
        )

    def test_a_non_numeric_port_probes_nothing(self):
        # SERVERHUB_PORT is interpolated into a URL, an lsof filter and now a
        # filename.  A garbage value cannot be probed, only miscounted -- three
        # ticks of failing to probe nonsense must not restart the real panel.
        code = self._code()
        guard = code.index("case \"$PORT\" in ''|*[!0-9]*)")
        for landmark in ('mkdir "$LOCK_DIR"', "launchctl print", "curl -sS"):
            self.assertLess(
                guard, code.index(landmark),
                f"the port guard must run before {landmark!r}",
            )

    def test_only_the_port_the_label_serves_is_acted_on(self):
        # Label discovery is port-blind, so a 59999 test run still resolved
        # com.elvin.serverhub and kickstarted the production panel on its own
        # third miss.  The script must read the label's SERVERHUB_PORT and
        # stand down on a mismatch -- before any counting, so a mismatched
        # probe can neither restart the panel nor advance a counter.
        self.assertIn("SERVERHUB_PORT => ", self.text)
        code = self._code()
        self.assertLess(
            code.index('[ "$label_port" != "$PORT" ]'),
            code.index('printf \'%s\' "$fails"'),
            "the ownership check must come before the counter is written",
        )

    def test_panel_logs_get_a_size_backstop(self):
        # launchd appends to StandardOut/ErrorPath forever and macOS rotates
        # neither; installs without the host's daily logrotate agent need the
        # watchdog to cap them.  Compress before truncating (the tail that
        # explains a crash must survive), truncate in place (launchd holds the
        # files open O_APPEND, so mv would strand its descriptor), and stay
        # out of the .1.gz..5.gz namespace the daily job rotates through.
        self.assertIn("serverhub.out.log", self.text)
        self.assertIn("serverhub.err.log", self.text)
        code = self._code()
        self.assertLess(
            code.index('gzip -c "$panel_log"'),
            code.index(': > "$panel_log"'),
            "must compress a copy before truncating",
        )
        self.assertNotIn('"$panel_log.1.gz"', self.text)
        self.assertNotIn('mv "$panel_log"', self.text)


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
