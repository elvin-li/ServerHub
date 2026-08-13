"""Behavioural runs of the panel watchdog against a shimmed launchd.

test_panel_watchdog.py pins the script's safety properties by reading its
text, because exercising the real thing would kickstart the live panel.
These tests do run it -- with PATH resolving launchctl/curl/lsof/pgrep to
shims in a scratch directory, and HOME/TMPDIR pointing at scratch space, so
no run can reach the real launchd domain, the real panel, or the real state
files.  What static checks cannot pin is the arithmetic across runs, and the
arithmetic is what failed on 2026-08-13:

* three consecutive misses -- not two -- produce exactly one kickstart, and
  the counter resets afterwards;
* a healthy answer (any HTTP response, or a mere TCP listener) clears the
  counter;
* counters are per-port files: misses against one port never advance another
  port's count;
* a probe whose port is not the one the resolved label serves takes no
  action at all -- no counting, no kickstart;
* a non-numeric SERVERHUB_PORT probes nothing;
* oversized launchd log files are compressed and then truncated, losslessly.
"""
import gzip
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SCRIPT = BASE / "deploy" / "panel-watchdog.sh"

#: Ports from the dynamic range so a stray unshimmed probe (which these tests
#: never make) could still not hit the live panel on 8086.
PANEL_PORT = 58086
OTHER_PORT = 59999

_LAUNCHCTL_SHIM = """#!/bin/bash
printf 'launchctl %s\\n' "$*" >> "$SHIM_LOG"
if [ "$1" = print ]; then
  [ -n "${FAKE_NO_LABELS:-}" ] && exit 113
  case "$2" in
    */com.elvin.serverhub)
      printf '\\tenvironment = {\\n'
      if [ -n "${FAKE_LABEL_PORT:-}" ]; then
        printf '\\t\\tSERVERHUB_PORT => %s\\n' "$FAKE_LABEL_PORT"
      fi
      printf '\\t}\\n'
      exit 0 ;;
    *) exit 113 ;;
  esac
fi
exit 0
"""

_CURL_SHIM = """#!/bin/bash
printf 'curl %s\\n' "$*" >> "$SHIM_LOG"
exit "${FAKE_CURL_RC:-7}"
"""

_LSOF_SHIM = """#!/bin/bash
printf 'lsof %s\\n' "$*" >> "$SHIM_LOG"
exit "${FAKE_LSOF_RC:-1}"
"""

_PGREP_SHIM = """#!/bin/bash
printf 'pgrep %s\\n' "$*" >> "$SHIM_LOG"
exit 1
"""


class WatchdogRuns(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-watchdog-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.home = root / "home"
        self.logs = self.home / "Library" / "Logs"
        self.logs.mkdir(parents=True)
        self.tmp = root / "tmp"
        self.tmp.mkdir()
        self.shims = root / "bin"
        self.shims.mkdir()
        self.shim_log = root / "shim.log"
        for name, body in (
            ("launchctl", _LAUNCHCTL_SHIM),
            ("curl", _CURL_SHIM),
            ("lsof", _LSOF_SHIM),
            ("pgrep", _PGREP_SHIM),
        ):
            shim = self.shims / name
            shim.write_text(body)
            shim.chmod(0o755)

    def run_watchdog(self, port, *, label_port=None, curl_rc=7, lsof_rc=1,
                     no_labels=False, threshold=None):
        """One tick.  Defaults model 'panel label loaded, port dead'."""
        env = {
            # Shims first; /usr/bin:/bin for the coreutils the script uses.
            "PATH": f"{self.shims}:/usr/bin:/bin",
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "SHIM_LOG": str(self.shim_log),
            "SERVERHUB_PORT": str(port),
            "FAKE_CURL_RC": str(curl_rc),
            "FAKE_LSOF_RC": str(lsof_rc),
        }
        if label_port is not None:
            env["FAKE_LABEL_PORT"] = str(label_port)
        if no_labels:
            env["FAKE_NO_LABELS"] = "1"
        if threshold is not None:
            env["SERVERHUB_WATCHDOG_THRESHOLD"] = str(threshold)
        return subprocess.run(
            ["/bin/bash", str(SCRIPT)],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def state(self, port):
        p = self.tmp / f"serverhub-watchdog.{port}.state"
        return p.read_text() if p.exists() else None

    def kickstarts(self):
        if not self.shim_log.exists():
            return []
        return [
            line for line in self.shim_log.read_text().splitlines()
            if line.startswith("launchctl kickstart")
        ]

    def watchdog_log(self):
        p = self.logs / "serverhub-watchdog.log"
        return p.read_text() if p.exists() else ""

    # ── the counting contract ────────────────────────────────────────────────

    def test_three_misses_produce_exactly_one_kickstart(self):
        for expected in ("1", "2"):
            proc = self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(self.state(PANEL_PORT), expected)
            self.assertEqual(self.kickstarts(), [],
                             "no restart before the third consecutive miss")
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
        kicks = self.kickstarts()
        self.assertEqual(len(kicks), 1, self.watchdog_log())
        self.assertIn("com.elvin.serverhub", kicks[0])
        self.assertIsNone(self.state(PANEL_PORT),
                          "the counter must reset after a restart")

    def test_a_healthy_http_answer_clears_the_counter(self):
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
        self.assertEqual(self.state(PANEL_PORT), "1")
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT, curl_rc=0)
        self.assertIsNone(self.state(PANEL_PORT))
        self.assertEqual(self.kickstarts(), [])
        self.assertIn("healthy again", self.watchdog_log())

    def test_a_mere_tcp_listener_counts_as_healthy(self):
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT,
                          curl_rc=7, lsof_rc=0)
        self.assertIsNone(self.state(PANEL_PORT))
        self.assertEqual(self.kickstarts(), [])

    def test_threshold_env_override_is_honoured(self):
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT, threshold=1)
        self.assertEqual(len(self.kickstarts()), 1)

    # ── the 2026-08-13 incident, replayed ────────────────────────────────────

    def test_counters_are_isolated_per_port(self):
        """Two production misses plus one test-port miss must not add up.

        Before the fix all ports shared one counter file, so the third miss
        -- taken against a port nobody served -- reached the threshold and
        kickstarted the healthy production panel (2026-08-13 03:49).
        """
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
        self.assertEqual(self.state(PANEL_PORT), "2")
        self.run_watchdog(OTHER_PORT, label_port=OTHER_PORT)
        self.assertEqual(self.state(PANEL_PORT), "2",
                         "another port's miss advanced the production count")
        self.assertEqual(self.state(OTHER_PORT), "1")
        self.assertEqual(self.kickstarts(), [])

    def test_a_port_the_label_does_not_serve_is_left_alone(self):
        """The incident's other half: label discovery is port-blind, so the
        59999 run resolved the production label and restarted it on its own
        third miss.  A probe of a port the label does not serve must neither
        count nor kickstart, no matter how often it runs."""
        for _ in range(4):
            proc = self.run_watchdog(OTHER_PORT, label_port=PANEL_PORT)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.kickstarts(), [])
        self.assertIsNone(self.state(OTHER_PORT),
                          "a mismatched probe must not even count")
        self.assertIn("leaving it alone", self.watchdog_log())

    def test_a_label_without_a_port_env_is_still_covered(self):
        """No SERVERHUB_PORT readable from the label means 'assume it
        matches': the guard must fail open, or an oddly-registered panel
        would never be restarted again."""
        for _ in range(3):
            self.run_watchdog(PANEL_PORT)  # shim prints no port line
        self.assertEqual(len(self.kickstarts()), 1)

    def test_a_non_numeric_port_probes_nothing(self):
        proc = self.run_watchdog("8086 -o /tmp/x")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("not a port", proc.stderr)
        self.assertFalse(self.shim_log.exists(),
                         "no launchctl/curl/lsof may run for a garbage port")

    def test_the_legacy_shared_state_file_is_removed(self):
        legacy = self.tmp / "serverhub-watchdog.state"
        legacy.write_text("2")
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT, curl_rc=0)
        self.assertFalse(legacy.exists(),
                         "the pre-scoping counter must not linger in TMPDIR")

    # ── standing down ────────────────────────────────────────────────────────

    def test_no_loaded_label_stands_down_and_clears_state(self):
        (self.tmp / f"serverhub-watchdog.{PANEL_PORT}.state").write_text("2")
        proc = self.run_watchdog(PANEL_PORT, no_labels=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIsNone(self.state(PANEL_PORT))
        self.assertEqual(self.kickstarts(), [])

    def test_a_fresh_lock_from_an_overlapping_tick_wins(self):
        lock = self.tmp / f"serverhub-watchdog.{PANEL_PORT}.state.lck"
        lock.mkdir()
        proc = self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT)
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(self.shim_log.exists(),
                         "a held lock must stop the tick before any probing")
        self.assertIsNone(self.state(PANEL_PORT))
        self.assertTrue(lock.is_dir(), "the other tick's lock must survive")

    # ── launchd log backstop ─────────────────────────────────────────────────

    def test_oversized_launchd_logs_are_compressed_then_truncated(self):
        body = os.urandom(1024) * (10 * 1024 + 1)  # just over 10 MiB
        err = self.logs / "serverhub.err.log"
        err.write_bytes(body)
        out = self.logs / "serverhub.out.log"
        out.write_bytes(b"small\n")
        self.run_watchdog(PANEL_PORT, label_port=PANEL_PORT, curl_rc=0)
        self.assertEqual(err.stat().st_size, 0, "oversized log must truncate")
        archived = gzip.decompress((self.logs / "serverhub.err.log.0.gz").read_bytes())
        self.assertEqual(archived, body, "rotation must be lossless")
        self.assertEqual(out.read_bytes(), b"small\n")
        self.assertFalse((self.logs / "serverhub.out.log.0.gz").exists(),
                         "a small log is not rotated")


if __name__ == "__main__":
    unittest.main()
