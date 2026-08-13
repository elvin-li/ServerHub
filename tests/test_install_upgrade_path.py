"""install.sh re-run is the supported upgrade; pin what makes it one.

The installer's header promises "safe to re-run: it upgrades an existing
install in place".  These checks pin the properties that promise rests on,
plus the guard added after reviewing what a re-run does on a host whose
panel runs under a legacy launchd label (com.elvin.serverhub /
local.serverhub): the old preflight died with "port in use ... re-run with
--port <n>", advice that would have started a second panel against the same
services.yaml and data/.  The refusal must name the legacy label and point
at the documented in-place upgrade instead.

Static checks on the script text, same reasoning as test_panel_watchdog.py:
actually executing install.sh would bootstrap launch agents on the machine
running the suite.
"""
import re
import subprocess
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
INSTALL = BASE / "install.sh"
UNINSTALL = BASE / "uninstall.sh"
UPGRADE_DOC = BASE / "docs" / "upgrade.md"

#: Every launchd label the panel has ever shipped under.  install.sh manages
#: only the first; the other two mark an install it must not fight with.
PANEL_LINEAGE = ("local.serverhub.panel", "com.elvin.serverhub", "local.serverhub")


class InstallerReRun(unittest.TestCase):
    def setUp(self):
        self.text = INSTALL.read_text()

    def test_scripts_are_valid_bash(self):
        for script in (INSTALL, UNINSTALL):
            proc = subprocess.run(
                ["bash", "-n", str(script)], capture_output=True, text=True
            )
            self.assertEqual(proc.returncode, 0, f"{script.name}: {proc.stderr}")

    def test_dependencies_are_reinstalled_on_every_run(self):
        # An upgrade that skips pip when the venv already exists ships new
        # code against old dependencies.  The venv creation may be guarded;
        # the install of requirements.txt must not be.
        self.assertIn('pip install --quiet -r "$BASE/requirements.txt"', self.text)

    def test_existing_config_and_state_survive_a_rerun(self):
        self.assertIn("Keeping existing services.yaml", self.text)
        self.assertNotIn("rm -rf $BASE/data", self.text)
        self.assertNotIn('rm -rf "$BASE/data"', self.text)

    def test_refuses_to_install_beside_a_legacy_label(self):
        # Both foreign lineage labels must be probed before any plist is
        # written, and the refusal must forward to the upgrade document
        # rather than the old --port trap.
        first_write = self.text.index("write_plist")
        for label in ("com.elvin.serverhub", "local.serverhub"):
            with self.subTest(label=label):
                self.assertLess(
                    self.text.index(label), first_write,
                    f"{label} must be checked before agents are written",
                )
        self.assertIn("docs/upgrade.md", self.text)
        block = self.text.split("legacy_label", 1)[1]
        self.assertIn("die", block, "a legacy label must abort the install")

    def test_uninstaller_still_covers_the_whole_lineage(self):
        # The documented migration path (uninstall, then install) only works
        # if uninstall.sh boots out every spelling the refusal can name.
        body = UNINSTALL.read_text()
        for label in PANEL_LINEAGE:
            self.assertIn(label, body)
        # ...and clears the watchdog's per-port counters, so a reinstall does
        # not inherit a stale miss count into its first three ticks.
        self.assertIn("serverhub-watchdog.*.state", body)


class UpgradeDocument(unittest.TestCase):
    """docs/upgrade.md must describe the procedure the scripts implement."""

    def setUp(self):
        self.assertTrue(UPGRADE_DOC.is_file(), "docs/upgrade.md is missing")
        self.body = UPGRADE_DOC.read_text()

    def test_names_every_panel_label(self):
        for label in PANEL_LINEAGE:
            self.assertIn(label, self.body)

    def test_covers_upgrade_and_rollback_mechanics(self):
        for needle in (
            "git pull",
            "install.sh",
            "pip install -r requirements.txt",
            "kickstart",
            "git reset --hard",
            "services.yaml.bak.",
            "configs_*.tgz",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.body)

    def test_readme_links_to_it(self):
        self.assertIn(
            "docs/upgrade.md", (BASE / "README.md").read_text(),
            "the upgrade doc must be discoverable from the README",
        )

    def test_watchdog_claim_matches_reality(self):
        # The doc says the watchdog needs no reload because the script is
        # re-read every tick; that is only true while the plist invokes the
        # script from the checkout (rather than a copied snapshot).
        self.assertIn("panel-watchdog.sh", self.body)
        plist = (BASE / "deploy" / "local.serverhub.watchdog.plist").read_text()
        self.assertIn("__WATCHDOG__", plist)
        self.assertRegex(
            (BASE / "install.sh").read_text(),
            re.compile(r"__WATCHDOG__.*panel-watchdog\.sh", re.S),
            "install.sh must point the watchdog plist at the repo script",
        )


if __name__ == "__main__":
    unittest.main()
