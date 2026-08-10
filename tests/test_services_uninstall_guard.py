"""Guard tests for LaunchAgent uninstall.

The uninstall path is the one place the panel can remove its own supervision, so
the refusals matter more than the happy path:

  * ServerHub's own agents (panel, menu bar, tunnel) must never be booted out --
    doing so kills the process serving the request with no supervised way back.
  * The guard is a *filesystem*-backed decision.  ``~/Library/LaunchAgents`` sits
    on a case-insensitive APFS volume by default, so ``Local.Serverhub.Panel``
    opens the very same file as ``local.serverhub.panel``.  A case-sensitive
    membership test therefore let a differently-cased spelling walk straight past
    the protected list and archive the real plist, uninstalling the panel.
  * Nothing outside the agents directory may be reached, whatever the label.
"""
from __future__ import annotations

import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import HTTPException

from hub import services_uninstall_svc as svc


def write_agent(agents: Path, label: str, program: str = "/usr/bin/true") -> Path:
    """Create a minimal, valid LaunchAgent plist for *label*."""
    path = agents / f"{label}.plist"
    path.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": [program],
    }))
    return path


class ProtectedLabelTests(unittest.TestCase):
    """Every casing of a protected label must be refused."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = Path(self.tmp.name) / "LaunchAgents"
        self.agents.mkdir(parents=True)
        self.backups = Path(self.tmp.name) / "uninstalled-agents"
        self.addCleanup(self.tmp.cleanup)

        for patched in (
            patch.object(svc, "AGENTS_DIR", self.agents),
            patch.object(svc, "BACKUP_DIR", self.backups),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def assert_protected(self, label: str):
        with self.assertRaises(HTTPException) as caught:
            svc.preview(label)
        detail = caught.exception.detail
        code = detail.get("code") if isinstance(detail, dict) else detail
        self.assertEqual(code, "services.uninstall_protected", f"label={label!r}")

    def test_exact_protected_labels_are_refused(self):
        for label in sorted(svc.PROTECTED_LABELS):
            self.assert_protected(label)

    def test_differently_cased_protected_labels_are_refused(self):
        # These are the spellings that resolve to the same file on a
        # case-insensitive volume.  Before the fix each of them passed the
        # membership test and reached shutil.move on the real plist.
        for label in (
            "Local.Serverhub.Panel",
            "LOCAL.SERVERHUB.PANEL",
            "local.ServerHub.panel",
            "Local.Serverhub.Menubar",
            "LOCAL.CLOUDFLARED-TUNNEL",
            "Local.Cloudflared-Tunnel",
        ):
            self.assert_protected(label)

    def test_every_installer_label_spelling_is_protected(self):
        """The panel job has shipped under three naming schemes.

        ``install.sh`` writes the dotted labels, ``ServerHubLauncher.swift``
        writes the hyphenated ones, and distribution builds use a ``com.elvin``
        prefix.  Each spelling supervises the same panel process, so protecting
        only one scheme would let the panel unload itself on the other two.
        """
        for label in (
            "local.serverhub.panel",
            "local.serverhub",
            "local.serverhub-launcher",
            "local.serverhub-menubar",
            "com.elvin.serverhub",
            "com.elvin.serverhub-launcher",
            "com.elvin.serverhub-menubar",
        ):
            self.assert_protected(label)

    def test_native_and_distribution_plists_survive_uninstall(self):
        """End-to-end: the on-disk plist of a live install is never archived."""
        for label in ("local.serverhub", "com.elvin.serverhub"):
            real = write_agent(self.agents, label)
            before = real.read_bytes()

            with patch.object(svc, "sh") as run:
                with self.assertRaises(HTTPException):
                    svc.uninstall(label)
                run.assert_not_called()

            self.assertTrue(real.is_file(), f"{label} plist was archived")
            self.assertEqual(real.read_bytes(), before)

    def test_surrounding_whitespace_does_not_defeat_the_guard(self):
        self.assert_protected("  local.serverhub.panel  ")
        self.assert_protected("\tLocal.Serverhub.Panel\n")

    def test_uninstall_never_touches_a_protected_plist_whatever_the_casing(self):
        """The end-to-end proof: the file survives and launchctl is not called."""
        real = write_agent(self.agents, "local.serverhub.panel")
        before = real.read_bytes()

        with patch.object(svc, "sh") as run:
            for label in ("local.serverhub.panel", "Local.Serverhub.Panel", "LOCAL.SERVERHUB.PANEL"):
                with self.assertRaises(HTTPException):
                    svc.uninstall(label)
            run.assert_not_called()

        self.assertTrue(real.is_file(), "protected plist was archived")
        self.assertEqual(real.read_bytes(), before)
        self.assertFalse(self.backups.exists(), "backup directory was created for a refused label")

    def test_an_unprotected_agent_is_still_uninstallable(self):
        """The guard must not have become a blanket refusal."""
        path = write_agent(self.agents, "com.example.worker")

        with patch.object(svc, "sh", return_value=(0, "", "")) as run:
            result = svc.uninstall("com.example.worker")

        self.assertTrue(result["ok"])
        self.assertTrue(result["booted_out"])
        self.assertFalse(path.is_file(), "plist was not archived")
        self.assertTrue(Path(result["backup"]).is_file())
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["/bin/launchctl", "bootout"])
        self.assertTrue(argv[2].endswith("/com.example.worker"))

    def test_a_label_that_merely_contains_a_protected_name_is_allowed(self):
        """Substring similarity is not protection: only the label itself is."""
        write_agent(self.agents, "local.serverhub.panel.helper")

        with patch.object(svc, "sh", return_value=(0, "", "")):
            result = svc.uninstall("local.serverhub.panel.helper")

        self.assertTrue(result["ok"])
        # The genuinely protected plist name is untouched by the near-miss label.
        self.assertFalse((self.agents / "local.serverhub.panel.plist").exists())


class LabelValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = Path(self.tmp.name) / "LaunchAgents"
        self.agents.mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)
        patched = patch.object(svc, "AGENTS_DIR", self.agents)
        patched.start()
        self.addCleanup(patched.stop)

    def assert_code(self, label, expected):
        with self.assertRaises(HTTPException) as caught:
            svc.preview(label)
        detail = caught.exception.detail
        code = detail.get("code") if isinstance(detail, dict) else detail
        self.assertEqual(code, expected, f"label={label!r}")

    def test_traversal_and_separators_are_refused(self):
        for label in ("../../etc/passwd", "a/b", "sub/dir.agent", "..", "."):
            self.assert_code(label, "services.uninstall_not_supported")

    def test_empty_and_malformed_labels_are_refused(self):
        for label in ("", "   ", None, ".leading-dot", "-leading-dash", "has space", "a" * 129):
            self.assert_code(label, "services.uninstall_not_supported")

    def test_a_wellformed_but_absent_label_reports_unknown(self):
        self.assert_code("com.example.absent", "services.uninstall_unknown")


if __name__ == "__main__":
    unittest.main()
