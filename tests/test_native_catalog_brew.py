"""Brew install plumbing: when to retry with admin rights, and how to quote.

Written as unittest.TestCase rather than bare pytest-style functions because the
project's gate is `python -m unittest discover`, which cannot collect module-level
test functions.  These three assertions existed but had never run in the gate.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.native_catalog import _brew_shell_command, _needs_admin_retry  # noqa: E402


class NeedsAdminRetryTests(unittest.TestCase):
    def test_a_sudo_password_prompt_warrants_the_admin_retry(self):
        msg = (
            "sudo: a password is required\n"
            "Error: Failure while executing; `/usr/bin/sudo"
        )
        self.assertIs(_needs_admin_retry(msg), True)

    def test_a_user_cancellation_does_not(self):
        """Retrying after the operator dismissed the prompt just asks again."""
        self.assertIs(_needs_admin_retry("User canceled."), False)


class BrewShellCommandTests(unittest.TestCase):
    def test_auto_update_is_disabled_and_the_formula_survives_quoting(self):
        cmd = ["/opt/homebrew/bin/brew", "install", "--cask", "tailscale-app"]
        line = _brew_shell_command(cmd)
        self.assertIn("HOMEBREW_NO_AUTO_UPDATE=1", line)
        self.assertIn("tailscale-app", line)


if __name__ == "__main__":
    unittest.main()
