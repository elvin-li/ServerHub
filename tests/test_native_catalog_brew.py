"""Brew install plumbing: when to retry with admin rights, and how to quote.

Written as unittest.TestCase rather than bare pytest-style functions because the
project's gate is `python -m unittest discover`, which cannot collect module-level
test functions.  These three assertions existed but had never run in the gate.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.native_catalog import _brew_refuses_root, _needs_admin_retry  # noqa: E402


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


class BrewRootRefusalTests(unittest.TestCase):
    """Homebrew will not run as root, so elevating brew itself cannot help.

    The panel used to retry a failed cask install by re-running the whole brew
    command through `osascript ... with administrator privileges`.  Homebrew
    exempts only `services`, `--prefix`, `setup-sandbox` and `as-console-user`
    from its root check, so that retry always died -- after popping a password
    dialog on the Mac's own display and waiting up to 900 seconds for it.
    """

    def test_the_root_refusal_is_recognised(self):
        msg = (
            "Error: Running Homebrew as root is extremely dangerous and no longer "
            "supported.\nAs Homebrew does not drop privileges on installation you "
            "would be giving all build scripts full access to your system."
        )
        self.assertTrue(_brew_refuses_root(msg))

    def test_an_ordinary_failure_is_not_mistaken_for_it(self):
        self.assertFalse(_brew_refuses_root("Error: No available formula with the name"))
        self.assertFalse(_brew_refuses_root(""))

    def test_no_code_path_elevates_brew_itself(self):
        """Pinned in the source: nothing may run brew with administrator rights.

        Checked over string literals via the AST, with docstrings excluded: the
        reason this rule exists is written down in _run_brew's docstring, and a
        plain text search would make the explanation trip the assertion it
        explains.
        """
        tree = ast.parse((BASE / "hub" / "native_catalog.py").read_text())
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        offenders = [
            f"line {node.lineno}: {node.value.strip()[:60]}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "with administrator privileges" in node.value
            and id(node) not in docstrings
        ]
        self.assertEqual(
            offenders,
            [],
            "brew cannot run as root; elevating it wastes the operator's password "
            "and fails with Homebrew's root warning:\n" + "\n".join(offenders),
        )

        # Prove the check is not vacuous: the removed call must still be caught,
        # while a docstring explaining it must not be.
        reintroduced = ast.parse(
            'def f():\n'
            '    """Explains `with administrator privileges` and why we avoid it."""\n'
            '    script = "do shell script X with administrator privileges"\n'
            "    return script\n"
        )
        docs = {
            id(n.body[0].value)
            for n in ast.walk(reintroduced)
            if isinstance(n, (ast.Module, ast.FunctionDef))
            and n.body
            and isinstance(n.body[0], ast.Expr)
            and isinstance(n.body[0].value, ast.Constant)
        }
        caught = [
            n.value
            for n in ast.walk(reintroduced)
            if isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and "with administrator privileges" in n.value
            and id(n) not in docs
        ]
        self.assertEqual(len(caught), 1, "the detector stopped detecting the call")


if __name__ == "__main__":
    unittest.main()
