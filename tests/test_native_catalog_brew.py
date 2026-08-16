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


class BrewSudoPrimeTests(unittest.TestCase):
    """Pkg cask installs retry brew after priming a sudo ticket from the web password."""

    def test_retries_brew_when_admin_password_primes_sudo(self):
        from hub import native_catalog
        from hub.macos_admin import use_admin_password
        from unittest import mock

        calls: list[list] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            if len(calls) == 1:
                return {
                    "ok": False,
                    "rc": 1,
                    "message": "sudo: a password is required",
                }
            return {"ok": True, "rc": 0, "message": "installed"}

        with (
            mock.patch.object(native_catalog, "_run", side_effect=fake_run),
            mock.patch("hub.macos_admin.prime_sudo_ticket", return_value={"ok": True}),
            use_admin_password("secret"),
        ):
            result = native_catalog._run_brew(["install", "--cask", "tailscale-app"])
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 2)


class NativeRedisBrewSkip(unittest.TestCase):
    """Install/start must not spawn Homebrew Redis when :6379 is Immich Valkey."""

    def test_helper_reports_the_probed_port(self):
        from hub import native_catalog
        from unittest import mock

        with mock.patch("hub.util.port_open", return_value=True) as poked:
            self.assertTrue(native_catalog.redis_port_already_served())
        poked.assert_called_once_with(native_catalog.REDIS_PORT, host="127.0.0.1")
        with mock.patch("hub.util.port_open", return_value=False):
            self.assertFalse(native_catalog.redis_port_already_served())

    def test_install_skips_brew_services_start_when_the_port_is_open(self):
        from hub import native_catalog
        from unittest import mock

        ran: list[list] = []

        def fake_run(argv, **kwargs):
            ran.append(list(argv))
            return {"ok": True, "message": "started", "rc": 0}

        app = next(a for a in native_catalog.NATIVE_APPS if a["id"] == "native-redis")
        with (
            mock.patch.object(native_catalog, "_is_installed", return_value=True),
            mock.patch.object(native_catalog, "redis_port_already_served", return_value=True),
            mock.patch.object(native_catalog, "_run", side_effect=fake_run),
            mock.patch.object(native_catalog, "_run_brew", side_effect=fake_run),
        ):
            result = native_catalog._install_native(app, "native-redis")
        self.assertTrue(result["ok"])
        self.assertIn("already served", result["message"])
        self.assertFalse(any("services" in cmd and "start" in cmd for cmd in ran))

    def test_apps_start_skips_a_second_daemon_when_the_port_is_open(self):
        from hub import apps_manage_svc, native_catalog
        from unittest import mock

        with (
            mock.patch.object(native_catalog, "redis_port_already_served", return_value=True),
            mock.patch.object(native_catalog, "_run") as run,
            mock.patch.object(apps_manage_svc, "invalidate_inventory"),
        ):
            result = apps_manage_svc.action("native-redis", "start")
        self.assertTrue(result["ok"])
        self.assertIn("already serving", result["message"])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
