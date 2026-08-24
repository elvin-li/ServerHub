"""A test that exercises an installer must seal the executor first.

`native_catalog.install_native` and `uninstall_native` shell out to Homebrew.
Called with only the cache helpers mocked, they reach the host's real Homebrew:
an earlier version of tests/test_app_store_invalidates_inventory.py did exactly
that, spawning `brew services stop` and `brew uninstall` against this machine and
taking 16 seconds to do it.  Nothing was lost because the app in question was not
installed, which is luck rather than design.

An instrumented run of the whole suite (wrapping subprocess.Popen) confirms the
current state: 203 spawns, all reads -- `launchctl print`, `brew list`,
`brew services list --json`, `diskutil info`, `ifconfig -a`, `nginx -t`, plus
synthetic sleep/echo processes for the job-control tests and build_app.sh writing
into temp directories.  No `brew install`, no `brew uninstall`, no launchctl
load/bootout, no osascript.  This keeps it that way for the installer entry
points, which are the ones that can remove software.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

TESTS = BASE / "tests"

#: Service functions that shell out and can change what is installed or running.
DANGEROUS = {
    "install_native",
    "uninstall_native",
    "install_stack",
    "uninstall_stack",
}

#: Names whose patching seals the execution boundary these functions go through.
EXECUTOR_SEALS = {"sh", "run", "Popen", "check_output", "run_admin", "subprocess"}


def _referenced_names(tree: ast.Module) -> set[str]:
    return {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Name))
    }


def _patched_names(tree: ast.Module) -> set[str]:
    """Every name handed to mock.patch/patch.object anywhere in the module."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        label = ast.unparse(node.func)
        if "patch" not in label:
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.update(arg.value.split("."))
        for kw in node.keywords:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                out.update(str(kw.value.value).split("."))
        # patch.object(mod, "name") -> the string argument is covered above
    return out


class HostMutationTests(unittest.TestCase):
    def setUp(self):
        self.modules = [
            p for p in TESTS.glob("test_*.py") if p.name != Path(__file__).name
        ]

    def test_the_scan_sees_the_suite(self):
        self.assertGreater(len(self.modules), 40, "the test-file scan found almost nothing")

    def test_installer_tests_seal_the_execution_boundary(self):
        offenders = []
        for path in self.modules:
            tree = ast.parse(path.read_text())
            used = _referenced_names(tree) & DANGEROUS
            if not used:
                continue
            if not (_patched_names(tree) & EXECUTOR_SEALS):
                offenders.append(
                    f"{path.relative_to(BASE)}: calls {sorted(used)} without "
                    "patching an executor"
                )
        self.assertEqual(
            offenders,
            [],
            "these tests can run real installers against this machine. Patch the "
            "module's `sh` and `subprocess.run` before calling them:\n"
            + "\n".join(offenders),
        )

    def test_mutable_state_is_redirected_out_of_the_checkout(self):
        """tests/__init__.py must win the race with the first ``hub`` import.

        hub.paths freezes STATE_ROOT / DATA_DIR / CONFIG_FILE at import time.
        Without the package-level SERVERHUB_STATE_DIR redirection a full run
        bootstraps services.yaml in the repo root and fills data/ with alert
        state, metrics journals, services.yaml.bak.* and lock files -- host
        mutations that .gitignore keeps invisible to `git status --porcelain`.
        """
        from hub import paths

        for name in ("STATE_ROOT", "DATA_DIR", "CONFIG_FILE"):
            value = Path(getattr(paths, name))
            self.assertFalse(
                value == BASE or BASE in value.parents,
                f"hub.paths.{name} ({value}) resolved inside the checkout "
                f"({BASE}); the suite would write panel state into the "
                "working tree. tests/__init__.py sets SERVERHUB_STATE_DIR "
                "before hub is imported, but it only runs when discovery "
                "imports the tests *package*: run "
                "`python -m unittest discover -s tests -t . -q` (note -t .).",
            )

    def test_the_detector_catches_the_shape_it_exists_for(self):
        """The first block is the version that spawned real brew commands."""
        unsealed = ast.parse(
            "from hub import native_catalog\n"
            "from unittest import mock\n"
            "def test_x():\n"
            "    with mock.patch.object(native_catalog, 'invalidate_brew_services'):\n"
            "        native_catalog.uninstall_native('native-syncthing')\n"
        )
        self.assertEqual(_referenced_names(unsealed) & DANGEROUS, {"uninstall_native"})
        self.assertEqual(_patched_names(unsealed) & EXECUTOR_SEALS, set())

        sealed = ast.parse(
            "from hub import native_catalog\n"
            "from unittest import mock\n"
            "def test_x():\n"
            "    with mock.patch.object(native_catalog, 'sh', return_value=(0, '', '')):\n"
            "        native_catalog.uninstall_native('native-syncthing')\n"
        )
        self.assertIn("sh", _patched_names(sealed))


if __name__ == "__main__":
    unittest.main()
