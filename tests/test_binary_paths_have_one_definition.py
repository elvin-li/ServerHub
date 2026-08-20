"""A tool's path must be resolved in one place, or the copies drift.

`hub.paths` resolves each external binary once, trying `which` before the two
standard Homebrew prefixes, so a tool installed in a custom prefix is still
found.  Three modules carried their own copy of the BREW fallback that knew only
/opt/homebrew and /usr/local: on such a host the app store, the autostart page
and the brew page would each report "brew missing" while every page using
hub.paths.BREW worked, which is a confusing way to be broken.

A sharper instance was live in hub/health_svc.py, which called
"/opt/homebrew/bin/smartctl" directly.  After the sudoers policy moved to the
root-owned copy under /usr/local/libexec/serverhub, that literal matched no rule,
so the health card's SMART probe asked for a password no web request can answer
and simply went blank.  Nothing raised.

So: whatever hub.paths defines, other modules import.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import paths as hub_paths  # noqa: E402

HUB = BASE / "hub"

#: Constants hub.paths owns.  A module-level assignment to any of these elsewhere
#: is a second definition that can disagree with the first.
OWNED = {
    name
    for name in dir(hub_paths)
    if name.isupper() and isinstance(getattr(hub_paths, name), str)
}

#: Literal binary paths that must never be written inline: each has a constant,
#: and the constant may resolve somewhere else on a given host.
LITERALS = {
    "/opt/homebrew/bin/brew": "hub.paths.BREW",
    "/opt/homebrew/bin/smartctl": "hub.paths.SMARTCTL",
    "/usr/local/bin/docker": "hub.paths.DOCKER",
}

#: hub.paths defines them; hub.sudoers_policy states the policy contract
#: independently on purpose, so that the two can be cross-checked.
EXEMPT = {"paths.py", "sudoers_policy.py"}


def _module_files() -> list[Path]:
    return sorted(
        p for p in HUB.rglob("*.py")
        if "__pycache__" not in str(p) and p.name not in EXEMPT
    )


def _imported_names(tree: ast.Module) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("hub"):
            out.update(alias.asname or alias.name for alias in node.names)
    return out


def _module_level_string_assignments(tree: ast.Module) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.isupper():
                out[target.id] = node.value
    return out


class OneDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.modules = _module_files()

    def test_the_scan_sees_the_package(self):
        self.assertGreater(len(self.modules), 30, "the hub/ scan found almost nothing")
        self.assertIn("BREW", OWNED, "hub.paths no longer defines BREW")
        self.assertIn("SMARTCTL", OWNED, "hub.paths no longer defines SMARTCTL")

    def test_no_module_redefines_a_path_constant(self):
        offenders = []
        for path in self.modules:
            tree = ast.parse(path.read_text())
            imported = _imported_names(tree)
            for name, value in _module_level_string_assignments(tree).items():
                if name not in OWNED or name in imported:
                    continue
                offenders.append(
                    f"{path.relative_to(BASE)}: {name} = {ast.unparse(value)[:50]} "
                    f"(hub.paths already defines {name})"
                )
        self.assertEqual(
            offenders,
            [],
            "these are second definitions that can disagree with hub.paths. "
            "Import instead:\n" + "\n".join(offenders),
        )

    def test_no_module_writes_a_managed_binary_path_inline(self):
        offenders = []
        for path in self.modules:
            source = path.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                use = LITERALS.get(node.value)
                if use:
                    offenders.append(
                        f"{path.relative_to(BASE)}:{node.lineno}: "
                        f"{node.value!r} -- use {use}"
                    )
        self.assertEqual(
            offenders,
            [],
            "an inline path bypasses the resolver, so it can name a binary that "
            "is not there (or, for a sudo call, one that no rule grants):\n"
            + "\n".join(offenders),
        )

    def test_the_resolver_agrees_with_itself_everywhere(self):
        """Belt and braces: the imported value really is the same object."""
        from hub import autostart_svc, brew_svc, native_catalog

        for module in (autostart_svc, brew_svc, native_catalog):
            with self.subTest(module=module.__name__):
                self.assertEqual(
                    module.BREW,
                    hub_paths.BREW,
                    f"{module.__name__}.BREW disagrees with hub.paths.BREW",
                )

    def test_the_detector_catches_the_shapes_it_exists_for(self):
        """Otherwise this file is decoration."""
        redefined = ast.parse('BREW = "/opt/homebrew/bin/brew"\n')
        self.assertIn("BREW", _module_level_string_assignments(redefined))
        self.assertEqual(_imported_names(redefined), set())

        imported = ast.parse("from hub.paths import BREW\n")
        self.assertIn("BREW", _imported_names(imported))
        self.assertEqual(_module_level_string_assignments(imported), {})


def _is_path_home_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "home":
        return False
    value = node.func.value
    if isinstance(value, ast.Name) and value.id == "Path":
        return True
    return (
        isinstance(value, ast.Attribute)
        and value.attr == "Path"
        and isinstance(value.value, ast.Name)
        and value.value.id == "pathlib"
    )


class ImportTimeHomeTests(unittest.TestCase):
    def test_no_hub_module_calls_path_home_at_import(self):
        """``Path.home()`` at import RuntimeError/ValueError 500s every importer."""
        offenders = []
        for path in sorted(HUB.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text())
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for child in ast.walk(node):
                    if _is_path_home_call(child):
                        offenders.append(f"{path.relative_to(BASE)}:{child.lineno}")
        self.assertEqual(
            offenders,
            [],
            "import-time Path.home() 500s the module; use user_home():\n"
            + "\n".join(offenders),
        )

    def test_the_detector_catches_module_level_path_home(self):
        tree = ast.parse('ROOT = Path.home() / "Services"\n')
        calls = [n for n in ast.walk(tree) if _is_path_home_call(n)]
        self.assertEqual(len(calls), 1)
        safe = ast.parse(
            "def user_home():\n"
            "    return Path.home()\n"
        )
        for node in safe.body:
            if isinstance(node, ast.FunctionDef):
                continue
            self.assertFalse(any(_is_path_home_call(n) for n in ast.walk(node)))


if __name__ == "__main__":
    unittest.main()
