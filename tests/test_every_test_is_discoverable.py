"""Every test file must be visible to the command that runs the suite.

The gate is `python -m unittest discover -s tests -p 'test_*.py'`, which collects
only unittest.TestCase subclasses.  A module written pytest-style -- module-level
`def test_*` functions -- is collected as zero tests and reported as a clean pass,
so the assertions inside it never run and nobody notices.

Two modules were in that state: tests/test_adaptive_protocol_probe.py (8 tests
covering a measured 802ms probe regression) and tests/test_native_catalog_brew.py
(3 tests on brew admin-retry detection).  Both had passed silently for as long as
they existed.

pytest is installed in the venv but is not declared in requirements.txt, so the
suite cannot depend on it being there.  This keeps the two styles from diverging
again by failing loudly instead.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

TESTS = BASE / "tests"


def _module_files() -> list[Path]:
    return sorted(p for p in TESTS.glob("test_*.py") if p.name != Path(__file__).name)


def _top_level_test_functions(tree: ast.Module) -> list[str]:
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    ]


def _testcase_classes(tree: ast.Module) -> set[str]:
    """Names of classes unittest will collect, following local base classes.

    Resolution has to be transitive.  Several modules define an intermediate base
    (`PoolTestBase(unittest.TestCase)`) and put the real tests in subclasses of it;
    matching only a direct `unittest.TestCase` base reported those modules as
    empty when they contribute 18 and 17 tests.
    """
    classes = {
        node.name: [ast.unparse(base) for base in node.bases]
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }
    collected = {
        name for name, bases in classes.items() if any("TestCase" in b for b in bases)
    }
    changed = True
    while changed:
        changed = False
        for name, bases in classes.items():
            if name in collected:
                continue
            if any(base in collected for base in bases):
                collected.add(name)
                changed = True
    return collected


class DiscoverabilityTests(unittest.TestCase):
    def setUp(self):
        self.modules = _module_files()

    def test_the_scan_sees_the_test_suite(self):
        # Guards this file: an empty list would make every assertion below vacuous.
        self.assertGreater(len(self.modules), 40, "the test-file scan found almost nothing")

    def test_no_module_hides_its_tests_in_module_level_functions(self):
        offenders = []
        for path in self.modules:
            tree = ast.parse(path.read_text())
            loose = _top_level_test_functions(tree)
            if loose and not _testcase_classes(tree):
                offenders.append(
                    f"{path.relative_to(BASE)}: {len(loose)} test function(s) "
                    f"({', '.join(loose[:3])}{'...' if len(loose) > 3 else ''})"
                )
        self.assertEqual(
            offenders,
            [],
            "these modules are collected as ZERO tests by `unittest discover`, so "
            "they pass without running anything. Wrap them in a unittest.TestCase:\n"
            + "\n".join(offenders),
        )

    def test_every_module_contributes_at_least_one_test(self):
        """A module with no runnable test is dead weight that looks like coverage."""
        empty = []
        for path in self.modules:
            tree = ast.parse(path.read_text())
            classes = _testcase_classes(tree)
            has_method = any(
                isinstance(node, ast.ClassDef)
                and node.name in classes
                and any(
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name.startswith("test")
                    for child in node.body
                )
                for node in ast.walk(tree)
            )
            if not has_method:
                empty.append(str(path.relative_to(BASE)))
        self.assertEqual(
            empty,
            [],
            "these modules define no runnable test method:\n" + "\n".join(empty),
        )

    def test_the_detector_catches_the_shape_it_exists_for(self):
        """Otherwise this file is decoration.

        The first case is what tests/test_native_catalog_brew.py looked like while
        its three assertions silently never ran.  The second is the intermediate
        base class that an earlier version of this detector wrongly reported as
        empty, so both directions are pinned.
        """
        pytest_style = ast.parse(
            "def test_one():\n    assert True\n\n\ndef test_two():\n    assert True\n"
        )
        self.assertEqual(_top_level_test_functions(pytest_style), ["test_one", "test_two"])
        self.assertEqual(_testcase_classes(pytest_style), set())

        indirect_base = ast.parse(
            "import unittest\n"
            "class Base(unittest.TestCase):\n"
            "    def setUp(self):\n        pass\n"
            "class Real(Base):\n"
            "    def test_thing(self):\n        pass\n"
        )
        self.assertEqual(_testcase_classes(indirect_base), {"Base", "Real"})
        self.assertEqual(_top_level_test_functions(indirect_base), [])

    def test_pytest_only_features_are_not_relied_on(self):
        """`tmp_path` and friends are injected by pytest and are absent here.

        A unittest run passes such a parameter nothing, so the test errors out --
        or, if the module is pytest-style, is skipped entirely.
        """
        offenders = []
        for path in self.modules:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not node.name.startswith("test"):
                    continue
                args = [a.arg for a in node.args.args if a.arg != "self"]
                fixtures = [
                    a for a in args
                    if a in {"tmp_path", "tmpdir", "capsys", "monkeypatch", "request"}
                ]
                if fixtures:
                    offenders.append(
                        f"{path.relative_to(BASE)}::{node.name} takes {fixtures}"
                    )
        self.assertEqual(
            offenders,
            [],
            "these tests expect pytest fixtures, which `unittest discover` cannot "
            "provide:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
