"""`if not p.exists(): write(p)` is a data-loss shape and must not come back.

It reads the filesystem, then writes based on that reading. When the reading is
wrong the write is destructive, and there is no way back. Four instances existed:

* ``config._bootstrap`` -- reset a populated 11 KB services.yaml to 407 bytes of
  defaults, taking the admin account, two apps, three stacks and twelve
  bookmarks. It fired on every run of the test suite, because an unrelated test
  patched ``pathlib.Path.exists`` process-wide.
* ``audit.record`` -- truncated the sign-in/failure audit trail to empty before
  appending one line to it.
* ``catalog`` template files and the Home Assistant update script -- would have
  overwritten files an operator had edited by hand.

The safe form asks the kernel to decide existence and content in one step:
``open(path, "x")``, or ``secure_io.create_secret_text`` for anything holding
secrets. A wrong guess is then a no-op instead of a truncation.

This flags the shape only when the write targets the same path the check tested,
which is what makes it dangerous rather than merely conditional.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

HUB = BASE / "hub"

#: Calls that replace a file's contents.
DESTRUCTIVE = {
    "write_text",
    "write_bytes",
    "write_secret_text",
    "replace_secret_text",
    "save_full",
    "_save_state",
    "_save_full_locked",
}


def _exists_target(test: ast.expr) -> str | None:
    """The path expression in `not <path>.exists()`, or None."""
    if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
        return None
    call = test.operand
    if not isinstance(call, ast.Call) or call.args:
        return None
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in ("exists", "is_file"):
        return None
    return ast.unparse(func.value)


def _destructive_writes(body: list[ast.stmt]) -> list[tuple[str, str, int]]:
    """(callee, target path expression, lineno) for destructive writes in *body*."""
    out = []
    for stmt in body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in DESTRUCTIVE:
                # p.write_text(...) -> target is p; mod.write_secret_text(p, ...)
                # -> target is the first argument.
                target = (
                    ast.unparse(node.args[0])
                    if node.args and func.attr.endswith("secret_text")
                    else ast.unparse(func.value)
                )
                out.append((func.attr, target, node.lineno))
            elif isinstance(func, ast.Name) and func.id in DESTRUCTIVE:
                target = ast.unparse(node.args[0]) if node.args else ""
                out.append((func.id, target, node.lineno))
            elif (
                isinstance(func, ast.Attribute)
                and func.attr == "open"
                and any(
                    isinstance(a, ast.Constant) and a.value in ("w", "wb", "w+")
                    for a in node.args
                )
            ):
                out.append(("open(w)", ast.unparse(func.value), node.lineno))
    return out


def _offenders(tree: ast.Module, module: str) -> list[str]:
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        target = _exists_target(node.test)
        if target is None:
            continue
        for callee, written, lineno in _destructive_writes(node.body):
            if written == target:
                found.append(f"{module}:{lineno}  if not {target}.exists(): {callee}(...)")
    return found


class NoCheckThenWriteTests(unittest.TestCase):
    def setUp(self):
        self.sources = [
            p for p in HUB.rglob("*.py") if "__pycache__" not in str(p)
        ]

    def test_the_scan_sees_the_package(self):
        # Guards this file: an empty list makes the assertion below vacuous.
        self.assertGreater(len(self.sources), 30, "the hub/ scan found almost nothing")

    def test_no_module_writes_a_file_it_just_checked_for(self):
        offenders: list[str] = []
        for path in self.sources:
            tree = ast.parse(path.read_text())
            offenders += _offenders(tree, path.relative_to(BASE).as_posix())
        self.assertEqual(
            offenders,
            [],
            "these sites truncate a file when exists() answers wrongly. Use "
            'open(path, "x") or secure_io.create_secret_text so the kernel decides:\n'
            + "\n".join(offenders),
        )

    def test_the_detector_catches_the_shapes_it_exists_for(self):
        """Otherwise this file is decoration.

        The first two are the code that actually destroyed data; the third is the
        corrected form and must not be flagged.
        """
        bootstrap = ast.parse(
            "def f():\n"
            "    if not YAML_PATH.exists():\n"
            "        secure_io.write_secret_text(YAML_PATH, body)\n"
        )
        self.assertEqual(len(_offenders(bootstrap, "m")), 1)

        audit_shape = ast.parse(
            "def f():\n"
            "    if not AUDIT_PATH.exists():\n"
            "        secure_io.write_secret_text(AUDIT_PATH, '')\n"
        )
        self.assertEqual(len(_offenders(audit_shape, "m")), 1)

        plain = ast.parse(
            "def f():\n"
            "    if not fp.exists():\n"
            "        fp.write_text(content)\n"
        )
        self.assertEqual(len(_offenders(plain, "m")), 1)

        corrected = ast.parse(
            "def f():\n"
            "    secure_io.create_secret_text(AUDIT_PATH, '')\n"
            "    with fp.open('x') as fh:\n"
            "        fh.write(content)\n"
        )
        self.assertEqual(_offenders(corrected, "m"), [])

    def test_a_write_to_a_different_path_is_not_flagged(self):
        """Only the same-path shape is the dangerous one; keep the noise out."""
        unrelated = ast.parse(
            "def f():\n"
            "    if not marker.exists():\n"
            "        logfile.write_text('started')\n"
        )
        self.assertEqual(_offenders(unrelated, "m"), [])


if __name__ == "__main__":
    unittest.main()
