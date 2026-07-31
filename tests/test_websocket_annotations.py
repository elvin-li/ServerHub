"""Guards for the bug class that broke both WebSocket endpoints.

``from __future__ import annotations`` makes type annotations lazy strings, so a
handler annotated with a name that was never imported still parses, still
imports, and still passes ``compileall``.  The failure only surfaces when
something resolves the annotation — which FastAPI does when the route is
registered, and which happens on the very first connection.

Both endpoints shipped broken this way: ``terminal_pty`` used four names from
``hub.auth`` without importing them, and ``vm_console`` annotated its handler
with ``WebSocket`` without importing it.  Syntax checks caught neither.

Each test below fails against the pre-fix source.
"""
from __future__ import annotations

import ast
import builtins
import typing
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent


def _require_pyflakes():
    """Return the pyflakes api module, or skip: it is a dev-only dependency."""
    try:
        from pyflakes import api as pyflakes_api
    except ImportError:  # pragma: no cover - depends on the environment
        raise unittest.SkipTest(
            "pyflakes is not installed - run: "
            "pip install -r requirements-dev.txt"
        )
    return pyflakes_api


def _pyflakes_messages(path: Path, needles: tuple[str, ...]) -> list[str]:
    """pyflakes messages for *path* whose text contains any of *needles*."""
    pyflakes_api = _require_pyflakes()

    class _Collect:
        def __init__(self) -> None:
            self.messages: list[str] = []

        def unexpectedError(self, filename, msg):  # noqa: N802 - pyflakes API
            self.messages.append(f"{filename}: {msg}")

        def syntaxError(self, filename, msg, lineno, _offset, text):  # noqa: N802
            self.messages.append(f"{filename}:{lineno}: {msg}")

        def flake(self, message):
            self.messages.append(str(message))

    collector = _Collect()
    pyflakes_api.checkPath(str(path), collector)
    return [m for m in collector.messages if any(n in m for n in needles)]


def _pyflakes_undefined(path: Path) -> list[str]:
    """Undefined names reported by pyflakes for *path*."""
    return _pyflakes_messages(path, ("undefined name",))


class TestNoUndefinedNames(unittest.TestCase):
    """The direct guard: pyflakes over the whole package."""

    def test_hub_package_has_no_undefined_names(self):
        offenders: list[str] = []
        for path in sorted((BASE / "hub").rglob("*.py")):
            offenders.extend(_pyflakes_undefined(path))
        self.assertEqual(
            offenders,
            [],
            "\nA name is read but never bound.  With lazy annotations this "
            "passes import and compileall, then fails at route registration "
            "or first request:\n  " + "\n  ".join(offenders),
        )


class TestAnnotationsResolve(unittest.TestCase):
    """Annotations must resolve, because FastAPI resolves them to build routes."""

    def test_terminal_websocket_annotations_resolve(self):
        from hub import terminal_pty

        hints = typing.get_type_hints(terminal_pty.terminal_websocket)
        self.assertIn("websocket", hints)

    def test_console_websocket_annotations_resolve(self):
        from hub import vm_console

        hints = typing.get_type_hints(vm_console.console_websocket)
        self.assertIn("websocket", hints)
        self.assertIn("console_id", hints)


class TestHandlerBodiesHaveTheirNames(unittest.TestCase):
    """Every global name a handler reads must be bound in its module.

    ``terminal_pty`` failed here specifically: the body called
    ``verify_session`` / ``COOKIE_NAME`` / ``setup_required`` /
    ``session_username`` while importing none of them, so the handler raised
    ``NameError`` on its first line for every connection.
    """

    def _unbound_globals(self, module_path: Path, func_name: str) -> list[str]:
        tree = ast.parse(module_path.read_text())
        bound: set[str] = set(dir(builtins))
        target = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    bound.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bound.add(node.name)
                if node.name == func_name:
                    target = node
            elif isinstance(node, ast.ClassDef):
                bound.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        bound.add(t.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                bound.add(node.target.id)
        self.assertIsNotNone(target, f"{func_name} not found in {module_path.name}")

        local: set[str] = set()
        for node in ast.walk(target):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                local.add(node.id)
            elif isinstance(node, ast.arg):
                local.add(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local.add(node.name)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                local.add(node.name)

        missing = sorted(
            n.id
            for n in ast.walk(target)
            if isinstance(n, ast.Name)
            and isinstance(n.ctx, ast.Load)
            and n.id not in bound
            and n.id not in local
        )
        return missing

    def test_terminal_websocket_body_names_are_bound(self):
        missing = self._unbound_globals(
            BASE / "hub" / "terminal_pty.py", "terminal_websocket"
        )
        self.assertEqual(missing, [], f"unbound in terminal_websocket: {missing}")

    def test_console_websocket_body_names_are_bound(self):
        missing = self._unbound_globals(
            BASE / "hub" / "vm_console.py", "console_websocket"
        )
        self.assertEqual(missing, [], f"unbound in console_websocket: {missing}")


class TestRoutesRegister(unittest.TestCase):
    """Route registration is where a bad annotation actually explodes."""

    def test_both_websocket_routes_are_registered(self):
        from hub.app_factory import create_app

        app = create_app()
        paths = {
            getattr(r, "path", None)
            for r in app.routes
            if type(r).__name__ == "APIWebSocketRoute"
        }
        self.assertIn("/api/terminal/ws", paths)
        self.assertIn("/api/vms/{console_id}/console/ws", paths)




class TestNoDeadCode(unittest.TestCase):
    """hub/ must stay free of unused imports and unused locals.

    Not style policing: an unused import is how a half-finished refactor hides,
    and an unused local is how a computed value gets dropped before it reaches
    the response (the dropped-value class of bug this suite already guards).
    Both were cleaned to zero; this keeps them there.
    """

    def _report(self, categories: tuple[str, ...]) -> list[str]:
        _require_pyflakes()
        from pyflakes import api as pyflakes_api

        found: list[str] = []

        class Collector:
            def unexpectedError(self, filename, msg):  # noqa: N802 - pyflakes API
                found.append(f"{filename}: {msg}")

            def syntaxError(self, filename, msg, lineno, _offset, text):  # noqa: N802
                found.append(f"{filename}:{lineno}: {msg}")

            def flake(self, message):
                text = str(message)
                if any(c in text for c in categories):
                    found.append(text)

        for path in sorted((BASE / "hub").rglob("*.py")):
            pyflakes_api.checkPath(str(path), Collector())
        return found

    def test_no_unused_imports(self):
        offenders = self._report(("imported but unused",))
        self.assertEqual(
            offenders,
            [],
            "\nUnused imports in hub/ — delete them, or wire up the code that "
            "was meant to use them:\n  " + "\n  ".join(offenders),
        )

    def test_no_unused_locals(self):
        offenders = self._report(("assigned to but never used",))
        self.assertEqual(
            offenders,
            [],
            "\nA local is computed and then dropped.  Confirm the value is not "
            "supposed to reach the caller before deleting the assignment:\n  "
            + "\n  ".join(offenders),
        )

    def test_no_shadowed_definitions(self):
        offenders = self._report(("redefinition of unused",))
        self.assertEqual(
            offenders,
            [],
            "\nA second definition shadows the first.  This silently swapped a "
            "route's request model once already:\n  " + "\n  ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
