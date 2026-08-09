"""The operator's password does not exist inside a worker thread.

Twenty-three modules now fan their probes out across a ThreadPoolExecutor. That
is safe for the reads they actually parallelise, and
tests/test_concurrent_collectors.py and tests/test_parallel_probes.py already pin
the functional contract -- overlap, result order, failure isolation.

This file pins the one thing none of that covers, because it fails *silently*.

``hub/macos_admin`` holds the web-entered administrator password in a
``ContextVar``, set for exactly one request by ``use_admin_password()``. A
ContextVar is bound to the context of the thread that set it, and
``ThreadPoolExecutor`` workers do not inherit it: ``_admin_password.get()``
returns ``""`` in a worker no matter what the request supplied.

So a ``run_admin()`` call made from inside an executor does not raise and does not
warn. It sees no password, falls back to ``sudo -n``, and when no passwordless
rule matches, answers ``password_required`` -- telling the operator to type a
password they just typed. The panel would look broken in a way that leads
straight away from the cause.

Nothing in the code prevents this today. It holds only because every
parallelised path happens to shell out to ``sudo -n`` directly instead of going
through ``run_admin``, which is a property of the current call sites rather than
of the design. The obvious next parallelisation -- start a SMART test on every
disk at once, apply a Spotlight setting to every volume at once -- reaches for a
mutation, and mutations are exactly the calls that need the password.

Both halves are asserted: the mechanism (a ContextVar really is empty in a
worker) and the rule (nothing submitted to an executor reaches a
password-dependent helper).
"""
from __future__ import annotations

import ast
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import macos_admin  # noqa: E402

#: Helpers whose behaviour depends on the request-scoped password.
PASSWORD_DEPENDENT = frozenset({
    "run_admin",
    "run_admin_sequence",
    "sudo_capture",
    "admin_password_supplied",
})

HUB = BASE / "hub"


class TheMechanismTests(unittest.TestCase):
    """Why the rule below exists, asserted rather than described."""

    def test_the_password_is_visible_on_the_thread_that_set_it(self):
        with macos_admin.use_admin_password("operator-secret"):
            self.assertTrue(macos_admin.admin_password_supplied())

    def test_the_password_is_invisible_inside_an_executor_worker(self):
        with macos_admin.use_admin_password("operator-secret"):
            with ThreadPoolExecutor(max_workers=1) as ex:
                in_worker = ex.submit(macos_admin.admin_password_supplied).result()
        self.assertFalse(
            in_worker,
            "a ContextVar appeared to cross into a worker thread; if that is "
            "genuinely true now, this whole file can be reconsidered",
        )

    def test_the_value_itself_is_empty_in_a_worker_not_merely_falsy(self):
        with macos_admin.use_admin_password("operator-secret"):
            with ThreadPoolExecutor(max_workers=1) as ex:
                value = ex.submit(macos_admin._admin_password.get).result()
        self.assertEqual(value, "")

    def test_a_worker_does_not_leak_a_password_into_the_next_request(self):
        """The failure mode is a missing password, never a borrowed one."""
        with macos_admin.use_admin_password("first-request"):
            with ThreadPoolExecutor(max_workers=1) as ex:
                ex.submit(lambda: None).result()
        with ThreadPoolExecutor(max_workers=1) as ex:
            leaked = ex.submit(macos_admin._admin_password.get).result()
        self.assertEqual(leaked, "")


def _module_functions(tree: ast.Module) -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _called_names(node: ast.AST) -> set[str]:
    """Every plain name called anywhere inside *node*."""
    names: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        target = child.func
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _callable_names(node: ast.AST) -> list[str]:
    """The function name(s) *node* stands for, when used as a callable.

    A bare name or attribute is the callable itself.  A lambda is a wrapper, so
    what matters is what it calls: ``lambda: _launchd_state("com.apple.x")`` puts
    ``_launchd_state`` on the worker, and ``lambda probe: probe()`` puts whatever
    was passed in -- which is why the *items* of a ``fan_out`` are inspected too.
    """
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.Lambda):
        return sorted(_called_names(node.body))
    return []


def _submitted_callables(tree: ast.Module) -> list[str]:
    """Everything this module hands to a worker thread.

    Three shapes reach an executor, and only the first was originally checked:

    * ``ex.submit(fn)`` / ``ex.map(fn, items)`` -- the callable is the first
      argument.
    * ``fan_out(fn, items)`` -- same, one level of indirection removed.  The
      ``ex.map`` itself lives in ``hub/util.py`` where the probe is a parameter and
      therefore unresolvable, so scanning only for ``.map(...)`` saw *none* of the
      twenty-odd ``fan_out`` call sites.
    * ``fan_out(lambda probe: probe(), [a, b, c])`` -- the callables are the items,
      not the probe.  This is the dominant shape for fanning out a fixed set of
      unrelated reads, and it is exactly where a privileged helper is most likely
      to be added by someone extending a list.
    """
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"submit", "map"}:
            out.extend(_callable_names(node.args[0]))
        elif (isinstance(func, ast.Name) and func.id == "fan_out") or (
            isinstance(func, ast.Attribute) and func.attr == "fan_out"
        ):
            out.extend(_callable_names(node.args[0]))
            if len(node.args) > 1 and isinstance(node.args[1], (ast.List, ast.Tuple)):
                for item in node.args[1].elts:
                    out.extend(_callable_names(item))
    return out


class TheRuleTests(unittest.TestCase):
    """Nothing handed to an executor may depend on the request password.

    Resolution is within one module and bounded in depth.  That is deliberate:
    it catches the realistic regression -- someone wraps an existing mutation in
    ``ex.map`` -- without pretending to be a whole-program call graph, which
    would need type inference this does not have.
    """

    MAX_DEPTH = 6

    def _offenders(self, path: Path) -> list[str]:
        tree = ast.parse(path.read_text())
        functions = _module_functions(tree)
        submitted = _submitted_callables(tree)
        if not submitted:
            return []
        found = []
        for entry in submitted:
            seen: set[str] = set()
            stack = [(entry, 0, [entry])]
            while stack:
                name, depth, trail = stack.pop()
                if name in seen or depth > self.MAX_DEPTH:
                    continue
                seen.add(name)
                if name in PASSWORD_DEPENDENT:
                    found.append(" -> ".join(trail))
                    continue
                body = functions.get(name)
                if body is None:
                    continue
                for callee in sorted(_called_names(body)):
                    if callee in PASSWORD_DEPENDENT:
                        found.append(" -> ".join(trail + [callee]))
                    elif callee in functions:
                        stack.append((callee, depth + 1, trail + [callee]))
        return found

    def test_no_executor_work_reaches_a_password_dependent_helper(self):
        offenders: list[str] = []
        for path in sorted(HUB.rglob("*.py")):
            for chain in self._offenders(path):
                offenders.append(f"{path.relative_to(BASE)}: {chain}")
        self.assertEqual(
            offenders,
            [],
            "these run inside a ThreadPoolExecutor and depend on the "
            "request-scoped administrator password, which is empty in a worker. "
            "The call will report password_required even when the operator "
            "supplied one. Read the password on the request thread and pass it "
            "in, or keep the privileged call off the executor:\n  "
            + "\n  ".join(offenders),
        )

    def test_the_analysis_sees_fan_out_call_sites(self):
        """`fan_out` is how this codebase fans out; the scan must reach inside it.

        The ``ex.map`` lives in hub/util.py where the probe is a parameter, so a scan
        that only looked for ``.submit``/``.map`` resolved nothing and silently
        exempted every ``fan_out`` caller -- most of the parallel code in hub/.
        """
        shapes = ast.parse(
            "def a(): pass\n"
            "def b(): pass\n"
            "def _helper(x): pass\n"
            "def direct():\n"
            "    return fan_out(a, items)\n"
            "def as_items():\n"
            "    return fan_out(lambda p: p(), [a, b])\n"
            "def wrapped():\n"
            "    return fan_out(lambda p: p(), [lambda: _helper(1)])\n"
        )
        seen = set(_submitted_callables(shapes))
        self.assertIn("a", seen, "fan_out(probe, items) was not seen")
        self.assertIn("b", seen, "callables passed as fan_out items were not seen")
        self.assertIn("_helper", seen, "a lambda wrapper hid the real callable")

    def test_the_analysis_would_catch_a_privileged_helper_in_a_fan_out(self):
        """Positive control for the shape this file now guards.

        ``wireguard_net_svc.readiness`` fans out seven probes and deliberately keeps
        four -- ``status``, ``nat_installed``, ``daemon_state``, ``pf_enabled`` --
        on the request thread because they reach ``sudo_capture``. Nothing but this
        check stands between that split and someone tidying the four stragglers
        into the list.
        """
        violation = ast.parse(
            "def daemon_state():\n"
            "    return sudo_capture(['launchctl', 'print', 'system/x'])\n"
            "def safe_probe():\n"
            "    return 1\n"
            "def readiness():\n"
            "    return fan_out(lambda p: p(), [safe_probe, daemon_state])\n"
        )
        found = []
        functions = _module_functions(violation)
        for entry in _submitted_callables(violation):
            seen: set[str] = set()
            stack = [(entry, 0, [entry])]
            while stack:
                name, depth, trail = stack.pop()
                if name in seen or depth > self.MAX_DEPTH:
                    continue
                seen.add(name)
                body = functions.get(name)
                if body is None:
                    continue
                for callee in sorted(_called_names(body)):
                    if callee in PASSWORD_DEPENDENT:
                        found.append(" -> ".join(trail + [callee]))
                    elif callee in functions:
                        stack.append((callee, depth + 1, trail + [callee]))
        self.assertEqual(
            found,
            ["daemon_state -> sudo_capture"],
            "the rule cannot see a privileged helper added to a fan_out list, so it "
            "would not catch the regression it exists to catch",
        )

    def test_the_readiness_split_is_still_intact(self):
        """The four password-dependent probes stay off the pool, by name.

        Asserted directly as well as by the generic rule above, because this is the
        one place in hub/ where privileged and fanned-out probes sit in the same
        function and the split is easy to lose while editing.
        """
        source = (HUB / "wireguard_net_svc.py").read_text()
        start = source.index("def readiness")
        body = source[start: source.index("\ndef ", start + 10)]
        fan_start = body.index("fan_out(")
        fanned = body[fan_start: body.index(")", body.index("max_workers"))]
        for probe in ("nat_installed", "daemon_state", "pf_enabled", "status"):
            self.assertNotIn(
                probe,
                fanned,
                f"{probe} reaches sudo_capture and must not be fanned out; the "
                "password is empty on a worker and the failure is silent",
            )
        self.assertIn("peer_origin_conflict", fanned, "the safe probes stopped overlapping")

    def test_the_analysis_actually_sees_the_executors(self):
        """Without this, a parsing change that found nothing would pass vacuously."""
        with_executors = [
            path.relative_to(BASE)
            for path in sorted(HUB.rglob("*.py"))
            if _submitted_callables(ast.parse(path.read_text()))
        ]
        self.assertGreaterEqual(
            len(with_executors),
            8,
            f"expected to find many fanned-out modules, saw {with_executors}",
        )

    def test_the_analysis_would_catch_a_real_violation(self):
        """A positive control, so the rule is known to be able to fail."""
        sample = ast.parse(
            "def _apply(v):\n"
            "    return run_admin(['x', v])\n"
            "def collect(vs):\n"
            "    with ThreadPoolExecutor() as ex:\n"
            "        return list(ex.map(_apply, vs))\n"
        )
        functions = _module_functions(sample)
        submitted = _submitted_callables(sample)
        self.assertEqual(submitted, ["_apply"])
        self.assertIn("run_admin", _called_names(functions["_apply"]))

    def test_indirect_violations_are_caught_too(self):
        """One hop of indirection must not hide it."""
        sample = ast.parse(
            "def _inner(v):\n"
            "    return sudo_capture(['x', v])\n"
            "def _probe(v):\n"
            "    return _inner(v)\n"
            "def collect(vs):\n"
            "    with ThreadPoolExecutor() as ex:\n"
            "        return list(ex.map(_probe, vs))\n"
        )
        functions = _module_functions(sample)
        chains = []
        for entry in _submitted_callables(sample):
            stack = [(entry, [entry])]
            while stack:
                name, trail = stack.pop()
                for callee in sorted(_called_names(functions.get(name, ast.Module(body=[], type_ignores=[])))):
                    if callee in PASSWORD_DEPENDENT:
                        chains.append(" -> ".join(trail + [callee]))
                    elif callee in functions:
                        stack.append((callee, trail + [callee]))
        self.assertEqual(chains, ["_probe -> _inner -> sudo_capture"])


class PasswordlessSudoIsTheSafePatternTests(unittest.TestCase):
    """Why the parallelised reads are fine as written.

    They call ``sudo -n`` through ``hub.util.sh`` directly.  That path reads no
    ContextVar, so it behaves identically on any thread: it either matches a
    packaged sudoers rule or it fails, and the caller treats failure as "not
    available" rather than as "ask for a password".
    """

    def test_the_shell_helper_does_not_consult_the_password(self):
        source = (HUB / "util.py").read_text()
        for helper in PASSWORD_DEPENDENT:
            self.assertNotIn(
                helper,
                source,
                f"hub/util.sh must stay independent of {helper} so it is safe "
                "to call from a worker thread",
            )

    def test_sh_returns_the_same_shape_on_a_worker_thread(self):
        from hub.util import sh

        on_request_thread = sh(["/usr/bin/true"], timeout=5)
        with ThreadPoolExecutor(max_workers=1) as ex:
            in_worker = ex.submit(sh, ["/usr/bin/true"], timeout=5).result()
        self.assertEqual(on_request_thread[0], 0)
        self.assertEqual(in_worker[0], 0)


if __name__ == "__main__":
    unittest.main()
