"""Every blocking subprocess call in hub/ must carry a timeout.

``subprocess.run`` without ``timeout=`` waits forever; on a request thread
that wedges the request, and on a worker thread it silently parks the
subsystem until the panel restarts (the UTM status probe in hub/actions.py
did exactly that).  ``hub.util.sh`` defaults to ``timeout=10``, so the rule
enforced here is simply: call ``subprocess.run`` with an explicit timeout, or
use ``sh()``.

``subprocess.Popen`` is exempt by design — streaming callers cannot pass a
timeout and are expected to run under a watchdog (hub/jobs.run_watchdog,
containers_svc._stream_job_command) or to be deliberately detached daemons;
those patterns have their own tests.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

HUB = BASE / "hub"


def _run_calls_without_timeout(tree: ast.AST) -> list[int]:
    """Line numbers of ``subprocess.run(...)`` calls lacking a timeout kwarg."""
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"):
            continue
        keywords = {kw.arg for kw in node.keywords}
        if "timeout" not in keywords and None not in keywords:  # None == **kwargs
            offenders.append(node.lineno)
    return offenders


class SubprocessTimeoutDiscipline(unittest.TestCase):
    def test_every_subprocess_run_in_hub_has_a_timeout(self):
        offenders: list[str] = []
        for path in sorted(HUB.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError as exc:  # pragma: no cover - would fail imports anyway
                self.fail(f"{path} does not parse: {exc}")
            offenders.extend(
                f"{path.relative_to(BASE)}:{line}"
                for line in _run_calls_without_timeout(tree)
            )
        self.assertEqual(
            offenders, [],
            "subprocess.run without timeout= blocks forever on a wedged "
            "child; pass an explicit timeout or use hub.util.sh: "
            + ", ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
