"""Pin the Linux CI contract so a drive-by workflow edit cannot drop a gate.

The panel that actually ships is committed ``static/``. Vite hashes every
chunk, so a ``web/`` change that CI tests against source but never rebuilds
leaves operators on the previous panel. ``git diff`` misses *untracked*
emitted files; ``git status --porcelain static/`` does not.

knip is the other silent hole: the i18n duplicate-key tests import
``rollup/parseAst`` (Vite's own parser). If rollup is not a declared web
devDependency, knip fails CI — which is what we want — unless someone
deletes the knip step or the rollup listing together.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
WORKFLOW = BASE / ".github" / "workflows" / "ci.yml"
WEB_PKG = BASE / "web" / "package.json"


class CiWorkflowInvariants(unittest.TestCase):
    def test_workflow_is_checked_in(self):
        self.assertTrue(WORKFLOW.is_file(), "CI workflow missing")

    def test_built_panel_check_uses_porcelain_not_diff_only(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("git status --porcelain static/", text)
        self.assertNotIn(
            'git diff --exit-code static/',
            text,
            "git diff misses untracked hashed chunks after a clean rebuild",
        )

    def test_knip_runs_in_ci(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("check:dead-code", text)

    def test_web_declares_rollup_for_i18n_ast_tests(self):
        pkg = json.loads(WEB_PKG.read_text(encoding="utf-8"))
        dev = pkg.get("devDependencies") or {}
        self.assertIn("rollup", dev, "knip treats rollup/parseAst as unlisted without this")


if __name__ == "__main__":
    unittest.main()
