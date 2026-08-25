"""Suite bootstrap: point mutable panel state at a per-run temp directory.

``hub.paths`` resolves ``STATE_ROOT`` / ``DATA_DIR`` / ``CONFIG_FILE`` once, at
import time, from ``SERVERHUB_STATE_DIR`` -- and defaults to the source
checkout.  Individual tests patch the constants they exercise, but any code
path that reaches an unpatched consumer writes into the working tree: a full
run used to bootstrap ``services.yaml`` in the repo root and leave
``data/alert_state.json``, ``data/metrics.jsonl``, ``data/services.yaml.bak.*``
and assorted lock files behind.  ``.gitignore`` hides all of it from
``git status --porcelain``, so CI's static/ drift check never noticed either.

unittest discovery imports this package before any test module, so setting the
variable here lands before the first ``hub`` import resolves the paths.
Subprocesses spawned by tests (the cross-process locking and audit suites)
inherit the same directory through the environment, which keeps their
shared-state semantics intact.

HOME is redirected for the same reason.  Several hub modules derive state
locations from ``Path.home()`` at import time -- hub.backups even
``mkdir``s ``~/Services/backups`` as an import side effect -- so a suite
run used to create ``~/Services/{backups,media,cloudflared}``,
``~/.cloudflared`` and ``~/Library/Logs`` on whatever machine ran it.
With HOME pointing into the per-run temp directory those paths are
hermetic on Linux CI and on a developer's Mac alike.

``setdefault``, not assignment: an explicit ``SERVERHUB_STATE_DIR`` (the e2e
harness, or a developer pointing the suite somewhere deliberate) still wins.
``test_tests_do_not_mutate_the_host`` asserts the redirection took effect.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_root = tempfile.mkdtemp(prefix="serverhub-tests-state-")
os.environ.setdefault("SERVERHUB_STATE_DIR", str(Path(_root) / "state"))
if "SERVERHUB_TESTS_KEEP_HOME" not in os.environ:
    _home = Path(_root) / "home"
    _home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(_home)
