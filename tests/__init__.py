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

``setdefault``, not assignment: an explicit ``SERVERHUB_STATE_DIR`` (the e2e
harness, or a developer pointing the suite somewhere deliberate) still wins.
``test_tests_do_not_mutate_the_host`` asserts the redirection took effect.
"""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault(
    "SERVERHUB_STATE_DIR",
    tempfile.mkdtemp(prefix="serverhub-tests-state-"),
)
