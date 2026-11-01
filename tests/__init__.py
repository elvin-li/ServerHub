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
# Stubbed subprocess answers must not leak between tests through hub.util.sh's
# memo; tests/test_sh_memo.py turns it back on for itself.
os.environ.setdefault("SERVERHUB_NO_SH_MEMO", "1")
# brew_cache reuses its snapshot while the host's Homebrew launchd jobs and
# plists look unchanged.  On a Mac the real listing would make stubbed brew
# answers stick across tests; tests/test_brew_services_reuse.py turns it on.
os.environ.setdefault("SERVERHUB_NO_BREW_REUSE", "1")
# Tests feed _gpu() canned ``ioreg`` XML through a stubbed sh; on a Mac the
# native IOKit read would answer with the real GPU instead.
# tests/test_sensors_gpu.py turns it back on for its own native tests.
os.environ.setdefault("SERVERHUB_NO_NATIVE_GPU", "1")
# Same for the free-memory percentage: tests feed canned `memory_pressure -Q`
# text; tests/test_memory_level_native.py turns the sysctl read back on.
os.environ.setdefault("SERVERHUB_NO_NATIVE_MEMLEVEL", "1")
if "SERVERHUB_TESTS_KEEP_HOME" not in os.environ:
    _home = Path(_root) / "home"
    _home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(_home)
