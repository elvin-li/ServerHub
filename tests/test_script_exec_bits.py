"""Scripts the docs tell people to run must be executable *in the commit*.

The on-disk bit and the committed bit are different facts, and only the second
one survives a clone.  This repository lost `install.sh`'s and `uninstall.sh`'s
executable bit exactly that way: the content was byte-identical to the published
copy (same blob hash) while the index recorded 100644, so nothing looked wrong
locally and `./install.sh` failed with "permission denied" for anyone who cloned
it.  `chmod +x` alone does not fix that -- the mode has to be staged -- so this
test asks git what the tree records, not what the filesystem currently says.

`git ls-files -s` is used rather than `os.access(X_OK)` for the same reason.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

# Scripts a user or the README invokes directly, with the reference that makes
# each one part of the published contract.
EXECUTABLE_SCRIPTS = [
    ("install.sh", "README documents `./install.sh` as the entry point"),
    ("uninstall.sh", "README documents `./uninstall.sh`, and `--purge`"),
    ("scripts/gates.sh", "the gate runner is invoked directly by contributors"),
    ("macos/build_app.sh", "builds the .app bundle"),
    ("macos/build_distribution.sh", "builds the distributable"),
]

GIT_EXEC_MODE = "100755"


def tracked_mode(rel: str) -> str:
    """Return the mode git has recorded for *rel*, or '' when untracked."""
    proc = subprocess.run(
        ["git", "ls-files", "-s", "--", rel],
        cwd=BASE,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(f"git ls-files failed for {rel}: {proc.stderr.strip()}")
    out = proc.stdout.strip()
    if not out:
        return ""
    # "<mode> <object> <stage>\t<path>"
    return out.split()[0]


class ScriptExecBitTests(unittest.TestCase):
    def test_git_is_available(self):
        # Otherwise every assertion below would pass vacuously in a tarball.
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=BASE,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode, 0, "this file asserts a git property and needs a work tree"
        )

    def test_documented_scripts_are_committed_executable(self):
        wrong = []
        for rel, why in EXECUTABLE_SCRIPTS:
            mode = tracked_mode(rel)
            if mode == "":
                wrong.append(f"  {rel} -- not tracked by git ({why})")
            elif mode != GIT_EXEC_MODE:
                wrong.append(f"  {rel} -- committed as {mode}, expected {GIT_EXEC_MODE} ({why})")
        self.assertEqual(
            wrong,
            [],
            "these scripts are documented as directly runnable but a fresh clone "
            "would not be able to execute them:\n" + "\n".join(wrong),
        )

    def test_the_scripts_actually_exist_on_disk(self):
        missing = [rel for rel, _ in EXECUTABLE_SCRIPTS if not (BASE / rel).is_file()]
        self.assertEqual(missing, [], f"documented scripts are missing: {missing}")


if __name__ == "__main__":
    unittest.main()
