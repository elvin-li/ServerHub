"""The UTM-open check reads the process table in-process, not by spawning pgrep.

``hub.util._utm_app_running()`` runs before every ``utmctl`` call (utmctl
relaunches UTM.app when it is closed) and spawned ``pgrep -x UTM`` each time:
about 4.5 ms of child CPU and 1.7 ms in the panel.  ``hub/proc_names.py``
answers from one sysctl read in about 0.4 ms.  These tests check it against
pgrep on a Mac, with system processes and with a crafted process that is
running, gone or a zombie, and check that the UTM check uses it and still
runs pgrep when it cannot answer.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import proc_names, util  # noqa: E402

_ON_MAC = sys.platform == "darwin" and os.path.exists("/usr/bin/pgrep")
_CC = shutil.which("cc") or shutil.which("clang")
_NAPPER = (
    "#include <stdlib.h>\n#include <unistd.h>\n"
    "int main(int c, char **v) { if (c > 1) sleep(atoi(v[1])); return 0; }\n"
)


def _pgrep(name: str) -> bool:
    return subprocess.run(
        ["/usr/bin/pgrep", "-x", name], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=10, check=False,
    ).returncode == 0


class _NativeOn(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop("SERVERHUB_NO_NATIVE_PROCNAME", None)


@unittest.skipUnless(_ON_MAC, "needs macOS pgrep")
class SameAnswerAsPgrepTests(_NativeOn):
    def test_system_processes(self):
        for name in ("Dock", "Finder", "WindowServer", "loginwindow", "cfprefsd",
                     "UTM", "zz-no-such-proc"):
            with self.subTest(name=name):
                for _ in range(3):  # equal unless one came or went in between
                    native, reference = proc_names.process_named(name), _pgrep(name)
                    if native == reference:
                        break
                self.assertEqual(native, reference)

    @unittest.skipUnless(_CC, "needs a C compiler to build a named process")
    def test_a_named_process_running_gone_and_zombie(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        source = os.path.join(tmp, "napper.c")
        with open(source, "w", encoding="ascii") as fh:
            fh.write(_NAPPER)
        live, dead = os.path.join(tmp, "ZshProbeLive"), os.path.join(tmp, "ZshProbeDead")
        for binary in (live, dead):
            subprocess.run([_CC, "-o", binary, source], check=True, timeout=120,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sleeper = subprocess.Popen([live, "30"])
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        zombie = subprocess.Popen([dead])  # exits at once and stays unreaped
        self.addCleanup(zombie.wait)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (
            proc_names.process_named("ZshProbeLive") and _pgrep("ZshProbeLive")
        ):
            time.sleep(0.05)
        time.sleep(0.2)
        self.assertIs(proc_names.process_named("ZshProbeLive"), True)
        self.assertIs(_pgrep("ZshProbeLive"), True)
        self.assertIs(proc_names.process_named("ZshProbeDead"), False)
        self.assertIs(_pgrep("ZshProbeDead"), False)
        sleeper.kill()
        sleeper.wait()
        self.assertIs(proc_names.process_named("ZshProbeLive"), False)
        self.assertIs(_pgrep("ZshProbeLive"), False)


class NoAnswerTests(_NativeOn):
    def test_names_it_cannot_check(self):
        for name in ("", "x" * 17, "two words", "caf\u00e9", "tab\tx", None, b"UTM"):
            with self.subTest(name=name):
                self.assertIsNone(proc_names.process_named(name))

    def test_the_env_flag_turns_it_off(self):
        os.environ["SERVERHUB_NO_NATIVE_PROCNAME"] = "1"
        with mock.patch.object(proc_names, "_load") as load:
            self.assertIsNone(proc_names.process_named("UTM"))
        load.assert_not_called()

    def test_no_library_or_a_failed_read(self):
        with mock.patch.object(proc_names, "_load", return_value=None):
            self.assertIsNone(proc_names.process_named("UTM"))
        lib = mock.Mock()
        lib.sysctl.return_value = -1
        with mock.patch.object(proc_names, "_load", return_value=lib):
            self.assertIsNone(proc_names.process_named("UTM"))

    @unittest.skipUnless(sys.platform == "darwin", "needs the sysctl")
    def test_a_table_without_this_process_is_not_trusted(self):
        with mock.patch.object(proc_names.os, "getpid", return_value=2**31 - 7):
            self.assertIsNone(proc_names.process_named("Finder"))


class UtmCheckTests(unittest.TestCase):
    def _check(self, native):
        calls = []

        def run(argv, **kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(util, "process_named", return_value=native), \
                mock.patch.object(util.subprocess, "run", side_effect=run):
            return util._utm_app_running(), calls

    def test_the_native_answer_is_used_without_spawning(self):
        for native in (True, False):
            with self.subTest(native=native):
                self.assertEqual(self._check(native), (native, []))

    def test_no_native_answer_runs_pgrep(self):
        running, calls = self._check(None)
        self.assertTrue(running)
        self.assertEqual(calls, [["/usr/bin/pgrep", "-x", "UTM"]])

    def test_a_closed_utm_lists_nothing_and_spawns_nothing(self):
        with mock.patch.object(util, "process_named", return_value=False), \
                mock.patch.object(util.subprocess, "run",
                                  side_effect=AssertionError("no spawn")):
            rc, out, err = util.sh(["/Applications/UTM.app/Contents/MacOS/utmctl", "list"])
        self.assertEqual((rc, err), (0, ""))
        self.assertTrue(out.startswith("UUID"))


if __name__ == "__main__":
    unittest.main()
