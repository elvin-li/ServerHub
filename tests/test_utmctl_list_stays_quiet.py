"""utmctl list must not launch UTM.app when the GUI is already closed."""

import subprocess
import unittest
from unittest import mock

from hub import util


class UtmctlListStaysQuiet(unittest.TestCase):
    def test_list_does_not_spawn_when_the_app_is_closed(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["/usr/bin/pgrep", "-x"]:
                return subprocess.CompletedProcess(argv, 1)
            raise AssertionError(argv)

        with mock.patch.object(util.subprocess, "run", side_effect=run):
            rc, out, err = util.sh(["/Applications/UTM.app/Contents/MacOS/utmctl", "list"])
        self.assertEqual(rc, 0)
        self.assertTrue(out.startswith("UUID"))
        self.assertEqual(err, "")
        self.assertEqual(calls, [["/usr/bin/pgrep", "-x", "UTM"]])

    def test_list_still_runs_when_the_app_is_open(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(list(argv))
            if argv[:2] == ["/usr/bin/pgrep", "-x"]:
                return subprocess.CompletedProcess(argv, 0)
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(util.subprocess, "run", side_effect=run):
            util.sh(["/Applications/UTM.app/Contents/MacOS/utmctl", "list"], timeout=3)
        self.assertEqual(calls[0], ["/usr/bin/pgrep", "-x", "UTM"])
        self.assertTrue(str(calls[1][0]).endswith("utmctl"))
        self.assertEqual(calls[1][1], "list")

    def test_status_does_not_spawn_when_the_app_is_closed(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1)

        with mock.patch.object(util.subprocess, "run", side_effect=run):
            rc, _out, err = util.sh(
                ["/Applications/UTM.app/Contents/MacOS/utmctl", "status", "box"],
            )
        self.assertEqual(rc, 1)
        self.assertEqual(err, "UTM is not running")
        self.assertEqual(calls, [["/usr/bin/pgrep", "-x", "UTM"]])
