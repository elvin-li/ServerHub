"""The reason a SMART read failed has to be the reason, not smartctl's banner.

smartctl writes a version line and a copyright line before everything, errors
included, so `serr or sout` picks those up first.  An unreadable external disk
therefore explained itself in the Dashboard tooltip as
"smartctl 7.5 2025-04-30 r5714 [Darwin 25.5.0 arm64] (local build) Copyright ...",
which tells a reader nothing about why the disk shows no health data.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.storage_svc import _smartctl_failure  # noqa: E402

BANNER = (
    "smartctl 7.5 2025-04-30 r5714 [Darwin 25.5.0 arm64] (local build)\n"
    "Copyright (C) 2002-25, Bruce Allen, Christian Franke, www.smartmontools.org\n"
)


class SmartFailureMessageTests(unittest.TestCase):
    def test_banner_is_not_the_error_message(self):
        message = _smartctl_failure(BANNER, "")
        self.assertNotIn("Copyright", message)
        self.assertNotIn("smartctl 7.5", message)

    def test_external_usb_disk_is_explained_as_a_transport_limit(self):
        """This is the real output for a USB enclosure on Apple silicon.

        It must not read as a drive fault: macOS has no SCSI/ATA passthrough for
        USB and Thunderbolt bridges, so no `-d` transport can reach the disk.
        """
        out = BANNER + "Smartctl open device: /dev/disk4 failed: Operation not supported by device"
        message = _smartctl_failure(out, "")
        self.assertIn("not a disk fault", message)
        self.assertNotIn("Copyright", message)

    def test_permission_failure_points_at_the_installer(self):
        """A missing sudoers rule is fixable, so the message says how."""
        out = BANNER + "Smartctl open device: /dev/disk0 failed: Permission denied"
        self.assertIn("install-sudoers.sh", _smartctl_failure(out, ""))

    def test_an_unrecognised_reason_is_still_reported(self):
        out = BANNER + "Smartctl open device: /dev/disk9 failed: No such file or directory"
        message = _smartctl_failure(out, "")
        self.assertIn("No such file or directory", message)

    def test_empty_output_falls_back_to_something_actionable(self):
        self.assertTrue(_smartctl_failure("", ""))
        self.assertNotIn("Copyright", _smartctl_failure(BANNER, BANNER))

    def test_message_stays_short_enough_for_a_tooltip(self):
        long_tail = BANNER + "x" * 500
        self.assertLessEqual(len(_smartctl_failure(long_tail, "")), 120)

    def test_stderr_is_preferred_but_stdout_is_not_lost(self):
        """smartctl reports the open failure on stdout, so both have to be read."""
        message = _smartctl_failure(
            BANNER + "Smartctl open device: /dev/disk4 failed: Operation not supported by device",
            BANNER,
        )
        self.assertIn("not a disk fault", message)


if __name__ == "__main__":
    unittest.main()
