"""Leftover >4300-digit numbers in the PhotosHub / Immich / files / shares parsers.

Prior passes guarded the smartctl / top / pmset digit parsers and the share-ACL
``ls -lde`` index parse (see test_leftover_smart_power_digit_500s.py and
test_leftover_share_acl_digit_500s.py) against CPython's 4300-digit str->int
ValueError.  A fresh hunt over the remaining int()/float() conversions in this
corner — hub/photoshub_svc.py, hub/routers/photoshub_api.py, hub/immich_svc.py,
hub/files_svc.py, hub/routers/files_api.py, hub/shares_svc.py and
hub/routers/shares.py — found every unbounded parse already wrapped, so this
battery pins the survivors instead of fixing anything:

* PhotosHub's inventory count (``_inventory_public``): an over-cap
  ``missing_elsewhere`` written by the operator's inventory script answers 0
  instead of raising past GET /api/photoshub/status;
* Immich's worker pidfile parse (``worker_pid``): the 256-char read cap keeps
  the pid structurally under the digit limit, so garbage digits become a
  nonsense-but-valid int that the ``ps`` liveness check rejects — "no worker",
  never a 500 of GET /api/health;
* the FileBrowser pid parses (``filebrowser_status``): over-cap digits in the
  ``launchctl print`` / ``pgrep`` output leave ``pid`` null while the rest of
  the payload still renders GET /api/files;
* the Time Machine quota parse (``parse_time_machine_records``): an over-cap
  ``backupQuotaSize`` — and the 400-digit variant whose ``int()`` succeeds but
  whose float division OverflowErrors — reads as "no cap" instead of dropping
  every share's TM attributes on GET /api/shares;
* the ``du -sm`` share-size parse (``_dir_size_mb``): ``float()`` has no digit
  cap, so 5000 digits parse to inf — which the guard turns into None before
  Starlette's ``allow_nan=False`` encoder can 500 GET /api/shares.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import files_svc, immich_svc, photoshub_svc, shares_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Under the cap: ``int()`` succeeds, but ``int/float`` division OverflowErrors.
_BIG_DIGITS = "9" * 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class PhotoshubInventoryDigitPinTests(unittest.TestCase):
    """GET /api/photoshub/status renders the inventory through this parse."""

    def test_huge_count_answers_zero_not_a_500(self):
        out = photoshub_svc._inventory_public({"missing_elsewhere": _HUGE_DIGITS})
        self.assertEqual(out, {"missing_elsewhere": 0})
        _starlette(out)

    def test_a_sane_count_still_parses(self):
        out = photoshub_svc._inventory_public({"missing_elsewhere": "12"})
        self.assertEqual(out, {"missing_elsewhere": 12})


class ImmichWorkerPidDigitPinTests(unittest.TestCase):
    """GET /api/health runs the Immich checks through ``worker_pid``."""

    def _pidfile(self, content: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".pid", delete=False, encoding="utf-8"
        )
        self.addCleanup(Path(tmp.name).unlink)
        tmp.write(content)
        tmp.close()
        return Path(tmp.name)

    def test_garbage_digit_pidfile_means_no_worker_not_a_500(self):
        # The 256-char read cap means the pid can never carry >4300 digits;
        # the leftover parses into a nonsense int whose ``ps`` probe fails.
        pidfile = self._pidfile(f"{_HUGE_DIGITS[:250]}\n")
        with (
            mock.patch.object(immich_svc, "WORKER_PID", pidfile),
            mock.patch.object(immich_svc, "sh", return_value=(1, "", "")) as fake_sh,
        ):
            self.assertIsNone(immich_svc.worker_pid())
        # str(pid) of the capped 250-digit int is itself under the str cap, so
        # building the argv cannot raise either.
        fake_sh.assert_called_once()

    def test_a_sane_pidfile_still_resolves_the_worker(self):
        started = "Mon Aug  4 13:42:00 2025"
        pidfile = self._pidfile(f"502\n{started}\n")
        with (
            mock.patch.object(immich_svc, "WORKER_PID", pidfile),
            mock.patch.object(
                immich_svc, "sh", return_value=(0, f"{started} immich", "")
            ),
        ):
            self.assertEqual(immich_svc.worker_pid(), 502)


class FileBrowserPidDigitPinTests(unittest.TestCase):
    """GET /api/files renders ``filebrowser_status`` on every page load."""

    def test_huge_launchctl_pid_leaves_pid_null_not_a_500(self):
        out = f"state = running\n\tpid = {_HUGE_DIGITS}\n"
        with (
            mock.patch.object(files_svc, "sh", return_value=(0, out, "")),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
        ):
            state = files_svc.filebrowser_status()
        self.assertTrue(state["running"])
        self.assertIsNone(state["pid"])
        _starlette(state)

    def test_huge_pgrep_pid_leaves_pid_null_not_a_500(self):
        def fake_sh(argv, timeout=0):
            if "pgrep" in argv[0]:
                return 0, f"{_HUGE_DIGITS}\n", ""
            return 1, "", ""

        with (
            mock.patch.object(files_svc, "sh", side_effect=fake_sh),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
        ):
            state = files_svc.filebrowser_status()
        self.assertTrue(state["running"])
        self.assertIsNone(state["pid"])
        _starlette(state)

    def test_a_sane_launchctl_pid_still_parses(self):
        out = "state = running\n\tpid = 4321\n"
        with (
            mock.patch.object(files_svc, "sh", return_value=(0, out, "")),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
        ):
            state = files_svc.filebrowser_status()
        self.assertEqual(state["pid"], 4321)


def _tm_plist(quota: str) -> bytes:
    return plistlib.dumps([
        {
            "dsAttrTypeStandard:RecordName": ["Media"],
            "dsAttrTypeNative:timeMachineBackup": ["1"],
            "dsAttrTypeNative:backupQuotaSize": [quota],
        }
    ])


class TimeMachineQuotaDigitPinTests(unittest.TestCase):
    """GET /api/shares merges these attributes into every SMB row."""

    def test_huge_quota_reads_as_no_cap_not_a_500(self):
        records = shares_svc.parse_time_machine_records(_tm_plist(_HUGE_DIGITS))
        self.assertEqual(
            records["Media"],
            {"time_machine": True, "tm_quota_gb": None, "uuid": None},
        )
        _starlette(records)

    def test_400_digit_quota_survives_the_float_division(self):
        # ``int()`` succeeds under the cap; ``quota_bytes / _GB`` is the
        # OverflowError ("int too large to convert to float") the guard eats.
        records = shares_svc.parse_time_machine_records(_tm_plist(_BIG_DIGITS))
        self.assertIsNone(records["Media"]["tm_quota_gb"])
        self.assertTrue(records["Media"]["time_machine"])

    def test_a_sane_quota_still_parses(self):
        records = shares_svc.parse_time_machine_records(_tm_plist("2000000000000"))
        self.assertEqual(records["Media"]["tm_quota_gb"], 2000)


class DirSizeDigitPinTests(unittest.TestCase):
    """``float()`` has no digit cap: 5000 digits parse to inf, not ValueError."""

    def test_huge_du_output_answers_none_not_inf(self):
        with mock.patch.object(
            shares_svc, "sh", return_value=(0, f"{_HUGE_DIGITS}\t/\n", "")
        ):
            self.assertIsNone(shares_svc._dir_size_mb("/"))

    def test_a_sane_du_output_still_parses(self):
        with mock.patch.object(
            shares_svc, "sh", return_value=(0, "1536\t/\n", "")
        ):
            self.assertEqual(shares_svc._dir_size_mb("/"), 1536.0)


if __name__ == "__main__":
    unittest.main()
