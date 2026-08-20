"""Time Machine destination shares: parsing, command construction, status.

The write-side attribute names could not be verified against a GUI-created TM
share (none existed on the dev machine and the sudoers policy does not cover
`dscl`), so every mutation here is asserted against mocks and the service's
own read-back verification is what guards a renamed attribute in production.
The parsing fixtures, on the other hand, are real output captured from
macOS 26.5.2 (`dscl -plist . -readall /SharePoints`, `dns-sd -B _smb._tcp`).
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hub import shares_svc

DSCL = "/usr/bin/dscl"

# Captured verbatim from macOS 26.5.2, with a second record appended in the
# same shape carrying the Time Machine attributes this module writes.
SHAREPOINTS_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
\t<dict>
\t\t<key>dsAttrTypeNative:directory_path</key>
\t\t<array>
\t\t\t<string>/Users/a0000/Public</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:smb_guestaccess</key>
\t\t<array>
\t\t\t<string>1</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:smb_name</key>
\t\t<array>
\t\t\t<string>Public Folder</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:smb_shared</key>
\t\t<array>
\t\t\t<string>1</string>
\t\t</array>
\t\t<key>dsAttrTypeStandard:RecordName</key>
\t\t<array>
\t\t\t<string>Public Folder</string>
\t\t</array>
\t\t<key>dsAttrTypeStandard:RecordType</key>
\t\t<array>
\t\t\t<string>dsRecTypeStandard:SharePoints</string>
\t\t</array>
\t</dict>
\t<dict>
\t\t<key>dsAttrTypeNative:directory_path</key>
\t\t<array>
\t\t\t<string>/Volumes/Backups/TM</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:smb_name</key>
\t\t<array>
\t\t\t<string>Backups</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:smb_shared</key>
\t\t<array>
\t\t\t<string>1</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:timeMachineBackup</key>
\t\t<array>
\t\t\t<string>1</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:timeMachineBackupUUID</key>
\t\t<array>
\t\t\t<string>5870B13B-0A0B-420A-BDA8-4853BD546839</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:backupQuotaSize</key>
\t\t<array>
\t\t\t<string>500000000000</string>
\t\t</array>
\t\t<key>dsAttrTypeStandard:RecordName</key>
\t\t<array>
\t\t\t<string>Backups</string>
\t\t</array>
\t</dict>
</array>
</plist>
"""

# Alternative attribute spelling seen in community dumps of GUI-enabled TM
# shares on other macOS versions; the reader must recognize it too.
ALIAS_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
\t<dict>
\t\t<key>dsAttrTypeNative:timemachine</key>
\t\t<array>
\t\t\t<string>1</string>
\t\t</array>
\t\t<key>dsAttrTypeNative:timemachine_quota</key>
\t\t<array>
\t\t\t<string>0</string>
\t\t</array>
\t\t<key>dsAttrTypeStandard:RecordName</key>
\t\t<array>
\t\t\t<string>Legacy</string>
\t\t</array>
\t</dict>
</array>
</plist>
"""

# Captured verbatim from `dns-sd -B _smb._tcp local.` on the dev machine.
DNS_SD_OUTPUT = """Browsing for _smb._tcp.local.
DATE: ---Thu 13 Aug 2026---
16:49:48.385  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
16:49:48.386  Add        3   1 local.               _smb._tcp.           MacBook Pro
16:49:48.388  Add        3  20 local.               _smb._tcp.           MacBook Pro
16:49:48.388  Rmv        2  27 local.               _smb._tcp.           Gone Host
"""


class SharePointsPlistParsingTests(unittest.TestCase):
    def test_reads_flag_quota_and_uuid_from_real_shaped_records(self):
        records = shares_svc.parse_time_machine_records(SHAREPOINTS_PLIST)
        self.assertEqual(records["Public Folder"], {
            "time_machine": False, "tm_quota_gb": None, "uuid": None,
        })
        self.assertEqual(records["Backups"], {
            "time_machine": True,
            "tm_quota_gb": 500,
            "uuid": "5870B13B-0A0B-420A-BDA8-4853BD546839",
        })

    def test_recognizes_alternative_attribute_spellings(self):
        records = shares_svc.parse_time_machine_records(ALIAS_PLIST)
        # quota "0" means no cap, exactly like an absent attribute
        self.assertEqual(records["Legacy"], {
            "time_machine": True, "tm_quota_gb": None, "uuid": None,
        })

    def test_records_read_failure_degrades_to_empty(self):
        with patch("hub.shares_svc.sh", return_value=(1, "", "denied")):
            self.assertEqual(shares_svc.time_machine_records(), {})
        with patch("hub.shares_svc.sh", return_value=(0, "not a plist", "")):
            self.assertEqual(shares_svc.time_machine_records(), {})

    def test_nested_plist_is_value_error_not_recursion(self):
        """plistlib RecursionError is not ValueError."""
        with patch.object(shares_svc.plistlib, "loads", side_effect=RecursionError):
            with self.assertRaises(ValueError):
                shares_svc.parse_time_machine_records("<plist/>")
        with (
            patch("hub.shares_svc.sh", return_value=(0, "<plist/>", "")),
            patch.object(shares_svc.plistlib, "loads", side_effect=RecursionError),
        ):
            self.assertEqual(shares_svc.time_machine_records(), {})

    def test_records_read_uses_fixed_dscl_argv(self):
        with patch("hub.shares_svc.sh", return_value=(0, SHAREPOINTS_PLIST, "")) as run:
            shares_svc.time_machine_records()
        self.assertEqual(
            run.call_args.args[0],
            [DSCL, "-plist", ".", "-readall", "/SharePoints"],
        )


class QuotaValidationTests(unittest.TestCase):
    def test_quota_requires_the_time_machine_flag(self):
        with self.assertRaisesRegex(
            shares_svc.ShareValidationError, "shares.quota_requires_time_machine",
        ):
            shares_svc._validate_quota(False, 100)

    def test_quota_range_and_type(self):
        for bad in (0, -5, 1_000_001, True, 1.5, "500"):
            with self.subTest(bad=bad), self.assertRaisesRegex(
                shares_svc.ShareValidationError, "shares.bad_quota",
            ):
                shares_svc._validate_quota(True, bad)
        self.assertEqual(shares_svc._validate_quota(True, 500), 500)
        self.assertIsNone(shares_svc._validate_quota(True, None))
        self.assertIsNone(shares_svc._validate_quota(False, None))


class TimeMachineCommandTests(unittest.TestCase):
    """The privileged argv is fixed and built only from validated values."""

    def _create(self, folder: Path, **kwargs):
        actual = {
            "record_name": "Backups", "smb_name": "Backups", "shared": True,
            "guest": False, "readonly": False, "encrypted": False,
            "time_machine": kwargs.get("time_machine", False),
            "tm_quota_gb": kwargs.get("tm_quota_gb"),
        }
        with (
            patch("hub.shares_svc._find_share", side_effect=[None, actual]),
            patch(
                "hub.shares_svc.run_admin_sequence", return_value={"ok": True},
            ) as admin,
            patch("hub.shares_svc.uuid4") as uuid4,
        ):
            uuid4.return_value = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
            result = shares_svc.create_smb_share(
                path=str(folder), name="Backups", smb_name="Backups",
                guest=False, readonly=False, encrypted=False, **kwargs,
            )
        return result, admin

    def test_create_with_time_machine_appends_dscl_attribute_writes(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            folder = Path(temporary) / "TM"
            folder.mkdir()
            result, admin = self._create(folder, time_machine=True, tm_quota_gb=500)

        self.assertTrue(result["ok"])
        commands = admin.call_args.args[0]
        self.assertEqual(commands[0][:2], ["/usr/sbin/sharing", "-a"])
        self.assertEqual(commands[1:], [
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:timeMachineBackup", "1"],
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:timeMachineBackupUUID",
             "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111"],
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:backupQuotaSize", "500000000000"],
        ])

    def test_create_without_quota_writes_no_quota_attribute(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            folder = Path(temporary) / "TM"
            folder.mkdir()
            result, admin = self._create(folder, time_machine=True)

        self.assertTrue(result["ok"])
        commands = admin.call_args.args[0]
        self.assertEqual(len(commands), 3)  # sharing -a, flag, uuid
        self.assertNotIn(
            "dsAttrTypeNative:backupQuotaSize",
            [part for command in commands for part in command],
        )

    def test_create_without_time_machine_issues_only_the_sharing_command(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            folder = Path(temporary) / "Plain"
            folder.mkdir()
            result, admin = self._create(folder)

        self.assertTrue(result["ok"])
        self.assertEqual(len(admin.call_args.args[0]), 1)

    def _update(self, existing: dict, records: dict, **kwargs):
        expected = {
            "record_name": "Backups", "smb_name": "Backups", "shared": True,
            "guest": False, "readonly": False, "encrypted": False,
            "time_machine": kwargs.get("time_machine", False),
            "tm_quota_gb": kwargs.get("tm_quota_gb")
            if kwargs.get("time_machine") else None,
        }
        with (
            patch("hub.shares_svc._find_share", side_effect=[existing, expected]),
            patch("hub.shares_svc.time_machine_records", return_value=records),
            patch(
                "hub.shares_svc.run_admin_sequence", return_value={"ok": True},
            ) as admin,
            patch("hub.shares_svc.uuid4") as uuid4,
        ):
            uuid4.return_value = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
            result = shares_svc.update_smb_share(
                "Backups", smb_name="Backups",
                guest=False, readonly=False, encrypted=False, **kwargs,
            )
        return result, admin

    def test_enable_mints_a_uuid_only_when_the_record_has_none(self):
        existing = {
            "record_name": "Backups", "time_machine": False, "tm_quota_gb": None,
        }
        result, admin = self._update(existing, {}, time_machine=True)
        self.assertTrue(result["ok"])
        self.assertEqual(admin.call_args.args[0][1:], [
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:timeMachineBackup", "1"],
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:timeMachineBackupUUID",
             "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111"],
        ])

    def test_enable_preserves_an_existing_uuid(self):
        existing = {
            "record_name": "Backups", "time_machine": False, "tm_quota_gb": None,
        }
        records = {"Backups": {
            "time_machine": False, "tm_quota_gb": None, "uuid": "KEEP-ME",
        }}
        result, admin = self._update(existing, records, time_machine=True)
        self.assertTrue(result["ok"])
        commands = admin.call_args.args[0]
        self.assertNotIn(
            "dsAttrTypeNative:timeMachineBackupUUID",
            [part for command in commands for part in command],
        )

    def test_disable_zeroes_the_flag_and_quota_but_never_deletes(self):
        existing = {
            "record_name": "Backups", "time_machine": True, "tm_quota_gb": 500,
        }
        result, admin = self._update(existing, {}, time_machine=False)
        self.assertTrue(result["ok"])
        commands = admin.call_args.args[0]
        self.assertEqual(commands[1:], [
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:timeMachineBackup", "0"],
            [DSCL, ".", "-create", "/SharePoints/Backups",
             "dsAttrTypeNative:backupQuotaSize", "0"],
        ])
        self.assertNotIn("-delete", [part for cmd in commands for part in cmd])

    def test_update_of_a_plain_share_stays_a_single_sharing_command(self):
        existing = {
            "record_name": "Backups", "time_machine": False, "tm_quota_gb": None,
        }
        result, admin = self._update(existing, {}, time_machine=False)
        self.assertTrue(result["ok"])
        self.assertEqual(len(admin.call_args.args[0]), 1)

    def test_time_machine_state_is_part_of_the_write_verification(self):
        actual = {
            "record_name": "Backups", "smb_name": "Backups", "shared": True,
            "guest": False, "readonly": False, "encrypted": False,
            # flag write silently did not stick (e.g. renamed attribute)
            "time_machine": False, "tm_quota_gb": None,
        }
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            folder = Path(temporary) / "TM"
            folder.mkdir()
            with (
                patch("hub.shares_svc._find_share", side_effect=[None, actual]),
                patch("hub.shares_svc.run_admin_sequence", return_value={"ok": True}),
            ):
                result = shares_svc.create_smb_share(
                    path=str(folder), name="Backups", smb_name="Backups",
                    guest=False, readonly=False, encrypted=False,
                    time_machine=True,
                )
        self.assertEqual(result["error"], "verification_failed")


class DiscoveryProbeTests(unittest.TestCase):
    def setUp(self):
        # The adisk browse is memoized for a minute; no test may read (or
        # leave behind) another test's cached answer.
        shares_svc._adisk_advertised.invalidate()
        self.addCleanup(shares_svc._adisk_advertised.invalidate)

    def test_dns_sd_browse_output_parses_add_rows_only(self):
        self.assertEqual(
            shares_svc.dns_sd_instances(DNS_SD_OUTPUT),
            ["MacBook Pro", "MacBook Pro"],
        )
        self.assertEqual(shares_svc.dns_sd_instances(""), [])
        self.assertEqual(
            shares_svc.dns_sd_instances("Browsing for _adisk._tcp.local.\n"),
            [],
        )

    def test_status_skips_the_bonjour_browse_without_tm_shares(self):
        shares = [{"record_name": "Plain", "time_machine": False}]
        with (
            patch("hub.shares_svc.smb_service_running", return_value=True),
            patch("hub.shares_svc._dns_sd_advertised") as browse,
        ):
            status = shares_svc.time_machine_status(shares)
        browse.assert_not_called()
        self.assertEqual(status, {
            "share_count": 0,
            "smb_service_running": True,
            "adisk_advertised": None,
        })

    def test_status_reports_advertisement_when_tm_shares_exist(self):
        shares = [
            {"record_name": "Backups", "time_machine": True},
            {"record_name": "Plain", "time_machine": False},
        ]
        with (
            patch("hub.shares_svc.smb_service_running", return_value=False),
            patch(
                "hub.shares_svc._dns_sd_advertised", return_value=True,
            ) as browse,
        ):
            status = shares_svc.time_machine_status(shares)
            # Second read within the memo TTL: the answer is served from
            # cache, so GET /api/shares no longer pays the browse each time.
            shares_svc.time_machine_status(shares)
        browse.assert_called_once_with("_adisk._tcp")
        self.assertEqual(status, {
            "share_count": 1,
            "smb_service_running": False,
            "adisk_advertised": True,
        })

    def test_browse_returns_as_soon_as_an_add_row_arrives(self):
        """dns-sd never exits on its own, so waiting out the full window on
        every call held the shares page 2.5s even when sharingd had already
        answered in the first millisecond.  The first Add row ends the wait."""
        import time as _time

        class _FakeDnsSd:
            def __init__(self):
                def lines():
                    yield "16:49:48.386  Add        3   1 local.               _adisk._tcp.         MacBook Pro\n"
                    _time.sleep(3)  # the browse never ends by itself
                    yield "never reached\n"
                self.stdout = lines()
                self.pid = 4242
            def kill(self):
                pass
            def wait(self, timeout=None):
                return 0

        with patch("hub.shares_svc.subprocess.Popen", lambda *a, **kw: _FakeDnsSd()):
            t0 = _time.monotonic()
            answer = shares_svc._dns_sd_advertised("_adisk._tcp", wait=2.5)
            elapsed = _time.monotonic() - t0
        self.assertIs(answer, True)
        self.assertLess(elapsed, 1.0, "an early Add must end the browse early")

    def test_browse_with_no_add_rows_pays_the_window_and_reports_false(self):
        class _SilentDnsSd:
            def __init__(self):
                self.stdout = iter(["Browsing for _adisk._tcp.local.\n"])
                self.pid = 4242
            def kill(self):
                pass
            def wait(self, timeout=None):
                return 0

        with patch("hub.shares_svc.subprocess.Popen", lambda *a, **kw: _SilentDnsSd()):
            answer = shares_svc._dns_sd_advertised("_adisk._tcp", wait=0.1)
        self.assertIs(answer, False)

    def test_browse_closes_the_pipe(self):
        closed = []

        class _PipeDnsSd:
            def __init__(self):
                self.stdout = type("S", (), {
                    "__iter__": lambda self: iter(["Browsing\n"]),
                    "close": lambda self: closed.append(True),
                })()
                self.pid = 7
            def kill(self):
                pass
            def wait(self, timeout=None):
                return 0

        with patch("hub.shares_svc.subprocess.Popen", lambda *a, **kw: _PipeDnsSd()):
            shares_svc._dns_sd_advertised("_adisk._tcp", wait=0.05)
        self.assertTrue(closed, "dns-sd stdout was left open")

    def test_browse_spawn_failure_reports_none_not_false(self):
        with patch("hub.shares_svc.subprocess.Popen", side_effect=OSError("no dns-sd")):
            self.assertIsNone(shares_svc._dns_sd_advertised("_adisk._tcp", wait=0.1))

    def test_browse_spawn_valueerror_reports_none_not_500(self):
        """Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError."""
        with patch(
            "hub.shares_svc.subprocess.Popen",
            side_effect=UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"),
        ):
            self.assertIsNone(shares_svc._dns_sd_advertised("_adisk._tcp", wait=0.1))

    def test_browse_passes_utf8_env(self):
        source = Path(shares_svc.__file__).read_text(encoding="utf-8")
        start = source.index("def _dns_sd_advertised")
        body = source[start: source.index("\n@ttl_memo", start)]
        self.assertIn("env=utf8_env()", body)

    def test_browse_uses_a_new_session(self):
        source = Path(shares_svc.__file__).read_text(encoding="utf-8")
        start = source.index("def _dns_sd_advertised")
        body = source[start: source.index("\n@ttl_memo", start)]
        self.assertIn("start_new_session=True", body)
        self.assertIn("killpg", body)
        self.assertIn("iter_capped_lines", body)
        self.assertIn('errors="replace"', body)

    def test_browse_does_not_buffer_an_unbounded_line(self):
        """``for line in stdout`` kept a leftover huge dns-sd row in RAM."""
        closed = []
        chunks = ["x" * 4096, "Add leftover\n"]

        class _CappedPipe:
            def readline(self, n=-1):
                return chunks.pop(0) if chunks else ""

            def __iter__(self):
                raise AssertionError("unbounded for-line on dns-sd stdout")

            def close(self):
                closed.append(True)

        class _HugeDnsSd:
            def __init__(self):
                self.stdout = _CappedPipe()
                self.pid = 9

            def kill(self):
                pass

            def wait(self, timeout=None):
                return 0

        with patch("hub.shares_svc.subprocess.Popen", lambda *a, **kw: _HugeDnsSd()):
            answer = shares_svc._dns_sd_advertised("_adisk._tcp", wait=0.05)
        self.assertIs(answer, False)
        self.assertTrue(closed)


class HealthCheckTests(unittest.TestCase):
    def test_silent_when_no_share_carries_the_flag(self):
        from hub import health_svc

        with patch(
            "hub.shares_svc.time_machine_records",
            return_value={"Plain": {"time_machine": False, "tm_quota_gb": None, "uuid": None}},
        ):
            self.assertEqual(health_svc._time_machine_checks(), [])

    def test_warns_when_a_tm_share_exists_but_smbd_is_down(self):
        from hub import health_svc

        records = {"Backups": {"time_machine": True, "tm_quota_gb": None, "uuid": "X"}}
        with (
            patch("hub.shares_svc.time_machine_records", return_value=records),
            patch("hub.shares_svc.smb_service_running", return_value=False),
        ):
            checks = health_svc._time_machine_checks()
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["id"], "tm_share_smb")
        self.assertEqual(checks[0]["level"], "warn")
        self.assertFalse(checks[0]["ok"])

    def test_ok_when_smbd_serves_the_flagged_share(self):
        from hub import health_svc

        records = {"Backups": {"time_machine": True, "tm_quota_gb": 500, "uuid": "X"}}
        with (
            patch("hub.shares_svc.time_machine_records", return_value=records),
            patch("hub.shares_svc.smb_service_running", return_value=True),
        ):
            checks = health_svc._time_machine_checks()
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["ok"])
        self.assertEqual(checks[0]["level"], "ok")


if __name__ == "__main__":
    unittest.main()
