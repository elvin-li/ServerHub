"""A disk alert that cries wolf is worse than no disk alert at all.

The SMART checks in :mod:`hub.alerts` exist to catch a dying disk before it takes
data with it.  That only works if the operator still trusts them by the time it
happens, which puts two requirements ahead of sensitivity:

* **Raw counters are not a verdict.** The external SSD on the host this was built
  for reports ``Reallocated_Sector_Ct`` raw 55, while the same attribute's
  *normalised* value is 100 against a vendor threshold of 10 and the drive answers
  ``PASSED``.  A rule of "raw > 0 means failing" announces an imminent failure on
  day one, on a healthy disk.  The vendor's own threshold is the verdict; the raw
  count is something to watch.
* **Unreadable is not broken.** macOS gives userspace no ATA/SCSI passthrough over
  USB or Thunderbolt bridges, so smartctl answers "not supported by device" for a
  perfectly good external disk.  Alerting on that means every Mac with a backup
  drive attached alerts forever.

The rest of this file pins the state machine, because its failure modes are silent:
a key that is not carried across a sweep re-announces the same fault every 300s,
and a key derived from ``diskN`` changes across a reboot so an alert never resolves
and the "new" disk is announced again.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import alerts  # noqa: E402

#: The thresholds the checks are written against, pinned here so a change to the
#: shipped defaults cannot quietly move what these tests assert.
THRESHOLDS = {
    "enabled": True,
    "cooldown_sec": 1800,
    "smart_enabled": True,
    "smart_temp_c": 60,
    "smart_wear_pct": 90,
    "smart_spare_pct": 10,
}


def disk(**smart) -> dict:
    """One healthy internal NVMe, with *smart* merged over it."""
    base = {
        "health": "PASSED",
        "temp": "37 Celsius",
        "wear": "0%",
        "serial": "SN-INTERNAL",
        "model": "APPLE SSD AP1024R",
        "critical_warning": "0x00",
        "available_spare": "100%",
        "media_errors": "0",
    }
    base.update(smart)
    return {
        "id": "disk0",
        "device": "/dev/disk0",
        "name": "APPLE SSD AP1024R",
        "size_bytes": 1000555581440,
        "error": None,
        "smart": base,
    }


#: The external SATA SSD exactly as the real host reports it: a scary-looking raw
#: count, and a drive that considers itself fine.
REAL_EXTERNAL_DISK = {
    "id": "disk4",
    "device": "/dev/disk4",
    "name": "MR001920GWFMB",
    "size_bytes": 1920383410176,
    "error": None,
    "smart": {
        "health": "PASSED",
        "temp": "52 Celsius",
        "serial": "17041816B155",
        "model": "MR001920GWFMB",
        "reallocated": "55",
        "attrs": [
            {"id": 5, "name": "Reallocated_Sector_Ct", "value": "100",
             "worst": "100", "thresh": "010", "type": "Pre-fail", "raw": "55"},
            {"id": 194, "name": "Temperature_Celsius", "value": "048",
             "worst": "023", "thresh": "000", "type": "Old_age", "raw": "52"},
        ],
    },
}


class SmartAlertCase(unittest.TestCase):
    """Base class that makes a sweep observable without touching the real host.

    Every guard here has a specific reason.  ``smart_devices`` is patched because
    the real one shells out to smartctl.  ``send_ha_notify`` is patched to *raise*
    rather than to a no-op, so a test that accidentally satisfies the notification
    gate fails loudly instead of quietly pushing to the operator's phone.  And the
    two journal paths are redirected into a temporary directory: this suite runs on
    the machine ServerHub is serving, and writing the repository's real
    ``data/alerts.jsonl`` would put fabricated disk failures in front of the user.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        patches = [
            mock.patch.object(alerts, "ALERTS_FILE", tmp / "alerts.jsonl"),
            mock.patch.object(alerts, "STATE_FILE", tmp / "alert_state.json"),
            mock.patch.object(alerts, "_resource_thresholds", lambda: dict(THRESHOLDS)),
            # check_once() also runs the CPU/memory/disk sweep, and that one
            # reads the real host.  This suite runs on the machine ServerHub
            # is serving, so a busy machine injected a genuine "CPU 100% ≥ 90%"
            # warning into assertions that enumerate every emitted alert --
            # green on an idle laptop, red under load, for no reason connected
            # to SMART.  Nothing in this file asserts resource alerts.
            mock.patch.object(
                alerts, "_check_resource_thresholds",
                lambda prev, new_state, now: [],
            ),
            mock.patch.object(alerts, "notify_settings", lambda: {"enabled": False}),
            mock.patch.object(
                alerts, "send_ha_notify",
                mock.Mock(side_effect=AssertionError("a test must never notify")),
            ),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self._tmp.cleanup)

    def sweep(self, devices, prev=None, now=None):
        """``(emitted, new_state)`` for one SMART pass over *devices*."""
        state: dict = {}
        with mock.patch("hub.storage_svc.smart_devices", lambda: devices):
            emitted = alerts._check_smart_health(
                dict(prev or {}), state, int(now if now is not None else time.time())
            )
        return emitted, state

    def levels(self, devices, prev=None, now=None) -> list[str]:
        emitted, _ = self.sweep(devices, prev=prev, now=now)
        return [a["level"] for a in emitted]

    def one(self, devices, prev=None, now=None) -> dict:
        emitted, _ = self.sweep(devices, prev=prev, now=now)
        self.assertEqual(len(emitted), 1, f"expected exactly one alert, got {emitted}")
        return emitted[0]


class FalsePositiveTests(SmartAlertCase):
    """The two ways this feature can destroy its own credibility."""

    def test_a_reallocated_count_the_drive_accepts_is_not_a_failure(self):
        """The real external SSD: raw 55, normalised 100, threshold 10, PASSED.

        Reported as ``down`` this is a false alarm on a working disk, and an
        operator who is shown one stops reading disk alerts. The count is still
        worth surfacing, so it is a ``warn``.
        """
        alert = self.one([REAL_EXTERNAL_DISK])
        self.assertEqual(alert["level"], "warn")
        self.assertIn("55", alert["detail"])

    def test_the_same_count_is_fatal_once_the_vendor_threshold_is_crossed(self):
        """Severity comes from the drive's own margin, not from the raw number."""
        dying = json.loads(json.dumps(REAL_EXTERNAL_DISK))
        dying["smart"]["attrs"][0].update(value="8", worst="8")
        self.assertEqual(self.one([dying])["level"], "down")

    def test_a_vendor_threshold_of_zero_is_not_a_threshold(self):
        """``thresh=000`` means the vendor declared no failure point.

        Comparing ``value <= 0`` against it would make every ``Old_age`` style
        attribute with a low normalised value look like an imminent failure.
        """
        odd = disk(attrs=[
            {"id": 194, "name": "Temperature_Celsius", "value": "0", "worst": "0",
             "thresh": "000", "type": "Pre-fail", "raw": "52"},
        ])
        self.assertEqual(self.levels([odd]), [])

    def test_a_disk_whose_smart_cannot_be_read_is_not_a_disk_that_is_failing(self):
        """External enclosures on macOS answer "not supported by device"."""
        opaque = {
            "id": "disk6", "device": "/dev/disk6", "name": "Backup",
            "size_bytes": 2000000000000, "smart": None,
            "error": "外置 USB/雷雳硬盘：macOS 不提供 SMART 直通，无法读取（非磁盘故障）",
        }
        emitted, state = self.sweep([opaque])
        self.assertEqual(emitted, [])
        self.assertEqual(
            [k for k in state if k != "_smart_last"], [],
            "an unreadable disk must not get a state key either -- otherwise the "
            "next readable sweep looks like a recovery from a fault it never had",
        )


class SeverityTests(SmartAlertCase):
    """Which readings are fatal, which are worth watching."""

    def test_the_drives_own_verdict_is_fatal(self):
        for health in ("FAILED!", "WARNING"):
            with self.subTest(health=health):
                self.assertEqual(self.one([disk(health=health)])["level"], "down")

    def test_media_errors_are_fatal(self):
        self.assertEqual(self.one([disk(media_errors="3")])["level"], "down")

    def test_pending_sectors_are_fatal_at_one(self):
        """A pending sector is data that cannot be read *now*, unlike a remapped one."""
        self.assertEqual(self.one([disk(pending="1")])["level"], "down")

    def test_a_hex_critical_warning_is_not_read_as_zero(self):
        """``0x02`` is "spare below threshold"; a decimal scan reads it as 0.

        That silently dropped the whole NVMe critical-warning check.
        """
        self.assertEqual(alerts._smart_num("0x02"), 2.0)
        self.assertEqual(self.one([disk(critical_warning="0x02")])["level"], "down")

    def test_temperature_and_wear_warn_at_their_thresholds(self):
        self.assertEqual(self.one([disk(temp="72 Celsius")])["level"], "warn")
        self.assertEqual(self.one([disk(wear="94%")])["level"], "warn")

    def test_available_spare_is_a_floor_not_a_ceiling(self):
        """It counts *down* from 100%, so a full pool must not look like a fault."""
        self.assertEqual(self.levels([disk(available_spare="100%")]), [])
        self.assertEqual(self.one([disk(available_spare="7%")])["level"], "warn")

    def test_a_disk_with_several_faults_still_gets_one_alert(self):
        """Five rows for one disk would bury every other disk on the page."""
        alert = self.one([disk(
            health="FAILED!", media_errors="3", temp="81 Celsius", wear="97%",
        )])
        self.assertEqual(alert["level"], "down")
        for fragment in ("FAILED!", "3", "81", "97"):
            self.assertIn(fragment, alert["detail"])


class StateMachineTests(SmartAlertCase):
    """Debounce, recovery, and the carry-over that makes both work."""

    def test_a_healthy_disk_is_recorded_but_not_announced(self):
        emitted, state = self.sweep([disk()])
        self.assertEqual(emitted, [])
        self.assertEqual(state["smart:SN-INTERNAL"], "ok")

    def test_a_disk_that_is_already_failing_the_first_time_it_is_seen_is_reported(self):
        """Deliberately unlike the service loop, which skips an unknown id.

        A service with no history is skipped so a fresh state file does not
        re-announce everything; a service can also be restarted. A disk cannot. If
        the first SMART read ever taken says FAILED, the disk is losing data now,
        and a state file that happens to be new is not a reason to stay quiet.
        """
        self.assertEqual(self.levels([disk(health="FAILED!")], prev={}), ["down"])

    def test_an_unchanged_fault_is_not_re_announced_inside_the_cooldown(self):
        now = 1_800_000
        prev = {"smart:SN-INTERNAL": "down", "_smart_last": {"SN-INTERNAL": now - 600}}
        self.assertEqual(self.levels([disk(health="FAILED!")], prev=prev, now=now), [])

    def test_an_unchanged_fault_is_re_announced_once_the_cooldown_elapses(self):
        now = 1_800_000
        prev = {"smart:SN-INTERNAL": "down", "_smart_last": {"SN-INTERNAL": now - 1900}}
        emitted, state = self.sweep([disk(health="FAILED!")], prev=prev, now=now)
        self.assertEqual([a["level"] for a in emitted], ["down"])
        self.assertEqual(state["_smart_last"]["SN-INTERNAL"], now)

    def test_recovery_is_announced_and_drops_the_cooldown_stamp(self):
        """Otherwise ``_smart_last`` grows for every disk ever seen."""
        prev = {"smart:SN-INTERNAL": "down", "_smart_last": {"SN-INTERNAL": 1}}
        emitted, state = self.sweep([disk()], prev=prev)
        self.assertEqual([(a["level"], a["event"]) for a in emitted],
                         [("ok", "resolved")])
        self.assertNotIn("SN-INTERNAL", state["_smart_last"])

    def test_the_cooldown_map_survives_a_full_sweep(self):
        """``check_once`` rebuilds its state dict from empty every pass.

        Only explicitly carried keys survive. If ``_smart_last`` is not one of
        them the debounce resets every interval, and a failing disk is announced
        again on every sweep -- every 300s on the shipped configuration.
        """
        devices = [disk(health="FAILED!")]
        with (
            mock.patch.object(alerts, "full_status", lambda force=False: {"groups": []}),
            mock.patch("hub.storage_svc.smart_devices", lambda: devices),
        ):
            first = alerts.check_once()
            saved = json.loads(Path(alerts.STATE_FILE).read_text())
            second = alerts.check_once()

        self.assertEqual([a["level"] for a in first], ["down"])
        self.assertIn("SN-INTERNAL", saved.get("_smart_last", {}))
        self.assertEqual(second, [], "the fault was announced twice in a row")
        after = json.loads(Path(alerts.STATE_FILE).read_text())
        self.assertIn("SN-INTERNAL", after.get("_smart_last", {}))
        self.assertEqual(after["smart:SN-INTERNAL"], "down")


class SwitchTests(SmartAlertCase):
    """SMART has its own switch, on purpose."""

    def test_its_own_switch_turns_it_off(self):
        thresholds = dict(THRESHOLDS, smart_enabled=False)
        with mock.patch.object(alerts, "_resource_thresholds", lambda: thresholds):
            emitted, state = self.sweep([disk(health="FAILED!")])
        self.assertEqual(emitted, [])
        self.assertEqual([k for k in state if k != "_smart_last"], [])

    def test_the_resource_switch_does_not_silence_it(self):
        """``enabled`` mutes CPU/memory/disk-usage noise during a big build.

        A disk reporting FAILED is not that kind of noise and must not disappear
        with the same click.
        """
        thresholds = dict(THRESHOLDS, enabled=False)
        with mock.patch.object(alerts, "_resource_thresholds", lambda: thresholds):
            self.assertEqual(self.levels([disk(health="FAILED!")]), ["down"])


class IdentityTests(SmartAlertCase):
    """The key has to name the disk, not the slot it happened to enumerate into."""

    def test_the_serial_number_is_preferred(self):
        self.assertEqual(alerts._smart_key(disk()), "SN-INTERNAL")

    def test_the_key_survives_a_renumbered_device_node(self):
        """macOS hands out ``diskN`` in enumeration order.

        Keyed on that, a reboot makes one key vanish -- its alert never resolving --
        and an identical disk appear under a new key, re-announcing the same fault.
        """
        moved = disk()
        moved["id"], moved["device"] = "disk7", "/dev/disk7"
        self.assertEqual(alerts._smart_key(moved), alerts._smart_key(disk()))

    def test_model_and_capacity_stand_in_for_a_missing_serial(self):
        anonymous = disk()
        anonymous["smart"].pop("serial")
        key = alerts._smart_key(anonymous)
        self.assertIn("APPLE-SSD-AP1024R", key)
        self.assertIn("1000555581440", key)

    def test_the_device_node_is_the_last_resort(self):
        bare = {"id": "disk9", "device": "/dev/disk9", "size_bytes": None,
                "error": None, "smart": {"health": "PASSED"}}
        self.assertEqual(alerts._smart_key(bare), "disk9")

    def test_separators_are_normalised_out_of_the_key(self):
        """The key becomes a JSON object key and part of an alert id."""
        messy = disk(serial="AB 12/34:56")
        self.assertEqual(alerts._smart_key(messy), "AB-12-34-56")


class FieldParsingTests(unittest.TestCase):
    """Nothing smartctl prints is a number."""

    def test_the_shapes_smartctl_actually_emits(self):
        for raw, expected in (
            ("37 Celsius", 37.0), ("0%", 0.0), ("100%", 100.0),
            ("0", 0.0), ("0x00", 0.0), ("0x02", 2.0), ("1,234", 1234.0),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(alerts._smart_num(raw), expected)

    def test_unreadable_is_none_and_never_zero(self):
        """"No value" and "zero" mean opposite things here.

        0 media errors is a healthy disk; an unparseable media-error field is a
        disk nothing is known about. Defaulting to 0.0 would report the second as
        the first.
        """
        for raw in (None, "", "   ", "-", "N/A", True):
            with self.subTest(raw=raw):
                self.assertIsNone(alerts._smart_num(raw))

    def test_an_unreadable_field_skips_its_check_rather_than_passing_it(self):
        case = SmartAlertCase("run")
        case.setUp()
        try:
            self.assertEqual(case.levels([disk(temp="N/A", media_errors="unknown")]), [])
        finally:
            case.doCleanups()


if __name__ == "__main__":
    unittest.main()
