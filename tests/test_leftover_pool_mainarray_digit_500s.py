"""Leftover >4300-digit ints on the Pool and Main Array storage endpoints.

Prior passes pinned the 400-digit class: ``int()`` succeeded and the GB
conversion OverflowError'd, which the storage services already catch.
CPython additionally refuses int->str past 4300 digits with ValueError, and
``json.dumps`` performs exactly that conversion — so a leftover plist Size /
SMART history int / SnapshotXID / volume total that was *already an int* rode
through every ``int()`` guard unchanged and 500'd Starlette's
``allow_nan=False`` encoder on GET /api/storage, /api/storage/manage,
/api/raid, /api/smart and /api/snapshots.

The Pool overview (GET /api/storage/pool) already coerces every numeric and
string field through ``_finite_*`` / ``_text``, so this battery pins that it
stays immune.  Its one leftover was on the write side: ``str(mount)`` /
``str(name)`` in plan/save raised the bare digit-cap ValueError instead of
the coded refusal every other junk mount gets, and a leftover ``\\ud800``
pool name was persisted raw into services.yaml instead of scrubbed.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import (
    disk_manage_svc,
    raid_svc,
    smart_test_svc,
    snapshots_svc,
    storage_pool_svc,
    storage_svc,
)

#: Past CPython's default 4300-digit int<->str conversion limit.  A valid
#: Python int — every ``isinstance(x, int)`` fast path accepts it — that
#: ``json.dumps`` cannot render.
_HUGE_INT = 10 ** 5000
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


_VAULT = {
    "device": "/dev/disk6s1",
    "mount": "/Volumes/Vault",
    "kind": "external",
    "total_gb": 10,
    "used_gb": 1,
    "avail_gb": 9,
    "pct": 10,
    "disk_id": "disk6",
    "filesystem": "apfs",
}


class PoolOverviewDigitLimitPinTests(unittest.TestCase):
    """GET /api/storage/pool already coerces this class; keep it that way."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_huge_int_yaml_pool_fields_do_not_500(self):
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=[dict(_VAULT)]),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": _HUGE_INT,
                    "members": [_HUGE_INT, "/Volumes/Vault"],
                    "policy": _HUGE_INT,
                    "min_free_gb": _HUGE_INT,
                }}},
            ),
        ):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        self.assertEqual(overview["name"], "pool")
        self.assertEqual([m["mount"] for m in overview["members"]], ["/Volumes/Vault"])

    def test_huge_int_volume_fields_do_not_500(self):
        vol = dict(_VAULT, total_gb=_HUGE_INT, used_gb=_HUGE_INT,
                   avail_gb=_HUGE_INT, pct=_HUGE_INT)
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=[vol]),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "members": ["/Volumes/Vault"], "policy": "most-free",
                    "name": "pool",
                }}},
            ),
        ):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        member = overview["members"][0]
        self.assertEqual(member["total_gb"], 0.0)
        self.assertEqual(member["pct"], 0)
        self.assertEqual(overview["summary"]["total_gb"], 0.0)

    def test_huge_digit_string_volume_fields_do_not_500(self):
        vol = dict(_VAULT, total_gb=_HUGE_DIGITS, pct=_HUGE_DIGITS)
        with mock.patch.object(storage_svc, "list_volumes", return_value=[vol]):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        row = overview["unassigned"][0]
        self.assertEqual(row["total_gb"], 0.0)
        self.assertEqual(row["pct"], 0)


class PoolValidateDigitLimitTests(unittest.TestCase):
    """plan/save used to raise the bare digit-cap ValueError out of str()."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        vols = mock.patch.object(
            storage_svc, "list_volumes", return_value=[dict(_VAULT)]
        )
        vols.start()
        self.addCleanup(vols.stop)

        self.settings: dict = {}

        def fake_update(patch: dict) -> dict:
            self.settings.update(patch)
            return self.settings

        upd = mock.patch.object(
            storage_pool_svc, "update_settings", side_effect=fake_update
        )
        upd.start()
        self.addCleanup(upd.stop)
        cfgp = mock.patch.object(
            storage_pool_svc, "cfg", side_effect=lambda: {"settings": self.settings}
        )
        cfgp.start()
        self.addCleanup(cfgp.stop)

    def test_huge_int_mount_is_coded_not_500(self):
        """``str(10**5000)`` ValueError'd POST /api/storage/pool/plan."""
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.plan_pool([_HUGE_INT])
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.no_members")

    def test_huge_int_name_saves_the_default_not_500(self):
        out = storage_pool_svc.save_pool(
            ["/Volumes/Vault"], name=_HUGE_INT, min_free_gb=_HUGE_INT
        )
        _starlette(out)
        self.assertEqual(self.settings["storage_pool"]["name"], "pool")
        self.assertEqual(self.settings["storage_pool"]["min_free_gb"], 0.0)

    def test_surrogate_name_is_scrubbed_before_persist(self):
        """A leftover ``\\ud800`` name was written raw into services.yaml."""
        out = storage_pool_svc.save_pool(["/Volumes/Vault"], name="va\ud800ult")
        _starlette(out)
        saved = self.settings["storage_pool"]["name"]
        self.assertNotIn("\ud800", saved)
        self.assertNotIn("\ud800", out["name"])
        saved.encode("utf-8")


class StorageOverviewDigitLimitTests(unittest.TestCase):
    def test_huge_int_volume_totals_do_not_500(self):
        """A leftover >4300-digit total rode the int fast path to the encoder."""
        vol = dict(_VAULT, total_gb=_HUGE_INT, pct=_HUGE_INT)
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=[vol]),
            mock.patch.object(storage_svc, "smart_devices", return_value=[]),
        ):
            overview = storage_svc.storage_overview()
        _starlette(overview)
        row = next(v for v in overview["volumes"] if v["mount"] == "/Volumes/Vault")
        self.assertEqual(row["total_gb"], 0.0)
        self.assertEqual(row["pct"], 0)

    def test_huge_int_smart_attr_does_not_500(self):
        disk = {
            "device": "/dev/disk0", "id": "disk0", "name": "disk0",
            "size_bytes": _HUGE_INT,
            "smart": {"attrs": [{"id": 5, "name": "Reallocated", "raw": _HUGE_INT}]},
        }
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=[dict(_VAULT)]),
            mock.patch.object(storage_svc, "smart_devices", return_value=[disk]),
        ):
            overview = storage_svc.storage_overview()
        _starlette(overview)
        cleaned = overview["disks"][0]
        self.assertIsNone(cleaned["size_bytes"])
        self.assertIsNone(cleaned["smart"]["attrs"][0]["raw"])

    def test_json_helpers_drop_the_over_cap_int(self):
        self.assertIsNone(storage_svc._jsonable(_HUGE_INT))
        self.assertEqual(storage_svc._json_int(_HUGE_INT), 0)
        _starlette(storage_svc._jsonable({"n": _HUGE_INT, "ok": 12}))


class ManagedVolumesDigitLimitTests(unittest.TestCase):
    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    def test_huge_int_plist_size_does_not_500(self):
        """The 400-digit pin lost size_gb; >4300 digits still 500'd size_bytes."""
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": _HUGE_INT}
            ]
        }
        with (
            mock.patch.object(disk_manage_svc, "_plist", lambda *a, **k: tree),
            mock.patch.object(
                disk_manage_svc, "physical_whole_disks", return_value=("disk4",)
            ),
            mock.patch.object(disk_manage_svc, "root_devices", return_value=set()),
            mock.patch.object(disk_manage_svc, "root_info", return_value={}),
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X", "MountPoint": "/Volumes/X"},
            ),
            mock.patch.object(disk_manage_svc, "_prefetch_disk_info", lambda n: None),
        ):
            vols = disk_manage_svc.list_managed_volumes()
        row = next(v for v in vols if v["id"] == "disk4")
        self.assertEqual(row["size_bytes"], 0)
        self.assertIsNone(row["size_gb"])
        _starlette(vols)


class RaidDigitLimitTests(unittest.TestCase):
    def test_huge_int_set_and_member_size_do_not_500(self):
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror",
                "Level": "mirror",
                "Status": "Online",
                "Size": _HUGE_INT,
                "AppleRAIDMembers": [{
                    "AppleRAIDMemberUUID": "m1",
                    "MemberStatus": "Online",
                    "Size": _HUGE_INT,
                }],
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertIsNone(sets[0]["size_bytes"])
        self.assertIsNone(sets[0]["members"][0]["size_bytes"])
        _starlette(sets)

    def test_huge_int_admin_payload_does_not_500_delete(self):
        with (
            mock.patch.object(
                raid_svc, "list_sets",
                return_value=[{
                    "uuid": "abcd1234", "name": "Mirror", "level": "mirror",
                    "members": [],
                }],
            ),
            mock.patch.object(raid_svc, "invalidate"),
            mock.patch.object(
                raid_svc, "run_admin",
                return_value={"ok": True, "message": "deleted", "n": _HUGE_INT},
            ),
        ):
            out = raid_svc.delete_set(
                set_uuid="abcd1234", confirm=True, confirm_phrase="Mirror",
            )
        self.assertTrue(out["ok"])
        self.assertIsNone(out["n"])
        _starlette(out)


class SnapshotsDigitLimitTests(unittest.TestCase):
    def test_huge_int_xid_does_not_500(self):
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local",
                "SnapshotUUID": "u",
                "SnapshotXID": _HUGE_INT,
            }]
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertIsNone(items[0]["xid"])
        _starlette(items)

    def test_surrogate_xid_string_does_not_500(self):
        """A ``\\ud800`` XID string passed through where names were scrubbed."""
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local",
                "SnapshotUUID": "u",
                "SnapshotXID": "7\ud800",
            }]
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertNotIn("\ud800", items[0]["xid"])
        _starlette(items)

    def test_huge_int_admin_payload_does_not_500_delete(self):
        with (
            mock.patch.object(snapshots_svc, "invalidate"),
            mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True, "message": "deleted", "n": _HUGE_INT},
            ),
        ):
            out = snapshots_svc.delete_snapshot("/", "2026-08-03-160000")
        self.assertTrue(out["ok"])
        self.assertIsNone(out["n"])
        _starlette(out)


class SmartDigitLimitTests(unittest.TestCase):
    def test_huge_int_history_field_does_not_500(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{"ok": True, "ts": 12, "extra": _HUGE_INT}],
        ):
            rows = smart_test_svc.history(10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ts"], 12)
        self.assertIsNone(rows[0]["extra"])
        _starlette(rows)

    def test_huge_int_abort_admin_payload_does_not_500(self):
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]
            ),
            mock.patch.object(smart_test_svc, "device_type", return_value=()),
            mock.patch.object(smart_test_svc, "invalidate"),
            mock.patch.object(
                smart_test_svc, "sh", return_value=(1, "", "permission denied")
            ),
            mock.patch.object(
                smart_test_svc, "run_admin",
                return_value={"ok": True, "message": "aborted", "n": _HUGE_INT},
            ),
        ):
            out = smart_test_svc.abort_test("/dev/disk0")
        self.assertTrue(out["ok"])
        self.assertIsNone(out["n"])
        _starlette(out)


if __name__ == "__main__":
    unittest.main()
