"""Leftover disk/storage/share parse and type 500s.

Plist fields that are not the dict/list/str the walk assumed, a df Capacity
of "-" on a 0-block mount, a non-string rename, and a NUL in a share path
each used to escape as an unhandled exception instead of a coded error or an
empty row.

Follow-up: leftover bytes/None from ``diskutil list`` / ``smartctl -t``
used to TypeError GET /api/smart and POST /api/smart/test.

Follow-up: leftover ``\\ud800`` in df mounts / plist names / YAML pool
fields 500'd Starlette's UTF-8 encode; two leftover ``1e308`` pool members
summed to inf and OverflowError'd GET /api/storage/pool.

Follow-up: leftover finite ``1e308`` Time Machine Percent overflowed ``* 100``
to inf; two leftover ``1e308`` volumes summed to inf on GET /api/storage;
probe ``str(e)`` / ``run_admin`` leftover ``\\ud800`` still 500'd SMART, RAID,
and snapshot mutations.
"""
from __future__ import annotations

import datetime
import errno
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import (
    disk_manage_svc,
    disk_power_svc,
    disk_snapshot,
    raid_svc,
    smart_test_svc,
    snapshots_svc,
    storage_pool_svc,
    storage_svc,
    usage_svc,
)
from hub.routers import shares as shares_router
from hub.routers import storage as storage_router


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class DfPercentParseTests(unittest.TestCase):
    def test_zero_block_dash_capacity_does_not_500(self):
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "foo 0 0 0 - /Volumes/Zero\n"
            "/dev/disk4s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        with mock.patch.object(
            storage_svc, "df_lines", return_value=tuple(df.splitlines())
        ):
            vols = storage_svc.list_volumes()
        mounts = [v["mount"] for v in vols]
        self.assertNotIn("/Volumes/Zero", mounts)
        self.assertIn("/Volumes/Data", mounts)
        self.assertEqual(
            next(v["pct"] for v in vols if v["mount"] == "/Volumes/Data"), 50
        )

    def test_fractional_capacity_is_not_dropped(self):
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/disk4s1 104857600 52428800 52428800 50.5% /Volumes/Half\n"
        )
        with mock.patch.object(
            storage_svc, "df_lines", return_value=tuple(df.splitlines())
        ):
            vols = storage_svc.list_volumes()
        half = next(v for v in vols if v["mount"] == "/Volumes/Half")
        self.assertEqual(half["pct"], 50)

    def test_infinite_capacity_does_not_500(self):
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/disk4s1 104857600 52428800 52428800 inf% /Volumes/Inf\n"
            "/dev/disk5s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        with mock.patch.object(
            storage_svc, "df_lines", return_value=tuple(df.splitlines())
        ):
            vols = storage_svc.list_volumes()
        inf_row = next(v for v in vols if v["mount"] == "/Volumes/Inf")
        self.assertEqual(inf_row["pct"], 50)
        json.dumps(vols, allow_nan=False)

    def test_huge_block_count_does_not_500(self):
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            f"/dev/disk4s1 {'9' * 400} 1 1 1% /Volumes/Huge\n"
            "/dev/disk5s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        with mock.patch.object(
            storage_svc, "df_lines", return_value=tuple(df.splitlines())
        ):
            vols = storage_svc.list_volumes()
        mounts = [v["mount"] for v in vols]
        self.assertNotIn("/Volumes/Huge", mounts)
        self.assertIn("/Volumes/Data", mounts)
        json.dumps(vols, allow_nan=False)

    def test_huge_root_disk_usage_fallback_does_not_500(self):
        """``du.total / 2**30`` OverflowError'd the `/` fallback on GET /api/storage."""
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/disk4s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        du = type("DU", (), {"total": 10 ** 400, "used": 10 ** 400, "free": 0})()
        with (
            mock.patch.object(
                storage_svc, "df_lines", return_value=tuple(df.splitlines())
            ),
            mock.patch.object(storage_svc.shutil, "disk_usage", return_value=du),
        ):
            vols = storage_svc.list_volumes()
        mounts = [v["mount"] for v in vols]
        self.assertNotIn("/", mounts)
        self.assertIn("/Volumes/Data", mounts)
        json.dumps(vols, allow_nan=False)

    def test_df_bytes_output_does_not_500(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        df = (
            b"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            b"/dev/disk4s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        with mock.patch.object(disk_snapshot, "sh", return_value=(0, df, "")):
            vols = storage_svc.list_volumes()
        self.assertIn("/Volumes/Data", [v["mount"] for v in vols])
        json.dumps(vols, allow_nan=False)

    def test_path_home_nul_does_not_500(self):
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/disk0s1 104857600 1 1 1% /System/Volumes/Preboot\n"
            "/dev/disk4s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        with (
            mock.patch.object(
                storage_svc, "df_lines", return_value=tuple(df.splitlines())
            ),
            mock.patch.object(
                Path, "home", side_effect=ValueError("embedded null byte")
            ),
        ):
            vols = storage_svc.list_volumes()
        mounts = [v["mount"] for v in vols]
        self.assertNotIn("/System/Volumes/Preboot", mounts)
        self.assertIn("/Volumes/Data", mounts)
        json.dumps(vols, allow_nan=False)

    def test_path_home_unresolved_does_not_500(self):
        """HOME unset RuntimeError'd Path.home() and 500'd GET /api/storage."""
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/disk0s1 104857600 1 1 1% /System/Volumes/Preboot\n"
            "/dev/disk4s1 104857600 52428800 52428800 50% /Volumes/Data\n"
        )
        with (
            mock.patch.object(
                storage_svc, "df_lines", return_value=tuple(df.splitlines())
            ),
            mock.patch.object(Path, "home", side_effect=RuntimeError("no home")),
        ):
            vols = storage_svc.list_volumes()
        mounts = [v["mount"] for v in vols]
        self.assertNotIn("/System/Volumes/Preboot", mounts)
        self.assertIn("/Volumes/Data", mounts)
        json.dumps(vols, allow_nan=False)

    def test_zero_disk_usage_total_does_not_500(self):
        import collections

        DU = collections.namedtuple("Usage", "total used free")
        with (
            mock.patch.object(
                storage_svc, "df_lines", return_value=("Filesystem",)
            ),
            mock.patch.object(
                storage_svc.shutil, "disk_usage", return_value=DU(0, 0, 0)
            ),
        ):
            vols = storage_svc.list_volumes()
        self.assertFalse(any(v["mount"] == "/" for v in vols))

    def test_leftover_surrogate_mount_does_not_500(self):
        """FUSE leftover ``\\ud800`` in a df mount used to 500 GET /api/storage."""
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/disk4s1 104857600 52428800 52428800 50% /Volumes/Data\ud800\n"
        )
        with mock.patch.object(
            storage_svc, "df_lines", return_value=tuple(df.splitlines())
        ):
            vols = storage_svc.list_volumes()
        row = next(v for v in vols if v["mount"].startswith("/Volumes/Data"))
        _starlette(vols)
        self.assertNotIn("\ud800", row["mount"])
        self.assertNotIn("\ud800", row["filesystem"])


class DiskPlistIdentifierTests(unittest.TestCase):
    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    def _list(self, tree, root_info=None):
        with (
            mock.patch.object(disk_manage_svc, "_plist", lambda *a, **k: tree),
            mock.patch.object(
                disk_manage_svc, "physical_whole_disks", return_value=("disk4",)
            ),
            mock.patch.object(disk_manage_svc, "root_devices", return_value=set()),
            mock.patch.object(
                disk_manage_svc, "root_info", return_value=root_info or {}
            ),
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X", "MountPoint": "/Volumes/X"},
            ),
            mock.patch.object(disk_manage_svc, "_prefetch_disk_info", lambda n: None),
        ):
            return disk_manage_svc.list_managed_volumes()

    def test_array_shaped_device_identifier_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {
                    "DeviceIdentifier": ["disk4"],
                    "Size": 100,
                    "Partitions": [
                        {"DeviceIdentifier": "disk4s1", "Size": 100},
                    ],
                }
            ]
        }
        vols = self._list(tree)
        self.assertEqual({v["id"] for v in vols}, {"disk4", "disk4s1"})

    def test_array_shaped_parent_whole_disk_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": 1}
            ]
        }
        vols = self._list(tree, root_info={"ParentWholeDisk": ["disk0"]})
        self.assertTrue(any(v["id"] == "disk4" for v in vols))

    def test_array_shaped_physical_store_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": 1}
            ]
        }
        vols = self._list(tree, root_info={
            "APFSPhysicalStores": [{"APFSPhysicalStore": ["disk0s2"]}],
        })
        self.assertTrue(any(v["id"] == "disk4" for v in vols))

    def test_non_string_device_id_is_coded_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc._normalize_id(["disk4"])
        self.assertEqual(ctx.exception.detail["code"], "disk.invalid_device")

    def test_infinite_size_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": float("inf")}
            ]
        }
        vols = self._list(tree)
        row = next(v for v in vols if v["id"] == "disk4")
        self.assertEqual(row["size_bytes"], 0)
        json.dumps(vols, allow_nan=False)

    def test_non_string_rename_is_coded_not_500(self):
        with (
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X"},
            ),
            mock.patch.object(
                disk_manage_svc, "_is_system_related", return_value=False
            ),
            mock.patch.object(disk_manage_svc, "sh") as shell,
        ):
            with self.assertRaises(HTTPException) as ctx:
                disk_manage_svc.disk_action("disk4s1", "rename", name=["Backups"])
        self.assertEqual(ctx.exception.detail["code"], "disk.name_required")
        shell.assert_not_called()

    def test_huge_integer_size_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": 10**400}
            ]
        }
        vols = self._list(tree)
        row = next(v for v in vols if v["id"] == "disk4")
        self.assertIsNone(row["size_gb"])
        json.dumps(vols, allow_nan=False)

    def test_volume_name_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` VolumeName used to 500 GET /api/storage."""
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": 100}
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
                return_value={
                    "VolumeName": "Back\ud800ups",
                    "MountPoint": "/Volumes/X\ud800",
                    "MediaName": "Ext",
                },
            ),
            mock.patch.object(disk_manage_svc, "_prefetch_disk_info", lambda n: None),
        ):
            vols = disk_manage_svc.list_managed_volumes()
        row = next(v for v in vols if v["id"] == "disk4")
        self.assertNotIn("\ud800", row["name"])
        self.assertNotIn("\ud800", row["mount"])
        json.dumps(vols, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_surrogate_device_identifier_is_dropped(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4\ud800", "Size": 100},
                {"DeviceIdentifier": "disk5", "Size": 100},
            ]
        }
        vols = self._list(tree)
        self.assertEqual({v["id"] for v in vols}, {"disk5"})
        json.dumps(vols, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_rename_surrogate_name_is_coded_not_500(self):
        with (
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X", "MountPoint": "/Volumes/X"},
            ),
            mock.patch.object(
                disk_manage_svc, "_is_system_related", return_value=False
            ),
            mock.patch.object(disk_manage_svc, "sh") as shell,
        ):
            with self.assertRaises(HTTPException) as ctx:
                disk_manage_svc.disk_action("disk4s1", "rename", name="X\ud800")
        self.assertEqual(ctx.exception.detail["code"], "disk.name_required")
        shell.assert_not_called()

    def test_volume_name_inf_and_bytes_do_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk4", "Size": 100}
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
                return_value={
                    "VolumeName": float("inf"),
                    "MountPoint": b"/Volumes/X",
                    "MediaName": b"Ext",
                    "Writable": float("inf"),
                },
            ),
            mock.patch.object(disk_manage_svc, "_prefetch_disk_info", lambda n: None),
        ):
            vols = disk_manage_svc.list_managed_volumes()
        row = next(v for v in vols if v["id"] == "disk4")
        self.assertIsInstance(row["name"], str)
        self.assertIsInstance(row["mount"], str)
        self.assertIsNone(row["writable"])
        json.dumps(vols, allow_nan=False)

    def test_bytes_device_identifier_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": b"disk4", "Size": 100}
            ]
        }
        vols = self._list(tree)
        self.assertIn("disk4", {v["id"] for v in vols})
        json.dumps(vols, allow_nan=False)

    def test_bytes_mount_point_is_system_protected_not_500(self):
        with (
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"MountPoint": b"/", "VolumeName": b"Macintosh HD"},
            ),
            mock.patch.object(disk_manage_svc, "root_devices", return_value=set()),
            mock.patch.object(disk_manage_svc, "sh") as shell,
        ):
            with self.assertRaises(HTTPException) as ctx:
                disk_manage_svc.disk_action("disk4s1", "unmount")
        self.assertEqual(ctx.exception.detail["code"], "disk.system_protected")
        shell.assert_not_called()

    def test_leftover_bytes_unmount_does_not_500_json(self):
        with (
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X", "MountPoint": "/Volumes/X"},
            ),
            mock.patch.object(
                disk_manage_svc, "_is_system_related", return_value=False
            ),
            mock.patch.object(
                disk_manage_svc, "sh", return_value=(0, b"unmounted", b"")
            ),
        ):
            out = disk_manage_svc.disk_action("disk4s1", "unmount")
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["message"], str)
        json.dumps(out, allow_nan=False)

    def test_leftover_inf_unmount_does_not_500_json(self):
        with (
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X", "MountPoint": "/Volumes/X"},
            ),
            mock.patch.object(
                disk_manage_svc, "_is_system_related", return_value=False
            ),
            mock.patch.object(
                disk_manage_svc, "sh", return_value=(0, float("inf"), "")
            ),
        ):
            out = disk_manage_svc.disk_action("disk4s1", "unmount")
        json.dumps(out, allow_nan=False)

    def test_erase_nul_name_is_coded_not_500(self):
        with (
            mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "X"},
            ),
            mock.patch.object(
                disk_manage_svc, "_is_system_related", return_value=False
            ),
            mock.patch.object(disk_manage_svc, "sh") as shell,
        ):
            with self.assertRaises(HTTPException) as ctx:
                disk_manage_svc.disk_action(
                    "disk4s1", "eraseVolume",
                    name="BAD\x00NAME", confirm=True, fs="ExFAT",
                )
        self.assertEqual(ctx.exception.detail["code"], "disk.name_required")
        shell.assert_not_called()


TORN_PLIST = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n"
    "<dict>\n"
    "<key>AppleRAIDSets</key>\n"
    "<array>\n"
)


class RaidPlistTypeTests(unittest.TestCase):
    def test_all_disks_scalar_does_not_500(self):
        with mock.patch.object(
            raid_svc, "_plist", return_value={"AllDisksAndPartitions": 12}
        ):
            self.assertEqual(raid_svc.disk_topology(), {})

    def test_apple_raid_sets_scalar_does_not_500(self):
        with mock.patch.object(
            raid_svc, "_plist", return_value={"AppleRAIDSets": 5}
        ):
            self.assertEqual(raid_svc.list_sets(), [])

    def test_members_scalar_does_not_500(self):
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror",
                "Level": "mirror",
                "Status": "Online",
                "AppleRAIDMembers": 2,
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertEqual(len(sets), 1)
        self.assertEqual(sets[0]["members"], [])

    def test_torn_xml_plist_does_not_500(self):
        with mock.patch.object(raid_svc, "sh", return_value=(0, TORN_PLIST, "")):
            self.assertEqual(raid_svc.disk_topology(), {})
            self.assertEqual(raid_svc.list_sets(), [])

    def test_bytes_plist_payload_does_not_500(self):
        xml = (
            b'<?xml version="1.0"?><plist version="1.0"><dict>'
            b"<key>AllDisksAndPartitions</key><array><dict>"
            b"<key>DeviceIdentifier</key><string>disk9</string>"
            b"</dict></array></dict></plist>"
        )
        with mock.patch.object(raid_svc, "sh", return_value=(0, xml, "")):
            topo = raid_svc.disk_topology()
        self.assertIn("disk9", topo)

    def test_candidate_listing_scalar_does_not_500(self):
        with (
            mock.patch.object(raid_svc, "disk_topology", return_value={}),
            mock.patch.object(
                raid_svc, "_plist",
                return_value={"AllDisksAndPartitions": {"disk0": True}},
            ),
        ):
            self.assertEqual(raid_svc.candidate_devices(), [])

    def test_infinite_size_does_not_500(self):
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror",
                "Level": "mirror",
                "Status": "Online",
                "Size": float("inf"),
                "AppleRAIDMembers": [{
                    "AppleRAIDMemberUUID": "m1",
                    "MemberStatus": "Online",
                    "Size": float("nan"),
                }],
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertEqual(len(sets), 1)
        self.assertIsNone(sets[0]["size_bytes"])
        self.assertIsNone(sets[0]["size_gb"])
        self.assertIsNone(sets[0]["members"][0]["size_bytes"])
        json.dumps(sets, allow_nan=False)

    def test_rebuild_percent_inf_does_not_500(self):
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror",
                "Level": "mirror",
                "Status": "Online",
                "AppleRAIDMembers": [{
                    "AppleRAIDMemberUUID": "m1",
                    "MemberStatus": "Rebuilding",
                    "AppleRAIDMemberRebuildPercent": float("inf"),
                }],
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertIsNone(sets[0]["members"][0]["rebuild_percent"])
        json.dumps(sets, allow_nan=False)

    def test_huge_integer_size_does_not_500(self):
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror",
                "Level": "mirror",
                "Status": "Online",
                "Size": 10**400,
                "AppleRAIDMembers": [],
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertIsNone(sets[0]["size_gb"])
        json.dumps(sets, allow_nan=False)

    def test_apfs_store_bytes_and_alt_key_protect_the_boot_disk(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": b"disk0", "Size": 1},
                {
                    "DeviceIdentifier": "disk3",
                    "APFSPhysicalStores": [
                        {"APFSPhysicalStore": b"disk0s2"},
                    ],
                    "APFSVolumes": [{
                        "DeviceIdentifier": b"disk3s1",
                        "MountedSnapshots": [
                            {"SnapshotMountPoint": b"/"},
                        ],
                    }],
                },
            ]
        }
        with mock.patch.object(raid_svc, "_plist", return_value=tree):
            topo = raid_svc.disk_topology()
        self.assertTrue(topo["disk0"]["system"])
        json.dumps(topo, allow_nan=False)

    def test_apfs_store_array_does_not_500(self):
        tree = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk0", "Size": 1},
                {
                    "DeviceIdentifier": "disk3",
                    "APFSPhysicalStores": [
                        {"APFSPhysicalStore": ["disk0s2"]},
                    ],
                    "APFSVolumes": [{
                        "MountPoint": float("inf"),
                        "MountedSnapshots": [
                            {"SnapshotMountPoint": ["/"]},
                        ],
                    }],
                },
            ]
        }
        with mock.patch.object(raid_svc, "_plist", return_value=tree):
            topo = raid_svc.disk_topology()
        self.assertTrue(topo["disk0"]["system"])
        json.dumps(topo, allow_nan=False)

    def test_candidate_bytes_device_id_does_not_500(self):
        with (
            mock.patch.object(raid_svc, "disk_topology", return_value={}),
            mock.patch.object(
                raid_svc, "_plist",
                return_value={"AllDisksAndPartitions": [
                    {"DeviceIdentifier": b"disk9", "Size": 1},
                ]},
            ),
            mock.patch.object(
                raid_svc, "_disk_info",
                return_value={"MediaName": b"Ext", "BusProtocol": float("inf")},
            ),
        ):
            rows = raid_svc.candidate_devices()
        self.assertEqual([r["device"] for r in rows], ["disk9"])
        json.dumps(rows, allow_nan=False)

    def test_bytes_size_does_not_500(self):
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror",
                "Level": "mirror",
                "Status": "Online",
                "Size": b"\x01\x02",
                "AppleRAIDMembers": [],
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertIsNone(sets[0]["size_bytes"])
        json.dumps(sets, allow_nan=False)

    def test_leftover_surrogate_set_name_does_not_500(self):
        """Leftover ``\\ud800`` in a plist Name used to 500 GET /api/raid."""
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": "Mirror\ud800",
                "Level": "mirror",
                "Status": "Online",
                "AppleRAIDMembers": [],
            }]
        }):
            sets = raid_svc.list_sets()
        self.assertEqual(len(sets), 1)
        self.assertNotIn("\ud800", sets[0]["name"])
        _starlette(sets)

    def test_leftover_admin_payload_does_not_500_delete(self):
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
                return_value={
                    "ok": True,
                    "message": "deleted\ud800",
                    "n": float("inf"),
                    "when": datetime.date(2026, 8, 19),
                    "blob": b"ok",
                },
            ),
        ):
            out = raid_svc.delete_set(
                set_uuid="abcd1234", confirm=True, confirm_phrase="Mirror",
            )
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        self.assertIsNone(out["n"])
        _starlette(out)


class SnapshotPlistTypeTests(unittest.TestCase):
    def test_torn_xml_plist_does_not_500(self):
        with mock.patch.object(snapshots_svc, "sh", return_value=(0, TORN_PLIST, "")):
            self.assertIsNone(snapshots_svc._plist(["tmutil"]))

    def test_infinite_progress_percent_does_not_500(self):
        for raw in (float("inf"), float("nan")):
            with (
                mock.patch.object(
                    snapshots_svc, "_tm_destinations",
                    return_value={"Destinations": []},
                ),
                mock.patch.object(
                    snapshots_svc, "_tm_status",
                    return_value={"Running": True, "Progress": {"Percent": raw}},
                ),
                mock.patch.object(snapshots_svc, "_tm_latest_backup", return_value=""),
            ):
                out = snapshots_svc.time_machine_overview()
            self.assertIsNone(out["percent"])
            json.dumps(out, allow_nan=False)

    def test_leftover_1e308_progress_percent_does_not_500(self):
        """Finite ``1e308`` is not inf; ``* 100`` overflowed to inf and 500'd encode."""
        with (
            mock.patch.object(
                snapshots_svc, "_tm_destinations",
                return_value={"Destinations": []},
            ),
            mock.patch.object(
                snapshots_svc, "_tm_status",
                return_value={"Running": True, "Progress": {"Percent": 1e308}},
            ),
            mock.patch.object(snapshots_svc, "_tm_latest_backup", return_value=""),
        ):
            out = snapshots_svc.time_machine_overview()
        self.assertIsNone(out["percent"])
        _starlette(out)

    def test_leftover_admin_payload_does_not_500_delete(self):
        with (
            mock.patch.object(snapshots_svc, "invalidate"),
            mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={
                    "ok": True,
                    "message": "deleted\ud800",
                    "n": float("inf"),
                    "when": datetime.date(2026, 8, 19),
                    "blob": b"ok",
                },
            ),
        ):
            out = snapshots_svc.delete_snapshot("/", "2026-08-03-160000")
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        self.assertIsNone(out["n"])
        _starlette(out)

    def test_destinations_scalar_does_not_500(self):
        with (
            mock.patch.object(
                snapshots_svc, "_tm_destinations",
                return_value={"Destinations": 3},
            ),
            mock.patch.object(snapshots_svc, "_tm_status", return_value={}),
            mock.patch.object(snapshots_svc, "_tm_latest_backup", return_value=""),
        ):
            out = snapshots_svc.time_machine_overview()
        self.assertEqual(out["destinations"], [])
        self.assertFalse(out["configured"])

    def test_snapshot_xid_inf_does_not_500(self):
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local",
                "SnapshotUUID": "u",
                "SnapshotXID": float("inf"),
            }]
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertEqual(len(items), 1)
        self.assertIsNone(items[0]["xid"])
        json.dumps(items, allow_nan=False)

    def test_snapshot_xid_bytes_does_not_500(self):
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local",
                "SnapshotUUID": "u",
                "SnapshotXID": b"\x00\x01",
            }]
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertIsNone(items[0]["xid"])
        json.dumps(items, allow_nan=False)

    def test_leftover_surrogate_snapshot_name_does_not_500(self):
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local\ud800",
                "SnapshotUUID": "u\ud800",
                "SnapshotXID": 12,
            }]
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertEqual(len(items), 1)
        self.assertNotIn("\ud800", items[0]["name"])
        self.assertNotIn("\ud800", items[0]["uuid"])
        _starlette(items)

    def test_leftover_yaml_date_xid_does_not_500(self):
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local",
                "SnapshotUUID": "u",
                "SnapshotXID": datetime.date(2026, 8, 19),
            }]
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertIsNone(items[0]["xid"])
        _starlette(items)

    def test_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/snapshots."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(snapshots_svc._jsonable(_Stamp()))
        out = snapshots_svc._jsonable({"ok": True, "when": _Stamp(), "name": "snap"})
        _starlette(out)
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "snap")


class RootWholeDisksPlistTypeTests(unittest.TestCase):
    def setUp(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)

    def test_array_and_bytes_physical_store_still_protect_disk0(self):
        with (
            mock.patch.object(
                disk_snapshot, "root_info",
                return_value={
                    "ParentWholeDisk": b"disk3",
                    "APFSPhysicalStores": [{"APFSPhysicalStore": ["disk0s2"]}],
                },
            ),
            mock.patch.object(disk_snapshot, "root_devices", return_value=frozenset()),
            mock.patch.object(disk_snapshot, "sh", return_value=(1, "", "")),
        ):
            protected = disk_snapshot.root_whole_disks()
        self.assertIn("disk0", protected)
        self.assertIn("disk3", protected)

    def test_info_plist_store_key_device_identifier_protects_disk0(self):
        with (
            mock.patch.object(
                disk_snapshot, "root_info",
                return_value={
                    "ParentWholeDisk": ["disk3"],
                    "APFSPhysicalStores": [{"DeviceIdentifier": b"disk0s2"}],
                },
            ),
            mock.patch.object(disk_snapshot, "root_devices", return_value=frozenset()),
            mock.patch.object(disk_snapshot, "sh", return_value=(1, "", "")),
        ):
            protected = disk_snapshot.root_whole_disks()
        self.assertIn("disk0", protected)

    def test_diskutil_info_bytes_does_not_500(self):
        with (
            mock.patch.object(disk_snapshot, "root_info", return_value={}),
            mock.patch.object(disk_snapshot, "root_devices", return_value=frozenset()),
            mock.patch.object(
                disk_snapshot, "sh",
                return_value=(0, b"   Device Node:       /dev/disk0\n", ""),
            ),
        ):
            protected = disk_snapshot.root_whole_disks()
        self.assertIn("disk0", protected)

    def test_diskutil_info_int_does_not_500(self):
        with (
            mock.patch.object(disk_snapshot, "root_info", return_value={}),
            mock.patch.object(disk_snapshot, "root_devices", return_value=frozenset()),
            mock.patch.object(disk_snapshot, "sh", return_value=(0, 12, "")),
        ):
            self.assertEqual(disk_snapshot.root_whole_disks(), frozenset())

    def test_physical_list_bytes_fallback_does_not_500(self):
        with (
            mock.patch.object(disk_snapshot, "run_bytes", return_value=(-1, b"", b"")),
            mock.patch.object(
                disk_snapshot, "sh",
                return_value=(0, b"/dev/disk0 x\n/dev/disk4 y\n", ""),
            ),
        ):
            ids = disk_snapshot.physical_whole_disks(force=True)
        self.assertEqual(ids, ("disk0", "disk4"))

    def test_whole_disks_bytes_and_inf_do_not_500(self):
        with (
            mock.patch.object(disk_snapshot, "run_bytes", return_value=(0, b"x", b"")),
            mock.patch.object(
                disk_snapshot.plistlib, "loads",
                return_value={"WholeDisks": [b"disk0", float("inf"), "disk4"]},
            ),
        ):
            ids = disk_snapshot.physical_whole_disks(force=True)
        self.assertEqual(ids, ("disk0", "disk4"))

    def test_physical_stores_scalar_does_not_500(self):
        with (
            mock.patch.object(
                disk_snapshot, "root_info",
                return_value={"ParentWholeDisk": "disk0", "APFSPhysicalStores": 7},
            ),
            mock.patch.object(disk_snapshot, "root_devices", return_value=frozenset()),
            mock.patch.object(disk_snapshot, "sh", return_value=(1, "", "")),
        ):
            protected = disk_snapshot.root_whole_disks()
        self.assertIn("disk0", protected)


class DiskPowerSizeTypeTests(unittest.TestCase):
    def test_infinite_total_size_does_not_drop_the_disk(self):
        with (
            mock.patch.object(
                disk_power_svc, "_diskutil_info",
                return_value={"TotalSize": float("inf"), "MediaName": "Ext"},
            ),
            mock.patch.object(disk_power_svc, "_volumes_on_disk", return_value=[]),
            mock.patch.object(disk_power_svc, "_is_system_disk", return_value=False),
            mock.patch.object(disk_power_svc, "_power_state", return_value="idle"),
        ):
            row = disk_power_svc._describe_disk("disk4")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "disk4")
        self.assertIsNone(row["size_gb"])
        json.dumps(row, allow_nan=False)

    def test_huge_df_blocks_do_not_drop_the_disk(self):
        df = (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            f"/dev/disk4s1 {'9' * 400} 1 1 1% /Volumes/Huge\n"
        )
        with (
            mock.patch.object(
                disk_power_svc, "_diskutil_info",
                return_value={"TotalSize": 100, "MediaName": "Ext"},
            ),
            mock.patch.object(
                disk_power_svc, "_df_lines",
                return_value=tuple(df.splitlines()),
            ),
            mock.patch.object(disk_power_svc, "_is_system_disk", return_value=False),
            mock.patch.object(disk_power_svc, "_power_state", return_value="active"),
        ):
            row = disk_power_svc._describe_disk("disk4")
        self.assertIsNotNone(row)
        self.assertEqual(len(row["volumes"]), 1)
        self.assertIsNone(row["volumes"][0]["total_gb"])
        json.dumps(row, allow_nan=False)

    def test_string_total_size_does_not_drop_the_disk(self):
        with (
            mock.patch.object(
                disk_power_svc, "_diskutil_info",
                return_value={"TotalSize": "500 GB", "MediaName": "Ext"},
            ),
            mock.patch.object(disk_power_svc, "_volumes_on_disk", return_value=[]),
            mock.patch.object(disk_power_svc, "_is_system_disk", return_value=False),
            mock.patch.object(disk_power_svc, "_power_state", return_value="idle"),
        ):
            row = disk_power_svc._describe_disk("disk4")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "disk4")
        self.assertIsNone(row["size_gb"])

    def test_surrogate_media_name_does_not_500(self):
        with (
            mock.patch.object(
                disk_power_svc, "_diskutil_info",
                return_value={"TotalSize": 100, "MediaName": "Ext\ud800"},
            ),
            mock.patch.object(
                disk_power_svc, "_df_lines",
                return_value=(
                    "Filesystem 1024-blocks Used Available Capacity Mounted on",
                    "/dev/disk4s1 1024 1 1 1% /Volumes/X\ud800",
                ),
            ),
            mock.patch.object(disk_power_svc, "_is_system_disk", return_value=False),
            mock.patch.object(disk_power_svc, "_power_state", return_value="active"),
        ):
            row = disk_power_svc._describe_disk("disk4")
        self.assertIsNotNone(row)
        self.assertNotIn("\ud800", row["name"])
        self.assertNotIn("\ud800", row["volumes"][0]["mount"])
        json.dumps(row, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_infinite_media_name_does_not_500(self):
        with (
            mock.patch.object(
                disk_power_svc, "_diskutil_info",
                return_value={
                    "TotalSize": 100,
                    "MediaName": float("inf"),
                    "SolidState": True,
                },
            ),
            mock.patch.object(
                disk_power_svc, "_volumes_on_disk",
                return_value=[{"mount": "/"}],
            ),
            mock.patch.object(disk_power_svc, "_power_state", return_value="active"),
        ):
            row = disk_power_svc._describe_disk("disk0")
        self.assertIsNotNone(row)
        self.assertIsInstance(row["name"], str)
        json.dumps(row, allow_nan=False)

    def test_wake_exists_eio_does_not_500(self):
        with (
            mock.patch.object(
                disk_power_svc.Path, "exists",
                side_effect=OSError(errno.EIO, "I/O error"),
            ),
            mock.patch.object(disk_power_svc, "sh", return_value=(0, "", "")),
        ):
            out = disk_power_svc.wake_disk("disk4")
        self.assertFalse(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_sleep_leftover_int_output_does_not_500(self):
        disk = {
            "id": "disk4", "device": "/dev/disk4",
            "system": False, "can_sleep": True,
        }
        with (
            mock.patch.object(
                disk_power_svc, "list_power_disks", return_value=[disk]
            ),
            mock.patch.object(disk_power_svc, "sh", return_value=(0, 12, None)),
            mock.patch.object(disk_power_svc, "invalidate_disk_info"),
            mock.patch.object(disk_power_svc, "invalidate_power_disks"),
        ):
            out = disk_power_svc.sleep_disk("disk4")
        self.assertTrue(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_infinite_protocol_does_not_500(self):
        with (
            mock.patch.object(
                disk_power_svc, "_diskutil_info",
                return_value={
                    "TotalSize": 100,
                    "MediaName": "APPLE SSD",
                    "SolidState": True,
                    "BusProtocol": float("inf"),
                },
            ),
            mock.patch.object(
                disk_power_svc, "_volumes_on_disk",
                return_value=[{"mount": "/"}],
            ),
            mock.patch.object(disk_power_svc, "_power_state", return_value="active"),
        ):
            row = disk_power_svc._describe_disk("disk0")
        self.assertIsNotNone(row)
        self.assertIsInstance(row["protocol"], str)
        json.dumps(row, allow_nan=False)


class SmartScheduleEpochTests(unittest.TestCase):
    def setUp(self):
        smart_test_svc.overview.invalidate()
        self.addCleanup(smart_test_svc.overview.invalidate)

    def test_infinite_last_run_does_not_500_overview(self):
        with (
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=[]),
            mock.patch.object(
                smart_test_svc, "passwordless_available", return_value=False
            ),
            mock.patch.object(smart_test_svc, "history", return_value=[]),
            mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": {
                    "interval": "daily",
                    "kind": "short",
                    "last_run": float("inf"),
                    "devices": [],
                }}},
            ),
        ):
            data = smart_test_svc.overview()
        self.assertEqual(data["schedule"]["last_run"], 0.0)
        self.assertIsInstance(data["next_due"], int)
        json.dumps(data, allow_nan=False)

    def test_overflow_strftime_does_not_500_overview_ts(self):
        """Leftover inf clock OverflowError'd GET /api/smart ``ts``."""
        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=[]),
            mock.patch.object(
                smart_test_svc, "passwordless_available", return_value=False
            ),
            mock.patch.object(smart_test_svc, "history", return_value=[]),
            mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": {
                    "interval": "off", "kind": "short", "last_run": 0, "devices": [],
                }}},
            ),
        ):
            data = smart_test_svc.overview()
        json.dumps(data, allow_nan=False)
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(data["ts"], "")

    def test_huge_finite_last_run_does_not_500_next_due(self):
        with (
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=[]),
            mock.patch.object(
                smart_test_svc, "passwordless_available", return_value=False
            ),
            mock.patch.object(smart_test_svc, "history", return_value=[]),
            mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": {
                    "interval": "daily",
                    "kind": "short",
                    "last_run": 1.7976931348623157e308,
                    "devices": [],
                }}},
            ),
        ):
            data = smart_test_svc.overview()
        self.assertIsInstance(data["next_due"], int)
        json.dumps(data, allow_nan=False)

    def test_nan_last_run_in_settings_is_zero(self):
        with mock.patch.object(
            smart_test_svc, "cfg",
            return_value={"settings": {"smart_schedule": {
                "interval": "weekly", "kind": "short", "last_run": "nan",
            }}},
        ):
            sched = smart_test_svc.get_schedule()
        self.assertEqual(sched["last_run"], 0.0)
        json.dumps(sched, allow_nan=False)

    def test_infinite_history_limit_is_clamped_not_500(self):
        with mock.patch.object(
            smart_test_svc, "_load_history", return_value=[{"ok": True}]
        ):
            rows = smart_test_svc.history(float("inf"))
        self.assertEqual(rows, [{"ok": True}])

    def test_smartctl_exists_eio_does_not_500_overview(self):
        with (
            mock.patch.object(smart_test_svc, "_device_nodes", return_value=[]),
            mock.patch.object(
                smart_test_svc, "passwordless_available", return_value=False
            ),
            mock.patch.object(smart_test_svc, "history", return_value=[]),
            mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": {
                    "interval": "off", "kind": "short", "last_run": 0,
                    "devices": [],
                }}},
            ),
            mock.patch.object(
                smart_test_svc.Path, "exists",
                side_effect=OSError(errno.EIO, "I/O error"),
            ),
        ):
            data = smart_test_svc.overview()
        self.assertFalse(data["smartctl_installed"])
        json.dumps(data, allow_nan=False)

    def test_infinite_history_ts_does_not_500(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{"ok": True, "ts": float("inf"), "extra": float("nan")}],
        ):
            rows = smart_test_svc.history(10)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["ts"])
        json.dumps(rows, allow_nan=False)


class SmartShLeftoverTests(unittest.TestCase):
    def setUp(self):
        smart_test_svc.overview.invalidate()
        self.addCleanup(smart_test_svc.overview.invalidate)

    def _report(self, node="/dev/disk0"):
        return {
            "device": node, "id": node.rsplit("/", 1)[-1],
            "capabilities": {
                "readable": True, "available": False, "supported": [],
                "reason": "", "device_type": "auto",
                "estimated_minutes": {}, "detail": "",
            },
            "log": [], "log_count": 0, "last_result": "", "failures": 0,
            "progress": {"running": False, "percent_remaining": None},
        }

    def test_bytes_and_none_diskutil_list_do_not_500_overview(self):
        """Leftover bytes/None from ``diskutil list`` used to TypeError GET /api/smart."""
        listing = b"/dev/disk0 (internal):\n/dev/disk4 (external):\n"
        for payload in (listing, None, 12):
            smart_test_svc.overview.invalidate()
            with (
                mock.patch.object(smart_test_svc, "sh", return_value=(0, payload, "")),
                mock.patch.object(smart_test_svc, "_device_report", self._report),
                mock.patch.object(
                    smart_test_svc, "passwordless_available", return_value=False
                ),
                mock.patch.object(smart_test_svc, "history", return_value=[]),
                mock.patch.object(
                    smart_test_svc, "cfg",
                    return_value={"settings": {"smart_schedule": {
                        "interval": "off", "kind": "short", "last_run": 0,
                        "devices": [],
                    }}},
                ),
            ):
                data = smart_test_svc.overview()
            json.dumps(data, allow_nan=False)
            self.assertTrue(data["devices"])

    def test_bytes_and_none_start_test_do_not_500(self):
        """Leftover bytes from ``smartctl -t`` used to TypeError POST /api/smart/test."""
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]
            ),
            mock.patch.object(
                smart_test_svc, "_capabilities",
                return_value={"available": True, "supported": ["short"], "reason": ""},
            ),
            mock.patch.object(smart_test_svc, "device_type", return_value=()),
            mock.patch.object(smart_test_svc, "_append_history"),
            mock.patch.object(smart_test_svc, "invalidate"),
            mock.patch.object(
                smart_test_svc, "sh", return_value=(0, b"Testing has begun", None)
            ),
        ):
            out = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["message"], str)
        json.dumps(out, allow_nan=False)

    def test_bytes_abort_test_does_not_500(self):
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]
            ),
            mock.patch.object(smart_test_svc, "device_type", return_value=()),
            mock.patch.object(smart_test_svc, "invalidate"),
            mock.patch.object(
                smart_test_svc, "sh", return_value=(0, b"aborted", b"")
            ),
        ):
            out = smart_test_svc.abort_test("/dev/disk0")
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["message"], str)
        json.dumps(out, allow_nan=False)


class SharePathTypeTests(unittest.TestCase):
    def test_nul_in_another_share_path_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Public"
            target.mkdir()
            with mock.patch.object(
                shares_router.shares_svc, "list_smb_shares",
                return_value=[
                    {"path": "/tmp/foo\x00bar"},
                    {"path": str(target)},
                ],
            ):
                resolved = shares_router._share_directory(str(target))
        self.assertEqual(resolved, str(target.resolve()))

    def test_non_str_share_path_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Public"
            target.mkdir()
            with mock.patch.object(
                shares_router.shares_svc, "list_smb_shares",
                return_value=[
                    {"path": ["/Users/a0000/Public"]},
                    {"path": str(target)},
                ],
            ):
                resolved = shares_router._share_directory(str(target))
        self.assertEqual(resolved, str(target.resolve()))


class UsageShareRootTests(unittest.TestCase):
    def test_share_roots_come_from_the_smb_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            share = Path(tmp) / "Media"
            share.mkdir()
            with (
                mock.patch.object(
                    usage_svc.files_svc, "default_roots", return_value=[]
                ),
                mock.patch.object(
                    usage_svc, "_is_never_walk", return_value=False
                ),
                mock.patch.object(
                    usage_svc.files_svc, "is_protected", return_value=False
                ),
                mock.patch(
                    "hub.shares_svc.list_smb_shares",
                    return_value=[{"name": "Media", "path": str(share)}],
                ),
            ):
                roots = usage_svc.scan_roots()
        self.assertTrue(any(r["path"] == str(share.resolve()) for r in roots))

    def test_non_str_share_path_does_not_500(self):
        with (
            mock.patch.object(
                usage_svc.files_svc, "default_roots", return_value=[]
            ),
            mock.patch(
                "hub.shares_svc.list_smb_shares",
                return_value=[{"name": "Media", "path": ["/tmp/media"]}],
            ),
        ):
            roots = usage_svc.scan_roots()
        self.assertFalse(any(r["id"].startswith("share-") for r in roots))

    def test_nul_share_path_does_not_500(self):
        with (
            mock.patch.object(
                usage_svc.files_svc, "default_roots", return_value=[]
            ),
            mock.patch(
                "hub.shares_svc.list_smb_shares",
                return_value=[{"name": "Bad", "path": "/tmp/foo\x00bar"}],
            ),
        ):
            roots = usage_svc.scan_roots()
        self.assertFalse(any(r["id"] == "share-Bad" for r in roots))


class StoragePoolHugeCapacityTests(unittest.TestCase):
    def test_infinite_mount_does_not_500(self):
        vols = [
            {
                "device": float("inf"),
                "mount": float("inf"),
                "kind": "external",
                "total_gb": 1,
                "used_gb": 1,
                "avail_gb": 1,
                "pct": 1,
                "disk_id": float("inf"),
                "filesystem": float("nan"),
            },
            {
                "device": b"/dev/disk6s1",
                "mount": b"/Volumes/Vault",
                "kind": "external",
                "total_gb": 10,
                "used_gb": 1,
                "avail_gb": 9,
                "pct": 10,
                "disk_id": b"disk6",
                "filesystem": b"apfs",
            },
        ]
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        with mock.patch.object(storage_svc, "list_volumes", return_value=vols):
            overview = storage_pool_svc.pool_overview(force=True)
        mounts = [c["mount"] for c in overview["unassigned"]]
        self.assertNotIn(float("inf"), mounts)
        self.assertIn("/Volumes/Vault", mounts)
        json.dumps(overview, allow_nan=False)

    def test_huge_integer_total_gb_does_not_500(self):
        vols = [
            {
                "device": "/dev/disk6s1",
                "mount": "/Volumes/Huge",
                "kind": "external",
                "total_gb": 10**400,
                "used_gb": 1,
                "avail_gb": 1,
                "pct": 1,
                "disk_id": "disk6",
            }
        ]
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        with mock.patch.object(storage_svc, "list_volumes", return_value=vols):
            overview = storage_pool_svc.pool_overview(force=True)
        row = next(c for c in overview["unassigned"] if c["mount"] == "/Volumes/Huge")
        self.assertEqual(row["total_gb"], 0.0)
        json.dumps(overview, allow_nan=False)

    def test_leftover_1e308_members_do_not_500_summary(self):
        """Two leftover finite ``1e308`` totals summed to inf and 500'd the encoder."""
        vols = [
            {
                "device": "/dev/disk6s1",
                "mount": "/Volumes/A",
                "kind": "external",
                "total_gb": 1e308,
                "used_gb": 1e308,
                "avail_gb": 1e308,
                "pct": 50,
                "disk_id": "disk6",
            },
            {
                "device": "/dev/disk7s1",
                "mount": "/Volumes/B",
                "kind": "external",
                "total_gb": 1e308,
                "used_gb": 1e308,
                "avail_gb": 1e308,
                "pct": 50,
                "disk_id": "disk7",
            },
        ]
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=vols),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "members": ["/Volumes/A", "/Volumes/B"],
                    "policy": "most-free",
                    "name": "pool",
                }}},
            ),
        ):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        self.assertEqual(overview["summary"]["total_gb"], 0.0)
        self.assertIsInstance(overview["summary"]["pct"], int)

    def test_leftover_yaml_name_date_bytes_and_surrogate_do_not_500(self):
        vols = [{
            "device": "/dev/disk6s1",
            "mount": "/Volumes/Vault\ud800",
            "kind": "external",
            "total_gb": 10,
            "used_gb": 1,
            "avail_gb": 9,
            "pct": 10,
            "disk_id": "disk6",
        }]
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=vols),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "vault\ud800",
                    "members": [
                        datetime.date(2026, 8, 19),
                        "/Volumes/Vault\ud800",
                        b"/Volumes/Other",
                        float("inf"),
                        {"x"},
                    ],
                    "policy": datetime.date(2026, 8, 19),
                    "min_free_gb": datetime.date(2026, 8, 19),
                }}},
            ),
        ):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        self.assertNotIn("\ud800", overview["name"])
        dumped = json.dumps(overview, ensure_ascii=False, allow_nan=False)
        self.assertNotIn("\ud800", dumped)

    def test_isoformat_inf_member_does_not_500(self):
        """A leftover ``isoformat()`` returning inf used to TypeError GET /api/storage/pool."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertEqual(storage_pool_svc._text(_Stamp()), "")
        vols = [{
            "device": "/dev/disk6s1",
            "mount": "/Volumes/Vault",
            "kind": "external",
            "total_gb": 10,
            "used_gb": 1,
            "avail_gb": 9,
            "pct": 10,
            "disk_id": "disk6",
        }]
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=vols),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": _Stamp(),
                    "members": [_Stamp(), "/Volumes/Vault"],
                    "policy": _Stamp(),
                    "min_free_gb": _Stamp(),
                }}},
            ),
        ):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        self.assertEqual(overview["name"], "pool")

    def test_leftover_1e308_volumes_do_not_500_aggregate(self):
        """Two leftover finite ``1e308`` totals summed to inf and 500'd GET /api/storage."""
        vols = [
            {
                "device": "/dev/disk6s1",
                "mount": "/Volumes/A",
                "kind": "external",
                "total_gb": 1e308,
                "used_gb": 1e308,
                "avail_gb": 1e308,
                "pct": 50,
                "disk_id": "disk6",
                "filesystem": "apfs",
            },
            {
                "device": "/dev/disk7s1",
                "mount": "/Volumes/B",
                "kind": "external",
                "total_gb": 1e308,
                "used_gb": 1e308,
                "avail_gb": 1e308,
                "pct": 50,
                "disk_id": "disk7",
                "filesystem": "apfs",
            },
        ]
        cap = storage_svc.aggregate_capacity(vols)
        _starlette(cap)
        self.assertEqual(cap["total_gb"], 0.0)
        self.assertEqual(cap["total_tb"], 0.0)


class StorageOverviewLeftoverTests(unittest.TestCase):
    def test_non_dict_volume_rows_do_not_500(self):
        """``v["kind"]`` TypeError on leftover rows used to 500 GET /api/storage."""
        vols = [
            None,
            "not-a-volume",
            {
                "kind": "system",
                "mount": "/",
                "disk_id": "disk0",
                "device": "/dev/disk0s1",
                "total_gb": 10,
                "used_gb": 1,
                "avail_gb": 9,
                "pct": 10,
                "filesystem": "apfs",
            },
        ]
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=vols),
            mock.patch.object(storage_svc, "smart_devices", return_value=[]),
        ):
            overview = storage_svc.storage_overview()
        json.dumps(overview, allow_nan=False)
        self.assertEqual(overview["array"]["system_count"], 1)
        self.assertEqual(overview["array"]["devices"][0]["mount"], "/")

    def test_non_list_volumes_do_not_500(self):
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=True),
            mock.patch.object(storage_svc, "smart_devices", return_value=float("inf")),
        ):
            overview = storage_svc.storage_overview()
        json.dumps(overview, allow_nan=False)
        self.assertEqual(overview["volumes"], [])
        self.assertEqual(overview["disks"], [])

    def test_incomplete_and_inf_volume_rows_do_not_500(self):
        """Missing ``total_gb`` KeyError'd GET /api/storage after non-dict rows."""
        vols = [
            {"kind": "system"},
            {
                "kind": "external",
                "mount": "/Volumes/A",
                "total_gb": float("inf"),
                "used_gb": 1,
                "avail_gb": 1,
                "pct": 1,
                "filesystem": "apfs",
                "disk_id": "disk1",
                "device": "/dev/disk1s1",
            },
            {
                "kind": "external",
                "mount": "ok\ud800",
                "total_gb": "10",
                "used_gb": None,
                "avail_gb": 9,
                "pct": float("nan"),
                "filesystem": "apfs",
                "disk_id": float("inf"),
                "device": "/dev/disk2s1",
            },
            {
                "kind": "system",
                "mount": "/",
                "disk_id": "disk0",
                "device": "/dev/disk0s1",
                "total_gb": 10,
                "used_gb": 1,
                "avail_gb": 9,
                "pct": 10,
                "filesystem": "apfs",
            },
        ]
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=vols),
            mock.patch.object(storage_svc, "smart_devices", return_value=[
                {"id": "disk0", "name": "ok\ud800", "size_gb": float("inf")},
            ]),
        ):
            overview = storage_svc.storage_overview()
        _starlette(overview)
        self.assertEqual(overview["array"]["system_count"], 1)
        self.assertEqual(overview["array"]["devices"][0]["mount"], "/")
        mounts = [v["mount"] for v in overview["volumes"]]
        self.assertNotIn("\ud800", "".join(mounts))
        self.assertTrue(all(
            d.get("size_gb") is None or isinstance(d.get("size_gb"), (int, float))
            and d["size_gb"] == d["size_gb"]
            for d in overview["disks"]
        ))

    def test_page_surrogate_error_does_not_500(self):
        """``str(e)`` leftover ``\\ud800`` used to 500 GET /api/storage."""
        with (
            mock.patch.object(
                storage_svc, "storage_overview",
                side_effect=RuntimeError("disk\ud800"),
            ),
            mock.patch.object(disk_power_svc, "list_power_disks", return_value=[]),
            mock.patch.object(disk_manage_svc, "overview", return_value={"volumes": []}),
        ):
            out = storage_router.storage(light=False)
        _starlette(out)
        self.assertNotIn("\ud800", out.get("error") or "")

    def test_string_gb_rows_do_not_500_aggregate(self):
        """YAML leftover ``total_gb: '10'`` TypeError'd shared-pool compare."""
        vols = [
            {
                "kind": "system", "mount": "/", "total_gb": "10",
                "used_gb": 1, "avail_gb": 9, "pct": 10,
                "filesystem": "apfs", "disk_id": "disk0",
            },
            {
                "kind": "system", "mount": "/System/Volumes/Data",
                "total_gb": "10", "used_gb": 2, "avail_gb": 8, "pct": 20,
                "filesystem": "apfs", "disk_id": "disk0",
            },
        ]
        cap = storage_svc.aggregate_capacity(vols)
        _starlette(cap)
        self.assertEqual(cap["total_gb"], 10.0)


class StorageSmartProbeLeftoverTests(unittest.TestCase):
    def test_bytes_and_int_diskutil_list_do_not_500_smart_devices(self):
        storage_svc.invalidate_smart()
        self.addCleanup(storage_svc.invalidate_smart)
        listing = b"/dev/disk0 (internal):\n"
        for payload in (listing, None, 12, float("inf")):
            storage_svc.invalidate_smart()
            with (
                mock.patch.object(storage_svc, "sh", return_value=(0, payload, "")),
                mock.patch.object(
                    storage_svc, "_probe_disk",
                    return_value={
                        "device": "/dev/disk0", "id": "disk0", "name": "disk0",
                        "size": None, "size_bytes": None, "size_gb": None,
                        "smart": None, "error": None,
                    },
                ),
            ):
                disks = storage_svc.smart_devices()
            _starlette(disks)
            self.assertTrue(disks)

    def test_leftover_surrogate_disk_name_does_not_500(self):
        info = {
            "device": "/dev/disk4", "id": "disk4", "name": "disk4",
            "size": None, "size_bytes": None, "size_gb": None,
            "smart": None, "error": None,
        }
        with mock.patch.object(
            storage_svc, "sh",
            side_effect=[
                (0, "   Device / Media Name:  Ext\ud800 Drive\n   Disk Size:  1 GB (1073741824 Bytes)\n", ""),
                (0, "SMART overall-health self-assessment test result: PASSED\n", ""),
            ],
        ):
            row = storage_svc._probe_disk_uncached("/dev/disk4", info)
        self.assertNotIn("\ud800", row["name"])
        _starlette(row)

    def test_leftover_bytes_diskutil_info_does_not_500(self):
        info = {
            "device": "/dev/disk4", "id": "disk4", "name": "disk4",
            "size": None, "size_bytes": None, "size_gb": None,
            "smart": None, "error": None,
        }
        blob = b"   Device / Media Name:  Ext\n   Disk Size:  1 GB (1073741824 Bytes)\n"
        with mock.patch.object(
            storage_svc, "sh",
            side_effect=[(0, blob, ""), (0, None, 12)],
        ):
            row = storage_svc._probe_disk_uncached("/dev/disk4", info)
        self.assertEqual(row["name"], "Ext")
        _starlette(row)


class SmartHistoryYamlLeftoverTests(unittest.TestCase):
    def test_leftover_yaml_date_and_surrogate_history_do_not_500(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{
                "ok": True,
                "ts": datetime.date(2026, 8, 19),
                "device": b"/dev/disk0",
                "kind": "short\ud800",
                "blob": b"hello",
                "extra": float("inf"),
            }],
        ):
            rows = smart_test_svc.history(10)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["kind"])
        self.assertIsNone(rows[0]["extra"])
        _starlette(rows)

    def test_append_history_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; POST /api/smart/test used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smart-tests.json"
            with (
                mock.patch.object(smart_test_svc, "HISTORY_PATH", path),
                mock.patch.object(smart_test_svc, "_load_history", return_value=[]),
                mock.patch.object(smart_test_svc.json, "dumps", side_effect=RecursionError),
            ):
                smart_test_svc._append_history({"ok": True, "device": "/dev/disk0"})
            self.assertFalse(path.exists())

    def test_leftover_surrogate_admin_message_does_not_500_start_test(self):
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]
            ),
            mock.patch.object(
                smart_test_svc, "_capabilities",
                return_value={"available": True, "supported": ["short"], "reason": ""},
            ),
            mock.patch.object(smart_test_svc, "device_type", return_value=()),
            mock.patch.object(smart_test_svc, "_append_history"),
            mock.patch.object(smart_test_svc, "invalidate"),
            mock.patch.object(
                smart_test_svc, "sh", return_value=(1, "", "permission denied")
            ),
            mock.patch.object(
                smart_test_svc, "run_admin",
                return_value={"ok": True, "message": "started\ud800"},
            ),
        ):
            out = smart_test_svc.start_test("/dev/disk0", "short")
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        _starlette(out)

    def test_leftover_abort_admin_payload_does_not_500(self):
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
                return_value={
                    "ok": True,
                    "message": "aborted\ud800",
                    "n": float("inf"),
                    "when": datetime.date(2026, 8, 19),
                    "blob": b"ok",
                },
            ),
        ):
            out = smart_test_svc.abort_test("/dev/disk0")
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["message"])
        self.assertIsNone(out["n"])
        _starlette(out)

    def test_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/smart."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(smart_test_svc._jsonable(_Stamp()))
        row = smart_test_svc._jsonable({
            "ok": True,
            "ts": _Stamp(),
            "device": "/dev/disk0",
        })
        _starlette(row)
        self.assertIsNone(row["ts"])
        self.assertEqual(row["device"], "/dev/disk0")

    def test_leftover_surrogate_probe_error_does_not_500(self):
        """Leftover ``\\ud800`` in a probe exception used to 500 GET /api/smart."""
        with mock.patch.object(
            smart_test_svc, "device_type",
            side_effect=ValueError("disk\ud800"),
        ):
            row = smart_test_svc._device_report("/dev/disk0")
        self.assertEqual(row["capabilities"]["reason"], "probe_failed")
        self.assertNotIn("\ud800", row["capabilities"]["detail"])
        _starlette(row)


class AsTextRecursionLeftoverTests(unittest.TestCase):
    def test_storage_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(storage_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": storage_svc._as_text(Recursing())})

    def test_smart_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(smart_test_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": smart_test_svc._as_text(Recursing())})

    def test_usage_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(usage_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": usage_svc._as_text(Recursing())})

    def test_disk_snapshot_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(disk_snapshot._as_text(Recursing()), "Recursing")
        _starlette({"message": disk_snapshot._as_text(Recursing())})

    def test_disk_power_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(disk_power_svc._text(Recursing()), "Recursing")
        _starlette({"message": disk_power_svc._text(Recursing())})

    def test_disk_manage_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(disk_manage_svc._text(Recursing()), "Recursing")
        _starlette({"message": disk_manage_svc._text(Recursing())})

    def test_raid_plist_recursing_does_not_500(self):
        """leftover ``str()`` RecursionError used to 500 GET /api/raid."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(raid_svc, "sh", return_value=(0, Recursing(), "")):
            self.assertEqual(raid_svc._plist(["diskutil", "appleRAID", "list"]), {})

    def test_raid_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/raid."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(raid_svc._jsonable(_Stamp()))
        out = raid_svc._jsonable({
            "ok": True,
            "when": _Stamp(),
            "name": datetime.date(2026, 8, 19),
            "blob": b"raid",
            "tags": {"mirror"},
            "n": float("inf"),
        })
        _starlette(out)
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "raid")
        self.assertEqual(out["tags"], ["mirror"])
        self.assertIsNone(out["n"])

    def test_storage_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/storage."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(storage_svc._jsonable(_Stamp()))
        out = storage_svc._jsonable({"when": _Stamp(), "ok": True})
        _starlette(out)
        self.assertIsNone(out["when"])
        self.assertIs(out["ok"], True)


if __name__ == "__main__":
    unittest.main()
