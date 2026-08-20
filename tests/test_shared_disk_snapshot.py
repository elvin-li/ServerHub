"""The three whole-machine disk reads are read once per request, by every module.

`storage_svc`, `disk_power_svc` and `disk_manage_svc` all run concurrently inside
`/api/storage`, and each asked the host the same three questions:

    `df -P -k`                       the mount table
    `diskutil list -plist physical`  which disks are physical
    `diskutil info -plist /`         what `/` sits on

plus `df -P /`, which is the mount table filtered to one row, and which
`disk_manage_svc` ran once per node in its listing walk.

    /api/storage  16 spawns, 5 waves, 3 redundant  ->  11 spawns, 1 wave, 0 redundant

Two of those duplicates were invisible to any measurement grouping spawns by argv,
because `storage_svc` spelled the command `df` and `disk_power_svc` spelled it
`/bin/df`.

The safety tests here matter more than the spawn counts.  `_root_whole_disks()` is
the set of disks the panel refuses to spin down or eject, and it is a union of three
independent reads; sharing two of them must not be able to make that union smaller.
Verified against this machine before and after: both produce {disk0, disk3}.
"""
from __future__ import annotations

import plistlib
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from hub import disk_manage_svc, disk_power_svc, disk_snapshot, storage_svc

#: A real APFS layout: `/` is a synthesised container (disk3) whose physical store
#: lives on disk0.  This is why the plist read cannot be dropped -- neither the `df`
#: row nor the text scrape names disk0, which is the disk an operator could spin down.
DF_TABLE = "\n".join([
    "Filesystem 1024-blocks Used Available Capacity Mounted on",
    "/dev/disk3s1s1 971350180 10485760 900000000 2% /",
    "devfs 197 197 0 100% /dev",
    "/dev/disk3s5 971350180 60000000 900000000 7% /System/Volumes/Data",
    "map auto_home 0 0 0 100% /System/Volumes/Data/home",
    "/dev/disk4s1 488281250 1000000 487281250 1% /Volumes/External",
])

ROOT_PLIST = {
    "ParentWholeDisk": "disk3",
    "APFSPhysicalStores": [{"APFSPhysicalStore": "disk0s2"}],
}

PHYSICAL_PLIST = {"WholeDisks": ["disk0", "disk4"]}


class _Host:
    """Answers the three reads from fixtures and counts every spawn."""

    def __init__(self, df: str = DF_TABLE, fail_df: bool = False):
        self.df = df
        self.fail_df = fail_df
        self.calls: list[list[str]] = []
        self.peak = 0
        self._live = 0
        self._lock = threading.Lock()

    def _record(self, argv: list[str]) -> None:
        with self._lock:
            self.calls.append(argv)
            self._live += 1
            self.peak = max(self.peak, self._live)
        time.sleep(0.03)
        with self._lock:
            self._live -= 1

    def sh(self, cmd, *a, **kw):
        argv = [str(c) for c in cmd]
        self._record(argv)
        if "df" in argv[0]:
            if self.fail_df:
                return -1, "", "timeout"
            return 0, self.df, ""
        if "diskutil" in argv[0] and "info" in argv:
            return 0, "   Device Node: /dev/disk3s1s1\n", ""
        if "diskutil" in argv[0] and "list" in argv:
            return 0, "/dev/disk0 x\n/dev/disk4 y\n", ""
        return 0, "", ""

    def run(self, cmd, *a, **kw):
        argv = [str(c) for c in cmd]
        self._record(argv)
        payload = ROOT_PLIST if argv[-1] == "/" else PHYSICAL_PLIST

        class Done:
            returncode = 0
            stdout = plistlib.dumps(payload)
            stderr = b""

        return Done()

    def count(self, *needles: str) -> int:
        return sum(
            1 for c in self.calls if all(any(n in p for p in c) for n in needles)
        )


def _clear() -> None:
    disk_snapshot.invalidate_disks()
    disk_power_svc.invalidate_power_disks()


class SharedDiskReadTests(unittest.TestCase):
    def setUp(self):
        _clear()
        self.addCleanup(_clear)

    def _patched(self, host: _Host):
        return (
            mock.patch.object(disk_snapshot, "sh", host.sh),
            mock.patch.object(disk_snapshot.subprocess, "run", host.run),
        )

    def test_the_three_modules_share_one_mount_table(self):
        host = _Host()
        a, b = self._patched(host)
        with a, b:
            storage_svc.list_volumes()
            disk_power_svc._df_lines()
            disk_manage_svc.root_devices()

        self.assertEqual(
            host.count("df"), 1,
            f"three readers ran {host.count('df')} mount-table reads",
        )

    def test_the_command_is_absolute(self):
        """`storage_svc` used a bare `df`, which depends on the inherited PATH."""
        host = _Host()
        a, b = self._patched(host)
        with a, b:
            storage_svc.list_volumes()

        self.assertEqual(host.calls[0][0], "/bin/df")

    def test_the_physical_list_and_the_root_info_are_shared(self):
        host = _Host()
        a, b = self._patched(host)
        with a, b:
            disk_power_svc._list_whole_disks()
            disk_snapshot.physical_whole_disks()
            disk_snapshot.root_info()
            disk_snapshot.root_info()

        self.assertEqual(host.count("list", "physical"), 1)
        self.assertEqual(host.count("info", "/"), 1)

    def test_root_devices_takes_only_the_row_mounted_at_slash(self):
        host = _Host()
        a, b = self._patched(host)
        with a, b:
            roots = disk_snapshot.root_devices()

        self.assertEqual(
            roots, frozenset({"disk3"}),
            "the Data volume, the external disk or an autofs row leaked in",
        )

    def test_an_autofs_row_is_not_mistaken_for_a_device(self):
        """`map auto_home` has a device column with a space in it."""
        host = _Host()
        a, b = self._patched(host)
        with a, b:
            self.assertNotIn("home", " ".join(disk_snapshot.root_devices()))

    def test_concurrent_cold_readers_do_not_each_spawn(self):
        host = _Host()
        a, b = self._patched(host)
        with a, b:
            threads = [
                threading.Thread(target=disk_snapshot.df_lines) for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(len(host.calls), 1)
        self.assertEqual(host.peak, 1, "two mount-table reads were in flight at once")


class BootDiskProtectionTests(unittest.TestCase):
    """The union that decides whether the panel will spin down or eject a disk."""

    def setUp(self):
        _clear()
        self.addCleanup(_clear)

    def _patched(self, host: _Host):
        return (
            mock.patch.object(disk_snapshot, "sh", host.sh),
            mock.patch.object(disk_snapshot.subprocess, "run", host.run),
            mock.patch.object(disk_power_svc, "sh", host.sh),
        )

    def test_the_physical_store_of_the_root_container_is_protected(self):
        """disk0 carries `/`, and neither df nor the text scrape names it.

        `/` is on disk3, a synthesised APFS container.  Only the plist read reaches
        disk0 through APFSPhysicalStores -- so this is the assertion that says the
        boot disk is still covered after two of the three reads moved.
        """
        host = _Host()
        a, b, c = self._patched(host)
        with a, b, c:
            protected = disk_power_svc._root_whole_disks()

        self.assertIn("disk0", protected, "the boot disk lost its protection")
        self.assertIn("disk3", protected, "the root container lost its protection")

    def test_an_external_disk_is_still_offered(self):
        """Guards the test above: protecting everything would also pass it."""
        host = _Host()
        a, b, c = self._patched(host)
        with a, b, c:
            protected = disk_power_svc._root_whole_disks()

        self.assertNotIn(
            "disk4", protected,
            "every disk was protected, so the assertion above proves nothing",
        )

    def test_the_system_disk_verdict_still_reaches_the_shared_union(self):
        """Empty info and no volumes, so the verdict comes only from the union.

        `_is_system_disk` short-circuits on a system mount point and on the internal
        Apple SSD heuristic before it gets here; passing neither is what makes this
        test about the union rather than about those.
        """
        host = _Host()
        a, b, c = self._patched(host)
        with a, b, c:
            self.assertTrue(
                disk_power_svc._is_system_disk({}, "disk0", []),
                "the boot disk would have been offered for sleep or eject",
            )
            self.assertFalse(disk_power_svc._is_system_disk({}, "disk4", []))

    def test_a_failed_mount_table_is_not_remembered_as_truth(self):
        """The safety-critical half of the cache contract.

        `cached_snapshot` keeps any value that is not None, and an empty tuple is not
        None -- so without dropping it, one `df` timeout would tell all three modules
        that no disk carries `/` for the whole TTL.  Each of them used to fail
        independently and retry on its own next call.
        """
        failing = _Host(fail_df=True)
        a, b = (
            mock.patch.object(disk_snapshot, "sh", failing.sh),
            mock.patch.object(disk_snapshot.subprocess, "run", failing.run),
        )
        with a, b:
            self.assertEqual(disk_snapshot.root_devices(), frozenset())
            disk_snapshot.root_devices()

        self.assertEqual(
            failing.count("df"), 2,
            "the failed mount table was served from cache instead of retried",
        )

        # And a later successful read is not shadowed by the cached failure.
        good = _Host()
        c, d = (
            mock.patch.object(disk_snapshot, "sh", good.sh),
            mock.patch.object(disk_snapshot.subprocess, "run", good.run),
        )
        with c, d:
            self.assertEqual(disk_snapshot.root_devices(), frozenset({"disk3"}))


class DiskInvalidationTests(unittest.TestCase):
    def setUp(self):
        _clear()
        self.addCleanup(_clear)

    def test_invalidate_disks_drops_all_three_reads(self):
        host = _Host()
        with (
            mock.patch.object(disk_snapshot, "sh", host.sh),
            mock.patch.object(disk_snapshot.subprocess, "run", host.run),
        ):
            disk_snapshot.df_lines()
            disk_snapshot.physical_whole_disks()
            disk_snapshot.root_info()
            before = len(host.calls)
            disk_snapshot.invalidate_disks()
            disk_snapshot.df_lines()
            disk_snapshot.physical_whole_disks()
            disk_snapshot.root_info()

        self.assertEqual(before, 3, host.calls)
        self.assertEqual(len(host.calls), 6, "invalidate_disks() missed a read")

    def test_a_disk_action_drops_the_shared_reads(self):
        """A mount or an erase changes the mount table the next read reports."""
        dropped = []
        with mock.patch.object(
            disk_manage_svc, "invalidate_disks", lambda: dropped.append(1)
        ):
            with (
                mock.patch.object(disk_manage_svc, "sh", lambda *a, **k: (0, "", "")),
                mock.patch.object(disk_manage_svc, "_diskutil_info", lambda n: {}),
                mock.patch.object(disk_manage_svc, "_is_system_related", lambda i, d: False),
            ):
                disk_manage_svc.disk_action("disk9s1", "mount")

        self.assertTrue(dropped, "a mount left the pre-mount table cached")

    def test_the_power_listing_does_not_discard_a_shared_read(self):
        """It used to clear these at its start, which was right when they were local.

        Once they are shared with the two other sections of the same request, the
        clearing threw away a read one of those had already paid for -- which put a
        second `df -P -k` and a second `diskutil list -plist physical` back into
        /api/storage.
        """
        host = _Host()
        with (
            mock.patch.object(disk_snapshot, "sh", host.sh),
            mock.patch.object(disk_snapshot.subprocess, "run", host.run),
            mock.patch.object(disk_power_svc, "sh", host.sh),
            mock.patch.object(disk_power_svc, "_describe_disk", lambda d: {"id": d}),
        ):
            storage_svc.list_volumes()          # the first section warms the table
            disk_power_svc.list_power_disks()   # the second must reuse it

        self.assertEqual(
            host.count("df"), 1,
            f"the power listing re-read the mount table ({host.count('df')} total)",
        )


class DiskPlistTypeTests(unittest.TestCase):
    def test_power_info_rejects_a_list_plist(self):
        class Done:
            returncode = 0
            stdout = plistlib.dumps(["WholeDisks"])

        with mock.patch.object(disk_power_svc.subprocess, "run", return_value=Done()):
            self.assertEqual(disk_power_svc._diskutil_info("disk0"), {})

    def test_physical_list_falls_back_when_plist_is_not_a_dict(self):
        class Done:
            returncode = 0
            stdout = plistlib.dumps(["disk0"])

        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        with (
            mock.patch.object(disk_snapshot.subprocess, "run", return_value=Done()),
            mock.patch.object(
                disk_snapshot, "sh",
                return_value=(0, "/dev/disk0 x\n", ""),
            ),
        ):
            self.assertEqual(disk_snapshot.physical_whole_disks(), ("disk0",))

    def test_disk_plist_readers_do_not_capture_output(self):
        for mod in (disk_snapshot, disk_power_svc, disk_manage_svc):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn(
                "capture_output=True", src, f"{mod.__name__} still buffers plists in RAM",
            )
            self.assertIn("run_bytes", src, f"{mod.__name__} should stream plists")


if __name__ == "__main__":
    unittest.main()
