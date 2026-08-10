"""A mount, unmount or eject must drop the cached `diskutil info` output.

``hub.disk_manage_svc`` memoises ``diskutil info`` for ``_INFO_TTL`` seconds
because the call costs ~130ms per device and listing volumes needs one per
partition -- serially that was ~3.7s on a 25-volume host for every
/api/storage request.  The cache is keyed on the device node and holds exactly
the fields an operation changes: mount point, volume name, filesystem.

Two modules mutate that state.  ``disk_manage_svc.disk_action`` handles
mount/unmount/rename/erase, and ``disk_power_svc`` parks and wakes disks
through its own ``sh`` calls.  Neither dropped the cache, so a disk the user
just unmounted kept rendering as mounted for up to the TTL -- and because the
storage page shows the managed-volume list and the power panel side by side, an
action taken in one was contradicted by the other.

These tests pin the invalidation to the mutating paths rather than to the TTL,
so tuning ``_INFO_TTL`` cannot quietly bring the stale window back.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import disk_manage_svc, disk_power_svc  # noqa: E402

#: A recognisable snapshot: if a test finds this still cached, the code under
#: test skipped invalidation rather than merely failing to populate the cache.
PRIMED = {"VolumeName": "Archive", "MountPoint": "/Volumes/Archive"}


class _DiskCacheTestCase(unittest.TestCase):
    """Shared fixture: every test starts from a primed cache."""

    def setUp(self):
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        self._prime()

    def _prime(self):
        # float("inf") pins the entry as permanently fresh, so a test that
        # observes an empty cache observed an explicit invalidation and never a
        # TTL expiry racing the assertion.
        with disk_manage_svc._INFO_LOCK:
            disk_manage_svc._INFO_CACHE.clear()
            for node in ("disk4", "disk4s1", "disk4s2"):
                disk_manage_svc._INFO_CACHE[node] = (float("inf"), dict(PRIMED))

    def _cache(self) -> dict:
        with disk_manage_svc._INFO_LOCK:
            return dict(disk_manage_svc._INFO_CACHE)

    def assertDropped(self, msg: str):
        self.assertEqual(self._cache(), {}, msg)

    def assertKept(self, msg: str):
        self.assertNotEqual(self._cache(), {}, msg)


class FixtureTests(_DiskCacheTestCase):
    def test_priming_actually_populates_the_cache(self):
        # Guards the fixture: if priming broke, every "was it dropped?" test
        # below would pass without exercising anything.
        self.assertEqual(len(self._cache()), 3)

    def test_primed_entries_are_served_without_a_subprocess(self):
        with patch.object(disk_manage_svc, "_diskutil_info_uncached") as uncached:
            self.assertEqual(disk_manage_svc._diskutil_info("disk4s1"), PRIMED)
        uncached.assert_not_called()

    def test_invalidate_drops_every_entry(self):
        disk_manage_svc.invalidate_disk_info()
        self.assertDropped("invalidate_disk_info() left entries behind")


class DiskActionInvalidationTests(_DiskCacheTestCase):
    """`disk_action` funnels every diskutil call through one helper."""

    def _run_action(self, action: str, rc: int = 0, **kwargs) -> dict:
        with patch.object(disk_manage_svc, "_is_system_related", return_value=False), \
                patch.object(disk_manage_svc, "sh", return_value=(rc, "ok", "")) as shell:
            result = disk_manage_svc.disk_action("disk4s1", action, **kwargs)
        self.shell = shell
        return result

    def test_mount_invalidates(self):
        result = self._run_action("mount")
        self.assertTrue(result["ok"])
        self.assertDropped(
            "mount left the pre-mount `diskutil info` cached; the volume list "
            "would keep reporting the disk as unmounted"
        )

    def test_unmount_invalidates(self):
        result = self._run_action("unmount")
        self.assertTrue(result["ok"])
        self.assertDropped("unmount left the stale mount point cached")

    def test_mount_disk_invalidates(self):
        self.assertTrue(self._run_action("mountDisk")["ok"])
        self.assertDropped("mountDisk left stale entries for the child volumes")

    def test_unmount_disk_invalidates(self):
        self.assertTrue(self._run_action("unmountDisk")["ok"])
        self.assertDropped("unmountDisk left stale entries for the child volumes")

    def test_eject_invalidates(self):
        self.assertTrue(self._run_action("eject")["ok"])
        self.assertDropped("eject left the ejected device cached as present")

    def test_rename_invalidates(self):
        result = self._run_action("rename", name="Backups")
        self.assertTrue(result["ok"])
        self.assertDropped(
            "rename left the old VolumeName cached, so the UI would show the "
            "previous name after a successful rename"
        )

    def test_failed_unmount_still_invalidates(self):
        # A non-zero exit does not mean nothing moved: `unmount` failing and
        # `unmount force` succeeding is the normal busy-volume path, and both
        # go through the same helper.  Trusting the cache after a failure is
        # how a half-applied change becomes invisible.
        result = self._run_action("unmount", rc=1)
        self.assertFalse(result["ok"])
        self.assertDropped("a failed unmount left the cache untouched")
        self.assertEqual(
            self.shell.call_count, 2, "expected the force-unmount retry"
        )

    def test_erase_invalidates(self):
        result = self._run_action(
            "eraseVolume", name="Scratch", fs="ExFAT", confirm=True
        )
        self.assertTrue(result["ok"])
        self.assertDropped(
            "erase left the previous filesystem and volume name cached"
        )

    def test_rejected_erase_keeps_the_cache(self):
        # Nothing ran, so the snapshot is still truthful; dropping it would
        # only buy a needless fan-out of ~130ms subprocesses on the next read.
        with patch.object(disk_manage_svc, "_is_system_related", return_value=False), \
                patch.object(disk_manage_svc, "sh") as shell:
            with self.assertRaises(Exception):
                disk_manage_svc.disk_action("disk4s1", "eraseVolume", confirm=False)
        shell.assert_not_called()
        self.assertKept("an unconfirmed erase needlessly dropped the cache")

    def test_system_protected_disk_keeps_the_cache(self):
        with patch.object(disk_manage_svc, "_is_system_related", return_value=True), \
                patch.object(disk_manage_svc, "sh") as shell:
            with self.assertRaises(Exception):
                disk_manage_svc.disk_action("disk4s1", "unmount")
        shell.assert_not_called()
        self.assertKept("a refused system-disk action dropped the cache")

    def test_unknown_action_keeps_the_cache(self):
        with patch.object(disk_manage_svc, "_is_system_related", return_value=False), \
                patch.object(disk_manage_svc, "sh") as shell:
            with self.assertRaises(Exception):
                disk_manage_svc.disk_action("disk4s1", "obliterate")
        shell.assert_not_called()
        self.assertKept("an unknown action dropped the cache")


class DiskPowerInvalidationTests(_DiskCacheTestCase):
    """`disk_power_svc` mutates the same mount state from a second module."""

    POWER_DISK = {
        "id": "disk4",
        "device": "/dev/disk4",
        "system": False,
        "can_sleep": True,
    }

    def _patch_power(self, rc: int = 0):
        return (
            patch.object(
                disk_power_svc, "list_power_disks", return_value=[dict(self.POWER_DISK)]
            ),
            patch.object(disk_power_svc, "sh", return_value=(rc, "ok", "")),
        )

    def test_sleep_invalidates(self):
        disks, shell = self._patch_power()
        with disks, shell:
            result = disk_power_svc.sleep_disk("disk4", mode="sleep")
        self.assertTrue(result["ok"])
        self.assertDropped(
            "parking a disk from the power panel left it cached as mounted in "
            "the managed-volume list rendered on the same page"
        )

    def test_eject_invalidates(self):
        disks, shell = self._patch_power()
        with disks, shell:
            result = disk_power_svc.sleep_disk("disk4", mode="eject")
        self.assertTrue(result["ok"])
        self.assertDropped("eject left the removed device cached as present")

    def test_failed_unmount_still_invalidates(self):
        # The unmount can fail after partially detaching volumes, so the cached
        # view is no longer trustworthy even on the error path.
        disks, shell = self._patch_power(rc=1)
        with disks, shell:
            result = disk_power_svc.sleep_disk("disk4", mode="sleep")
        self.assertFalse(result["ok"])
        self.assertDropped("a failed sleep left the cache untouched")

    def test_wake_invalidates(self):
        disks, shell = self._patch_power()
        with disks, shell, \
                patch.object(Path, "exists", return_value=True), \
                patch.object(disk_power_svc.time, "sleep"):
            result = disk_power_svc.wake_disk("disk4")
        self.assertTrue(result["ok"])
        self.assertDropped(
            "waking remounted the volumes but left their pre-wake mount points "
            "cached"
        )

    def test_missing_device_keeps_the_cache(self):
        # The device node is gone, so nothing was mounted or unmounted and the
        # cached entries for other disks are still correct.
        disks, shell = self._patch_power()
        with disks, shell, patch.object(Path, "exists", return_value=False):
            result = disk_power_svc.wake_disk("disk4")
        self.assertFalse(result["ok"])
        self.assertKept("a no-op wake dropped the cache")

    def test_invalid_disk_id_is_rejected_before_any_command(self):
        with patch.object(disk_power_svc, "sh") as shell:
            with self.assertRaises(Exception):
                disk_power_svc.sleep_disk("disk4s1; rm -rf /")
        shell.assert_not_called()
        self.assertKept("a rejected disk id dropped the cache")


class WiringTests(unittest.TestCase):
    """Structural guards: the call must be reachable and the import present."""

    def test_disk_power_imports_the_invalidator(self):
        # A call that is not imported is an ImportError at module load, which
        # takes down every storage route rather than one endpoint.
        src = (BASE / "hub" / "disk_power_svc.py").read_text(encoding="utf-8")
        self.assertRegex(
            src,
            r"from hub\.disk_manage_svc import [^\n]*invalidate_disk_info",
            "hub/disk_power_svc.py must import invalidate_disk_info",
        )

    def test_disk_manage_does_not_import_disk_power(self):
        # disk_power_svc imports disk_manage_svc; the reverse edge would make
        # that a cycle and break module load.
        src = (BASE / "hub" / "disk_manage_svc.py").read_text(encoding="utf-8")
        self.assertNotIn("disk_power_svc", src)

    def test_every_power_mutation_point_invalidates(self):
        src = (BASE / "hub" / "disk_power_svc.py").read_text(encoding="utf-8")
        self.assertEqual(
            src.count("invalidate_disk_info()"),
            3,
            "expected invalidation after the unmount, the eject and the "
            "wake-time mountDisk",
        )


if __name__ == "__main__":
    unittest.main()
