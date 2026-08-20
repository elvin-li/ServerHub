"""Guards for the read-only storage-pool planner.

The pool is deliberately *not* RAID: members stay independent, each file lives
whole on one disk, and losing a disk costs only that disk's files.  Two things
must never regress:

1. The planner must not touch the disks.  It reports what a pool would look
   like; mounting needs a union filesystem that is not installed.
2. System volumes must never be eligible.  A boot volume in the pool makes the
   pool undetachable and risks the running OS.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import HTTPException

from hub import storage_pool_svc, storage_svc

#: Two external disks with very different free space, plus the volumes a real
#: macOS host always has.  Free space differs so placement policy is testable.
VOLS = [
    {"device": "/dev/disk3s1s1", "mount": "/", "kind": "system",
     "total_gb": 926.4, "used_gb": 11.7, "avail_gb": 735.1, "pct": 2, "disk_id": "disk3"},
    {"device": "/dev/disk3s5", "mount": "/System/Volumes/Data", "kind": "system",
     "total_gb": 926.4, "used_gb": 169.7, "avail_gb": 735.1, "pct": 19, "disk_id": "disk3"},
    {"device": "OrbStack:/OrbStack", "mount": "/Users/exampleuser/OrbStack", "kind": "orbstack",
     "total_gb": 704.2, "used_gb": 6.0, "avail_gb": 698.2, "pct": 1, "disk_id": None},
    {"device": "/dev/disk6s1", "mount": "/Volumes/PhotoVault", "kind": "external",
     "total_gb": 1788.3, "used_gb": 100.0, "avail_gb": 1688.3, "pct": 6, "disk_id": "disk6"},
    {"device": "/dev/disk7s1", "mount": "/Volumes/Archive", "kind": "external",
     "total_gb": 1000.0, "used_gb": 900.0, "avail_gb": 100.0, "pct": 90, "disk_id": "disk7"},
]

POOL = ["/Volumes/PhotoVault", "/Volumes/Archive"]


class PoolTestBase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(storage_svc, "list_volumes", return_value=list(VOLS))
        patcher.start()
        self.addCleanup(patcher.stop)
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)


class TestNothingIsMutated(PoolTestBase):
    """Planning must not shell out to anything that can change disk state."""

    FORBIDDEN = ("diskutil", "mount", "umount", "newfs", "mergerfs", "mount_fusefs", "ln")

    def _assert_no_state_change(self, call):
        seen: list[str] = []

        def spy(cmd, *a, **kw):
            seen.append(" ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd))
            return (0, "", "")

        with mock.patch.object(storage_pool_svc, "cfg", return_value={}), \
             mock.patch("hub.util.sh", side_effect=spy), \
             mock.patch("subprocess.run", side_effect=AssertionError("subprocess.run called")):
            call()

        offenders = [c for c in seen if any(f in c for f in self.FORBIDDEN)]
        self.assertEqual(offenders, [], f"planner ran a state-changing command: {offenders}")

    def test_overview_runs_no_state_changing_command(self):
        self._assert_no_state_change(lambda: storage_pool_svc.pool_overview(force=True))

    def test_plan_runs_no_state_changing_command(self):
        self._assert_no_state_change(lambda: storage_pool_svc.plan_pool(POOL))

    def test_plan_reports_that_nothing_was_applied(self):
        plan = storage_pool_svc.plan_pool(POOL)
        self.assertFalse(plan["applied"])
        self.assertFalse(plan["union"]["single_mount_supported"])


class TestSystemVolumesAreNeverEligible(PoolTestBase):
    def test_boot_and_data_volumes_are_not_candidates(self):
        mounts = {c["mount"] for c in storage_pool_svc.pool_overview(force=True)["unassigned"]}
        self.assertNotIn("/", mounts)
        self.assertNotIn("/System/Volumes/Data", mounts)

    def test_virtual_filesystems_are_not_candidates(self):
        mounts = {c["mount"] for c in storage_pool_svc.pool_overview(force=True)["unassigned"]}
        self.assertNotIn("/Users/exampleuser/OrbStack", mounts)

    def test_external_volumes_are_candidates(self):
        mounts = {c["mount"] for c in storage_pool_svc.pool_overview(force=True)["unassigned"]}
        self.assertEqual(mounts, {"/Volumes/PhotoVault", "/Volumes/Archive"})

    def test_junk_volume_rows_do_not_500_the_planner(self):
        junk = list(VOLS) + [
            "not-a-row",
            {"kind": "external", "mount": "/Volumes/Broken", "total_gb": "huge"},
        ]
        with mock.patch.object(storage_svc, "list_volumes", return_value=junk):
            overview = storage_pool_svc.pool_overview(force=True)
        mounts = {c["mount"] for c in overview["unassigned"]}
        self.assertIn("/Volumes/Broken", mounts)
        broken = next(c for c in overview["unassigned"] if c["mount"] == "/Volumes/Broken")
        self.assertEqual(broken["total_gb"], 0.0)

    def test_a_system_volume_cannot_be_planned_into_a_pool(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.plan_pool(["/", "/Volumes/PhotoVault"])
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.not_poolable")


class TestCapacityIsAdditiveNotStriped(PoolTestBase):
    def test_capacity_is_the_sum_of_members(self):
        s = storage_pool_svc.plan_pool(POOL)["summary"]
        self.assertAlmostEqual(s["total_gb"], 2788.3, places=1)
        self.assertAlmostEqual(s["used_gb"], 1000.0, places=1)
        self.assertAlmostEqual(s["avail_gb"], 1788.3, places=1)

    def test_largest_single_file_is_bounded_by_one_member(self):
        """The trap of a JBOD union: 1788GB free, but no single 1788GB file."""
        s = storage_pool_svc.plan_pool(POOL)["summary"]
        self.assertAlmostEqual(s["largest_single_file_gb"], 1688.3, places=1)
        self.assertLess(s["largest_single_file_gb"], s["avail_gb"])

    def test_response_states_it_is_not_raid(self):
        plan = storage_pool_svc.plan_pool(POOL)
        self.assertFalse(plan["raid"])
        self.assertFalse(plan["parity"])


class TestFaultModelIsPerDisk(PoolTestBase):
    def test_losing_one_member_keeps_the_others(self):
        rows = {r["mount"]: r for r in storage_pool_svc.plan_pool(POOL)["fault_model"]}
        archive = rows["/Volumes/Archive"]
        self.assertAlmostEqual(archive["at_risk_gb"], 900.0, places=1)
        self.assertAlmostEqual(archive["survives_gb"], 1788.3, places=1)
        self.assertFalse(archive["other_members_affected"])

    def test_every_member_has_a_blast_radius_row(self):
        rows = storage_pool_svc.plan_pool(POOL)["fault_model"]
        self.assertEqual({r["mount"] for r in rows}, set(POOL))


class TestWritePlacement(PoolTestBase):
    def test_most_free_targets_the_emptiest_member(self):
        plan = storage_pool_svc.plan_pool(POOL, policy="most-free")
        self.assertEqual(plan["next_write_target"], "/Volumes/PhotoVault")

    def test_least_used_pct_targets_the_lowest_percentage(self):
        plan = storage_pool_svc.plan_pool(POOL, policy="least-used-pct")
        self.assertEqual(plan["next_write_target"], "/Volumes/PhotoVault")

    def test_unknown_policy_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.plan_pool(POOL, policy="stripe")
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.bad_policy")

    def test_empty_member_list_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.plan_pool([])
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.no_members")


class TestOverviewCache(PoolTestBase):
    def test_repeated_calls_reuse_the_cached_view(self):
        calls = {"n": 0}
        real = storage_svc.list_volumes

        def counting(*a, **kw):
            calls["n"] += 1
            return list(VOLS)

        with mock.patch.object(storage_svc, "list_volumes", side_effect=counting):
            storage_pool_svc.pool_overview(force=True)
            first = calls["n"]
            storage_pool_svc.pool_overview()
            storage_pool_svc.pool_overview()
            self.assertEqual(calls["n"], first, "cached view still re-read the volumes")
        del real

    def test_callers_cannot_mutate_the_cached_view(self):
        a = storage_pool_svc.pool_overview(force=True)
        a["members"] = "clobbered"
        b = storage_pool_svc.pool_overview()
        self.assertIsInstance(b["members"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
