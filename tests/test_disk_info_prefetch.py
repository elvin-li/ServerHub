"""Listing volumes must warm `diskutil info` in one parallel batch.

``list_managed_volumes`` walks the device tree and asks ``_diskutil_info()`` for
every node it visits.  Each cache miss is a ~130ms subprocess, so on a host with
many partitions that walk spent seconds in strictly serial waits -- the whole
/api/storage request stalled behind it.  ``_prefetch_disk_info`` exists to
collapse those waits into a handful of concurrent ones, but it was never called,
so the optimisation was inert and the walk stayed serial.

These tests pin two properties that a future refactor could quietly lose:

* the prefetch covers **every** identifier the walk will visit, including nested
  APFS volumes -- a node missed here falls back to a serial subprocess inside
  the walk, which is the exact cost this is meant to remove;
* the fetches genuinely overlap.  A barrier is used rather than a wall-clock
  measurement: if the calls were serialised the first one could never see its
  peers arrive, so the test fails deterministically instead of flaking on a
  loaded machine.
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import disk_manage_svc  # noqa: E402

#: A whole disk with a partition and two nested APFS volumes.  The nesting
#: matters: APFS volumes hang off ``APFSVolumes`` rather than ``Partitions``, and
#: a collector that only looked at one key would silently leave them serial.
TREE = {
    "AllDisksAndPartitions": [
        {
            "DeviceIdentifier": "disk9",
            "Size": 1000,
            "Content": "GUID_partition_scheme",
            "Partitions": [
                {"DeviceIdentifier": "disk9s1", "Size": 200, "Content": "EFI"},
            ],
            "APFSVolumes": [
                {"DeviceIdentifier": "disk9s2", "Size": 400, "VolumeName": "Alpha"},
                {"DeviceIdentifier": "disk9s3", "Size": 400, "VolumeName": "Beta"},
            ],
        },
    ],
}

#: Every identifier in TREE, in no particular order.
EXPECTED_NODES = {"disk9", "disk9s1", "disk9s2", "disk9s3"}


class _Harness:
    """Replaces the two subprocess doors of disk_manage_svc with fakes.

    ``_plist`` serves the tree listings; ``_diskutil_info_uncached`` records
    which nodes were asked for and on which thread.  Nothing here shells out, so
    the test says the same thing on a laptop with 25 volumes and in CI with one.
    """

    def __init__(self, barrier_parties: int | None = None):
        self.info_calls: list[str] = []
        self.threads: set[int] = set()
        self.lock = threading.Lock()
        self.barrier = (
            threading.Barrier(barrier_parties) if barrier_parties else None
        )
        self.barrier_broke = False

    def plist(self, args, timeout=None):
        if "physical" in args:
            return {"WholeDisks": ["disk9"]}
        if "list" in args:
            return TREE
        return {}

    def sh(self, args, timeout=None):
        # Only /bin/df reaches here; the root probe below is answered by the
        # info fake.
        return 0, "Filesystem\n/dev/disk3s1 1 1 1 100% /\n", ""

    def info(self, node: str) -> dict:
        with self.lock:
            self.info_calls.append(node)
            self.threads.add(threading.get_ident())
        if self.barrier is not None and node in EXPECTED_NODES:
            try:
                self.barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                self.barrier_broke = True
        if node == "/":
            return {"ParentWholeDisk": "disk3", "MountPoint": "/"}
        return {"VolumeName": f"vol-{node}", "MountPoint": f"/Volumes/{node}"}

    def __enter__(self):
        self._patches = [
            patch.object(disk_manage_svc, "_plist", self.plist),
            patch.object(disk_manage_svc, "sh", self.sh),
            patch.object(disk_manage_svc, "_diskutil_info_uncached", self.info),
        ]
        for p in self._patches:
            p.start()
        disk_manage_svc.invalidate_disk_info()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        disk_manage_svc.invalidate_disk_info()
        return False


class PrefetchCoverageTests(unittest.TestCase):
    def tearDown(self):
        disk_manage_svc.invalidate_disk_info()

    def test_every_visited_node_is_fetched_exactly_once(self):
        with _Harness() as h:
            disk_manage_svc.list_managed_volumes()

        fetched = [n for n in h.info_calls if n in EXPECTED_NODES]
        self.assertEqual(
            set(fetched),
            EXPECTED_NODES,
            "the prefetch missed a node the walk visits; that node falls back "
            "to a serial ~130ms subprocess inside the walk",
        )
        self.assertEqual(
            len(fetched),
            len(EXPECTED_NODES),
            f"a node was fetched more than once: {sorted(fetched)}",
        )

    def test_nested_apfs_volumes_are_included(self):
        # Regression guard for a collector that only walks "Partitions": the
        # APFS volumes are where the volume count (and the cost) actually lives.
        with _Harness() as h:
            disk_manage_svc.list_managed_volumes()

        for node in ("disk9s2", "disk9s3"):
            with self.subTest(node=node):
                self.assertIn(node, h.info_calls)

    def test_the_walk_adds_no_subprocess_of_its_own(self):
        # If the prefetch works, the walk is served entirely from cache, so the
        # only fetches are the batched ones plus the root probe.
        with _Harness() as h:
            disk_manage_svc.list_managed_volumes()

        extra = [n for n in h.info_calls if n not in EXPECTED_NODES]
        self.assertEqual(
            extra,
            [],
            f"unexpected uncached fetches outside the batch: {extra}",
        )

    def test_results_still_reach_the_output(self):
        # Warming a cache is only correct if the walk reads the same values back.
        with _Harness():
            vols = disk_manage_svc.list_managed_volumes()

        by_id = {v["id"]: v for v in vols}
        self.assertEqual(set(by_id) & EXPECTED_NODES, EXPECTED_NODES)
        self.assertEqual(by_id["disk9s2"]["volume_name"], "vol-disk9s2")


class PrefetchConcurrencyTests(unittest.TestCase):
    def tearDown(self):
        disk_manage_svc.invalidate_disk_info()

    def test_the_batch_runs_concurrently(self):
        # Each of the four nodes blocks until all four have arrived.  Serial
        # execution can never satisfy that, so this fails loudly rather than
        # measuring elapsed time and hoping the machine is idle.
        with _Harness(barrier_parties=len(EXPECTED_NODES)) as h:
            disk_manage_svc.list_managed_volumes()

        self.assertFalse(
            h.barrier_broke,
            "the prefetch did not run its nodes concurrently -- the walk is "
            "back to one blocking subprocess per volume",
        )
        self.assertGreater(
            len(h.threads),
            1,
            "all fetches ran on one thread; the ThreadPoolExecutor fan-out is "
            "not being used",
        )

    def test_worker_count_stays_bounded(self):
        # diskutil is a system service.  Trading one slow request for a
        # thundering herd of processes would just move the problem.
        self.assertLessEqual(disk_manage_svc._INFO_WORKERS, 8)
        self.assertGreater(disk_manage_svc._INFO_WORKERS, 1)


class PrefetchCacheInteractionTests(unittest.TestCase):
    def tearDown(self):
        disk_manage_svc.invalidate_disk_info()

    def test_already_cached_nodes_are_not_refetched(self):
        disk_manage_svc.invalidate_disk_info()
        calls: list[str] = []

        def info(node: str) -> dict:
            calls.append(node)
            return {"VolumeName": node}

        with patch.object(disk_manage_svc, "_diskutil_info_uncached", info):
            disk_manage_svc._prefetch_disk_info(["disk9", "disk9s1"])
            disk_manage_svc._prefetch_disk_info(["disk9", "disk9s1"])

        self.assertEqual(
            sorted(calls),
            ["disk9", "disk9s1"],
            "a warm entry was fetched again; the TTL is not being honoured",
        )

    def test_invalidation_forces_a_refetch(self):
        # The mutating paths drop the cache precisely so the next listing sees
        # the new state; the prefetch must not defeat that.
        calls: list[str] = []

        def info(node: str) -> dict:
            calls.append(node)
            return {"VolumeName": node}

        with patch.object(disk_manage_svc, "_diskutil_info_uncached", info):
            disk_manage_svc._prefetch_disk_info(["disk9"])
            disk_manage_svc.invalidate_disk_info()
            disk_manage_svc._prefetch_disk_info(["disk9"])

        self.assertEqual(calls, ["disk9", "disk9"])

    def test_empty_and_blank_nodes_are_ignored(self):
        calls: list[str] = []

        def info(node: str) -> dict:
            calls.append(node)
            return {}

        with patch.object(disk_manage_svc, "_diskutil_info_uncached", info):
            disk_manage_svc._prefetch_disk_info([])
            disk_manage_svc._prefetch_disk_info(["", ""])

        self.assertEqual(calls, [], "a blank identifier reached diskutil")


if __name__ == "__main__":
    unittest.main()
