"""Concurrent readers must share one `diskutil info` per node, not one each.

The cache in ``hub.disk_manage_svc`` only helps *after* a fetch completes, so
simultaneous readers each began their own fan-out for the same nodes.  Measured on
a 39-node host: one reader spawned 38 ``diskutil info`` processes in 2.1s, two
spawned 76 in 4.4s, four spawned 152 in 9.5s -- latency scaling linearly with
readers because they competed for one system service while fetching identical
data.  The panel polls, the menu-bar client polls, and a browser refresh adds a
third reader, which is how /api/storage was observed taking ~20s.

Raising the worker count does not fix this and was measured to do nothing at all
(``diskutil`` serialises internally).  De-duplicating the concurrent fetches does:
these tests pin that, and pin the one race it introduces -- a fetch in flight when
a mount/unmount lands must not write its stale result into the cache.
"""
from __future__ import annotations

import sys
import threading
import unittest
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import disk_manage_svc  # noqa: E402

NODES = ["disk4", "disk4s1", "disk4s2", "disk5s1"]


class SingleFlightTests(unittest.TestCase):
    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)
        self.calls: list[str] = []
        self.lock = threading.Lock()
        # Every fetch waits until all readers have arrived, so the test forces the
        # exact overlap the fix is about instead of hoping for a timing race.
        self.gate = threading.Event()

    def _slow_fetch(self, node: str) -> dict:
        with self.lock:
            self.calls.append(node)
        self.gate.wait(timeout=5)
        return {"VolumeName": node}

    def test_concurrent_readers_of_one_node_cause_one_subprocess(self):
        readers = 8
        with patch.object(disk_manage_svc, "_diskutil_info_uncached", self._slow_fetch):
            with ThreadPoolExecutor(max_workers=readers) as ex:
                futures = [ex.submit(disk_manage_svc._diskutil_info, "disk4") for _ in range(readers)]
                # Let the waiters pile up behind the owner before releasing it.
                threading.Timer(0.2, self.gate.set).start()
                results = [f.result(timeout=10) for f in futures]

        self.assertEqual(self.calls, ["disk4"], "each reader ran its own subprocess")
        for result in results:
            self.assertEqual(result, {"VolumeName": "disk4"})

    def test_every_reader_receives_the_shared_result(self):
        """A joiner must get real data, not an empty dict."""
        self.gate.set()
        with patch.object(disk_manage_svc, "_diskutil_info_uncached", self._slow_fetch):
            with ThreadPoolExecutor(max_workers=4) as ex:
                results = list(ex.map(lambda _: disk_manage_svc._diskutil_info("disk4s1"), range(4)))
        self.assertTrue(all(r == {"VolumeName": "disk4s1"} for r in results))

    def test_concurrent_prefetches_share_one_fetch_per_node(self):
        self.gate.set()
        with patch.object(disk_manage_svc, "_diskutil_info_uncached", self._slow_fetch):
            with ThreadPoolExecutor(max_workers=4) as ex:
                list(ex.map(lambda _: disk_manage_svc._prefetch_disk_info(NODES), range(4)))

        counts = Counter(self.calls)
        self.assertEqual(
            sorted(counts), sorted(NODES), "prefetch fetched an unexpected node set"
        )
        duplicated = {node: n for node, n in counts.items() if n != 1}
        self.assertEqual(
            duplicated, {}, f"nodes fetched more than once: {duplicated}"
        )

    def test_inflight_map_is_left_empty(self):
        """A leaked entry would wedge every later reader of that node."""
        self.gate.set()
        with patch.object(disk_manage_svc, "_diskutil_info_uncached", self._slow_fetch):
            disk_manage_svc._prefetch_disk_info(NODES)
        with disk_manage_svc._INFO_LOCK:
            self.assertEqual(dict(disk_manage_svc._INFO_INFLIGHT), {})

    def test_a_failing_fetch_does_not_leak_an_inflight_entry(self):
        def boom(node: str) -> dict:
            raise OSError("diskutil exploded")

        with patch.object(disk_manage_svc, "_diskutil_info_uncached", boom):
            with self.assertRaises(OSError):
                disk_manage_svc._diskutil_info("disk4")
        with disk_manage_svc._INFO_LOCK:
            self.assertEqual(dict(disk_manage_svc._INFO_INFLIGHT), {})


class InvalidationRaceTests(unittest.TestCase):
    """A fetch already running when a mount lands must not cache a stale result."""

    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    def test_result_from_before_an_invalidation_is_not_cached(self):
        started = threading.Event()
        release = threading.Event()

        def slow(node: str) -> dict:
            started.set()
            release.wait(timeout=5)
            return {"MountPoint": "/Volumes/Stale"}

        with patch.object(disk_manage_svc, "_diskutil_info_uncached", slow):
            with ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(disk_manage_svc._diskutil_info, "disk4s1")
                self.assertTrue(started.wait(timeout=5))
                # The user unmounts while the read is in flight.
                disk_manage_svc.invalidate_disk_info()
                release.set()
                # The in-flight caller still gets its answer...
                self.assertEqual(future.result(timeout=5), {"MountPoint": "/Volumes/Stale"})

        # ...but it must not have become the cached truth, or the page would keep
        # rendering the volume as mounted for a full TTL after the unmount.
        with disk_manage_svc._INFO_LOCK:
            self.assertNotIn(
                "disk4s1",
                disk_manage_svc._INFO_CACHE,
                "a pre-invalidation result was written into the cache afterwards",
            )

    def test_a_fetch_started_after_the_invalidation_is_cached(self):
        """The guard must not block legitimate caching."""
        with patch.object(
            disk_manage_svc, "_diskutil_info_uncached", return_value={"MountPoint": "/Volumes/Fresh"}
        ):
            disk_manage_svc.invalidate_disk_info()
            disk_manage_svc._diskutil_info("disk4s2")
        with disk_manage_svc._INFO_LOCK:
            self.assertIn("disk4s2", disk_manage_svc._INFO_CACHE)


if __name__ == "__main__":
    unittest.main()
