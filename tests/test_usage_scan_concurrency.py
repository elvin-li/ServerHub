"""The usage walks run concurrently, and the shared budget survives that.

Serial walks were the slowest thing this panel did.  Measured over ~421k files
under ~/Services, taking the minimum of several rounds because the host has enough
background load that one reading measures the neighbours:

    serial 13.8s | w=1 13.7s | w=3 9.0s | w=4 6.9s | w=5 8.5s | w=8 10.2s

The w=1 control runs the concurrent code path with no concurrency and lands on the
serial time, so the gain is threads rather than an incidental rewrite.

None of that is asserted here.  Wall-clock thresholds on a loaded host fail for
reasons that have nothing to do with the code -- the same run above produced
medians between 10s and 45s.  These tests assert the two things that actually have
to hold:

  * the walk really overlaps (peak simultaneous workers, measured directly), and
  * it still returns exactly what the serial walk returned, terminates when either
    ceiling is hit, and never hands one budget's mutable state to two threads.

The last point is the sharp edge.  ``_Budget`` used to be a plain counter with a
``spend()`` that mutated three fields; handing it to four threads would have
corrupted the ceiling and, worse, could have left workers waiting on a condition
nobody would ever notify.  It now leases blocks under a lock and each thread keeps
its own ``_Spender``.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import usage_svc  # noqa: E402


class _Peak:
    """Counts how many threads are inside the guarded region at once."""

    def __init__(self):
        self._lock = threading.Lock()
        self.current = 0
        self.peak = 0

    def __enter__(self):
        with self._lock:
            self.current += 1
            self.peak = max(self.peak, self.current)
        return self

    def __exit__(self, *exc):
        with self._lock:
            self.current -= 1
        return False


def _make_tree(root: Path, dirs: int = 8, files: int = 5, depth: int = 2) -> int:
    """Build a predictable tree; return the number of files created."""
    made = 0
    for d in range(dirs):
        branch = root / f"dir{d}"
        current = branch
        for level in range(depth):
            current.mkdir(parents=True, exist_ok=True)
            for f in range(files):
                (current / f"f{level}_{f}.bin").write_bytes(b"x" * (16 + f))
                made += 1
            current = current / f"sub{level}"
    return made


def _serial_reference(target: Path) -> set[str]:
    """Every file under *target*, walked the way the module used to."""
    out: set[str] = set()
    stack = [target]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        out.add(entry.path)
        except OSError:
            continue
    return out


def _collect(target: Path, budget, workers: int, hook=None) -> list[str]:
    def sink():
        return []

    def on_file(entry, bucket):
        if hook is not None:
            hook()
        bucket.append(entry.path)

    sinks = usage_svc._walk_parallel(target, budget, sink, on_file, workers=workers)
    return [p for bucket in sinks for p in bucket]


class WalkOverlapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.expected = _make_tree(self.root)

    def test_the_fixture_built_something_worth_walking(self):
        self.assertGreater(self.expected, 40)
        self.assertEqual(len(_serial_reference(self.root)), self.expected)

    def test_workers_are_in_flight_at_the_same_time(self):
        peak = _Peak()

        def hook():
            with peak:
                # Long enough that the other workers are still inside their own
                # directories; without it a fast temp tree can finish one worker
                # before the next is scheduled and the peak says 1 for no reason.
                time.sleep(0.01)

        budget = usage_svc._Budget(60.0, 10_000_000)
        _collect(self.root, budget, workers=4, hook=hook)
        self.assertGreaterEqual(
            peak.peak, 2, "the walk ran one directory at a time despite 4 workers"
        )

    def test_a_single_worker_does_not_overlap(self):
        # The control for the test above: if the peak counter reported >= 2 here,
        # it would be measuring something other than concurrency.
        peak = _Peak()

        def hook():
            with peak:
                time.sleep(0.005)

        budget = usage_svc._Budget(60.0, 10_000_000)
        _collect(self.root, budget, workers=1, hook=hook)
        self.assertEqual(peak.peak, 1)

    def test_it_visits_every_file_exactly_once(self):
        budget = usage_svc._Budget(60.0, 10_000_000)
        found = _collect(self.root, budget, workers=4)
        self.assertEqual(
            len(found), len(set(found)), "a file was handed to two workers"
        )
        self.assertEqual(set(found), _serial_reference(self.root))
        self.assertFalse(budget.truncated)

    def test_the_result_does_not_depend_on_the_worker_count(self):
        reference = None
        for workers in (1, 2, 4, 7):
            budget = usage_svc._Budget(60.0, 10_000_000)
            found = set(_collect(self.root, budget, workers=workers))
            if reference is None:
                reference = found
            with self.subTest(workers=workers):
                self.assertEqual(found, reference)


class WalkTerminationTests(unittest.TestCase):
    """A walk that does not stop is worse than a slow one: it holds a thread."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        _make_tree(self.root)

    def test_an_expired_deadline_ends_the_walk(self):
        budget = usage_svc._Budget(-1.0, 10_000_000)
        started = time.monotonic()
        _collect(self.root, budget, workers=4)
        self.assertLess(
            time.monotonic() - started, 10.0, "the walk did not notice the deadline"
        )
        self.assertTrue(budget.truncated)

    def test_an_exhausted_entry_ceiling_ends_the_walk(self):
        budget = usage_svc._Budget(60.0, 1)
        started = time.monotonic()
        _collect(self.root, budget, workers=4)
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertTrue(budget.truncated)

    def test_a_deadline_that_expires_mid_walk_ends_it(self):
        # The case that could hang: one worker gives up while the others are
        # blocked on the condition variable waiting for work that will never come.
        budget = usage_svc._Budget(0.05, 10_000_000)
        started = time.monotonic()
        _collect(self.root, budget, workers=4, hook=lambda: time.sleep(0.002))
        self.assertLess(
            time.monotonic() - started,
            10.0,
            "workers were left waiting after another gave up on the budget",
        )

    def test_an_empty_directory_terminates(self):
        with TemporaryDirectory() as empty:
            budget = usage_svc._Budget(60.0, 10_000_000)
            self.assertEqual(_collect(Path(empty), budget, workers=4), [])


class WalkSafetyTests(unittest.TestCase):
    def test_symlinks_are_not_followed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "real" / "a.bin").write_bytes(b"a")
            (root / "loop").symlink_to(root, target_is_directory=True)
            (root / "link.bin").symlink_to(root / "real" / "a.bin")
            budget = usage_svc._Budget(20.0, 1_000_000)
            found = _collect(root, budget, workers=4)
        self.assertEqual(found, [str(root / "real" / "a.bin")])

    def test_never_walk_directories_are_skipped(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep").mkdir()
            (root / "keep" / "a.bin").write_bytes(b"a")
            budget = usage_svc._Budget(20.0, 1_000_000)
            # Declare the fixture's own subdirectory off-limits and watch it go.
            original = usage_svc._NEVER_WALK
            usage_svc._NEVER_WALK = original + (str(root / "keep"),)
            try:
                found = _collect(root, budget, workers=4)
            finally:
                usage_svc._NEVER_WALK = original
        self.assertEqual(found, [])


class BudgetThreadSafetyTests(unittest.TestCase):
    def test_the_budget_no_longer_offers_a_shared_spend(self):
        # The old API was budget.spend(), which mutated three unguarded fields.
        # A caller that hands one of those to four threads corrupts the ceiling,
        # so the method is gone rather than merely discouraged.
        self.assertFalse(
            hasattr(usage_svc._Budget(1.0, 1), "spend"),
            "_Budget still exposes a per-entry spend(); threads sharing it would "
            "race on the counter",
        )

    def test_leases_never_exceed_the_ceiling_under_contention(self):
        ceiling = 10_000
        budget = usage_svc._Budget(60.0, ceiling)
        granted = []
        lock = threading.Lock()

        def drain():
            total = 0
            while True:
                block = budget.lease(7)
                if block <= 0:
                    break
                total += block
            with lock:
                granted.append(total)

        threads = [threading.Thread(target=drain) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(
            sum(granted), ceiling, "the leases handed out more than the ceiling"
        )
        self.assertTrue(budget.truncated)

    def test_each_spender_is_independent(self):
        budget = usage_svc._Budget(60.0, 10_000)
        a, b = budget.spender(), budget.spender()
        self.assertTrue(a.spend())
        self.assertTrue(b.spend())
        self.assertIsNot(a, b)

    def test_a_spender_reports_exhaustion(self):
        budget = usage_svc._Budget(60.0, 2)
        spender = budget.spender()
        for _ in range(10):
            if not spender.spend():
                break
        else:
            self.fail("the spender never reported the ceiling")
        self.assertTrue(budget.truncated)


class HashGroupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.paths = []
        for i in range(6):
            p = root / f"f{i}.bin"
            p.write_bytes(b"same-content" if i % 2 == 0 else bytes([i]) * 32)
            self.paths.append(str(p))

    def test_hashes_come_back_in_input_order(self):
        budget = usage_svc._Budget(60.0, 1_000_000)
        digests = usage_svc._hash_group(self.paths, budget, partial=False)
        self.assertEqual(len(digests), len(self.paths))
        # Identical content must hash identically, different content must not.
        self.assertEqual(digests[0], digests[2])
        self.assertNotEqual(digests[0], digests[1])

    def test_hashing_overlaps(self):
        peak = _Peak()
        real = usage_svc._hash_file

        def slow(path, *, partial):
            with peak:
                time.sleep(0.01)
                return real(path, partial=partial)

        budget = usage_svc._Budget(60.0, 1_000_000)
        original = usage_svc._hash_file
        usage_svc._hash_file = slow
        try:
            usage_svc._hash_group(self.paths, budget, partial=True)
        finally:
            usage_svc._hash_file = original
        self.assertGreaterEqual(peak.peak, 2, "the hash stage ran one file at a time")

    def test_an_expired_budget_yields_no_digests(self):
        budget = usage_svc._Budget(-1.0, 1_000_000)
        self.assertEqual(
            usage_svc._hash_group(self.paths, budget, partial=True),
            [None] * len(self.paths),
        )

    def test_an_unreadable_file_is_none_rather_than_an_exception(self):
        # fan_out re-raises on iteration, which would cost the whole group.
        budget = usage_svc._Budget(60.0, 1_000_000)
        digests = usage_svc._hash_group(
            self.paths[:1] + ["/nonexistent/serverhub-test/nope.bin"],
            budget,
            partial=True,
        )
        self.assertIsNotNone(digests[0])
        self.assertIsNone(digests[1])


class TreeVanishedDirTests(unittest.TestCase):
    def test_scandir_filenotfound_is_not_permission_denied(self):
        from unittest.mock import patch

        from fastapi import HTTPException

        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "live"
            target.mkdir()
            with (
                patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(root)}],
                ),
                patch.object(usage_svc, "_is_never_walk", return_value=False),
                patch.object(usage_svc.files_svc, "is_protected", return_value=False),
                patch.object(usage_svc.os, "scandir", side_effect=FileNotFoundError),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    usage_svc.tree(str(target), "t")
            self.assertEqual(ctx.exception.detail["code"], "files.not_found")

    def test_scandir_permissionerror_stays_permission_denied(self):
        from unittest.mock import patch

        from fastapi import HTTPException

        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "live"
            target.mkdir()
            with (
                patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(root)}],
                ),
                patch.object(usage_svc, "_is_never_walk", return_value=False),
                patch.object(usage_svc.files_svc, "is_protected", return_value=False),
                patch.object(usage_svc.os, "scandir", side_effect=PermissionError),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    usage_svc.tree(str(target), "t")
            self.assertEqual(ctx.exception.detail["code"], "files.permission_denied")


if __name__ == "__main__":
    unittest.main()
