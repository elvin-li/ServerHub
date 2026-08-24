"""Every TTL cache in hub/ goes through a shared helper, and both are single-flight.

A cache that checks its TTL, releases the lock, and *then* does the work is correct
only while callers arrive one at a time. Once several branches of a fan-out -- or
several polling requests -- reach it together they all miss, all do the work, and the
cache never helps on the read that needed it most. It is worst exactly where it
matters: when a rebuild takes longer than the poll interval, every poll arriving
during a rebuild starts another one.

Two shapes existed in this tree, both hand-written per module:

* per-key sub-reads, now :func:`hub.util.ttl_memo`;
* whole-payload endpoint snapshots behind a ``force`` flag, now
  :func:`hub.util.cached_snapshot`.

Eight modules had hand-written copies of the second, and every one of them had no
lock at all -- so besides rebuilding concurrently, ``_cache.update(t=..., v=...)`` is
two key writes rather than one atomic publish, and a reader could observe the new
timestamp beside the previous payload and serve a stale answer as fresh for a whole
TTL. Consolidating them means the property is asserted once, here, instead of being
re-established per module.

Two page caches stay hand-written on purpose and are exempted below with reasons:
``network_svc`` coalesces a ``force=True`` caller onto a refresh already in flight,
and ``status.full_status`` serves the last good snapshot when a rebuild raises.
Neither behaviour belongs in the shared helper, and both are already single-flight.
The third reason ``network_svc`` used to give -- a generation counter, so that an
invalidation landing mid-build is not overwritten when the build finishes -- is no
longer one: both shared helpers do that now, and it is asserted below.

A static scan of this was written first and produced two false positives -- exactly
those two -- because their work happens inside a ``_build_*()`` call the token list
did not recognise. So the assertions here drive real concurrent callers and count
real work, and the structural test only checks that a shared helper is used at all.
"""
from __future__ import annotations

import ast
import contextlib
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.util import cached_snapshot, ttl_memo  # noqa: E402

HUB = BASE / "hub"


class CachedSnapshotContractTests(unittest.TestCase):
    """The helper the eight whole-payload caches now share."""

    def test_concurrent_callers_build_once(self):
        built = []
        lock = threading.Lock()

        @cached_snapshot(30.0)
        def read():
            with lock:
                built.append(1)
            time.sleep(0.05)
            return {"n": len(built)}

        results = []
        threads = [threading.Thread(target=lambda: results.append(read())) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(built), 1, f"eight callers rebuilt {len(built)} times")
        self.assertEqual(len(results), 8)
        self.assertEqual(
            len({id(r) for r in results}), 1, "callers got different objects"
        )

    def test_the_timestamp_and_payload_are_published_together(self):
        """A reader must never see a fresh timestamp beside a stale payload.

        Two separate key writes on an unlocked dict allowed exactly that, which made
        a stale answer look fresh for a whole TTL.
        """
        @cached_snapshot(30.0)
        def read():
            time.sleep(0.05)
            return {"payload": True}

        seen = []
        stop = threading.Event()

        def poll():
            while not stop.is_set():
                seen.append(read())

        watcher = threading.Thread(target=poll, daemon=True)
        watcher.start()
        read()
        stop.set()
        watcher.join(timeout=2)

        self.assertTrue(
            all(v == {"payload": True} for v in seen),
            "a caller observed something other than a fully built payload",
        )

    def test_a_second_read_inside_the_ttl_does_not_rebuild(self):
        built = []

        @cached_snapshot(30.0)
        def read():
            built.append(1)
            return {"n": len(built)}

        read()
        read()
        self.assertEqual(len(built), 1)

    def test_an_expired_ttl_rebuilds(self):
        built = []

        @cached_snapshot(0.01)
        def read():
            built.append(1)
            return {"n": len(built)}

        read()
        time.sleep(0.05)
        read()
        self.assertEqual(len(built), 2)

    def test_force_bypasses_the_cache(self):
        built = []

        @cached_snapshot(30.0)
        def read():
            built.append(1)
            return {"n": len(built)}

        read()
        read(force=True)
        self.assertEqual(len(built), 2, "force did not rebuild")

    def test_force_is_passed_to_a_builder_that_wants_it(self):
        """``apps_manage_svc.inventory`` re-probes brew for just-installed natives."""
        seen = []

        @cached_snapshot(30.0)
        def read(force: bool = False):
            seen.append(force)
            return {"force": force}

        read()
        read(force=True)
        self.assertEqual(seen, [False, True])

    def test_a_builder_that_takes_nothing_is_called_with_nothing(self):
        @cached_snapshot(30.0)
        def read():
            return {"ok": True}

        self.assertEqual(read(), {"ok": True})
        self.assertEqual(read(force=True), {"ok": True})

    def test_invalidate_forces_the_next_read_to_rebuild(self):
        built = []

        @cached_snapshot(30.0)
        def read():
            built.append(1)
            return {"n": len(built)}

        read()
        read.invalidate()
        read()
        self.assertEqual(len(built), 2)
        self.assertIs(read.cache_clear, read.invalidate, "the alias diverged")

    def test_an_invalidate_during_a_build_is_not_undone_by_that_build(self):
        """The build already read the pre-action world; publishing it loses the action.

        The invalidate calls in this tree all sit on the mutation path -- stop a
        container, change a share, rotate a key -- and the dashboard is polling
        the whole time, so an overlapping build is the normal case rather than a
        narrow window. Without a generation counter the poll that started a
        moment before the click wins, and the page shows the pre-action state
        until the TTL lapses.
        """
        world = {"state": "running"}
        reading = threading.Event()
        release = threading.Event()

        @cached_snapshot(30.0)
        def read():
            observed = world["state"]
            reading.set()
            release.wait(2)
            return {"state": observed}

        slow = threading.Thread(target=read)
        slow.start()
        self.assertTrue(reading.wait(2), "the build never started")

        world["state"] = "stopped"
        read.invalidate()
        release.set()
        slow.join(timeout=2)

        self.assertEqual(
            read(),
            {"state": "stopped"},
            "a build that began before invalidate() republished the stale payload",
        )

    def test_a_build_with_no_invalidate_racing_it_still_publishes(self):
        """The generation check must not turn every refresh into a rebuild."""
        built = []

        @cached_snapshot(30.0)
        def read():
            built.append(1)
            return {"n": len(built)}

        read()
        read()
        read()
        self.assertEqual(len(built), 1, "the epoch check defeated the cache")

    def test_a_raising_builder_is_not_cached(self):
        """Otherwise one transient failure would be served for a whole TTL."""
        calls = []

        @cached_snapshot(30.0)
        def read():
            calls.append(1)
            raise RuntimeError("probe failed")

        for _ in range(2):
            with self.assertRaises(RuntimeError):
                read()
        self.assertEqual(len(calls), 2, "a failure was cached")


class TtlMemoContractTests(unittest.TestCase):
    """The per-key helper, which the same mutation paths invalidate."""

    def test_concurrent_callers_of_one_key_read_once(self):
        reads = []
        lock = threading.Lock()

        @ttl_memo(30.0)
        def read(device):
            with lock:
                reads.append(device)
            time.sleep(0.05)
            return device.upper()

        threads = [threading.Thread(target=read, args=("disk0",)) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(reads, ["disk0"], f"eight callers ran {len(reads)} reads")

    def test_two_keys_are_still_read_concurrently(self):
        """Serialising distinct keys would defeat the fan-out that motivated this."""
        live = 0
        peak = 0
        lock = threading.Lock()

        @ttl_memo(30.0)
        def read(device):
            nonlocal live, peak
            with lock:
                live += 1
                peak = max(peak, live)
            time.sleep(0.05)
            with lock:
                live -= 1
            return device

        threads = [
            threading.Thread(target=read, args=(f"disk{n}",)) for n in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(peak, 4, "per-key reads stopped overlapping")

    def test_an_invalidate_during_a_read_is_not_undone_by_that_read(self):
        """Same property as the snapshot helper, and the same reason it matters."""
        world = {"state": "attached"}
        reading = threading.Event()
        release = threading.Event()

        @ttl_memo(30.0)
        def read(device):
            observed = world["state"]
            reading.set()
            release.wait(2)
            return observed

        slow = threading.Thread(target=read, args=("disk0",))
        slow.start()
        self.assertTrue(reading.wait(2), "the read never started")

        world["state"] = "detached"
        read.invalidate()
        release.set()
        slow.join(timeout=2)

        self.assertEqual(
            read("disk0"),
            "detached",
            "a read that began before invalidate() republished the stale value",
        )

    def test_the_epoch_check_does_not_defeat_the_cache(self):
        reads = []

        @ttl_memo(30.0)
        def read(device):
            reads.append(device)
            return device

        read("disk0")
        read("disk0")
        read("disk1")
        self.assertEqual(reads, ["disk0", "disk1"])


class ConvertedSnapshotTests(unittest.TestCase):
    """Each converted module still caches, still rebuilds, and no longer stampedes."""

    def test_the_bookmark_sweep_runs_once_for_concurrent_callers(self):
        from hub import bookmarks_svc

        links = [
            {"name": "One", "url": "http://10.0.0.1:8001", "id": "a"},
            {"name": "Two", "url": "http://10.0.0.1:8002", "id": "b"},
            {"name": "Three", "url": "http://10.0.0.1:8003", "id": "c"},
        ]
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

        probed = []
        lock = threading.Lock()

        def probe(url, timeout=3.0):
            with lock:
                probed.append(url)
            time.sleep(0.05)
            return {"ok": True, "status": 200, "ms": 5}

        with contextlib.ExitStack() as stack:
            for target, value in {
                "cfg": lambda: {"quick_links": list(links), "overrides": {}},
                "resolve_value": lambda v: v,
                "_backend_index": lambda: {},
                "_resolve_backend": lambda link, idx: None,
                "_probe": probe,
            }.items():
                stack.enter_context(mock.patch.object(bookmarks_svc, target, value))

            results = []
            threads = [
                threading.Thread(
                    target=lambda: results.append(bookmarks_svc.list_bookmarks())
                )
                for _ in range(6)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(
            len(probed), len(links),
            f"six concurrent readers ran {len(probed)} probes for {len(links)} "
            "bookmarks; the sweep should happen once",
        )
        self.assertTrue(all(r["up"] == 3 for r in results))
        self.assertEqual(
            [b["name"] for b in results[0]["bookmarks"]], ["One", "Two", "Three"],
            "rows stopped following configuration order",
        )

    def test_a_failing_bookmark_probe_costs_only_its_own_row(self):
        from hub import bookmarks_svc

        links = [
            {"name": "One", "url": "http://10.0.0.1:8001", "id": "a"},
            {"name": "Two", "url": "http://10.0.0.1:8002", "id": "b"},
        ]
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

        def probe(url, timeout=3.0):
            if url.endswith("8002"):
                raise OSError("connection reset")
            return {"ok": True, "status": 200, "ms": 1}

        with contextlib.ExitStack() as stack:
            for target, value in {
                "cfg": lambda: {"quick_links": list(links), "overrides": {}},
                "resolve_value": lambda v: v,
                "_backend_index": lambda: {},
                "_resolve_backend": lambda link, idx: None,
                "_probe": probe,
            }.items():
                stack.enter_context(mock.patch.object(bookmarks_svc, target, value))
            data = bookmarks_svc.list_bookmarks()

        self.assertEqual(len(data["bookmarks"]), 2, "a raising probe dropped a row")
        by_name = {b["name"]: b for b in data["bookmarks"]}
        self.assertEqual(by_name["Two"]["health"], "error")
        self.assertEqual(by_name["One"]["health"], "ok")

    def test_a_backend_index_raise_still_lists_bookmarks(self):
        from hub import bookmarks_svc

        links = [{"name": "One", "url": "http://10.0.0.1:8001", "id": "a"}]
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

        with contextlib.ExitStack() as stack:
            for target, value in {
                "cfg": lambda: {"quick_links": list(links), "overrides": {}},
                "resolve_value": lambda v: v,
                "_backend_index": mock.Mock(side_effect=RuntimeError("utmctl timeout")),
                "_resolve_backend": lambda link, idx: None,
                "_probe": lambda url, timeout=3.0: {"ok": True, "status": 200, "ms": 1},
            }.items():
                stack.enter_context(mock.patch.object(bookmarks_svc, target, value))
            data = bookmarks_svc.list_bookmarks()
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["name"], "One")

    def test_every_converted_reader_exposes_invalidation(self):
        """Mutation paths call these; a missing attribute would be an AttributeError
        at the moment a setting is changed, which is the worst time to find out."""
        from hub import (
            apps_manage_svc, autostart_svc, bookmarks_svc, immich_svc, nfs_svc,
            raid_svc, snapshots_svc, system_settings_svc,
        )

        readers = [
            apps_manage_svc.inventory,
            autostart_svc.overview,
            bookmarks_svc.list_bookmarks,
            immich_svc.run_checks,
            nfs_svc.overview,
            raid_svc.overview,
            snapshots_svc.overview,
            system_settings_svc.unraid_settings_bundle,
        ]
        for reader in readers:
            with self.subTest(reader=reader.__name__):
                self.assertTrue(
                    hasattr(reader, "invalidate"),
                    f"{reader.__name__} is not a cached_snapshot",
                )

    def test_the_module_level_invalidate_helpers_still_work(self):
        """`nfs_svc.invalidate()` and friends are called from mutation paths."""
        from hub import nfs_svc, raid_svc, snapshots_svc

        for module in (nfs_svc, raid_svc, snapshots_svc):
            with self.subTest(module=module.__name__):
                module.invalidate()  # must not raise


class AdaptiveScanCacheTests(unittest.TestCase):
    """/api/status is the most polled endpoint; its two scans should run once."""

    def setUp(self):
        from hub import status

        self.status = status
        self._reset()
        self.addCleanup(self._reset)

    def _reset(self):
        with self.status._lock:
            self.status._adaptive_cache.update(t=0.0, compose=None, nginx=None)

    def test_concurrent_callers_scan_once(self):
        calls = []
        lock = threading.Lock()

        def slow(tag, result):
            def run():
                with lock:
                    calls.append(tag)
                time.sleep(0.05)
                return result
            return run

        with (
            mock.patch.object(self.status, "scan_new_compose_projects",
                              slow("compose", ["proj"])),
            mock.patch.object(self.status, "nginx_sites", slow("nginx", ["site"])),
        ):
            results = []
            threads = [
                threading.Thread(target=lambda: results.append(self.status._adaptive_info()))
                for _ in range(6)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(
            calls.count("compose"), 1,
            f"the compose tree was walked {calls.count('compose')} times",
        )
        self.assertEqual(calls.count("nginx"), 1)
        self.assertTrue(all(r["compose_projects"] == ["proj"] for r in results))

    def test_the_two_scans_still_overlap(self):
        """Single-flight must not have serialised the pair inside the refresh."""
        live = 0
        peak = 0
        lock = threading.Lock()

        def slow(result):
            def run():
                nonlocal live, peak
                with lock:
                    live += 1
                    peak = max(peak, live)
                time.sleep(0.05)
                with lock:
                    live -= 1
                return result
            return run

        with (
            mock.patch.object(self.status, "scan_new_compose_projects", slow([])),
            mock.patch.object(self.status, "nginx_sites", slow([])),
        ):
            self.status._adaptive_info()

        self.assertEqual(peak, 2, "the compose and nginx scans stopped overlapping")


class InvalidationDuringBuildTests(unittest.TestCase):
    """The three page caches that stayed hand-written need the property too.

    They are on the shortest path between an action and the row it changes:
    stopping a container ends in ``invalidate_status``, which cascades into the
    container discovery cache, and saving a pool ends in ``invalidate_pool``.
    Each is polled by the page the operator is looking at, so the build that
    loses this race is the one that started a moment before the click, and the
    symptom is the action appearing not to have happened.
    """

    def _racing_build(self, world, key="state"):
        """A builder that samples *world* on entry and publishes much later."""
        reading = threading.Event()
        release = threading.Event()

        def build(*args, **kwargs):
            observed = world[key]
            if not reading.is_set():
                reading.set()
                release.wait(2)
            return observed

        return build, reading, release

    def _assert_invalidate_wins(self, world, read, invalidate, expected):
        slow = threading.Thread(target=read)
        slow.start()
        self.assertTrue(world["reading"].wait(2), "the build never started")
        world["state"] = "after"
        invalidate()
        world["release"].set()
        slow.join(timeout=2)
        self.assertEqual(read(), expected, "the stale build published anyway")

    def test_full_status_drops_a_build_that_invalidate_superseded(self):
        from hub import status

        with status._lock:
            status._status_cache.update(t=0.0, v=None)
        self.addCleanup(
            lambda: status._status_cache.update(t=0.0, v=None)
        )

        world = {"state": "before"}
        build, reading, release = self._racing_build(world)
        world["reading"], world["release"] = reading, release

        with (
            mock.patch.object(status, "_build_status",
                              lambda: {"marker": build()}),
            mock.patch.object(status, "_stamp_locale", lambda v: v),
        ):
            self._assert_invalidate_wins(
                world,
                lambda: status.full_status().get("marker"),
                # The real invalidate_status also reaches into the discovery
                # caches; those imports are cheap and their absence would be
                # the more surprising thing to mock away.
                status.invalidate_status,
                "after",
            )

    def test_container_discovery_drops_a_superseded_docker_ps(self):
        from hub.discovery import containers

        containers.invalidate_containers()
        self.addCleanup(containers.invalidate_containers)

        world = {"state": "before"}
        build, reading, release = self._racing_build(world)
        world["reading"], world["release"] = reading, release

        def fake_sh(cmd, timeout=None):
            return 0, f"web\trunning\tUp ({build()})\tnginx\t", ""

        def detail():
            items, _up = containers.discover_containers()
            return items[0]["detail"] if items else ""

        with (
            mock.patch.object(containers, "sh", fake_sh),
            mock.patch.object(containers, "override", lambda name: None),
            mock.patch.object(containers, "configured_signatures", list),
            mock.patch.object(containers, "configured_group_rules", list),
        ):
            self._assert_invalidate_wins(
                world, detail, containers.invalidate_containers, "Up (after)"
            )

    def test_pool_overview_drops_a_build_that_invalidate_superseded(self):
        from hub import storage_pool_svc

        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

        world = {"state": "before"}
        build, reading, release = self._racing_build(world)
        world["reading"], world["release"] = reading, release

        with mock.patch.object(storage_pool_svc, "_build",
                               lambda: {"marker": build()}):
            self._assert_invalidate_wins(
                world,
                lambda: storage_pool_svc.pool_overview().get("marker"),
                storage_pool_svc.invalidate_pool,
                "after",
            )

    def test_health_still_serves_the_last_snapshot_after_an_invalidate(self):
        """invalidate_status expires the snapshot without discarding it.

        /api/health reads it through cached_status() and never builds, so
        dropping the payload would make a liveness probe answer "no data"
        every time a container was restarted.
        """
        from hub import status

        with status._lock:
            status._status_cache.update(t=time.time(), v={"ok": True})
        self.addCleanup(
            lambda: status._status_cache.update(t=0.0, v=None)
        )
        status.invalidate_status()
        self.assertEqual(status.cached_status(), {"ok": True})


class NoHandWrittenPayloadCacheTests(unittest.TestCase):
    """A new endpoint cache must use a shared helper, not another local copy.

    Structural and deliberately shallow: it flags a module that keeps a
    ``{"t": ..., "v": ...}`` dict beside a TTL without going through
    ``cached_snapshot`` or ``ttl_memo``. The two exemptions below are the
    implementations the helper was modelled on, kept local because each needs
    behaviour the helper does not have.
    """

    #: module -> why it keeps its own implementation.  Each was read and confirmed
    #: to hold a lock across its refresh; none is a whole-payload snapshot of the
    #: shape the helper replaced.
    EXEMPT = {
        "hub/network_svc.py":
            "a refresh serial, so a force=True caller that queued behind another "
            "refresh reuses that refresh instead of running a second one; also "
            "hands out a copy per caller rather than the shared list",
        "hub/status.py":
            "serves the last good snapshot when a rebuild raises",
        "hub/health_svc.py": "single-flight via its own _refresh_lock",
        "hub/sensors_svc.py": "single-flight via its own _refresh_lock",
        "hub/host_address.py": "single-flight via _detect_refresh_lock; `force` "
                               "must re-detect rather than key a second entry",
        "hub/brew_cache.py": "single-flight via its own _refresh_lock",
        "hub/discovery/containers.py": "single-flight via its own _refresh_lock",
        "hub/docker_cli.py": "single-flight via _engine_lock",
        "hub/adaptive.py": "single-flight via _lsof_refresh_lock",
        "hub/cloudflared_svc.py":
            "serves the previous tunnel list when Cloudflare is unreachable and "
            "deliberately does not cache the failure",
        "hub/storage_pool_svc.py": "single-flight via its own _refresh_lock",
        "hub/tools_svc.py":
            "three separate refresh locks, one per read, so a slow syslog tail does "
            "not block the hardware profile",
    }

    def _payload_cache_modules(self) -> list[str]:
        out = []
        for path in sorted(HUB.rglob("*.py")):
            if "__pycache__" in str(path):
                continue
            src = path.read_text()
            if "TTL" not in src:
                continue
            tree = ast.parse(src)
            for node in tree.body:
                value = getattr(node, "value", None)
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(value, ast.Dict):
                    keys = {k.value for k in value.keys if isinstance(k, ast.Constant)}
                    if keys and keys <= {"t", "v", "value", "ts", "data", "compose", "nginx"}:
                        out.append(path.relative_to(BASE).as_posix())
                        break
        return out

    def test_the_scan_still_sees_the_exempt_modules(self):
        """Guards the test below: if the scan finds nothing it passes vacuously."""
        found = set(self._payload_cache_modules())
        missing = set(self.EXEMPT) - found
        self.assertEqual(
            missing, set(),
            f"the scan no longer sees {missing}; either they were converted (remove "
            "the exemption) or the detector broke",
        )

    def test_no_new_module_hand_writes_a_payload_cache(self):
        offenders = [
            m for m in self._payload_cache_modules() if m not in self.EXEMPT
        ]
        self.assertEqual(
            offenders,
            [],
            "these keep a hand-written TTL cache. Use hub.util.cached_snapshot for a "
            "whole-payload read or hub.util.ttl_memo for a per-key one; both are "
            "single-flight and publish atomically, which every hand-written copy in "
            "this tree got wrong:\n  " + "\n  ".join(offenders),
        )

    def test_the_shared_helpers_are_actually_used(self):
        """Otherwise the rule above could be satisfied by deleting all caching."""
        users = 0
        for path in sorted(HUB.rglob("*.py")):
            if "__pycache__" in str(path):
                continue
            src = path.read_text()
            users += src.count("@cached_snapshot(") + src.count("@ttl_memo(")
        self.assertGreaterEqual(
            users, 14, f"only {users} decorated reads found across hub/"
        )


if __name__ == "__main__":
    unittest.main()
