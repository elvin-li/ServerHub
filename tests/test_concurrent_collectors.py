"""Five read paths that used to walk their subprocesses one at a time.

These are the collectors behind /api/apps/autostart, /api/smart,
/api/health/checks, /api/snapshots and /api/docker/info.  Measured with
``subprocess.run`` itself instrumented -- not ``hub.util.sh``, which 29 call sites
bypass -- their serial depth was:

    /api/apps/autostart   63 spawns, none overlapping
    /api/smart            18 spawns, none overlapping
    /api/health/checks     7 spawns, none overlapping
    /api/snapshots         7 spawns, none overlapping
    /api/docker/info       3 spawns, none overlapping

Two different fixes are pinned here, because they are not interchangeable:

* **Fewer spawns.** ``launchctl list`` already reports every loaded job, so calling
  it once per label asked one command the same question N times; ``smartctl -c``
  was likewise run twice per disk, once for the capability list and once for the
  progress percentage.  Removing that duplication is a strict win and survives
  regardless of threading, so it is asserted by counting argv, not by timing.
* **Overlap.** What remains is genuinely independent work, and it is overlapped.

Overlap is asserted through a peak-concurrency counter rather than elapsed time.
An earlier version of this file used elapsed-time bounds; they passed in isolation
and failed under full-suite load, because a loaded machine can serialise threads
that a quiet one overlaps.  Peak concurrency answers the question actually being
asked -- "were two of these ever in flight together" -- and is indifferent to how
long the suite's other threads keep the CPU.

The invariants that make overlapping legal at all are pinned alongside it:

1. **Order.** Every collector here feeds a rendered list.  ``fan_out`` uses
   ``ex.map``, which yields in submission order; ``as_completed`` would reshuffle
   the table on every refresh depending on which disk answered first.
2. **Failure isolation.** ``ex.map`` re-raises on iteration, so one probe that
   raises costs the whole batch.  Each probe absorbs its own exception.
3. **Grouped error semantics.** ``health_svc`` reports one combined failure when
   nginx is absent, not that plus a redundant config-syntax error.  Moving the pair
   into a worker must not split them.
"""
from __future__ import annotations

import plistlib
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    autostart_svc,
    docker_info_svc,
    health_svc,
    smart_test_svc,
    snapshots_svc,
)


class Concurrency:
    """Counts how many probes are in flight at once, and what was asked.

    ``peak`` greater than one is proof of overlap that does not depend on the
    machine being idle, unlike an elapsed-time bound.
    """

    def __init__(self, delay: float = 0.05):
        self.delay = delay
        self._lock = threading.Lock()
        self.live = 0
        self.peak = 0
        self.argv: list[list[str]] = []

    def enter(self, argv) -> None:
        with self._lock:
            self.live += 1
            self.peak = max(self.peak, self.live)
            self.argv.append([str(a) for a in argv])

    def leave(self) -> None:
        with self._lock:
            self.live -= 1

    def run(self, argv, result):
        """Record *argv*, hold the slot open for *delay*, then answer *result*."""
        self.enter(argv)
        try:
            time.sleep(self.delay)
            return result
        finally:
            self.leave()

    def count(self, *tokens: str) -> int:
        """How many recorded commands contain every one of *tokens*."""
        return sum(1 for argv in self.argv if all(t in argv for t in tokens))


# ── /api/apps/autostart ──────────────────────────────────────────────────────

class LaunchAgentInventoryTests(unittest.TestCase):
    """``launchctl`` once for the directory, not once per plist.

    A host with 29 LaunchAgents paid 29 ``launchctl list`` invocations plus the
    per-label ``launchctl print``, all in series -- the single worst read path in
    the panel at 63 spawns deep.
    """

    LABELS = ["local.alpha", "local.beta", "local.gamma", "local.delta"]

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        for label in self.LABELS:
            (self.dir / f"{label}.plist").write_bytes(
                plistlib.dumps({"Label": label, "RunAtLoad": True})
            )
        # A brew-managed agent, which this collector deliberately leaves to the brew
        # section rather than listing twice.
        (self.dir / "homebrew.mxcl.postgresql@17.plist").write_bytes(
            plistlib.dumps({"Label": "homebrew.mxcl.postgresql@17", "RunAtLoad": True})
        )

    def _items(self, listing: str):
        tracker = Concurrency()

        def fake_sh(cmd, *a, **kw):
            argv = list(cmd)
            if argv[-1] == "list":
                return tracker.run(argv, (0, listing, ""))
            # `launchctl print <domain>/<label>`
            label = str(argv[-1]).rsplit("/", 1)[-1]
            return tracker.run(argv, (0, f"state = running\n{label}", ""))

        with (
            mock.patch.object(autostart_svc, "AGENTS_DIR", self.dir),
            mock.patch.object(autostart_svc, "sh", fake_sh),
        ):
            items = autostart_svc._launchd_items()
        return items, tracker

    def test_a_full_listing_needs_no_per_label_probe(self):
        """The strongest form of the win: N labels, one subprocess."""
        listing = "\n".join(f"123\t0\t{label}" for label in self.LABELS)
        items, tracker = self._items(listing)

        self.assertEqual(
            tracker.count("list"), 1,
            f"`launchctl list` ran {tracker.count('list')} times for "
            f"{len(self.LABELS)} labels; it answers all of them at once",
        )
        self.assertEqual(
            tracker.count("print"), 0,
            "the shared listing already said these are loaded, so `launchctl print` "
            "should not have run at all",
        )
        self.assertTrue(all(i["running"] for i in items))

    def test_labels_missing_from_the_listing_are_probed_together(self):
        items, tracker = self._items("123\t0\tlocal.alpha")

        self.assertEqual(tracker.count("list"), 1, "the listing is still read once")
        self.assertEqual(
            tracker.count("print"), 3,
            "only the three labels the listing did not cover need their own probe",
        )
        self.assertGreater(
            tracker.peak, 1,
            "the per-label probes ran one after another; they are independent",
        )
        self.assertTrue(all(i["running"] for i in items))

    def test_rows_follow_directory_order(self):
        items, _ = self._items("")
        self.assertEqual(
            [i["id"] for i in items],
            [f"launchd:{label}" for label in sorted(self.LABELS)],
            "rows were reordered by which probe finished first",
        )

    def test_a_brew_managed_agent_is_still_left_to_the_brew_section(self):
        items, _ = self._items("")
        self.assertNotIn(
            "launchd:homebrew.mxcl.postgresql@17",
            [i["id"] for i in items],
            "a brew-managed agent would be listed twice on the page",
        )

    def test_an_empty_directory_needs_no_subprocess(self):
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
        tracker = Concurrency()
        with (
            mock.patch.object(autostart_svc, "AGENTS_DIR", empty),
            mock.patch.object(
                autostart_svc, "sh", lambda cmd, *a, **kw: tracker.run(cmd, (0, "", ""))
            ),
        ):
            self.assertEqual(autostart_svc._launchd_items(), [])
        self.assertEqual(
            tracker.argv, [],
            "an empty LaunchAgents directory should not reach launchctl at all",
        )

    def test_a_caller_without_a_snapshot_still_works(self):
        """``apps_manage_svc`` calls this with no arguments."""
        listing = "\n".join(f"1\t0\t{label}" for label in self.LABELS)
        with (
            mock.patch.object(autostart_svc, "AGENTS_DIR", self.dir),
            mock.patch.object(
                autostart_svc, "sh", lambda cmd, *a, **kw: (0, listing, "")
            ),
        ):
            self.assertEqual(len(autostart_svc._launchd_items()), len(self.LABELS))


class AutostartOverviewTests(unittest.TestCase):
    """The four inventories behind the page are independent of one another."""

    def setUp(self):
        autostart_svc._cache.update(t=0.0, v=None)
        self.addCleanup(autostart_svc._cache.update, t=0.0, v=None)

    def _overview(self):
        tracker = Concurrency(delay=0.08)
        docker = [{"id": "docker:web", "name": "web"}]
        brew = [{"id": "brew:redis", "name": "redis"}]
        launchd = [{"id": "launchd:local.alpha", "name": "alpha"}]
        script = {"id": "script:autostart", "name": "script"}

        with (
            mock.patch.object(
                autostart_svc, "sh", lambda cmd, *a, **kw: tracker.run(cmd, (0, "", ""))
            ),
            mock.patch.object(
                autostart_svc, "_docker_autostart_items",
                lambda: tracker.run(["docker"], docker),
            ),
            mock.patch.object(
                autostart_svc, "_brew_service_items",
                lambda: tracker.run(["brew"], brew),
            ),
            mock.patch.object(
                autostart_svc, "_launchd_items",
                lambda *a, **kw: tracker.run(["launchd"], launchd),
            ),
            mock.patch.object(
                autostart_svc, "_script_status",
                lambda *a, **kw: tracker.run(["script"], script),
            ),
        ):
            data = autostart_svc.overview(force=True)
        return data, tracker

    def test_the_four_inventories_overlap(self):
        _, tracker = self._overview()
        self.assertGreater(
            tracker.peak, 1,
            "docker, brew, launchd and the login script ran in series",
        )

    def test_sections_keep_their_rendered_order(self):
        data, _ = self._overview()
        self.assertEqual(
            [i["id"] for i in data["items"]],
            ["script:autostart", "brew:redis", "launchd:local.alpha", "docker:web"],
            "the page renders script, then brew, then launchd, then docker",
        )

    def test_the_shared_listing_is_read_once_for_both_consumers(self):
        _, tracker = self._overview()
        self.assertEqual(
            tracker.count("list"), 1,
            "`_launchd_items` and `_script_status` both need the loaded-job listing; "
            "it should be taken once and handed to both",
        )


# ── /api/smart ───────────────────────────────────────────────────────────────

#: Real `smartctl -c` wording, so the parse assertions below describe production.
#: The parsing itself is covered in tests/test_smart_capability_parsing.py; here it
#: only needs to prove the shared `-c` output survives being read once and handed to
#: two consumers.
CAPS_OUT = (
    "SMART capabilities:\n"
    "Short self-test routine\nrecommended polling time:  (   2) minutes\n"
    "Extended self-test routine\nrecommended polling time:  ( 120) minutes\n"
    "Conveyance self-test routine\nrecommended polling time:  (   3) minutes\n"
)
SELFTEST_OUT = (
    "SMART Self-test log\n"
    "# 1  Short offline       Completed without error       00%      1234         -\n"
)


class SmartOverviewTests(unittest.TestCase):
    NODES = ["/dev/disk0", "/dev/disk2", "/dev/disk4", "/dev/disk6"]

    def setUp(self):
        smart_test_svc._cache.update(t=0.0, v=None)
        smart_test_svc._device_type_cache.clear()
        self.addCleanup(smart_test_svc._cache.update, t=0.0, v=None)
        self.addCleanup(smart_test_svc._device_type_cache.clear)

    def _overview(self, raw=None):
        tracker = Concurrency()

        def default(argv, *, timeout):
            if "-c" in argv:
                return tracker.run(argv, (0, CAPS_OUT, ""))
            if "selftest" in argv:
                return tracker.run(argv, (0, SELFTEST_OUT, ""))
            return tracker.run(argv, (0, "Device Model: Fake", ""))

        with (
            mock.patch.object(smart_test_svc, "_device_nodes", lambda: list(self.NODES)),
            mock.patch.object(smart_test_svc, "_raw_smartctl", raw or default),
            mock.patch.object(smart_test_svc, "passwordless_available", lambda: True),
            mock.patch.object(smart_test_svc, "cfg", lambda: {}),
            mock.patch.object(smart_test_svc, "history", lambda limit=100: []),
        ):
            data = smart_test_svc.overview(force=True)
        return data, tracker

    def test_the_capability_read_happens_once_per_disk(self):
        """``smartctl -c`` answers both the test list and the progress percentage.

        It used to be spawned twice per disk, once by ``_capabilities`` and once by
        ``_in_progress``, which is one command asked the same question twice.
        """
        _, tracker = self._overview()
        for node in self.NODES:
            self.assertEqual(
                tracker.count("-c", node), 1,
                f"`smartctl -c {node}` ran {tracker.count('-c', node)} times",
            )

    def test_the_selftest_log_is_also_read_once_per_disk(self):
        _, tracker = self._overview()
        for node in self.NODES:
            self.assertEqual(tracker.count("selftest", node), 1)

    def test_the_disks_are_read_concurrently(self):
        _, tracker = self._overview()
        self.assertGreater(
            tracker.peak, 1,
            "each disk waited for the previous one; they are separate controllers",
        )

    def test_rows_follow_the_diskutil_listing(self):
        data, _ = self._overview()
        self.assertEqual([d["device"] for d in data["devices"]], self.NODES)

    def test_the_parsed_result_is_unchanged(self):
        data, _ = self._overview()
        first = data["devices"][0]
        self.assertEqual(
            first["capabilities"]["supported"], ["short", "long", "conveyance"]
        )
        self.assertEqual(
            first["capabilities"]["estimated_minutes"],
            {"short": 2, "long": 120, "conveyance": 3},
        )
        self.assertEqual(first["log_count"], 1)
        self.assertEqual(first["last_result"], "Completed without error")
        self.assertEqual(first["failures"], 0)
        self.assertFalse(first["progress"]["running"])

    def test_a_running_test_is_still_reported_from_the_shared_output(self):
        in_progress = CAPS_OUT + (
            "Self-test routine in progress...\n  40% of test remaining.\n"
        )

        def raw(argv, *, timeout):
            if "-c" in argv:
                return 0, in_progress, ""
            if "selftest" in argv:
                return 0, SELFTEST_OUT, ""
            return 0, "Device Model: Fake", ""

        data, _ = self._overview(raw=raw)
        progress = data["devices"][0]["progress"]
        self.assertTrue(progress["running"])
        self.assertEqual(progress["percent_remaining"], 40)
        self.assertEqual(progress["percent_done"], 60)

    def test_one_exploding_disk_costs_only_its_own_row(self):
        def raw(argv, *, timeout):
            if "/dev/disk4" in argv:
                raise OSError("controller went away")
            if "-c" in argv:
                return 0, CAPS_OUT, ""
            if "selftest" in argv:
                return 0, SELFTEST_OUT, ""
            return 0, "Device Model: Fake", ""

        data, _ = self._overview(raw=raw)
        self.assertEqual(
            [d["device"] for d in data["devices"]], self.NODES,
            "a raising probe emptied the disk table instead of marking one row",
        )
        broken = next(d for d in data["devices"] if d["device"] == "/dev/disk4")
        self.assertFalse(broken["capabilities"]["readable"])
        self.assertEqual(broken["capabilities"]["reason"], "probe_failed")
        healthy = next(d for d in data["devices"] if d["device"] == "/dev/disk0")
        self.assertTrue(healthy["capabilities"]["available"])


class DeviceTypeSingleFlightTests(unittest.TestCase):
    """The transport probe costs up to two spawns, so it must not stampede.

    Reading disks concurrently means several threads can arrive on a cold cache for
    the same device -- during a refresh that races another refresh -- and without
    single-flight they would each pay for the probe.
    """

    def setUp(self):
        smart_test_svc._device_type_cache.clear()
        self.addCleanup(smart_test_svc._device_type_cache.clear)

    def test_concurrent_callers_probe_once(self):
        calls = []
        lock = threading.Lock()

        def raw(argv, *, timeout):
            with lock:
                calls.append(list(argv))
            time.sleep(0.05)
            return 0, "Device Model: Fake", ""

        results: list[tuple] = []
        with mock.patch.object(smart_test_svc, "_raw_smartctl", raw):
            threads = [
                threading.Thread(
                    target=lambda: results.append(
                        smart_test_svc.device_type("/dev/disk0")
                    )
                )
                for _ in range(6)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertEqual(
            len(calls), 1,
            f"six concurrent callers ran the transport probe {len(calls)} times",
        )
        self.assertEqual(len(results), 6)
        self.assertEqual(set(results), {()}, "callers disagreed about the flags")

    def test_separate_devices_are_not_serialised_behind_each_other(self):
        tracker = Concurrency()

        def raw(argv, *, timeout):
            return tracker.run(argv, (0, "Device Model: Fake", ""))

        with mock.patch.object(smart_test_svc, "_raw_smartctl", raw):
            threads = [
                threading.Thread(target=smart_test_svc.device_type, args=(node,))
                for node in ("/dev/disk0", "/dev/disk2", "/dev/disk4")
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertGreater(
            tracker.peak, 1,
            "a per-device lock must not become one global lock",
        )


# ── /api/health/checks ───────────────────────────────────────────────────────

class HealthCheckTests(unittest.TestCase):
    ORDERED_PREFIXES = ["disk_root", "orbstack", "nginx", "nginx_conf",
                        "port_8086", "port_8123", "port_8281"]

    def setUp(self):
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(health_svc._cache.update, t=0.0, v=None)

    def _run(self, *, nginx_overview=None, nginx_test=None, brew=None, immich=None):
        tracker = Concurrency()

        def ok_overview():
            return tracker.run(["nginx-overview"], {"running": True, "pid": 42,
                                                    "site_count": 3})

        def ok_test():
            return tracker.run(["nginx-test"], {"ok": True, "message": "syntax is ok"})

        with (
            mock.patch.object(
                health_svc, "engine_up", lambda: tracker.run(["engine"], True)
            ),
            mock.patch.object(health_svc, "nginx_overview", nginx_overview or ok_overview),
            mock.patch.object(health_svc, "nginx_test", nginx_test or ok_test),
            mock.patch.object(
                health_svc, "port_open",
                lambda port, **kw: tracker.run([f"port{port}"], port == 8086),
            ),
            mock.patch.object(
                health_svc, "sh",
                lambda cmd, *a, **kw: tracker.run(cmd, (0, "1\t0\tlocal.alpha\n", "")),
            ),
            mock.patch.object(
                health_svc, "brew_services_list",
                brew or (lambda: tracker.run(["brew"], [])),
            ),
            mock.patch.object(
                health_svc, "_immich_checks",
                immich or (lambda: tracker.run(["immich"], [])),
            ),
        ):
            data = health_svc.run_checks(force=True)
        return data, tracker

    def test_the_probes_overlap(self):
        _, tracker = self._run()
        self.assertGreater(
            tracker.peak, 1,
            "the engine, nginx, port, launchctl, brew and immich probes ran serially",
        )

    def test_checks_keep_their_rendered_order(self):
        data, _ = self._run()
        ids = [c["id"] for c in data["checks"]]
        positions = [ids.index(i) for i in self.ORDERED_PREFIXES]
        self.assertEqual(
            positions, sorted(positions),
            f"the check order changed: {ids[:8]}",
        )

    def test_a_missing_nginx_reports_one_combined_failure(self):
        """Not two.

        ``nginx_overview()`` raising means nginx is not installed, in which case a
        separate "config syntax" error is noise.  One try/except covering both calls
        is what produces that, and moving the pair into a worker must not split it.
        """
        def boom():
            raise RuntimeError("nginx not installed")

        data, _ = self._run(nginx_overview=boom)
        nginx_checks = [c for c in data["checks"] if c["id"].startswith("nginx")]
        self.assertEqual(
            [c["id"] for c in nginx_checks], ["nginx"],
            "a redundant nginx_conf failure appeared alongside the real one",
        )
        self.assertIn("nginx not installed", nginx_checks[0]["detail"])
        self.assertFalse(nginx_checks[0]["ok"])

    def test_a_config_syntax_failure_still_reports_both(self):
        data, _ = self._run(
            nginx_test=lambda: {"ok": False, "message": "unexpected } in conf.d/a.conf"}
        )
        ids = [c["id"] for c in data["checks"]]
        self.assertIn("nginx", ids)
        self.assertIn("nginx_conf", ids)
        conf = next(c for c in data["checks"] if c["id"] == "nginx_conf")
        self.assertFalse(conf["ok"])
        self.assertIn("unexpected }", conf["detail"])

    def test_port_results_are_not_reshuffled_by_completion(self):
        data, _ = self._run()
        by_id = {c["id"]: c for c in data["checks"]}
        self.assertTrue(by_id["port_8086"]["ok"], "the open port lost its result")
        self.assertFalse(by_id["port_8123"]["ok"])
        self.assertFalse(by_id["port_8281"]["ok"])

    def test_a_raising_brew_snapshot_does_not_lose_the_other_checks(self):
        def boom():
            raise RuntimeError("brew is wedged")

        data, _ = self._run(brew=boom)
        ids = [c["id"] for c in data["checks"]]
        for expected in self.ORDERED_PREFIXES:
            self.assertIn(expected, ids, "one failing probe emptied the batch")

    def test_a_raising_immich_probe_becomes_its_own_warning(self):
        """`_immich_checks` is the boundary that absorbs this, so exercise the real one.

        Patch the attribute on the `hub` package, not `sys.modules`.
        `_immich_checks` does `from hub import immich_svc`, which resolves as an
        attribute lookup once anything else has imported the submodule -- so a
        `sys.modules` entry takes effect in isolation and is ignored during a
        full-suite run. An earlier version of this test did exactly that and
        passed alone while failing together, which is the same trap
        `ContainerLogTests._logs` documents in tests/test_fanned_out_probes.py.
        """
        class Exploding:
            @staticmethod
            def run_checks():
                raise RuntimeError("immich module broken")

        import hub

        with (
            mock.patch.object(hub, "immich_svc", Exploding, create=True),
            mock.patch.dict(sys.modules, {"hub.immich_svc": Exploding}),
        ):
            data, _ = self._run(immich=health_svc._immich_checks)

        immich = [c for c in data["checks"] if c["id"] == "immich"]
        self.assertEqual(len(immich), 1)
        self.assertFalse(immich[0]["ok"])
        self.assertEqual(immich[0]["level"], "warn")
        self.assertIn("immich module broken", immich[0]["detail"])

    def test_the_loaded_job_listing_is_read_once(self):
        _, tracker = self._run()
        self.assertEqual(
            tracker.count("list"), 1,
            "`launchctl list` answers both the brew fallback and the KeepAlive scan",
        )

    def test_the_summary_still_counts_what_it_renders(self):
        data, _ = self._run()
        summary = data["summary"]
        self.assertEqual(summary["total"], len(data["checks"]))
        self.assertEqual(
            summary["ok"] + summary["warn"] + summary["error"], summary["total"]
        )


# ── /api/snapshots ───────────────────────────────────────────────────────────

class SnapshotOverviewTests(unittest.TestCase):
    MOUNTS = ["/", "/Volumes/Data", "/Volumes/Media", "/Volumes/Archive"]

    def setUp(self):
        snapshots_svc._overview_cache.update(t=0.0, v=None)
        self.addCleanup(snapshots_svc._overview_cache.update, t=0.0, v=None)

    def _overview(self, snaps=None):
        tracker = Concurrency()

        def default(mount):
            return tracker.run(
                ["listSnapshots", mount],
                [{"name": f"snap-{mount}", "date": "2026-08-01 10:00:00",
                  "deletable": True, "uuid": "u", "xid": 1}],
            )

        with (
            mock.patch.object(snapshots_svc, "snapshot_mounts", lambda: list(self.MOUNTS)),
            mock.patch.object(snapshots_svc, "list_snapshots", snaps or default),
            mock.patch.object(
                snapshots_svc, "_plist",
                lambda argv, **kw: tracker.run(argv, {"Destinations": [], "Running": False}),
            ),
            mock.patch.object(
                snapshots_svc, "sh",
                lambda argv, **kw: tracker.run(argv, (0, "/Volumes/TM/backup", "")),
            ),
        ):
            data = snapshots_svc.overview(force=True)
        return data, tracker

    def test_the_volumes_and_time_machine_read_together(self):
        _, tracker = self._overview()
        self.assertGreater(
            tracker.peak, 1,
            "each volume waited for the previous one and Time Machine waited for all",
        )

    def test_volumes_follow_mount_order(self):
        data, _ = self._overview()
        self.assertEqual([v["mount"] for v in data["volumes"]], self.MOUNTS)

    def test_a_snapshotless_external_volume_is_still_dropped(self):
        def snaps(mount):
            return [] if mount == "/Volumes/Media" else [
                {"name": "s", "date": "2026-08-01 10:00:00", "deletable": False,
                 "uuid": "u", "xid": 1}
            ]

        data, _ = self._overview(snaps=snaps)
        self.assertEqual(
            [v["mount"] for v in data["volumes"]],
            ["/", "/Volumes/Data", "/Volumes/Archive"],
        )

    def test_the_boot_volume_is_kept_even_with_no_snapshots(self):
        data, _ = self._overview(snaps=lambda mount: [])
        self.assertEqual([v["mount"] for v in data["volumes"]], ["/"])
        self.assertEqual(data["total"], 0)

    def test_the_total_still_sums_every_volume(self):
        data, _ = self._overview()
        self.assertEqual(data["total"], len(self.MOUNTS))

    def test_time_machine_state_survives_the_move_into_the_batch(self):
        data, _ = self._overview()
        tm = data["time_machine"]
        self.assertFalse(tm["running"])
        self.assertEqual(tm["latest_backup"], "/Volumes/TM/backup")

    def test_the_three_tmutil_reads_overlap(self):
        tracker = Concurrency()
        with (
            mock.patch.object(
                snapshots_svc, "_plist",
                lambda argv, **kw: tracker.run(argv, {"Destinations": [], "Running": False}),
            ),
            mock.patch.object(
                snapshots_svc, "sh",
                lambda argv, **kw: tracker.run(argv, (0, "/Volumes/TM/b", "")),
            ),
        ):
            snapshots_svc.time_machine_overview()
        self.assertGreater(
            tracker.peak, 1,
            "destinationinfo, status and latestbackup ran one after another; "
            "latestbackup alone can block for its full 12s timeout",
        )

    def test_an_unreachable_destination_does_not_raise(self):
        with (
            mock.patch.object(snapshots_svc, "_plist", lambda argv, **kw: None),
            mock.patch.object(snapshots_svc, "sh", lambda argv, **kw: (1, "", "timeout")),
        ):
            tm = snapshots_svc.time_machine_overview()
        self.assertFalse(tm["configured"])
        self.assertEqual(tm["destinations"], [])
        self.assertEqual(tm["latest_backup"], "")


# ── /api/docker/info ─────────────────────────────────────────────────────────

class DockerEngineInfoTests(unittest.TestCase):
    INFO = ('{"ServerVersion":"27.1","OperatingSystem":"OrbStack","NCPU":8,'
            '"Images":12,"Containers":5}')
    VERSION = '{"Client":{"Version":"27.1"},"Server":{"Version":"27.1"}}'

    def _info(self, *, up=True, docker_impl=None, orb=None):
        tracker = Concurrency()

        def default_docker(*args, **kwargs):
            argv = list(args)
            if "info" in argv:
                return tracker.run(argv, (0, self.INFO, ""))
            return tracker.run(argv, (0, self.VERSION, ""))

        with (
            mock.patch.object(docker_info_svc, "engine_up", lambda: up),
            mock.patch.object(docker_info_svc, "docker", docker_impl or default_docker),
            mock.patch.object(
                docker_info_svc, "sh",
                orb or (lambda argv, **kw: tracker.run(argv, (0, "Version 1.9\n", ""))),
            ),
        ):
            data = docker_info_svc.engine_info()
        return data, tracker

    def test_the_three_reads_overlap(self):
        _, tracker = self._info()
        self.assertGreater(
            tracker.peak, 1,
            "`docker info`, `docker version` and `orb version` ran in series, so the "
            "panel waited out the sum of a 15s, a 10s and a 5s timeout",
        )

    def test_the_payload_is_unchanged(self):
        data, _ = self._info()
        self.assertTrue(data["engine_up"])
        self.assertEqual(data["info"]["ServerVersion"], "27.1")
        self.assertEqual(data["info"]["NCPU"], 8)
        self.assertEqual(data["version"]["Server"]["Version"], "27.1")
        self.assertEqual(data["orb_version"], "Version 1.9\n")

    def test_a_stopped_engine_still_short_circuits_every_read(self):
        data, tracker = self._info(up=False)
        self.assertFalse(data["engine_up"])
        self.assertEqual(
            tracker.argv, [],
            "the engine is down, so none of the three reads should have been spawned",
        )

    def test_unparseable_json_does_not_lose_the_other_two_reads(self):
        def docker_impl(*args, **kwargs):
            argv = list(args)
            if "info" in argv:
                return 0, "not json at all", ""
            return 0, self.VERSION, ""

        data, _ = self._info(docker_impl=docker_impl)
        self.assertIsNone(data["info"]["ServerVersion"])
        self.assertEqual(data["version"]["Server"]["Version"], "27.1")
        self.assertEqual(data["orb_version"], "Version 1.9\n")

    def test_a_failing_orb_binary_leaves_the_docker_halves_intact(self):
        data, _ = self._info(orb=lambda argv, **kw: (127, "", "not found"))
        self.assertEqual(data["orb_version"], "")
        self.assertEqual(data["info"]["ServerVersion"], "27.1")
        self.assertEqual(data["version"]["Server"]["Version"], "27.1")


if __name__ == "__main__":
    unittest.main()
