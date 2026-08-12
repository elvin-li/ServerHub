"""Reads that were correct and independent, but queued behind each other.

Once the duplicate spawns were gone, what was left on the slow endpoints was serial
depth: independent probes inlined in a return dict, so they ran *after* the wave
that should have contained them, and prewarms taken one at a time.

Measured per endpoint, one process each:

    /api/system/diagnostics   11 spawns, 6 waves  ->  11 spawns, 1 wave
    /api/tools/about           4 spawns, 4 waves  ->   4 spawns, 1 wave
    /api/bookmarks             6 spawns, 6 waves  ->   6 spawns, 1 wave
    /api/storage              12 spawns, 3 waves  ->  12 spawns, 2 waves
    /api/settings/disk        10 spawns, 6 waves  ->  10 spawns, 4 waves

Overlap is asserted with a peak-concurrency counter, never with elapsed time: a
loaded machine serialises threads that an idle one overlaps, so a timing bound
passes alone and fails under full-suite load.

Two of the fixes here remove work rather than overlap it, and those are asserted by
counting spawns, which holds regardless of threading.
"""
from __future__ import annotations

import contextlib
import sys
import threading
import time
import unittest
from unittest import mock

from hub import bookmarks_svc, disk_power_svc, disk_snapshot, tools_svc


@contextlib.contextmanager
def _fake_vms_module(fake):
    """Stand in for ``hub.vms_svc`` however the caller reaches it.

    ``bookmarks_svc`` uses ``from hub import vms_svc`` inside the function, which
    reads the attribute off the already-imported ``hub`` package rather than
    consulting ``sys.modules``.  Patching only ``sys.modules`` therefore works when
    this test runs alone and silently does nothing once any earlier test has imported
    the real module -- which is exactly how these two tests passed in isolation and
    failed in the suite.
    """
    import hub

    with (
        mock.patch.dict(sys.modules, {"hub.vms_svc": fake}),
        mock.patch.object(hub, "vms_svc", fake, create=True),
    ):
        yield


class Overlap:
    """Counts peak concurrency and what was asked, per probe name."""

    def __init__(self, delay: float = 0.05):
        self.delay = delay
        self.names: list[str] = []
        self.spans: list[tuple[str, float, float]] = []
        self.peak = 0
        self._live = 0
        self._lock = threading.Lock()

    def run(self, name, value):
        with self._lock:
            self.names.append(str(name))
            self._live += 1
            self.peak = max(self.peak, self._live)
        started = time.perf_counter()
        time.sleep(self.delay)
        ended = time.perf_counter()
        with self._lock:
            self._live -= 1
            self.spans.append((str(name), started, ended))
        return value

    def count(self, needle: str) -> int:
        return sum(1 for n in self.names if needle in n)

    def overlapped(self, name: str) -> bool:
        """Whether *name* was in flight at the same time as some other probe.

        Interval intersection, not position in the start order: the probe submitted
        last is recorded last even when it ran concurrently, so ordering proves
        nothing about overlap.
        """
        mine = [s for s in self.spans if s[0] == name]
        others = [s for s in self.spans if s[0] != name]
        return any(
            start < other_end and other_start < end
            for _, start, end in mine
            for _, other_start, other_end in others
        )


class DiagnosticsTailTests(unittest.TestCase):
    """`platform.platform()` and `host_ip()` were inlined in the return dict.

    Both shell out -- on macOS `platform()` runs `uname -p` and then `file -b` on the
    interpreter, and `host_ip()` is a route lookup then an `ipconfig` -- so they were
    four spawns of pure tail, arriving after the six-way fan-out above them had
    already finished.
    """

    def _diagnostics(self):
        tracker = Overlap()

        def sh(cmd, *a, **kw):
            return tracker.run(" ".join(str(c) for c in cmd), (0, "8", ""))

        with (
            mock.patch.object(tools_svc, "sh", sh),
            mock.patch.object(tools_svc, "engine_up", lambda: tracker.run("engine", False)),
            mock.patch.object(tools_svc, "host_ip", lambda: tracker.run("host_ip", "10.0.0.5")),
            mock.patch(
                "hub.identity_svc.platform_string",
                lambda: tracker.run("platform", "macOS-15.0-arm64"),
            ),
            mock.patch.object(tools_svc.metrics, "history", lambda n: []),
        ):
            return tools_svc.diagnostics(), tracker

    def test_the_tail_joined_the_wave(self):
        _, tracker = self._diagnostics()
        self.assertGreater(
            tracker.peak, 1,
            "the probes ran one at a time; nothing here reads anything else here",
        )

    def test_the_two_tail_reads_are_in_the_same_wave_as_the_rest(self):
        """Overlapping only the cheap sysctls would miss the point.

        These two are the ones that were outside the wave, so a peak counter over the
        batch as a whole would still pass with them left in the tail.
        """
        _, tracker = self._diagnostics()
        for probe in ("host_ip", "platform"):
            self.assertTrue(
                tracker.overlapped(probe),
                f"{probe} ran alone, so it is still a tail rather than part of the wave",
            )

    def test_the_payload_is_unchanged(self):
        data, tracker = self._diagnostics()
        self.assertEqual(data["host_ip"], "10.0.0.5")
        self.assertEqual(data["platform"], "macOS-15.0-arm64")
        self.assertEqual(tracker.count("host_ip"), 1, "host_ip was read twice")
        self.assertEqual(tracker.count("platform"), 1)

    def test_a_failing_tail_read_does_not_take_the_bundle_down(self):
        """It used to raise straight out of the return dict."""
        def boom():
            raise OSError("no route to host")

        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "8", "")),
            mock.patch.object(tools_svc, "engine_up", lambda: False),
            mock.patch.object(tools_svc, "host_ip", boom),
            mock.patch.object(tools_svc.metrics, "history", lambda n: []),
        ):
            data = tools_svc.diagnostics()

        self.assertEqual(data["host_ip"], "", "a failed address read lost the payload")

    def test_the_platform_string_goes_through_the_shared_memo(self):
        """Not a bare platform.platform(): two other endpoints want the same string."""
        source = (
            __import__("pathlib").Path(tools_svc.__file__).read_text(encoding="utf-8")
        )
        start = source.index("def diagnostics")
        body = source[start: source.index("\ndef ", start + 10)]
        self.assertIn("platform_string", body)


class AboutTailTests(unittest.TestCase):
    def test_the_two_reads_overlap(self):
        tracker = Overlap()
        with (
            mock.patch.object(tools_svc, "host_ip", lambda: tracker.run("ip", "10.0.0.5")),
            mock.patch(
                "hub.identity_svc.platform_string",
                lambda: tracker.run("platform", "macOS-15.0-arm64"),
            ),
        ):
            data = tools_svc.about_info()

        self.assertGreater(tracker.peak, 1, "four spawns, three deep, for two fields")
        self.assertEqual(data["host_ip"], "10.0.0.5")
        self.assertEqual(data["platform"], "macOS-15.0-arm64")


class BackendIndexTests(unittest.TestCase):
    """Three unrelated CLIs -- UTM, OrbStack and the container engine."""

    def _index(self, utm=None, orb=None, containers=None):
        tracker = Overlap()

        def rows(name, value):
            def collect(*a, **kw):
                return tracker.run(name, value)
            return collect

        fake_vms = mock.Mock()
        fake_vms.list_utm_vms = rows("utm", utm if utm is not None else [])
        fake_vms.list_orb_machines = rows("orb", orb if orb is not None else [])
        with (
            _fake_vms_module(fake_vms),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                rows("containers", (containers if containers is not None else [], None)),
            ),
        ):
            return bookmarks_svc._backend_index(), tracker

    def test_the_three_inventories_overlap(self):
        _, tracker = self._index()
        self.assertGreater(
            tracker.peak, 1,
            "utmctl, orbctl and docker ran one after another; none reads another",
        )

    def test_a_failing_inventory_no_longer_costs_its_neighbour(self):
        """UTM and Orb shared one try/except, so a UTM failure skipped Orb too.

        The visible consequence was that every bookmark pointing at a stopped Orb
        machine lost its backend state and got probed over the network instead of
        being reported as stopped.
        """
        def explode(*a, **kw):
            raise RuntimeError("utmctl is not installed")

        fake_vms = mock.Mock()
        fake_vms.list_utm_vms = explode
        fake_vms.list_orb_machines = lambda: [
            {"id": "orb:alpha", "name": "alpha", "state": "stopped", "status": "exited"}
        ]
        with (
            _fake_vms_module(fake_vms),
            mock.patch("hub.discovery.containers.discover_containers", lambda: ([], None)),
        ):
            idx = bookmarks_svc._backend_index()

        self.assertIn("alpha", idx, "an unavailable UTM still hid the Orb machines")
        self.assertEqual(idx["alpha"]["state"], "stopped")

    def test_a_name_collision_is_still_won_by_the_last_writer(self):
        """`put()` overwrites, so the winner is decided by the sequence.

        `fan_out` returns in submission order, so containers still overwrite VMs on a
        shared key exactly as they did when this ran top to bottom.  Completion order
        would have made the winner depend on which CLI answered first.
        """
        idx, _ = self._index(
            utm=[{"id": "shared", "name": "shared", "state": "down"}],
            containers=[{"id": "shared", "name": "shared", "state": "ok"}],
        )
        self.assertEqual(
            idx["shared"]["kind"], "container",
            "the VM entry won, so the merge order changed",
        )


class RootDiskUnionTests(unittest.TestCase):
    def setUp(self):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)

    def test_the_three_sources_overlap(self):
        tracker = Overlap()

        def sh(cmd, *a, **kw):
            return tracker.run(
                " ".join(str(c) for c in cmd),
                (0, "Filesystem 1 1 1 1% Mounted on\n/dev/disk3s1s1 1 1 1 1% /\n", ""),
            )

        class FakeSubprocess:
            @staticmethod
            def run(cmd, *a, **kw):
                import plistlib

                class Done:
                    returncode = 0
                    stdout = plistlib.dumps(
                        {"APFSPhysicalStores": [{"APFSPhysicalStore": "disk0s2"}]}
                    )

                tracker.run(" ".join(str(c) for c in cmd), None)
                return Done()

        with (
            mock.patch.object(disk_snapshot, "sh", sh),
            mock.patch.object(disk_snapshot, "subprocess", FakeSubprocess),
        ):
            found = disk_snapshot.root_whole_disks()

        self.assertGreater(
            tracker.peak, 1, "the three union members ran one after another"
        )
        self.assertIn("disk0", found, "the physical store behind the container was lost")
        self.assertIn("disk3", found)


class PowerListingPrewarmTests(unittest.TestCase):
    def setUp(self):
        disk_power_svc.list_power_disks.invalidate()
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_power_svc.list_power_disks.invalidate)
        self.addCleanup(disk_snapshot.invalidate_disks)

    def test_the_two_prewarms_overlap_and_still_read_the_table_once(self):
        """`_root_whole_disks` reaches the mount table too, through its union.

        That is not a second read: both go through the same single-flight cache, so
        the one that arrives second waits instead of spawning. Asserted, because it
        is the detail that makes overlapping these two safe.
        """
        tracker = Overlap(delay=0.03)

        def sh(cmd, *a, **kw):
            argv = " ".join(str(c) for c in cmd)
            if "df" in argv:
                return tracker.run(
                    argv,
                    (0, "Filesystem 1 1 1 1% Mounted on\n/dev/disk0s1 1 1 1 1% /\n", ""),
                )
            return tracker.run(argv, (0, "   Device Node: /dev/disk0\n", ""))

        class FakeSubprocess:
            @staticmethod
            def run(cmd, *a, **kw):
                import plistlib

                class Done:
                    returncode = 0
                    stdout = plistlib.dumps({"WholeDisks": ["disk0"]})

                tracker.run(" ".join(str(c) for c in cmd), None)
                return Done()

        with (
            mock.patch.object(disk_snapshot, "sh", sh),
            mock.patch.object(disk_snapshot, "subprocess", FakeSubprocess),
            mock.patch.object(disk_power_svc, "_describe_disk", lambda d: {"id": d}),
        ):
            rows = disk_power_svc.list_power_disks()

        self.assertEqual([r["id"] for r in rows], ["disk0"])
        self.assertEqual(
            tracker.count("df"), 1,
            f"the mount table was read {tracker.count('df')} times",
        )
        self.assertGreater(tracker.peak, 1, "the prewarms did not overlap")

    def test_no_disks_still_returns_before_the_per_disk_work(self):
        """The early return is worth more than one level of overlap."""
        with mock.patch.object(disk_power_svc, "_list_whole_disks", lambda: []):
            self.assertEqual(disk_power_svc.list_power_disks(), [])


if __name__ == "__main__":
    unittest.main()


class WireGuardStatusKeyTests(unittest.TestCase):
    """`wg pubkey` ran on every status poll, and its result was usually discarded.

    ``status()`` reports ``server_public or conf_public``, so whenever the running
    interface reported a key -- which is the healthy case -- the config-derived
    fallback was computed and thrown away.  Computing it spawns ``wg pubkey``.
    """

    CONF = {
        "interface": {
            "PrivateKey": "cHJpdmF0ZWtleWJhc2U2NHZhbHVlZm9ydGVzdGluZzEyMw==",
            "Address": "10.10.0.1/24",
            "ListenPort": "51820",
        },
        "peers": [],
    }

    def _status(self, *, dump_key: str):
        from hub import wireguard_svc

        calls: list[list[str]] = []

        def sh(cmd, *a, **kw):
            argv = [str(c) for c in cmd]
            calls.append(argv)
            return 0, "", ""

        rows = [["interface", dump_key, "51820", "off"]] if dump_key else []
        with (
            mock.patch.object(wireguard_svc, "sh", sh),
            mock.patch.object(wireguard_svc, "read_conf", lambda: self.CONF),
            mock.patch.object(wireguard_svc, "settings", lambda: {
                "interface": "wg0", "subnet": "10.10.0.0/24", "mtu": 1420,
                "dns": "1.1.1.1", "endpoint": "vpn.example.com:51820",
                "listen_port": 51820, "keepalive": 25,
            }),
            mock.patch.object(wireguard_svc, "installation", lambda: {"installed": True}),
            mock.patch.object(wireguard_svc, "peer_records", lambda: []),
            mock.patch.object(
                wireguard_svc, "_dump", lambda iface: (bool(dump_key), rows, "")
            ),
            mock.patch.object(
                wireguard_svc, "public_from_private",
                lambda key: calls.append(["wg", "pubkey"]) or "CONFPUB",
            ),
        ):
            return wireguard_svc.status(), calls

    def test_a_running_interface_does_not_derive_the_key_again(self):
        data, calls = self._status(dump_key="LIVEPUB")
        self.assertEqual(data["public_key"], "LIVEPUB")
        self.assertEqual(
            [c for c in calls if "pubkey" in c], [],
            "`wg pubkey` ran to compute a value the payload then discarded",
        )

    def test_a_down_interface_still_falls_back_to_the_config(self):
        """The fallback exists for exactly this case and must survive."""
        data, calls = self._status(dump_key="")
        self.assertEqual(
            data["public_key"], "CONFPUB",
            "with the tunnel down the page lost the key its config would serve",
        )
        self.assertTrue([c for c in calls if "pubkey" in c])


class DaemonLabelMatchTests(unittest.TestCase):
    """The launchd fallback matched labels by substring."""

    def test_a_longer_label_is_not_mistaken_for_ours(self):
        from hub import launchd_cache, wireguard_net_svc

        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)

        # `com.wireguard.wg01` is loaded; `com.wireguard.wg0` is not.
        listing = "PID\tStatus\tLabel\n-\t0\tcom.wireguard.wg01\n"
        with (
            mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, listing, "")),
            mock.patch.object(wireguard_net_svc, "sh", lambda *a, **k: (1, "", "")),
            mock.patch.object(
                wireguard_net_svc, "sudo_capture", lambda *a, **k: (1, "", "")
            ),
            mock.patch.object(
                wireguard_net_svc.wireguard_svc, "settings", lambda: {"interface": "wg0"}
            ),
        ):
            state = wireguard_net_svc.daemon_state()

        self.assertFalse(
            state["loaded"],
            "a different job whose label merely contains ours was read as ours",
        )

    def test_our_own_label_is_still_found(self):
        """Guards the test above: always answering False would also pass it."""
        from hub import launchd_cache, wireguard_net_svc

        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)

        listing = "PID\tStatus\tLabel\n-\t0\tcom.wireguard.wg0\n"
        with (
            mock.patch.object(launchd_cache, "sh", lambda *a, **k: (0, listing, "")),
            mock.patch.object(wireguard_net_svc, "sh", lambda *a, **k: (1, "", "")),
            mock.patch.object(
                wireguard_net_svc, "sudo_capture", lambda *a, **k: (1, "", "")
            ),
            mock.patch.object(
                wireguard_net_svc.wireguard_svc, "settings", lambda: {"interface": "wg0"}
            ),
        ):
            self.assertTrue(wireguard_net_svc.daemon_state()["loaded"])
