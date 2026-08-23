"""Probes that were parallelised must keep the answer their serial version gave.

Five read paths used to walk their subprocesses one at a time, so their latency
was the item count times the per-item timeout -- and two of them sit on
/api/status, which the dashboard polls every few seconds:

* ``discovery.apps.collect_apps`` ran ``pgrep`` (3s timeout) plus a TCP connect
  (0.6s against a closed port) per configured app;
* ``discovery.apps.collect_scripts`` connected to every port of every script;
* ``vms_svc._list_utm_vms_uncached`` connected to each VM's mapped port, which
  costs the whole timeout while a guest is still booting;
* ``shares_svc.file_services`` probed each file service in turn;
* ``apps_manage_svc`` ran ``docker inspect`` (15s) and ``docker logs`` (30s) once
  per container in a stack.

Overlapping them is only correct while three properties hold, and all three are
invisible in the happy path, so they are pinned here rather than assumed:

1. **Order.** Every one of these feeds a rendered list or a concatenated
   document. ``fan_out`` uses ``ex.map``, which yields in submission order;
   switching to ``as_completed`` would reshuffle rows or log sections on every
   refresh depending on which probe finished first.
2. **Failure isolation.** ``ex.map`` re-raises on iteration, so one probe that
   raises would cost the entire batch -- an empty VM list instead of one row
   reading "warn". Each probe therefore absorbs its own exception, and these
   tests assert the surviving rows.
3. **Nothing privileged moves onto a worker.** The administrator password lives
   in a ContextVar that does not cross into a pool thread. That rule has its own
   file, tests/test_privileged_calls_stay_on_the_request_thread.py; here it only
   shows up as the reason ``daemon_state`` was left serial.

Timing assertions use a deliberately slow fake probe and a generous bound, so
they measure "did these overlap at all" rather than a performance target.
"""
from __future__ import annotations

import collections
import contextlib
import json
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    apps_manage_svc,
    containers_svc,
    disk_manage_svc,
    disk_power_svc,
    disk_snapshot,
    health_svc,
    launchd_cache,
    native_catalog,
    network_svc,
    proc_cache,
    raid_svc,
    shares_svc,
    storage_svc,
    tools_svc,
    vms_svc,
    wireguard_svc,
)
from hub.discovery import apps as discovery_apps  # noqa: E402
from hub.util import fan_out  # noqa: E402

#: Long enough that a serial run is unmistakably slower, short enough to keep the
#: suite quick.
PROBE_DELAY = 0.2


def slow(result_for):
    """A probe that sleeps, so overlap is measurable."""

    def probe(*args, **kwargs):
        time.sleep(PROBE_DELAY)
        return result_for(*args, **kwargs)

    return probe


class FanOutContractTests(unittest.TestCase):
    """The shared helper, which every call site below depends on."""

    def test_results_follow_input_order_not_completion_order(self):
        def uneven(n):
            # Reverse-proportional sleep: completion order is the opposite of
            # submission order, so anything order-preserving must reorder it back.
            time.sleep((5 - n) * 0.02)
            return n

        self.assertEqual(fan_out(uneven, [1, 2, 3, 4]), [1, 2, 3, 4])

    def test_an_empty_input_does_not_build_a_pool(self):
        # max_workers=0 is a ValueError, so this case has to short-circuit.
        self.assertEqual(fan_out(lambda x: x, []), [])

    def test_a_single_item_runs_inline(self):
        self.assertEqual(fan_out(lambda x: x * 2, [21]), [42])

    def test_work_actually_overlaps(self):
        started = time.time()
        fan_out(slow(lambda x: x), list(range(6)))
        elapsed = time.time() - started
        self.assertLess(
            elapsed,
            6 * PROBE_DELAY * 0.7,
            f"six probes took {elapsed:.2f}s; they did not overlap",
        )

    def test_worker_count_is_capped(self):
        from hub.util import MAX_PROBE_WORKERS

        seen = set()

        def record(_):
            import threading

            seen.add(threading.current_thread().name)
            time.sleep(0.05)
            return None

        fan_out(record, list(range(MAX_PROBE_WORKERS * 3)))
        self.assertLessEqual(len(seen), MAX_PROBE_WORKERS)

    def test_a_generator_input_is_accepted(self):
        self.assertEqual(fan_out(lambda x: x, (i for i in range(3))), [0, 1, 2])

    def test_nested_fan_out_from_a_worker_does_not_deadlock(self):
        from hub.util import MAX_PROBE_WORKERS

        def inner(n):
            return n * 2

        def outer(n):
            # Saturating the shared pool in the outer wave used to hang
            # here: the worker waited for map() on the same executor.
            return sum(fan_out(inner, [n, n + 1]))

        got = fan_out(outer, list(range(MAX_PROBE_WORKERS)))
        self.assertEqual(got, [4 * n + 2 for n in range(MAX_PROBE_WORKERS)])

    def test_nested_fan_out_still_overlaps(self):
        def inner(_):
            time.sleep(PROBE_DELAY)
            return 1

        def outer(_):
            return sum(fan_out(inner, [0, 1, 2, 3]))

        started = time.time()
        got = fan_out(outer, [0, 1])
        elapsed = time.time() - started
        self.assertEqual(got, [4, 4])
        self.assertLess(
            elapsed,
            4 * PROBE_DELAY * 0.7,
            f"nested batch took {elapsed:.2f}s; inner items ran serially",
        )


APP_CONFIG = {
    "apps": [
        {"id": "engine", "container_engine": True, "name": "OrbStack"},
        {"id": "a1", "process": "proc1", "port": 1001, "name": "App One"},
        {"id": "a2", "process": "proc2", "port": 1002},
        {"id": "a3", "process": "proc3", "port": 1003},
        {"id": "rejected", "process": "-f"},
        {"id": "nameless"},
    ],
    "scripts": [
        {"id": "s1", "ports": [2001, 2002]},
        {"id": "s2", "ports": [2003]},
        {"id": "s3", "ports": []},
    ],
}


class DiscoveryCollectorTests(unittest.TestCase):
    """/api/status is the hottest path in the panel; these two feed it."""

    def _collect(self, sh_impl=None, port_impl=None):
        sh_impl = sh_impl or slow(lambda cmd: (1 if cmd[2] == "proc2" else 0, "", ""))
        port_impl = port_impl or slow(lambda port: port not in (1003, 2002))
        with (
            mock.patch.object(discovery_apps, "cfg", lambda: APP_CONFIG),
            mock.patch.object(discovery_apps, "resolve_value", lambda v: v),
            mock.patch.object(discovery_apps, "sh", lambda cmd, **kw: sh_impl(cmd)),
            mock.patch.object(
                discovery_apps, "port_open", lambda port, **kw: port_impl(port)
            ),
        ):
            started = time.time()
            items = discovery_apps.collect_apps(engine_up=True)
            apps_elapsed = time.time() - started
            started = time.time()
            scripts = discovery_apps.collect_scripts()
            scripts_elapsed = time.time() - started
        return items, scripts, apps_elapsed, scripts_elapsed

    def test_apps_keep_configuration_order(self):
        items, _, _, _ = self._collect()
        self.assertEqual(
            [i["id"] for i in items], ["engine", "a1", "a2", "a3"]
        )

    def test_the_input_guards_still_reject_bad_entries(self):
        items, _, _, _ = self._collect()
        ids = [i["id"] for i in items]
        self.assertNotIn("rejected", ids, "an option-shaped process name got through")
        self.assertNotIn("nameless", ids, "an entry with no process got through")

    def test_each_app_keeps_the_state_its_probe_implies(self):
        items, _, _, _ = self._collect()
        state = {i["id"]: i["state"] for i in items}
        self.assertEqual(state["a1"], "ok", "running with an open port")
        self.assertEqual(state["a2"], "down", "not running")
        self.assertEqual(state["a3"], "warn", "running but the port is closed")

    def test_the_engine_row_needs_no_probe(self):
        items, _, _, _ = self._collect()
        engine = next(i for i in items if i["id"] == "engine")
        self.assertEqual(engine["kind"], "app-engine")
        self.assertEqual(engine["state"], "ok")

    def test_app_probes_overlap(self):
        _, _, apps_elapsed, _ = self._collect()
        # Three probed apps, two waits each.
        self.assertLess(
            apps_elapsed,
            6 * PROBE_DELAY * 0.7,
            f"collect_apps took {apps_elapsed:.2f}s; the probes did not overlap",
        )

    def test_scripts_keep_configuration_order_and_per_port_detail(self):
        _, scripts, _, _ = self._collect()
        self.assertEqual([s["id"] for s in scripts], ["s1", "s2", "s3"])
        by = {s["id"]: s for s in scripts}
        self.assertEqual(by["s1"]["state"], "warn", "one of two ports is closed")
        self.assertIn(":2002", by["s1"]["detail"], "the missing port must be named")
        self.assertEqual(by["s2"]["state"], "ok")
        self.assertEqual(by["s3"]["state"], "down", "no ports configured")

    def test_script_probes_overlap_across_scripts_and_ports(self):
        _, _, _, scripts_elapsed = self._collect()
        # Three ports across three scripts; the flattening is what lets all three
        # overlap rather than only the outer loop.
        self.assertLess(
            scripts_elapsed,
            3 * PROBE_DELAY * 0.8,
            f"collect_scripts took {scripts_elapsed:.2f}s",
        )

    def test_one_exploding_probe_costs_only_its_own_row(self):
        def boom(cmd):
            if cmd[2] == "proc2":
                raise RuntimeError("pgrep unavailable")
            return 0, "", ""

        items, _, _, _ = self._collect(sh_impl=boom, port_impl=lambda p: True)
        self.assertEqual([i["id"] for i in items], ["engine", "a1", "a2", "a3"])
        self.assertEqual(
            {i["id"]: i["state"] for i in items}["a2"],
            "down",
            "a failed probe must read as down, not remove the row",
        )

    def test_an_empty_configuration_does_not_raise(self):
        with (
            mock.patch.object(discovery_apps, "cfg", lambda: {"apps": [], "scripts": []}),
            mock.patch.object(discovery_apps, "resolve_value", lambda v: v),
        ):
            self.assertEqual(discovery_apps.collect_apps(engine_up=False), [])
            self.assertEqual(discovery_apps.collect_scripts(), [])


UTM_LISTING = "\n".join([
    "UUID                                 Status   Name",
    "11111111-1111-1111-1111-111111111111 started  Ubuntu Server",
    "22222222-2222-2222-2222-222222222222 started  Debian Box",
    "33333333-3333-3333-3333-333333333333 stopped  Fedora",
    "44444444-4444-4444-4444-444444444444 paused   Arch",
    "55555555-5555-5555-5555-555555555555 started  Hidden One",
    "malformed",
])

UTM_OVERRIDES = {
    "Ubuntu Server": {"port": 8001},
    "Debian Box": {"port": 8002},
    "Hidden One": {"hide": True},
}


class UtmListingTests(unittest.TestCase):
    def _list(self, port_impl=None):
        port_impl = port_impl or slow(lambda port: port != 8002)
        with (
            mock.patch.object(vms_svc, "_utm_available", lambda: True),
            mock.patch.object(vms_svc, "sh", lambda *a, **k: (0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", lambda key: UTM_OVERRIDES.get(key)),
            mock.patch.object(vms_svc, "port_open", lambda port, **kw: port_impl(port)),
        ):
            started = time.time()
            vms = vms_svc._list_utm_vms_uncached()
            return vms, time.time() - started

    def test_order_follows_the_utmctl_output(self):
        vms, _ = self._list()
        self.assertEqual(
            [v["id"] for v in vms],
            ["Ubuntu Server", "Debian Box", "Fedora", "Arch"],
        )

    def test_hidden_and_malformed_rows_are_still_dropped(self):
        vms, _ = self._list()
        ids = [v["id"] for v in vms]
        self.assertNotIn("Hidden One", ids)
        self.assertEqual(len(ids), 4, "a malformed line became a row")

    def test_states_still_reflect_status_and_port(self):
        vms, _ = self._list()
        state = {v["id"]: v["state"] for v in vms}
        self.assertEqual(state["Ubuntu Server"], "ok")
        self.assertEqual(state["Debian Box"], "warn", "started but the port is closed")
        self.assertEqual(state["Fedora"], "stopped")
        self.assertEqual(state["Arch"], "warn", "suspended")

    def test_console_identity_is_still_keyed_by_uuid(self):
        vms, _ = self._list()
        ubuntu = next(v for v in vms if v["id"] == "Ubuntu Server")
        self.assertIn("11111111-1111-1111-1111-111111111111", ubuntu["console_id"])

    def test_the_port_probes_overlap(self):
        _, elapsed = self._list()
        self.assertLess(
            elapsed,
            2 * PROBE_DELAY * 0.8,
            f"the listing took {elapsed:.2f}s; the probes did not overlap",
        )

    def test_an_unreachable_network_does_not_empty_the_list(self):
        def boom(port):
            raise OSError("network unreachable")

        vms, _ = self._list(port_impl=boom)
        self.assertEqual(len(vms), 4, "a raising probe emptied the VM list")
        state = {v["id"]: v["state"] for v in vms}
        self.assertEqual(state["Ubuntu Server"], "warn")


class FileServiceProbeTests(unittest.TestCase):
    def test_order_state_and_overlap(self):
        with (
            mock.patch.object(
                shares_svc, "port_open", lambda port, **kw: slow(lambda p: p == 8125)(port)
            ),
            mock.patch.object(shares_svc, "host_ip", lambda: "192.168.1.9"),
            mock.patch.object(shares_svc, "cfg", lambda: {}),
            mock.patch.object(shares_svc, "resolve_value", lambda v: v),
        ):
            started = time.time()
            services = shares_svc.file_services()
            elapsed = time.time() - started

        self.assertEqual([s["id"] for s in services], ["filebrowser", "onedrive-share"])
        by = {s["id"]: s for s in services}
        self.assertEqual(by["filebrowser"]["state"], "ok")
        self.assertEqual(by["onedrive-share"]["state"], "down")
        self.assertEqual(by["filebrowser"]["url"], "http://192.168.1.9:8125")
        self.assertLess(elapsed, 2 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s")

    def test_junk_quick_links_do_not_500(self):
        with (
            mock.patch.object(shares_svc, "port_open", lambda port, **kw: False),
            mock.patch.object(shares_svc, "host_ip", lambda: "192.168.1.9"),
            mock.patch.object(shares_svc, "cfg", lambda: {"quick_links": {"not": "a-list"}}),
            mock.patch.object(shares_svc, "resolve_value", lambda v: v),
        ):
            services = shares_svc.file_services()
        self.assertEqual(len(services), 2)
        self.assertTrue(all(s["url"].startswith("http://192.168.1.9:") for s in services))


def _inspect_payload(name):
    return json.dumps([{
        "Mounts": [{"Type": "bind", "Source": f"/srv/{name}",
                    "Destination": "/data", "RW": True}],
        "NetworkSettings": {
            "Networks": {"demo_net": {"IPAddress": "10.0.0.2", "Gateway": "10.0.0.1"}},
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
        },
        "Config": {"Env": [f"NAME={name}", "DB_PASSWORD=hunter2"]},
    }])


class ContainerInspectTests(unittest.TestCase):
    NAMES = ["web", "db", "cache"]

    def test_results_follow_input_order(self):
        def fake(*args, **kwargs):
            name = args[1]
            return (1, "", "gone") if name == "cache" else (0, _inspect_payload(name), "")

        with mock.patch.object(apps_manage_svc, "docker", fake):
            results = fan_out(apps_manage_svc._inspect, self.NAMES)
        self.assertEqual([rc for rc, _ in results], [0, 0, 1])

    def test_inspects_overlap(self):
        def fake(*args, **kwargs):
            time.sleep(PROBE_DELAY)
            return 0, _inspect_payload(args[1]), ""

        with mock.patch.object(apps_manage_svc, "docker", fake):
            started = time.time()
            fan_out(apps_manage_svc._inspect, self.NAMES)
            elapsed = time.time() - started
        self.assertLess(elapsed, 3 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s")

    def test_a_raising_inspect_becomes_a_failed_rc(self):
        with mock.patch.object(apps_manage_svc, "docker", side_effect=RuntimeError("boom")):
            self.assertEqual(apps_manage_svc._inspect("web"), (1, ""))


class ContainerLogTests(unittest.TestCase):
    CONTAINERS = {
        "containers": [
            {"name": "demo-web", "labels": {"com.docker.compose.project": "demo"}},
            {"name": "demo-db", "labels": {"com.docker.compose.project": "demo"}},
            {"name": "demo-cache", "labels": {"com.docker.compose.project": "demo"}},
            {"name": "unrelated", "labels": {"com.docker.compose.project": "other"}},
        ]
    }

    def _logs(self, docker_impl, source_id="demo"):
        class FakeContainers:
            @staticmethod
            def list_containers(with_stats=False):
                return ContainerLogTests.CONTAINERS

        # Patch the attribute on the `hub` package, not sys.modules.
        # `_docker_logs` does `from hub import containers_svc`, which is an
        # attribute lookup once the submodule has been imported by anything else
        # -- so a sys.modules entry is consulted in isolation and ignored during a
        # full-suite run, which made these tests pass alone and fail together.
        import hub

        with (
            mock.patch.object(apps_manage_svc, "docker", docker_impl),
            mock.patch.object(hub, "containers_svc", FakeContainers, create=True),
            mock.patch.dict(sys.modules, {"hub.containers_svc": FakeContainers}),
            mock.patch.object(apps_manage_svc, "SERVICES_ROOT", Path("/nonexistent")),
        ):
            started = time.time()
            result = apps_manage_svc._docker_logs(source_id, lines=50)
            return result, time.time() - started

    @staticmethod
    def _slow_docker(*args, **kwargs):
        time.sleep(PROBE_DELAY)
        name = args[-1]
        if name == "demo-db":
            return 1, "", f"error reading {name}"
        return 0, f"log line from {name}", ""

    def test_sections_stay_in_enumeration_order(self):
        result, _ = self._logs(self._slow_docker)
        log = result["log"]
        positions = [
            log.index("===== demo-web ====="),
            log.index("===== demo-db ====="),
            log.index("===== demo-cache ====="),
        ]
        self.assertEqual(
            positions,
            sorted(positions),
            "log sections were reordered by completion time",
        )

    def test_only_matching_containers_appear(self):
        result, _ = self._logs(self._slow_docker)
        self.assertNotIn("unrelated", result["log"])

    def test_a_failing_container_still_contributes_its_error(self):
        result, _ = self._logs(self._slow_docker)
        self.assertIn("error reading demo-db", result["log"])
        self.assertEqual(result["log"].count("====="), 6, "a section went missing")

    def test_log_reads_overlap(self):
        _, elapsed = self._logs(self._slow_docker)
        self.assertLess(elapsed, 3 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s")

    def test_a_raising_read_does_not_lose_the_other_sections(self):
        def exploding(*args, **kwargs):
            if args[-1] == "demo-db":
                raise RuntimeError("socket gone")
            return 0, f"ok {args[-1]}", ""

        result, _ = self._logs(exploding)
        self.assertEqual(result["log"].count("====="), 6)
        self.assertIn("ok demo-web", result["log"])
        self.assertIn("socket gone", result["log"])

    def test_no_matching_containers_keeps_the_placeholder(self):
        result, _ = self._logs(self._slow_docker, source_id="nothing-matches")
        self.assertFalse(result["ok"])
        self.assertEqual(result["log"], "no logs")


class RaidCandidateTests(unittest.TestCase):
    """``diskutil info`` per physical disk.

    The RAID picker exists for machines with several disks, so walking them in turn
    made the page slowest exactly where it is used most.
    """

    DEVICES = ["disk0", "disk2", "disk4", "disk6"]

    def _listing(self):
        return {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": device, "Size": 500 * 2**30}
                for device in self.DEVICES
            ]
        }

    def _run(self, info=None, listing=None):
        info = info or (
            lambda device: {
                "MediaName": f"Media {device}",
                "TotalSize": 500 * 2**30,
                "Internal": True,
                "SolidState": True,
                "BusProtocol": "PCI-Express",
            }
        )
        with (
            mock.patch.object(raid_svc, "disk_topology", lambda: {}),
            mock.patch.object(
                raid_svc, "_plist", lambda *a, **kw: listing or self._listing()
            ),
            mock.patch.object(raid_svc, "_disk_info", slow(info)),
        ):
            started = time.time()
            devices = raid_svc.candidate_devices()
            return devices, time.time() - started

    def test_order_follows_the_diskutil_listing(self):
        devices, _ = self._run()
        self.assertEqual([d["device"] for d in devices], self.DEVICES)
        self.assertEqual([d["name"] for d in devices], [f"Media {d}" for d in self.DEVICES])

    def test_the_info_reads_overlap(self):
        _, elapsed = self._run()
        self.assertLess(
            elapsed,
            len(self.DEVICES) * PROBE_DELAY * 0.8,
            f"took {elapsed:.2f}s for {len(self.DEVICES)} disks",
        )

    def test_the_device_guard_still_rejects_odd_identifiers(self):
        listing = {
            "AllDisksAndPartitions": [
                {"DeviceIdentifier": "disk0", "Size": 1},
                {"DeviceIdentifier": "../etc/passwd", "Size": 1},
                {"DeviceIdentifier": "", "Size": 1},
                "not-a-dict",
            ]
        }
        devices, _ = self._run(listing=listing)
        self.assertEqual([d["device"] for d in devices], ["disk0"])

    def test_a_disk_whose_info_comes_back_empty_still_gets_a_row(self):
        # `_disk_info` answers {} for anything it could not read, so the row has to
        # fall back to the listing's size and the device id as its name.
        devices, _ = self._run(info=lambda device: {} if device == "disk4" else {
            "MediaName": f"Media {device}", "TotalSize": 500 * 2**30,
        })
        self.assertEqual([d["device"] for d in devices], self.DEVICES)
        blank = next(d for d in devices if d["device"] == "disk4")
        self.assertEqual(blank["name"], "disk4")
        self.assertEqual(blank["size_bytes"], 500 * 2**30)

    def test_an_empty_listing_does_not_raise(self):
        devices, _ = self._run(listing={"AllDisksAndPartitions": []})
        self.assertEqual(devices, [])


class NativeCatalogListingTests(unittest.TestCase):
    """The app grid: one liveness probe per catalog entry, plus one shared `ps`.

    Two separate wins are pinned here.  The probes overlap, and the process table
    -- which is the same for every entry -- is read once for the whole pass instead
    of once per entry.
    """

    APPS = [
        {"id": "one", "name": "One", "launchd_label": "local.one"},
        {"id": "two", "name": "Two", "launchd_label": "local.two"},
        {"id": "three", "name": "Three", "launchd_label": "local.three"},
        {"id": "four", "name": "Four", "launchd_label": "local.four"},
    ]

    #: No launchd label and no brew service, so these fall through to the `ps` scan.
    PS_APPS = [
        {"id": "p-one", "name": "P One", "process_match": "alpha"},
        {"id": "p-two", "name": "P Two", "process_match": "beta"},
        {"id": "p-three", "name": "P Three", "process_match": "gamma"},
        {"id": "p-four", "name": "P Four", "process_match": "delta"},
    ]

    def setUp(self):
        native_catalog.list_native_apps.invalidate()
        self.addCleanup(native_catalog.list_native_apps.invalidate)

    def _enter(self, apps, **extra):
        """Push the shared patches onto an ExitStack and return it entered."""
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for target, value in {
            "NATIVE_APPS": apps,
            "_is_installed": lambda app, inst=None: True,
            "_brew_list_installed": lambda: set(),
            "brew_services_list": lambda: [],
            "host_ip": lambda: "192.168.1.9",
            **extra,
        }.items():
            stack.enter_context(mock.patch.object(native_catalog, target, value))
        return stack

    def test_rows_follow_catalog_order_within_the_sort(self):
        # Nothing here is featured, so the sort is by name and must be total.
        with self._enter(
            self.APPS, _launchd_or_process_running=slow(lambda *a: True)
        ):
            items = native_catalog.list_native_apps(force=True)
        self.assertEqual([i["id"] for i in items], ["four", "one", "three", "two"])
        self.assertTrue(all(i["running"] for i in items))

    def test_the_liveness_probes_overlap(self):
        with self._enter(
            self.APPS, _launchd_or_process_running=slow(lambda *a: True)
        ):
            started = time.time()
            native_catalog.list_native_apps(force=True)
            elapsed = time.time() - started
        self.assertLess(
            elapsed,
            len(self.APPS) * PROBE_DELAY * 0.8,
            f"took {elapsed:.2f}s for {len(self.APPS)} apps",
        )

    def test_the_process_table_is_read_once_for_the_whole_pass(self):
        calls = []

        def fake_sh(cmd, *a, **kw):
            calls.append(list(cmd))
            if cmd[:2] == ["/bin/ps", "aux"]:
                time.sleep(PROBE_DELAY)
                return 0, "USER PID COMMAND\nme 1 alpha\nme 2 beta\nme 3 gamma\nme 4 delta\n", ""
            return 1, "", ""

        # The table lives in hub.proc_cache now, shared beyond this pass with
        # cloudflared's liveness probe and the Tools process list.  Cleared first
        # because a neighbouring test's table would otherwise answer this one.
        proc_cache.invalidate_processes()
        self.addCleanup(proc_cache.invalidate_processes)
        with (
            self._enter(self.PS_APPS, sh=fake_sh),
            mock.patch.object(proc_cache, "sh", fake_sh),
        ):
            items = native_catalog.list_native_apps(force=True)

        ps_calls = [c for c in calls if c[:2] == ["/bin/ps", "aux"]]
        self.assertEqual(
            len(ps_calls),
            1,
            f"one `ps aux` should serve every app; ran {len(ps_calls)} for {len(self.PS_APPS)}",
        )
        # And the shared table still answers each app's question correctly.
        self.assertTrue(all(i["running"] for i in items))

    def test_the_three_opening_reads_overlap(self):
        def slow_value(value):
            def read(*a, **kw):
                time.sleep(PROBE_DELAY)
                return value
            return read

        with (
            mock.patch.object(native_catalog, "NATIVE_APPS", []),
            mock.patch.object(native_catalog, "_brew_list_installed", slow_value(set())),
            mock.patch.object(native_catalog, "brew_services_list", slow_value([])),
            mock.patch.object(native_catalog, "host_ip", slow_value("192.168.1.9")),
        ):
            started = time.time()
            native_catalog.list_native_apps(force=True)
            elapsed = time.time() - started
        self.assertLess(
            elapsed, 3 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s for three reads"
        )

    def test_a_brew_service_state_still_wins_over_a_probe(self):
        apps = [{"id": "svc", "name": "Svc", "service": True, "package": "pg",
                 "launchd_label": "local.pg"}]
        probed = []

        def record(*a, **kw):
            probed.append(a)
            return False

        with (
            mock.patch.object(native_catalog, "NATIVE_APPS", apps),
            mock.patch.object(native_catalog, "_is_installed", lambda app, inst=None: True),
            mock.patch.object(native_catalog, "_brew_list_installed", lambda: {"pg"}),
            mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: [{"name": "pg", "status": "started"}],
            ),
            mock.patch.object(native_catalog, "host_ip", lambda: "192.168.1.9"),
            mock.patch.object(native_catalog, "_launchd_or_process_running", record),
        ):
            items = native_catalog.list_native_apps(force=True)

        self.assertTrue(items[0]["running"])
        self.assertEqual(probed, [], "a known brew service state should not be re-probed")

    def test_a_brew_services_raise_does_not_empty_the_catalog(self):
        with self._enter(
            self.APPS,
            brew_services_list=mock.Mock(side_effect=RuntimeError("brew timeout")),
            _launchd_or_process_running=lambda *a: False,
        ):
            items = native_catalog.list_native_apps(force=True)
        self.assertEqual(len(items), len(self.APPS))
        self.assertTrue(all(i.get("id") for i in items))


class WireGuardPingTests(unittest.TestCase):
    """One ICMP probe per peer, each waiting out its own deadline."""

    PEERS = [
        {"public_key": f"key{i}", "name": f"peer{i}", "ip": f"10.10.0.{i + 2}/32"}
        for i in range(4)
    ]

    def _run(self, ping=None):
        def default(cmd, *a, **kw):
            time.sleep(PROBE_DELAY)
            return 0, "64 bytes from x: icmp_seq=0 ttl=64 time=1.5 ms", ""

        with (
            mock.patch.object(wireguard_svc, "peer_records", lambda: list(self.PEERS)),
            mock.patch.object(wireguard_svc, "sh", ping or default),
        ):
            started = time.time()
            out = wireguard_svc.ping_peers()
            return out, time.time() - started

    def test_results_follow_peer_order(self):
        out, _ = self._run()
        self.assertEqual([r["name"] for r in out["results"]], [p["name"] for p in self.PEERS])
        self.assertEqual([r["ip"] for r in out["results"]], ["10.10.0.2", "10.10.0.3", "10.10.0.4", "10.10.0.5"])
        self.assertEqual(out["reachable"], 4)
        self.assertEqual(out["total"], 4)

    def test_the_probes_overlap(self):
        _, elapsed = self._run()
        self.assertLess(
            elapsed,
            len(self.PEERS) * PROBE_DELAY * 0.8,
            f"took {elapsed:.2f}s for {len(self.PEERS)} peers",
        )

    def test_one_exploding_probe_costs_only_its_own_peer(self):
        def ping(cmd, *a, **kw):
            if cmd[-1] == "10.10.0.4":
                raise OSError("no route to host")
            return 0, "time=1.5 ms", ""

        out, _ = self._run(ping=ping)
        self.assertEqual([r["name"] for r in out["results"]], [p["name"] for p in self.PEERS])
        by_ip = {r["ip"]: r for r in out["results"]}
        self.assertFalse(by_ip["10.10.0.4"]["reachable"])
        self.assertIsNone(by_ip["10.10.0.4"]["latency_ms"])
        self.assertEqual(out["reachable"], 3)

    def test_a_peer_without_a_usable_address_is_skipped(self):
        peers = [{"public_key": "k", "name": "blank", "ip": ""}, *self.PEERS]
        with (
            mock.patch.object(wireguard_svc, "peer_records", lambda: peers),
            mock.patch.object(wireguard_svc, "sh", lambda *a, **kw: (0, "time=1.0 ms", "")),
        ):
            out = wireguard_svc.ping_peers()
        self.assertEqual(out["total"], len(self.PEERS))
        self.assertNotIn("blank", [r["name"] for r in out["results"]])

    def test_no_peers_needs_no_pool(self):
        with mock.patch.object(wireguard_svc, "peer_records", lambda: []):
            out = wireguard_svc.ping_peers()
        self.assertEqual(out, {"ok": True, "results": [], "reachable": 0, "total": 0})


class PeerPingTests(unittest.TestCase):
    """One ICMP probe per peer, each waiting out its own deadline.

    In series this cost the peer count times up to five seconds, so a server with
    a dozen phones on it timed out before answering at all.
    """

    RECORDS = [
        {"public_key": "k1", "name": "phone", "ip": "10.7.0.2/32"},
        {"public_key": "k2", "name": "laptop", "ip": "10.7.0.3/32"},
        {"public_key": "k3", "name": "tablet", "ip": "10.7.0.4/32"},
        {"public_key": "k4", "name": "broken", "ip": ""},
    ]

    def _ping(self, sh_impl):
        from hub import wireguard_svc

        with (
            mock.patch.object(wireguard_svc, "peer_records", lambda: self.RECORDS),
            mock.patch.object(wireguard_svc, "sh", sh_impl),
        ):
            started = time.time()
            result = wireguard_svc.ping_peers(timeout_ms=500)
            return result, time.time() - started

    @staticmethod
    def _slow_ping(cmd, **kwargs):
        time.sleep(PROBE_DELAY)
        host = cmd[-1]
        if host == "10.7.0.3":
            return 1, "", "timeout"
        return 0, "64 bytes: time=1.23 ms", ""

    def test_peers_without_an_address_are_skipped(self):
        result, _ = self._ping(self._slow_ping)
        self.assertEqual([r["name"] for r in result["results"]],
                         ["phone", "laptop", "tablet"])

    def test_reachability_and_latency_are_parsed(self):
        result, _ = self._ping(self._slow_ping)
        by = {r["name"]: r for r in result["results"]}
        self.assertTrue(by["phone"]["reachable"])
        self.assertEqual(by["phone"]["latency_ms"], 1.23)
        self.assertFalse(by["laptop"]["reachable"])
        self.assertIsNone(by["laptop"]["latency_ms"])

    def test_the_summary_counts_match(self):
        result, _ = self._ping(self._slow_ping)
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["reachable"], 2)

    def test_the_pings_overlap(self):
        _, elapsed = self._ping(self._slow_ping)
        self.assertLess(
            elapsed, 3 * PROBE_DELAY * 0.8, f"pings took {elapsed:.2f}s in series"
        )

    def test_a_raising_ping_marks_one_peer_not_all(self):
        def boom(cmd, **kwargs):
            if cmd[-1] == "10.7.0.3":
                raise OSError("no route")
            return 0, "time=2.0 ms", ""

        result, _ = self._ping(boom)
        self.assertEqual(result["total"], 3, "a raising ping emptied the results")
        by = {r["name"]: r for r in result["results"]}
        self.assertFalse(by["laptop"]["reachable"])
        self.assertTrue(by["phone"]["reachable"])


class HealthPortTests(unittest.TestCase):
    def test_the_key_ports_are_probed_together(self):
        from hub import health_svc

        calls = []
        ports = [port for port, _, _ in health_svc._key_ports()]

        def slow_port(port, **kwargs):
            calls.append(port)
            time.sleep(PROBE_DELAY)
            return port == 8086

        with mock.patch.object(health_svc, "port_open", slow_port):
            started = time.time()
            probed = fan_out(health_svc._probe_port, ports)
            elapsed = time.time() - started

        self.assertEqual(probed, [port == 8086 for port in ports], "order or result changed")
        self.assertEqual(sorted(calls), sorted(ports))
        self.assertLess(elapsed, len(ports) * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s")

    def test_a_raising_probe_reads_as_closed(self):
        from hub import health_svc

        with mock.patch.object(health_svc, "port_open", side_effect=OSError("down")):
            self.assertFalse(health_svc._probe_port(8086))

    def test_collect_checks_absorbs_a_raising_probe(self):
        from hub import health_svc

        source = Path(health_svc.__file__).read_text()
        self.assertIn("def _safe(item):", source)
        self.assertIn("(_engine_up, False)", source)
        self.assertIn("(_immich_checks, [])", source)

    def test_panel_port_follows_the_bind_env(self):
        from hub import health_svc

        with mock.patch.dict("os.environ", {"SERVERHUB_PORT": "9099"}):
            ports = [port for port, _, _ in health_svc._key_ports()]
        self.assertIn(9099, ports)
        self.assertNotIn(8086, ports)


#: Ubuntu CI has no /bin/zsh; a present path keeps a running pid in state ok.
_PRESENT_EXE = "/bin/sh" if Path("/bin/sh").exists() else sys.executable


class LaunchdDiscoveryTests(unittest.TestCase):
    """Two network stages per agent used to sit in one serial loop.

    The reachability connect and ``enrich_service`` -- which probes a detected
    port for a URL -- both ran per installed LaunchAgent, on the /api/status path
    the dashboard polls.
    """

    SPECS = {
        "local.alpha": {"ProgramArguments": ["/usr/local/bin/alpha", "--port", "9001"]},
        "local.beta": {"ProgramArguments": ["/usr/local/bin/beta", "--port", "9002"]},
        "local.gamma": {"ProgramArguments": ["/usr/local/bin/gamma", "--port", "9003"]},
        "local.timer": {"StartInterval": 3600, "ProgramArguments": ["/bin/echo"]},
        "local.hidden": {"ProgramArguments": ["/bin/true"]},
    }
    TABLE = {
        "local.alpha": ("101", "0"),
        "local.beta": ("102", "0"),
        "local.gamma": ("-", "0"),
        "local.timer": ("-", "0"),
    }

    def setUp(self):
        import plistlib
        import shutil
        import tempfile

        from hub.discovery import launchd

        self.launchd = launchd
        self.dir = Path(tempfile.mkdtemp(prefix="serverhub-launchd-test-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        for label, body in self.SPECS.items():
            with open(self.dir / f"{label}.plist", "wb") as fh:
                plistlib.dump({"Label": label, **body}, fh)

    def _discover(self, port_impl=None, enrich_impl=None):
        port_impl = port_impl or slow(lambda port: port != 9002)

        def default_enrich(item, pl=None, pid=None):
            time.sleep(PROBE_DELAY)
            item["enriched"] = True
            return item

        with (
            mock.patch.object(self.launchd, "AGENTS_DIR", str(self.dir)),
            mock.patch.object(self.launchd, "launchctl_table", lambda: self.TABLE),
            mock.patch.object(
                self.launchd, "override",
                lambda label: {"hide": True} if label == "local.hidden" else {},
            ),
            mock.patch.object(
                self.launchd, "port_open", lambda port, **kw: port_impl(port)
            ),
            mock.patch.object(
                self.launchd, "enrich_service", enrich_impl or default_enrich
            ),
            mock.patch.object(self.launchd, "resolve_template", lambda u: u),
            mock.patch.object(self.launchd, "pid_exe_path", lambda pid: _PRESENT_EXE),
            mock.patch.object(self.launchd, "_http_alive", lambda port: True),
        ):
            started = time.time()
            items = self.launchd.discover_launchd()
            return items, time.time() - started

    def test_order_follows_the_sorted_plist_names(self):
        items, _ = self._discover()
        self.assertEqual(
            [i["id"] for i in items],
            ["local.alpha", "local.beta", "local.gamma", "local.timer"],
        )

    def test_hidden_agents_are_still_excluded(self):
        items, _ = self._discover()
        self.assertNotIn("local.hidden", [i["id"] for i in items])

    def test_the_state_machine_is_unchanged(self):
        items, _ = self._discover()
        state = {i["id"]: i["state"] for i in items}
        self.assertEqual(state["local.alpha"], "ok", "running, port reachable")
        self.assertEqual(state["local.beta"], "warn", "running, port closed")
        self.assertEqual(state["local.gamma"], "down", "not running")
        self.assertEqual(state["local.timer"], "ok", "loaded interval job")

    def test_every_item_is_still_enriched(self):
        items, _ = self._discover()
        self.assertTrue(all(i.get("enriched") for i in items))

    def test_detected_ports_still_reach_the_metadata(self):
        items, _ = self._discover()
        alpha = next(i for i in items if i["id"] == "local.alpha")
        self.assertEqual(alpha["port"], 9001)
        self.assertEqual(alpha["meta"]["detected_ports"], [9001])

    def test_both_network_stages_overlap(self):
        _, elapsed = self._discover()
        # 3 ports + 4 enrichments = 7 waits if nothing overlapped.
        self.assertLess(elapsed, 7 * PROBE_DELAY * 0.6, f"took {elapsed:.2f}s")

    def test_a_raising_enrich_keeps_its_row(self):
        def boom(item, pl=None, pid=None):
            if item["id"] == "local.beta":
                raise RuntimeError("url probe exploded")
            return item

        items, _ = self._discover(port_impl=lambda p: True, enrich_impl=boom)
        self.assertEqual(len(items), 4, "a raising enrich emptied the service list")
        self.assertIn("local.beta", [i["id"] for i in items])


class HardwareProfileTests(unittest.TestCase):
    TYPES = [
        ("hardware", "SPHardwareDataType"),
        ("memory", "SPMemoryDataType"),
        ("storage", "SPStorageDataType"),
        ("power", "SPPowerDataType"),
    ]

    def test_reports_keep_their_declared_order_and_overlap(self):
        import hub.disk_power_svc as dps
        from hub import tools_svc

        def slow_profiler(cmd, **kwargs):
            time.sleep(PROBE_DELAY)
            data_type = cmd[1]
            if data_type == "SPPowerDataType":
                return 1, "", f"cannot read {data_type}"
            return 0, f"body for {data_type}", ""

        # list_power_disks is imported inside the function, so it is patched where
        # it is fetched from; otherwise this measures real disk enumeration.
        with (
            mock.patch.object(tools_svc, "sh", slow_profiler),
            mock.patch.object(dps, "list_power_disks", lambda: []),
        ):
            started = time.time()
            profile = tools_svc._hardware_profile_uncached()
            elapsed = time.time() - started

        sections = profile["sections"]
        self.assertEqual(
            list(sections), ["hardware", "memory", "storage", "power"],
            "sections were reordered by completion time",
        )
        self.assertTrue(sections["hardware"]["ok"])
        self.assertFalse(sections["power"]["ok"])
        self.assertIn("cannot read", sections["power"]["text"])
        self.assertLess(elapsed, 4 * PROBE_DELAY * 0.7, f"took {elapsed:.2f}s")

    def test_each_report_is_truncated_independently(self):
        from hub import tools_svc

        with mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "x" * 9000, "")):
            _, text = tools_svc._profiler_report(("hardware", "SPHardwareDataType"))
        self.assertTrue(text.endswith("…(truncated)"))
        self.assertLess(len(text), 4100)

    def test_a_raising_report_becomes_a_failed_section(self):
        from hub import tools_svc

        with mock.patch.object(tools_svc, "sh", side_effect=RuntimeError("gone")):
            rc, text = tools_svc._profiler_report(("hardware", "SPHardwareDataType"))
        self.assertEqual(rc, 1)
        self.assertIn("gone", text)


class SpotlightStatusTests(unittest.TestCase):
    def test_rows_follow_enumeration_order_and_overlap(self):
        from hub import usage_svc

        volumes = ["/", "/Volumes/Media", "/Volumes/Backup", "/Volumes/Scratch"]

        def slow_mdutil(cmd, **kwargs):
            time.sleep(PROBE_DELAY)
            volume = cmd[2]
            if volume == "/Volumes/Backup":
                return 0, "Indexing disabled.", ""
            if volume == "/Volumes/Scratch":
                return 1, "", "no such volume"
            return 0, "Indexing enabled.", ""

        class FakePath:
            def __init__(self, p):
                self.p = p

            def is_dir(self):
                return True

            def is_symlink(self):
                return False

            def iterdir(self):
                return [FakePath(v) for v in volumes[1:]]

            def __str__(self):
                return self.p

            def __lt__(self, other):
                return self.p < other.p

        with (
            mock.patch.object(usage_svc, "sh", slow_mdutil),
            mock.patch.object(usage_svc, "Path", lambda p: FakePath(p)),
        ):
            started = time.time()
            rows = usage_svc.spotlight_status()
            elapsed = time.time() - started

        # "/" first, then the /Volumes children sorted, because the function
        # sorts iterdir() -- so Backup precedes Media.
        self.assertEqual(
            [r["volume"] for r in rows], ["/"] + sorted(volumes[1:])
        )
        by = {r["volume"]: r for r in rows}
        self.assertTrue(by["/"]["enabled"])
        self.assertEqual(by["/Volumes/Backup"]["state"], "disabled")
        self.assertFalse(by["/Volumes/Scratch"]["readable"])
        self.assertEqual(by["/Volumes/Scratch"]["state"], "unknown")
        self.assertLess(elapsed, 4 * PROBE_DELAY * 0.7, f"took {elapsed:.2f}s")

    def test_a_vanished_volume_does_not_lose_the_page(self):
        from hub import usage_svc

        with mock.patch.object(usage_svc, "sh", side_effect=OSError("vanished")):
            rc, blob = usage_svc._spotlight_query("/Volumes/Gone")
        self.assertEqual(rc, 1)
        self.assertIn("vanished", blob)


class _FakeCompleted:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


class DiskPowerListingTests(unittest.TestCase):
    """The storage page: one `diskutil info` and possibly a `smartctl` per disk.

    Two shared reads used to sit inside that per-disk loop -- the mount table and the
    "what does `/` live on" question -- so a listing ran them once per disk to learn
    something with a single answer.  Both are pinned here, because both are invisible
    in the output: the rows are identical either way, only the subprocess count moves.
    """

    IDS = ["disk0", "disk2", "disk4", "disk6"]

    DF_K = (
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
        "/dev/disk0s1 100 50 50 50% /\n"
        "/dev/disk2s1 200 100 100 50% /Volumes/Two\n"
    )

    def setUp(self):
        self._reset()
        self.addCleanup(self._reset)

    def _reset(self):
        disk_power_svc.list_power_disks.invalidate()
        disk_power_svc._invalidate_root_disks()
        disk_power_svc._invalidate_df()

    def _run(self, power_state=None, diskutil_info=None):
        """List with every shell-out faked, counting what actually ran."""
        counts = collections.Counter()

        def fake_sh(cmd, *a, **kw):
            key = " ".join(str(c) for c in cmd)
            counts[key] += 1
            if cmd[:3] == ["/bin/df", "-P", "-k"]:
                return 0, self.DF_K, ""
            if cmd[:3] == ["/bin/df", "-P", "/"]:
                return 0, "Filesystem\n/dev/disk0s1 1 1 1 1% /\n", ""
            if cmd[:3] == ["/usr/sbin/diskutil", "info", "/"]:
                return 0, "   Device Node: /dev/disk0s1\n", ""
            return 1, "", ""

        class FakeSubprocess:
            @staticmethod
            def run(cmd, *a, **kw):
                counts[" ".join(str(c) for c in cmd)] += 1
                return _FakeCompleted(b"", 1)

        info = diskutil_info or (
            lambda node: {
                "MediaName": f"Media {node}",
                "TotalSize": 500 * 10**9,
                "SolidState": True,
                "Internal": False,
                "BusProtocol": "USB",
                "Ejectable": True,
            }
        )
        state = power_state or slow(lambda *a, **kw: "idle")

        # The mount table and the root-disk reads live in hub.disk_snapshot now,
        # shared with the volume list and the manage listing, so they are intercepted
        # there as well as here -- the counter has to see them wherever they run.
        with (
            mock.patch.object(disk_power_svc, "_list_whole_disks", lambda: list(self.IDS)),
            mock.patch.object(disk_power_svc, "sh", fake_sh),
            mock.patch.object(disk_snapshot, "sh", fake_sh),
            mock.patch.object(disk_power_svc, "subprocess", FakeSubprocess),
            mock.patch.object(disk_snapshot, "sh", fake_sh),
            mock.patch.object(disk_snapshot, "subprocess", FakeSubprocess),
            mock.patch.object(disk_power_svc, "_diskutil_info", info),
            mock.patch.object(disk_power_svc, "_power_state", state),
        ):
            started = time.time()
            rows = disk_power_svc.list_power_disks()
            return rows, time.time() - started, counts

    def test_order_follows_the_whole_disk_listing(self):
        rows, _, _ = self._run()
        self.assertEqual([r["id"] for r in rows], self.IDS)

    def test_the_per_disk_probes_overlap(self):
        _, elapsed, _ = self._run()
        self.assertLess(
            elapsed,
            len(self.IDS) * PROBE_DELAY * 0.8,
            f"took {elapsed:.2f}s for {len(self.IDS)} disks",
        )

    def test_the_mount_table_is_read_once_not_once_per_disk(self):
        _, _, counts = self._run()
        reads = counts["/bin/df -P -k"]
        self.assertEqual(
            reads, 1, f"one `df` should serve every disk; ran {reads} for {len(self.IDS)}"
        )

    def test_the_root_disk_question_is_asked_once_not_once_per_disk(self):
        _, _, counts = self._run()
        for command in ("/usr/sbin/diskutil info /", "/bin/df -P /"):
            self.assertLessEqual(
                counts[command],
                1,
                f"{command} ran {counts[command]} times for {len(self.IDS)} disks",
            )

    def test_the_shared_reads_still_classify_the_boot_disk(self):
        # `/` is on disk0s1 in both fakes, so disk0 must come back as the system disk
        # and must not be offered a sleep action.
        rows, _, _ = self._run()
        by_id = {r["id"]: r for r in rows}
        self.assertTrue(by_id["disk0"]["system"])
        self.assertFalse(by_id["disk0"]["can_sleep"])
        self.assertEqual(by_id["disk0"]["actions"], [])
        self.assertFalse(by_id["disk4"]["system"])

    def test_the_shared_mount_table_still_attaches_volumes_per_disk(self):
        rows, _, _ = self._run()
        by_id = {r["id"]: r for r in rows}
        self.assertEqual([v["mount"] for v in by_id["disk0"]["volumes"]], ["/"])
        self.assertEqual([v["mount"] for v in by_id["disk2"]["volumes"]], ["/Volumes/Two"])
        self.assertEqual(by_id["disk4"]["volumes"], [])

    def test_one_unreadable_disk_drops_only_its_own_row(self):
        def exploding(node):
            if "disk4" in str(node):
                raise OSError("bus reset")
            return {"MediaName": "ok", "TotalSize": 1, "SolidState": True, "Internal": True}

        rows, _, _ = self._run(diskutil_info=exploding)
        self.assertEqual([r["id"] for r in rows], ["disk0", "disk2", "disk6"])

    def test_invalidation_drops_both_derived_reads(self):
        """Asserted through a re-read rather than through the module's globals.

        Both reads moved into the snapshot shared with the volume list and the manage
        listing, so `_df_cache` and `_root_disks` no longer exist here.  Counting the
        subprocess is the durable form of the same question: after
        `invalidate_power_disks()` the next listing must go back to the host.
        """
        _, _, first = self._run()
        self.assertEqual(first["/bin/df -P -k"], 1)

        # Without invalidating, a second listing reuses the shared table.
        disk_power_svc.list_power_disks.invalidate()
        _, _, second = self._run()
        self.assertEqual(
            second["/bin/df -P -k"], 0,
            "the shared mount table should still have been warm",
        )

        disk_power_svc.list_power_disks.invalidate()
        disk_power_svc.invalidate_power_disks()
        _, _, third = self._run()
        self.assertEqual(
            third["/bin/df -P -k"], 1,
            "invalidate_power_disks() left the mount table cached",
        )
        self.assertLessEqual(
            third["/usr/sbin/diskutil info /"], 1,
            "the root-disk question should be asked once per listing at most",
        )


class AppsInventoryTests(unittest.TestCase):
    """The Apps page aggregates three backends that have nothing to do with each other.

    Compose stacks, Homebrew/native installs and VMs each shell out several
    times.  Run in series their latencies simply added, so the page waited for
    Docker, then brew, then utmctl before rendering anything -- even though every
    collector is internally overlapped already.

    Fanning them out also changes the failure mode, which is the more valuable
    half: an unreachable Docker socket now costs the Docker section instead of
    the whole page.
    """

    DOCKER = [
        {"id": "docker:web", "kind": "docker", "name": "web", "state": "ok"},
        {"id": "docker:db", "kind": "docker", "name": "db", "state": "down"},
    ]
    NATIVE = [{"id": "native:pg", "kind": "native", "name": "postgres", "state": "ok"}]
    VMS = [{"id": "vm:ubuntu", "kind": "vm", "name": "ubuntu", "state": "warn"}]

    def setUp(self):
        apps_manage_svc.invalidate_inventory()
        self.addCleanup(apps_manage_svc.invalidate_inventory)

    def _inventory(self, **overrides):
        """Run inventory() with every collector slowed and optionally broken."""

        def slow(value):
            def call(*args, **kwargs):
                time.sleep(PROBE_DELAY)
                if isinstance(value, Exception):
                    raise value
                return value
            return call

        values = {
            "_docker_stacks": overrides.get("docker", self.DOCKER),
            "_native_apps": overrides.get("native", self.NATIVE),
            "_launchd_apps": overrides.get("launchd", []),
            "_vms": overrides.get("vms", self.VMS),
            "engine_up": overrides.get("engine", True),
            "_host_ip": overrides.get("host", "192.168.1.9"),
        }
        with mock.patch.multiple(
            apps_manage_svc, **{name: slow(v) for name, v in values.items()}
        ):
            started = time.time()
            inventory = apps_manage_svc.inventory(force=True)
            return inventory, time.time() - started

    def test_every_section_reaches_the_payload(self):
        inventory, _ = self._inventory()
        self.assertEqual(len(inventory["items"]), 4)
        self.assertEqual(inventory["host_ip"], "192.168.1.9")
        self.assertIs(inventory["engine_up"], True)

    def test_the_counts_are_unchanged(self):
        inventory, _ = self._inventory()
        self.assertEqual(
            inventory["counts"],
            {"total": 4, "native": 1, "docker": 2, "launchd": 0, "vm": 1, "running": 2, "stopped": 1},
        )

    def test_the_sort_is_unchanged(self):
        """Running first, then native/docker/vm, then name."""
        inventory, _ = self._inventory()
        self.assertEqual(
            [i["name"] for i in inventory["items"]],
            ["postgres", "web", "ubuntu", "db"],
        )

    def test_the_collectors_overlap(self):
        _, elapsed = self._inventory()
        self.assertLess(
            elapsed,
            6 * PROBE_DELAY * 0.6,
            f"the collectors took {elapsed:.2f}s; they ran in series",
        )

    def test_a_dead_docker_socket_costs_only_the_docker_section(self):
        inventory, _ = self._inventory(docker=RuntimeError("socket gone"))
        self.assertEqual(
            [i["name"] for i in inventory["items"]],
            ["postgres", "ubuntu"],
            "a failing collector emptied sections that had nothing to do with it",
        )
        self.assertEqual(inventory["counts"]["docker"], 0)
        self.assertEqual(inventory["host_ip"], "192.168.1.9")

    def test_a_failing_engine_probe_reads_as_down(self):
        inventory, _ = self._inventory(engine=RuntimeError("no socket"))
        self.assertIs(inventory["engine_up"], False)
        self.assertEqual(len(inventory["items"]), 4, "the item list is independent")

    def test_the_cache_still_short_circuits(self):
        calls = {"n": 0}

        def counting(*args, **kwargs):
            calls["n"] += 1
            return self.DOCKER

        with mock.patch.multiple(
            apps_manage_svc,
            _docker_stacks=counting,
            _native_apps=lambda **kw: self.NATIVE,
            _launchd_apps=lambda: [],
            _vms=lambda: self.VMS,
            engine_up=lambda: True,
            _host_ip=lambda: "192.168.1.9",
        ):
            apps_manage_svc.inventory(force=True)
            apps_manage_svc.inventory(force=False)
        self.assertEqual(calls["n"], 1, "the second call re-collected instead of caching")

    def test_force_is_still_passed_to_the_native_collector(self):
        seen = {}

        def record_native(force=False):
            seen["force"] = force
            return []

        with mock.patch.multiple(
            apps_manage_svc,
            _docker_stacks=lambda: [],
            _native_apps=record_native,
            _launchd_apps=lambda: [],
            _vms=lambda: [],
            engine_up=lambda: True,
            _host_ip=lambda: "h",
        ):
            apps_manage_svc.inventory(force=True)
        self.assertIs(
            seen["force"], True,
            "force must still reach _native_apps, or a just-installed app stays hidden",
        )


class WiredFailoverTests(unittest.TestCase):
    """The failover poller pings each wired link's gateway.

    Every device is probed regardless -- the healthy pick reads the finished list --
    so there was never a short-circuit to preserve, only timeouts to add up. This
    runs on a timer, so a slow tick delays the next one.
    """

    DEVICES = [{"device": "en0"}, {"device": "en7"}, {"device": "en8"}, {"device": "en9"}]

    def _run(self, probe=None, settings=None):
        conf = {
            "enabled": True,
            "probe_timeout_ms": 300,
            "recover_threshold": 99,   # high, so no wifi action is attempted
            "fail_threshold": 99,
            "power_save_wifi": False,
            **(settings or {}),
        }
        calls = []

        def default_probe(device, timeout_ms, iface=None):
            time.sleep(PROBE_DELAY)
            calls.append(device)
            return {"ok": device == "en8", "device": device, "ip": "1.2.3.4",
                    "gateway": "1.2.3.1"}

        with (
            mock.patch.object(network_svc, "_failover_settings", lambda: conf),
            mock.patch.object(network_svc, "_wired_devices", lambda: list(self.DEVICES)),
            mock.patch.object(network_svc, "interfaces", lambda: []),
            mock.patch.object(network_svc, "wifi_power_status", lambda: {"on": None}),
            mock.patch.object(
                network_svc, "set_wifi_power",
                lambda *a, **kw: self.fail("failover must not touch wifi in this test"),
            ),
            mock.patch.object(network_svc, "_probe_wired_device", probe or default_probe),
        ):
            started = time.time()
            result = network_svc.network_failover_tick()
            return result, time.time() - started

    def test_the_gateway_probes_overlap(self):
        _, elapsed = self._run()
        self.assertLess(
            elapsed,
            len(self.DEVICES) * PROBE_DELAY * 0.8,
            f"took {elapsed:.2f}s for {len(self.DEVICES)} wired devices",
        )

    def test_the_healthy_link_is_chosen_in_device_order(self):
        # Two healthy links: the earlier one in configured order must win, regardless
        # of which ping happened to answer first.
        def probe(device, timeout_ms, iface=None):
            time.sleep(PROBE_DELAY if device == "en7" else PROBE_DELAY * 2)
            return {"ok": device in ("en7", "en8"), "device": device}

        result, _ = self._run(probe=probe)
        self.assertEqual(result["mode"], "wired")
        self.assertEqual(result["active_wired"]["device"], "en7")

    def test_one_exploding_probe_does_not_read_as_total_link_loss(self):
        def probe(device, timeout_ms, iface=None):
            if device == "en0":
                raise OSError("interface went away")
            return {"ok": device == "en8", "device": device}

        result, _ = self._run(probe=probe)
        self.assertEqual(result["mode"], "wired", "a healthy link was still present")
        failed = next(p for p in result["wired_probes"] if p["device"] == "en0")
        self.assertFalse(failed["ok"])
        self.assertIn("probe failed", failed["reason"])
        self.assertIn("interface went away", failed["reason"])

    def test_probes_stay_in_device_order(self):
        result, _ = self._run()
        self.assertEqual(
            [p["device"] for p in result["wired_probes"]],
            [d["device"] for d in self.DEVICES],
        )


class AliasStatusTests(unittest.TestCase):
    """Alias IP status: the interface table answers every IP at once."""

    IPS = ["192.168.1.204", "192.168.1.205", "192.168.1.206", "192.168.1.207"]

    TABLE = [
        {"device": "en7", "up": True,
         "addresses": [{"ip": "192.168.1.204", "alias": True, "netmask": "255.255.255.0"}]},
        {"device": "en0", "up": True,
         "addresses": [{"ip": "192.168.1.205", "alias": False, "netmask": "255.255.255.0"}]},
    ]

    def _run(self, route=None):
        reads = collections.Counter()

        def table():
            reads["interface_addresses"] += 1
            return [dict(row) for row in self.TABLE]

        def default_route(ip):
            time.sleep(PROBE_DELAY)
            return {"ok": True, "interface": "en7", "flags": ""}

        with (
            mock.patch.object(
                network_svc, "_alias_settings", lambda: {"ips": list(self.IPS)}
            ),
            mock.patch.object(
                network_svc, "preferred_active_device", lambda: {"device": "en7"}
            ),
            mock.patch.object(network_svc, "interface_addresses", table),
            mock.patch.object(network_svc, "_alias_local_route", route or default_route),
        ):
            started = time.time()
            out = network_svc.alias_auto_status()
            return out, time.time() - started, reads

    def test_the_interface_table_is_read_once_not_once_per_ip(self):
        _, _, reads = self._run()
        self.assertEqual(
            reads["interface_addresses"],
            1,
            f"one table read should serve {len(self.IPS)} ips; "
            f"ran {reads['interface_addresses']}",
        )

    def test_the_route_lookups_overlap(self):
        _, elapsed, _ = self._run()
        self.assertLess(
            elapsed,
            len(self.IPS) * PROBE_DELAY * 0.8,
            f"took {elapsed:.2f}s for {len(self.IPS)} ips",
        )

    def test_rows_follow_configured_ip_order(self):
        out, _, _ = self._run()
        self.assertEqual([r["ip"] for r in out["ips"]], self.IPS)

    def test_the_shared_table_still_locates_each_ip(self):
        out, _, _ = self._run()
        by_ip = {r["ip"]: r for r in out["ips"]}
        self.assertEqual([L["device"] for L in by_ip["192.168.1.204"]["locations"]], ["en7"])
        self.assertTrue(by_ip["192.168.1.204"]["on_preferred"])
        # Present but on the wrong device: located, but not on the preferred one.
        self.assertEqual([L["device"] for L in by_ip["192.168.1.205"]["locations"]], ["en0"])
        self.assertFalse(by_ip["192.168.1.205"]["on_preferred"])
        # Absent entirely.
        self.assertTrue(by_ip["192.168.1.206"]["missing"])

    def test_a_failing_route_lookup_costs_only_its_own_row(self):
        def route(ip):
            if ip == "192.168.1.205":
                raise OSError("route table busy")
            return {"ok": True}

        out, _, _ = self._run(route=route)
        self.assertEqual([r["ip"] for r in out["ips"]], self.IPS)
        by_ip = {r["ip"]: r for r in out["ips"]}
        self.assertFalse(by_ip["192.168.1.205"]["local_route"]["ok"])
        self.assertTrue(by_ip["192.168.1.204"]["local_route"]["ok"])


class NativeAppAutostartLookupTests(unittest.TestCase):
    """The autostart lookups answer the same question for every app, so ask once.

    Both used to be issued inside the per-app loop. That is an N+1: eight
    brew-backed apps meant eight ``brew services`` enumerations and two
    launchd-backed apps meant two ``launchctl`` reads.

    In practice the brew side was already softened by a shared TTL cache -- 1079ms
    on the first call and under a millisecond after -- so the measured saving is
    only about 30ms, not the seconds a naive reading of the loop suggests. The
    reason to pin it is structural rather than numeric: with the lookups hoisted,
    the cost cannot scale with the number of installed apps at all, and it no
    longer depends on a cache staying warm for the whole loop. ``_launchd_items``
    is not cached (22-49ms every call), so that part is a real subprocess saved.
    """

    APPS = [
        {"id": "a", "installed": True, "method": "brew_formula", "package": "pg"},
        {"id": "b", "installed": True, "method": "brew_formula", "package": "redis"},
        {"id": "c", "installed": True, "method": "brew_cask", "package": "docker"},
        {"id": "d", "installed": True, "launchd_label": "local.one"},
        {"id": "e", "installed": True, "launchd_label": "local.two"},
        {"id": "skipped", "installed": False, "method": "brew_formula", "package": "no"},
    ]

    def _count_lookups(self):
        from hub import apps_manage_svc, autostart_svc, native_catalog

        calls = {"brew": 0, "launchd": 0}

        def brew_items():
            calls["brew"] += 1
            return [{"name": "pg", "autostart": True},
                    {"name": "redis", "autostart": False},
                    {"name": "docker", "autostart": True}]

        def launchd_items():
            calls["launchd"] += 1
            return [{"label": "local.one", "autostart": True},
                    {"label": "local.two", "autostart": False}]

        with (
            mock.patch.object(
                native_catalog, "list_native_apps", lambda force=False: self.APPS
            ),
            mock.patch.object(autostart_svc, "_brew_service_items", brew_items),
            mock.patch.object(autostart_svc, "_launchd_items", launchd_items),
            mock.patch.object(apps_manage_svc, "_host_ip", lambda: "10.0.0.1"),
        ):
            items = apps_manage_svc._native_apps(force=False)
        return calls, items

    def test_each_lookup_runs_once_regardless_of_app_count(self):
        calls, _ = self._count_lookups()
        self.assertEqual(
            calls["brew"], 1,
            f"brew services was enumerated {calls['brew']} times for 3 brew apps",
        )
        self.assertEqual(
            calls["launchd"], 1,
            f"launchctl was read {calls['launchd']} times for 2 launchd apps",
        )

    def test_the_autostart_flags_are_still_resolved_per_app(self):
        _, items = self._count_lookups()
        # Emitted ids are namespaced "native:<source id>".
        flags = {i["source_id"]: i.get("autostart") for i in items}
        self.assertIs(flags["a"], True, "brew formula flag lost")
        self.assertIs(flags["b"], False, "a False flag must survive, not become None")
        self.assertIs(flags["c"], True, "brew cask flag lost")
        self.assertIs(flags["d"], True, "launchd flag lost")
        self.assertIs(flags["e"], False)

    def test_uninstalled_apps_are_still_excluded(self):
        _, items = self._count_lookups()
        self.assertNotIn("skipped", [i["source_id"] for i in items])

    def test_an_unavailable_brew_leaves_flags_unknown_rather_than_dropping_apps(self):
        """The per-app try/except this replaced failed soft; so must the hoist."""
        from hub import apps_manage_svc, autostart_svc, native_catalog

        with (
            mock.patch.object(
                native_catalog, "list_native_apps", lambda force=False: self.APPS
            ),
            mock.patch.object(
                autostart_svc, "_brew_service_items", side_effect=OSError("no brew")
            ),
            mock.patch.object(autostart_svc, "_launchd_items", lambda: []),
            mock.patch.object(apps_manage_svc, "_host_ip", lambda: "10.0.0.1"),
        ):
            items = apps_manage_svc._native_apps(force=False)

        self.assertEqual(
            len(items), 5,
            "a failing autostart lookup dropped apps from the inventory",
        )
        self.assertTrue(
            all(
                i.get("autostart") is None
                for i in items
                if i["source_id"] in {"a", "b", "c"}
            ),
            "flags should be unknown, not wrong",
        )


class UpdateCheckTests(unittest.TestCase):
    """Two package managers, two unrelated questions, each with a 45s timeout."""

    def _run(self, brew=None, macos=None):
        def slow_brew():
            time.sleep(PROBE_DELAY)
            return {"ok": True, "outdated": ["pkg 1.0 < 2.0"], "count": 1, "raw": ""}

        def slow_macos():
            time.sleep(PROBE_DELAY)
            return {"ok": True, "lines": ["* Label: macOS 26.1"], "raw": "raw",
                    "has_updates": True}

        tools_svc._updates_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._updates_cache.update, t=0.0, v=None)
        with (
            mock.patch.object(tools_svc, "_brew_outdated", brew or slow_brew),
            mock.patch.object(tools_svc, "_macos_updates", macos or slow_macos),
            mock.patch.object(
                tools_svc, "_github_latest",
                return_value={
                    "ok": True, "current": "3.9.1", "latest": "3.9.1",
                    "update_available": False, "tag": "v3.9.1",
                    "html_url": "", "notes": "", "error": "",
                    "repo": "elvin-li/ServerHub", "source": "release",
                    "published_at": "",
                },
            ),
        ):
            started = time.time()
            out = tools_svc.check_updates(force=True)
            return out, time.time() - started

    def test_the_two_package_managers_are_asked_together(self):
        _, elapsed = self._run()
        self.assertLess(elapsed, 2 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s")

    def test_both_answers_land_in_their_own_keys(self):
        out, _ = self._run()
        self.assertEqual(out["brew"]["count"], 1)
        self.assertTrue(out["macos"]["has_updates"])
        self.assertIn("ts", out)
        self.assertEqual(out["cached_ttl"], tools_svc._UPDATES_TTL)

    def test_a_failing_brew_probe_does_not_hide_the_macos_answer(self):
        out, _ = self._run(brew=lambda: {"ok": False, "outdated": [], "count": 0,
                                         "raw": "brew exploded"})
        self.assertFalse(out["brew"]["ok"])
        self.assertTrue(out["macos"]["ok"], "the macOS side should still be reported")

    def test_the_result_is_cached_for_the_next_caller(self):
        first, _ = self._run()
        # Second call must not re-probe: patches are gone, so a probe would use the
        # real commands and the counts would change.
        second = tools_svc.check_updates()
        self.assertEqual(first["ts"], second["ts"])


class DockerDiskUsageCacheTests(unittest.TestCase):
    """`docker system df` makes the daemon total every image and volume."""

    def setUp(self):
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def test_repeat_callers_share_one_invocation(self):
        calls = []

        def fake_docker(*args, **kw):
            calls.append(args)
            time.sleep(PROBE_DELAY)
            return 0, "TYPE TOTAL ACTIVE SIZE RECLAIMABLE\nImages 3 1 1GB 500MB (50%)", ""

        with (
            mock.patch.object(tools_svc, "engine_up", lambda: True),
            mock.patch.object(tools_svc, "docker", fake_docker),
        ):
            first = tools_svc.docker_disk_usage()
            second = tools_svc.docker_disk_usage()
            third = tools_svc.docker_disk_usage()

        self.assertEqual(
            len(calls), 1, f"three callers should share one `docker system df`, ran {len(calls)}"
        )
        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(first["lines"][0]["type"], "Images")

    def test_a_prune_drops_the_cached_totals(self):
        # The numbers a prune reports must not be the ones it just invalidated.
        with (
            mock.patch.object(tools_svc, "engine_up", lambda: True),
            mock.patch.object(
                tools_svc, "docker",
                lambda *a, **kw: (0, "TYPE TOTAL ACTIVE SIZE RECLAIMABLE\n"
                                     "Images 9 9 9GB 0B (0%)", ""),
            ),
        ):
            tools_svc.docker_disk_usage()
            calls = []

            def counting(*args, **kw):
                calls.append(args)
                return 0, "TYPE TOTAL ACTIVE SIZE RECLAIMABLE\nImages 1 1 1GB 0B (0%)", ""

            with mock.patch.object(tools_svc, "docker", counting):
                result = tools_svc.docker_prune("dangling", confirm=True)

        # One call for the prune itself, one for the fresh df it reports.
        self.assertIn(("system", "df"), calls, "the prune should re-read the totals")
        self.assertEqual(result["df"]["lines"][0]["total"], "1")


class SystemDiagnosticsTests(unittest.TestCase):
    """Five small reads that used to queue behind `docker system df`."""

    def _run(self):
        def slow_sh(cmd, *a, **kw):
            time.sleep(PROBE_DELAY)
            if cmd[:1] == ["/bin/hostname"]:
                return 0, "testhost", ""
            if cmd[-1] == "machdep.cpu.brand_string":
                return 0, "Test CPU", ""
            if cmd[-1] == "hw.ncpu":
                return 0, "10", ""
            if cmd[-1] == "hw.memsize":
                return 0, str(32 * 2**30), ""
            if cmd[-1] == "kern.boottime":
                return 0, "{ sec = 1000, usec = 0 }", ""
            return 1, "", ""

        def slow_df():
            time.sleep(PROBE_DELAY)
            return {"engine_up": True, "raw": "", "lines": []}

        with (
            mock.patch.object(tools_svc, "sh", slow_sh),
            mock.patch.object(tools_svc, "engine_up", lambda: True),
            mock.patch.object(tools_svc, "docker_disk_usage", slow_df),
        ):
            started = time.time()
            out = tools_svc.diagnostics()
            return out, time.time() - started

    def test_the_six_reads_overlap(self):
        _, elapsed = self._run()
        self.assertLess(elapsed, 6 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s for six reads")

    def test_every_field_still_comes_from_its_own_read(self):
        out, _ = self._run()
        self.assertEqual(out["hostname"], "testhost")
        self.assertEqual(out["cpu"], "Test CPU")
        self.assertEqual(out["ncpu"], 10)
        self.assertEqual(out["mem_gb"], 32.0)
        self.assertTrue(out["orbstack"])
        self.assertIsNotNone(out["uptime_sec"])

    def test_a_failed_read_falls_back_exactly_as_the_serial_version_did(self):
        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **kw: (1, "", "nope")),
            mock.patch.object(tools_svc, "engine_up", lambda: False),
        ):
            out = tools_svc.diagnostics()
        # hostname fell back to platform.node(), the rest to empty/None.
        self.assertTrue(out["hostname"])
        self.assertEqual(out["cpu"], "")
        self.assertIsNone(out["ncpu"])
        self.assertIsNone(out["mem_gb"])
        self.assertIsNone(out["uptime_sec"])
        self.assertEqual(out["docker_df"], {})

    def test_an_exploding_docker_probe_does_not_lose_the_sysctls(self):
        def boom():
            raise OSError("daemon gone")

        with (
            mock.patch.object(tools_svc, "engine_up", lambda: True),
            mock.patch.object(tools_svc, "docker_disk_usage", boom),
        ):
            out = tools_svc.diagnostics()
        self.assertFalse(out["orbstack"])
        self.assertEqual(out["docker_df"], {})
        self.assertTrue(out["hostname"], "the rest of the payload should survive")


class ManagedVolumePrologueTests(unittest.TestCase):
    """The four reads that open a managed-volume listing."""

    TREE = {"AllDisksAndPartitions": [
        {"DeviceIdentifier": "disk0", "Size": 500 * 2**30, "Partitions": [
            {"DeviceIdentifier": "disk0s1", "Size": 500 * 2**30},
        ]},
        {"DeviceIdentifier": "disk4", "Size": 100 * 2**30, "Partitions": [
            {"DeviceIdentifier": "disk4s1", "Size": 100 * 2**30},
        ]},
    ]}

    def setUp(self):
        disk_manage_svc.invalidate_disk_info()
        self.addCleanup(disk_manage_svc.invalidate_disk_info)

    def _run(self):
        def slow_plist(argv, **kw):
            time.sleep(PROBE_DELAY)
            if "physical" in argv:
                return {"WholeDisks": ["disk0", "disk4"]}
            return {k: v for k, v in self.TREE.items()}

        def slow_sh(cmd, *a, **kw):
            time.sleep(PROBE_DELAY)
            if cmd[:3] == ["/bin/df", "-P", "/"]:
                return 0, "Filesystem\n/dev/disk0s1 1 1 1 1% /\n", ""
            return 1, "", ""

        def slow_info(node):
            time.sleep(PROBE_DELAY)
            if node == "/":
                return {"ParentWholeDisk": "disk0"}
            return {"MediaName": f"Media {node}", "TotalSize": 1}

        with (
            mock.patch.object(disk_manage_svc, "_plist", slow_plist),
            mock.patch.object(disk_manage_svc, "sh", slow_sh),
            mock.patch.object(disk_manage_svc, "_diskutil_info", slow_info),
            mock.patch.object(disk_manage_svc, "_prefetch_disk_info", lambda nodes: None),
        ):
            started = time.time()
            out = disk_manage_svc.list_managed_volumes()
            return out, time.time() - started

    def test_the_four_opening_reads_overlap(self):
        _, elapsed = self._run()
        # Four prologue reads plus the per-node lookups the walk still makes; the
        # bound only has to exclude the prologue having been serial.
        self.assertLess(elapsed, 8 * PROBE_DELAY, f"took {elapsed:.2f}s")

    def test_the_boot_disk_is_still_classified_from_the_shared_reads(self):
        # This is the safety-critical output: a volume wrongly marked non-system is
        # offered erase and rename.
        out, _ = self._run()
        by_id = {v["id"]: v for v in out}
        self.assertTrue(by_id["disk0"]["system"])
        self.assertTrue(by_id["disk0s1"]["system"])
        self.assertEqual(by_id["disk0"]["actions"], [])
        self.assertEqual(by_id["disk0s1"]["actions"], [])
        self.assertFalse(by_id["disk4"]["system"])
        self.assertTrue(by_id["disk4"]["actions"])

    def test_an_empty_device_tree_returns_nothing(self):
        with (
            mock.patch.object(disk_manage_svc, "_plist", lambda argv, **kw: {}),
            mock.patch.object(disk_manage_svc, "sh", lambda *a, **kw: (1, "", "")),
            mock.patch.object(disk_manage_svc, "_diskutil_info", lambda n: {}),
        ):
            self.assertEqual(disk_manage_svc.list_managed_volumes(), [])


class ContainerListSingleFlightTests(unittest.TestCase):
    """Simultaneous readers must share one `docker ps` / `inspect` / `stats`.

    This is the other half of the concurrency work in this file: the probes above
    were made to overlap, and these caches were made not to duplicate. The TTL dicts
    these replaced checked the cache, released the lock and only then ran the
    command, so every reader that arrived during a cold window ran the whole chain --
    and `docker stats --no-stream` is the ~2s one.
    """

    ROWS = "\n".join(
        f"id{i}\tctr{i}\timg{i}\trunning\tUp 2 hours\t\tproj\tsvc\t1MB" for i in range(3)
    )

    def setUp(self):
        containers_svc.invalidate_container_lists()
        self.addCleanup(containers_svc.invalidate_container_lists)
        self.calls = collections.Counter()
        self._lock = threading.Lock()

    def _docker(self, *args, timeout=30):
        kind = args[0] if args else "?"
        with self._lock:
            self.calls[kind] += 1
        time.sleep(PROBE_DELAY)
        if kind == "ps":
            return 0, self.ROWS, ""
        if kind == "inspect":
            return 0, json.dumps([
                {"Name": f"/ctr{i}",
                 "HostConfig": {"NetworkMode": "bridge",
                                "RestartPolicy": {"Name": "always"}},
                 "NetworkSettings": {"Networks": {}}, "Mounts": [],
                 "Config": {"Image": f"img{i}"},
                 "Created": "2026-01-01T00:00:00Z"}
                for i in range(3)
            ]), ""
        if kind == "stats":
            return 0, "\n".join(
                f"ctr{i}\t1%\t10MiB / 1GiB\t1%\t0B / 0B\t0B / 0B" for i in range(3)
            ), ""
        return 0, "", ""

    @contextlib.contextmanager
    def _patched(self, engine_up=True):
        with (
            mock.patch.object(containers_svc, "docker", self._docker),
            mock.patch.object(containers_svc, "engine_up", lambda: engine_up),
        ):
            yield

    def _read(self, readers):
        with self._patched():
            with ThreadPoolExecutor(max_workers=readers) as ex:
                return list(ex.map(lambda _: containers_svc.list_containers(True), range(readers)))

    def test_the_invocation_count_does_not_grow_with_readers(self):
        for readers in (2, 4, 8):
            with self.subTest(readers=readers):
                containers_svc.invalidate_container_lists()
                self.calls.clear()
                self._read(readers)
                for command in ("ps", "inspect", "stats"):
                    self.assertEqual(
                        self.calls[command], 1,
                        f"{readers} readers ran `docker {command}` "
                        f"{self.calls[command]} times; one should serve all",
                    )

    def test_every_reader_gets_the_same_answer(self):
        results = self._read(4)
        self.assertEqual({len(r["containers"]) for r in results}, {3})
        self.assertTrue(all(len(r["stats"]) == 3 for r in results))
        self.assertTrue(all(r["engine_up"] for r in results))

    def test_a_warm_cache_costs_no_subprocess(self):
        self._read(1)
        self.calls.clear()
        with self._patched():
            containers_svc.list_containers(True)
        self.assertEqual(sum(self.calls.values()), 0)

    def test_invalidation_forces_a_fresh_read(self):
        self._read(1)
        containers_svc.invalidate_container_lists()
        self.calls.clear()
        with self._patched():
            containers_svc.list_containers(True)
        self.assertEqual(self.calls["ps"], 1)
        self.assertEqual(self.calls["stats"], 1)

    def test_stats_are_skipped_when_not_asked_for(self):
        with self._patched():
            out = containers_svc.list_containers(with_stats=False)
        self.assertEqual(self.calls["stats"], 0, "`docker stats` is the ~2s call")
        self.assertEqual(out["stats"], {})
        self.assertEqual(len(out["containers"]), 3)

    def test_an_engine_that_is_down_still_short_circuits(self):
        with self._patched(engine_up=False):
            out = containers_svc.list_containers(True)
        self.assertEqual(
            out, {"engine_up": False, "containers": [], "stats": {}, "projects": []}
        )

    def test_a_caller_cannot_edit_the_shared_cache(self):
        # The rows are handed to several readers now, so a mutation by one of them
        # must not be visible to the next.
        with self._patched():
            first = containers_svc.list_containers(True)
            first["containers"][0]["name"] = "MUTATED"
            second = containers_svc.list_containers(True)
        self.assertNotEqual(second["containers"][0]["name"], "MUTATED")


class SmartSnapshotTests(unittest.TestCase):
    """The SMART snapshot: shared by simultaneous readers, and droppable.

    Two separate defects, both invisible in a single-reader happy path. The cache was
    a bare dict that computed outside any lock, so concurrent cold readers each ran
    the whole per-disk probe; and nothing invalidated it, so with a ten-minute TTL a
    disk that was ejected or erased kept its health row for the rest of that window.
    """

    def setUp(self):
        storage_svc.invalidate_smart()
        self.addCleanup(storage_svc.invalidate_smart)
        self.calls = collections.Counter()
        self._lock = threading.Lock()

    def _sh(self, cmd, timeout=10):
        joined = " ".join(str(c) for c in cmd)
        if "smartctl" in joined:
            key = "smartctl"
        elif joined.startswith("diskutil info"):
            key = "info"
        else:
            key = "list"
        with self._lock:
            self.calls[key] += 1
        time.sleep(PROBE_DELAY)
        if "list physical" in joined:
            return 0, "/dev/disk0 (internal):\n/dev/disk4 (external):\n", ""
        if "smartctl" in joined:
            return 0, "SMART overall-health self-assessment test result: PASSED", ""
        return 0, "Device / Media Name: Test\nDisk Size: 500.0 GB (500000000000 Bytes)", ""

    def test_the_probe_count_does_not_grow_with_readers(self):
        for readers in (2, 4, 8):
            with self.subTest(readers=readers):
                storage_svc.invalidate_smart()
                self.calls.clear()
                with mock.patch.object(storage_svc, "sh", self._sh):
                    with ThreadPoolExecutor(max_workers=readers) as ex:
                        list(ex.map(lambda _: storage_svc.smart_devices(), range(readers)))
                self.assertEqual(
                    self.calls["smartctl"], 2,
                    f"{readers} readers ran smartctl {self.calls['smartctl']} times "
                    f"for 2 disks; one probe per disk should serve all readers",
                )

    def test_every_reader_sees_the_same_disks_in_the_same_order(self):
        with mock.patch.object(storage_svc, "sh", self._sh):
            with ThreadPoolExecutor(max_workers=4) as ex:
                results = list(ex.map(lambda _: storage_svc.smart_devices(), range(4)))
        for devices in results:
            self.assertEqual([d["id"] for d in devices], ["disk0", "disk4"])
            self.assertEqual([(d.get("smart") or {}).get("health") for d in devices],
                             ["PASSED", "PASSED"])

    def test_a_warm_snapshot_costs_no_subprocess(self):
        with mock.patch.object(storage_svc, "sh", self._sh):
            storage_svc.smart_devices()
            self.calls.clear()
            storage_svc.smart_devices()
        self.assertEqual(sum(self.calls.values()), 0)

    def test_invalidate_smart_forces_a_re_probe(self):
        # Without this hook a disk removed from the machine kept its health row for
        # the full ten-minute TTL.
        with mock.patch.object(storage_svc, "sh", self._sh):
            storage_svc.smart_devices()
            storage_svc.invalidate_smart()
            self.calls.clear()
            storage_svc.smart_devices()
        self.assertEqual(self.calls["smartctl"], 2)

    def test_the_disk_routes_drop_the_snapshot(self):
        """Both mutating storage routes must reach the invalidation.

        Checked at the source, because the alternative is driving diskutil for real.
        """
        source = (BASE / "hub" / "routers" / "storage.py").read_text()
        self.assertEqual(
            source.count("storage_svc.invalidate_smart()"),
            2,
            "the power route and the manage route both change which disks are present",
        )
        for anchor in ("def storage_disk_power", "def storage_manage_action"):
            start = source.index(anchor)
            body = source[start: source.index("\n@router", start + 10)
                          if "\n@router" in source[start:] else len(source)]
            self.assertIn(
                "invalidate_smart", body, f"{anchor} does not drop the SMART snapshot"
            )


class HealthCheckSingleFlightTests(unittest.TestCase):
    """The health snapshot is a seven-way fan-out; it should run once per window.

    The TTL alone did not achieve that. The health card, the dashboard and the
    diagnostics bundle all read it, and the panel and menu-bar client both poll, so
    readers land together on a cold cache and each used to run the whole collection --
    including `sudo -n smartctl` and the Immich probe.
    """

    def setUp(self):
        health_svc._cache.update(t=0.0, v=None)
        self.addCleanup(health_svc._cache.update, t=0.0, v=None)
        launchd_cache.invalidate_launchd()
        self.addCleanup(launchd_cache.invalidate_launchd)
        self.calls = collections.Counter()
        self._lock = threading.Lock()

    #: A listing with a row in it.  An empty one would mean the read failed, and the
    #: shared cache deliberately does not remember a failure -- so a blank fixture
    #: would make every reader retry and this test would be measuring that instead of
    #: single-flight.
    LISTING = "PID\tStatus\tLabel\n4242\t0\tlocal.alpha\n"

    def _sh(self, cmd, *a, **kw):
        argv = list(cmd) if isinstance(cmd, (list, tuple)) else [cmd]
        key = " ".join(str(c) for c in argv[:2])
        with self._lock:
            self.calls[key] += 1
        time.sleep(PROBE_DELAY)
        if key == "/bin/launchctl list":
            return 0, self.LISTING, ""
        return 0, "", ""

    def test_the_collection_does_not_repeat_per_reader(self):
        # `/bin/launchctl`, not a bare `launchctl`: the shared listing settled on the
        # absolute path, because a bare name depends on the panel's PATH and a
        # LaunchAgent does not necessarily set one.
        listing = "/bin/launchctl list"
        for readers in (2, 4, 8):
            with self.subTest(readers=readers):
                health_svc._cache.update(t=0.0, v=None)
                launchd_cache.invalidate_launchd()
                self.calls.clear()
                with (
                    mock.patch.object(health_svc, "sh", self._sh),
                    mock.patch.object(launchd_cache, "sh", self._sh),
                ):
                    with ThreadPoolExecutor(max_workers=readers) as ex:
                        list(ex.map(lambda _: health_svc.run_checks(), range(readers)))
                self.assertEqual(
                    self.calls[listing], 1,
                    f"{readers} readers ran `launchctl list` "
                    f"{self.calls[listing]} times",
                )
                self.assertEqual(
                    self.calls["/usr/bin/sudo -n"], 1,
                    f"{readers} readers ran `/usr/bin/sudo -n smartctl` "
                    f"{self.calls['/usr/bin/sudo -n']} times",
                )

    def test_every_reader_gets_the_one_collected_snapshot(self):
        with mock.patch.object(health_svc, "sh", self._sh):
            with ThreadPoolExecutor(max_workers=4) as ex:
                results = list(ex.map(lambda _: health_svc.run_checks(), range(4)))
        # Object identity, not equality: `ts` is second-resolution, so four separate
        # collections in the same second compare equal and would prove nothing. One
        # shared object is what distinguishes joining a collection from repeating it.
        self.assertEqual(
            len({id(r) for r in results}), 1,
            "each reader collected its own snapshot instead of joining the first",
        )
        self.assertEqual(len({len(r["checks"]) for r in results}), 1)

    def test_a_warm_snapshot_costs_no_subprocess(self):
        with mock.patch.object(health_svc, "sh", self._sh):
            health_svc.run_checks()
            self.calls.clear()
            health_svc.run_checks()
        self.assertEqual(sum(self.calls.values()), 0)

    def test_force_still_bypasses_a_fresh_cache(self):
        # The lock must not turn `force` into "wait, then return the cached copy".
        with mock.patch.object(health_svc, "sh", self._sh):
            health_svc.run_checks()
            self.calls.clear()
            health_svc.run_checks(force=True)
        self.assertGreater(sum(self.calls.values()), 0, "force= must re-collect")

    def test_the_snapshot_shape_is_unchanged(self):
        with mock.patch.object(health_svc, "sh", self._sh):
            out = health_svc.run_checks()
        self.assertEqual(sorted(out.keys()), ["checks", "healthy", "summary", "ts"])
        self.assertEqual(sorted(out["summary"].keys()), ["error", "ok", "total", "warn"])
        self.assertEqual(
            out["summary"]["total"], len(out["checks"]), "summary must count the checks"
        )


class DeliberatelySerialTests(unittest.TestCase):
    """Not everything with several shell-outs should be fanned out.

    ``wireguard_net_svc.daemon_state`` issues up to three, but they are a
    *fallback chain*: the sudo retry only runs when the unprivileged read failed,
    and the ``launchctl list`` scan only runs when both failed. Running them
    together would make the common case slower, and it would move ``sudo_capture``
    onto a worker thread where the administrator password is invisible -- so the
    root fallback would silently stop working.
    """

    def test_daemon_state_is_not_fanned_out(self):
        source = (BASE / "hub" / "wireguard_net_svc.py").read_text()
        start = source.index("def daemon_state")
        body = source[start: source.index("\ndef ", start + 10)]
        self.assertNotIn("fan_out", body)
        self.assertNotIn("ThreadPoolExecutor", body)
        self.assertIn(
            "sudo_capture",
            body,
            "if the sudo fallback left this function, revisit the comment above",
        )


if __name__ == "__main__":
    unittest.main()
