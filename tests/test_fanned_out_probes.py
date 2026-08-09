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

import contextlib
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    apps_manage_svc,
    native_catalog,
    raid_svc,
    shares_svc,
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
        self.assertEqual(result["log"], "无日志")


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
        native_catalog._list_cache.update(t=0.0, v=None)
        self.addCleanup(native_catalog._list_cache.update, t=0.0, v=None)

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

        with self._enter(self.PS_APPS, sh=fake_sh):
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
    def test_the_three_key_ports_are_probed_together(self):
        from hub import health_svc

        calls = []

        def slow_port(port, **kwargs):
            calls.append(port)
            time.sleep(PROBE_DELAY)
            return port == 8086

        with mock.patch.object(health_svc, "port_open", slow_port):
            started = time.time()
            probed = fan_out(health_svc._probe_port, [8086, 8123, 8281])
            elapsed = time.time() - started

        self.assertEqual(probed, [True, False, False], "order or result changed")
        self.assertEqual(sorted(calls), [8086, 8123, 8281])
        self.assertLess(elapsed, 3 * PROBE_DELAY * 0.8, f"took {elapsed:.2f}s")

    def test_a_raising_probe_reads_as_closed(self):
        from hub import health_svc

        with mock.patch.object(health_svc, "port_open", side_effect=OSError("down")):
            self.assertFalse(health_svc._probe_port(8086))


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
