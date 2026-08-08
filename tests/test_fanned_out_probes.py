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

import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import apps_manage_svc, shares_svc, vms_svc  # noqa: E402
from hub.discovery import apps as discovery_apps  # noqa: E402
from hub.util import fan_out  # noqa: E402

#: Long enough that a serial run is unmistakably slower, short enough to keep the
#: suite quick.
PROBE_DELAY = 0.2


def slow(result_for):
    """A probe that sleeps, so overlap is measurable."""

    def probe(item):
        time.sleep(PROBE_DELAY)
        return result_for(item)

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
