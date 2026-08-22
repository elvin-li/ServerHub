"""Port detection must read one shared lsof snapshot, not one lsof per pid.

`discover_launchd()` resolved a service's live port with
`lsof -nP -a -p <pid> -iTCP -sTCP:LISTEN`, once per running agent.  Each of
those calls costs ~43ms, so on a host with 15 running LaunchAgents port
detection alone was ~644ms of a ~730ms status refresh — and the cost grew with
every agent the user installed.  `enrich_service()` re-ran lsof for pids
`discover_launchd()` had already resolved, and `discover_orphan_listeners()`
shelled out a *third* time, after the discovery thread pool had already joined,
adding ~106ms of pure serial tail.

One global `lsof -nP -iTCP -sTCP:LISTEN` costs ~61ms and contains every answer
all three callers need.

The contract these tests pin down:
  - a full refresh spawns exactly ONE lsof, no matter how many pids it resolves
  - per-pid port lookups still return that pid's ports, and only that pid's
  - the orphan scan reads the same snapshot instead of shelling out again
  - concurrent cold callers collapse into a single subprocess (single-flight)
  - invalidate_status() drops the snapshot, so the refresh after a start/stop
    never reports pre-action ports
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import adaptive  # noqa: E402

# Real `lsof -nP -iTCP -sTCP:LISTEN` output shape: header row, then one row per
# listening socket.  Two pids own two ports each; one row omits the trailing
# (LISTEN) token, which real lsof does, so NAME lands in the last field.
LSOF_OUT = """COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
python3.1   901 a0000    7u  IPv4 0x95e5fc567e5a7d66      0t0  TCP *:8086 (LISTEN)
python3.1   901 a0000    8u  IPv6 0x37e6fd865f9d2fa6      0t0  TCP *:8125 (LISTEN)
postgres    902 a0000    5u  IPv4 0x11e5fc567e5a7d11      0t0  TCP 127.0.0.1:5432 (LISTEN)
postgres    902 a0000    6u  IPv4 0x22e5fc567e5a7d22      0t0  TCP 127.0.0.1:5433
node       9103 a0000    9u  IPv4 0x33e5fc567e5a7d33      0t0  TCP *:3000 (LISTEN)
Cursor     9200 a0000   11u  IPv4 0x44e5fc567e5a7d44      0t0  TCP 127.0.0.1:45678 (LISTEN)
"""


def _fake_sh(recorder):
    """Stand in for hub.util.sh, recording every argv it is handed."""

    def run(cmd, timeout=10, shell=False):
        recorder.append(list(cmd) if isinstance(cmd, (list, tuple)) else [cmd])
        return 0, LSOF_OUT, ""

    return run


class LsofSnapshotTestCase(unittest.TestCase):
    def setUp(self):
        adaptive.invalidate_lsof_snapshot()
        self.addCleanup(adaptive.invalidate_lsof_snapshot)


class TestOneLsofPerRefresh(LsofSnapshotTestCase):
    def test_resolving_many_pids_spawns_exactly_one_lsof(self):
        """The whole point: N pids, one subprocess."""
        calls = []
        with mock.patch.object(adaptive, "sh", _fake_sh(calls)):
            for pid in (901, 902, 9103, 901, 902):
                adaptive.ports_for_pid(pid)
        self.assertEqual(
            len(calls), 1,
            f"expected 1 lsof for 5 pid lookups, got {len(calls)}: {calls}",
        )

    def test_the_one_call_is_the_global_listener_query(self):
        """Not a per-pid query — no `-p <pid>` in the argv."""
        calls = []
        with mock.patch.object(adaptive, "sh", _fake_sh(calls)):
            adaptive.ports_for_pid(901)
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertIn("-iTCP", argv)
        self.assertIn("-sTCP:LISTEN", argv)
        self.assertNotIn("-p", argv, f"per-pid lsof is the thing we removed: {argv}")

    def test_orphan_scan_reuses_the_snapshot_taken_by_port_detection(self):
        """Port detection then the orphan scan = still one lsof total."""
        calls = []
        with mock.patch.object(adaptive, "sh", _fake_sh(calls)):
            adaptive.ports_for_pid(901)
            adaptive.discover_orphan_listeners(set(), set())
        self.assertEqual(
            len(calls), 1,
            f"orphan scan shelled out again; calls={calls}",
        )

    def test_orphan_scan_alone_still_takes_a_snapshot(self):
        """It must not depend on someone else having warmed the cache."""
        calls = []
        with mock.patch.object(adaptive, "sh", _fake_sh(calls)):
            adaptive.discover_orphan_listeners(set(), set())
        self.assertEqual(len(calls), 1)


class TestPerPidPortsStillCorrect(LsofSnapshotTestCase):
    """Speed is worthless if the ports come back wrong."""

    def test_returns_only_the_requested_pids_ports(self):
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            self.assertEqual(adaptive.ports_for_pid(901), [8086, 8125])
            self.assertEqual(adaptive.ports_for_pid(902), [5432, 5433])
            self.assertEqual(adaptive.ports_for_pid(9103), [3000])

    def test_pid_prefix_does_not_leak(self):
        """pid 910 must not match pid 9103's row via substring comparison."""
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            self.assertEqual(adaptive.ports_for_pid(910), [])

    def test_row_without_listen_token_is_still_parsed(self):
        """pid 902's :5433 row has no trailing (LISTEN)."""
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            self.assertIn(5433, adaptive.ports_for_pid(902))

    def test_string_pid_from_launchctl_table_works(self):
        """launchctl list yields pids as strings."""
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            self.assertEqual(adaptive.ports_for_pid("901"), [8086, 8125])

    def test_unknown_and_invalid_pids_return_empty(self):
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            for pid in (4242, 0, -1, None, "-", "", "abc"):
                with self.subTest(pid=pid):
                    self.assertEqual(adaptive.ports_for_pid(pid), [])

    def test_lsof_failure_yields_no_ports_and_no_crash(self):
        def failing(cmd, timeout=10, shell=False):
            return 1, "", "lsof: not permitted"

        with mock.patch.object(adaptive, "sh", failing):
            self.assertEqual(adaptive.ports_for_pid(901), [])
            self.assertEqual(adaptive.discover_orphan_listeners(set(), set()), [])


class TestSingleFlight(LsofSnapshotTestCase):
    def test_concurrent_cold_callers_collapse_into_one_subprocess(self):
        """full_status fans out across a thread pool, so cold races are real."""
        calls = []
        gate = threading.Barrier(6, timeout=10)
        lock = threading.Lock()

        def slow(cmd, timeout=10, shell=False):
            with lock:
                calls.append(list(cmd))
            return 0, LSOF_OUT, ""

        results = {}

        def worker(pid):
            gate.wait()
            results[pid] = adaptive.ports_for_pid(pid)

        with mock.patch.object(adaptive, "sh", slow):
            threads = [threading.Thread(target=worker, args=(p,))
                       for p in (901, 902, 9103, 901, 902)]
            for t in threads:
                t.start()
            gate.wait()
            for t in threads:
                t.join(timeout=10)

        self.assertEqual(
            len(calls), 1,
            f"single-flight broken: {len(calls)} concurrent lsof calls",
        )
        self.assertEqual(results[901], [8086, 8125])
        self.assertEqual(results[902], [5432, 5433])


class TestInvalidation(LsofSnapshotTestCase):
    def test_invalidate_lsof_snapshot_forces_a_fresh_read(self):
        calls = []
        with mock.patch.object(adaptive, "sh", _fake_sh(calls)):
            adaptive.ports_for_pid(901)
            adaptive.invalidate_lsof_snapshot()
            adaptive.ports_for_pid(901)
        self.assertEqual(len(calls), 2)

    def test_invalidate_status_drops_the_snapshot(self):
        """A start/stop changes exactly what the snapshot records."""
        from hub import status

        calls = []
        with mock.patch.object(adaptive, "sh", _fake_sh(calls)):
            adaptive.ports_for_pid(901)
            self.assertEqual(len(calls), 1)
            status.invalidate_status()
            adaptive.ports_for_pid(901)
        self.assertEqual(
            len(calls), 2,
            "invalidate_status() left a stale lsof snapshot in place",
        )

    def test_new_port_is_visible_after_invalidation(self):
        """The behaviour a user sees: start a service, its port shows up."""
        before = LSOF_OUT
        after = LSOF_OUT + (
            "redis      903 a0000    5u  IPv4 0x55e5fc567e5a7d55      0t0"
            "  TCP 127.0.0.1:6379 (LISTEN)\n"
        )
        state = {"out": before}

        def shifting(cmd, timeout=10, shell=False):
            return 0, state["out"], ""

        with mock.patch.object(adaptive, "sh", shifting):
            self.assertEqual(adaptive.ports_for_pid(903), [])
            state["out"] = after
            adaptive.invalidate_lsof_snapshot()
            self.assertEqual(adaptive.ports_for_pid(903), [6379])


class TestOrphanScanBehaviourUnchanged(LsofSnapshotTestCase):
    """Reading from the snapshot must not alter what the scan reports."""

    def test_known_ports_are_excluded(self):
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            items = adaptive.discover_orphan_listeners({8086, 8125, 5432, 5433}, set())
        ports = {i["meta"]["port"] for i in items}
        self.assertNotIn(8086, ports)
        self.assertIn(3000, ports)

    def test_noisy_processes_and_ephemeral_high_ports_are_skipped(self):
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            items = adaptive.discover_orphan_listeners(set(), set())
        ports = {i["meta"]["port"] for i in items}
        self.assertNotIn(45678, ports, "Cursor's ephemeral port leaked in")

    def test_reported_item_carries_process_pid_and_bind(self):
        with mock.patch.object(adaptive, "sh", _fake_sh([])):
            items = adaptive.discover_orphan_listeners(set(), set())
        node = next(i for i in items if i["meta"]["port"] == 3000)
        self.assertEqual(node["meta"]["pid"], "9103")
        self.assertEqual(node["meta"]["process"], "node")
        self.assertEqual(node["kind"], "auto")
        self.assertEqual(node["state"], "ok")


class TestPlistPortExtraction(unittest.TestCase):
    def test_cloudflared_edge_flags_are_not_listen_ports(self):
        ports = adaptive.ports_from_plist({
            "ProgramArguments": [
                "/opt/homebrew/bin/cloudflared", "tunnel",
                "--config", "/tmp/zaoxue.yml",
                "--edge", "198.41.192.7:7844",
                "--edge", "198.41.192.27:7844",
                "--protocol", "http2",
                "run",
            ],
        })
        self.assertEqual(ports, [])

    def test_non_dict_env_and_sockets_do_not_500(self):
        ports = adaptive.ports_from_plist({
            "ProgramArguments": ["/bin/svc", "--port", "8123"],
            "EnvironmentVariables": ["PORT=9"],
            "Sockets": ["http"],
        })
        self.assertIn(8123, ports)
        self.assertIsNone(adaptive.url_from_plist({
            "EnvironmentVariables": ["URL=http://x"],
        }))


class TestVmListTtlOutlivesStatusTtl(unittest.TestCase):
    """A VM list TTL under the status TTL missed on every single refresh."""

    def test_vm_list_ttl_exceeds_status_ttl(self):
        from hub import status, vms_svc

        self.assertGreater(
            vms_svc._LIST_TTL, status._STATUS_TTL,
            "VM lists expire before the status cache does, so every polled "
            "refresh pays full utmctl+orbctl cost",
        )


if __name__ == "__main__":
    unittest.main()
