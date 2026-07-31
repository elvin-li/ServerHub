"""Bounded job history, one registration entry point, and cache single-flight.

Two long-lived leaks and one stampede lived here:

1. ``containers_svc._cjobs`` was keyed by a generated tid
   (``stack-<id>-<action>-<epoch>``), so every container job added a permanent
   entry holding up to ``JOB_LOG_MAX_LINES`` log lines.  A panel left running
   for weeks accumulated them until restart.
2. ``tools_svc.hardware_profile`` / ``check_updates`` cached their result but
   had no single-flight, so N concurrent cold callers each paid the full
   ``system_profiler`` / ``softwareupdate`` cost (up to 45s apiece).

The cap test is paired with an AST invariant: it is not enough to add a
constant, every write has to go through the one entry point that enforces it.
A direct ``_cjobs[tid] = {...}`` elsewhere silently reopens the leak.
"""
from __future__ import annotations

import ast
import sys
import threading
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import containers_svc, network_svc, tools_svc  # noqa: E402


class TestJobHistoryIsBounded(unittest.TestCase):
    def setUp(self):
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()

    def tearDown(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    def test_cap_constant_exists(self):
        self.assertTrue(
            hasattr(containers_svc, "JOB_HISTORY_MAX"),
            "the job store needs an explicit upper bound",
        )
        self.assertGreater(containers_svc.JOB_HISTORY_MAX, 0)

    def test_registering_many_jobs_evicts_the_oldest(self):
        cap = containers_svc.JOB_HISTORY_MAX
        for i in range(cap * 3):
            containers_svc._register_job(f"job-{i:04d}", stack_id="s", action="up")
            # jobs must not stay "running" or the next registration is refused
            containers_svc._cjobs[f"job-{i:04d}"]["running"] = False
        self.assertLessEqual(
            len(containers_svc._cjobs),
            cap,
            "the job store grew past its cap",
        )
        # the newest entry survived, the very first did not
        self.assertIn(f"job-{cap * 3 - 1:04d}", containers_svc._cjobs)
        self.assertNotIn("job-0000", containers_svc._cjobs)

    def test_eviction_never_drops_a_running_job(self):
        containers_svc._register_job("keeper", stack_id="s", action="up")
        # keeper stays running; fill the store around it
        for i in range(containers_svc.JOB_HISTORY_MAX * 2):
            tid = f"filler-{i:04d}"
            try:
                containers_svc._register_job(tid, stack_id="s", action="up")
            except Exception:
                # a running keeper makes the mutex refuse new jobs — that is the
                # real behaviour; force the entry in to exercise eviction only.
                containers_svc._cjobs[tid] = {
                    "running": False, "rc": 0, "log": [], "stack_id": "s",
                    "action": "up", "started": "00:00:00", "finished": "00:00:01",
                }
                containers_svc._evict_old_jobs()
        self.assertIn("keeper", containers_svc._cjobs, "a running job was evicted")

    def test_register_refuses_a_second_running_job(self):
        containers_svc._register_job("first", stack_id="s", action="up")
        with self.assertRaises(Exception):
            containers_svc._register_job("second", stack_id="s", action="up")

    def test_register_returns_the_live_job_dict(self):
        j = containers_svc._register_job("solo", stack_id="s", action="up")
        j["log"].append("hello")
        self.assertEqual(containers_svc._cjobs["solo"]["log"], ["hello"])


class TestNoDirectJobStoreWrites(unittest.TestCase):
    """Every write to _cjobs must go through the capped entry point."""

    ALLOWED_FUNCTIONS = {"_register_job", "_evict_old_jobs"}

    def test_no_subscript_assignment_outside_the_entry_point(self):
        src = (BASE / "hub" / "containers_svc.py").read_text()
        tree = ast.parse(src)

        # map every node to the function that encloses it
        enclosing: dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    enclosing.setdefault(id(child), node.name)

        offenders = []
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                targets = [node.target]
            for tgt in targets:
                if not isinstance(tgt, ast.Subscript):
                    continue
                base = tgt.value
                if isinstance(base, ast.Name) and base.id == "_cjobs":
                    fn = enclosing.get(id(node), "<module>")
                    if fn not in self.ALLOWED_FUNCTIONS:
                        offenders.append(f"{fn}:{node.lineno}")

        self.assertEqual(
            offenders,
            [],
            "_cjobs written directly (bypasses the cap) at: " + ", ".join(offenders),
        )


class TestToolsCacheSingleFlight(unittest.TestCase):
    def test_hardware_profile_collapses_concurrent_cold_calls(self):
        tools_svc._hw_cache.update(t=0.0, v=None)
        calls = []
        real_sh = tools_svc.sh

        def counting_sh(cmd, **kw):
            if "system_profiler" in " ".join(cmd):
                calls.append(cmd)
                time.sleep(0.15)
                return (0, "Model Name: Test", "")
            return real_sh(cmd, **kw)

        tools_svc.sh = counting_sh
        try:
            threads = [
                threading.Thread(target=lambda: tools_svc.hardware_profile())
                for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            tools_svc.sh = real_sh
            tools_svc._hw_cache.update(t=0.0, v=None)

        # 4 system_profiler subsets for one refresh; 8 concurrent callers
        # without single-flight would issue 32.
        self.assertLessEqual(
            len(calls), 4,
            f"concurrent cold callers each re-ran system_profiler ({len(calls)} calls)",
        )

    def test_check_updates_collapses_concurrent_cold_calls(self):
        tools_svc._updates_cache.update(t=0.0, v=None)
        calls = []
        real_sh = tools_svc.sh

        def counting_sh(cmd, **kw):
            joined = " ".join(cmd)
            if "softwareupdate" in joined or "outdated" in joined:
                calls.append(cmd)
                time.sleep(0.15)
                return (0, "", "")
            return real_sh(cmd, **kw)

        tools_svc.sh = counting_sh
        try:
            threads = [
                threading.Thread(target=lambda: tools_svc.check_updates())
                for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            tools_svc.sh = real_sh
            tools_svc._updates_cache.update(t=0.0, v=None)

        self.assertLessEqual(
            len(calls), 2,
            f"concurrent cold callers each re-ran the update check ({len(calls)} calls)",
        )

    def test_warm_cache_does_not_shell_out(self):
        tools_svc._hw_cache.update(t=time.time(), v={"sections": {}, "disks": []})
        calls = []
        real_sh = tools_svc.sh

        def counting_sh(cmd, **kw):
            calls.append(cmd)
            return real_sh(cmd, **kw)

        tools_svc.sh = counting_sh
        try:
            tools_svc.hardware_profile()
        finally:
            tools_svc.sh = real_sh
            tools_svc._hw_cache.update(t=0.0, v=None)
        self.assertEqual(calls, [], "a warm cache still shelled out")


class TestNetworkCacheSingleFlight(unittest.TestCase):
    def setUp(self):
        self._overview_cache = dict(network_svc._cache)
        self._services_cache = dict(network_svc._services_cache)
        network_svc._bust()

    def tearDown(self):
        with network_svc._cache_lock:
            network_svc._cache.update(self._overview_cache)
        with network_svc._services_cache_lock:
            network_svc._services_cache.update(self._services_cache)

    def _run_together(self, fn, count=8):
        barrier = threading.Barrier(count)
        results = []
        errors = []

        def call():
            try:
                barrier.wait()
                results.append(fn())
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=call) for _ in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), count)
        return results

    def test_services_collapses_concurrent_cold_calls(self):
        calls = []
        real_build = network_svc._build_network_services

        def fake_build():
            calls.append(time.monotonic())
            time.sleep(0.15)
            return [{"name": "Wi-Fi"}]

        network_svc._build_network_services = fake_build
        try:
            results = self._run_together(network_svc.network_services)
        finally:
            network_svc._build_network_services = real_build

        self.assertEqual(len(calls), 1)
        self.assertTrue(all(result == [{"name": "Wi-Fi"}] for result in results))

    def test_services_coalesces_concurrent_forced_calls(self):
        calls = []
        real_build = network_svc._build_network_services

        def fake_build():
            calls.append(time.monotonic())
            time.sleep(0.15)
            return [{"name": "Ethernet"}]

        network_svc._build_network_services = fake_build
        try:
            results = self._run_together(lambda: network_svc.network_services(force=True))
        finally:
            network_svc._build_network_services = real_build

        self.assertEqual(len(calls), 1)
        self.assertTrue(all(result == [{"name": "Ethernet"}] for result in results))

    def test_overview_collapses_cold_and_forced_calls(self):
        calls = []
        real_build = network_svc._build_overview

        def fake_build(force_services=False):
            calls.append(force_services)
            time.sleep(0.15)
            return {"generation": len(calls)}

        network_svc._build_overview = fake_build
        try:
            cold = self._run_together(network_svc.overview)
            with network_svc._cache_lock:
                network_svc._cache["t"] = 0.0
            forced = self._run_together(lambda: network_svc.overview(force=True))
        finally:
            network_svc._build_overview = real_build

        self.assertEqual(calls, [False, True])
        self.assertTrue(all(result == {"generation": 1} for result in cold))
        self.assertTrue(all(result == {"generation": 2} for result in forced))

    def test_bust_invalidates_overview_and_services(self):
        with network_svc._cache_lock:
            network_svc._cache.update(t=time.time(), v={"cached": True})
        with network_svc._services_cache_lock:
            network_svc._services_cache.update(t=time.time(), v=[{"cached": True}])

        network_svc._bust()

        self.assertEqual(network_svc._cache, {"t": 0.0, "v": None})
        self.assertEqual(network_svc._services_cache, {"t": 0.0, "v": None})


if __name__ == "__main__":
    unittest.main(verbosity=2)
