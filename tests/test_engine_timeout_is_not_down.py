"""A slow Docker probe must not be reported as a stopped engine.

A *stopped* engine fails fast -- `docker info` / `docker ps` answer "Cannot
connect to the Docker daemon" with a non-zero exit within milliseconds.  A
probe *timeout* is different: the host (or daemon) was too loaded to answer
inside the budget, which says nothing about whether the engine is running.

On the host this was written for, an overnight load storm made `docker ps -a`
exceed its 8s budget once per alert cycle, and every timeout was reported as
"OrbStack engine not running" -- fifteen down/recover alert pairs in one night
against an engine with two days of uptime and containers that never stopped.

The rule pinned here: a bounded number of consecutive timeouts re-serves the
last real observation; beyond that the engine is reported down anyway, so a
genuinely wedged daemon (which also times out, forever) still surfaces.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import docker_cli  # noqa: E402
from hub.discovery import containers  # noqa: E402

TIMEOUT = (-1, "", "timeout")
DEAD_ENGINE = (1, "", "Cannot connect to the Docker daemon")
PS_ONE_CONTAINER = (0, "web\trunning\tUp 2 days\tproj", "")


class EngineUpTimeoutTests(unittest.TestCase):
    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def _expire_cache(self):
        with docker_cli._engine_lock:
            docker_cli._engine_cache["t"] -= docker_cli._ENGINE_TTL + 1

    def test_a_timeout_keeps_the_last_real_observation(self):
        with mock.patch.object(docker_cli, "docker", return_value=(0, "ok", "")):
            self.assertTrue(docker_cli.engine_up())
        self._expire_cache()
        with mock.patch.object(docker_cli, "docker", return_value=TIMEOUT):
            self.assertTrue(
                docker_cli.engine_up(),
                "one slow probe flipped a running engine to down",
            )

    def test_endless_timeouts_do_eventually_report_down(self):
        # A wedged daemon times out on every probe; the tolerance must run out.
        with mock.patch.object(docker_cli, "docker", return_value=(0, "ok", "")):
            docker_cli.engine_up()
        results = []
        with mock.patch.object(docker_cli, "docker", return_value=TIMEOUT):
            for _ in range(docker_cli._TIMEOUT_TOLERANCE + 1):
                self._expire_cache()
                results.append(docker_cli.engine_up())
        self.assertFalse(results[-1], "a daemon that never answers read as up forever")

    def test_a_success_resets_the_tolerance(self):
        with mock.patch.object(docker_cli, "docker", return_value=(0, "ok", "")):
            docker_cli.engine_up()
        with mock.patch.object(docker_cli, "docker", return_value=TIMEOUT):
            for _ in range(docker_cli._TIMEOUT_TOLERANCE - 1):
                self._expire_cache()
                docker_cli.engine_up()
        with mock.patch.object(docker_cli, "docker", return_value=(0, "ok", "")):
            self._expire_cache()
            self.assertTrue(docker_cli.engine_up())
        # The counter is back at zero, so the next timeout is tolerated again.
        with mock.patch.object(docker_cli, "docker", return_value=TIMEOUT):
            self._expire_cache()
            self.assertTrue(docker_cli.engine_up())

    def test_a_stopped_engine_is_still_reported_immediately(self):
        # The fast failure of a dead daemon is real evidence, not a timeout.
        with mock.patch.object(docker_cli, "docker", return_value=(0, "ok", "")):
            docker_cli.engine_up()
        self._expire_cache()
        with mock.patch.object(docker_cli, "docker", return_value=DEAD_ENGINE):
            self.assertFalse(
                docker_cli.engine_up(),
                "a cleanly-stopped engine must not hide behind the stale value",
            )

    def test_a_timeout_with_no_history_reports_down(self):
        # First probe after startup times out: there is nothing real to serve.
        with mock.patch.object(docker_cli, "docker", return_value=TIMEOUT):
            self.assertFalse(docker_cli.engine_up())


class DiscoverContainersTimeoutTests(unittest.TestCase):
    def setUp(self):
        containers.invalidate_containers()
        self.addCleanup(containers.invalidate_containers)

    def _expire_cache(self):
        with containers._lock:
            containers._cache["t"] -= containers._TTL + 1

    def test_a_timeout_keeps_the_last_container_list(self):
        with mock.patch.object(containers, "sh", return_value=PS_ONE_CONTAINER):
            items, engine_up = containers.discover_containers(force=True)
        self.assertTrue(engine_up)
        self.assertEqual([i["id"] for i in items], ["web"])

        self._expire_cache()
        with mock.patch.object(containers, "sh", return_value=TIMEOUT):
            items, engine_up = containers.discover_containers()
        self.assertTrue(engine_up, "one slow `docker ps` read as engine down")
        self.assertEqual(
            [i["id"] for i in items],
            ["web"],
            "a slow probe emptied the container list",
        )

    def test_endless_timeouts_do_eventually_report_down(self):
        with mock.patch.object(containers, "sh", return_value=PS_ONE_CONTAINER):
            containers.discover_containers(force=True)
        with mock.patch.object(containers, "sh", return_value=TIMEOUT):
            for _ in range(containers._TIMEOUT_TOLERANCE + 1):
                self._expire_cache()
                items, engine_up = containers.discover_containers()
        self.assertFalse(engine_up)
        self.assertEqual(items, [])

    def test_a_fast_failure_is_still_reported_immediately(self):
        with mock.patch.object(containers, "sh", return_value=PS_ONE_CONTAINER):
            containers.discover_containers(force=True)
        self._expire_cache()
        with mock.patch.object(containers, "sh", return_value=DEAD_ENGINE):
            items, engine_up = containers.discover_containers()
        self.assertFalse(engine_up)
        self.assertEqual(items, [])

    def test_a_timeout_with_no_history_reports_down(self):
        with mock.patch.object(containers, "sh", return_value=TIMEOUT):
            items, engine_up = containers.discover_containers(force=True)
        self.assertFalse(engine_up)
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
