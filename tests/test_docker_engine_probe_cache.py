"""`engine_up()` must not run `docker info` once per caller.

The probe has around twenty call sites across a dozen modules and each ran a full
`docker info` just to read its exit status -- 160ms to 1.1s against the daemon.
Building one page payload probed the engine two or three times (health checks 2,
autostart 2, network 3), all within milliseconds and all necessarily agreeing.

The cached value decides whether the UI claims Docker is running, so the TTL is
deliberately short and these tests pin both halves: duplicates inside a request
collapse, and a stale answer cannot outlive the window or survive an explicit
invalidation.
"""
from __future__ import annotations

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import docker_cli  # noqa: E402


class EngineProbeCacheTests(unittest.TestCase):
    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self.probes = 0

    def _probe(self, *args, timeout=None):
        self.probes += 1
        return (0, "Server Version: 29.4.0", "")

    def test_repeated_callers_share_one_probe(self):
        with patch.object(docker_cli, "docker", side_effect=self._probe):
            results = [docker_cli.engine_up() for _ in range(5)]
        self.assertEqual(self.probes, 1, "engine_up ran docker info per caller")
        self.assertTrue(all(results))

    def test_a_down_engine_is_cached_too(self):
        """Otherwise a stopped engine costs a full timeout on every call."""
        def failing(*args, timeout=None):
            self.probes += 1
            return (1, "", "Cannot connect to the Docker daemon")

        with patch.object(docker_cli, "docker", side_effect=failing):
            results = [docker_cli.engine_up() for _ in range(4)]
        self.assertEqual(self.probes, 1)
        self.assertEqual(results, [False, False, False, False])

    def test_force_re_probes(self):
        with patch.object(docker_cli, "docker", side_effect=self._probe):
            docker_cli.engine_up()
            docker_cli.engine_up(force=True)
        self.assertEqual(self.probes, 2)

    def test_invalidation_re_probes(self):
        """A caller that just started or stopped the engine must not read stale state."""
        with patch.object(docker_cli, "docker", side_effect=self._probe):
            docker_cli.engine_up()
            docker_cli.invalidate_engine_state()
            docker_cli.engine_up()
        self.assertEqual(self.probes, 2)

    def test_the_window_is_short_enough_to_reflect_a_restart(self):
        # A long TTL would leave the UI claiming Docker is up after it died.
        self.assertLessEqual(docker_cli._ENGINE_TTL, 10.0)
        self.assertGreater(docker_cli._ENGINE_TTL, 0)

    def test_expiry_re_probes(self):
        with patch.object(docker_cli, "docker", side_effect=self._probe):
            docker_cli.engine_up()
            # Age the entry past the window rather than sleeping through it.
            with docker_cli._engine_lock:
                docker_cli._engine_cache["t"] -= docker_cli._ENGINE_TTL + 1
            docker_cli.engine_up()
        self.assertEqual(self.probes, 2)

    def test_concurrent_callers_share_one_probe(self):
        started = threading.Event()
        release = threading.Event()

        def slow(*args, timeout=None):
            self.probes += 1
            started.set()
            release.wait(timeout=5)
            return (0, "ok", "")

        with patch.object(docker_cli, "docker", side_effect=slow):
            with ThreadPoolExecutor(max_workers=4) as ex:
                futures = [ex.submit(docker_cli.engine_up) for _ in range(4)]
                self.assertTrue(started.wait(timeout=5))
                release.set()
                results = [f.result(timeout=10) for f in futures]

        self.assertEqual(self.probes, 1, "concurrent callers each probed the daemon")
        self.assertTrue(all(results))


if __name__ == "__main__":
    unittest.main()
