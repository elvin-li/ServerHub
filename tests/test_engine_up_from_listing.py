"""A successful container listing counts as the engine-up probe.

``docker_cli.engine_up()`` spawns ``docker info`` (~130 ms of CPU) whenever its
five-second memo is stale, only to read the exit status.  The container
listing behind ``/api/status`` (``discovery.containers``) runs ``docker ps -a``
every few seconds while the dashboard is open, and its success proves the
same thing.  It now records that in the memo, so health checks and the
containers page in the same tick skip their own probe.  A failed or
timed-out listing records nothing, and the memo keeps its TTL.
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import docker_cli  # noqa: E402
from hub.discovery import containers  # noqa: E402

PS_OUT = "web\trunning\tUp 2 hours\tnginx:latest\tstack\n"


class EngineUpFromListingTests(unittest.TestCase):
    def setUp(self):
        for reset in (docker_cli.invalidate_engine_state, containers.invalidate_containers):
            reset()
            self.addCleanup(reset)
        self.probes = []

        def docker_info(cmd, timeout=10, **kwargs):
            self.probes.append(list(cmd))
            return 1, "", "Cannot connect to the Docker daemon"

        self.enterContext(mock.patch.object(docker_cli, "sh", side_effect=docker_info))
        self.enterContext(mock.patch.object(containers, "override", return_value={}))
        self.enterContext(mock.patch.object(containers, "configured_signatures", return_value=[]))
        self.enterContext(mock.patch.object(containers, "configured_group_rules", return_value=[]))

    def _list(self, answer):
        with mock.patch.object(containers, "sh", return_value=answer):
            return containers.discover_containers(force=True)

    def test_a_successful_listing_answers_engine_up(self):
        items, up = self._list((0, PS_OUT, ""))
        self.assertTrue(up)
        self.assertEqual(len(items), 1)
        self.assertIs(docker_cli.engine_up(), True)
        self.assertEqual(self.probes, [])

    def test_the_memo_still_ages_out(self):
        self._list((0, PS_OUT, ""))
        with mock.patch.object(docker_cli, "_ENGINE_TTL", 0.0):
            self.assertIs(docker_cli.engine_up(), False)
        self.assertEqual(len(self.probes), 1)

    def test_force_still_probes(self):
        self._list((0, PS_OUT, ""))
        self.assertIs(docker_cli.engine_up(force=True), False)
        self.assertEqual(len(self.probes), 1)

    def test_a_failed_listing_records_nothing(self):
        for answer in ((1, "", "Cannot connect to the Docker daemon"), (-1, "", "timeout")):
            with self.subTest(answer=answer):
                docker_cli.invalidate_engine_state()
                containers.invalidate_containers()
                self.probes.clear()
                self._list(answer)
                self.assertIs(docker_cli.engine_up(), False)
                self.assertEqual(len(self.probes), 1)

    def test_a_running_probe_is_not_waited_for(self):
        with docker_cli._engine_lock:
            done = threading.Event()
            worker = threading.Thread(target=lambda: (docker_cli.note_engine_up(), done.set()))
            worker.start()
            self.assertTrue(done.wait(2), "note_engine_up waited for the probe lock")
            worker.join()
        self.assertIsNone(docker_cli._engine_cache.get("v"))


if __name__ == "__main__":
    unittest.main()
