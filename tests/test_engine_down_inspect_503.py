"""Engine-down per-container inspects are a coded 503, never a fake 404.

A stopped container engine is an ordinary state the panel models everywhere
(``engine_up`` on /api/status, the Containers page renders "engine is down"),
so a ``docker inspect`` that fails *because* the engine is off must map to
``container.engine_down`` (503) — not to ``container.not_found`` (404), which
told the operator a container that exists had vanished and pointed away from
the real remedy (start the engine).

Three request paths inspected a container and mapped any non-zero exit to a
missing-resource 404:

* GET  /api/containers/{name}/inspect  (``inspect_container``)
* POST /api/containers/{name}/update   (``start_update_container_job``)
* PUT  /api/system/network/docker/ports (``docker_update_ports``)

Same subtlety as the inventory-list sweep (test_engine_down_list_503): the
``engine_up`` memo has a 5s TTL, so for the first seconds after the engine
stops a cached "up" would misreport the failure.  The failure paths force a
fresh probe, which these tests pin.  A failure while the engine really is up
stays the coded 404 — that answer is then trustworthy.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import containers_svc, docker_cli, network_svc

#: What the docker CLI prints on stderr when the daemon socket is gone.
ENGINE_DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?"
)
FAIL = (1, "", ENGINE_DOWN_ERR)


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class ContainerInspectEngineDownTests(unittest.TestCase):
    """inspect_container / start_update_container_job: 503 down, 404 up."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def _entry_points(self):
        return [
            ("inspect", lambda: containers_svc.inspect_container("web-1")),
            ("update", lambda: containers_svc.start_update_container_job("web-1")),
        ]

    def test_engine_down_inspect_failures_map_to_coded_503(self):
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                with (
                    mock.patch.object(containers_svc, "docker", return_value=FAIL),
                    mock.patch.object(
                        containers_svc, "engine_up", return_value=False,
                    ),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_up_inspect_failures_stay_the_coded_404(self):
        """Engine answered and said no such container: 404 is the truth."""
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                with (
                    mock.patch.object(
                        containers_svc, "docker",
                        return_value=(1, "", "Error: No such object: web-1"),
                    ),
                    mock.patch.object(
                        containers_svc, "engine_up", return_value=True,
                    ),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                self.assertEqual(ctx.exception.status_code, 404)
                self.assertEqual(_detail(ctx)["code"], "container.not_found")

    def test_the_failure_path_forces_a_fresh_engine_probe(self):
        """The classification must not trust the 5s memoised answer."""
        probe = mock.Mock(return_value=False)
        with mock.patch.object(containers_svc, "engine_up", probe):
            with self.assertRaises(HTTPException):
                containers_svc._raise_inspect_failure()
        probe.assert_called_once_with(force=True)

    def test_a_stale_cached_up_does_not_turn_engine_down_into_a_404(self):
        """Engine dies inside the probe TTL: the very next inspect is 503.

        The memo still holds "up" from before the engine stopped.  Without a
        forced re-probe both entry points read that stale answer and reported
        ``container.not_found`` for a dependency that is off.  Only the docker
        *transports* are stubbed here — ``engine_up`` itself runs for real
        against the stubbed CLI.
        """
        docker_cli._engine_cache.update(t=time.time(), v=True)  # stale "up"
        with (
            mock.patch.object(docker_cli, "docker", return_value=FAIL),
            mock.patch.object(containers_svc, "docker", return_value=FAIL),
        ):
            for kind, call in self._entry_points():
                with self.subTest(kind=kind):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                    self.assertEqual(ctx.exception.status_code, 503)
                    self.assertEqual(
                        _detail(ctx)["code"], "container.engine_down",
                    )

    def test_a_torn_payload_with_a_clean_exit_stays_not_found(self):
        """rc == 0 answered by the engine: an unusable body is not engine-down."""
        with mock.patch.object(
            containers_svc, "docker", return_value=(0, "[not json", ""),
        ):
            with self.assertRaises(HTTPException) as ctx:
                containers_svc.inspect_container("web-1")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(_detail(ctx)["code"], "container.not_found")


class DockerUpdatePortsEngineDownTests(unittest.TestCase):
    """docker_update_ports gates on the memo, so its failure re-probes."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def test_engine_dying_inside_the_ttl_is_a_coded_503(self):
        """The upfront memoised gate said up; the inspect then failed."""

        def probe(force: bool = False) -> bool:
            return not force  # memo says up, the forced re-probe says down

        with (
            mock.patch.object(network_svc, "engine_up", side_effect=probe),
            mock.patch.object(network_svc, "docker", return_value=FAIL),
        ):
            with self.assertRaises(HTTPException) as ctx:
                network_svc.docker_update_ports("web-1", ["8080:80"])
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_up_inspect_failures_stay_the_coded_404(self):
        with (
            mock.patch.object(network_svc, "engine_up", return_value=True),
            mock.patch.object(
                network_svc, "docker",
                return_value=(1, "", "Error: No such object: web-1"),
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                network_svc.docker_update_ports("web-1", ["8080:80"])
        self.assertEqual(ctx.exception.status_code, 404)
        detail = _detail(ctx)
        self.assertEqual(detail["code"], "network.container_not_found")
        self.assertEqual(detail.get("params", {}).get("name"), "web-1")

    def test_engine_down_upfront_is_still_the_coded_503(self):
        """The pre-existing gate keeps rejecting before any docker call."""
        with mock.patch.object(network_svc, "engine_up", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                network_svc.docker_update_ports("web-1", ["8080:80"])
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")


if __name__ == "__main__":
    unittest.main(verbosity=2)
