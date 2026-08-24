"""Engine-down list reads are a coded 503, never an uncaught 500.

A stopped container engine is an ordinary state the panel models everywhere
(``engine_up`` on /api/status, the Containers page renders "engine is down"),
so an inventory read that fails *because* the engine is off must map to
``container.engine_down`` (503) via ``_raise_list_failure`` -- not to
``container.list_failed`` (500), and never to an uncaught exception.

The subtle case is the probe cache: ``engine_up`` memoises its answer for 5s,
so for the first seconds after the engine stops the cache still said "up" and
the failed read was misreported as a panel fault (500).  The failure path now
forces a fresh probe, which these tests pin.

The rest of the file sweeps every other engine-adjacent list endpoint --
containers, compose stacks, docker df/sizes, docker networks/ports, engine
info, VMs (UTM/OrbStack), brew services -- and pins that an engine or CLI
that is down/broken degrades to an empty/flagged payload instead of raising.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import (
    brew_svc,
    containers_svc,
    docker_cli,
    docker_info_svc,
    network_svc,
    tools_svc,
    vms_svc,
)

#: What the docker CLI prints on stderr when the daemon socket is gone.
ENGINE_DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?"
)


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class InventoryListEngineDownTests(unittest.TestCase):
    """list_images / list_volumes / list_networks: 503 down, 500 otherwise."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def _failing_calls(self):
        """Each inventory read, with its docker transport failing."""
        fail = (1, "", ENGINE_DOWN_ERR)
        return [
            ("images", containers_svc.list_images,
             mock.patch.object(containers_svc, "docker_json",
                               return_value=(None, 1, ENGINE_DOWN_ERR))),
            ("volumes", containers_svc.list_volumes,
             mock.patch.object(containers_svc, "docker", return_value=fail)),
            ("networks", containers_svc.list_networks,
             mock.patch.object(containers_svc, "docker", return_value=fail)),
        ]

    def test_engine_down_maps_every_inventory_read_to_coded_503(self):
        for kind, read, transport in self._failing_calls():
            with self.subTest(kind=kind):
                with transport, mock.patch.object(
                    containers_svc, "engine_up", return_value=False,
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        read()
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_up_failures_stay_coded_500_with_the_kind(self):
        """A failure that is NOT the engine being off is still a panel fault."""
        for kind, read, transport in self._failing_calls():
            with self.subTest(kind=kind):
                with transport, mock.patch.object(
                    containers_svc, "engine_up", return_value=True,
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        read()
                self.assertEqual(ctx.exception.status_code, 500)
                detail = _detail(ctx)
                self.assertEqual(detail["code"], "container.list_failed")
                self.assertEqual(detail.get("params", {}).get("kind"), kind)

    def test_the_failure_path_forces_a_fresh_engine_probe(self):
        """The classification must not trust the 5s memoised answer."""
        probe = mock.Mock(return_value=False)
        with mock.patch.object(containers_svc, "engine_up", probe):
            with self.assertRaises(HTTPException):
                containers_svc._raise_list_failure("volumes")
        probe.assert_called_once_with(force=True)

    def test_a_stale_cached_up_does_not_turn_engine_down_into_a_500(self):
        """Engine dies inside the probe TTL: the very next list read is 503.

        The memo still holds "up" from before the engine stopped.  Without a
        forced re-probe, ``_raise_list_failure`` read that stale answer and
        reported ``container.list_failed`` (500) for what is a dependency
        that is off.  Only the docker *transports* are stubbed here --
        ``engine_up`` itself runs for real against the stubbed CLI.
        """
        docker_cli._engine_cache.update(t=time.time(), v=True)  # stale "up"
        fail = (1, "", ENGINE_DOWN_ERR)
        with (
            mock.patch.object(docker_cli, "docker", return_value=fail),
            mock.patch.object(containers_svc, "docker", return_value=fail),
            mock.patch.object(containers_svc, "docker_json",
                              return_value=(None, 1, ENGINE_DOWN_ERR)),
        ):
            for read in (
                containers_svc.list_images,
                containers_svc.list_volumes,
                containers_svc.list_networks,
            ):
                with self.subTest(read=read.__name__):
                    with self.assertRaises(HTTPException) as ctx:
                        read()
                    self.assertEqual(ctx.exception.status_code, 503)
                    self.assertEqual(
                        _detail(ctx)["code"], "container.engine_down",
                    )


class EngineDownListSweepTests(unittest.TestCase):
    """Every other engine-adjacent list read degrades, it does not raise."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        containers_svc.invalidate_container_lists()
        self.addCleanup(containers_svc.invalidate_container_lists)
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def test_container_list_reports_engine_down_instead_of_raising(self):
        with mock.patch.object(containers_svc, "engine_up", return_value=False):
            payload = containers_svc.list_containers()
        self.assertEqual(payload["engine_up"], False)
        self.assertEqual(payload["containers"], [])
        self.assertEqual(payload["stats"], {})
        self.assertEqual(payload["projects"], [])

    def test_compose_stack_list_survives_the_engine_being_down(self):
        """Stacks come from config + ~/Services scan; engine off means the
        running_containers overlay is simply empty, never a 500."""
        with (
            mock.patch.object(containers_svc, "engine_up", return_value=False),
            mock.patch.object(containers_svc, "cfg", return_value={
                "stacks": [{"id": "web", "name": "web",
                            "containers": ["web-1"]}],
            }),
            mock.patch.object(containers_svc, "user_home", return_value=None),
        ):
            stacks = containers_svc.list_stacks()
        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0]["id"], "web")
        self.assertEqual(stacks[0]["running_containers"], [])
        self.assertEqual(stacks[0]["status"], "idle")

    def test_docker_disk_usage_flags_the_engine_instead_of_raising(self):
        with mock.patch.object(tools_svc, "engine_up", return_value=False):
            payload = tools_svc.docker_disk_usage()
        self.assertEqual(
            payload, {"engine_up": False, "raw": "", "lines": []},
        )

    def test_container_sizes_are_empty_when_the_engine_is_down(self):
        with mock.patch.object(tools_svc, "engine_up", return_value=False):
            self.assertEqual(tools_svc.container_sizes(), [])

    def test_docker_ports_and_networks_are_empty_when_the_engine_is_down(self):
        with mock.patch.object(network_svc, "engine_up", return_value=False):
            self.assertEqual(network_svc.docker_published_ports(), [])
            self.assertEqual(network_svc.docker_networks_detail(), [])

    def test_docker_ports_and_networks_tolerate_a_failed_cli_too(self):
        """Engine says up, but the list command itself fails (racing stop)."""
        fail = (1, "", ENGINE_DOWN_ERR)
        with (
            mock.patch.object(network_svc, "engine_up", return_value=True),
            mock.patch.object(network_svc, "docker", return_value=fail),
        ):
            self.assertEqual(network_svc.docker_published_ports(), [])
            self.assertEqual(network_svc.docker_networks_detail(), [])

    def test_engine_info_reports_down_instead_of_raising(self):
        with mock.patch.object(docker_info_svc, "engine_up", return_value=False):
            payload = docker_info_svc.engine_info()
        self.assertEqual(payload["engine_up"], False)
        self.assertIn("message", payload)

    def test_vm_list_survives_both_hypervisor_listings_blowing_up(self):
        """utmctl/orbctl gone or broken: /api/vms lists zero VMs, not a 500."""
        boom = RuntimeError("hypervisor CLI is gone")
        with (
            mock.patch.object(vms_svc, "list_utm_vms", side_effect=boom),
            mock.patch.object(vms_svc, "list_orb_machines", side_effect=boom),
        ):
            payload = vms_svc.list_all_vms()
        self.assertEqual(payload["vms"], [])
        self.assertEqual(payload["utm_count"], 0)
        self.assertEqual(payload["orb_count"], 0)

    def test_brew_service_list_survives_a_broken_brew(self):
        """brew present but wedged: both the JSON snapshot and the text
        fallback raising must yield an empty list, not a 500."""
        boom = RuntimeError("brew is wedged")
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", side_effect=boom),
            mock.patch.object(brew_svc, "sh", side_effect=boom),
        ):
            self.assertEqual(brew_svc.list_services(), [])

    def test_brew_service_list_is_empty_when_brew_is_not_installed(self):
        with mock.patch.object(brew_svc, "_brew_present", return_value=False):
            self.assertEqual(brew_svc.list_services(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
