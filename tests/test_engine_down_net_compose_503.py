"""Engine-down docker CLI failures in network/compose/vms map to coded 503.

Continues the sweep from test_engine_down_list_503 / test_engine_down_inspect_503
across the remaining docker CLI wrappers:

* POST /api/system/network/docker/connect     (``docker_network_connect``)
* POST /api/system/network/docker/disconnect  (``docker_network_disconnect``)
* PUT  /api/compose/{id} / POST /api/compose  (``save_compose`` / ``create_stack``)
* POST /api/compose/validate                  (``validate_compose_text``)

A stopped container engine is an ordinary state the panel models everywhere,
so a docker command that fails *because* the engine is off must map to
``container.engine_down`` (503) -- never to a raw untranslated daemon message,
and never to ``compose.invalid`` (400), which told the operator their YAML was
broken when it was the daemon socket that was gone.

Same subtlety as the earlier sweeps: the ``engine_up`` memo has a 5s TTL, so
the failure paths force a fresh probe (``engine_up(force=True)``); healthy
paths keep the cheap memoised answer and never probe at all.

The vms_svc sweep result is pinned rather than changed: it spawns no docker
CLI, and a hypervisor CLI that is down/broken already degrades to an empty
listing or an ``ok: false`` payload -- these tests keep it that way.
"""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import compose_svc, docker_cli, network_svc, vms_svc

#: What the docker CLI prints on stderr when the daemon socket is gone.
ENGINE_DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?"
)
FAIL = (1, "", ENGINE_DOWN_ERR)

#: A compose body that passes the client-side YAML gate.
VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class DockerNetworkMutationEngineDownTests(unittest.TestCase):
    """connect/disconnect: 503 down, ok:false with the message otherwise."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def _entry_points(self):
        return [
            ("connect",
             lambda: network_svc.docker_network_connect("mynet", "web-1")),
            ("disconnect",
             lambda: network_svc.docker_network_disconnect("mynet", "web-1")),
        ]

    def test_engine_down_failures_map_to_coded_503(self):
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                with (
                    mock.patch.object(network_svc, "docker", return_value=FAIL),
                    mock.patch.object(
                        network_svc, "engine_up", return_value=False,
                    ),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_up_failures_keep_the_ok_false_contract(self):
        """Engine answered and said no: the raw message is then trustworthy."""
        err = "Error response from daemon: No such container: web-1"
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                probe = mock.Mock(return_value=True)
                with (
                    mock.patch.object(
                        network_svc, "docker", return_value=(1, "", err),
                    ),
                    mock.patch.object(network_svc, "engine_up", probe),
                ):
                    result = call()
                self.assertEqual(result["ok"], False)
                self.assertEqual(result["message"], err)
                # The classification must not trust the 5s memoised answer.
                probe.assert_called_once_with(force=True)

    def test_the_healthy_path_never_probes_the_engine(self):
        """Success keeps the wrappers probe-free -- no docker info spawned."""
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                probe = mock.Mock(return_value=True)
                with (
                    mock.patch.object(
                        network_svc, "docker", return_value=(0, "done", ""),
                    ),
                    mock.patch.object(network_svc, "engine_up", probe),
                ):
                    result = call()
                self.assertEqual(result["ok"], True)
                probe.assert_not_called()

    def test_a_stale_cached_up_does_not_leak_the_raw_daemon_error(self):
        """Engine dies inside the probe TTL: the very next mutation is 503.

        Only the docker *transports* are stubbed here -- ``engine_up`` itself
        runs for real against the stubbed CLI.
        """
        docker_cli._engine_cache.update(t=time.time(), v=True)  # stale "up"
        with (
            mock.patch.object(docker_cli, "docker", return_value=FAIL),
            mock.patch.object(network_svc, "docker", return_value=FAIL),
        ):
            for kind, call in self._entry_points():
                with self.subTest(kind=kind):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                    self.assertEqual(ctx.exception.status_code, 503)
                    self.assertEqual(
                        _detail(ctx)["code"], "container.engine_down",
                    )


class ComposeValidateEngineDownTests(unittest.TestCase):
    """validate_compose_text classifies daemon-unreachable CLI failures."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _validate(self, rc_text: tuple, engine):
        with (
            mock.patch.object(compose_svc, "run_capped", return_value=rc_text),
            mock.patch.object(compose_svc, "engine_up", engine),
        ):
            return compose_svc.validate_compose_text(
                VALID_COMPOSE, cwd=self.tmp.name,
            )

    def test_engine_down_cli_failure_is_the_coded_soft_fail(self):
        probe = mock.Mock(return_value=False)
        v = self._validate((1, ENGINE_DOWN_ERR), probe)
        self.assertEqual(v["ok"], False)
        self.assertEqual(v["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)

    def test_a_daemon_looking_message_with_the_engine_up_keeps_the_text(self):
        """The engine answered a fresh probe: the message is not engine-down."""
        v = self._validate((1, ENGINE_DOWN_ERR), mock.Mock(return_value=True))
        self.assertEqual(v["ok"], False)
        self.assertNotIn("code", v)
        self.assertIn("Cannot connect", v["message"])

    def test_a_genuine_yaml_error_with_the_engine_off_stays_the_yaml_error(self):
        """``docker compose config`` is client-side: a real syntax error must
        surface even while the engine happens to be stopped, and the healthy
        classification must not spawn a probe for it."""
        probe = mock.Mock(return_value=False)
        v = self._validate((1, "services.web.ports must be a list"), probe)
        self.assertEqual(v["ok"], False)
        self.assertNotIn("code", v)
        self.assertIn("must be a list", v["message"])
        probe.assert_not_called()

    def test_a_valid_compose_never_probes_the_engine(self):
        probe = mock.Mock(return_value=True)
        v = self._validate((0, ""), probe)
        self.assertEqual(v["ok"], True)
        probe.assert_not_called()


class ComposeWriteEngineDownTests(unittest.TestCase):
    """save_compose / create_stack: 503 down, coded 400 for real YAML faults."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "Services" / "web"
        self.root.mkdir(parents=True)
        self.compose = self.root / "docker-compose.yml"
        self.compose.write_text("services: {}\n", encoding="utf-8")
        self.stack = {
            "id": "web",
            "name": "web",
            "path": str(self.root),
            "compose_path": str(self.compose),
        }

    def _save(self, rc_text: tuple, engine):
        with (
            mock.patch.object(
                compose_svc, "_stack_paths", return_value=[self.stack],
            ),
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
            mock.patch.object(compose_svc, "run_capped", return_value=rc_text),
            mock.patch.object(compose_svc, "engine_up", engine),
        ):
            return compose_svc.save_compose("web", VALID_COMPOSE, validate=True)

    def test_engine_down_save_is_a_coded_503_and_writes_nothing(self):
        with self.assertRaises(HTTPException) as ctx:
            self._save((1, ENGINE_DOWN_ERR), mock.Mock(return_value=False))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")
        # The refused save must not have touched the compose on disk.
        self.assertEqual(
            self.compose.read_text(encoding="utf-8"), "services: {}\n",
        )

    def test_a_real_validation_fault_stays_the_coded_400(self):
        with self.assertRaises(HTTPException) as ctx:
            self._save(
                (1, "services.web.ports must be a list"),
                mock.Mock(return_value=True),
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "compose.invalid")

    def test_engine_down_create_stack_is_a_coded_503_and_creates_nothing(self):
        with (
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
            mock.patch.object(
                compose_svc, "run_capped", return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(
                compose_svc, "engine_up", mock.Mock(return_value=False),
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.create_stack("newstack", None, VALID_COMPOSE)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")
        self.assertFalse((self.home / "Services" / "newstack").exists())


class VmsEngineDownSweepPins(unittest.TestCase):
    """vms_svc spawns no docker CLI; a down hypervisor degrades, never 404/500."""

    def setUp(self):
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def test_orb_listing_degrades_to_empty_when_orbctl_fails(self):
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(
                vms_svc, "sh",
                return_value=(1, "", "OrbStack is not running"),
            ),
        ):
            self.assertEqual(vms_svc.list_orb_machines(force=True), [])

    def test_orb_action_failure_is_ok_false_with_the_message(self):
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(
                vms_svc, "sh",
                return_value=(1, "", "OrbStack is not running"),
            ),
        ):
            result = vms_svc.vm_action("orb:web", "start")
        self.assertEqual(result["ok"], False)
        self.assertIn("not running", result["message"])

    def test_utm_action_failure_is_ok_false_with_the_message(self):
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(
                vms_svc, "sh",
                return_value=(1, "", "UTM is not running"),
            ),
        ):
            result = vms_svc.vm_action(
                "123e4567-e89b-12d3-a456-426614174000", "start",
            )
        self.assertEqual(result["ok"], False)
        self.assertIn("not running", result["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
