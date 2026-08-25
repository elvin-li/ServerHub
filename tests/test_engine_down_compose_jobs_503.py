"""Engine-down compose up/down/logs and stack-job failures carry the code.

Continues the sweep from test_engine_down_list_503 / test_engine_down_inspect_503
/ test_engine_down_net_compose_503 across the remaining compose command paths:

* POST /api/apps/managed/action  docker start/stop/restart/update
  (``apps_manage_svc._compose_cmd`` — compose up/stop/restart/pull)
* GET  /api/apps/managed/logs    docker kind (``_docker_logs`` — compose logs)
* POST /api/stacks/{id}/run      (``start_stack_job`` — compose up/down/pull)
* POST /api/containers/{n}/update mid-job (``start_update_container_job``)
* POST /api/catalog/{id}/install   (``install_template`` — compose up)
* POST /api/catalog/{id}/uninstall (``uninstall_template`` — compose down)

A stopped container engine is an ordinary state the panel models everywhere,
so a compose command that fails *because* the engine is off must surface
``container.engine_down`` — never only the raw untranslated daemon stderr, and
never a fake success (the uninstall path used to rmtree the stack directory
after a failed ``down`` and report ok because the compose file was gone).

Same subtleties as the earlier sweeps, pinned again here:

* the ``engine_up`` memo has a 5s TTL, so every classification forces a fresh
  probe (``engine_up(force=True)``);
* healthy paths never probe at all;
* output that merely *looks* engine-down while the engine answers "up" keeps
  its original failure mapping — the daemon's message is then the truth.
"""
from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import apps_manage_svc, catalog, containers_svc, docker_cli

#: What the docker CLI prints on stderr when the daemon socket is gone.
ENGINE_DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?"
)


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class _SyncThread:
    """threading.Thread stand-in that runs the job body on start().

    The job runners are exercised end to end (register → run → finish)
    without a real thread, so assertions never race the worker.
    """

    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        if self._target is not None:
            self._target()


class AppsComposeCommandEngineDownTests(unittest.TestCase):
    """_compose_cmd (Apps up/stop/restart/pull/logs): coded soft-fail down."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.services = root / "Services"
        (self.services / "mystack").mkdir(parents=True)
        self.compose = self.services / "mystack" / "docker-compose.yml"
        self.compose.write_text("services:\n  web:\n    image: nginx:alpine\n")
        self.docker_bin = root / "docker"
        self.docker_bin.write_text("#!/bin/sh\nexit 0\n")
        self.docker_bin.chmod(0o755)
        patches = [
            mock.patch.object(apps_manage_svc, "SERVICES_ROOT", self.services),
            mock.patch.object(apps_manage_svc, "DOCKER", str(self.docker_bin)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _entry_points(self):
        return [
            ("start", lambda: apps_manage_svc.action("docker:mystack", "start")),
            ("stop", lambda: apps_manage_svc.action("docker:mystack", "stop")),
            ("restart", lambda: apps_manage_svc.action("docker:mystack", "restart")),
            ("update", lambda: apps_manage_svc.action("docker:mystack", "update")),
        ]

    def test_engine_down_compose_actions_carry_the_code(self):
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                with (
                    mock.patch.object(
                        apps_manage_svc, "run_capped",
                        return_value=(1, ENGINE_DOWN_ERR),
                    ),
                    mock.patch.object(
                        apps_manage_svc, "engine_up", return_value=False,
                    ),
                ):
                    result = call()
                self.assertEqual(result["ok"], False)
                self.assertEqual(result["code"], "container.engine_down")

    def test_engine_up_failures_keep_the_raw_message(self):
        """Engine answered and said no: the daemon's message is the truth."""
        err = 'Error response from daemon: pull access denied for "x"'
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped", return_value=(1, err),
            ),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            result = apps_manage_svc.action("docker:mystack", "start")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["message"], err)
        self.assertNotIn("code", result)
        # A daemon-error message does not even look engine-down, so the
        # classifier declines before spawning any probe.
        probe.assert_not_called()

    def test_engine_down_looking_output_with_a_live_engine_stays_raw(self):
        """The message-pattern gate alone must not classify; the probe rules."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped",
                return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            result = apps_manage_svc.action("docker:mystack", "stop")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["message"], ENGINE_DOWN_ERR)
        self.assertNotIn("code", result)
        # The classification must not trust the 5s memoised answer.
        probe.assert_called_once_with(force=True)

    def test_the_healthy_path_never_probes_the_engine(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped", return_value=(0, "Started"),
            ),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            result = apps_manage_svc.action("docker:mystack", "start")
        self.assertEqual(result["ok"], True)
        probe.assert_not_called()

    def test_compose_logs_carry_the_code_when_the_engine_is_down(self):
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped",
                return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(apps_manage_svc, "engine_up", return_value=False),
        ):
            result = apps_manage_svc.logs("docker:mystack")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["code"], "container.engine_down")

    def test_compose_logs_stay_raw_while_the_engine_is_up(self):
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped", return_value=(0, "web-1 | ready"),
            ),
            mock.patch.object(apps_manage_svc, "engine_up", return_value=True),
        ):
            result = apps_manage_svc.logs("docker:mystack")
        self.assertEqual(result["ok"], True)
        self.assertNotIn("code", result)
        self.assertIn("ready", result["log"])


class _JobSandbox(unittest.TestCase):
    """Shared plumbing: synchronous job threads and an isolated job store."""

    STACK = {
        "id": "media",
        "name": "media",
        "path": "/tmp/media",
        "compose_file": "docker-compose.yml",
        "compose_path": "/tmp/media/docker-compose.yml",
        "containers": [],
        "source": "config",
    }

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore_jobs)
        patches = [
            mock.patch.object(
                containers_svc, "threading",
                types.SimpleNamespace(Thread=_SyncThread),
            ),
            mock.patch.object(containers_svc, "maintenance_env", lambda: {}),
            mock.patch.object(containers_svc, "invalidate_status", lambda: None),
            mock.patch.object(
                containers_svc, "_stack_paths", lambda: [dict(self.STACK)],
            ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _restore_jobs(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    @staticmethod
    def _failing_stream(text: str, rc: int = 1):
        def stream(cmd, j, **kwargs):
            j["log"].append(text)
            return rc

        return stream


class StackJobEngineDownTests(_JobSandbox):
    """start_stack_job: a failed compose job is stamped with the code."""

    def test_engine_down_job_failures_carry_the_code(self):
        for action in ("up", "down", "pull", "update"):
            with self.subTest(action=action):
                containers_svc._cjobs.clear()
                with (
                    mock.patch.object(
                        containers_svc, "_stream_job_command",
                        side_effect=self._failing_stream(ENGINE_DOWN_ERR),
                    ),
                    mock.patch.object(
                        containers_svc, "engine_up", return_value=False,
                    ),
                ):
                    r = containers_svc.start_stack_job("media", action)
                job = containers_svc.stack_job_log(r["job_id"])
                self.assertEqual(job["running"], False)
                self.assertNotEqual(job["rc"], 0)
                self.assertEqual(job["code"], "container.engine_down")
                self.assertIn("container.engine_down", job["log"])

    def test_the_classification_forces_a_fresh_probe(self):
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(
                containers_svc, "_stream_job_command",
                side_effect=self._failing_stream(ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            containers_svc.start_stack_job("media", "up")
        probe.assert_called_once_with(force=True)

    def test_engine_up_job_failures_keep_the_raw_log_and_no_code(self):
        """Engine answered and said no: the log already tells the truth."""
        err = "Error response from daemon: No such image: example/x"
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "_stream_job_command",
                side_effect=self._failing_stream(err),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            r = containers_svc.start_stack_job("media", "up")
        job = containers_svc.stack_job_log(r["job_id"])
        self.assertIsNone(job["code"])
        self.assertIn(err, job["log"])
        # A daemon-error log does not look engine-down: no probe spawned.
        probe.assert_not_called()

    def test_engine_down_looking_log_with_a_live_engine_gets_no_code(self):
        """A container may echo these strings; the forced probe rules."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "_stream_job_command",
                side_effect=self._failing_stream(ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            r = containers_svc.start_stack_job("media", "up")
        job = containers_svc.stack_job_log(r["job_id"])
        self.assertIsNone(job["code"])
        probe.assert_called_once_with(force=True)

    def test_successful_jobs_never_probe_and_carry_no_code(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "_stream_job_command", return_value=0,
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            r = containers_svc.start_stack_job("media", "up")
        job = containers_svc.stack_job_log(r["job_id"])
        self.assertEqual(job["rc"], 0)
        self.assertIsNone(job["code"])
        probe.assert_not_called()

    def test_job_public_surfaces_the_code(self):
        with (
            mock.patch.object(
                containers_svc, "_stream_job_command",
                side_effect=self._failing_stream(ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", return_value=False),
        ):
            containers_svc.start_stack_job("media", "up")
        jobs = containers_svc.latest_stack_jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["code"], "container.engine_down")


class UpdateContainerJobEngineDownTests(_JobSandbox):
    """The engine dying mid-update-job is classified too, not only at entry."""

    INSPECT = (
        '[{"Id": "abc123", "Name": "/web-1", "Config": {"Image": "nginx", '
        '"Labels": {"com.docker.compose.project": "media", '
        '"com.docker.compose.project.working_dir": "/tmp/media", '
        '"com.docker.compose.project.config_files": '
        '"/tmp/media/docker-compose.yml", '
        '"com.docker.compose.service": "web"}}}]'
    )

    def test_engine_dying_after_the_entry_inspect_stamps_the_job(self):
        """Inspect succeeded (engine was up); compose then hit a dead socket."""
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(0, self.INSPECT, ""),
            ),
            mock.patch.object(
                containers_svc, "_stream_job_command",
                side_effect=self._failing_stream(ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", return_value=False),
            mock.patch.object(containers_svc, "_save_update_status", lambda s: None),
            mock.patch.object(containers_svc, "_load_update_status", dict),
        ):
            r = containers_svc.start_update_container_job("web-1")
        job = containers_svc.stack_job_log(r["job_id"])
        self.assertEqual(job["code"], "container.engine_down")
        self.assertNotEqual(job["rc"], 0)

    def test_a_plain_mid_job_failure_gets_no_code(self):
        err = "Error response from daemon: manifest unknown"
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(0, self.INSPECT, ""),
            ),
            mock.patch.object(
                containers_svc, "_stream_job_command",
                side_effect=self._failing_stream(err),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
            mock.patch.object(containers_svc, "_save_update_status", lambda s: None),
            mock.patch.object(containers_svc, "_load_update_status", dict),
        ):
            r = containers_svc.start_update_container_job("web-1")
        job = containers_svc.stack_job_log(r["job_id"])
        self.assertIsNone(job["code"])
        probe.assert_not_called()


TEMPLATE = """---
name: Engine Down Fixture
desc: fixture
category: other
ports: ["59732"]
vars: []
---
services:
  fixture:
    image: example/fixture:latest
    container_name: engine-down-fixture
    ports:
      - "59732:80"
"""


class _CatalogSandbox(unittest.TestCase):
    """Temp SERVICES_ROOT + fake docker, same shape as test_catalog_rollback."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.services = tmp / "Services"
        self.services.mkdir()
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.tid = "engine-down-fixture"
        (self.templates / f"{self.tid}.yml").write_text(TEMPLATE)
        self.docker = tmp / "docker"
        self.docker.write_text("#!/bin/sh\nexit 0\n")
        self.docker.chmod(0o755)
        self.registered: list[dict] = []
        patches = [
            mock.patch.object(catalog, "SERVICES_ROOT", self.services),
            mock.patch.object(catalog, "TEMPLATES", self.templates),
            mock.patch.object(catalog, "DOCKER", str(self.docker)),
            mock.patch.object(
                catalog, "_register_stack",
                lambda tid, name, dest: self.registered.append(
                    {"id": tid, "name": name, "path": str(dest)}
                ),
            ),
            mock.patch.object(
                catalog, "_unregister_stack",
                lambda tid, dest=None: self.registered.clear(),
            ),
            mock.patch.object(catalog, "_port_is_bound", lambda port: False),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    @property
    def dest_dir(self) -> Path:
        return self.services / self.tid


class CatalogInstallEngineDownTests(_CatalogSandbox):
    """install_template: engine off is the missing-CLI shape, not a rollback."""

    def test_engine_down_keeps_the_files_and_registration(self):
        with (
            mock.patch.object(
                catalog, "run_capped", return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(catalog, "engine_up", return_value=False),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["code"], "container.engine_down")
        self.assertTrue(
            (self.dest_dir / "docker-compose.yml").exists(),
            "an engine that is off must not cost the written compose file",
        )
        self.assertEqual(len(self.registered), 1)
        self.assertEqual(r["stack_id"], self.tid)

    def test_engine_down_looking_output_with_a_live_engine_still_rolls_back(self):
        """The forced probe rules: engine up means the failure was real."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                catalog, "run_capped", return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertNotIn("code", r)
        self.assertFalse(self.dest_dir.exists(), "real failures keep rolling back")
        self.assertEqual(self.registered, [])
        probe.assert_called_once_with(force=True)

    def test_plain_failures_keep_the_transactional_rollback(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                catalog, "run_capped",
                return_value=(1, "Error: port is already allocated"),
            ),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertFalse(self.dest_dir.exists())
        self.assertEqual(self.registered, [])
        probe.assert_not_called()


class CatalogUninstallEngineDownTests(_CatalogSandbox):
    """uninstall_template: a down that did nothing must not delete the data."""

    def setUp(self):
        super().setUp()
        self.dest_dir.mkdir()
        (self.dest_dir / "docker-compose.yml").write_text(
            "services:\n  fixture:\n    image: example/fixture:latest\n"
        )
        self.registered.append({"id": self.tid})

    def test_engine_down_refuses_with_the_coded_503(self):
        with (
            mock.patch.object(
                catalog, "run_capped", return_value=(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(catalog, "engine_up", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                catalog.uninstall_template(
                    self.tid, remove_data=True, confirm=True,
                )
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")
        self.assertTrue(
            (self.dest_dir / "docker-compose.yml").exists(),
            "a refused uninstall must not have deleted the stack directory",
        )
        self.assertEqual(len(self.registered), 1, "stack must stay registered")

    def test_engine_up_down_failures_keep_the_existing_contract(self):
        """Engine answered and the down still failed: proceed as before."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                catalog, "run_capped",
                return_value=(1, "Error response from daemon: conflict"),
            ),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.uninstall_template(self.tid, remove_data=True, confirm=True)
        self.assertIn("ok", r)
        self.assertFalse(self.dest_dir.exists(), "remove_data still removes files")
        probe.assert_not_called()

    def test_a_healthy_uninstall_never_probes(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(catalog, "run_capped", return_value=(0, "Removed")),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.uninstall_template(self.tid, remove_data=True, confirm=True)
        self.assertTrue(r["ok"])
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
