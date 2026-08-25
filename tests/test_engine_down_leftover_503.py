"""Engine-down leftovers: the remaining docker CLI spawn paths carry the code.

Continues the sweep from test_engine_down_list_503 / test_engine_down_inspect_503
/ test_engine_down_net_compose_503 / test_engine_down_compose_jobs_503 across
every docker CLI call site that still answered a dead daemon with the raw
untranslated stderr, an uncoded ``ok: false``, or a misleading payload:

* containers_svc mutations — action/exec/restart-policy/prune/rm/pull/rename/
  run/create (POST /api/containers/*, /api/images/*, /api/volumes/*,
  /api/networks/*, /api/prune) → coded 503, and batch rows carry the code
* tools_svc ``docker system df`` / prune (GET /api/docker/df,
  POST /api/tools/docker/prune) → engine-down shape / coded soft-fail
* services_manage_svc container logs (GET /api/services/{id}/logs) → coded 503
* terminal_svc ``docker exec`` (POST /api/terminal/run) → coded 503
* actions.run_action container branch (POST /api/action, services bulk) → 503
* backups stack job — ``compose config`` / volume export mid-job → the
  ``engine_down`` job error instead of compose_config_failed / raw stderr

Same subtleties as the earlier sweeps, pinned again here:

* the ``engine_up`` memo has a 5s TTL, so every classification forces a fresh
  probe (``engine_up(force=True)``);
* healthy paths never probe at all;
* output that merely *looks* engine-down while the engine answers "up" keeps
  its original failure mapping — the daemon's message is then the truth.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import actions, backups, containers_svc, docker_cli, services_manage_svc, terminal_svc, tools_svc

#: What the docker CLI prints on stderr when the daemon socket is gone.
ENGINE_DOWN_ERR = (
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
    "Is the docker daemon running?"
)


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class _EngineStateSandbox(unittest.TestCase):
    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)


class ContainerMutationEngineDownTests(_EngineStateSandbox):
    """Every containers_svc mutation raises the coded 503 on a dead engine."""

    def _entry_points(self):
        svc = containers_svc
        return [
            ("action", lambda: svc.container_action("web-1", "stop")),
            ("exec", lambda: svc.exec_in_container("web-1", "echo hi")),
            ("restart_policy", lambda: svc.set_restart_policy("web-1", "always")),
            ("prune", lambda: svc.prune("system")),
            ("remove_image", lambda: svc.remove_image("nginx:alpine")),
            ("remove_volume", lambda: svc.remove_volume("data-vol")),
            ("remove_network", lambda: svc.remove_network("appnet")),
            ("pull_image", lambda: svc.pull_image("nginx:alpine")),
            ("rename", lambda: svc.rename_container("web-1", "web-2")),
            ("create_volume", lambda: svc.create_volume("data-vol")),
            ("create_network", lambda: svc.create_network("appnet")),
        ]

    def test_engine_down_mutations_carry_the_code(self):
        for kind, call in self._entry_points():
            with self.subTest(kind=kind):
                with (
                    mock.patch.object(
                        containers_svc, "docker",
                        return_value=(1, "", ENGINE_DOWN_ERR),
                    ),
                    mock.patch.object(
                        containers_svc, "engine_up", return_value=False,
                    ),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        call()
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_up_failures_keep_the_raw_message(self):
        """Engine answered and said no: the daemon's message is the truth."""
        err = "Error response from daemon: No such container: web-1"
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(1, "", err),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            result = containers_svc.container_action("web-1", "stop")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["message"], err)
        # A daemon-error message does not even look engine-down, so the
        # classifier declines before spawning any probe.
        probe.assert_not_called()

    def test_engine_down_looking_output_with_a_live_engine_stays_raw(self):
        """The message-pattern gate alone must not classify; the probe rules."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "docker",
                return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            result = containers_svc.exec_in_container("web-1", "true")
        self.assertEqual(result["ok"], False)
        self.assertIn("Cannot connect", result["output"])
        # The classification must not trust the 5s memoised answer.
        probe.assert_called_once_with(force=True)

    def test_the_healthy_path_never_probes_the_engine(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                containers_svc, "docker", return_value=(0, "web-1", ""),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            result = containers_svc.container_action("web-1", "start")
        self.assertEqual(result["ok"], True)
        probe.assert_not_called()

    def test_run_container_engine_dying_inside_the_ttl_is_classified(self):
        """create_run_container gates entry on the 5s memo; the engine can die
        between that gate and the docker run."""
        probe = mock.Mock(side_effect=lambda force=False: not force)
        with (
            mock.patch.object(
                containers_svc, "docker",
                return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            with self.assertRaises(HTTPException) as ctx:
                containers_svc.create_run_container({"image": "nginx:alpine"})
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")
        probe.assert_called_with(force=True)

    def test_batch_rows_carry_the_code(self):
        with (
            mock.patch.object(
                containers_svc, "docker",
                return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(containers_svc, "engine_up", return_value=False),
        ):
            result = containers_svc.batch_action(["web-1", "db-1"], "stop")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["done"], 0)
        for row in result["results"]:
            self.assertEqual(row["ok"], False)
            self.assertEqual(row["code"], "container.engine_down")
            self.assertEqual(row["message"], "the Docker engine is not running")


class ToolsDockerEngineDownTests(_EngineStateSandbox):
    """tools_svc df/prune: coded shapes instead of raw stderr / fake engine_up."""

    def setUp(self):
        super().setUp()
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def test_df_engine_dying_inside_the_ttl_reports_engine_down(self):
        """The payload used to claim engine_up: True with raw stderr in raw."""
        probe = mock.Mock(side_effect=lambda force=False: not force)
        with (
            mock.patch.object(
                tools_svc, "docker", return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(tools_svc, "engine_up", probe),
        ):
            result = tools_svc.docker_disk_usage()
        self.assertEqual(
            result, {"engine_up": False, "raw": "", "lines": []},
        )
        probe.assert_called_with(force=True)

    def test_df_plain_failures_keep_the_raw_message(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                tools_svc, "docker",
                return_value=(1, "", "Error response from daemon: boom"),
            ),
            mock.patch.object(tools_svc, "engine_up", probe),
        ):
            result = tools_svc.docker_disk_usage()
        self.assertEqual(result["engine_up"], True)
        self.assertIn("boom", result["raw"])
        # engine_up() at entry only; no forced probe for a non-matching error.
        probe.assert_called_once_with()

    def test_prune_engine_down_is_the_coded_soft_fail(self):
        probe = mock.Mock(side_effect=lambda force=False: not force)
        with (
            mock.patch.object(
                tools_svc, "docker", return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(tools_svc, "engine_up", probe),
        ):
            result = tools_svc.docker_prune(what="dangling", confirm=True)
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["code"], "container.engine_down")
        self.assertEqual(result["what"], "dangling")
        self.assertIsNone(result["df"])
        probe.assert_called_with(force=True)

    def test_prune_engine_up_failures_keep_the_raw_message(self):
        err = "Error response from daemon: conflict"
        with (
            mock.patch.object(tools_svc, "docker", return_value=(1, "", err)),
            mock.patch.object(tools_svc, "engine_up", return_value=True),
        ):
            result = tools_svc.docker_prune(what="dangling", confirm=True)
        self.assertEqual(result["ok"], False)
        self.assertNotIn("code", result)
        self.assertEqual(result["message"], err)


class ServiceLogsEngineDownTests(_EngineStateSandbox):
    """GET /api/services/{id}/logs used to render the daemon stderr as a log."""

    def setUp(self):
        super().setUp()
        find = mock.patch.object(
            services_manage_svc, "find_service",
            lambda sid, force=False: {"id": sid, "kind": "container", "name": sid},
        )
        find.start()
        self.addCleanup(find.stop)

    def test_engine_down_logs_carry_the_coded_503(self):
        with (
            mock.patch.object(
                services_manage_svc, "sh",
                return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(
                services_manage_svc, "engine_up", return_value=False,
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                services_manage_svc.service_logs("web-1")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_down_looking_log_with_a_live_engine_stays_raw(self):
        """A container can echo these strings itself; the forced probe rules."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                services_manage_svc, "sh",
                return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(services_manage_svc, "engine_up", probe),
        ):
            result = services_manage_svc.service_logs("web-1")
        self.assertIn("Cannot connect", result["log"])
        probe.assert_called_once_with(force=True)

    def test_healthy_logs_never_probe(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                services_manage_svc, "sh", return_value=(0, "line one", ""),
            ),
            mock.patch.object(services_manage_svc, "engine_up", probe),
        ):
            result = services_manage_svc.service_logs("web-1")
        self.assertEqual(result["log"], "line one")
        probe.assert_not_called()


class TerminalExecEngineDownTests(_EngineStateSandbox):
    """POST /api/terminal/run (container target): coded 503, after the audit."""

    def _result(self, rc: int, stderr: str) -> dict:
        return {
            "ok": rc == 0, "rc": rc, "stdout": "", "stderr": stderr,
            "truncated": False, "duration_ms": 1,
        }

    def test_engine_down_exec_carries_the_code_and_still_audits(self):
        audit = mock.Mock()
        with (
            mock.patch.object(
                terminal_svc, "_run",
                return_value=self._result(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(terminal_svc, "_audit", audit),
            mock.patch.object(terminal_svc, "engine_up", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                terminal_svc.run_container("web-1", "echo hi")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")
        audit.assert_called_once()

    def test_command_output_quoting_the_strings_stays_verbatim(self):
        """A command whose own output reads engine-down keeps that output."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                terminal_svc, "_run",
                return_value=self._result(1, ENGINE_DOWN_ERR),
            ),
            mock.patch.object(terminal_svc, "_audit", mock.Mock()),
            mock.patch.object(terminal_svc, "engine_up", probe),
        ):
            result = terminal_svc.run_container("web-1", "cat daemon.log")
        self.assertIn("Cannot connect", result["stderr"])
        probe.assert_called_once_with(force=True)

    def test_healthy_exec_never_probes(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                terminal_svc, "_run", return_value=self._result(0, ""),
            ),
            mock.patch.object(terminal_svc, "_audit", mock.Mock()),
            mock.patch.object(terminal_svc, "engine_up", probe),
        ):
            result = terminal_svc.run_container("web-1", "echo hi")
        self.assertEqual(result["rc"], 0)
        probe.assert_not_called()


class ActionsEngineDownTests(_EngineStateSandbox):
    """POST /api/action container branch: 503 instead of raw stderr in ok:false."""

    def setUp(self):
        super().setUp()
        reg = mock.patch.object(
            actions, "registry", lambda: {"web-1": ("container", {})},
        )
        reg.start()
        self.addCleanup(reg.stop)

    def test_engine_down_container_actions_carry_the_code(self):
        for action in ("start", "stop", "restart", "remove"):
            with self.subTest(action=action):
                with (
                    mock.patch.object(
                        actions, "sh", return_value=(1, "", ENGINE_DOWN_ERR),
                    ),
                    mock.patch.object(
                        actions, "engine_up", return_value=False,
                    ),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        actions.run_action("web-1", action)
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "container.engine_down")

    def test_engine_up_failures_keep_the_raw_tuple(self):
        err = "Error response from daemon: No such container: web-1"
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(actions, "sh", return_value=(1, "", err)),
            mock.patch.object(actions, "engine_up", probe),
        ):
            rc, out, got = actions.run_action("web-1", "stop")
        self.assertEqual(rc, 1)
        self.assertEqual(got, err)
        probe.assert_not_called()

    def test_engine_down_looking_output_with_a_live_engine_stays_raw(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                actions, "sh", return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(actions, "engine_up", probe),
        ):
            rc, _out, got = actions.run_action("web-1", "stop")
        self.assertEqual(rc, 1)
        self.assertEqual(got, ENGINE_DOWN_ERR)
        probe.assert_called_once_with(force=True)

    def test_healthy_actions_never_probe(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(actions, "sh", return_value=(0, "web-1", "")),
            mock.patch.object(actions, "engine_up", probe),
        ):
            rc, out, _err = actions.run_action("web-1", "start")
        self.assertEqual(rc, 0)
        probe.assert_not_called()


class BackupStackEngineDownTests(_EngineStateSandbox):
    """The stack-backup job: engine dying inside the TTL gets the job code."""

    def setUp(self):
        super().setUp()
        root = Path(tempfile.mkdtemp(prefix="serverhub-engdown-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        backup_root = root / "backups"
        backup_root.mkdir()
        data_dir = root / "data"
        data_dir.mkdir()
        stack_dir = root / "photoprism"
        stack_dir.mkdir()
        self.compose_path = stack_dir / "docker-compose.yml"
        self.compose_path.write_text("services: {}\n")
        stack = {"id": "photoprism", "name": "PhotoPrism",
                 "path": str(stack_dir), "compose_path": str(self.compose_path)}
        patches = [
            mock.patch.object(backups, "BACKUP_ROOT", backup_root),
            mock.patch.object(backups, "DATA_DIR", data_dir),
            mock.patch.object(
                backups, "_find_stack",
                lambda sid: dict(stack) if sid == "photoprism" else None,
            ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def _probe(entry: bool, forced: bool) -> mock.Mock:
        return mock.Mock(side_effect=lambda force=False: forced if force else entry)

    def test_compose_config_hitting_a_dead_socket_is_the_engine_down_error(self):
        """The entry gate trusts a 5s memo; compose config can hit the corpse."""
        probe = self._probe(entry=True, forced=False)
        log: list = []
        with (
            mock.patch.object(
                backups, "_run_argv", return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(backups, "_engine_up", probe),
        ):
            result = backups.backup_stack("photoprism", log=log)
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "engine_down")
        self.assertEqual(result["message"], "the Docker engine is not running")
        probe.assert_called_with(force=True)

    def test_compose_config_engine_up_failures_stay_compose_config_failed(self):
        """Looks-down output while the engine answers up keeps the original map."""
        probe = self._probe(entry=True, forced=True)
        with (
            mock.patch.object(
                backups, "_run_argv", return_value=(1, "", ENGINE_DOWN_ERR),
            ),
            mock.patch.object(backups, "_engine_up", probe),
        ):
            result = backups.backup_stack("photoprism")
        self.assertEqual(result["error"], "compose_config_failed")
        probe.assert_called_with(force=True)

    def test_volume_export_hitting_a_dead_socket_is_the_engine_down_error(self):
        probe = self._probe(entry=True, forced=False)

        def fake_run(argv, *, timeout, **_kwargs):
            if "config" in argv and "--format" in argv:
                return 0, '{"services": {}, "volumes": {"db": {"name": "p_db"}}}', ""
            if "run" in argv and "alpine" in argv:
                return 1, "", ENGINE_DOWN_ERR
            return 0, "", ""

        with (
            mock.patch.object(backups, "_run_argv", fake_run),
            mock.patch.object(backups, "_engine_up", probe),
            mock.patch.object(
                backups, "_stack_mounts", return_value=([], ["p_db"], ""),
            ),
        ):
            result = backups.backup_stack("photoprism", stop_first=False)
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "engine_down")
        self.assertEqual(result["message"], "the Docker engine is not running")
        probe.assert_called_with(force=True)

    def test_volume_export_plain_failures_keep_the_original_error(self):
        probe = self._probe(entry=True, forced=True)

        def fake_run(argv, *, timeout, **_kwargs):
            if "run" in argv and "alpine" in argv:
                return 1, "", "volume gone"
            return 0, "", ""

        with (
            mock.patch.object(backups, "_run_argv", fake_run),
            mock.patch.object(backups, "_engine_up", probe),
            mock.patch.object(
                backups, "_stack_mounts", return_value=([], ["p_db"], ""),
            ),
        ):
            result = backups.backup_stack("photoprism", stop_first=False)
        self.assertEqual(result["error"], "volume_export_failed")
        self.assertIn("volume gone", result["message"])
        # "volume gone" does not look engine-down: only the entry gate probed.
        probe.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
