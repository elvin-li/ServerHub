"""Vanished-CLI leftovers: catalog / apps / compose paths carry the code.

Continues the sweep from test_cli_missing_leftover_503 (vms / brew / wg) and
test_backup_cli_missing_leftover_503 (pg_dump / tar / stack-backup docker)
across the docker and brew spawn paths that still answered a binary that
vanished *between* an up-front presence gate and the spawn — an uninstall
mid-request, OrbStack removed while a job ran, a dying mount — with an
uncoded shape or, worse, destructive fake success:

* ``catalog.install_template`` (POST /api/catalog/{id}/install) rolled the
  whole install back — discarding the operator's filled-in variables and the
  generated passwords — and answered the uncoded two-word
  ``{ok: false, message: "not found"}`` the SPA cannot translate, when the
  keep-the-stack engine-down shape is the truthful answer
* ``catalog.uninstall_template`` (POST /api/catalog/{id}/uninstall) ran a
  ``compose down`` that did nothing, then rmtree'd the stack directory anyway
  and reported a *successful* uninstall — the exact fake-success shape the
  engine-down fix already refuses — leaving orphaned containers to restart
  against a deleted tree
* ``apps_manage_svc._compose_cmd`` (POST /api/apps/managed/action, logs)
  handed back the uncoded ``{ok: false, message: "not found"}``
* ``compose_svc.validate_compose_text`` (compose save/create) failed the
  operation as ``compose.invalid: not found`` — a 400 blaming the YAML for a
  missing CLI
* ``containers_svc`` stack/update jobs (POST /api/stacks/{id}/run) finished
  as a bare rc -1 with only Popen's locale-dependent strerror in the log
* ``native_catalog._run_brew`` (native app install/uninstall) returned the
  uncoded sentinel instead of the same ``catalog.brew_missing`` 503 its own
  up-front gate raises
* ``autostart_svc.set_brew_autostart`` (PUT /api/apps/autostart, brew kind)
  answered the uncoded ``{ok: false, message: "not found"}`` — the exact
  leftover ``brew_svc.brew_service_action`` already fixed; this sibling
  spawn of the very same ``brew services start/stop`` command kept it

``run_capped``/``sh`` report the FileNotFoundError spawn as the exact
sentinel ``(-1, "not found")`` — never a real CLI exit.  Deliberately narrow,
pinned by the negative cases below: only that sentinel (or, for the job
runner's direct Popen, a FileNotFoundError whose filename is the command's
own binary) classifies, and every docker classification still defers to a
forced ``engine_up`` probe — which cannot answer "up" while the CLI is gone —
so a timeout keeps its own shape and a genuine CLI exit keeps its raw output.
"""
from __future__ import annotations

import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import apps_manage_svc, autostart_svc, catalog, compose_svc, containers_svc, docker_cli, native_catalog
from hub.errors import CODES

#: What hub.util.run_capped returns when the binary is gone (sentinel).
MISSING = (-1, "not found")


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class CodeStatusPins(unittest.TestCase):
    """A demotion would silently turn "start the engine / install the tool"
    answers back into generic failures."""

    def test_codes_stay_503(self):
        for code in ("container.engine_down", "catalog.brew_missing"):
            with self.subTest(code=code):
                self.assertEqual(CODES[code][0], 503)

    def test_the_sentinel_gate_is_exact(self):
        self.assertTrue(docker_cli.looks_cli_vanished("not found"))
        self.assertTrue(docker_cli.looks_cli_vanished(" not found\n"))
        for text in ("", "timeout", "exit -1", "image not found",
                     "Error: not found here", None, b"not found?"):
            with self.subTest(text=text):
                self.assertFalse(docker_cli.looks_cli_vanished(text))


TEMPLATE = """---
name: Vanished CLI Fixture
desc: fixture
category: other
ports: ["59741"]
vars: []
---
services:
  fixture:
    image: example/fixture:latest
    container_name: vanished-cli-fixture
    ports:
      - "59741:80"
"""


class _CatalogSandbox(unittest.TestCase):
    """Temp SERVICES_ROOT + real docker stub, same shape as the engine-down
    sweep: the up-front ``_exists(Path(DOCKER))`` gate passes, so the mocked
    run_capped sentinel is exactly the vanished-between-gate-and-spawn race."""

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
        self.tid = "vanished-cli-fixture"
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
            # cli_on_disk is stubbed so the verdict never depends on whether
            # the machine running the suite happens to have a docker binary:
            # the sentinel only reads as a vanished CLI once the binary is
            # confirmed gone from disk (a vanished *cwd* raises the same
            # FileNotFoundError) — the compose_svc convention.
            mock.patch.object(catalog, "cli_on_disk", return_value=False),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    @property
    def dest_dir(self) -> Path:
        return self.services / self.tid


class CatalogInstallCliVanishedTests(_CatalogSandbox):
    """install_template: a vanished docker is the keep-the-stack coded shape,
    not a rollback that discards the generated passwords."""

    def test_vanished_docker_keeps_the_files_and_carries_the_code(self):
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", return_value=False),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["code"], "container.engine_down")
        self.assertTrue(
            (self.dest_dir / "docker-compose.yml").exists(),
            "a vanished CLI must not cost the written compose file",
        )
        self.assertEqual(len(self.registered), 1)
        self.assertEqual(r["stack_id"], self.tid)

    def test_the_classification_forces_a_fresh_probe(self):
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            catalog.install_template(self.tid, {})
        probe.assert_called_once_with(force=True)

    def test_sentinel_with_a_live_engine_still_rolls_back(self):
        """The forced probe rules: an engine that answers "up" means the
        sentinel did not come from a vanished docker CLI."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertNotIn("code", r)
        self.assertFalse(self.dest_dir.exists(), "real failures keep rolling back")
        self.assertEqual(self.registered, [])
        probe.assert_called_once_with(force=True)

    def test_timeout_sentinel_is_not_classified(self):
        """A timed-out compose up is not a missing CLI: no probe, rollback."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(catalog, "run_capped", return_value=(-1, "")),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertNotIn("code", r)
        probe.assert_not_called()

    def test_sentinel_with_the_binary_still_on_disk_keeps_the_stack_engine_down(self):
        """Union keep-the-stack: FileNotFoundError spawn with the CLI still
        on disk and a down engine is ``container.engine_down``, not a
        transactional rollback. The compose tree stays registered."""
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", probe),
            mock.patch.object(catalog, "cli_on_disk", return_value=True),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["code"], "container.engine_down")
        self.assertTrue(self.dest_dir.exists(), "keep-the-stack leaves the compose tree")

    def test_a_real_nonzero_exit_reading_not_found_stays_raw(self):
        """``rc == -1`` is part of the gate: a genuine CLI exit whose output
        happens to read "not found" keeps the transactional rollback."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(catalog, "run_capped", return_value=(1, "not found")),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertNotIn("code", r)
        probe.assert_not_called()

    def test_upfront_absence_keeps_the_friendly_manual_shape(self):
        """Already safe, pinned: no docker CLI at all keeps the files and
        answers with the run-manually message (no rollback, no 5xx)."""
        self.docker.unlink()
        with mock.patch.object(catalog.shutil, "which", return_value=None):
            r = catalog.install_template(self.tid, {})
        self.assertEqual(r["ok"], False)
        self.assertIn("docker CLI was not found", r["message"])
        self.assertTrue((self.dest_dir / "docker-compose.yml").exists())
        self.assertEqual(len(self.registered), 1)


class CatalogUninstallCliVanishedTests(_CatalogSandbox):
    """uninstall_template: a down that could not even spawn must not delete
    the data and report success."""

    def setUp(self):
        super().setUp()
        self.dest_dir.mkdir()
        (self.dest_dir / "docker-compose.yml").write_text(
            "services:\n  fixture:\n    image: example/fixture:latest\n"
        )
        self.registered.append({"id": self.tid})

    def test_vanished_docker_refuses_with_the_coded_503(self):
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", probe),
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
        probe.assert_called_once_with(force=True)

    def test_sentinel_with_a_live_engine_keeps_the_existing_contract(self):
        """The forced probe rules: engine up means the down really ran."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.uninstall_template(self.tid, remove_data=True, confirm=True)
        self.assertIn("ok", r)
        self.assertFalse(self.dest_dir.exists(), "remove_data still removes files")
        probe.assert_called_once_with(force=True)

    def test_timeout_sentinel_is_not_classified(self):
        """A timed-out down keeps its own shape; the probe is never spawned."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(catalog, "run_capped", return_value=(-1, "")),
            mock.patch.object(catalog, "engine_up", probe),
        ):
            r = catalog.uninstall_template(self.tid, remove_data=True, confirm=True)
        self.assertIn("ok", r)
        probe.assert_not_called()

    def test_sentinel_with_the_binary_still_on_disk_keeps_the_stack_engine_down(self):
        """Union keep-the-stack: FileNotFoundError spawn with the CLI still
        on disk and a down engine is ``container.engine_down``, not a
        destructive uninstall that deletes the compose tree."""
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(catalog, "run_capped", return_value=MISSING),
            mock.patch.object(catalog, "engine_up", probe),
            mock.patch.object(catalog, "cli_on_disk", return_value=True),
        ):
            with self.assertRaises(HTTPException) as ctx:
                catalog.uninstall_template(self.tid, remove_data=True, confirm=True)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "container.engine_down")
        self.assertTrue(
            (self.dest_dir / "docker-compose.yml").exists(),
            "keep-the-stack leaves the compose tree",
        )
        self.assertEqual(len(self.registered), 1, "stack must stay registered")
        probe.assert_called_once_with(force=True)


class AppsComposeCliVanishedTests(unittest.TestCase):
    """_compose_cmd (Apps start/stop/restart/update/logs): coded soft-fail."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.services = root / "Services"
        (self.services / "mystack").mkdir(parents=True)
        compose = self.services / "mystack" / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:alpine\n")
        self.docker_bin = root / "docker"
        self.docker_bin.write_text("#!/bin/sh\nexit 0\n")
        self.docker_bin.chmod(0o755)
        patches = [
            mock.patch.object(apps_manage_svc, "SERVICES_ROOT", self.services),
            mock.patch.object(apps_manage_svc, "DOCKER", str(self.docker_bin)),
            # Stubbed so the verdict never depends on the suite machine's
            # own docker binary (the compose_svc convention).
            mock.patch.object(apps_manage_svc, "cli_on_disk", return_value=False),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_vanished_docker_actions_carry_the_code(self):
        for action in ("start", "stop", "restart", "update"):
            with self.subTest(action=action):
                with (
                    mock.patch.object(
                        apps_manage_svc, "run_capped", return_value=MISSING,
                    ),
                    mock.patch.object(
                        apps_manage_svc, "engine_up", return_value=False,
                    ),
                ):
                    result = apps_manage_svc.action("docker:mystack", action)
                self.assertEqual(result["ok"], False)
                self.assertEqual(result["code"], "container.engine_down")

    def test_sentinel_with_a_live_engine_keeps_the_raw_message(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(apps_manage_svc, "run_capped", return_value=MISSING),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            result = apps_manage_svc.action("docker:mystack", "stop")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["message"], "not found")
        self.assertNotIn("code", result)
        probe.assert_called_once_with(force=True)

    def test_timeout_sentinel_is_not_classified(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped", return_value=(-1, ""),
            ),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            result = apps_manage_svc.action("docker:mystack", "start")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["message"], "exit -1")
        self.assertNotIn("code", result)
        probe.assert_not_called()

    def test_compose_logs_carry_the_code_too(self):
        with (
            mock.patch.object(apps_manage_svc, "run_capped", return_value=MISSING),
            mock.patch.object(apps_manage_svc, "engine_up", return_value=False),
        ):
            result = apps_manage_svc.logs("docker:mystack")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["code"], "container.engine_down")

    def test_sentinel_with_the_binary_still_on_disk_is_not_a_missing_cli(self):
        """A stack directory (the compose cwd) that vanished mid-request
        raises the same FileNotFoundError sentinel; with the CLI still on
        disk the raw result rules, not the engine-down soft-fail."""
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(apps_manage_svc, "run_capped", return_value=MISSING),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
            mock.patch.object(apps_manage_svc, "cli_on_disk", return_value=True),
        ):
            result = apps_manage_svc.action("docker:mystack", "stop")
        self.assertEqual(result["ok"], False)
        self.assertNotIn("code", result)
        self.assertEqual(result["message"], "not found")
        # The message-pattern gate fails first, so no probe is spawned.
        probe.assert_not_called()


class ComposeValidateCliVanishedTests(unittest.TestCase):
    """validate_compose_text: a missing CLI is a dependency state, never a
    ``compose.invalid`` verdict on the operator's YAML."""

    CONTENT = "services:\n  web:\n    image: nginx:alpine\n"

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _validate(self, run_result, probe, on_disk=False):
        # cli_on_disk is stubbed so the verdict never depends on whether the
        # machine running the suite happens to have a docker binary: the
        # sentinel only reads as a vanished CLI once the binary is confirmed
        # gone from disk (a vanished *cwd* raises the same FileNotFoundError).
        with (
            mock.patch.object(compose_svc, "run_capped", return_value=run_result),
            mock.patch.object(compose_svc, "engine_up", probe),
            mock.patch.object(compose_svc, "cli_on_disk", return_value=on_disk),
        ):
            return compose_svc.validate_compose_text(
                self.CONTENT, cwd=self._tmp.name,
            )

    def test_vanished_docker_is_the_coded_soft_fail(self):
        probe = mock.Mock(return_value=False)
        result = self._validate(MISSING, probe)
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)

    def test_sentinel_with_the_binary_still_on_disk_is_engine_down(self):
        """Union keep-the-stack: a MISSING spawn with the CLI on disk and a
        down engine is ``container.engine_down``, not a raw "not found"."""
        probe = mock.Mock(return_value=False)
        result = self._validate(MISSING, probe, on_disk=True)
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["code"], "container.engine_down")

    def test_sentinel_with_a_live_engine_keeps_the_raw_message(self):
        probe = mock.Mock(return_value=True)
        result = self._validate(MISSING, probe)
        self.assertEqual(result["ok"], False)
        self.assertNotIn("code", result)
        self.assertEqual(result["message"], "not found")
        probe.assert_called_once_with(force=True)

    def test_a_real_yaml_error_never_probes(self):
        probe = mock.Mock(return_value=True)
        result = self._validate((1, "services.web.image must be a string"), probe)
        self.assertEqual(result["ok"], False)
        self.assertNotIn("code", result)
        probe.assert_not_called()


class _SyncThread:
    """threading.Thread stand-in that runs the job body on start()."""

    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        if self._target is not None:
            self._target()


class StackJobCliVanishedTests(unittest.TestCase):
    """The job runner: a docker CLI that cannot even be spawned stamps the
    job with the coded reason instead of only Popen's strerror."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.workdir = Path(self._tmp.name) / "media"
        self.workdir.mkdir()
        (self.workdir / "docker-compose.yml").write_text("services: {}\n")

    def test_spawn_of_a_missing_binary_sets_the_internal_flag(self):
        j = {"log": []}
        rc = containers_svc._stream_job_command(
            ["/definitely/not/a/real/docker-xyz", "compose", "up"], j,
            cwd=str(self.workdir),
        )
        self.assertEqual(rc, -1)
        self.assertTrue(j.get("cli_missing"))
        self.assertTrue(any(line.startswith("!! error") for line in j["log"]))

    def test_a_vanished_cwd_is_not_a_missing_cli(self):
        """Both are ENOENT; only the binary's own absence may classify."""
        j = {"log": []}
        rc = containers_svc._stream_job_command(
            ["/bin/echo", "hi"], j, cwd="/definitely/not/a/real/dir-xyz",
        )
        self.assertEqual(rc, -1)
        self.assertNotIn("cli_missing", j)

    def test_stack_job_end_to_end_carries_the_code(self):
        stack = {
            "id": "media", "name": "media", "path": str(self.workdir),
            "compose_file": "docker-compose.yml",
            "compose_path": str(self.workdir / "docker-compose.yml"),
            "containers": [], "source": "config",
        }
        saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(lambda: (containers_svc._cjobs.clear(),
                                 containers_svc._cjobs.update(saved)))
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(
                containers_svc, "threading",
                # Only Thread is replaced: _stream_job_command runs for real
                # here (that is the point of this test) and needs the true
                # Event / Timer / Lock.
                types.SimpleNamespace(
                    Thread=_SyncThread, Event=threading.Event,
                    Timer=threading.Timer, Lock=threading.Lock,
                ),
            ),
            mock.patch.object(containers_svc, "maintenance_env", lambda: {}),
            mock.patch.object(containers_svc, "invalidate_status", lambda: None),
            mock.patch.object(
                containers_svc, "_stack_paths", lambda: [dict(stack)],
            ),
            mock.patch.object(
                containers_svc, "DOCKER", "/definitely/not/a/real/docker-xyz",
            ),
            mock.patch.object(containers_svc, "engine_up", probe),
        ):
            r = containers_svc.start_stack_job("media", "up")
        job = containers_svc.stack_job_log(r["job_id"])
        self.assertEqual(job["running"], False)
        self.assertNotEqual(job["rc"], 0)
        self.assertEqual(job["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)
        # The internal spawn flag never leaks into the public payloads.
        self.assertNotIn("cli_missing", job)
        for row in containers_svc.latest_stack_jobs():
            self.assertNotIn("cli_missing", row)

    def test_the_flag_still_defers_to_a_live_engine(self):
        """cli_missing with an engine that answers "up" keeps the raw failure:
        the probe cannot answer "up" while the CLI is really gone, so a live
        answer means the flag came from something else."""
        j = {"log": ["!! error: spawn failed"], "rc": -1, "cli_missing": True}
        probe = mock.Mock(return_value=True)
        with mock.patch.object(containers_svc, "engine_up", probe):
            containers_svc._classify_job_failure(j)
        self.assertNotIn("code", j)
        probe.assert_called_once_with(force=True)


class NativeBrewCliVanishedTests(unittest.TestCase):
    """_run_brew: a brew that vanished after install_native's up-front gate
    raises the same coded 503 the gate itself answers."""

    SENTINEL = {"ok": False, "message": "not found", "rc": -1}

    def test_vanished_brew_raises_the_coded_503(self):
        with (
            mock.patch.object(native_catalog, "_run", return_value=dict(self.SENTINEL)),
            mock.patch.object(native_catalog, "_is_file", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                native_catalog._run_brew(["install", "--cask", "orbstack"])
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "catalog.brew_missing")

    def test_sentinel_while_brew_is_still_present_keeps_the_dict(self):
        """The filesystem confirmation rules, mirroring the forced engine
        probe: a brew that is really there keeps the raw result."""
        with (
            mock.patch.object(native_catalog, "_run", return_value=dict(self.SENTINEL)),
            mock.patch.object(native_catalog, "_is_file", return_value=True),
        ):
            r = native_catalog._run_brew(["install", "redis"])
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["message"], "not found")

    def test_a_real_brew_failure_keeps_its_output(self):
        result = {"ok": False, "message": "Error: No available formula", "rc": 1}
        checker = mock.Mock(return_value=False)
        with (
            mock.patch.object(native_catalog, "_run", return_value=dict(result)),
            mock.patch.object(native_catalog, "_is_file", checker),
        ):
            r = native_catalog._run_brew(["install", "redis"])
        self.assertEqual(r["message"], "Error: No available formula")
        # A real exit is not the sentinel: the filesystem is never consulted.
        checker.assert_not_called()

    def test_timeout_keeps_its_own_message(self):
        result = {"ok": False, "message": "command timed out", "rc": -1}
        with (
            mock.patch.object(native_catalog, "_run", return_value=dict(result)),
            mock.patch.object(native_catalog, "_is_file", return_value=False),
        ):
            r = native_catalog._run_brew(["install", "redis"])
        self.assertEqual(r["message"], "command timed out")

    def test_cask_install_surfaces_the_raise(self):
        """Through _install_native, the body every brew_cask install runs."""
        app = {"id": "native-test-cask", "method": "brew_cask", "package": "x"}
        with (
            mock.patch.object(native_catalog, "_is_installed", return_value=False),
            mock.patch.object(native_catalog, "_run", return_value=dict(self.SENTINEL)),
            mock.patch.object(native_catalog, "_is_file", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                native_catalog._install_native(app, app["id"])
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "catalog.brew_missing")


class AutostartBrewCliVanishedTests(unittest.TestCase):
    """set_brew_autostart: the Apps page's autostart toggle spawns the same
    ``brew services start/stop`` as brew_svc.brew_service_action; the vanished
    brew answer is the same coded 503 its own up-front gate raises."""

    def _toggle(self, run_result, is_file, invalidate=None):
        with (
            mock.patch.object(autostart_svc, "run_capped", return_value=run_result),
            mock.patch.object(autostart_svc, "_is_file", is_file),
            mock.patch.object(
                autostart_svc, "invalidate_brew_services",
                invalidate or mock.Mock(),
            ),
        ):
            return autostart_svc.set_brew_autostart("redis", True)

    def test_vanished_brew_raises_the_coded_503(self):
        # The up-front gate passes, then the confirmation finds brew gone.
        gate = mock.Mock(side_effect=[True, False])
        with self.assertRaises(HTTPException) as ctx:
            self._toggle(MISSING, gate)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "brew.not_found")
        self.assertEqual(gate.call_count, 2)

    def test_sentinel_while_brew_is_still_present_keeps_the_dict(self):
        """The filesystem confirmation rules: brew really there, raw result."""
        gate = mock.Mock(side_effect=[True, True])
        invalidate = mock.Mock()
        r = self._toggle(MISSING, gate, invalidate)
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["message"], "not found")
        self.assertIsNone(r["autostart"])
        invalidate.assert_called_once_with()

    def test_timeout_sentinel_is_not_classified(self):
        """rc -1 with empty output is run_capped's timeout, not the spawn
        sentinel: no second filesystem look, the friendly fallback message."""
        gate = mock.Mock(return_value=True)
        r = self._toggle((-1, ""), gate)
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["message"], "brew services start redis")
        gate.assert_called_once()

    def test_a_real_brew_exit_reading_not_found_stays_raw(self):
        """``rc == -1`` is part of the gate: a genuine brew exit whose output
        happens to read "not found" keeps its own shape."""
        gate = mock.Mock(return_value=True)
        r = self._toggle((1, "not found"), gate)
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["message"], "not found")
        gate.assert_called_once()

    def test_a_success_still_reports_the_new_state(self):
        gate = mock.Mock(return_value=True)
        invalidate = mock.Mock()
        r = self._toggle((0, "Successfully started `redis`"), gate, invalidate)
        self.assertEqual(r["ok"], True)
        self.assertEqual(r["autostart"], True)
        invalidate.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
