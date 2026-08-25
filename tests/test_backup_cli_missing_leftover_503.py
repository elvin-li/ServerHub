"""CLI-missing leftovers, backups sweep: vanished binaries carry coded answers.

``run_capped()`` reports a FileNotFoundError spawn with the exact sentinel
``(-1, "not found")`` — never a real CLI exit — and a direct
``subprocess.Popen`` spawn raises the FileNotFoundError itself.  The backup
jobs probe (or assume) their binaries up front, but a binary that vanished
between that check and the spawn — or was never installed at all — used to
fall through as an answer the SPA cannot translate:

* ``_dump_one_postgres`` (POST /api/backups/postgres) answered a missing
  ``pg_dump`` with the uncoded two-word ``{ok: false, message: "not found"}``
  → now the coded ``backup.tool_missing`` 503 (the vms_svc._cli_missing /
  brew.not_found shape), with the pre-created 0600 placeholder discarded
* ``_backup_configs`` (POST /api/backups/configs) did the same for a missing
  ``/usr/bin/tar`` → the same coded 503
* ``_backup_immich_script`` (POST /api/backups/immich) spawned a script the
  ``immich_backup_info()`` probe had just blessed; vanished, it answered
  ``message: "not found"`` → now the same coded ``not_configured`` refusal
  the up-front gate gives
* ``_backup_immich_native`` swallowed the Popen FileNotFoundError of a
  vanished postgresql@18 ``pg_dump`` into its broad catch and answered an
  uncoded ``[Errno 2] ...`` → now the same "postgresql@18 pg_dump is not
  installed" answer the up-front ``_pg18_dump()`` probe gives
* the stack-backup job (``compose config`` / volume export) kept
  ``compose_config_failed`` / ``volume_export_failed`` with the raw sentinel
  when the docker CLI itself vanished mid-job → now the same coded
  ``engine_down`` state a dead daemon maps to, confirmed by the same forced
  ``_engine_up`` probe the engine-down classifiers use

Deliberately narrow, pinned by the negative cases below: only the exact
spawn sentinel (or the FileNotFoundError raise) classifies.  A timeout keeps
its own shape (a slow tool is not a missing one), a PermissionError keeps
the uncoded ok:false (present-but-unexecutable is not missing), a genuine
non-zero exit keeps its raw output — that message is then the truth — and a
stack step whose output merely reads "not found" while the engine answers
"up" keeps its original failure mapping.

Since the disk-confirm sweep, the sentinel alone no longer classifies:
``_cli_vanished`` re-probes the disk (the vms ``_cli_missing`` rule), so the
vanished cases below stub ``_tool_on_disk`` to answer "gone" — this suite
runs on hosts where pg_dump and /usr/bin/tar really are installed.  The
still-on-disk direction is pinned by
test_leftover_backups_hexint_surrogate_vanish_500s.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import backups
from hub.errors import CODES

#: What hub.util.run_capped returns when the binary is gone (sentinel).
MISSING = (-1, "not found")

TARGET = {
    "id": "teslamate", "host": "localhost", "port": 5432,
    "db": "teslamate", "user": "teslamate", "password_env": "",
}


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class CodeStatusPins(unittest.TestCase):
    """The codes this sweep maps to must stay 503 — a demotion would silently
    turn the "install the tool" / "start the engine" answers back into
    generic failures."""

    def test_backup_codes_are_503(self):
        for code in ("backup.tool_missing", "backup.engine_down"):
            with self.subTest(code=code):
                self.assertEqual(CODES[code][0], 503)


class PostgresDumpCliMissingTests(unittest.TestCase):
    """POST /api/backups/postgres answers a missing pg_dump with the coded 503."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-pg-cli-missing-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "_pg_env", return_value={}),
            # The disk confirm must answer "gone" for the sentinel to
            # classify; this host may genuinely have pg_dump installed.
            mock.patch.object(backups, "_tool_on_disk", return_value=False),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_vanished_pg_dump_carries_the_code(self):
        with mock.patch.object(backups, "run_capped", return_value=MISSING):
            with self.assertRaises(HTTPException) as ctx:
                backups._dump_one_postgres(dict(TARGET))
        self.assertEqual(ctx.exception.status_code, 503)
        detail = _detail(ctx)
        self.assertEqual(detail["code"], "backup.tool_missing")
        self.assertEqual(detail["params"], {"tool": "pg_dump"})
        json.dumps(detail, ensure_ascii=False, allow_nan=False).encode("utf-8")
        # The pre-created 0600 placeholder is discarded, not left as a
        # zero-byte artefact in the backup listing.
        self.assertEqual(list(self.backup_root.iterdir()), [])

    def test_the_whole_job_aborts_coded_and_releases_its_lock(self):
        """Through backup_postgres, the entry the route uses: every target
        needs the same binary, so the aggregate answer is the coded 503 —
        and the _only_one job lock is released for the retry."""
        targets = [dict(TARGET), {**TARGET, "id": "grafana", "db": "grafana"}]
        with (
            mock.patch.object(backups, "pg_targets", return_value=targets),
            mock.patch.object(backups, "run_capped", return_value=MISSING),
        ):
            with self.assertRaises(HTTPException) as ctx:
                backups.backup_postgres()
        self.assertEqual(_detail(ctx)["code"], "backup.tool_missing")
        self.assertFalse(backups._job_locks["postgres"].locked(),
                         "a coded refusal must not leave the job marked busy")

    def test_timeout_sentinel_keeps_the_uncoded_shape(self):
        """A slow pg_dump is not a missing one."""
        with mock.patch.object(backups, "run_capped", return_value=(-1, "")):
            result = backups._dump_one_postgres(dict(TARGET))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "exit -1")

    def test_real_dump_failure_keeps_its_own_message(self):
        err = "pg_dump: error: connection to server failed"
        with mock.patch.object(backups, "run_capped", return_value=(1, err)):
            result = backups._dump_one_postgres(dict(TARGET))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], err)

    def test_spawn_oserror_keeps_the_uncoded_shape(self):
        """A dying pipe / hostile env is not a missing binary."""
        with mock.patch.object(
            backups, "run_capped", side_effect=OSError("kaboom"),
        ):
            result = backups._dump_one_postgres(dict(TARGET))
        self.assertFalse(result["ok"])
        self.assertIn("kaboom", result["message"])


class ConfigArchiveCliMissingTests(unittest.TestCase):
    """POST /api/backups/configs answers a missing tar with the coded 503."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfg-cli-missing-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        config_file = root / "services.yaml"
        config_file.write_text("settings: {}\n")
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "CONFIG_FILE", config_file),
            mock.patch.object(backups, "DATA_DIR", root / "empty-data"),
            mock.patch.object(backups, "cfg", lambda: {}),
            mock.patch.object(Path, "home", return_value=root / "no-home"),
            # /usr/bin/tar exists on every host this suite runs on; the
            # vanished case needs the disk confirm to answer "gone".
            mock.patch.object(backups, "_tool_on_disk", return_value=False),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_vanished_tar_carries_the_code_and_releases_the_lock(self):
        with mock.patch.object(backups, "run_capped", return_value=MISSING):
            with self.assertRaises(HTTPException) as ctx:
                backups.backup_configs()
        self.assertEqual(ctx.exception.status_code, 503)
        detail = _detail(ctx)
        self.assertEqual(detail["code"], "backup.tool_missing")
        self.assertEqual(detail["params"], {"tool": "/usr/bin/tar"})
        self.assertEqual(list(self.backup_root.iterdir()), [],
                         "the pre-created placeholder must be discarded")
        self.assertFalse(backups._job_locks["configs"].locked())

    def test_real_tar_failure_keeps_its_own_message(self):
        err = "tar: services.yaml: Cannot stat"
        with mock.patch.object(backups, "run_capped", return_value=(1, err)):
            result = backups.backup_configs()
        self.assertFalse(result["ok"])
        self.assertIn("Cannot stat", result["message"])


class ImmichCliMissingTests(unittest.TestCase):
    """POST /api/backups/immich: a vanished script / pg18 answers like the
    up-front probe instead of leaking the sentinel or the raw errno."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.immich = root / "immich"
        self.immich.mkdir()
        self.script = self.immich / "backup-db.sh"
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "IMMICH_ROOT", self.immich),
            mock.patch.object(backups, "IMMICH_SCRIPT", self.script),
            mock.patch.object(backups, "IMMICH_DB_ENV", self.immich / "db.env"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_vanished_script_answers_the_coded_refusal(self):
        """Mid-flight state, real spawn: the script the probe blessed is gone
        by the time run_capped execs it."""
        result = backups._backup_immich_script()
        self.assertEqual(result, backups._immich_unavailable())
        self.assertEqual(result["error"], "not_configured")
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(list(self.backup_root.iterdir()), [])

    def test_probe_to_spawn_race_through_the_job_entry(self):
        """backup_immich's gate says "script"; the script vanishes before the
        spawn, which hits the sentinel — the answer is the same refusal the
        gate itself gives.  The unlink models the race: the disk confirm
        must find the script really gone, not just trust the sentinel."""
        self.script.write_text("#!/bin/sh\n")
        self.script.chmod(0o755)

        def vanish(argv, **_kwargs):
            self.script.unlink()
            return MISSING

        with mock.patch.object(backups, "run_capped", side_effect=vanish):
            result = backups.backup_immich()
        self.assertEqual(result, backups._immich_unavailable())

    def test_timeout_sentinel_keeps_the_uncoded_shape(self):
        self.script.write_text("#!/bin/sh\n")
        self.script.chmod(0o755)
        with mock.patch.object(backups, "run_capped", return_value=(-1, "")):
            result = backups._backup_immich_script()
        self.assertFalse(result["ok"])
        self.assertNotIn("error", result)
        self.assertEqual(result["message"], "exit -1")

    def test_real_script_failure_keeps_its_own_message(self):
        self.script.write_text("#!/bin/sh\n")
        self.script.chmod(0o755)
        err = "pg_dump: error: connection to server on port 5433 failed"
        with mock.patch.object(backups, "run_capped", return_value=(1, err)):
            result = backups._backup_immich_script()
        self.assertFalse(result["ok"])
        self.assertNotIn("error", result)
        self.assertIn("port 5433 failed", result["message"])

    def test_vanished_pg18_answers_like_the_probe(self):
        """The Popen FileNotFoundError of a pg18 that vanished after the
        _pg18_dump() probe answers exactly like the probe finding nothing —
        not an uncoded "[Errno 2] ..."."""
        (self.immich / "db.env").write_text(
            "DB_URL=postgresql://immich:s3cret@127.0.0.1:5433/immich\n"
        )
        gone = Path(self.tmp.name) / "gone-pg_dump"
        with mock.patch.object(backups, "_pg18_dump", return_value=gone):
            result = backups._backup_immich_native()
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "postgresql@18 pg_dump is not installed")
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(list(self.backup_root.iterdir()), [],
                         "the pre-created placeholder must be discarded")

    def test_pg18_permission_error_is_not_classified(self):
        """Present-but-unexecutable is not missing: the raw message is then
        the truth."""
        (self.immich / "db.env").write_text(
            "DB_URL=postgresql://immich:s3cret@127.0.0.1:5433/immich\n"
        )
        with (
            mock.patch.object(backups, "_pg18_dump", return_value=Path("/bin/true")),
            mock.patch.object(
                backups.subprocess, "Popen",
                side_effect=PermissionError(13, "Permission denied"),
            ),
        ):
            result = backups._backup_immich_native()
        self.assertFalse(result["ok"])
        self.assertIn("Permission denied", result["message"])
        self.assertEqual(list(self.backup_root.iterdir()), [])


class StackBackupCliMissingTests(unittest.TestCase):
    """The stack-backup job: a docker CLI that vanishes mid-job gets the same
    coded engine_down state a dead daemon does, confirmed by the same forced
    probe — never compose_config_failed / volume_export_failed with the raw
    spawn sentinel."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-stack-cli-missing-"))
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
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", backup_root),
            mock.patch.object(backups, "DATA_DIR", data_dir),
            mock.patch.object(
                backups, "_find_stack",
                lambda sid: dict(stack) if sid == "photoprism" else None,
            ),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    @staticmethod
    def _probe(entry: bool, forced: bool) -> mock.Mock:
        return mock.Mock(side_effect=lambda force=False: forced if force else entry)

    def test_compose_config_spawn_sentinel_is_the_engine_down_error(self):
        """The entry gate trusts a 5s memo; the CLI can vanish before
        `compose config` execs."""
        probe = self._probe(entry=True, forced=False)
        log: list = []
        with (
            mock.patch.object(
                backups, "_run_argv", return_value=(-1, "not found", ""),
            ),
            mock.patch.object(backups, "_engine_up", probe),
        ):
            result = backups.backup_stack("photoprism", log=log)
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "engine_down")
        self.assertEqual(result["message"], "the Docker engine is not running")
        probe.assert_called_with(force=True)

    def test_config_not_found_output_with_a_live_engine_stays_original(self):
        """The message-pattern gate alone must not classify; the probe rules."""
        probe = self._probe(entry=True, forced=True)
        with (
            mock.patch.object(
                backups, "_run_argv", return_value=(-1, "not found", ""),
            ),
            mock.patch.object(backups, "_engine_up", probe),
        ):
            result = backups.backup_stack("photoprism")
        self.assertEqual(result["error"], "compose_config_failed")
        self.assertIn("not found", result["message"])
        probe.assert_called_with(force=True)

    def test_volume_export_spawn_sentinel_is_the_engine_down_error(self):
        probe = self._probe(entry=True, forced=False)

        def fake_run(argv, *, timeout, **_kwargs):
            if "run" in argv and "alpine" in argv:
                return -1, "not found", ""
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

    def test_volume_export_sentinel_with_a_live_engine_stays_original(self):
        probe = self._probe(entry=True, forced=True)

        def fake_run(argv, *, timeout, **_kwargs):
            if "run" in argv and "alpine" in argv:
                return -1, "not found", ""
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
        self.assertIn("not found", result["message"])
        probe.assert_called_with(force=True)

    def test_classification_never_skips_the_restart(self):
        """The one promise the job makes survives this sweep: once stop was
        issued, start runs — even when the failure is the coded engine_down."""
        probe = self._probe(entry=True, forced=False)
        calls: list[str] = []

        def fake_run(argv, *, timeout, **_kwargs):
            joined = " ".join(argv)
            calls.append(joined)
            if "run" in argv and "alpine" in argv:
                return -1, "not found", ""
            return 0, "", ""

        with (
            mock.patch.object(backups, "_run_argv", fake_run),
            mock.patch.object(backups, "_engine_up", probe),
            mock.patch.object(
                backups, "_stack_mounts", return_value=([], ["p_db"], ""),
            ),
        ):
            result = backups.backup_stack("photoprism")
        self.assertEqual(result["error"], "engine_down")
        self.assertTrue(result["stopped"])
        self.assertTrue(result["restarted"])
        self.assertTrue(any(line.endswith("start") for line in calls))


if __name__ == "__main__":
    unittest.main()
