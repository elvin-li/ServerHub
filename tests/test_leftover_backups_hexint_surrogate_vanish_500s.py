"""Leftover Backups 500s: hex-YAML over-cap ints, surrogate names/paths,
and the vanished-CLI 503 that fired without a disk confirm.

The digit-cap battery (test_leftover_files_shares_backups_digit_500s) pinned
the *string* parses — over-cap ports arrive as str and die in ``int(str)``.
This sweep covers the shapes that dodge that cap on the Backups page:

* YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
  CPython's 4300-digit conversion limit), so a leftover ``db: 0xFF…`` in
  ``backups.postgres`` arrived *already-int* and the bare ``str()`` inside
  ``pg_targets`` raised the digit-cap ValueError — 500ing GET /api/backups
  and POST /api/backups/postgres, on a function whose contract is "drop
  malformed entries one by one rather than raising";
* a quoted ``"\\ud800…"`` in the same fields loads as a lone-surrogate str,
  passed every check (it is neither whitespace nor ``=``), and 500'd
  Starlette's UTF-8 encode (``ensure_ascii=False`` then ``.encode``) on the
  same routes;
* an Immich artefact whose on-disk name is undecodable surfaces as lone
  surrogates (os surrogateescape); ``_backup_immich_script`` put the raw
  name into the result's ``path`` and 500'd POST /api/backups/immich at the
  same encode — on the *successful* run;
* ``_cli_vanished`` classified on the ``(-1, "not found")`` sentinel alone.
  rc -1 is also what a SIGHUP-killed run reports, so a still-present
  pg_dump/tar/backup-db.sh whose trailing output read exactly ``not found``
  was answered with the vanished-binary 503 (or the not_configured refusal)
  instead of its raw result.  Classification now requires a disk confirm
  (the vms ``_cli_missing`` / ollama ``delete_model`` / photoshub
  ``_ctl_on_disk`` rule), run only on the failure path.
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

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

#: What hub.util.run_capped returns when the binary is gone (sentinel) — and
#: also what a SIGHUP-killed run whose tail read "not found" looks like.
MISSING = (-1, "not found")

TARGET = {
    "id": "teslamate", "host": "localhost", "port": 5432,
    "db": "teslamate", "user": "teslamate", "password_env": "",
}


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _with_targets(raw: list):
    return mock.patch.object(backups, "cfg", lambda: {"backups": {"postgres": raw}})


class PgTargetsOverCapIntTests(unittest.TestCase):
    """Already-int over-cap YAML values drop their entry, never the route."""

    def test_hex_yaml_loads_past_the_digit_cap(self):
        """The vector this file guards: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        import yaml
        loaded = yaml.safe_load("port: 0x" + "f" * 5000)
        self.assertIsInstance(loaded["port"], int)
        with self.assertRaises(ValueError):
            str(loaded["port"])

    def test_each_field_drops_only_its_own_entry(self):
        for field in ("id", "db", "host", "user", "password_env"):
            with self.subTest(field=field):
                poisoned = dict(TARGET)
                poisoned[field] = _HUGE_INT
                with _with_targets([poisoned, {"id": "sane", "db": "grafana"}]):
                    targets = backups.pg_targets()
                _starlette(targets)
                self.assertEqual([t["id"] for t in targets], ["sane"])

    def test_backup_postgres_reports_not_configured_instead_of_500(self):
        """With every entry poisoned, the job answers the same coded
        sentence an unconfigured install gets — not a stack trace."""
        with _with_targets([{"id": _HUGE_INT, "db": _HUGE_INT}]):
            result = backups.backup_postgres()
        _starlette(result)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "not_configured")

    def test_sane_int_fields_still_coerce(self):
        """The old str() behaviour for renderable ints is kept: a numeric id
        is odd but was accepted, and this sweep must not reject it."""
        with _with_targets([{"id": 42, "db": "teslamate"}]):
            targets = backups.pg_targets()
        self.assertEqual(targets[0]["id"], "42")


class PgTargetsSurrogateTests(unittest.TestCase):
    """Lone-surrogate YAML values drop their entry before Starlette's encode."""

    def test_surrogate_fields_are_dropped(self):
        for field in ("id", "db", "host", "user", "password_env"):
            with self.subTest(field=field):
                poisoned = dict(TARGET)
                poisoned[field] = "tesla\ud800mate"
                with _with_targets([poisoned, {"id": "sane", "db": "grafana"}]):
                    targets = backups.pg_targets()
                _starlette(targets)
                self.assertEqual([t["id"] for t in targets], ["sane"])

    def test_real_utf8_names_still_pass(self):
        """Rejection is for lone surrogates, not for non-ASCII: a réal UTF-8
        database name keeps working."""
        with _with_targets([{"id": "meteo", "db": "météo"}]):
            targets = backups.pg_targets()
        _starlette(targets)
        self.assertEqual(targets[0]["db"], "météo")


class ImmichSurrogateArtefactTests(unittest.TestCase):
    """POST /api/backups/immich survives an undecodable artefact name."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-immich-surrogate-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.script = root / "backup-db.sh"
        self.script.write_text("#!/bin/sh\nexit 0\n")
        self.script.chmod(0o755)
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "IMMICH_ROOT", root),
            mock.patch.object(backups, "IMMICH_SCRIPT", self.script),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_success_path_is_utf8_encodable(self):
        def fake_run(argv, **_kwargs):
            # The host script writes its artefact while running; an
            # undecodable on-disk name surfaces as lone surrogates.
            (self.backup_root / "immich_2026\udcff.sql.gz").write_bytes(b"x" * 64)
            return 0, "done"

        with mock.patch.object(backups, "run_capped", fake_run):
            result = backups._backup_immich_script()
        _starlette(result)
        self.assertTrue(result["ok"])
        self.assertNotIn("\udcff", result["path"])

    def test_clean_names_keep_their_exact_path(self):
        def fake_run(argv, **_kwargs):
            (self.backup_root / "immich_20260825_063000.sql.gz").write_bytes(b"x" * 64)
            return 0, "done"

        with mock.patch.object(backups, "run_capped", fake_run):
            result = backups._backup_immich_script()
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["path"],
            str(self.backup_root / "immich_20260825_063000.sql.gz"),
        )


class VanishedCliDiskConfirmTests(unittest.TestCase):
    """The sentinel is the 503 only after a disk probe confirms the tool left."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-backup-confirm-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.backup_root = root / "backups"
        self.backup_root.mkdir()

    def test_pg_dump_sentinel_with_the_tool_on_disk_keeps_raw_failure(self):
        """rc -1 is also a SIGHUP-killed dump; while pg_dump is still on
        disk the raw result is the truth, not a false "not installed"."""
        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "_pg_env", return_value={}),
            mock.patch.object(backups, "run_capped", return_value=MISSING),
            mock.patch.object(backups, "_tool_on_disk", return_value=True),
        ):
            result = backups._dump_one_postgres(dict(TARGET))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "not found")
        self.assertEqual(list(self.backup_root.iterdir()), [],
                         "the failed run's placeholder must still be discarded")

    def test_pg_dump_sentinel_with_the_tool_gone_is_the_coded_503(self):
        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "_pg_env", return_value={}),
            mock.patch.object(backups, "run_capped", return_value=MISSING),
            mock.patch.object(backups, "_tool_on_disk", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                backups._dump_one_postgres(dict(TARGET))
        self.assertEqual(ctx.exception.status_code, 503)

    def test_pg_dump_success_never_probes_the_disk(self):
        """The re-check runs only on the failure path (the ollama rule)."""
        probe = mock.Mock(return_value=True)

        def fake_run(argv, **_kwargs):
            dest = Path(argv[argv.index("-f") + 1])
            dest.write_bytes(b"x" * 64)
            return 0, ""

        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "_pg_env", return_value={}),
            mock.patch.object(backups, "run_capped", fake_run),
            mock.patch.object(backups, "_tool_on_disk", probe),
        ):
            result = backups._dump_one_postgres(dict(TARGET))
        self.assertTrue(result["ok"])
        probe.assert_not_called()

    def test_tar_sentinel_with_tar_on_disk_keeps_raw_failure(self):
        """/usr/bin/tar really is present here, so no seam stub is needed:
        the real probe must veto the classification."""
        config_file = self.root / "services.yaml"
        config_file.write_text("settings: {}\n")
        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "CONFIG_FILE", config_file),
            mock.patch.object(backups, "DATA_DIR", self.root / "empty-data"),
            mock.patch.object(backups, "cfg", lambda: {}),
            mock.patch.object(backups, "user_home", lambda: None),
            mock.patch.object(backups, "run_capped", return_value=MISSING),
        ):
            result = backups.backup_configs()
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "not found")
        self.assertFalse(backups._job_locks["configs"].locked())

    def test_immich_sentinel_with_the_script_on_disk_keeps_raw_failure(self):
        """A still-present backup-db.sh killed mid-run must not be reported
        as "not available" — the operator would go reinstall a script that
        is sitting right there."""
        script = self.root / "backup-db.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "IMMICH_ROOT", self.root),
            mock.patch.object(backups, "IMMICH_SCRIPT", script),
            mock.patch.object(backups, "run_capped", return_value=MISSING),
        ):
            result = backups._backup_immich_script()
        self.assertFalse(result["ok"])
        self.assertNotIn("error", result)
        self.assertEqual(result["message"], "not found")

    def test_tool_on_disk_resolves_bare_names_over_path(self):
        self.assertTrue(backups._tool_on_disk("/usr/bin/tar"))
        self.assertFalse(backups._tool_on_disk(self.root / "gone"))
        self.assertFalse(backups._tool_on_disk(""))
        self.assertFalse(backups._tool_on_disk(None))
        with mock.patch.object(backups.shutil, "which", return_value=None):
            self.assertFalse(backups._tool_on_disk("pg_dump"))
        with mock.patch.object(
            backups.shutil, "which", return_value="/usr/bin/pg_dump",
        ):
            self.assertTrue(backups._tool_on_disk("pg_dump"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
