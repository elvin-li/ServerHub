"""Leftover Backups 500s and silent-loss classes: surrogate-HOME paths in
job results / the page root, and huge JSON int literals wiping whole stores.

Earlier sweeps scrubbed the *rows* (scan_backups), the immich-script path,
and pg_targets' YAML fields.  What was still left:

* a BACKUP_ROOT under an undecodable HOME surfaces as lone surrogates
  (os surrogateescape).  The GET /api/backups route's bare
  ``str(BACKUP_ROOT)`` (the ``root`` field) and every job's *success*
  ``path`` (``str(dest)`` in the postgres, configs, native-immich and stack
  backups) still 500'd Starlette's UTF-8 encode — after the backup itself
  had already succeeded.  The configs job's refusal message interpolated
  ``CONFIG_FILE`` raw on the same class;
* ``json.loads`` converts number literals via ``int(str)``, so one leftover
  >4300-digit number raised the digit-cap *ValueError* — not
  JSONDecodeError — and the except-ValueError fallbacks read the whole
  document as corrupt:
    - panel_status.json / backup_status.json fell to ``{}`` and every
      layer card on the Backups page silently blanked;
    - backup-credentials.json fell to ``{}`` and the target's password
      read back as "" — pg_dump then ran unauthenticated and failed;
    - resolved ``compose config --format json`` refused the whole stack
      backup as ``compose_config_failed`` over a number tar never reads;
    - an inflight marker's ``ts`` made crash recovery forget the recorded
      compose_path, leaving the stack stopped unless it was still
      discoverable.
  All four now parse with the ``parse_int`` hook the notify_channels /
  smart_test_svc / docker_cli stores already use: the one number drops to
  None and the siblings survive.

Stays-immune pins: ``api_error("backup.name_taken", path=…)`` already
scrubs surrogates in hub.errors, and a torn / over-deep document still
reads as ``{}`` — the hook must only soften numbers.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import backups

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_DIGITS = "9" * 5000

TARGET = {
    "id": "teslamate", "host": "localhost", "port": 5432,
    "db": "teslamate", "user": "teslamate", "password_env": "",
}


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then encode."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _SurrogateRootCase(unittest.TestCase):
    """A temp tree whose backups directory name carries a lone surrogate,
    the shape an undecodable HOME takes after os surrogateescape."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-backups-sur-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.backup_root = root / "b\udcffackups"
        self.backup_root.mkdir()


class BackupRootFieldTests(_SurrogateRootCase):
    """GET /api/backups' ``root`` survives a surrogate BACKUP_ROOT."""

    def test_backup_root_text_is_utf8_clean(self):
        with mock.patch.object(backups, "BACKUP_ROOT", self.backup_root):
            text = backups.backup_root_text()
        _starlette({"root": text})
        self.assertNotIn("\udcff", text)

    def test_get_backups_payload_is_encodable(self):
        from hub.routers import settings_api
        immich = {"available": False, "via": "", "last": None, "layers": None}
        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "scan_backups", return_value=[]),
            mock.patch.object(backups, "pg_targets", return_value=[]),
            mock.patch.object(backups, "immich_backup_info", return_value=immich),
        ):
            payload = settings_api.get_backups()
        _starlette(payload)

    def test_clean_root_keeps_its_exact_path(self):
        clean = self.root / "backups"
        clean.mkdir()
        with mock.patch.object(backups, "BACKUP_ROOT", clean):
            self.assertEqual(backups.backup_root_text(), str(clean))


class JobResultPathSurrogateTests(_SurrogateRootCase):
    """Every job's success ``path`` (and the configs refusal) is encodable."""

    def test_pg_dump_success_path_is_encodable(self):
        def fake_run(argv, **_kwargs):
            Path(argv[argv.index("-f") + 1]).write_bytes(b"x" * 64)
            return 0, ""

        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "_pg_env", return_value={}),
            mock.patch.object(backups, "run_capped", fake_run),
        ):
            result = backups._dump_one_postgres(dict(TARGET))
        _starlette(result)
        self.assertTrue(result["ok"])
        self.assertNotIn("\udcff", result["path"])

    def test_configs_success_path_is_encodable(self):
        config_file = self.root / "services.yaml"
        config_file.write_text("settings: {}\n")

        def fake_run(argv, **_kwargs):
            Path(argv[2]).write_bytes(b"x" * 64)  # tar czf <dest> ...
            return 0, ""

        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "CONFIG_FILE", config_file),
            mock.patch.object(backups, "DATA_DIR", self.root / "empty-data"),
            mock.patch.object(backups, "cfg", lambda: {}),
            mock.patch.object(backups, "user_home", lambda: None),
            mock.patch.object(backups, "run_capped", fake_run),
        ):
            result = backups._backup_configs()
        _starlette(result)
        self.assertTrue(result["ok"])
        self.assertNotIn("\udcff", result["path"])

    def test_configs_refusal_message_is_encodable(self):
        missing = self.backup_root / "serv\udcffices.yaml"
        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "CONFIG_FILE", missing),
            mock.patch.object(backups, "DATA_DIR", self.root / "empty-data"),
            mock.patch.object(backups, "cfg", lambda: {}),
            mock.patch.object(backups, "user_home", lambda: None),
        ):
            result = backups._backup_configs()
        _starlette(result)
        self.assertFalse(result["ok"])
        self.assertNotIn("\udcff", result["message"])
        self.assertEqual(
            list(self.backup_root.glob("configs_*")), [],
            "a refused run must not leave a placeholder behind",
        )

    def test_stack_backup_success_path_is_encodable(self):
        compose = self.root / "docker-compose.yml"
        compose.write_text("services: {}\n")
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            if argv[0] == "/usr/bin/tar":
                Path(argv[2]).write_bytes(b"x" * 64)  # tar czf <dest> ...
            return 0, "", ""

        with (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "DATA_DIR", self.root / "data"),
            mock.patch.object(backups, "_find_stack",
                              lambda sid: {"id": sid, "compose_path": str(compose)}),
            mock.patch.object(backups, "_engine_up", lambda force=False: True),
            mock.patch.object(backups, "_stack_mounts",
                              return_value=([], [], "")),
            mock.patch.object(backups, "_run_argv", fake_run),
        ):
            result = backups.backup_stack("media", log=[])
        _starlette(result)
        self.assertTrue(result["ok"])
        self.assertNotIn("\udcff", result["path"])
        # The stop/start contract stays intact around the scrub.
        self.assertTrue(result["stopped"])
        self.assertTrue(result["restarted"])


class CappedJsonIntTests(unittest.TestCase):
    """One >4300-digit literal drops to None; the document survives."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-backups-jsonint-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root

    def test_status_file_siblings_survive_a_huge_literal(self):
        st = self.root / "backup_status.json"
        st.write_text(
            '{"ok": true, "reason": "disk full", "junk": ' + _HUGE_DIGITS + "}"
        )
        got = backups._json_object(st)
        _starlette(got)
        self.assertIs(got["ok"], True)
        self.assertEqual(got["reason"], "disk full")
        self.assertIsNone(got.get("junk"))

    def test_torn_status_file_still_reads_as_empty(self):
        st = self.root / "backup_status.json"
        st.write_text('{"ok": tru')
        self.assertEqual(backups._json_object(st), {})

    def test_over_deep_status_file_still_reads_as_empty(self):
        st = self.root / "backup_status.json"
        st.write_text("[" * 3000 + "]" * 3000)
        self.assertEqual(backups._json_object(st), {})

    def test_pg_password_survives_a_huge_sibling(self):
        cred = self.root / "backup-credentials.json"
        cred.write_text(
            '{"teslamate": {"password": "s3cret"}, "junk": ' + _HUGE_DIGITS + "}"
        )
        cred.chmod(0o600)
        with mock.patch.object(backups, "BACKUP_SECRETS_FILE", cred):
            self.assertEqual(backups._pg_password("teslamate"), "s3cret")

    def test_stack_mounts_survive_a_huge_compose_literal(self):
        resolved = json.dumps({
            "services": {"app": {"volumes": [
                {"type": "volume", "source": "data"},
            ]}},
            "volumes": {"data": {"name": "proj_data"}},
        })
        # Splice an over-cap x- extension value into the document.
        resolved = resolved[:-1] + ', "x-junk": ' + _HUGE_DIGITS + "}"
        with mock.patch.object(
            backups, "_run_argv", return_value=(0, resolved, ""),
        ):
            binds, volumes, err = backups._stack_mounts("/tmp/dc.yml", None)
        self.assertEqual(err, "")
        self.assertEqual(volumes, ["proj_data"])
        self.assertEqual(binds, [])

    def test_recovery_keeps_compose_path_past_a_huge_ts(self):
        data = self.root / "data"
        data.mkdir()
        marker = data / f"{backups._INFLIGHT_PREFIX}media"
        marker.write_text(
            '{"stack": "media", "compose_path": "/srv/dc.yml", "ts": '
            + _HUGE_DIGITS + "}"
        )
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            return 0, "", ""

        with (
            mock.patch.object(backups, "DATA_DIR", data),
            mock.patch.object(backups, "_run_argv", fake_run),
            mock.patch.object(backups, "_find_stack", lambda sid: None),
            mock.patch("hub.alerts.emit_alert", lambda **_kw: None),
        ):
            recovered = backups.recover_interrupted_stack_backups()
        self.assertEqual(len(recovered), 1)
        self.assertIs(recovered[0]["started"], True,
                      "the recorded compose_path must survive the huge ts "
                      "so the stopped stack is started back up")
        self.assertEqual(recovered[0]["detail"], "restarted")
        self.assertIn("/srv/dc.yml", calls[0])
        self.assertFalse(marker.exists())


class NameTakenStaysImmuneTests(unittest.TestCase):
    """hub.errors already scrubs the collision refusal's surrogate path."""

    def test_name_taken_detail_is_encodable(self):
        from hub.errors import api_error
        exc = api_error(
            "backup.name_taken", path="/home/u\udcffser/backups/x.tgz",
        )
        _starlette(exc.detail)
        self.assertEqual(exc.status_code, 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
