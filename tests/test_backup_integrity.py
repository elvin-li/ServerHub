"""A backup must not overwrite another backup, nor claim success without the config.

Three defects, all of which produced a green row in the backups table:

  * `_private_dest` opened the destination `O_TRUNC`.  The stamp in a backup name
    has second resolution, so two runs starting in the same second resolved to the
    same path and the second truncated the first.  Both exited 0, both saw a
    non-empty file, so both reported success and one archive was unrestorable.
    The `backup-pg` / `backup-cfg` maintenance tasks shell out to their own python
    process, so a lock cannot prevent this -- refusing to reuse a name can.
  * `backup_configs` then threw the collision-free path away: it called
    `_private_dest(dest)` for the side effect and handed `tar` the *original*
    name, so the guard above was inert in the one job that needed it.
  * `backup_configs` accepted "at least one file exists".  With services.yaml
    missing but a single plist present, tar succeeded and a config archive with no
    config in it was reported as a good backup.

Nothing here runs a real pg_dump or tar; `subprocess.run` is patched and every
path is a temp directory.
"""
from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import backups  # noqa: E402


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class PrivateDestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_it_creates_the_file_owner_only(self):
        dest = backups._private_dest(self.root / "configs_20260101_000000.tgz")
        self.assertTrue(dest.exists())
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o600)

    def test_it_never_truncates_an_existing_backup(self):
        first = self.root / "configs_20260101_000000.tgz"
        first.write_bytes(b"a real archive")
        second = backups._private_dest(first)
        self.assertNotEqual(
            second,
            first,
            "the second run was handed the first run's path and would truncate it",
        )
        self.assertEqual(first.read_bytes(), b"a real archive")

    def test_the_alternate_name_keeps_the_full_extension(self):
        base = self.root / "teslamate_20260101_000000.sql.bak"
        base.write_bytes(b"x")
        alt = backups._private_dest(base)
        self.assertEqual(alt.name, "teslamate_20260101_000000-2.sql.bak")

    def test_collisions_keep_stepping(self):
        base = self.root / "configs_20260101_000000.tgz"
        names = []
        for _ in range(4):
            names.append(backups._private_dest(base).name)
        self.assertEqual(len(set(names)), 4, names)

    def test_concurrent_callers_get_distinct_paths(self):
        base = self.root / "configs_20260101_000000.tgz"
        got: list[Path] = []
        lock = threading.Lock()

        def claim():
            path = backups._private_dest(base)
            with lock:
                got.append(path)

        threads = [threading.Thread(target=claim) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
        self.assertEqual(
            len(set(got)), 8, f"two threads were handed the same filename: {got}"
        )

    def test_it_refuses_rather_than_reusing_when_every_name_is_taken(self):
        base = self.root / "configs_20260101_000000.tgz"
        for _ in range(backups._MAX_COLLISIONS):
            backups._private_dest(base)
        with self.assertRaises(HTTPException) as ctx:
            backups._private_dest(base)
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(ctx.exception.detail["code"], "backup.name_taken")


class ConfigBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        patcher = patch.object(backups, "BACKUP_ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _config(self, exists: bool) -> Path:
        path = self.root / "services.yaml"
        if exists:
            path.write_text("settings: {}\n")
        return path

    def test_it_refuses_when_the_config_file_is_missing(self):
        # The whole point of this job is services.yaml. Without it the archive is
        # a handful of plists that nobody would restore from.
        with patch.object(backups, "CONFIG_FILE", self._config(False)):
            with patch.object(backups.subprocess, "run") as run:
                result = backups.backup_configs()
        self.assertFalse(result["ok"])
        self.assertIn("services.yaml", result["message"])
        self.assertFalse(run.called, "tar ran without the file it exists to archive")

    def test_it_writes_to_the_collision_free_path(self):
        config = self._config(True)
        seen: list[str] = []

        def _tar(cmd, *a, **k):
            # cmd is ["tar", "czf", <dest>, *members]
            seen.append(cmd[2])
            Path(cmd[2]).write_bytes(b"archive bytes")
            return _Proc(0)

        with patch.object(backups, "CONFIG_FILE", config):
            with patch.object(backups.subprocess, "run", _tar):
                first = backups.backup_configs()
                # Force the collision the second-resolution stamp allows.
                with patch.object(backups.time, "strftime", return_value="20260101_000000"):
                    second = backups.backup_configs()
                    third = backups.backup_configs()

        self.assertTrue(first["ok"] and second["ok"] and third["ok"])
        self.assertEqual(
            len(set(seen)), 3, f"tar was pointed at the same file twice: {seen}"
        )
        self.assertEqual(second["path"], seen[1])
        self.assertNotEqual(second["path"], third["path"])
        for path in seen:
            self.assertEqual(Path(path).read_bytes(), b"archive bytes")

    def test_a_failed_tar_leaves_no_placeholder_behind(self):
        config = self._config(True)
        with patch.object(backups, "CONFIG_FILE", config):
            with patch.object(backups.subprocess, "run", return_value=_Proc(2, stderr="boom")):
                result = backups.backup_configs()
        self.assertFalse(result["ok"])
        self.assertEqual(list(self.root.glob("configs_*.tgz")), [])

    def test_a_second_concurrent_run_is_refused(self):
        config = self._config(True)
        reached = threading.Event()
        release = threading.Event()

        def _slow_tar(cmd, *a, **k):
            reached.set()
            release.wait(20)
            Path(cmd[2]).write_bytes(b"archive")
            return _Proc(0)

        out: list = []
        with patch.object(backups, "CONFIG_FILE", config):
            with patch.object(backups.subprocess, "run", _slow_tar):
                worker = threading.Thread(
                    target=lambda: out.append(backups.backup_configs()), daemon=True
                )
                worker.start()
                try:
                    self.assertTrue(reached.wait(20))
                    with self.assertRaises(HTTPException) as ctx:
                        backups.backup_configs()
                finally:
                    release.set()
                    worker.join(30)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "backup.busy")
        self.assertTrue(out and out[0]["ok"])

    def test_the_lock_is_released_after_a_failure(self):
        config = self._config(True)
        with patch.object(backups, "CONFIG_FILE", config):
            with patch.object(backups.subprocess, "run", return_value=_Proc(1)):
                self.assertFalse(backups.backup_configs()["ok"])
            def _tar(cmd, *a, **k):
                Path(cmd[2]).write_bytes(b"ok")
                return _Proc(0)

            with patch.object(backups.subprocess, "run", _tar):
                self.assertTrue(backups.backup_configs()["ok"])


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for target, replacement in (
            ("BACKUP_ROOT", self.root),
            # create_app() gives serverhub.* a real stderr handler, so each pruned
            # fixture file would print into the suite's output. A noisy run is a run
            # where a genuine warning goes unnoticed.
            ("log", None),
        ):
            patcher = (
                patch.object(backups, target, replacement)
                if replacement is not None
                else patch.object(backups, target)
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_it_keeps_the_newest_and_drops_the_rest(self):
        for day in range(1, backups.RETAIN + 6):
            (self.root / f"configs_202601{day:02d}_000000.tgz").write_bytes(b"x")
        backups._prune("configs_*.tgz")
        left = sorted(p.name for p in self.root.glob("configs_*.tgz"))
        self.assertEqual(len(left), backups.RETAIN)
        # Newest kept, oldest gone: the stamp is fixed-width so name order is time order.
        self.assertIn(f"configs_202601{backups.RETAIN + 5:02d}_000000.tgz", left)
        self.assertNotIn("configs_20260101_000000.tgz", left)

    def test_it_only_touches_its_own_job(self):
        # BACKUP_ROOT also holds other tooling's files and large manual dumps; a
        # blanket glob would delete them.
        keep = [
            "teslamate_preimmich_20260726_105632.dump",
            "grafana.ini.bak-20260808-093407",
            "immich_20260809_033702.sql.gz",
        ]
        for name in keep:
            (self.root / name).write_bytes(b"x")
        for day in range(1, backups.RETAIN + 6):
            (self.root / f"configs_202601{day:02d}_000000.tgz").write_bytes(b"x")
        backups._prune("configs_*.tgz")
        for name in keep:
            self.assertTrue((self.root / name).exists(), f"{name} was pruned")

    def test_it_does_nothing_below_the_threshold(self):
        for day in range(1, 5):
            (self.root / f"teslamate_202601{day:02d}_000000.sql.bak").write_bytes(b"x")
        backups._prune("teslamate_*.sql.bak")
        self.assertEqual(len(list(self.root.glob("teslamate_*.sql.bak"))), 4)


class RestoreHintTests(unittest.TestCase):
    """A backup nobody knows how to restore is a directory full of reassurance.

    No restore path existed anywhere in this project -- no code, no script, no
    note -- and the TeslaMate artefact actively misleads: `pg_dump -F c` writes a
    custom-format archive, so its `.sql.bak` name points a restorer at `psql`,
    which cannot read it.  The command now travels with the file.
    """

    def test_the_pg_dump_hint_uses_pg_restore_not_psql(self):
        hint = backups.restore_hint("teslamate_20260101_000000.sql.bak")
        self.assertIn("pg_restore", hint)
        self.assertNotRegex(
            hint,
            r"\bpsql\b",
            "a -F c custom-format archive cannot be replayed with psql",
        )

    def test_the_immich_hint_matches_that_dump_s_actual_shape(self):
        # Plain SQL, gzipped, PG18 on 5433 -- not the default port.
        hint = backups.restore_hint("immich_20260101_000000.sql.gz")
        self.assertIn("gunzip", hint)
        self.assertIn("psql", hint)
        self.assertIn("5433", hint)

    def test_the_config_hint_does_not_extract_over_the_filesystem_root(self):
        # tar strips the leading "/" from absolute members, so `tar xzf ... -C /`
        # would be both wrong and dangerous to suggest.
        hint = backups.restore_hint("configs_20260101_000000.tgz")
        self.assertIn("tar xzf", hint)
        self.assertNotRegex(hint, r"-C\s+/\s*$")
        self.assertIn("/tmp/", hint)

    def test_the_config_rotation_hint_names_the_live_config(self):
        hint = backups.restore_hint("services.yaml.bak.1786268205")
        self.assertIn(str(backups.CONFIG_FILE), hint)

    def test_an_unrecognised_artefact_gets_no_invented_hint(self):
        self.assertEqual(backups.restore_hint("kiro-audit-configs.tgz"), "")
        self.assertEqual(backups.restore_hint("random.zip"), "")

    def test_the_listing_interpolates_the_real_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artefact = root / "configs_20260101_000000.tgz"
            artefact.write_bytes(b"x")
            with patch.object(backups, "BACKUP_ROOT", root):
                with patch.object(backups, "DATA_DIR", root):
                    rows = [r for r in backups.scan_backups() if r["name"] == artefact.name]
        self.assertTrue(rows, "the fixture artefact was not listed")
        self.assertIn(str(artefact), rows[0]["restore"])
        self.assertNotIn("{path}", rows[0]["restore"])

    def test_every_hint_carries_the_path_placeholder(self):
        # A hint that forgets it renders as a command with no file in it.
        for prefix, template in backups._RESTORE_HINTS:
            with self.subTest(prefix=prefix):
                self.assertIn("{path}", template)


class BackupsAreNotBrowsableTests(unittest.TestCase):
    """PROTECTED_PREFIXES withholds services.yaml; the tarball holds it verbatim.

    `configs_*.tgz` matched no deny-list entry, so /api/files/download handed any
    signed-in session the admin password hash and every token inside an archive.
    The deny-list protected the original and not the copy.
    """

    def test_the_backup_directory_is_protected(self):
        from hub import files_svc

        self.assertTrue(files_svc.is_protected(backups.BACKUP_ROOT))

    def test_a_config_archive_is_not_downloadable(self):
        from hub import files_svc

        self.assertTrue(
            files_svc.is_protected(backups.BACKUP_ROOT / "configs_20260809_040501.tgz")
        )

    def test_a_database_dump_is_not_downloadable(self):
        from hub import files_svc

        self.assertTrue(
            files_svc.is_protected(backups.BACKUP_ROOT / "teslamate_20260809_040501.sql.bak")
        )

    def test_resolving_one_directly_is_refused(self):
        # The listing filter is not the only way in; _resolve_safe is the choke
        # point every download/delete/rename passes through.
        from hub import files_svc

        with self.assertRaises(HTTPException):
            files_svc._resolve_safe(str(backups.BACKUP_ROOT / "configs_x.tgz"))

    def test_ordinary_media_is_still_browsable(self):
        # Guards the guard: a deny-list that matches everything is not a fix.
        from hub import files_svc

        self.assertFalse(
            files_svc.is_protected(Path.home() / "Services" / "media" / "movie.mkv")
        )


if __name__ == "__main__":
    unittest.main()
