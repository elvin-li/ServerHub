"""Immich database backup on the Backups page.

The host already had ``~/Services/immich/backup-db.sh`` (PG18, gzip SQL,
``immich_*.sql.gz``) and a nightly LaunchAgent.  The panel's one-click
PostgreSQL button only dumped TeslaMate after targets became configuration.
These tests pin the rediscovered Immich path: discover the script or a native
PG18 dump, never put the password on argv, and refuse when neither is present.
"""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import backups  # noqa: E402


class ImmichInfoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.immich = root / "immich"
        self.immich.mkdir()
        self.addCleanup(self.tmp.cleanup)
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "IMMICH_ROOT", self.immich),
            mock.patch.object(backups, "IMMICH_SCRIPT", self.immich / "backup-db.sh"),
            mock.patch.object(backups, "IMMICH_DB_ENV", self.immich / "db.env"),
            mock.patch.object(backups, "_PG18_DUMPS", (root / "no-such-pg_dump",)),
            mock.patch.object(backups, "PHOTOSHUB_CFG", root / "no-photoshub.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", root / "no-photoshub-state"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_unavailable_when_nothing_is_installed(self):
        info = backups.immich_backup_info()
        self.assertFalse(info["available"])
        self.assertEqual(info["via"], "")
        self.assertIsNone(info["last"])
        self.assertIsNone(info["layers"])

    def test_script_wins_and_reports_the_newest_dump(self):
        script = self.immich / "backup-db.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        older = self.backup_root / "immich_20260101_000000.sql.gz"
        newer = self.backup_root / "immich_20260816_033704.sql.gz"
        older.write_bytes(b"old")
        newer.write_bytes(b"new")
        info = backups.immich_backup_info()
        self.assertTrue(info["available"])
        self.assertEqual(info["via"], "script")
        self.assertEqual(info["last"]["name"], newer.name)

    def test_native_when_pg18_and_db_env_exist(self):
        pg18 = Path(self.tmp.name) / "pg_dump"
        pg18.write_text("#!/bin/sh\n")
        pg18.chmod(0o755)
        (self.immich / "db.env").write_text(
            "DB_URL=postgresql://immich:s3cret@127.0.0.1:5433/immich\n"
        )
        with mock.patch.object(backups, "_PG18_DUMPS", (pg18,)):
            info = backups.immich_backup_info()
        self.assertTrue(info["available"])
        self.assertEqual(info["via"], "native")

    def test_layers_come_from_photoshub_config_without_walking_trees(self):
        vault = Path(self.tmp.name) / "vault"
        (vault / "Photos Library.photoslibrary").mkdir(parents=True)
        (vault / "PhotosBridge" / "library").mkdir(parents=True)
        media = vault / "immich"
        (media / "thumbs").mkdir(parents=True)
        (media / "encoded-video").mkdir()
        hub = Path(self.tmp.name) / "PhotosHub"
        (hub / "config").mkdir(parents=True)
        (hub / "state").mkdir()
        (hub / "config" / "config.json").write_text(
            json.dumps({
                "photos_library": str(vault / "Photos Library.photoslibrary"),
                "bridge_dir": str(vault / "PhotosBridge" / "library"),
                "immich": {"media_location": str(media)},
            }),
            encoding="utf-8",
        )
        (hub / "state" / "backup_status.json").write_text(
            json.dumps({"ok": True, "last_success": "2026-08-16T03:20:00", "size_human": "12G"}),
            encoding="utf-8",
        )
        (hub / "state" / "panel_status.json").write_text(
            json.dumps({
                "originals": {"local_original_pct": 68.17, "originals_human": "22.7 GB", "assets_active": 5461},
                "bridge": {"last_success": "2026-08-16T17:15:06", "exported_files": 3703},
            }),
            encoding="utf-8",
        )
        with (
            mock.patch.object(backups, "PHOTOSHUB_CFG", hub / "config" / "config.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", hub / "state"),
        ):
            layers = backups.immich_layers()
        self.assertTrue(layers["originals"]["present"])
        self.assertTrue(layers["bridge"]["present"])
        self.assertTrue(layers["generated"]["present"])
        self.assertEqual(
            [d["name"] for d in layers["generated"]["dirs"] if d["present"]],
            ["thumbs", "encoded-video"],
        )
        self.assertEqual(layers["originals"]["backup"]["size_human"], "12G")
        self.assertEqual(layers["originals"]["pct"], 68.17)
        self.assertEqual(layers["bridge"]["exported_files"], 3703)
        self.assertNotIn("secret", json.dumps(layers))


class ImmichDumpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.immich = root / "immich"
        self.immich.mkdir()
        self.addCleanup(self.tmp.cleanup)
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "IMMICH_ROOT", self.immich),
            mock.patch.object(backups, "IMMICH_SCRIPT", self.immich / "backup-db.sh"),
            mock.patch.object(backups, "IMMICH_DB_ENV", self.immich / "db.env"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_not_configured_does_not_touch_disk(self):
        with mock.patch.object(backups, "_PG18_DUMPS", (Path(self.tmp.name) / "missing",)):
            result = backups.backup_immich()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "not_configured")
        self.assertEqual(list(self.backup_root.iterdir()), [])

    def test_script_path_is_invoked_and_password_stays_off_argv(self):
        script = self.immich / "backup-db.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        artefact = self.backup_root / "immich_20260816_120000.sql.gz"

        def fake_run(argv, **kwargs):
            artefact.write_bytes(gzip.compress(b"-- PostgreSQL database dump complete\n"))
            return mock.Mock(returncode=0, stdout="immich backup ok", stderr="")

        run = mock.Mock(side_effect=fake_run)
        with mock.patch.object(backups.subprocess, "run", run):
            result = backups.backup_immich()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["path"].endswith(".sql.gz"))
        argv = run.call_args.args[0]
        self.assertEqual(argv, [str(script)])
        self.assertNotIn("s3cret", " ".join(argv))

    def _fake_pg_dump(self, body: str) -> Path:
        """A real executable standing in for pg_dump.

        Deliberately not a mocked ``Popen``: the streaming path is the part that
        can deadlock or exhaust memory, and a mock replaces exactly that.  The
        script records its argv and PGPASSWORD so the caller can still assert
        the password never reached the command line.
        """
        pg18 = Path(self.tmp.name) / "pg_dump"
        self.argv_log = Path(self.tmp.name) / "argv.log"
        pg18.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > {self.argv_log}\n'
            f'printf "PGPASSWORD=%s\\n" "$PGPASSWORD" >> {self.argv_log}\n'
            f"{body}\n"
        )
        pg18.chmod(0o755)
        (self.immich / "db.env").write_text(
            "DB_URL=postgresql://immich:s3cret@127.0.0.1:5433/immich\n"
        )
        return pg18

    def _recorded(self) -> list[str]:
        return self.argv_log.read_text().splitlines()

    def _alive(self, pg18: Path) -> str:
        return subprocess.run(
            ["/usr/bin/pgrep", "-f", str(pg18)], capture_output=True, text=True
        ).stdout.strip()

    def test_native_dump_uses_pg18_and_pgpassword(self):
        payload = "-- header\n-- PostgreSQL database dump complete\n"
        pg18 = self._fake_pg_dump(f"printf '%s' '{payload}'")
        with mock.patch.object(backups, "_PG18_DUMPS", (pg18,)):
            result = backups.backup_immich()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["path"].endswith(".sql.gz"))
        dest = Path(result["path"])
        self.assertTrue(dest.is_file())
        # The artefact really is gzip, and really holds the dump.
        self.assertEqual(gzip.decompress(dest.read_bytes()).decode(), payload)
        self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
        recorded = self._recorded()
        self.assertEqual(recorded[:6], ["-h", "127.0.0.1", "-p", "5433", "-U", "immich"])
        self.assertNotIn("s3cret", " ".join(recorded[:-1]))
        self.assertEqual(recorded[-1], "PGPASSWORD=s3cret")

    def test_a_chatty_dump_does_not_deadlock(self):
        """pg_dump warnings must not wedge the dump.

        The pipeline this replaced could not read pg_dump's stderr until gzip
        had exited, and gzip could not exit until pg_dump closed stdout, so
        more than a pipe buffer of warnings hung the backup until its timeout.
        200 KiB is comfortably past the 64 KiB buffer.
        """
        payload = "-- PostgreSQL database dump complete\n"
        pg18 = self._fake_pg_dump(
            "i=0; while [ $i -lt 4000 ]; do "
            "printf 'WARNING: a fifty-byte-ish line of pg_dump noise\\n' >&2; "
            "i=$((i+1)); done\n"
            f"printf '%s' '{payload}'"
        )
        with mock.patch.object(backups, "_PG18_DUMPS", (pg18,)):
            result = backups.backup_immich()
        self.assertTrue(result["ok"], result)
        self.assertEqual(gzip.decompress(Path(result["path"]).read_bytes()).decode(), payload)

    def test_a_truncated_dump_is_refused_and_leaves_nothing_behind(self):
        """No closing marker means the dump stopped early — keeping it lies."""
        pg18 = self._fake_pg_dump("printf '%s' '-- header, then the server went away'")
        with mock.patch.object(backups, "_PG18_DUMPS", (pg18,)):
            result = backups.backup_immich()
        self.assertFalse(result["ok"], result)
        self.assertEqual(list(self.backup_root.glob("immich_*")), [])

    def test_a_failing_dump_is_refused_with_its_stderr(self):
        pg18 = self._fake_pg_dump(
            "echo 'pg_dump: error: connection to server failed' >&2; exit 1"
        )
        with mock.patch.object(backups, "_PG18_DUMPS", (pg18,)):
            result = backups.backup_immich()
        self.assertFalse(result["ok"], result)
        self.assertIn("connection to server failed", result["message"])
        self.assertEqual(list(self.backup_root.glob("immich_*")), [])

    def test_a_dump_that_stalls_mid_stream_hits_its_deadline(self):
        """The deadline must interrupt a blocked read, not wait politely for it.

        This is the shape that matters: pg_dump emits a little, then hangs on a
        lock. ``read()`` blocks, so a deadline checked between reads is never
        reached -- the request thread and the ``_only_one`` job lock are held
        until the process restarts, and the Backups button stays dead.  The
        assertion is therefore that the call *returns at all*.
        """
        pg18 = self._fake_pg_dump("printf '%s' '-- header, then a lock wait'; sleep 60")
        started = time.monotonic()
        with (
            mock.patch.object(backups, "_PG18_DUMPS", (pg18,)),
            mock.patch.object(backups, "_IMMICH_TIMEOUT", 2),
        ):
            result = backups.backup_immich()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 30, "the deadline did not interrupt the blocked read")
        self.assertFalse(result["ok"], result)
        self.assertIn("timed out", result["message"])
        self.assertEqual(list(self.backup_root.glob("immich_*")), [])
        self.assertEqual(self._alive(pg18), "", "pg_dump outlived the request")
        # The job lock is free, so the operator can retry immediately.
        with backups._only_one("immich"):
            pass

    def test_a_slow_exit_does_not_destroy_a_complete_dump(self):
        """Every byte arrived; the process just took its time going away.

        Judging the artefact by pg_dump's exit status meant a complete, valid
        backup was deleted because waiting for the exit timed out.
        """
        payload = "-- PostgreSQL database dump complete\n"
        pg18 = self._fake_pg_dump(f"printf '%s' '{payload}'; exec sleep 8")
        real_wait = subprocess.Popen.wait

        def impatient(self_, timeout=None):
            # Stand in for "the exit took longer than we were willing to wait".
            if timeout == 30:
                raise subprocess.TimeoutExpired("pg_dump", 30)
            return real_wait(self_, timeout=timeout)

        with (
            mock.patch.object(backups, "_PG18_DUMPS", (pg18,)),
            mock.patch.object(subprocess.Popen, "wait", impatient),
        ):
            result = backups.backup_immich()
        self.assertTrue(result["ok"], result)
        self.assertEqual(gzip.decompress(Path(result["path"]).read_bytes()).decode(), payload)

    def test_conn_parser_does_not_echo_the_password(self):
        (self.immich / "db.env").write_text(
            "DB_URL=postgresql://immich:s3cret@127.0.0.1:5433/immich\n"
        )
        conn = backups._immich_conn()
        self.assertEqual(conn["user"], "immich")
        self.assertEqual(conn["db"], "immich")
        self.assertEqual(conn["port"], 5433)
        self.assertEqual(conn["password"], "s3cret")


if __name__ == "__main__":
    unittest.main()
