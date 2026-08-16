"""Machine-specific backup targets come from services.yaml, not from code.

Until 2026-08 the one-click backups hardcoded this developer machine: the
pg_dump invocation named one specific TeslaMate database (with a literal
fallback password in the source), and the config archive carried two compose
paths from this host's ~/Services.  On any other install those were dead code
at best and, at worst, a "successful" dump of a database that does not exist.
Both are configuration now (``backups:`` in services.yaml), and these tests
pin the seam:

* parsing -- a missing, empty or malformed section degrades entry by entry to
  "no targets" instead of raising on the Backups page;
* equivalence -- the LIVE_* fixtures below are verbatim copies of this host's
  services.yaml, and the argv / restore hint they produce must equal the
  historical hardcoded ones byte for byte.  Fixtures, deliberately not a read
  of the live file: the suite must pass on any machine, so fixture-vs-live
  drift is the operator equivalence check's job, not this file's;
* secrets -- passwords come from data/backup-credentials.json or from the
  environment variable named by ``password_env``, never from services.yaml
  (which the settings export returns verbatim and the config archive tars
  verbatim), and an ambient PGPASSWORD keeps meaning what it always meant;
* no config -- the job answers "not configured" without touching the disk.

Every subprocess is faked; no pg_dump or tar ever runs, and nothing outside
the per-test temp directory is read or written.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import backups  # noqa: E402

#: Verbatim copy of the ``backups.postgres`` entry in this host's
#: services.yaml.  If the live file changes, change this fixture with it.
LIVE_PG_TARGET = {
    "id": "teslamate",
    "host": "localhost",
    "port": 5432,
    "db": "teslamate",
    "user": "teslamate",
}

#: Verbatim copy of ``backups.config_archive.extra_paths`` on this host.
LIVE_EXTRA_PATHS = (
    "/Users/a0000/Services/teslamate/docker-compose.yml",
    "/Users/a0000/Services/music-assistant/docker-compose.yml",
)

#: What hub.backups hardcoded before the targets became configuration.
OLD_HARDCODED_ARGV_PREFIX = [
    "pg_dump", "-h", "localhost", "-U", "teslamate", "-d", "teslamate",
    "-F", "c", "-b", "-f",
]
OLD_TESLAMATE_HINT = (
    "pg_restore -h localhost -U teslamate -d teslamate --clean --if-exists {path}"
)


class PgTargetParsing(unittest.TestCase):
    """pg_targets() accepts what it can and drops what it cannot."""

    def test_absent_section_means_no_targets(self):
        with mock.patch.object(backups, "cfg", lambda: {}):
            self.assertEqual(backups.pg_targets(), [])

    def test_wrong_shapes_mean_no_targets(self):
        for raw in ({}, "text", 7, {"id": "x"}):
            with self.subTest(raw=raw):
                self.assertEqual(backups.pg_targets(raw), [])

    def test_defaults_fill_in(self):
        (t,) = backups.pg_targets([{"id": "app", "db": "appdb"}])
        self.assertEqual(t, {
            "id": "app",
            "host": "localhost",
            "port": 5432,
            "db": "appdb",
            "user": "appdb",
            "password_env": "",
        })

    def test_malformed_entries_are_dropped_individually(self):
        raw = [
            "not-a-mapping",
            {"db": "no-id"},
            {"id": "no-db"},
            {"id": "bad*glob", "db": "d"},
            {"id": "bad/sep", "db": "d"},
            {"id": "has space", "db": "d"},
            {"id": "badport", "db": "d", "port": "many"},
            {"id": "portzero", "db": "d", "port": 0},
            {"id": "porthuge", "db": "d", "port": 70000},
            {"id": "good", "db": "gooddb", "port": "5433"},
            {"id": "good", "db": "duplicate-id"},
        ]
        parsed = backups.pg_targets(raw)
        self.assertEqual([t["id"] for t in parsed], ["good"])
        self.assertEqual(parsed[0]["port"], 5433)

    def test_ids_are_filename_and_glob_safe(self):
        """The id names the artefact and scopes the prune glob; a wildcard or
        separator in it would prune (or write) outside its own lane."""
        for tid in ("*", "a*", "../up", "a/b", "", " ", "a" * 65):
            with self.subTest(tid=tid):
                self.assertEqual(backups.pg_targets([{"id": tid, "db": "d"}]), [])


class _DumpHarness(unittest.TestCase):
    """A fake pg_dump and a scratch BACKUP_ROOT/credentials file."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-pgbak-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.secrets_file = root / "backup-credentials.json"
        self.config: dict = {"backups": {"postgres": [dict(LIVE_PG_TARGET)]}}
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("BACKUP_SECRETS_FILE", self.secrets_file),
        ):
            patch = mock.patch.object(backups, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        cfg_patch = mock.patch.object(backups, "cfg", lambda: self.config)
        cfg_patch.start()
        self.addCleanup(cfg_patch.stop)

        self.calls: list[tuple[list[str], dict]] = []
        self.returncode = 0

        def fake_run(argv, capture_output, text, timeout, env):
            self.calls.append((list(argv), dict(env)))
            if self.returncode == 0:
                Path(argv[-1]).write_bytes(b"x" * 4096)
            return mock.Mock(returncode=self.returncode, stdout="", stderr="boom")

        run_patch = mock.patch.object(backups.subprocess, "run", fake_run)
        run_patch.start()
        self.addCleanup(run_patch.stop)

    def set_secrets(self, data) -> None:
        self.secrets_file.write_text(json.dumps(data), encoding="utf-8")


class PgDumpBehaviour(_DumpHarness):
    def test_argv_equals_the_historical_hardcoded_command(self):
        """This host's live entry (LIVE_PG_TARGET) must reproduce the exact
        command the old code ran, artefact name included."""
        result = backups._backup_postgres()
        self.assertTrue(result["ok"], result)
        (argv, _env), = self.calls
        self.assertEqual(argv[:-1], OLD_HARDCODED_ARGV_PREFIX)
        dest = Path(argv[-1])
        self.assertEqual(dest.parent, self.backup_root)
        self.assertRegex(dest.name, r"\Ateslamate_\d{8}_\d{6}\.sql\.bak\Z")
        self.assertEqual(set(result), {"ok", "path", "message", "size_mb"},
                         "the single-target answer keeps its historical shape")
        self.assertEqual(result["path"], str(dest))

    def test_a_non_default_port_is_passed_explicitly(self):
        self.config["backups"]["postgres"] = [
            {"id": "immichdb", "db": "immich", "port": 5433}
        ]
        backups._backup_postgres()
        (argv, _env), = self.calls
        self.assertIn("-p", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "5433")

    def test_password_comes_from_the_credentials_file(self):
        self.set_secrets({"teslamate": {"password": "from-file"}})
        with mock.patch.dict(os.environ, {"PGPASSWORD": "ambient"}):
            backups._backup_postgres()
        (_argv, env), = self.calls
        self.assertEqual(env["PGPASSWORD"], "from-file",
                         "a per-target stored password is more specific than "
                         "whatever PGPASSWORD happened to be in the panel env")

    def test_password_env_indirection(self):
        self.config["backups"]["postgres"][0]["password_env"] = "TESLA_PG"
        with mock.patch.dict(os.environ, {"TESLA_PG": "indirect"}):
            backups._backup_postgres()
        (_argv, env), = self.calls
        self.assertEqual(env["PGPASSWORD"], "indirect")

    def test_ambient_pgpassword_still_works(self):
        with mock.patch.dict(os.environ, {"PGPASSWORD": "ambient"}):
            backups._backup_postgres()
        (_argv, env), = self.calls
        self.assertEqual(env["PGPASSWORD"], "ambient")

    def test_no_password_anywhere_sets_nothing(self):
        """With no stored secret, no password_env and no ambient variable the
        env is left alone -- pg_dump then relies on ~/.pgpass or trust auth,
        and a literal fallback password never ships in the source again."""
        with mock.patch.dict(os.environ):
            os.environ.pop("PGPASSWORD", None)
            backups._backup_postgres()
        (_argv, env), = self.calls
        self.assertNotIn("PGPASSWORD", env)

    def test_maintenance_env_still_overlays_the_environment(self):
        self.config["settings"] = {"maintenance_env": {"PATH": "/pg17/bin", "N": 1}}
        backups._backup_postgres()
        (_argv, env), = self.calls
        self.assertEqual(env["PATH"], "/pg17/bin")
        self.assertEqual(env["N"], "1")

    def test_not_configured_is_a_sentence_not_a_stack_trace(self):
        self.config = {}
        result = backups._backup_postgres()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "not_configured")
        self.assertEqual(self.calls, [], "no subprocess may run unconfigured")
        self.assertEqual(list(self.backup_root.iterdir()), [],
                         "no placeholder file may be left behind")

    def test_a_failed_dump_discards_its_placeholder(self):
        self.returncode = 1
        result = backups._backup_postgres()
        self.assertFalse(result["ok"])
        self.assertIn("boom", result["message"])
        self.assertEqual(list(self.backup_root.iterdir()), [])

    def test_success_prunes_only_its_own_lane(self):
        for i in range(20):
            (self.backup_root / f"teslamate_202601{i:02d}_000000.sql.bak").write_text("x")
        (self.backup_root / "otherdb_20260101_000000.sql.bak").write_text("x")
        backups._backup_postgres()
        mine = sorted(self.backup_root.glob("teslamate_*.sql.bak"))
        self.assertEqual(len(mine), backups.RETAIN)
        self.assertTrue((self.backup_root / "otherdb_20260101_000000.sql.bak").exists(),
                        "another target's artefacts are not this job's to prune")

    def test_two_targets_dump_two_artifacts(self):
        self.config["backups"]["postgres"].append(
            {"id": "seconddb", "db": "second", "port": 5433}
        )
        result = backups._backup_postgres()
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["targets"]), 2)
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(list(self.backup_root.glob("teslamate_*.sql.bak")))
        self.assertTrue(list(self.backup_root.glob("seconddb_*.sql.bak")))

    def test_multi_target_failure_fails_the_aggregate(self):
        self.config["backups"]["postgres"].append({"id": "seconddb", "db": "second"})
        original = backups.subprocess.run

        def second_fails(argv, **kwargs):
            result = original(argv, **kwargs)
            if "seconddb" in argv[-1]:
                Path(argv[-1]).unlink(missing_ok=True)
                return mock.Mock(returncode=1, stdout="", stderr="down")
            return result

        with mock.patch.object(backups.subprocess, "run", second_fails):
            result = backups._backup_postgres()
        self.assertFalse(result["ok"])
        self.assertIn("seconddb", result["message"])


class RestoreHints(unittest.TestCase):
    def setUp(self):
        self.config: dict = {"backups": {"postgres": [dict(LIVE_PG_TARGET)]}}
        patch = mock.patch.object(backups, "cfg", lambda: self.config)
        patch.start()
        self.addCleanup(patch.stop)

    def test_this_hosts_hint_equals_the_historical_one(self):
        self.assertEqual(
            backups.restore_hint("teslamate_20260813_120000.sql.bak"),
            OLD_TESLAMATE_HINT,
        )

    def test_non_default_port_appears_in_the_hint(self):
        self.config["backups"]["postgres"] = [
            {"id": "immichdb", "db": "immich", "user": "immich", "port": 5433}
        ]
        self.assertEqual(
            backups.restore_hint("immichdb_20260813_120000.sql.bak"),
            "pg_restore -h localhost -p 5433 -U immich -d immich "
            "--clean --if-exists {path}",
        )

    def test_fixed_hints_still_answer(self):
        self.assertTrue(backups.restore_hint("immich_x.sql.gz").startswith("gunzip"))
        self.assertTrue(backups.restore_hint("configs_x.tgz").startswith("mkdir"))

    def test_an_unconfigured_dump_name_gets_no_guessed_connection(self):
        self.config = {}
        self.assertEqual(backups.restore_hint("teslamate_x.sql.bak"), "")
        self.assertEqual(backups.restore_hint("randomfile.tgz"), "")


class ConfigArchivePaths(unittest.TestCase):
    """extra_paths parsing plus the tar member list of _backup_configs()."""

    def test_extra_paths_parse_expand_and_dedupe(self):
        raw = {"backups": {"config_archive": {"extra_paths": [
            "~/Services/app/docker-compose.yml",
            "/abs/two.yml",
            "/abs/two.yml",
            "relative/nope.yml",
            "",
            42,
        ]}}}
        with mock.patch.object(backups, "cfg", lambda: raw):
            parsed = backups.config_archive_extra_paths()
        self.assertEqual(parsed, [
            Path(os.path.expanduser("~/Services/app/docker-compose.yml")),
            Path("/abs/two.yml"),
        ])

    def test_malformed_sections_mean_no_extras(self):
        for bad in ({}, {"backups": []}, {"backups": {"config_archive": {"extra_paths": "x"}}}):
            with self.subTest(cfg=bad):
                with mock.patch.object(backups, "cfg", lambda bad=bad: bad):
                    self.assertEqual(backups.config_archive_extra_paths(), [])

    def test_tar_members_are_config_plus_existing_extras(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfgbak-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        backup_root = root / "backups"
        backup_root.mkdir()
        config_file = root / "services.yaml"
        config_file.write_text("settings: {}\n")
        present = root / "present-compose.yml"
        present.write_text("services: {}\n")
        missing = root / "missing-compose.yml"
        raw = {"backups": {"config_archive": {"extra_paths": [str(present), str(missing)]}}}

        calls: list[list[str]] = []

        def fake_run(argv, capture_output, text, timeout):
            calls.append(list(argv))
            Path(argv[2]).write_bytes(b"x" * 2048)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(backups, "BACKUP_ROOT", backup_root), \
             mock.patch.object(backups, "CONFIG_FILE", config_file), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(backups, "cfg", lambda: raw), \
             mock.patch.object(backups.subprocess, "run", fake_run):
            result = backups._backup_configs()

        self.assertTrue(result["ok"], result)
        (argv,) = calls
        self.assertEqual(argv[:2], ["/usr/bin/tar", "czf"])
        members = argv[3:]
        self.assertIn(str(config_file), members)
        self.assertIn(str(present), members)
        self.assertNotIn(str(missing), members,
                         "missing extras are skipped at archive time")

    def test_still_refuses_without_the_config_file(self):
        """The 'config archive without the config' guard survives the extras
        becoming configurable."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfgbak-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        present = root / "present-compose.yml"
        present.write_text("services: {}\n")
        raw = {"backups": {"config_archive": {"extra_paths": [str(present)]}}}
        ran = mock.Mock()
        with mock.patch.object(backups, "BACKUP_ROOT", root / "backups"), \
             mock.patch.object(backups, "CONFIG_FILE", root / "no-such.yaml"), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(backups, "cfg", lambda: raw), \
             mock.patch.object(backups.subprocess, "run", ran):
            result = backups._backup_configs()
        self.assertFalse(result["ok"])
        ran.assert_not_called()


class ConfigArchiveDataState(unittest.TestCase):
    """The data/ credential and state files ride in the config archive.

    Losing data/ is an admin lockout (twofa.json holds the TOTP secrets) plus
    every integration token gone -- services.yaml alone does not bring a
    panel back.  Selection is a rule, not an allowlist: small regular files
    directly under data/, minus the bulk/derived/harmful-to-restore classes.
    These tests pin both directions of the rule, the untouched
    no-services.yaml refusal, and -- with one real tar run -- that the 0600
    modes survive the round trip.
    """

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfgdata-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.data = root / "data"
        self.data.mkdir()
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.config_file = root / "services.yaml"
        self.config_file.write_text("settings: {}\n")
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("CONFIG_FILE", self.config_file),
            ("DATA_DIR", self.data),
        ):
            patch = mock.patch.object(backups, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        cfg_patch = mock.patch.object(backups, "cfg", lambda: {})
        cfg_patch.start()
        self.addCleanup(cfg_patch.stop)
        # Keep the real ~/Library/LaunchAgents out of these archives: the
        # agent manifest has its own tests, and this class is about data/.
        agents_patch = mock.patch.object(backups, "_wanted_agent",
                                         lambda *_a, **_k: False)
        agents_patch.start()
        self.addCleanup(agents_patch.stop)

    SECRETS = (
        "twofa.json",
        "api-keys.json",
        "notify-credentials.json",
        "backup-credentials.json",
        "service-credentials.json",
        ".session-secret",
        ".local-client-token",
        "wireguard-peers.json",
        "alert_state.json",
    )

    def test_every_lockout_class_file_is_selected(self):
        for name in self.SECRETS:
            (self.data / name).write_text("s")
        self.assertEqual(
            backups.data_state_paths(),
            sorted(self.data / name for name in self.SECRETS),
        )

    def test_bulk_derived_and_transient_files_stay_out(self):
        (self.data / "twofa.json").write_text("keep")
        rejects = (
            "alerts.jsonl",                          # alert history
            "metrics-5m.jsonl",                      # metrics bulk
            "auth-audit.jsonl.bak-20260805-112015",  # rotated audit log
            "services.yaml.bak.1786507185",          # pre-image of a live member
            ".services.yaml.lock",                   # flock target
            "wireguard.lock",
            "audit_monitor.out",                     # stray process log
            "stack-backup-inflight-immich",          # crash marker
        )
        for name in rejects:
            (self.data / name).write_text("x")
        (self.data / "huge.blob").write_bytes(b"\0" * (backups._DATA_FILE_MAX + 1))
        (self.data / "a-link.json").symlink_to(self.data / "twofa.json")
        (self.data / "nested").mkdir()
        (self.data / "nested" / "deep.json").write_text("x")
        self.assertEqual(backups.data_state_paths(), [self.data / "twofa.json"])

    def test_archive_members_are_config_then_data_then_extras(self):
        for name in ("twofa.json", "api-keys.json"):
            (self.data / name).write_text("s")
        extra = self.root / "compose.yml"
        extra.write_text("services: {}\n")
        cfg = {"backups": {"config_archive": {"extra_paths": [str(extra)]}}}
        calls: list[list[str]] = []

        def fake_run(argv, capture_output, text, timeout):
            calls.append(list(argv))
            Path(argv[2]).write_bytes(b"x" * 2048)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(backups, "cfg", lambda: cfg), \
             mock.patch.object(backups.subprocess, "run", fake_run):
            result = backups._backup_configs()
        self.assertTrue(result["ok"], result)
        (argv,) = calls
        self.assertEqual(argv[3:], [
            str(self.config_file),
            str(self.data / "api-keys.json"),
            str(self.data / "twofa.json"),
            str(extra),
        ])

    def test_data_files_alone_never_satisfy_the_config_guard(self):
        """No services.yaml still means refusal, however rich data/ is: a
        config archive without the config stays a failure, not a partial
        success."""
        (self.data / "twofa.json").write_text("s")
        ran = mock.Mock()
        with mock.patch.object(backups, "CONFIG_FILE", self.root / "gone.yaml"), \
             mock.patch.object(backups.subprocess, "run", ran):
            result = backups._backup_configs()
        self.assertFalse(result["ok"])
        ran.assert_not_called()

    def test_owner_only_modes_survive_a_real_tar(self):
        """One real tar run: the 0600 secrets must be recorded 0600 in the
        archive (tar restores recorded modes), and the archive itself must be
        0600 -- it now carries the TOTP secrets and every integration token."""
        import tarfile

        secret = self.data / "twofa.json"
        secret.write_text('{"admin": "totp"}')
        secret.chmod(0o600)
        helper = self.data / "pf-anchor-keepalive.sh"
        helper.write_text("#!/bin/sh\n")
        helper.chmod(0o755)

        result = backups._backup_configs()
        self.assertTrue(result["ok"], result)
        archive = Path(result["path"])
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        modes = {}
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                modes[Path(member.name).name] = member.mode & 0o777
        self.assertEqual(modes.get("twofa.json"), 0o600)
        self.assertEqual(modes.get("pf-anchor-keepalive.sh"), 0o755)
        self.assertIn("services.yaml", modes)


if __name__ == "__main__":
    unittest.main()
