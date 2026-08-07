"""services.yaml and its backups must never exist world-readable, even briefly.

This file is the most sensitive thing ServerHub writes: it holds the admin
password hash from the moment setup runs, plus per-service credentials and the
Cloudflare tunnel token.  Three write paths create or replace it --
``_bootstrap`` on first run, ``save_full`` on every settings save, and the
timestamped backup ``save_full`` takes first -- and all three used to create the
file at whatever the umask allowed and tighten it with a follow-up ``chmod``.
On this host that means 0644 for the duration of the write.

``shutil.copy2`` was the worse of the two: it copies the *source* file's mode,
so bootstrapping from the repo's world-readable ``services.yaml.example``
produced a world-readable config that only became private one syscall later.

Testing approach mirrors ``test_secret_file_modes.py``: rather than racing a
concurrent reader, neutralise every chmod and open the umask wide, then assert
the file is *still* 0600.  A path that is secure at creation passes; a path that
leans on a follow-up chmod is left at 0666 -- precisely what a reader in the
window would have found.  This keeps the assertion on the real property (safe
when it first exists, not safe eventually) and cannot go flaky.

``DATA_DIR`` is covered here too.  It contains the session secret, the setup
token, the local client token, the credential index and these same backups, so a
traversable directory lets any local user watch tokens appear and read the
backups by name.
"""
from __future__ import annotations

import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import config, secure_io  # noqa: E402


class NoChmod:
    """Neutralise every chmod path so only creation-time modes survive."""

    def __enter__(self):
        self._patches = [
            mock.patch("os.chmod"),
            mock.patch("os.fchmod"),
            mock.patch.object(Path, "chmod"),
        ]
        for p in self._patches:
            p.start()
        self._umask = os.umask(0)
        return self

    def __exit__(self, *exc):
        os.umask(self._umask)
        for p in reversed(self._patches):
            p.stop()
        return False


def mode_of(path: Path) -> int:
    return path.stat().st_mode & 0o777


class _ConfigSandbox(unittest.TestCase):
    """Point config.py's module-level paths at a scratch directory.

    ``YAML_PATH`` and ``DATA_DIR`` are resolved at import time, so patching the
    attributes on the module is what redirects the writes.  Without this the
    tests would rewrite the developer's real services.yaml.
    """

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-cfg-{os.getpid()}-{id(self)}"
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.data = data
        self.yaml = root / "services.yaml"
        for target, value in (
            ("YAML_PATH", self.yaml),
            ("DATA_DIR", self.data),
            ("BASE", self.root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        # save_full() calls reload_cfg(), which re-reads the patched path; reset
        # the cache afterwards so a later test in the process does not inherit
        # this sandbox's parsed contents.
        self.addCleanup(config.reload_cfg)


class BootstrapModeTests(_ConfigSandbox):
    def test_bootstrap_from_defaults_is_private_at_creation(self):
        with NoChmod():
            config._bootstrap()
        self.assertTrue(self.yaml.exists())
        self.assertEqual(
            mode_of(self.yaml),
            0o600,
            "first-run services.yaml was created world-readable and only "
            "tightened afterwards; the admin password hash lands in this file",
        )

    def test_bootstrap_from_example_does_not_inherit_the_example_mode(self):
        # The repo ships services.yaml.example as a normal 0644 file.  copy2
        # propagates that mode, which is the specific bug this pins.
        example = self.root / "services.yaml.example"
        example.write_text("settings: {}\n", encoding="utf-8")
        os.chmod(example, 0o644)

        with NoChmod():
            config._bootstrap()

        self.assertEqual(mode_of(self.yaml), 0o600)
        self.assertEqual(
            self.yaml.read_text(encoding="utf-8"),
            "settings: {}\n",
            "bootstrapping must still use the example as the starting point",
        )

    def test_bootstrap_leaves_an_existing_config_untouched(self):
        self.yaml.write_text("settings:\n  keep: true\n", encoding="utf-8")
        config._bootstrap()
        self.assertIn("keep: true", self.yaml.read_text(encoding="utf-8"))

    def test_bootstrap_survives_a_read_only_directory(self):
        # A packaged install can have an unwritable install dir; _bootstrap must
        # not raise there, because cfg() is responsible for surfacing that.
        with mock.patch.object(
            secure_io, "create_secret_text", side_effect=OSError("read-only")
        ):
            config._bootstrap()
        self.assertFalse(self.yaml.exists())


class SaveFullModeTests(_ConfigSandbox):
    def setUp(self):
        super().setUp()
        self.yaml.write_text("settings:\n  a: 1\n", encoding="utf-8")
        os.chmod(self.yaml, 0o600)

    def test_saved_config_is_private_at_creation(self):
        with NoChmod():
            config.save_full({"settings": {"a": 2}})
        self.assertEqual(
            mode_of(self.yaml),
            0o600,
            "save_full staged the new config world-readable before replacing; "
            "every settings save reopened that window",
        )

    def test_the_staging_file_is_not_left_behind(self):
        config.save_full({"settings": {"a": 3}})
        leftovers = [p.name for p in self.root.glob("services.yaml.tmp*")]
        self.assertEqual(leftovers, [], f"staging file left on disk: {leftovers}")

    def test_the_replace_is_atomic_so_readers_never_see_a_partial_file(self):
        # os.replace is the primitive that guarantees this; assert the config is
        # never observed missing or truncated by checking it stays parseable and
        # that no separate write lands directly on YAML_PATH.
        real_replace = os.replace
        seen = []

        def spy(src, dst):
            seen.append((str(src), str(dst)))
            return real_replace(src, dst)

        with mock.patch("os.replace", side_effect=spy):
            config.save_full({"settings": {"a": 4}})

        self.assertTrue(
            any(dst == str(self.yaml) for _, dst in seen),
            "the new config must arrive via os.replace, not an in-place write",
        )

    def test_the_backup_is_private_at_creation(self):
        with NoChmod():
            config.save_full({"settings": {"a": 5}})
        baks = list(self.data.glob("services.yaml.bak.*"))
        self.assertEqual(len(baks), 1, f"expected one backup, got {baks}")
        self.assertEqual(
            mode_of(baks[0]),
            0o600,
            "the timestamped backup is a verbatim copy of the credentials file "
            "and must not be readable by other local users",
        )

    def test_saved_content_round_trips(self):
        config.save_full({"settings": {"a": 6}, "extra": ["x"]})
        loaded = config.cfg()
        self.assertEqual(loaded["settings"]["a"], 6)
        self.assertEqual(loaded["extra"], ["x"])

    def test_backups_are_capped(self):
        # Unbounded backups of a credentials file are both SSD churn and a
        # widening disclosure surface.
        for i in range(9):
            config.save_full({"settings": {"a": i}})
        baks = list(self.data.glob("services.yaml.bak.*"))
        self.assertLessEqual(len(baks), 5, f"backup retention slipped: {len(baks)}")


class DataDirModeTests(unittest.TestCase):
    """DATA_DIR must be owner-only on every install, not just packaged ones."""

    def test_ensure_state_dirs_tightens_data_dir_without_an_override(self):
        from hub import paths

        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-state-{os.getpid()}"
        data = root / "data"
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)

        with mock.patch.object(paths, "STATE_ROOT", root), \
                mock.patch.object(paths, "DATA_DIR", data), \
                mock.patch.object(paths, "_STATE_OVERRIDE", ""):
            paths.ensure_state_dirs()

        self.assertTrue(data.is_dir())
        self.assertEqual(
            mode_of(data),
            0o700,
            "DATA_DIR holds the session secret, setup token and credential "
            "index; a source install left it listable by every local user",
        )

    def test_a_source_install_root_is_not_clamped(self):
        # On a source install STATE_ROOT *is* the checkout.  Forcing the whole
        # project tree to 0700 is a side effect this function must not have.
        from hub import paths

        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-src-{os.getpid()}"
        data = root / "data"
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        os.chmod(root, 0o755)

        with mock.patch.object(paths, "STATE_ROOT", root), \
                mock.patch.object(paths, "DATA_DIR", data), \
                mock.patch.object(paths, "_STATE_OVERRIDE", ""):
            paths.ensure_state_dirs()

        self.assertEqual(mode_of(root), 0o755)
        self.assertEqual(mode_of(data), 0o700)

    def test_a_dedicated_state_dir_is_clamped(self):
        from hub import paths

        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-pkg-{os.getpid()}"
        data = root / "data"
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)

        with mock.patch.object(paths, "STATE_ROOT", root), \
                mock.patch.object(paths, "DATA_DIR", data), \
                mock.patch.object(paths, "_STATE_OVERRIDE", str(root)):
            paths.ensure_state_dirs()

        self.assertEqual(mode_of(root), 0o700)
        self.assertEqual(mode_of(data), 0o700)

    def test_ensure_state_dirs_is_idempotent(self):
        from hub import paths

        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-idem-{os.getpid()}"
        data = root / "data"
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)

        with mock.patch.object(paths, "STATE_ROOT", root), \
                mock.patch.object(paths, "DATA_DIR", data), \
                mock.patch.object(paths, "_STATE_OVERRIDE", ""):
            paths.ensure_state_dirs()
            marker = data / "keep.json"
            marker.write_text("{}", encoding="utf-8")
            paths.ensure_state_dirs()

        self.assertTrue(marker.exists(), "re-running must not recreate the dir")
        self.assertEqual(mode_of(data), 0o700)


class DenylistCoverageTests(unittest.TestCase):
    """The intermediate files these fixes create must not be browsable.

    ``replace_secret_text`` stages at ``services.yaml.tmp`` and ``save_full``
    drops ``services.yaml.bak.<epoch>`` into DATA_DIR.  Both are verbatim copies
    of the credentials file, so the file browser has to refuse them by the same
    rule that refuses ``services.yaml`` itself.  The mode fixes above make the
    files 0600, but the browser runs as the owner -- 0600 is no defence there,
    the deny-list is.

    Case-folded spellings are asserted explicitly because APFS is
    case-insensitive: ``Services.YAML.tmp`` resolves to the same inode, and
    ``os.path.normcase`` (the obvious-looking fold) is the identity function on
    darwin, so a fold that is not spelled out here would silently not happen.
    """

    def _refuses(self, name: str) -> None:
        from hub import files_svc
        from hub.paths import BASE as REAL_BASE

        self.assertTrue(
            files_svc.is_protected(REAL_BASE / "data" / name),
            f"{name} is a copy of services.yaml and must be deny-listed",
        )

    def test_staging_file_is_protected(self):
        self._refuses("services.yaml.tmp")

    def test_staging_file_is_protected_case_folded(self):
        self._refuses("Services.YAML.tmp")
        self._refuses("SERVICES.YAML.TMP")

    def test_backup_is_protected(self):
        self._refuses("services.yaml.bak.1784879564")

    def test_backup_is_protected_case_folded(self):
        self._refuses("Services.Yaml.Bak.1784879564")

    def test_the_names_config_actually_writes_are_the_ones_tested(self):
        # Pins the coupling: if the staging suffix or backup prefix changes, the
        # deny-list assertions above would still pass while covering dead names.
        io_src = (BASE / "hub" / "secure_io.py").read_text(encoding="utf-8")
        cfg_src = (BASE / "hub" / "config.py").read_text(encoding="utf-8")
        self.assertIn('p.with_name(p.name + ".tmp")', io_src)
        self.assertIn('f"services.yaml.bak.{int(time.time())}"', cfg_src)


class WiringTests(unittest.TestCase):
    """Pin the call sites so a refactor cannot quietly reintroduce the window."""

    def test_config_does_not_write_the_config_with_write_text(self):
        src = (BASE / "hub" / "config.py").read_text(encoding="utf-8")
        self.assertNotIn(
            "YAML_PATH.write_text",
            src,
            "writing services.yaml directly skips the 0600-at-creation helper",
        )
        self.assertNotIn(
            "shutil.copy2(example",
            src,
            "copy2 propagates the example file's world-readable mode",
        )

    def test_config_uses_the_secure_helpers(self):
        src = (BASE / "hub" / "config.py").read_text(encoding="utf-8")
        self.assertRegex(src, r"from hub import secure_io")
        self.assertIn("secure_io.create_secret_text(YAML_PATH", src)
        self.assertIn("secure_io.replace_secret_text(YAML_PATH", src)
        self.assertIn("secure_io.copy_secret_file(YAML_PATH", src)

    def test_bootstrap_does_not_use_the_truncating_helper(self):
        """Creating the config must not be able to overwrite one.

        write_secret_text opens with O_TRUNC, so reaching it from the bootstrap
        path turns any false negative about the file's existence into total data
        loss.  That is not theoretical: it emptied a populated services.yaml on
        every test-suite run.  Bootstrapping goes through the O_EXCL helper, where
        a wrong answer is a no-op.  See
        tests/test_config_bootstrap_never_destroys.py.
        """
        src = (BASE / "hub" / "config.py").read_text(encoding="utf-8")
        self.assertNotIn(
            "secure_io.write_secret_text(YAML_PATH",
            src,
            "bootstrap must create with O_EXCL, not truncate",
        )
        bootstrap = src[src.index("def _bootstrap("):src.index("def cfg(")]
        self.assertNotIn(
            "YAML_PATH.exists()",
            bootstrap,
            "bootstrap must not branch on exists(); let O_EXCL decide atomically",
        )

    def test_config_does_not_copy2_the_backup(self):
        # copy2 creates the destination at the umask and copies the mode only
        # afterwards, so the backup was world-readable for the length of the
        # copy -- a full copy of the admin password hash and every credential.
        src = (BASE / "hub" / "config.py").read_text(encoding="utf-8")
        self.assertNotRegex(
            src,
            r"^\s*shutil\.copy2\(",
            "shutil.copy2 cannot create a secret file safely",
        )

    def test_paths_uses_the_secure_dir_helper(self):
        src = (BASE / "hub" / "paths.py").read_text(encoding="utf-8")
        self.assertIn("secure_io.make_secret_dir(DATA_DIR)", src)

    def test_secure_io_stays_dependency_free(self):
        # paths.py imports secure_io at module scope, so secure_io importing
        # anything from hub would be a cycle that breaks every route at load.
        src = (BASE / "hub" / "secure_io.py").read_text(encoding="utf-8")
        self.assertNotRegex(src, r"^\s*from hub", )
        self.assertNotRegex(src, r"^\s*import hub", )


if __name__ == "__main__":
    unittest.main()


class BackupRetentionTests(_ConfigSandbox):
    """The pre-image history has to be deep enough to actually recover from.

    services.yaml holds the admin credential. It was once cleared, and by the time
    anyone noticed, the retained pre-images had all rotated past the point where
    the credential still existed -- a months-old archive was the only remaining
    source. These tests pin the window so it cannot quietly shrink back.
    """

    def setUp(self):
        super().setUp()
        self.yaml.write_text("settings:\n  a: 1\n", encoding="utf-8")
        os.chmod(self.yaml, 0o600)

    def test_the_window_is_deep_enough_to_survive_a_burst_of_writes(self):
        self.assertGreaterEqual(
            config.BACKUP_RETENTION,
            30,
            "a shallow window rotates the whole history within minutes of "
            "ordinary settings traffic, which is how the credential became "
            "unrecoverable from data/ at all",
        )

    def test_writes_beyond_the_window_prune_the_oldest_and_keep_the_newest(self):
        # One more write than the window, each with a distinct epoch suffix so
        # ordering is unambiguous.
        total = config.BACKUP_RETENTION + 5
        base = 1_700_000_000
        for i in range(total):
            with mock.patch.object(config.time, "time", return_value=base + i):
                config.save_full({"settings": {"a": i}})

        baks = sorted(p.name for p in self.data.glob("services.yaml.bak.*"))
        self.assertEqual(
            len(baks),
            config.BACKUP_RETENTION,
            f"expected the window to cap at {config.BACKUP_RETENTION}, got {len(baks)}",
        )
        # The suffix is a fixed-width epoch, so the newest sort last.
        newest_kept = baks[-1]
        self.assertEqual(
            newest_kept,
            f"services.yaml.bak.{base + total - 1}",
            "pruning must drop the oldest copies, never the most recent one",
        )
        self.assertNotIn(
            f"services.yaml.bak.{base}",
            baks,
            "the oldest copy should have been pruned once the window filled",
        )

    def test_every_retained_backup_stays_private(self):
        base = 1_700_000_000
        with NoChmod():
            for i in range(3):
                with mock.patch.object(config.time, "time", return_value=base + i):
                    config.save_full({"settings": {"a": i}})
        for bak in self.data.glob("services.yaml.bak.*"):
            self.assertEqual(
                mode_of(bak),
                0o600,
                f"{bak.name} is a verbatim copy of the credentials file",
            )
