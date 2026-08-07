"""Bootstrapping a config must never be able to destroy one.

This is a regression test for real data loss.  ``config._bootstrap()`` used to be

    if YAML_PATH.exists():
        return
    ...
    secure_io.write_secret_text(YAML_PATH, defaults)

which reads the filesystem twice and trusts the first answer.  A test elsewhere
patched ``pathlib.Path.exists`` process-wide to ``False`` while exercising an
unrelated code path; ``exists()`` then lied about services.yaml, the guard fell
through, and ``O_TRUNC`` reduced a populated 11 KB config to 407 bytes of
defaults -- taking the admin account, two apps, three stacks and twelve
bookmarks.  It happened on every run of the test suite.

The fix is structural: creation goes through ``O_EXCL``, so the kernel decides
whether the file is new and a wrong guess is a no-op instead of a truncation.
These tests pin that property, because the guard cannot be re-introduced without
re-introducing the outage.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import config, secure_io  # noqa: E402

POPULATED = """\
settings:
  auth:
    enabled: true
    username: elvin
    password_hash: scrypt$notarealhash
apps:
- id: immich
  name: Immich
quick_links:
- name: Router
  url: http://192.168.1.1
"""


class BootstrapCannotTruncateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "services.yaml"
        self.path.write_text(POPULATED)
        self.path.chmod(0o600)

    def test_bootstrap_leaves_an_existing_config_alone(self):
        with patch.object(config, "YAML_PATH", self.path):
            config._bootstrap()
        self.assertEqual(self.path.read_text(), POPULATED)

    def test_bootstrap_leaves_it_alone_even_when_exists_lies(self):
        """The exact failure mode: every path claims to be missing."""
        with patch.object(config, "YAML_PATH", self.path):
            with patch.object(Path, "exists", return_value=False):
                config._bootstrap()
        self.assertEqual(
            self.path.read_text(),
            POPULATED,
            "a false negative from exists() overwrote a populated config",
        )

    def test_cfg_does_not_destroy_the_config_when_exists_lies(self):
        """cfg() calls _bootstrap() on a negative exists(), so it needs the same guard."""
        with patch.object(config, "YAML_PATH", self.path):
            config._cfg["mtime"] = 0  # force a re-read rather than a cache hit
            real_exists = Path.exists

            def lying_exists(self_path: Path) -> bool:
                return False if self_path == self.path else real_exists(self_path)

            with patch.object(Path, "exists", lying_exists):
                try:
                    config.cfg()
                except OSError:
                    pass  # stat() may still be attempted; the file must survive
        self.assertEqual(self.path.read_text(), POPULATED)

    def test_bootstrap_still_creates_a_config_when_there_is_none(self):
        """The feature has to keep working: a fresh install must get a file."""
        fresh = Path(self.dir.name) / "brand-new.yaml"
        with patch.object(config, "YAML_PATH", fresh):
            config._bootstrap()
        self.assertTrue(fresh.is_file(), "a fresh install got no config file")
        self.assertTrue(fresh.read_text().strip(), "the created config is empty")

    def test_a_created_config_is_not_readable_by_other_users(self):
        """It holds the admin password hash from the moment setup runs."""
        fresh = Path(self.dir.name) / "modes.yaml"
        with patch.object(config, "YAML_PATH", fresh):
            config._bootstrap()
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o600)


class ExclusiveCreateTests(unittest.TestCase):
    """The primitive the fix rests on."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_creates_when_absent_and_reports_it(self):
        target = Path(self.dir.name) / "new.txt"
        self.assertTrue(secure_io.create_secret_text(target, "hello"))
        self.assertEqual(target.read_text(), "hello")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_refuses_to_touch_an_existing_file(self):
        target = Path(self.dir.name) / "existing.txt"
        target.write_text("precious")
        self.assertFalse(secure_io.create_secret_text(target, "clobber"))
        self.assertEqual(target.read_text(), "precious")

    def test_refuses_even_when_exists_lies(self):
        """O_EXCL means the kernel decides, so a patched exists() changes nothing."""
        target = Path(self.dir.name) / "guarded.txt"
        target.write_text("precious")
        with patch.object(Path, "exists", return_value=False):
            self.assertFalse(secure_io.create_secret_text(target, "clobber"))
        self.assertEqual(target.read_text(), "precious")


if __name__ == "__main__":
    unittest.main()
