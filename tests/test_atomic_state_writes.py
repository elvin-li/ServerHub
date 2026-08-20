"""Hot state files must be replaced atomically.

A crash mid-``Path.write_text`` leaves half a JSON document. The readers of
these files treat parse failure as "no cache / no history / no diagnostics",
which is how a brew page waited on a live ``brew services list`` after a
killed write, and how SMART history vanished after a crash during append.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


class AtomicStateWrites(unittest.TestCase):
    def test_brew_cache_disk_snapshot_is_atomic(self):
        src = (BASE / "hub" / "brew_cache.py").read_text(encoding="utf-8")
        self.assertIn("replace_bytes(_DISK", src)
        self.assertNotIn("_DISK.write_text", src)

    def test_container_update_status_is_atomic(self):
        src = (BASE / "hub" / "containers_svc.py").read_text(encoding="utf-8")
        self.assertIn("replace_bytes(", src)
        self.assertNotIn("UPDATE_STATUS_PATH.write_text", src)

    def test_smart_history_is_atomic(self):
        src = (BASE / "hub" / "smart_test_svc.py").read_text(encoding="utf-8")
        self.assertIn("replace_bytes(", src)
        self.assertNotIn("HISTORY_PATH.write_text", src)

    def test_diagnostics_snapshot_is_atomic(self):
        src = (BASE / "hub" / "system_settings_svc.py").read_text(encoding="utf-8")
        self.assertIn("replace_bytes(", src)
        self.assertNotIn("path.write_text", src)

    def test_catalog_vars_are_replaced_not_truncated(self):
        src = (BASE / "hub" / "catalog.py").read_text(encoding="utf-8")
        self.assertIn("replace_secret_text(", src)
        self.assertNotIn("write_secret_text(\n            vars_file", src)

    def test_jsonl_journals_append_without_following_symlinks(self):
        sites = (
            BASE / "hub" / "audit.py",
            BASE / "hub" / "terminal_svc.py",
            BASE / "hub" / "metrics.py",
            BASE / "hub" / "alerts.py",
            BASE / "hub" / "scheduler_svc.py",
            BASE / "hub" / "metrics_rollup.py",
        )
        for path in sites:
            src = path.read_text(encoding="utf-8")
            self.assertIn("append_text(", src, path.name)
            self.assertNotIn('.open("a"', src, path.name)
            self.assertNotIn('open(METRICS_FILE, "a")', src, path.name)
            self.assertNotIn('open(ALERTS_FILE, "a")', src, path.name)
            self.assertNotIn('open(dst_path, "a")', src, path.name)

    def test_remote_catalog_templates_are_born_private(self):
        src = (BASE / "hub" / "catalog_remote.py").read_text(encoding="utf-8")
        self.assertIn("replace_secret_text(final", src)
        self.assertNotIn("staged.write_text", src)
        self.assertNotIn("write_secret_text(staged", src)

    def test_journal_rewrites_use_excl_nofollow_replace_bytes(self):
        """Predictable `{name}.{pid}.tmp` + write_text followed a planted symlink."""
        for name in (
            "alerts.py",
            "metrics.py",
            "metrics_rollup.py",
            "scheduler_svc.py",
            "ups_policy.py",
        ):
            src = (BASE / "hub" / name).read_text(encoding="utf-8")
            self.assertIn("replace_bytes(", src, name)
            self.assertNotIn("tmp.write_text", src, name)
            self.assertNotIn("os.replace(", src, name)

    def test_replace_bytes_opens_tmp_with_nofollow(self):
        src = (BASE / "hub" / "secure_io.py").read_text(encoding="utf-8")
        start = src.index("def replace_bytes(")
        body = src[start: src.index("\ndef copy_secret_file")]
        self.assertIn("O_EXCL", body)
        self.assertIn("O_NOFOLLOW", body)


class AlertStateTmpSymlinkTests(unittest.TestCase):
    def test_planted_tmp_symlink_is_not_followed(self):
        from hub import alerts

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "alert_state.json"
            planted = root / "secret"
            planted.write_text("keep", encoding="utf-8")
            decoy = root / f"alert_state.json.{os.getpid()}.tmp"
            decoy.symlink_to(planted)
            with mock.patch.object(alerts, "STATE_FILE", state):
                with self.assertRaises(FileExistsError):
                    alerts._save_state({"ok": True})
            self.assertEqual(planted.read_text(encoding="utf-8"), "keep")
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
