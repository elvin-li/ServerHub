"""NFS export path hardening — refuse credential-bearing trees."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import nfs_svc  # noqa: E402
from hub.paths import BASE as INSTALL_BASE  # noqa: E402


class NfsProtectedPathTests(unittest.TestCase):
    def test_cloudflared_and_backup_exports_are_refused(self):
        for relative in (
            "Services/cloudflared",
            "Services/backups",
            "Services/filebrowser",
            ".cloudflared",
        ):
            target = Path.home() / relative
            target.mkdir(parents=True, exist_ok=True)
            with self.subTest(path=str(target)):
                with self.assertRaises(nfs_svc.NfsConfigError) as raised:
                    nfs_svc._validate_entry({"path": str(target), "clients": ["192.168.1.0/24"]})
                self.assertEqual(raised.exception.code, "nfs.protected_path")

    def test_serverhub_install_tree_is_refused(self):
        with self.assertRaises(nfs_svc.NfsConfigError) as raised:
            nfs_svc._validate_entry({"path": str(INSTALL_BASE), "clients": ["everyone"]})
        self.assertEqual(raised.exception.code, "nfs.protected_path")


if __name__ == "__main__":
    unittest.main()
