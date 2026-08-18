"""Guard tests for the file-browser deny-list.

These cover the security blocker where ~/Services and ~ were browsable roots,
so the panel would serve its own session-signing key, credential store and
admin password hash — and accept delete/rename on them.
"""
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

from fastapi import HTTPException

from hub import files_svc
from hub.paths import BASE


class TestIsProtected(unittest.TestCase):
    def test_install_dir_itself(self):
        self.assertTrue(files_svc.is_protected(BASE))

    def test_session_secret(self):
        self.assertTrue(files_svc.is_protected(BASE / "data" / ".session-secret"))

    def test_credential_store(self):
        self.assertTrue(
            files_svc.is_protected(BASE / "data" / "service-credentials.json")
        )

    def test_services_yaml_and_backups(self):
        self.assertTrue(files_svc.is_protected(BASE / "services.yaml"))
        self.assertTrue(
            files_svc.is_protected(BASE / "data" / "services.yaml.bak.1784879564")
        )

    def test_ssh_keys(self):
        home = Path.home()
        self.assertTrue(files_svc.is_protected(home / ".ssh"))
        self.assertTrue(files_svc.is_protected(home / ".ssh" / "authorized_keys"))
        self.assertTrue(files_svc.is_protected(home / ".ssh" / "id_ed25519"))

    def test_dotenv_anywhere(self):
        self.assertTrue(files_svc.is_protected(Path("/tmp/whatever/.env")))

    def test_named_env_files_are_protected(self):
        self.assertTrue(files_svc.is_protected(Path.home() / "Services" / "immich" / "db.env"))
        self.assertTrue(files_svc.is_protected(Path("/tmp/twofa.json")))

    def test_filebrowser_stop_does_not_pkill_by_argv_substring(self):
        source = Path(files_svc.__file__).read_text()
        self.assertNotIn('pkill", "-f"', source)
        self.assertIn('pkill", "-x", "filebrowser-bin"', source)

    def test_ordinary_media_file_is_allowed(self):
        p = files_svc.SERVICES_ROOT / "media" / "movie.mkv"
        self.assertFalse(files_svc.is_protected(p))

    def test_ondemand_rejects_a_non_dict_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "fb.plist"
            plist.write_bytes(plistlib.dumps(["not", "a", "dict"]))
            with patch.object(files_svc, "FB_PLIST", plist):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.set_filebrowser_ondemand(True)
            self.assertEqual(ctx.exception.detail["code"], "files.fb_bad_plist")

    def test_ondemand_write_is_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "fb.plist"
            plist.write_bytes(plistlib.dumps({
                "Label": "local.filebrowser",
                "RunAtLoad": True,
                "KeepAlive": True,
            }))
            with (
                patch.object(files_svc, "FB_PLIST", plist),
                patch.object(files_svc, "UID", 502),
                patch.object(files_svc, "sh", return_value=(0, "", "")),
            ):
                result = files_svc.set_filebrowser_ondemand(True)
            self.assertTrue(result["ok"])
            loaded = plistlib.loads(plist.read_bytes())
            self.assertFalse(loaded["RunAtLoad"])
            self.assertFalse(loaded["KeepAlive"])
            residue = [p.name for p in Path(tmp).iterdir() if ".tmp" in p.name]
            self.assertEqual(residue, [])


class TestResolveSafeRejects(unittest.TestCase):
    """A directly-supplied path must be refused, not merely hidden."""

    def _assert_refused(self, path: str):
        with self.assertRaises(HTTPException) as ctx:
            files_svc._resolve_safe(path, "services")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_direct_path_to_session_secret(self):
        self._assert_refused(str(BASE / "data" / ".session-secret"))

    def test_direct_path_to_services_yaml(self):
        self._assert_refused(str(BASE / "services.yaml"))

    def test_direct_path_to_credentials(self):
        self._assert_refused(str(BASE / "data" / "service-credentials.json"))

    def test_traversal_outside_roots_still_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            files_svc._resolve_safe("/etc/passwd", "services")
        self.assertEqual(ctx.exception.status_code, 403)


class TestHomeNotADefaultRoot(unittest.TestCase):
    def test_home_absent_from_default_roots(self):
        ids = {r["id"] for r in files_svc.default_roots()}
        self.assertNotIn("home", ids)


class TestFileBrowserStartup(unittest.TestCase):
    def test_direct_start_uses_argv_without_a_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "filebrowser;not-a-command"
            binary.touch()
            database = root / "filebrowser.db"
            media = root / "media with spaces"
            service_root = root / "services"
            statuses = [
                {"running": False},
                {"running": True, "port": files_svc.FB_PORT},
            ]
            with (
                patch.object(files_svc, "FB_BIN", binary),
                patch.object(files_svc, "FB_DB", database),
                patch.object(files_svc, "FB_ROOT_DEFAULT", media),
                patch.object(files_svc, "SERVICES_ROOT", service_root),
                patch.object(files_svc, "FB_PLIST", root / "missing.plist"),
                patch.object(files_svc, "filebrowser_status", side_effect=statuses),
                patch.object(files_svc.time, "sleep"),
                patch.object(files_svc.subprocess, "Popen") as popen,
                patch("builtins.open", mock_open()),
            ):
                result = files_svc.ensure_filebrowser()

        self.assertTrue(result["running"])
        argv = popen.call_args.args[0]
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], str(binary))
        self.assertIn(str(media), argv)
        self.assertIn("-a", argv)
        self.assertEqual(argv[argv.index("-a") + 1], "127.0.0.1")
        self.assertNotIn("0.0.0.0", argv)
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_catalog_install_also_binds_loopback(self):
        source = (
            Path(__file__).resolve().parent.parent / "hub" / "native_catalog.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"-a", "127.0.0.1"', source)
        self.assertNotIn('"-a", "0.0.0.0"', source)


if __name__ == "__main__":
    unittest.main()
