"""Guard tests for the file-browser deny-list.

These cover the security blocker where ~/Services and ~ were browsable roots,
so the panel would serve its own session-signing key, credential store and
admin password hash — and accept delete/rename on them.
"""
import unittest
from pathlib import Path

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

    def test_ordinary_media_file_is_allowed(self):
        p = files_svc.SERVICES_ROOT / "media" / "movie.mkv"
        self.assertFalse(files_svc.is_protected(p))


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


if __name__ == "__main__":
    unittest.main()
