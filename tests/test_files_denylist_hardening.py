"""Regression tests for three confirmed file-manager holes.

All three were reachable from any authenticated panel session and none were
covered by the existing suite, so the whole thing was green while these worked.

1. Case-folding bypass.  APFS/NTFS are case-insensitive by default, so
   ``Services.YAML`` and ``.../ServerHub/...`` open the very same bytes as the
   deny-listed spellings — but ``str`` comparison and ``Path.relative_to`` both
   said "not protected".  That handed out the HMAC session-signing key plus the
   admin password hash, which together are enough to forge a valid session
   cookie offline without ever knowing the password.

   Note the first fix attempt used ``os.path.normcase``, which is a *no-op on
   macOS* — it only folds case on Windows.  The tests below therefore assert on
   real mixed-case spellings rather than trusting a helper to do the folding.

2. The SGCC scraper's credential and session files were not deny-listed at all.
   ``GET /api/files/download`` returned the grid-account password, a long-lived
   Home Assistant token and an LLM API key in plain text.  Their 0600 mode is
   irrelevant: the panel process is their owner.

3. ``upload()`` never raised ``files.upload_would_overwrite`` even though the
   error code existed, so any upload silently clobbered its destination.
"""
from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from hub import files_svc
from hub.paths import BASE

HOME = Path.home()


def _mixed_case(p: Path) -> Path:
    """Re-spell every path segment in a way that differs from the original.

    Deliberately not just ``str.upper()``: the point is to produce a spelling a
    real attacker could send, which still resolves to the same inode on a
    case-insensitive filesystem.
    """
    parts = []
    for seg in p.parts:
        parts.append(seg if seg == p.anchor else seg.swapcase())
    return Path(*parts)


class TestCaseFoldingBypass(unittest.TestCase):
    """The exact spellings that were confirmed readable on this host."""

    def test_install_dir_with_different_capitalisation(self):
        self.assertTrue(files_svc.is_protected(Path(str(BASE).replace("serverhub", "ServerHub"))))

    def test_services_yaml_uppercased(self):
        self.assertTrue(
            files_svc.is_protected(BASE.parent / "ServerHub" / "Services.YAML")
        )

    def test_session_secret_titlecased(self):
        self.assertTrue(
            files_svc.is_protected(BASE.parent / "ServerHub" / "data" / ".Session-Secret")
        )

    def test_local_client_token_via_mixed_case_dir(self):
        self.assertTrue(
            files_svc.is_protected(
                BASE.parent / "ServerHub" / "data" / ".local-client-token"
            )
        )

    def test_credential_store_mixed_case(self):
        self.assertTrue(
            files_svc.is_protected(
                BASE.parent / "ServerHub" / "data" / "service-Credentials.json"
            )
        )

    def test_setup_token_via_fully_uppercased_dir(self):
        self.assertTrue(
            files_svc.is_protected(BASE.parent / "SERVERHUB" / "data" / ".setup-token")
        )

    def test_source_code_is_not_writable_via_mixed_case(self):
        """Overwriting hub/auth.py is arbitrary code execution on next restart."""
        self.assertTrue(
            files_svc.is_protected(BASE.parent / "ServerHub" / "hub" / "auth.py")
        )

    def test_ssh_key_dir_mixed_case(self):
        self.assertTrue(files_svc.is_protected(HOME / ".SSH" / "id_ed25519"))

    def test_every_segment_swapcased_still_protected(self):
        self.assertTrue(files_svc.is_protected(_mixed_case(BASE / "services.yaml")))


class TestSgccCredentialsAreProtected(unittest.TestCase):
    SGCC = files_svc.SERVICES_ROOT / "sgcc_native"

    def test_credential_file(self):
        self.assertTrue(files_svc.is_protected(self.SGCC / ".sgcc_cred"))

    def test_session_cookie_jar(self):
        self.assertTrue(files_svc.is_protected(self.SGCC / ".sgcc_session"))

    def test_browser_profile_cookie_database(self):
        self.assertTrue(
            files_svc.is_protected(self.SGCC / ".sgcc_browser_profile" / "Default" / "Cookies")
        )

    def test_whole_scraper_directory(self):
        self.assertTrue(files_svc.is_protected(self.SGCC))

    def test_credential_file_mixed_case(self):
        self.assertTrue(
            files_svc.is_protected(files_svc.SERVICES_ROOT / "SGCC_NATIVE" / ".SGCC_CRED")
        )

    def test_sgcc_prefix_blocks_copies_elsewhere(self):
        """A copy dragged into Downloads must not become downloadable."""
        self.assertTrue(files_svc.is_protected(HOME / "Downloads" / ".sgcc_cred"))


class TestOrdinaryFilesStillAllowed(unittest.TestCase):
    """A deny-list that blocks everything is not a fix."""

    def test_media_file(self):
        self.assertFalse(files_svc.is_protected(files_svc.SERVICES_ROOT / "media" / "movie.mkv"))

    def test_downloads_dir(self):
        self.assertFalse(files_svc.is_protected(HOME / "Downloads"))

    def test_home_assistant_config_is_browsable(self):
        self.assertFalse(
            files_svc.is_protected(
                files_svc.SERVICES_ROOT / "homeassistant" / "config" / "automations.yaml"
            )
        )

    def test_sibling_dir_sharing_a_prefix_is_not_blocked(self):
        """`/a/bcd` must not match the protected parent `/a/bc`."""
        self.assertFalse(files_svc.is_protected(Path(str(BASE) + "-notes")))

    def test_a_file_merely_containing_the_name_is_allowed(self):
        self.assertFalse(
            files_svc.is_protected(HOME / "Downloads" / "my-services.yaml.notes.txt")
        )


class _FakeUpload:
    """Minimal UploadFile stand-in: only read()/close() are used."""

    def __init__(self, filename: str, payload: bytes = b"x"):
        self.filename = filename
        self._payload = payload
        self._done = False
        self.closed = False

    async def read(self, _size: int = -1) -> bytes:
        if self._done:
            return b""
        self._done = True
        return self._payload

    async def close(self) -> None:
        self.closed = True


class TestUploadDoesNotClobber(unittest.TestCase):
    def setUp(self):
        self.dir = files_svc.SERVICES_ROOT / "media"

    def _upload(self, name: str, payload: bytes = b"new"):
        return asyncio.run(
            files_svc.upload(str(self.dir), _FakeUpload(name, payload), "media")
        )

    def test_existing_file_is_refused(self):
        target = self.dir / "denylist-upload-probe.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("original", encoding="utf-8")
        try:
            with self.assertRaises(HTTPException) as ctx:
                self._upload(target.name)
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "original",
                "the upload overwrote an existing file",
            )
        finally:
            target.unlink(missing_ok=True)

    def test_a_new_name_still_uploads(self):
        target = self.dir / "denylist-upload-fresh.txt"
        target.unlink(missing_ok=True)
        try:
            result = self._upload(target.name, b"hello")
            self.assertTrue(result["ok"])
            self.assertEqual(target.read_bytes(), b"hello")
        finally:
            target.unlink(missing_ok=True)

    def test_upload_into_a_protected_dir_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(files_svc.upload(str(BASE), _FakeUpload("auth.py"), "services"))
        self.assertEqual(ctx.exception.status_code, 403)


class TestResolveSafeRefusesDirectly(unittest.TestCase):
    """Hiding a path from a listing is not access control; resolve must refuse."""

    def _refused(self, path: Path):
        with self.assertRaises(HTTPException) as ctx:
            files_svc._resolve_safe(str(path), "services")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_sgcc_credentials(self):
        self._refused(files_svc.SERVICES_ROOT / "sgcc_native" / ".sgcc_cred")

    def test_mixed_case_services_yaml(self):
        self._refused(BASE.parent / "ServerHub" / "Services.YAML")

    def test_mixed_case_session_secret(self):
        self._refused(BASE.parent / "ServerHub" / "data" / ".Session-Secret")


class TestDenylistShape(unittest.TestCase):
    """Guard the fix's structure so the regression cannot quietly return."""

    def setUp(self):
        self.source = (BASE / "hub" / "files_svc.py").read_text(encoding="utf-8")

    def test_normcase_is_not_relied_on_for_folding(self):
        """os.path.normcase is a no-op on macOS — it only folds case on Windows."""
        self.assertNotIn(
            "os.path.normcase",
            self.source,
            "normcase does not fold case on macOS, so the bypass would be back",
        )

    def test_sgcc_prefix_is_deny_listed(self):
        self.assertIn(".sgcc", files_svc.PROTECTED_PREFIXES)

    def test_overwrite_guard_is_present(self):
        self.assertIn("files.upload_would_overwrite", self.source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
