"""Secrets must be unreadable to other local users from the moment they exist.

Every one of these files holds something an attacker on the same Mac would want:
a Cloudflare tunnel token that grants ingress to the LAN, the generated database
and admin passwords inside an app's compose file, the variable values captured at
install time, the keychain index.  They all end up mode 0600 -- but the ones that
call ``write_text`` and *then* ``chmod`` publish their contents at the umask
default first, and on this host that is 0644.  The window is short, but a local
process only has to win it once, and a file's contents cannot be un-leaked.

How these tests work
--------------------
Timing a race is flaky, so instead each test asks a sharper question: *if chmod
never ran, would the file still be safe?*  With ``os.chmod``/``Path.chmod``
stubbed out and the umask forced wide open, a call site that creates the file
securely (``os.open`` with an explicit mode) still lands on 0600, while one that
depends on a follow-up chmod is left at 0666 -- exactly the state a concurrent
reader would have found.  That makes the guarantee deterministic to check and
keeps the assertion pointed at the real property: safe at creation, not safe
eventually.
"""
from __future__ import annotations

import errno
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import secure_io  # noqa: E402


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


class SecureWriteHelperTests(unittest.TestCase):
    """The shared helper is what the call sites are converted onto."""

    def setUp(self):
        self.tmp = Path(
            os.environ.get("TMPDIR", "/tmp")
        ) / f"serverhub-secret-test-{os.getpid()}"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_creates_a_new_file_already_private(self):
        target = self.tmp / "fresh.token"
        with NoChmod():
            secure_io.write_secret_text(target, "s3cret\n")
        self.assertEqual(
            mode_of(target),
            0o600,
            "a new secret file must be private at creation, not after a later chmod",
        )
        self.assertEqual(target.read_text(), "s3cret\n")

    def test_tightens_a_file_that_already_exists_too_open(self):
        target = self.tmp / "stale.token"
        target.write_text("old\n")
        os.chmod(target, 0o644)
        # chmod stays live here: repairing an existing file legitimately needs it.
        secure_io.write_secret_text(target, "new\n")
        self.assertEqual(mode_of(target), 0o600)
        self.assertEqual(target.read_text(), "new\n")

    def test_replaces_content_rather_than_appending(self):
        target = self.tmp / "trunc.token"
        secure_io.write_secret_text(target, "aaaaaaaaaa\n")
        secure_io.write_secret_text(target, "b\n")
        self.assertEqual(target.read_text(), "b\n")

    def test_append_text_creates_and_appends(self):
        target = self.tmp / "trail.jsonl"
        secure_io.append_text(target, "one\n", mode=0o600)
        secure_io.append_text(target, "two\n", mode=0o600)
        self.assertEqual(target.read_text(), "one\ntwo\n")
        self.assertEqual(mode_of(target), 0o600)

    def test_append_text_refuses_to_follow_a_last_component_symlink(self):
        target = self.tmp / "real.jsonl"
        target.write_text("keep\n")
        link = self.tmp / "alias.jsonl"
        link.symlink_to(target)
        with self.assertRaises(OSError) as ctx:
            secure_io.append_text(link, "stolen\n")
        self.assertEqual(ctx.exception.errno, __import__("errno").ELOOP)
        self.assertEqual(target.read_text(), "keep\n")

    def test_refuses_to_follow_a_last_component_symlink(self):
        target = self.tmp / "real.token"
        target.write_text("keep\n")
        os.chmod(target, 0o600)
        link = self.tmp / "alias.token"
        link.symlink_to(target)
        with self.assertRaises(OSError) as ctx:
            secure_io.write_secret_text(link, "stolen\n")
        self.assertEqual(ctx.exception.errno, __import__("errno").ELOOP)
        self.assertEqual(target.read_text(), "keep\n")

    def test_copy_secret_file_leftover_multi_mb_raises_efbig(self):
        """``Path.read_bytes()`` of leftover multi-MB source used to OOM settings save."""
        src = self.tmp / "huge.yaml"
        dst = self.tmp / "bak.yaml"
        src.write_bytes(b"x" * (2 * 1024 * 1024))
        with self.assertRaises(OSError) as ctx:
            secure_io.copy_secret_file(src, dst)
        self.assertEqual(ctx.exception.errno, errno.EFBIG)
        self.assertFalse(dst.exists())

    def test_copy_secret_file_copies_a_small_secret(self):
        src = self.tmp / "services.yaml"
        dst = self.tmp / "services.yaml.bak"
        src.write_text("settings: {}\n", encoding="utf-8")
        os.chmod(src, 0o644)
        with NoChmod():
            secure_io.copy_secret_file(src, dst)
        self.assertEqual(dst.read_text(encoding="utf-8"), "settings: {}\n")
        self.assertEqual(mode_of(dst), 0o600)

    def test_copy_secret_file_does_not_use_unbounded_read_bytes(self):
        src = Path(secure_io.__file__).read_text(encoding="utf-8")
        body = src[src.index("def copy_secret_file"): src.index("\ndef append_text")]
        self.assertIn("read_bytes_capped", body)
        self.assertNotIn(".read_bytes()", body)

    def test_creates_missing_parent_directories_privately(self):
        # NoChmod is deliberately NOT used here.  It proves "private at
        # creation", which is a property of the O_CREAT mode and only applies to
        # the file.  A directory's mode legitimately depends on a chmod, because
        # mkdir's mode argument is masked by the umask and is not applied to
        # intermediate levels at all -- so suppressing chmod would assert
        # something the OS cannot deliver.
        target = self.tmp / "nested" / "deep" / "creds.json"
        secure_io.write_secret_text(target, "{}\n")
        self.assertEqual(mode_of(target), 0o600)
        for d in (target.parent, target.parent.parent):
            self.assertEqual(
                mode_of(d),
                0o700,
                f"{d.name}: a directory holding secrets must not be listable "
                "by other users",
            )


class CallSiteTests(unittest.TestCase):
    """The real writers, exercised with chmod disabled."""

    def setUp(self):
        self.tmp = Path(
            os.environ.get("TMPDIR", "/tmp")
        ) / f"serverhub-callsite-test-{os.getpid()}"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        for child in sorted(self.tmp.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink(missing_ok=True)
            else:
                child.rmdir()
        self.tmp.rmdir()

    def test_cloudflared_tunnel_token_is_private_at_creation(self):
        from hub import cloudflared_svc

        token_file = self.tmp / "tunnel.token"
        with mock.patch.object(cloudflared_svc, "TOKEN_FILE", token_file), \
                mock.patch.object(cloudflared_svc, "_ensure_dirs", lambda: None):
            with NoChmod():
                cloudflared_svc._write_token(
                    "eyJhIjoiYWNjdGFjY3RhY2N0YWNjdGFjY3RhY2N0YWNjdGFjY3QiLCJzIjoic2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0IiwidCI6IjAxMjM0NTY3LTg5YWItY2RlZi0wMTIzLTQ1Njc4OWFiY2RlZiJ9"
                )

        self.assertEqual(
            mode_of(token_file),
            0o600,
            "the tunnel token grants ingress to the LAN; it must never be "
            "world-readable, not even briefly",
        )

    def test_service_credential_index_is_private_at_creation(self):
        from hub import service_credentials

        index = self.tmp / "index.json"
        with mock.patch.object(service_credentials, "INDEX_FILE", index):
            with NoChmod():
                service_credentials._save({"filebrowser": {"username": "admin"}})

        self.assertEqual(mode_of(index), 0o600)

    def test_cloudflared_state_is_private_at_creation(self):
        from hub import cloudflared_svc

        state = self.tmp / "serverhub-state.json"
        with mock.patch.object(cloudflared_svc, "STATE_FILE", state), \
                mock.patch.object(cloudflared_svc, "_ensure_dirs", lambda: None):
            with NoChmod():
                cloudflared_svc._save_state({"tunnel": "demo"})

        self.assertEqual(mode_of(state), 0o600)


if __name__ == "__main__":
    unittest.main()
