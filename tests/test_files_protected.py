"""Guard tests for the file-browser deny-list.

These cover the security blocker where ~/Services and ~ were browsable roots,
so the panel would serve its own session-signing key, credential store and
admin password hash — and accept delete/rename on them.
"""
import asyncio
import errno
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
        self.assertTrue(files_svc.is_protected(Path("/tmp/notify-credentials.json")))

    def test_download_refuses_a_symlink_at_the_last_component(self):
        """_resolve_safe already followed the name; FileResponse used to reopen it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "secret"
            target.write_text("token", encoding="utf-8")
            link = root / "notes.txt"
            link.symlink_to(target)
            with patch.object(files_svc, "_resolve_safe", return_value=link):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.download(str(link), "downloads")
            detail = ctx.exception.detail
            code = detail.get("code") if isinstance(detail, dict) else detail
            self.assertEqual(code, "files.file_only")

    def test_download_opens_with_nofollow(self):
        src = Path(files_svc.__file__).read_text()
        self.assertIn("O_NOFOLLOW", src)
        self.assertIn("StreamingResponse", src)

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


class MkdirRaceTests(unittest.TestCase):
    def test_existing_name_is_files_exists_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            (parent / "taken").mkdir()
            with patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.mkdir(str(parent), "taken", "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.exists")

    def test_mkdir_fileexistserror_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)

            def racing(self, *a, **kw):
                raise FileExistsError()

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "mkdir", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.mkdir(str(parent), "new", "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.exists")


class DeleteRaceTests(unittest.TestCase):
    def test_missing_file_is_not_found_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            gone = parent / "already-gone"
            with patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.delete_path(str(gone), "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.not_found")

    def test_unlink_filenotfounderror_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "vanishing"
            target.write_text("x", encoding="utf-8")

            def racing(self):
                raise FileNotFoundError()

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "unlink", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.delete_path(str(target), "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.not_found")


class ListDirRaceTests(unittest.TestCase):
    def test_missing_dir_is_not_found_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            gone = parent / "already-gone"
            with patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.list_dir(str(gone), "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.not_found")

    def test_iterdir_filenotfounderror_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "vanishing"
            target.mkdir()

            def racing(self):
                raise FileNotFoundError()

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "iterdir", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.list_dir(str(target), "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.not_found")

    def test_iterdir_notadirectoryerror_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "was-dir"
            target.mkdir()

            def racing(self):
                raise NotADirectoryError()

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "iterdir", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.list_dir(str(target), "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.not_a_dir")

    def test_iterdir_oserror_is_coded(self):
        """A dying FUSE mount used to raise EIO and 500 the Files page."""
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "dying"
            target.mkdir()

            def racing(self):
                raise OSError(5, "I/O error")

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "iterdir", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.list_dir(str(target), "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.permission_denied")


class MkdirVanishedParentTests(unittest.TestCase):
    def test_mkdir_filenotfounderror_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)

            def racing(self, *a, **kw):
                raise FileNotFoundError()

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "mkdir", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.mkdir(str(parent), "new", "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.parent_not_a_dir")


class RenameRaceTests(unittest.TestCase):
    def test_rename_filenotfounderror_is_coded(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old-name"
            src.write_text("x", encoding="utf-8")

            def racing(src_path, dest_path):
                raise FileNotFoundError()

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(files_svc.os, "link", racing),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.rename_path(str(src), "new-name", "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.not_found")

    def test_rename_does_not_clobber_a_dest_planted_in_the_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old-name"
            src.write_text("keep", encoding="utf-8")
            dest = parent / "new-name"

            def plant_then_link(src_path, dest_path):
                Path(dest_path).write_text("secret", encoding="utf-8")
                raise FileExistsError(errno.EEXIST, "exists", dest_path)

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(files_svc.os, "link", plant_then_link),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.rename_path(str(src), "new-name", "tmp")
            self.assertEqual(ctx.exception.detail["code"], "files.dest_exists")
            self.assertEqual(src.read_text(encoding="utf-8"), "keep")
            self.assertEqual(dest.read_text(encoding="utf-8"), "secret")

    def test_rename_succeeds_when_dest_is_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old-name"
            src.write_text("keep", encoding="utf-8")
            dest = parent / "new-name"
            with patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                result = files_svc.rename_path(str(src), "new-name", "tmp")
            self.assertTrue(result["ok"])
            self.assertFalse(src.exists())
            self.assertEqual(dest.read_text(encoding="utf-8"), "keep")

    def test_directory_rename_refuses_an_existing_empty_dest(self):
        """POSIX rename would clobber the empty dest directory."""
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old-dir"
            dest = parent / "new-dir"
            src.mkdir()
            (src / "kept").write_text("keep", encoding="utf-8")
            dest.mkdir()
            with self.assertRaises(OSError) as ctx:
                files_svc._rename_no_clobber(src, dest)
            self.assertEqual(ctx.exception.errno, errno.EEXIST)
            self.assertEqual((src / "kept").read_text(encoding="utf-8"), "keep")
            self.assertEqual(list(dest.iterdir()), [])

    def test_directory_rename_succeeds_when_dest_is_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old-dir"
            dest = parent / "new-dir"
            src.mkdir()
            (src / "kept").write_text("keep", encoding="utf-8")
            files_svc._rename_no_clobber(src, dest)
            self.assertFalse(src.exists())
            self.assertEqual((dest / "kept").read_text(encoding="utf-8"), "keep")


class DeleteNotADirectoryTests(unittest.TestCase):
    def test_rmtree_notadirectoryerror_unlinks_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "was-dir"
            target.write_text("now-a-file", encoding="utf-8")

            with (
                patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                patch.object(Path, "is_dir", return_value=True),
                patch.object(Path, "is_symlink", return_value=False),
                patch.object(files_svc.shutil, "rmtree", side_effect=NotADirectoryError()),
            ):
                result = files_svc.delete_path(str(target), "tmp")
            self.assertTrue(result["ok"])
            self.assertFalse(target.exists())


class UploadVanishedParentTests(unittest.TestCase):
    def test_open_enoent_is_dest_not_a_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)

            def racing(*a, **kw):
                raise FileNotFoundError(errno.ENOENT, "no parent")

            class _File:
                filename = "upload.bin"

            async def _run():
                with (
                    patch.object(
                        files_svc, "default_roots",
                        return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                    ),
                    patch.object(files_svc.os, "open", racing),
                ):
                    await files_svc.upload(str(parent), _File(), "tmp")

            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(_run())
            self.assertEqual(ctx.exception.detail["code"], "files.dest_not_a_dir")


if __name__ == "__main__":
    unittest.main()
