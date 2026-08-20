"""Leftover 500s on share / ACL / NFS / usage path resolution.

Path.resolve() raises RuntimeError on a symlink loop, not OSError, so the
create-share, ACL, usage-tree and NFS-save paths used to escape as unhandled
exceptions. A corrupt file mtime did the same to largest-files via localtime,
and a garbled `du` `inf` 500'd GET /api/shares (Starlette allow_nan=False).

Later leftovers: YAML `.inf` / bytes quick_link URLs 500'd the shares page
JSON encoder; Path.is_dir/exists EIO/ESTALE on a dying mount 500'd create,
ACL, NFS save, NFS overview and usage tree; a junk files.default_roots row
AttributeError'd GET /api/storage/usage.

Follow-up: int/bytes ``nfsd`` / ``dscl`` / ``mdutil`` / ``sharing`` / ``open``
payloads AttributeError'd GET /api/nfs, /api/shares/acl, /api/storage/usage
and POST /api/shares/smb; inf/None ``st_size`` 500'd the usage-tree JSON
encoder; ENOSPC on the NFS stage file 500'd POST /api/nfs/exports.

Follow-up 2: ``Path.resolve()`` ValueError on an embedded NUL 500'd
POST /api/shares/smb (Path() itself accepts the NUL); leftover int/bytes/date
``chmod`` stderr TypeError'd PUT /api/shares/acl.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import nfs_svc, share_acl_svc, shares_svc, usage_svc
from hub.routers import shares as shares_router


def _symlink_loop(directory: Path) -> Path:
    loop = directory / "loop"
    loop.symlink_to(loop)
    return loop


class ShareHomeLeftoverTests(unittest.TestCase):
    def test_unresolved_home_skips_sensitive_roots(self):
        """Path.home() RuntimeError used to fail importing hub.shares_svc."""
        with mock.patch.object(shares_svc, "user_home", return_value=None):
            self.assertEqual(shares_svc._home_sensitive_roots(), ())

    def test_safe_resolve_symlink_loop_does_not_raise(self):
        """``BASE.resolve()`` leftover used to 500 import of hub.shares_svc."""
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            resolved = shares_svc._safe_resolve(loop)
        self.assertIsInstance(resolved, Path)
        for p in shares_svc._SENSITIVE_ROOTS + shares_svc._SYSTEM_ROOTS:
            self.assertIsInstance(p, Path)


class ShareSymlinkLoopTests(unittest.TestCase):
    def test_looping_share_path_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with self.assertRaises(shares_svc.ShareValidationError) as ctx:
                shares_svc.validate_share_path(str(loop))
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_looping_acl_path_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
                share_acl_svc._validated_dir(str(loop))
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_looping_acl_request_path_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with mock.patch.object(
                shares_router.shares_svc, "list_smb_shares", return_value=[]
            ):
                with self.assertRaises(HTTPException) as ctx:
                    shares_router._share_directory(str(loop))
        self.assertEqual(ctx.exception.detail["code"], "shares.bad_path")

    def test_loop_in_another_share_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "Public"
            target.mkdir()
            loop = _symlink_loop(root)
            with mock.patch.object(
                shares_router.shares_svc, "list_smb_shares",
                return_value=[{"path": str(loop)}, {"path": str(target)}],
            ):
                resolved = shares_router._share_directory(str(target))
        self.assertEqual(resolved, str(target.resolve()))


class SharePathNulTests(unittest.TestCase):
    def test_nul_share_path_is_coded_not_500(self):
        with self.assertRaises(shares_svc.ShareValidationError) as ctx:
            shares_svc.validate_share_path("/tmp/foo\x00bar")
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_surrogate_share_path_is_coded_not_500(self):
        with self.assertRaises(shares_svc.ShareValidationError) as ctx:
            shares_svc.validate_share_path("/tmp/\ud800")
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_expanduser_runtimeerror_is_coded_not_500(self):
        """``Path.expanduser`` RuntimeError on leftover HOME used to 500 POST /api/shares/smb."""
        with mock.patch.object(Path, "expanduser", side_effect=RuntimeError("no home")):
            with self.assertRaises(shares_svc.ShareValidationError) as ctx:
                shares_svc.validate_share_path("~/Media")
        self.assertEqual(ctx.exception.code, "shares.bad_path")


class UsageSymlinkAndMtimeTests(unittest.TestCase):
    def test_looping_usage_path_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with mock.patch.object(
                usage_svc, "scan_roots",
                return_value=[{"id": "t", "name": "t", "path": str(tmp)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    usage_svc._resolve(str(loop), None)
        self.assertEqual(ctx.exception.detail["code"], "files.not_found")

    def test_corrupt_mtime_does_not_500_largest_files(self):
        with (
            mock.patch.object(usage_svc, "_resolve", return_value=Path("/tmp")),
            mock.patch.object(
                usage_svc, "_walk_parallel",
                return_value=[{
                    "seen": 2,
                    "top": [
                        (10, "/tmp/huge", 1e20),
                        (8, "/tmp/nan", float("nan")),
                    ],
                }],
            ),
        ):
            out = usage_svc.largest_files("/", None, limit=10)
        self.assertEqual([item["path"] for item in out["items"]], ["/tmp/huge", "/tmp/nan"])
        self.assertEqual(out["items"][0]["mtime"], "")
        self.assertEqual(out["items"][1]["mtime"], "")

    def test_infinite_limit_is_clamped_not_500(self):
        with (
            mock.patch.object(usage_svc, "_resolve", return_value=Path("/tmp")),
            mock.patch.object(usage_svc, "_walk_parallel", return_value=[]),
        ):
            out = usage_svc.largest_files("/", None, limit=float("inf"))
        self.assertEqual(out["items"], [])


class SharesDuInfTests(unittest.TestCase):
    def test_infinite_du_size_does_not_500(self):
        with mock.patch.object(shares_svc, "sh", return_value=(0, "inf\t/tmp", "")):
            self.assertIsNone(shares_svc._dir_size_mb("/tmp"))
        with mock.patch.object(shares_svc, "sh", return_value=(0, "nan\t/tmp", "")):
            self.assertIsNone(shares_svc._dir_size_mb("/tmp"))


class NfsResolveLoopTests(unittest.TestCase):
    def test_looping_export_path_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                nfs_svc._validate_entry({"path": str(loop), "clients": ["everyone"]})
        self.assertIn(ctx.exception.code, {"nfs.path_missing", "nfs.bad_path"})

    def test_resolve_runtimeerror_on_a_real_dir_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "export"
            folder.mkdir()
            with mock.patch.object(
                nfs_svc.Path, "resolve", side_effect=RuntimeError("symlink loop")
            ):
                with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                    nfs_svc._validate_entry({
                        "path": str(folder), "clients": ["everyone"],
                    })
        self.assertEqual(ctx.exception.code, "nfs.bad_path")

    def test_huge_exports_does_not_oom_read(self):
        """``read_text()`` of leftover multi-MB /etc/exports used to OOM GET /api/nfs."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exports"
            path.write_bytes(b"x" * (2 * 1024 * 1024))
            with mock.patch.object(nfs_svc, "EXPORTS_PATH", path):
                self.assertEqual(nfs_svc.read_exports(), [])


class QuickLinkUrlJsonTests(unittest.TestCase):
    def _services(self, links):
        with (
            mock.patch.object(shares_svc, "port_open", return_value=False),
            mock.patch.object(shares_svc, "host_ip", return_value="192.0.2.9"),
            mock.patch.object(shares_svc, "cfg", lambda: {"quick_links": links}),
            mock.patch.object(shares_svc, "resolve_value", lambda v: v),
        ):
            return shares_svc.file_services()

    def test_infinite_quick_link_url_does_not_500_json(self):
        services = self._services([
            {"name": "FileBrowser", "url": float("inf")},
            {"name": "OneDrive Share", "url": float("nan")},
        ])
        json.dumps(services, allow_nan=False)
        by_id = {row["id"]: row for row in services}
        self.assertTrue(by_id["filebrowser"]["url"].startswith("http://192.0.2.9:"))
        self.assertTrue(by_id["onedrive-share"]["url"].startswith("http://192.0.2.9:"))

    def test_bytes_quick_link_url_does_not_500_json(self):
        services = self._services([
            {"name": "FileBrowser", "url": b"http://example.invalid"},
        ])
        json.dumps(services, allow_nan=False)
        self.assertTrue(services[0]["url"].startswith("http://192.0.2.9:"))

    def test_surrogate_quick_link_url_does_not_500_json(self):
        """Leftover ``\\ud800`` in a YAML quick_link URL used to 500 GET /api/shares."""
        services = self._services([
            {"name": "FileBrowser", "url": "http://example.invalid/\ud800"},
        ])
        dumped = json.dumps(services, ensure_ascii=False, allow_nan=False)
        dumped.encode("utf-8")
        self.assertNotIn("\ud800", dumped)
        self.assertNotIn("\ud800", services[0]["url"])


class SharesHostnameJsonTests(unittest.TestCase):
    def test_leftover_surrogate_hostname_does_not_500(self):
        """Leftover ``\\ud800`` from gethostname used to 500 GET /api/shares."""
        with (
            mock.patch.object(shares_svc.socket, "gethostname", return_value="mac\ud800"),
            mock.patch.object(shares_svc, "fan_out", return_value=["192.0.2.9", [], [], []]),
            mock.patch.object(shares_svc, "time_machine_status", return_value={}),
        ):
            out = shares_svc.shares_overview()
        dumped = json.dumps(out, ensure_ascii=False, allow_nan=False)
        dumped.encode("utf-8")
        self.assertNotIn("\ud800", out["host"]["name"])
        self.assertNotIn("\ud800", dumped)


class DyingMountIsDirTests(unittest.TestCase):
    def test_share_path_is_dir_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Media"
            folder.mkdir()
            with mock.patch.object(
                Path, "is_dir", autospec=True, side_effect=OSError(5, "I/O error")
            ):
                with self.assertRaises(shares_svc.ShareValidationError) as ctx:
                    shares_svc.validate_share_path(str(folder))
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_acl_path_is_dir_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Public"
            folder.mkdir()
            with mock.patch.object(
                Path, "is_dir", autospec=True, side_effect=OSError(5, "I/O error")
            ):
                with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
                    share_acl_svc._validated_dir(str(folder))
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_nfs_export_is_dir_estale_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "export"
            folder.mkdir()
            with mock.patch.object(
                Path, "is_dir", autospec=True,
                side_effect=OSError(70, "Stale NFS file handle"),
            ):
                with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                    nfs_svc._validate_entry({
                        "path": str(folder), "clients": ["everyone"],
                    })
        self.assertEqual(ctx.exception.code, "nfs.bad_path")

    def test_nfs_overview_exists_eio_does_not_500(self):
        self.addCleanup(nfs_svc.overview.invalidate)
        with (
            mock.patch.object(nfs_svc, "read_exports", return_value=[]),
            mock.patch.object(
                nfs_svc, "_nfsd_status",
                return_value={"enabled": False, "running": False, "detail": ""},
            ),
            mock.patch.object(
                Path, "exists", autospec=True, side_effect=OSError(5, "I/O error")
            ),
        ):
            data = nfs_svc.overview(force=True)
        self.assertFalse(data["exports_exists"])
        self.assertEqual(data["check"], {"ok": True, "detail": ""})
        json.dumps(data, allow_nan=False)


class UsageDyingMountAndJunkRootsTests(unittest.TestCase):
    def test_exists_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            parent = Path(tmp).resolve()
            target = parent / "dying"
            target.mkdir()
            with (
                mock.patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(parent)}],
                ),
                mock.patch.object(
                    Path, "exists", autospec=True, side_effect=OSError(5, "I/O error")
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    usage_svc._resolve(str(target), None)
        self.assertEqual(ctx.exception.detail["code"], "files.permission_denied")

    def test_is_dir_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            parent = Path(tmp).resolve()
            target = parent / "dying"
            target.mkdir()
            with (
                mock.patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(parent)}],
                ),
                mock.patch.object(
                    Path, "is_dir", autospec=True, side_effect=OSError(5, "I/O error")
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    usage_svc._resolve(str(target), None)
        self.assertEqual(ctx.exception.detail["code"], "files.permission_denied")

    def test_volumes_is_dir_eio_does_not_500_scan_roots(self):
        with (
            mock.patch.object(usage_svc.files_svc, "default_roots", return_value=[]),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=[]),
            mock.patch.object(
                Path, "is_dir", autospec=True, side_effect=OSError(5, "I/O error")
            ),
        ):
            roots = usage_svc.scan_roots()
        self.assertEqual(roots, [])
        json.dumps(roots, allow_nan=False)

    def test_volumes_is_dir_eio_does_not_500_spotlight(self):
        with (
            mock.patch.object(
                Path, "is_dir", autospec=True, side_effect=OSError(5, "I/O error")
            ),
            mock.patch.object(
                usage_svc, "fan_out", return_value=[(0, "Indexing enabled.")]
            ),
        ):
            rows = usage_svc.spotlight_status()
        self.assertEqual(rows[0]["volume"], "/")
        json.dumps(rows, allow_nan=False)

    def test_junk_default_roots_do_not_500(self):
        with (
            mock.patch.object(
                usage_svc.files_svc, "default_roots",
                return_value=[None, "x", {"id": "a"}, {"path": ["/tmp"]}],
            ),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=[]),
        ):
            roots = usage_svc.scan_roots()
        json.dumps(roots, allow_nan=False)
        self.assertFalse(any(r.get("id") == "a" for r in roots))


class NfsShPayloadTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(nfs_svc.overview.invalidate)

    def test_int_nfsd_status_does_not_500_overview(self):
        with (
            mock.patch.object(nfs_svc, "sh", return_value=(0, 5, "")),
            mock.patch.object(nfs_svc, "read_exports", return_value=[]),
            mock.patch.object(nfs_svc, "_exports_exists", return_value=False),
        ):
            data = nfs_svc.overview(force=True)
        self.assertFalse(data["server"]["running"])
        json.dumps(data, allow_nan=False)

    def test_bytes_nfsd_status_does_not_500_overview(self):
        def fake_sh(argv, timeout=0):
            if argv[:2] == [nfs_svc.NFSD, "status"]:
                return 0, b"nfsd service is enabled\nnfsd is running", b""
            if argv[0] == nfs_svc.SHOWMOUNT:
                return 0, b"Exports list on localhost:\n/tmp everyone\n", ""
            return 0, "", ""

        with (
            mock.patch.object(nfs_svc, "sh", side_effect=fake_sh),
            mock.patch.object(nfs_svc, "read_exports", return_value=[]),
            mock.patch.object(nfs_svc, "_exports_exists", return_value=False),
        ):
            data = nfs_svc.overview(force=True)
        self.assertTrue(data["server"]["running"])
        self.assertEqual(data["active"][0]["path"], "/tmp")
        json.dumps(data, allow_nan=False)

    def test_int_nfsstat_does_not_500_statistics(self):
        with mock.patch.object(nfs_svc, "sh", return_value=(0, 99, "")):
            out = nfs_svc.statistics()
        self.assertTrue(out["ok"])
        self.assertEqual(out["text"], "99")
        json.dumps(out, allow_nan=False)


class NfsStageWriteTests(unittest.TestCase):
    def test_stage_enospc_is_coded_not_500(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            folder = Path(tmp) / "export"
            folder.mkdir()
            with mock.patch.object(
                nfs_svc, "replace_secret_text",
                side_effect=OSError(28, "No space left on device"),
            ):
                result = nfs_svc.save_exports([
                    {"path": str(folder), "clients": ["everyone"]},
                ])
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "failed")

    def test_stage_recursing_oserror_does_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST /api/nfs/exports."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            folder = Path(tmp) / "export"
            folder.mkdir()
            with mock.patch.object(
                nfs_svc, "replace_secret_text",
                side_effect=Recursing(28, "No space left on device"),
            ):
                result = nfs_svc.save_exports([
                    {"path": str(folder), "clients": ["everyone"]},
                ])
        self.assertFalse(result.get("ok"))
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(result.get("message"), "Recursing")


class AclDsclPayloadTests(unittest.TestCase):
    def test_int_dscl_listing_does_not_500(self):
        with mock.patch.object(share_acl_svc, "sh", return_value=(0, 8, "")):
            self.assertEqual(share_acl_svc.local_users(), [])

    def test_bytes_dscl_listing_does_not_500(self):
        def fake_sh(argv, timeout=0):
            if "-list" in argv:
                return 0, b"a0000                  502\n", b""
            if argv[-1] == "RealName":
                return 0, b"RealName: Alice\n", b""
            return 1, "", ""

        with mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh):
            users = share_acl_svc.local_users()
        self.assertEqual(users[0]["username"], "a0000")
        self.assertEqual(users[0]["real_name"], "Alice")
        json.dumps(users, allow_nan=False)

    def test_recursing_as_text_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 GET /api/shares/acl."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(share_acl_svc._as_text(Recursing()), "Recursing")
        json.dumps({"t": share_acl_svc._as_text(Recursing())}, ensure_ascii=False).encode("utf-8")

    def test_inf_uniqueid_does_not_500_local_users(self):
        """Leftover UniqueID ``inf`` OverflowError'd GET /api/shares/acl."""
        def fake_sh(argv, timeout=0):
            if "-list" in argv:
                return 0, "alice inf\nbob 502\n", ""
            return 0, "RealName: Bob\n", ""

        with mock.patch.object(share_acl_svc, "sh", side_effect=fake_sh):
            users = share_acl_svc.local_users()
        json.dumps(users, allow_nan=False)
        self.assertEqual([u["username"] for u in users], ["bob"])


class AclChmodPayloadTests(unittest.TestCase):
    def test_bytes_chmod_is_needs_root_not_500(self):
        with mock.patch.object(
            share_acl_svc, "sh",
            return_value=(1, b"fail", b"operation not permitted"),
        ):
            result = share_acl_svc._run_unprivileged(
                [[share_acl_svc.CHMOD, "-a#", "0", "/tmp"]],
            )
        self.assertEqual(result["error"], "needs_root")
        self.assertIsInstance(result["message"], str)
        json.dumps(result, allow_nan=False)

    def test_int_chmod_does_not_500(self):
        with mock.patch.object(share_acl_svc, "sh", return_value=(1, 12, 13)):
            result = share_acl_svc._run_unprivileged(
                [[share_acl_svc.CHMOD, "-a#", "0", "/tmp"]],
            )
        self.assertEqual(result["error"], "failed")
        self.assertIsInstance(result["message"], str)
        json.dumps(result, allow_nan=False)

    def test_date_chmod_does_not_500(self):
        from datetime import date

        with mock.patch.object(
            share_acl_svc, "sh", return_value=(1, date(2026, 8, 19), None),
        ):
            result = share_acl_svc._run_unprivileged(
                [[share_acl_svc.CHMOD, "-a#", "0", "/tmp"]],
            )
        self.assertEqual(result["error"], "failed")
        self.assertIsInstance(result["message"], str)
        json.dumps(result, allow_nan=False)


class UsageSpotlightPayloadTests(unittest.TestCase):
    def test_int_mdutil_does_not_500(self):
        with (
            mock.patch.object(usage_svc, "sh", return_value=(0, 3, "")),
            mock.patch.object(Path, "is_dir", return_value=False),
        ):
            rows = usage_svc.spotlight_status()
        self.assertEqual(rows[0]["volume"], "/")
        self.assertEqual(rows[0]["state"], "unknown")
        json.dumps(rows, allow_nan=False)

    def test_bytes_mdutil_does_not_500(self):
        with (
            mock.patch.object(
                usage_svc, "sh", return_value=(0, b"Indexing enabled.", b""),
            ),
            mock.patch.object(Path, "is_dir", return_value=False),
        ):
            rows = usage_svc.spotlight_status()
        self.assertEqual(rows[0]["state"], "enabled")
        json.dumps(rows, allow_nan=False)


class UsageSizeJsonTests(unittest.TestCase):
    def test_infinite_st_size_does_not_500_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "huge").write_text("x", encoding="utf-8")

            class _Entry:
                name = "huge"
                path = str(target / "huge")

                def is_symlink(self):
                    return False

                def is_dir(self, follow_symlinks=False):
                    return False

                def is_file(self, follow_symlinks=False):
                    return True

                def stat(self, follow_symlinks=False):
                    return mock.Mock(st_size=float("inf"), st_mtime=1.0)

            class _Scan:
                def __enter__(self):
                    return [_Entry()]

                def __exit__(self, *exc):
                    return False

            with (
                mock.patch.object(usage_svc, "_resolve", return_value=target),
                mock.patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(target)}],
                ),
                mock.patch.object(usage_svc.os, "scandir", return_value=_Scan()),
            ):
                out = usage_svc.tree(str(target), None)
        json.dumps(out, allow_nan=False)
        self.assertEqual(out["children"][0]["bytes"], 0)

    def test_none_st_size_does_not_500_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)

            class _Entry:
                name = "x"
                path = str(target / "x")

                def is_symlink(self):
                    return False

                def is_dir(self, follow_symlinks=False):
                    return False

                def is_file(self, follow_symlinks=False):
                    return True

                def stat(self, follow_symlinks=False):
                    return mock.Mock(st_size=None, st_mtime=1.0)

            class _Scan:
                def __enter__(self):
                    return [_Entry()]

                def __exit__(self, *exc):
                    return False

            with (
                mock.patch.object(usage_svc, "_resolve", return_value=target),
                mock.patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(target)}],
                ),
                mock.patch.object(usage_svc.os, "scandir", return_value=_Scan()),
            ):
                out = usage_svc.tree(str(target), None)
        json.dumps(out, allow_nan=False)

    def test_string_mtime_does_not_500_largest_files(self):
        with (
            mock.patch.object(usage_svc, "_resolve", return_value=Path("/tmp")),
            mock.patch.object(
                usage_svc, "_walk_parallel",
                return_value=[{"seen": 1, "top": [(10, "/tmp/a", "not-a-time")]}],
            ),
        ):
            out = usage_svc.largest_files("/", None, limit=10)
        self.assertEqual(out["items"][0]["mtime"], "")
        json.dumps(out, allow_nan=False)

    def test_leftover_surrogate_hash_path_does_not_500(self):
        """``open()`` UnicodeEncodeError used to 500 GET /api/storage/usage/duplicates."""
        self.assertIsNone(usage_svc._hash_file(Path("/tmp/ok\ud800"), partial=True))


class SharesShPayloadTests(unittest.TestCase):
    def test_int_sharing_output_does_not_500_list(self):
        with (
            mock.patch.object(shares_svc, "sh", return_value=(0, 5, "")),
            mock.patch.object(shares_svc, "host_ip", return_value="192.0.2.1"),
        ):
            rows = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual(rows, [])
        json.dumps(rows, allow_nan=False)

    def test_deeply_nested_sharing_json_does_not_500_list(self):
        """``json.loads`` RecursionError is not ValueError; leftover nested
        ``sharing -l -f json`` used to 500 GET /api/shares/acl."""
        nested = '{"k":' * 12000 + "1" + "}" * 12000
        with (
            mock.patch.object(
                shares_svc, "sh",
                side_effect=[(0, nested, ""), (1, "", ""), (1, "", "")],
            ),
            mock.patch.object(shares_svc, "host_ip", return_value="192.0.2.1"),
        ):
            rows = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual(rows, [])
        json.dumps(rows, allow_nan=False)

    def test_int_open_output_does_not_500_settings(self):
        with mock.patch.object(shares_svc, "sh", return_value=(1, 5, 7)):
            out = shares_svc.open_system_settings()
        self.assertFalse(out["ok"])
        self.assertIsInstance(out["message"], str)
        json.dumps(out, allow_nan=False)

    def test_int_du_size_does_not_500(self):
        with mock.patch.object(shares_svc, "sh", return_value=(0, 12, "")):
            self.assertEqual(shares_svc._dir_size_mb("/tmp"), 12.0)

    def test_expanduser_runtimeerror_does_not_500_dir_size(self):
        """``os.path.expanduser`` RuntimeError used to 500 GET /api/shares via fan_out."""
        with mock.patch.object(os.path, "expanduser", side_effect=RuntimeError("no home")):
            self.assertIsNone(shares_svc._dir_size_mb("~/Media"))

    def test_huge_tm_quota_does_not_raise(self):
        huge = "1" + "0" * 400
        plist = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            "<plist version=\"1.0\"><array><dict>"
            "<key>dsAttrTypeStandard:RecordName</key>"
            "<array><string>Backups</string></array>"
            "<key>dsAttrTypeNative:timeMachineBackup</key>"
            "<array><string>1</string></array>"
            "<key>dsAttrTypeNative:backupQuotaSize</key>"
            f"<array><string>{huge}</string></array>"
            "</dict></array></plist>"
        )
        records = shares_svc.parse_time_machine_records(plist)
        self.assertTrue(records["Backups"]["time_machine"])
        self.assertIsNone(records["Backups"]["tm_quota_gb"])
        json.dumps(records, allow_nan=False)


class SharesAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_shares_as_text_recursing_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 GET /api/shares."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(shares_svc._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": shares_svc._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
