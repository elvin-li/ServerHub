"""Leftover UTF-8 500s on the shares / share-ACL / NFS surface.

Hunt across the remaining share-corner encode paths (hub/routers/shares.py,
hub/shares_svc.py, hub/share_acl_svc.py, hub/nfs_svc.py) after the digit-limit
and payload passes (test_leftover_share_acl_digit_500s,
test_leftover_photoshub_files_shares_digit_500s,
test_shares_nfs_usage_leftover_500s).  One UTF-8 leftover was still live:

* ``nfs_svc.save_exports`` staged the rendered table with
  ``replace_secret_text``, which writes strict UTF-8, but only mapped OSError
  to a coded failure.  A directory whose on-disk name holds undecodable bytes
  arrives from ``os.fsdecode`` as lone ``\\udcXX`` surrogates; such a path
  passes ``_validate_entry`` (it exists, ``is_dir`` is true, and a surrogate
  is neither a control character nor a quote), so the stage write raised
  UnicodeEncodeError — a ValueError, which is not OSError and not
  NfsConfigError, the only things the router maps — and 500'd
  POST /api/nfs/exports.  ``_validate_entry`` now refuses the path with the
  coded ``nfs.bad_path``, and the stage write maps ValueError as the second
  layer.

The battery also pins the hunted siblings that already survive this class:

* the share-ACL read on such a directory: ``as_argv`` refuses surrogate argv,
  so ``read_acl`` raises the coded ``ShareAclError`` the routers map instead
  of leaking UnicodeEncodeError out of the spawn;
* the per-share ``du -sm`` size on such a path answers None, not a raise;
* a surrogate-bearing share record name (JSON bodies may carry ``\\ud800``)
  passes name validation but the privileged spawn refuses the argv, so
  ``create_smb_share`` returns the coded admin failure the router maps;
* a raw non-UTF-8 ``/etc/exports`` is read with ``errors="replace"``, so
  GET /api/nfs renders every entry without a surrogate in the payload.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import nfs_svc, share_acl_svc, shares_svc
from hub.macos_admin import use_admin_password


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _undecodable_dir(parent: Path) -> str:
    """A real directory whose name cannot decode as UTF-8, or skip.

    ``os.fsdecode`` hands the \\xff byte back as the lone surrogate
    ``\\udcff`` — the exact shape a leftover mount or a Linux-created
    folder presents to every share-corner path helper.
    """
    raw = os.path.join(os.fsencode(str(parent)), b"exp\xffort")
    try:
        os.mkdir(raw)
    except OSError as error:  # pragma: no cover - APFS refuses the byte
        raise unittest.SkipTest(f"filesystem refuses undecodable names: {error}")
    return os.fsdecode(raw)


class NfsUndecodableExportPathTests(unittest.TestCase):
    """POST /api/nfs/exports used to 500 on a real surrogate-named directory."""

    def test_validate_entry_refuses_the_surrogate_path(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path = _undecodable_dir(Path(tmp))
            with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                nfs_svc._validate_entry({"path": path, "clients": ["everyone"]})
        self.assertEqual(ctx.exception.code, "nfs.bad_path")

    def test_save_exports_is_coded_not_500(self):
        """UnicodeEncodeError escaped the OSError map before the stage write."""
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path = _undecodable_dir(Path(tmp))
            with mock.patch.object(nfs_svc, "run_admin_sequence") as admin:
                with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
                    nfs_svc.save_exports([{"path": path, "clients": ["everyone"]}])
        self.assertEqual(ctx.exception.code, "nfs.bad_path")
        admin.assert_not_called()

    def test_a_clean_sibling_still_validates(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            folder = Path(tmp) / "export"
            folder.mkdir()
            entry = nfs_svc._validate_entry({
                "path": str(folder), "clients": ["everyone"],
            })
        self.assertTrue(entry["everyone"])
        _starlette(entry)


class NfsStageSurrogateWriteTests(unittest.TestCase):
    """Second layer: a stage-write UnicodeEncodeError is a coded failure."""

    def test_stage_unicode_error_is_coded_not_500(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            folder = Path(tmp) / "export"
            folder.mkdir()
            with mock.patch.object(
                nfs_svc, "replace_secret_text",
                side_effect=UnicodeEncodeError(
                    "utf-8", "\udcff", 0, 1, "surrogates not allowed",
                ),
            ):
                result = nfs_svc.save_exports([
                    {"path": str(folder), "clients": ["everyone"]},
                ])
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "failed")
        _starlette(result)


class AclUndecodableDirPinTests(unittest.TestCase):
    """GET/PUT /api/shares/acl answer the coded ShareAclError, not a raise."""

    def test_read_acl_is_coded_not_a_unicode_raise(self):
        # ``as_argv`` refuses surrogate argv, so the ``ls -lde`` spawn reports
        # rc=-1 and read_acl raises the code the routers already map.
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path = _undecodable_dir(Path(tmp))
            with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
                share_acl_svc.read_acl(path)
        self.assertEqual(ctx.exception.code, "shares.acl_read_failed")


class SharesUndecodablePathPinTests(unittest.TestCase):
    """GET /api/shares keeps its rows when one share path is undecodable."""

    def test_dir_size_answers_none_not_a_raise(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path = _undecodable_dir(Path(tmp))
            self.assertIsNone(shares_svc._dir_size_mb(path))

    def test_surrogate_record_name_is_a_coded_admin_failure(self):
        """JSON bodies may carry ``\\ud800``; _NAME_RE accepts it, the spawn
        refuses it, and POST /api/shares/smb maps the coded failure."""
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            folder = Path(tmp) / "Media"
            folder.mkdir()
            with (
                mock.patch.object(shares_svc, "_find_share", return_value=None),
                use_admin_password("pw"),
            ):
                result = shares_svc.create_smb_share(
                    path=str(folder), name="Media\ud800", smb_name="Media",
                    guest=False, readonly=False, encrypted=False,
                )
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "unavailable")
        _starlette(result)


class NfsExportsRawBytesPinTests(unittest.TestCase):
    """GET /api/nfs reads a raw non-UTF-8 exports file with errors=replace."""

    def test_raw_bytes_render_without_surrogates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exports"
            path.write_bytes(b"/srv/exp\xffort -alldirs 10.0.0.0\n")
            with mock.patch.object(nfs_svc, "EXPORTS_PATH", path):
                entries = nfs_svc.read_exports()
        self.assertEqual(len(entries), 1)
        _starlette(entries)
        self.assertNotIn("\udcff", json.dumps(entries, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
