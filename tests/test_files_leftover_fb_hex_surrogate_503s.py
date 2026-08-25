"""Leftover Files 500s: hex over-cap ints, surrogate FB paths, vanished binary.

Prior passes hardened the listing/download/upload paths (``_finite_int``,
``_as_text``, the O_NOFOLLOW opens — see test_files_logs_tools_leftover_500s
and test_leftover_photoshub_files_shares_digit_500s).  A fresh hunt over what
was left found four live failures, pinned here:

* ``max_upload_mb`` (``_max_upload_mb``): YAML parses hex/octal integer text
  uncapped (``int(x, 16)`` is a power-of-two base, so CPython's 4300-digit
  parse limit does not apply) — a leftover ``max_upload_mb: 0xFFF…`` was
  already an int, passed the conversion-only try untouched and silently
  disabled the upload size cap;
* the coded-error param sanitizer (``errors._jsonable_param``): the same
  already-int passthrough let an over-cap param reach Starlette's
  ``json.dumps``, which raises the very ValueError the guard was meant to
  eat — the coded 4xx became a 500 while encoding its own error body;
* the FileBrowser status paths (``filebrowser_status`` /
  ``set_filebrowser_ondemand``): a home directory whose on-disk name holds
  undecodable bytes reaches Python as lone surrogates (os surrogateescape);
  the listing fields are sanitized in ``_entry()`` but ``plist``/``bin``/
  ``root``/``url`` were returned raw, 500ing GET /api/files at Starlette's
  UTF-8 encode while the listing itself was clean;
* ``set_filebrowser_ondemand``: plistlib's XML parser reads
  ``<integer>0x…</integer>`` uncapped, so a leftover hex integer loads fine
  and then OverflowErrors the writer's 64-bit range check — loads() had been
  guarded, dumps() had not;
* ``ensure_filebrowser``: the binary vanishing between the ``_exists`` gate
  and the spawn answered with the uncoded 500 ``files.fb_start_failed``
  instead of a 503 like the other tool-absent states — and only after the
  disk confirms it actually left (the docker ``cli_on_disk`` / photoshub
  ``_ctl_on_disk`` rule); a spawn failure with the binary still present
  keeps the uncoded start failure.
"""
from __future__ import annotations

import errno
import json
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi import HTTPException

from hub import errors, files_svc

#: Loaded through a power-of-two base, so already an int past the digit cap.
_HUGE_HEX = int("F" * 5000, 16)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to every payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class UploadCapHexDigitPinTests(unittest.TestCase):
    """POST /api/files/upload sizes every chunk against this cap."""

    def _cap(self, raw):
        with mock.patch.object(
            files_svc, "settings_section", return_value={"max_upload_mb": raw}
        ):
            return files_svc._max_upload_mb()

    def test_over_cap_hex_yaml_keeps_the_cap_enforced(self):
        # The literal a leftover services.yaml would carry.
        raw = yaml.safe_load("max_upload_mb: 0x" + "F" * 5000)["max_upload_mb"]
        self.assertGreater(raw.bit_length(), 4300 * 3)  # already an int
        self.assertEqual(self._cap(raw), 512)

    def test_a_sane_cap_still_parses(self):
        self.assertEqual(self._cap(100), 100)
        self.assertEqual(self._cap("64"), 64)

    def test_bool_none_and_zero_fall_back(self):
        self.assertEqual(self._cap(True), 512)
        self.assertEqual(self._cap(None), 512)
        self.assertEqual(self._cap(0), 512)


class ErrorParamDigitPinTests(unittest.TestCase):
    """Every coded files error renders its params through this sanitizer."""

    def test_over_cap_int_param_drops_instead_of_500ing_the_body(self):
        status, body = errors.error_payload(
            "files.upload_too_large", max_mb=_HUGE_HEX
        )
        self.assertEqual(status, 400)
        _starlette(body)  # used to raise ValueError past the digit cap
        self.assertIsNone(body["detail"]["params"]["max_mb"])

    def test_a_sane_int_param_still_passes_through(self):
        status, body = errors.error_payload("files.upload_too_large", max_mb=512)
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["params"]["max_mb"], 512)
        self.assertIn("512", body["detail"]["message"])


class FileBrowserSurrogatePathPinTests(unittest.TestCase):
    """GET /api/files renders ``filebrowser_status`` on every page load."""

    def test_surrogate_home_paths_render_not_500(self):
        home = Path("/Users/m\udcffuser")
        with (
            mock.patch.object(files_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
            mock.patch.object(
                files_svc, "FB_PLIST",
                home / "Library" / "LaunchAgents" / "local.filebrowser.plist",
            ),
            mock.patch.object(
                files_svc, "FB_BIN",
                home / "Services" / "filebrowser" / "filebrowser-bin",
            ),
            mock.patch.object(
                files_svc, "FB_ROOT_DEFAULT", home / "Services" / "media"
            ),
            mock.patch.object(files_svc, "_exists", lambda p: True),
        ):
            state = files_svc.filebrowser_status()
        _starlette(state)  # used to raise UnicodeEncodeError
        # encode(..., "replace") swaps the surrogate for "?" on the way out.
        for field in ("plist", "bin", "root"):
            self.assertNotIn("\udcff", state[field])
            self.assertIn("m?user", state[field])


class OndemandHexPlistPinTests(unittest.TestCase):
    """POST /api/files/filebrowser/ondemand rewrites the LaunchAgent plist."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.plist = self.tmp / "local.filebrowser.plist"

    def _run(self, enabled=True):
        with (
            mock.patch.object(files_svc, "FB_PLIST", self.plist),
            mock.patch.object(files_svc, "sh", return_value=(0, "", "")),
        ):
            return files_svc.set_filebrowser_ondemand(enabled)

    def test_hex_over_cap_integer_answers_coded_bad_plist(self):
        self.plist.write_bytes(
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<plist version="1.0"><dict>'
            b"<key>Nice</key><integer>0x" + b"F" * 5000 + b"</integer>"
            b"<key>KeepAlive</key><true/>"
            b"</dict></plist>"
        )
        with self.assertRaises(HTTPException) as ctx:
            self._run(True)  # used to escape as a raw OverflowError
        self.assertEqual(ctx.exception.detail["code"], "files.fb_bad_plist")

    def test_a_sane_plist_still_flips_to_ondemand(self):
        self.plist.write_bytes(
            plistlib.dumps(
                {"Label": "local.filebrowser", "KeepAlive": True, "RunAtLoad": True}
            )
        )
        out = self._run(True)
        self.assertTrue(out["ok"])
        _starlette(out)
        written = plistlib.loads(self.plist.read_bytes())
        self.assertFalse(written["KeepAlive"])
        self.assertFalse(written["RunAtLoad"])


class VanishedFileBrowserBinaryPinTests(unittest.TestCase):
    """POST /api/files/filebrowser/ensure spawns the binary directly."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "filebrowser" / "filebrowser-bin"
        self.bin.parent.mkdir(parents=True)
        self.bin.write_text("#!/bin/sh\n")

    def _ensure(self, popen):
        with (
            mock.patch.object(files_svc, "FB_BIN", self.bin),
            mock.patch.object(files_svc, "FB_PLIST", self.tmp / "absent.plist"),
            mock.patch.object(files_svc, "FB_DB", self.bin.parent / "filebrowser.db"),
            mock.patch.object(files_svc, "FB_ROOT_DEFAULT", self.tmp / "media"),
            mock.patch.object(files_svc, "FB_LOG", self.tmp / "logs" / "fb.log"),
            mock.patch.object(files_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
            mock.patch.object(files_svc.time, "sleep"),
            mock.patch.object(files_svc.subprocess, "Popen", side_effect=popen),
        ):
            return files_svc.ensure_filebrowser()

    def test_vanished_binary_is_a_coded_503(self):
        def vanish(*args, **kwargs):
            # The _exists gate blessed the binary; it leaves the disk in the
            # window before the spawn.
            self.bin.unlink()
            raise FileNotFoundError(errno.ENOENT, "No such file or directory")

        with self.assertRaises(HTTPException) as ctx:
            self._ensure(vanish)  # used to answer the uncoded 500
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "files.fb_missing")

    def test_start_failure_with_binary_on_disk_stays_uncoded(self):
        def refuse(*args, **kwargs):
            raise PermissionError(errno.EACCES, "Operation not permitted")

        with self.assertRaises(HTTPException) as ctx:
            self._ensure(refuse)
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(ctx.exception.detail["code"], "files.fb_start_failed")
        self.assertTrue(self.bin.is_file())


if __name__ == "__main__":
    unittest.main()
