"""Seventh leftover-500s sweep of the Files page, over the real mounted app.

The hunted classes (UTF-8 surrogates in keys AND values, over-cap ints via
the YAML/plist hex bypass, numeric ids, FIFO/oversize/invalid-UTF-8 journals,
vanished-CLI 503s, iterbombs) were re-driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` against every mounted Files
route — this time including the two surfaces the files1-6 sweeps never
reached: raw *multipart* bodies on POST /api/files/upload (all prior HTTP
batteries sent JSON), and hostile on-disk LaunchAgent plists behind
POST /api/files/filebrowser/ondemand.

One live leak was found and fixed — three raw-500 shapes from a single
under-enumerated except arm.  ``set_filebrowser_ondemand()`` guarded
``plistlib.loads`` with ``(OSError, ValueError, OverflowError,
RecursionError)``, but plistlib's XML path raises far more than ValueError:

* a torn / truncated plist (a partial write, exactly the torn-journal class)
  raises ``xml.parsers.expat.ExpatError``;
* a plist whose bytes are not valid UTF-8 (CESU-8 surrogate bytes inside an
  XML-prefixed file) is the same ``ExpatError``;
* a junk ``<date>`` value raises ``AttributeError``
  (``NoneType…groupdict``);
* a stray ``<key>`` outside any ``<dict>`` raises ``IndexError``.

Each of those answered a raw ``Internal Server Error`` with a traceback in
the log while every neighbouring corruption (binary junk, oversize, non-dict,
over-cap hex ``<integer>``, FIFO at the path) already got the coded
``files.fb_bad_plist``.  The fix swallows broadly around the capped
read + parse, like the sibling reader ``_plist_keepalive()`` and every other
plist reader in the repo (raid_svc and snapshots_svc document the identical
ExpatError leftover).

The multipart battery pins what was probed and found already immune —
including the ``charset=unicode_escape`` trick, which is the one route by
which a network client really can mint *lone surrogates* into ``str`` form
fields (Starlette decodes each part with the client-sent charset).
"""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import files_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_client = None


def client() -> TestClient:
    global _client
    if _client is None:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        # The SPA's failure mode is what is under test, not exception
        # propagation into the test process.
        _client = TestClient(app, raise_server_exceptions=False)
    return _client


def _assert_clean(test: unittest.TestCase, resp) -> None:
    """The body must be strictly renderable UTF-8 with no lone surrogates."""
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")


def _code(test: unittest.TestCase, resp) -> str:
    """The machine-readable error code — a raw 500 body has none."""
    _assert_clean(test, resp)
    try:
        detail = resp.json()["detail"]
    except (ValueError, KeyError, TypeError):
        test.fail(f"uncoded body: {resp.status_code} {resp.text[:200]!r}")
    test.assertIsInstance(detail, dict, f"uncoded detail: {detail!r}")
    return detail.get("code", "")


class OndemandHostilePlistHttpTests(unittest.TestCase):
    """The fixed leak: every plist corruption answers the coded shape.

    On the pre-fix tree the first four cases below answered a raw
    ``Internal Server Error`` (ExpatError / AttributeError / IndexError
    escaping the enumerated except arm); the rest were already coded and
    must stay that way.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.plist = self.tmp / "local.filebrowser.plist"
        patched = mock.patch.object(files_svc, "FB_PLIST", self.plist)
        patched.start()
        self.addCleanup(patched.stop)

    def _ondemand(self, content: bytes | None = None, *, enabled=True):
        if content is not None:
            self.plist.write_bytes(content)
        # launchctl is absent on CI anyway (sh maps that to rc -1), but a
        # macOS dev machine must not have its live launchd domain touched.
        with mock.patch.object(files_svc, "sh", return_value=(1, "", "")):
            return client().post(
                "/api/files/filebrowser/ondemand", json={"enabled": enabled}
            )

    def _assert_bad_plist(self, resp):
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.fb_bad_plist")

    def test_torn_xml_plist_is_the_coded_error_not_a_raw_500(self):
        # A partial write: valid XML prefix, then the file just ends.
        self._assert_bad_plist(self._ondemand(
            b"<?xml version='1.0'?><plist version='1.0'><dict><key>K</key>"
        ))

    def test_invalid_utf8_bytes_plist_is_the_coded_error(self):
        # CESU-8 surrogate bytes inside an XML-prefixed plist: expat refuses
        # the encoding, which is ExpatError, not ValueError.
        self._assert_bad_plist(self._ondemand(
            b"<?xml version='1.0'?><plist version='1.0'><dict>"
            b"<key>K\xed\xa0\x80</key><string>v</string></dict></plist>"
        ))

    def test_junk_date_plist_is_the_coded_error(self):
        # plistlib's <date> handler does re.match(...).groupdict() with no
        # None check — AttributeError, not ValueError.
        self._assert_bad_plist(self._ondemand(
            b"<?xml version='1.0'?><plist version='1.0'><dict>"
            b"<key>D</key><date>junk</date></dict></plist>"
        ))

    def test_stray_key_outside_a_dict_is_the_coded_error(self):
        # <key> with no enclosing <dict> pops an empty stack — IndexError.
        self._assert_bad_plist(self._ondemand(
            b"<?xml version='1.0'?><plist version='1.0'>"
            b"<key>K</key></plist>"
        ))

    def test_binary_junk_plist_stays_the_coded_error(self):
        self._assert_bad_plist(self._ondemand(b"\xff\xfe not a plist"))

    def test_oversize_plist_stays_the_coded_error(self):
        self._assert_bad_plist(self._ondemand(
            b"<plist>" + b"A" * (files_svc._PLIST_CAP + 1024)
        ))

    def test_non_dict_plist_stays_the_coded_error(self):
        self._assert_bad_plist(self._ondemand(plistlib.dumps(["not", "a", "dict"])))

    def test_over_cap_hex_integer_plist_stays_the_coded_error(self):
        # <integer>0x…</integer> loads through int(x, 16) uncapped; the
        # writer's 64-bit range check then OverflowErrors dumps().
        self._assert_bad_plist(self._ondemand(
            b"<?xml version='1.0'?><plist version='1.0'><dict>"
            b"<key>Label</key><string>x</string>"
            b"<key>N</key><integer>0x" + b"F" * 4400 + b"</integer>"
            b"</dict></plist>"
        ))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no mkfifo")
    def test_fifo_at_the_plist_path_stays_the_coded_error(self):
        os.mkfifo(self.plist)
        self._assert_bad_plist(self._ondemand(None))

    def test_a_valid_plist_still_flips_ondemand(self):
        resp = self._ondemand(plistlib.dumps(
            {"Label": "local.filebrowser", "RunAtLoad": True, "KeepAlive": True}
        ))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue(resp.json()["ondemand"])
        written = plistlib.loads(self.plist.read_bytes())
        self.assertFalse(written["RunAtLoad"])
        self.assertFalse(written["KeepAlive"])

    def test_service_level_expat_shape_is_the_coded_exception(self):
        self.plist.write_bytes(
            b"<?xml version='1.0'?><plist version='1.0'><dict><key>K</key>"
        )
        with mock.patch.object(files_svc, "sh", return_value=(1, "", "")):
            with self.assertRaises(HTTPException) as ctx:
                files_svc.set_filebrowser_ondemand(True)
        self.assertEqual(ctx.exception.detail["code"], "files.fb_bad_plist")


class _UploadSandbox(unittest.TestCase):
    """One temp browsable root, patched in as the only configured root."""

    BOUNDARY = "files7boundary"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        self.root.mkdir()
        self.settings = {"roots": [{"id": "r", "path": str(self.root)}]}
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: self.settings
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _multipart(self, parts, charset: str | None = None):
        """A raw multipart body from (headers-bytes, body-bytes) pairs."""
        b = self.BOUNDARY.encode()
        out = b""
        for headers, body in parts:
            out += b"--" + b + b"\r\n" + headers + b"\r\n\r\n" + body + b"\r\n"
        out += b"--" + b + b"--\r\n"
        ctype = f"multipart/form-data; boundary={self.BOUNDARY}"
        if charset:
            ctype += f"; charset={charset}"
        return out, ctype

    def _upload(self, parts, charset: str | None = None):
        body, ctype = self._multipart(parts, charset)
        return client().post(
            "/api/files/upload", content=body, headers={"content-type": ctype}
        )

    def _field(self, name: str, value: bytes) -> tuple[bytes, bytes]:
        return (
            b'Content-Disposition: form-data; name="' + name.encode() + b'"',
            value,
        )

    def _file(self, filename: bytes, value: bytes) -> tuple[bytes, bytes]:
        return (
            b'Content-Disposition: form-data; name="file"; filename="'
            + filename + b'"',
            value,
        )


class UploadMultipartStaysImmuneTests(_UploadSandbox):
    """Hostile raw multiparts through the real app's parse + routing."""

    def test_plain_upload_lands_in_the_root(self):
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            self._file(b"up.txt", b"payload"),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertEqual((self.root / "up.txt").read_bytes(), b"payload")

    def test_invalid_utf8_filename_bytes_upload_and_render_clean(self):
        # Starlette decodes part headers with a latin-1 fallback, so raw
        # \xff\xfe bytes become ÿþ rather than raising mid-parse.
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            self._file(b"f\xff\xfe.txt", b"x"),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertEqual(resp.json()["name"], "f\xff\xfe.txt")

    def test_unicode_escape_charset_surrogate_filename_is_the_coded_400(self):
        # charset=unicode_escape is the one way a network client can mint a
        # *lone surrogate* into a str form field: Starlette decodes each part
        # with the client-sent charset, and \\ud800 escapes decode to the
        # bare surrogate.  _clean_component's encode probe must refuse it and
        # the error body must survive Starlette's strict UTF-8 render.
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            self._file(b"a\\ud800b.txt", b"x"),
        ], charset="unicode_escape")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.bad_name")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unicode_escape_charset_surrogate_path_is_coded_and_clean(self):
        resp = self._upload([
            self._field("path", b"/tmp/a\\ud800b"),
            self._file(b"a.txt", b"x"),
        ], charset="unicode_escape")
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.not_found")
        _assert_clean(self, resp)

    def test_bogus_charset_falls_back_and_still_uploads(self):
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            self._file(b"ok.txt", b"x"),
        ], charset="no-such-codec")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_traversal_filename_is_flattened_into_the_root(self):
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            self._file(b"../../evil.txt", b"x"),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["path"], str(self.root / "evil.txt"))
        self.assertTrue((self.root / "evil.txt").is_file())
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_huge_digit_root_id_is_the_coded_400(self):
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"9" * 5000),
            self._file(b"a.txt", b"x"),
        ])
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.unknown_root")

    def test_missing_boundary_is_a_400_not_a_500(self):
        resp = client().post(
            "/api/files/upload", content=b"garbage",
            headers={"content-type": "multipart/form-data"},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _assert_clean(self, resp)

    def test_binary_junk_multipart_is_a_400_not_a_500(self):
        resp = client().post(
            "/api/files/upload", content=b"\xff" * 64,
            headers={"content-type": "multipart/form-data; boundary=X"},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _assert_clean(self, resp)

    def test_over_cap_upload_is_the_coded_400_and_leaves_no_debris(self):
        self.settings["max_upload_mb"] = 1
        resp = self._upload([
            self._field("path", str(self.root).encode()),
            self._field("root_id", b"r"),
            self._file(b"big.bin", b"A" * (1024 * 1024 + 2)),
        ])
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(_code(self, resp), "files.upload_too_large")
        self.assertFalse((self.root / "big.bin").exists())


if __name__ == "__main__":
    unittest.main()
