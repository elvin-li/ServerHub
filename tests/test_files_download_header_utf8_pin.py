"""Pin: the Files download header path stays latin-1/UTF-8 safe.

Starlette encodes response *header* values as latin-1 and JSON bodies as
UTF-8 (``ensure_ascii=False``), so the two classic leftover 500s on a file
manager are:

* a non-ASCII filename rendered verbatim into ``Content-Disposition``
  (UnicodeEncodeError during the header render — the exact bug the
  WireGuard peer download had, see
  tests/test_wireguard_download_header_leftover_500s.py), and
* an on-disk name that is not valid UTF-8 (the kernel hands it to Python as
  lone surrogates via surrogateescape) leaking into a JSON listing.

``GET /api/files/download`` is already safe by construction:
``files_svc.download`` builds the header as
``"attachment; filename*=UTF-8''" + quote(_as_text(p.name))`` — ``_as_text``
replaces lone surrogates, and ``quote`` percent-encodes every non-ASCII byte,
so the value is pure ASCII whatever the filesystem held.  Nothing pinned that
composition, so a refactor to ``filename="{name}"`` (the natural-looking
form) would reintroduce the 500 for every CJK/Cyrillic/latin-1 filename
without failing a single test.  These tests are that pin.

Also pinned here: the download failure paths beside the header keep their
coded 4xx shape (``files.file_only``), so a missing or non-file path never
degrades back to a bare 500.
"""
from __future__ import annotations

import asyncio
import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, unquote

from hub import files_svc

_RFC5987_PREFIX = "attachment; filename*=UTF-8''"

#: Leftover names a filesystem, an SMB client, or a hand-edit can produce.
#: Every one of these must survive Starlette's latin-1 header encode.
_LEFTOVER_NAMES = (
    "照片 2026.txt",          # CJK + space
    "café-menü.pdf",          # latin-1 but not ASCII
    "Телефон.conf",           # Cyrillic
    "phone².log",             # superscript (str.isalnum is true for it)
    "ok\ufffd.bin",           # replacement char from an earlier clean
    "bad\ud800name.txt",      # lone surrogate (surrogateescape leftover)
    "emoji-📷.jpg",
)


def _header_value(value: str) -> bytes:
    """Starlette's own header encode: the value has to survive it."""
    return value.encode("latin-1")


def _drain(response) -> bytes:
    """Consume a StreamingResponse body (and close its fd) outside an app."""
    async def _collect() -> bytes:
        chunks = []
        async for chunk in response.body_iterator:
            chunks.append(chunk if isinstance(chunk, bytes) else chunk.encode())
        return b"".join(chunks)

    return asyncio.run(_collect())


class HeaderCompositionPin(unittest.TestCase):
    """The exact expression download() uses, against adversarial names."""

    def test_every_leftover_name_yields_an_ascii_header(self):
        for name in _LEFTOVER_NAMES:
            with self.subTest(name=name):
                value = _RFC5987_PREFIX + quote(files_svc._as_text(name))
                _header_value(value)
                self.assertTrue(value.isascii(), value)

    def test_wellformed_names_round_trip_through_the_encoding(self):
        """The RFC 5987 form is not just safe — the client gets the name back."""
        for name in ("照片 2026.txt", "café-menü.pdf", "Телефон.conf"):
            with self.subTest(name=name):
                encoded = quote(files_svc._as_text(name))
                self.assertEqual(unquote(encoded), name)

    def test_lone_surrogate_degrades_to_replacement_not_an_exception(self):
        # quote() itself raises UnicodeEncodeError on a raw lone surrogate;
        # _as_text in front of it is what makes the pair total.
        with self.assertRaises(UnicodeEncodeError):
            quote("bad\ud800name.txt")
        cleaned = files_svc._as_text("bad\ud800name.txt")
        # encode(..., "replace") substitutes "?" on the *encode* side; the
        # point pinned here is that the surrogate is gone and quote is total.
        self.assertEqual(cleaned, "bad?name.txt")
        self.assertNotIn("\ud800", cleaned)
        _header_value(_RFC5987_PREFIX + quote(cleaned))


class _RootHarness(unittest.TestCase):
    """A scratch directory served as the only Files root."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="serverhub-files-dl-"))
        self.addCleanup(self._cleanup)
        patcher = patch.object(
            files_svc, "default_roots",
            return_value=[{"id": "tmp", "name": "tmp", "path": str(self.root)}],
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)


class DownloadServicePin(_RootHarness):
    """files_svc.download() directly: headers and body for leftover names."""

    def _download(self, path: str):
        response = files_svc.download(path, root_id="tmp")
        body = _drain(response)
        return response, body

    def test_cjk_filename_header_is_ascii_and_round_trips(self):
        target = self.root / "照片 2026.txt"
        target.write_bytes(b"pixels")
        response, body = self._download(str(target))
        disposition = response.headers["content-disposition"]
        _header_value(disposition)
        self.assertTrue(disposition.isascii(), disposition)
        self.assertTrue(disposition.startswith(_RFC5987_PREFIX), disposition)
        self.assertEqual(
            unquote(disposition[len(_RFC5987_PREFIX):]), "照片 2026.txt",
        )
        self.assertEqual(body, b"pixels")
        self.assertEqual(response.headers["content-length"], "6")

    def test_latin1_filename_header_is_ascii(self):
        target = self.root / "café-menü.pdf"
        target.write_bytes(b"%PDF")
        response, body = self._download(str(target))
        disposition = response.headers["content-disposition"]
        _header_value(disposition)
        self.assertTrue(disposition.isascii(), disposition)
        self.assertEqual(body, b"%PDF")

    def test_invalid_utf8_on_disk_name_downloads_with_an_ascii_header(self):
        """A raw-bytes name (surrogateescape) must stream its exact bytes.

        The display name degrades (surrogates replaced) in the header; the
        content must not degrade at all.
        """
        raw = os.path.join(os.fsencode(self.root), b"caf\xe9-\xff.txt")
        try:
            with open(raw, "wb") as handle:
                handle.write(b"raw bytes intact")
        except (OSError, ValueError):
            self.skipTest("filesystem refuses invalid UTF-8 names")
        listed = [n for n in os.listdir(self.root)]
        self.assertEqual(len(listed), 1)
        surrogate_name = listed[0]
        # Precondition for the pin: the kernel really handed back surrogates.
        with self.assertRaises(UnicodeEncodeError):
            surrogate_name.encode("utf-8")
        response, body = self._download(str(self.root / surrogate_name))
        disposition = response.headers["content-disposition"]
        _header_value(disposition)
        self.assertTrue(disposition.isascii(), disposition)
        self.assertEqual(body, b"raw bytes intact")

    def test_listing_beside_the_download_stays_utf8_safe(self):
        """The same directory must render as JSON without an encode error."""
        import json

        (self.root / "照片 2026.txt").write_bytes(b"x")
        raw = os.path.join(os.fsencode(self.root), b"caf\xe9-\xff.txt")
        try:
            with open(raw, "wb") as handle:
                handle.write(b"y")
        except (OSError, ValueError):
            pass  # the CJK row alone still exercises the encoder
        listing = files_svc.list_dir(str(self.root), "tmp")
        # Starlette's body encoder settings: the payload has to survive them.
        json.dumps(listing, ensure_ascii=False, allow_nan=False).encode("utf-8")
        names = {item["name"] for item in listing["items"]}
        self.assertIn("照片 2026.txt", names)


class DownloadRoutePin(_RootHarness):
    """Through the app: the request an SPA download link actually makes."""

    def _client(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def test_cjk_download_is_200_with_a_latin1_safe_header(self):
        target = self.root / "照片 2026.txt"
        target.write_bytes(b"pixels")
        client = self._client()
        response = client.get(
            "/api/files/download",
            params={"path": str(target), "root_id": "tmp"},
        )
        self.assertEqual(response.status_code, 200, response.text[:200])
        disposition = response.headers.get("content-disposition") or ""
        _header_value(disposition)
        self.assertTrue(disposition.isascii(), disposition)
        self.assertTrue(disposition.startswith(_RFC5987_PREFIX), disposition)
        self.assertEqual(response.content, b"pixels")

    def test_directory_stays_coded_400_not_500(self):
        client = self._client()
        response = client.get(
            "/api/files/download",
            params={"path": str(self.root), "root_id": "tmp"},
        )
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "files.file_only")

    def test_missing_path_stays_coded_400_not_500(self):
        client = self._client()
        response = client.get(
            "/api/files/download",
            params={"path": str(self.root / "gone.txt"), "root_id": "tmp"},
        )
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(response.json()["detail"]["code"], "files.file_only")


if __name__ == "__main__":
    unittest.main()
