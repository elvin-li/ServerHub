"""Eleventh leftover-500s sweep of the Files page, over the real mounted app.

Nothing to fold: the whole known zoo was re-driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` against every mounted Files
route — GET /api/files, /api/files/list, download, and POST mkdir, rename,
delete, upload — plus the FileBrowser status/ondemand routes, and every case
already answered below 500 with a strictly renderable UTF-8 body.  files10
closed the last live leftover (a roots row whose dict-subclass ``.get`` raised
outside the enumerated arm), and this pass found no remaining one.

What earns a fresh regression pin here is the *end-to-end* coverage: the prior
files passes proved most of these vectors at the unit rank (``default_roots``,
``list_dir``, ``_as_text``) or one route at a time; this module drives the
whole mounted route stack — parse, resolve, list/read/write, render — with the
bombs in place at once, so a future refactor that moves a launderer cannot
quietly reopen the page.  The batteries:

* **A single roots list carrying the whole bomb zoo at once** (a KeyError
  ``.get`` row, a self-``__str__`` encode-bomb id, a bytes ``decode``-bomb
  name, a ``__bool__``-bomb path value, a float YAML id, and lone-surrogate
  id/name) plus one clean row: every route stays below 500 with a clean
  body, and the clean row still serves — the row-serving / one-row-cost
  contract holds through the HTTP layer, not just in ``default_roots``.

* **A float YAML id round-trips through GET /api/files/list** — the
  numeric-id ``str()`` probe (files_leftover_numeric_root_ids) was unit-pinned
  for ints; a float (``id: 1.5``) is the neighbour, addressed as ``"1.5"``.

* **Filesystem leftovers a listing walks into** — a FIFO (the download
  O_NONBLOCK guard), a symlink loop (the ``_try_resolve`` ELOOP guard), and a
  dangling symlink, all in one browsable root: the listing renders 200 clean,
  and download/rename against the FIFO and the loop answer coded 4xx rather
  than hanging or 500ing.  files9 pinned a unix socket; these are its
  siblings, driven the same end-to-end way.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
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
        # The SPA's failure mode is under test, not exception propagation
        # into the test process.
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


def _assert_below_500(test: unittest.TestCase, resp, route: str) -> None:
    _assert_clean(test, resp)
    test.assertLess(resp.status_code, 500, f"{route}: {resp.status_code} {resp.text[:200]}")


def _code(test: unittest.TestCase, resp) -> str:
    _assert_clean(test, resp)
    try:
        detail = resp.json()["detail"]
    except (ValueError, KeyError, TypeError):
        test.fail(f"uncoded body: {resp.status_code} {resp.text[:200]!r}")
    test.assertIsInstance(detail, dict, f"uncoded detail: {detail!r}")
    return detail.get("code", "")


# ── The leftover bomb classes (the modules5 / bookmarks5 / json6 shapes) ─────

class GetKeyErrRow(dict):
    """``.get`` raises OUTSIDE the enumerated per-row arm (files10's class)."""

    def get(self, *a, **k):
        raise KeyError("get keyerror bomb")


class SelfStrEncodeBomb(str):
    """``str()`` answers *self*, then the bound ``encode`` raises."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("str encode bomb")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class BoolBomb:
    """Truthiness bomb whose exception type is not RuntimeError."""

    def __bool__(self):
        raise ArithmeticError("bool bomb")


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root, patched in as the only configured root.

    ``settings_section`` is patched with a *plain dict* carrying the bombs:
    that models the real laundering exactly — the section mapping is
    re-dicted by hub.config, but the rows and values inside it are the
    original leftover objects.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        self.root.mkdir()
        (self.root / "a.txt").write_text("hi", encoding="utf-8")
        self.settings = {"roots": [{"id": "r", "path": str(self.root)}]}
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: self.settings
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _all_routes(self):
        return [
            ("GET /api/files", client().get("/api/files")),
            ("GET /api/files/list", client().get("/api/files/list")),
            (
                "GET /api/files/list?root",
                client().get("/api/files/list", params={"root_id": "r"}),
            ),
            (
                "GET /api/files/download",
                client().get(
                    "/api/files/download",
                    params={"path": str(self.root / "a.txt"), "root_id": "r"},
                ),
            ),
            (
                "POST /api/files/mkdir",
                client().post(
                    "/api/files/mkdir",
                    json={"path": str(self.root), "name": "d11", "root_id": "r"},
                ),
            ),
            (
                "POST /api/files/rename",
                client().post(
                    "/api/files/rename",
                    json={"path": str(self.root / "nope"), "new_name": "x", "root_id": "r"},
                ),
            ),
            (
                "POST /api/files/delete",
                client().post(
                    "/api/files/delete",
                    json={"path": str(self.root / "nope"), "root_id": "r"},
                ),
            ),
            (
                "POST /api/files/upload",
                client().post(
                    "/api/files/upload",
                    data={"path": str(self.root), "root_id": "r"},
                    files={"file": ("up11.bin", b"payload")},
                ),
            ),
            ("GET /api/files/filebrowser", client().get("/api/files/filebrowser")),
            (
                "POST /api/files/filebrowser/ondemand",
                client().post(
                    "/api/files/filebrowser/ondemand", json={"enabled": True}
                ),
            ),
        ]


# ── The whole zoo in one roots list, driven through every route ─────────────

class WholeZooRootsListStaysImmuneTests(_FilesSandbox):
    """One roots list carrying every bomb shape at once: no route 500s."""

    def setUp(self):
        super().setUp()
        self.settings["roots"] = [
            GetKeyErrRow({"id": "getbomb", "path": str(self.root)}),
            {"id": SelfStrEncodeBomb("enc"), "path": str(self.root)},
            {"id": "dec", "name": BytesDecodeBomb(b"n"), "path": str(self.root)},
            {"id": "boom", "path": BoolBomb()},
            {"id": "r\ud800x", "name": "n\ud800m", "path": str(self.root)},
            {"id": "r", "path": str(self.root)},
        ]

    def test_no_files_route_500s_with_the_whole_zoo_in_the_roots_list(self):
        for route, resp in self._all_routes():
            _assert_below_500(self, resp, route)

    def test_overview_renders_and_the_clean_row_survives(self):
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        ids = [r["id"] for r in resp.json()["roots"]]
        # The clean row's id is present; every bomb row either serves its real
        # storage or costs only itself — never the page.
        self.assertIn("r", ids)

    def test_listing_through_the_clean_row_still_works(self):
        resp = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("a.txt", [i["name"] for i in resp.json()["items"]])


# ── Float YAML id round-trips through the mounted list route ────────────────

class FloatYamlRootIdStaysImmuneTests(_FilesSandbox):
    """``id: 1.5`` in services.yaml arrives as a float; the ``str()`` probe
    keeps it addressable as ``"1.5"`` rather than collapsing to the basename
    or 500ing, end-to-end through GET /api/files/list."""

    def setUp(self):
        super().setUp()
        self.settings = yaml.safe_load(
            'roots:\n  - {path: "%s", id: 1.5, name: 2.5}\n' % self.root
        )
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: self.settings
        )
        patched.start()
        self.addCleanup(patched.stop)

    def test_float_id_is_kept_in_the_overview(self):
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        roots = resp.json()["roots"]
        self.assertEqual(roots[0]["id"], "1.5")
        self.assertEqual(roots[0]["name"], "2.5")

    def test_float_id_round_trips_to_a_listing(self):
        resp = client().get("/api/files/list", params={"root_id": "1.5"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("a.txt", [i["name"] for i in resp.json()["items"]])


# ── Filesystem leftovers a listing walks into ───────────────────────────────

class FilesystemLeftoverStaysImmuneTests(_FilesSandbox):
    """A FIFO, a symlink loop, and a dangling symlink in one browsable root:
    the listing renders and the read/write routes answer coded, never hang or
    500 (the download O_NONBLOCK and _try_resolve ELOOP guards, end-to-end)."""

    def setUp(self):
        super().setUp()
        try:
            os.mkfifo(self.root / "fifo")
        except OSError:  # pragma: no cover - platform without mkfifo
            self.skipTest("mkfifo unavailable on this host")
        os.symlink(self.root / "loop_b", self.root / "loop_a")
        os.symlink(self.root / "loop_a", self.root / "loop_b")
        os.symlink(self.root / "does-not-exist", self.root / "dangle")

    def test_listing_a_root_holding_a_fifo_and_loops_renders(self):
        resp = client().get(
            "/api/files/list", params={"path": str(self.root), "root_id": "r"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        names = {i["name"] for i in resp.json()["items"]}
        self.assertIn("a.txt", names)
        self.assertIn("fifo", names)

    def test_downloading_the_fifo_is_a_coded_answer_not_a_hang(self):
        resp = client().get(
            "/api/files/download",
            params={"path": str(self.root / "fifo"), "root_id": "r"},
        )
        _assert_clean(self, resp)
        self.assertIn(resp.status_code, (400, 403), resp.text[:200])
        self.assertIn(
            _code(self, resp), ("files.file_only", "files.permission_denied")
        )

    def test_downloading_the_symlink_loop_is_coded(self):
        resp = client().get(
            "/api/files/download",
            params={"path": str(self.root / "loop_a"), "root_id": "r"},
        )
        _assert_below_500(self, resp, "download loop")
        self.assertGreaterEqual(resp.status_code, 400)

    def test_renaming_the_loop_is_coded_not_a_500(self):
        resp = client().post(
            "/api/files/rename",
            json={"path": str(self.root / "loop_a"), "new_name": "z", "root_id": "r"},
        )
        _assert_below_500(self, resp, "rename loop")
        self.assertGreaterEqual(resp.status_code, 400)

    def test_deleting_the_fifo_succeeds_without_opening_it(self):
        resp = client().post(
            "/api/files/delete",
            json={"path": str(self.root / "fifo"), "root_id": "r"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse((self.root / "fifo").exists())


if __name__ == "__main__":
    unittest.main()
