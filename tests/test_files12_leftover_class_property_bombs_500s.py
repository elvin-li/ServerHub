"""Twelfth leftover-500s sweep of the Files page, over the real mounted app.

files11 re-drove the whole known Files zoo through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` and found only stays-immune
pins.  This pass hunts the one net files11 did not carry: the
**``__class__``-property bomb** (the modules8/catalog10/tools ``_isinst``
rule).  CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
real-type fast check misses, so a leftover whose ``__class__`` is a raising
property blows straight through a *bare* ``isinstance`` gate that sits outside
a try.  Two such gates were live raw 500s in hub/files_svc.py:

* **``isinstance(_settings().get("roots"), list)``** in ``default_roots`` — the
  very first thing every Files route runs (``_resolve_safe`` → ``default_roots``).
  A leftover ``roots`` value whose ``__class__`` raises 500'd GET /api/files,
  /api/files/list, download, and POST mkdir/rename/delete/upload all at once.
  Confirmed live before the fix (raw ``500 Internal Server Error``).

* **``isinstance(raw, bool)``** in ``_max_upload_mb`` on a leftover
  ``settings.files.max_upload_mb`` — read only by POST /api/files/upload, and it
  raised *after* the multipart body was accepted, so the upload 500'd raw.

The fix routes both gates (and the sibling ``_as_text`` / ``_root_label`` type
checks) through a guarded ``files_svc._isinst`` that fails closed to False, so
a raising ``__class__`` degrades to "none of these types": the ``roots``
section falls back to the default candidates like an absent key, and the
upload cap falls back to its 512 MB default.

The rest of this module pins the neighbouring shapes as **stays-immune** — a
str-subclass mapping key with a raising ``__eq__``, a ``roots`` list-subclass
whose ``__len__`` / ``__iter__`` raises, a ``__bool__``-bomb path value, and a
``__class__``-bomb row inside an otherwise clean list — so a future refactor
that reorders a launderer cannot quietly reopen the page.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        _client = TestClient(app, raise_server_exceptions=False)
    return _client


def _assert_clean(test: unittest.TestCase, resp) -> None:
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")


def _assert_below_500(test: unittest.TestCase, resp, route: str) -> None:
    _assert_clean(test, resp)
    test.assertLess(resp.status_code, 500, f"{route}: {resp.status_code} {resp.text[:200]}")


# ── The leftover bomb classes ────────────────────────────────────────────────

class ClassBomb:
    """``__class__`` is a raising property: ``isinstance(x, T)`` reads it on the
    real-type miss and raises unless the gate is guarded."""

    @property
    def __class__(self):  # type: ignore[override]
        raise RuntimeError("class bomb")


class EqBombKey(str):
    """A str-subclass mapping key whose ``__eq__`` raises, hash-colliding with
    the literal ``"path"`` the unbound ``dict.get`` looks up."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __hash__(self):
        return hash("path")


class LenBombList(list):
    def __len__(self):
        raise RuntimeError("len bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class BoolBombPath:
    def __bool__(self):
        raise ArithmeticError("bool bomb")


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root; ``settings_section`` patched with a plain dict
    carrying the leftover values (models hub.config's real laundering — the
    section mapping is re-dicted but the values inside are the leftovers)."""

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
                "GET /api/files/download",
                client().get(
                    "/api/files/download",
                    params={"path": str(self.root / "a.txt")},
                ),
            ),
            (
                "POST /api/files/mkdir",
                client().post(
                    "/api/files/mkdir",
                    json={"path": str(self.root), "name": "d12"},
                ),
            ),
            (
                "POST /api/files/rename",
                client().post(
                    "/api/files/rename",
                    json={"path": str(self.root / "nope"), "new_name": "x"},
                ),
            ),
            (
                "POST /api/files/delete",
                client().post(
                    "/api/files/delete",
                    json={"path": str(self.root / "nope")},
                ),
            ),
            (
                "POST /api/files/upload",
                client().post(
                    "/api/files/upload",
                    data={"path": str(self.root)},
                    files={"file": ("up12.bin", b"payload")},
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


# ── New find #1: __class__-bomb roots value 500'd every Files route ──────────

class ClassBombRootsValueTests(_FilesSandbox):
    """``settings.files.roots`` is a leftover whose ``__class__`` raises: the
    ``isinstance(..., list)`` gate at the head of ``default_roots`` used to 500
    every route.  Guarded, the section degrades to the default candidates."""

    def setUp(self):
        super().setUp()
        self.settings["roots"] = ClassBomb()

    def test_no_files_route_500s(self):
        for route, resp in self._all_routes():
            _assert_below_500(self, resp, route)

    def test_overview_degrades_to_default_candidates(self):
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        # The bomb roots value is treated as absent, so ``default_roots``
        # returns the built-in candidates (whatever of them exist on the host)
        # rather than raising.  The key contract is a non-500, renderable body.
        self.assertIsInstance(resp.json()["roots"], list)

    def test_default_roots_unit_degrades(self):
        self.assertIsInstance(files_svc.default_roots(), list)


# ── New find #2: __class__-bomb max_upload_mb 500'd the upload ───────────────

class ClassBombMaxUploadTests(_FilesSandbox):
    """``settings.files.max_upload_mb`` is a leftover whose ``__class__``
    raises: ``_max_upload_mb``'s ``isinstance(raw, bool)`` used to 500 POST
    /api/files/upload after the body was accepted.  Guarded, it falls back to
    the 512 MB default and the upload completes."""

    def setUp(self):
        super().setUp()
        self.settings["max_upload_mb"] = ClassBomb()

    def test_upload_completes_with_the_default_cap(self):
        resp = client().post(
            "/api/files/upload",
            data={"path": str(self.root)},
            files={"file": ("up12.bin", b"payload")},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue((self.root / "up12.bin").exists())

    def test_max_upload_mb_unit_falls_back_to_512(self):
        self.assertEqual(files_svc._max_upload_mb(), 512)


# ── Stays-immune neighbours ──────────────────────────────────────────────────

class NeighbourBombsStayImmuneTests(_FilesSandbox):
    """The shapes next to the two finds: none 500 any route, and a clean
    sibling row is always kept."""

    def _drive(self, roots):
        self.settings["roots"] = roots
        for route, resp in self._all_routes():
            _assert_below_500(self, resp, route)

    def test_eq_bomb_mapping_key_row_is_dropped_not_500(self):
        self._drive([
            {EqBombKey("path"): str(self.root), "id": "x"},
            {"id": "r", "path": str(self.root)},
        ])

    def test_len_bomb_roots_list_degrades(self):
        self._drive(LenBombList([{"id": "r", "path": str(self.root)}]))

    def test_iter_bomb_roots_list_degrades(self):
        self._drive(IterBombList([{"id": "r", "path": str(self.root)}]))

    def test_bool_bomb_path_value_row_is_dropped_not_500(self):
        self._drive([
            {"id": "boom", "path": BoolBombPath()},
            {"id": "r", "path": str(self.root)},
        ])

    def test_class_bomb_row_inside_a_clean_list_is_dropped(self):
        self.settings["roots"] = [ClassBomb(), {"id": "r", "path": str(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("r", [x["id"] for x in resp.json()["roots"]])
        # The clean sibling still serves a listing.
        listing = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        self.assertIn("a.txt", [i["name"] for i in listing.json()["items"]])


# ── _isinst unit pins (the modules8/catalog10 helper contract) ───────────────

class IsInstHelperTests(unittest.TestCase):
    def test_class_bomb_answers_false_not_raise(self):
        self.assertFalse(files_svc._isinst(ClassBomb(), list))
        self.assertFalse(files_svc._isinst(ClassBomb(), dict))
        self.assertFalse(files_svc._isinst(ClassBomb(), bool))

    def test_ordinary_values_unchanged(self):
        self.assertTrue(files_svc._isinst([], list))
        self.assertTrue(files_svc._isinst({}, dict))
        self.assertTrue(files_svc._isinst("x", str))
        self.assertTrue(files_svc._isinst(True, bool))
        self.assertFalse(files_svc._isinst("x", dict))

    def test_lying_subclass_still_reports_its_claim(self):
        class LyingList(list):
            @property
            def __class__(self):  # type: ignore[override]
                return list

        self.assertTrue(files_svc._isinst(LyingList(), list))


if __name__ == "__main__":
    unittest.main()
