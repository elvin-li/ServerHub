"""Thirteenth leftover-500s sweep of the Files page, over the real mounted app.

files12 sealed the ``__class__``-property bombs behind ``files_svc._isinst``.
This pass hunted the nas9/json9 class next door — **lying ``__class__``
impostors** that *pass* the guarded gate and then blow the unbound base
operation that follows (decode/items/iter), plus bool-liars — and the
files12 eq-bomb neighbour one level up.  The liar zoo turned out already
sealed (every ``_isinst`` gate's follow-up sits in a try or a per-row
guard), but the hunt surfaced two live raw 500s one seam *earlier* than any
value gate: the section **key lookup** itself.

``settings_section`` launders the section mapping with ``dict(...)``, but a
plain-dict copy keeps hostile *keys* as-is, and ``.get`` on the copy is
still a hash-table probe.  A leftover key whose ``__hash__`` collides with
the literal being fetched runs its ``__eq__`` during that probe (CPython
demotes the table to the general lookup once a non-exact-str key is
inserted), so a raising ``__eq__`` detonated:

* **``_settings().get("roots")``** at the head of ``default_roots`` — the
  first thing every Files route runs — 500ing GET /api/files,
  /api/files/list, download, and POST mkdir/rename/delete/upload at once.
  Confirmed live before the fix (raw ``500 Internal Server Error``), for a
  plain eq-bomb key and a str-subclass one alike.

* **``_settings().get("max_upload_mb")``** in ``_max_upload_mb`` — read only
  by POST /api/files/upload, *after* the multipart body was accepted.

The fix routes the section reads through ``files_svc._setting``, which wraps
the unbound ``dict.get`` (and the ``_settings()`` call itself) in a try and
fails closed to the absent-key default: ``roots`` degrades to the default
candidates, the upload cap to 512 MB.  files12's value-side pins (``roots``
falling back on a ``__class__`` bomb, the 512 cap) are unchanged.

The rest of this module pins the nas9/json9 impostor zoo as
**stays-immune**: list-liars (inert, raising-iter, and one that really
iterates), dict-liar rows (dropped alone, healthy siblings serve),
items-liars, str/bytes-liars in every row field, real strs lying bytes, and
bool/int/str-liars on the upload cap and ``show_hidden``.
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


# ── The leftover bomb / impostor classes ─────────────────────────────────────

class EqBombKey:
    """A section key whose ``__hash__`` collides with the literal being
    fetched and whose ``__eq__`` raises — the probe itself detonates."""

    def __init__(self, target: str):
        self._h = hash(target)

    def __eq__(self, other):
        raise RuntimeError("section key eq bomb")

    def __hash__(self):
        return self._h


class StrEqBombKey(str):
    """Same shape as a str *subclass*: still demotes the table to the general
    lookup, so the raising ``__eq__`` runs during the probe."""

    def __eq__(self, other):
        raise RuntimeError("section key eq bomb (str subclass)")

    def __hash__(self):
        return str.__hash__(self)


def _liar(claim):
    """A plain object whose ``__class__`` property *lies* about its type: it
    passes ``_isinst(x, claim)`` but has none of the claimed type's layout,
    so any unbound base call on it raises TypeError."""
    return type("Liar", (object,), {"__class__": property(lambda self: claim)})()


class RaisingIterListLiar:
    """Claims list; its real ``__iter__`` raises when the launderer runs."""

    @property
    def __class__(self):  # type: ignore[override]
        return list

    def __iter__(self):
        raise RuntimeError("iter liar")


class ItemsLiarRow:
    """Claims dict; bound ``get`` raises and ``items()`` yields non-pairs —
    the json9 shape.  files reads rows via unbound ``dict.get``, which
    TypeErrors on the missing dict layout inside the per-row guard."""

    @property
    def __class__(self):  # type: ignore[override]
        return dict

    def get(self, key, default=None):
        raise RuntimeError("bound get bomb")

    def items(self):
        return [1, 2]


class StrLiarBadStr:
    """Claims str; ``str()`` on it raises."""

    @property
    def __class__(self):  # type: ignore[override]
        return str

    def __str__(self):
        raise RuntimeError("str bomb")


class StrLyingBytes(str):
    """A real str (a plausible root id/path) whose ``__class__`` lies bytes:
    passes ``_as_text``'s bytes arm, then the unbound ``bytes.decode``
    TypeErrors inside the launderer's try."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root; ``settings_section`` patched with a plain dict
    carrying the leftover values/keys (models hub.config's real laundering —
    the section mapping is re-dicted but keys and values inside are the
    leftovers)."""

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
                    json={"path": str(self.root), "name": "d13"},
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
                    files={"file": ("up13.bin", b"payload")},
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

    def _drive_all(self):
        for route, resp in self._all_routes():
            _assert_below_500(self, resp, route)


# ── New find #1: eq-bomb section key colliding "roots" 500'd every route ─────

class RootsKeyEqBombTests(_FilesSandbox):
    """The section holds a leftover key hash-colliding with ``"roots"`` whose
    ``__eq__`` raises: ``.get("roots")`` used to detonate inside the hash
    probe at the head of ``default_roots`` and 500 every Files route.
    Guarded, the lookup degrades to the absent-key default candidates."""

    def setUp(self):
        super().setUp()
        self.settings = {EqBombKey("roots"): [{"id": "r", "path": str(self.root)}]}

    def test_no_files_route_500s(self):
        self._drive_all()

    def test_overview_degrades_to_default_candidates(self):
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIsInstance(resp.json()["roots"], list)

    def test_default_roots_unit_degrades(self):
        self.assertIsInstance(files_svc.default_roots(), list)


class RootsKeyStrSubclassEqBombTests(_FilesSandbox):
    """Same seam with a str-*subclass* bomb key (still the general lookup)."""

    def setUp(self):
        super().setUp()
        self.settings = {
            StrEqBombKey("roots"): [{"id": "r", "path": str(self.root)}]
        }

    def test_no_files_route_500s(self):
        self._drive_all()


# ── New find #2: eq-bomb section key colliding "max_upload_mb" ───────────────

class MaxUploadKeyEqBombTests(_FilesSandbox):
    """A leftover key hash-colliding with ``"max_upload_mb"``: the probe in
    ``_max_upload_mb`` used to 500 POST /api/files/upload after the body was
    accepted.  Guarded, the cap falls back to the 512 MB default and the
    upload completes; the healthy ``roots`` key keeps serving."""

    def setUp(self):
        super().setUp()
        self.settings[EqBombKey("max_upload_mb")] = 64

    def test_upload_completes_with_the_default_cap(self):
        resp = client().post(
            "/api/files/upload",
            data={"path": str(self.root)},
            files={"file": ("up13.bin", b"payload")},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue((self.root / "up13.bin").exists())

    def test_max_upload_mb_unit_falls_back_to_512(self):
        self.assertEqual(files_svc._max_upload_mb(), 512)

    def test_no_files_route_500s(self):
        self._drive_all()


class ShowHiddenKeyEqBombTests(_FilesSandbox):
    """The ``show_hidden`` sibling read: its ``bool(...)`` try already ate the
    probe bomb; pinned so the listing keeps answering either way."""

    def setUp(self):
        super().setUp()
        self.settings[EqBombKey("show_hidden")] = True

    def test_listing_answers_200(self):
        resp = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("a.txt", [i["name"] for i in resp.json()["items"]])


# ── Stays-immune: the nas9/json9 lying-__class__ impostor zoo ────────────────

class LiarRootsValueStaysImmuneTests(_FilesSandbox):
    """``roots`` values that *pass* ``_isinst(..., list)`` by lying: the
    ``list(custom)`` materialisation is guarded, so an impostor that cannot
    iterate — or whose iteration raises — degrades to the default candidates
    instead of 500ing."""

    def test_inert_list_liar_degrades(self):
        self.settings["roots"] = _liar(list)
        self._drive_all()

    def test_raising_iter_list_liar_degrades(self):
        self.settings["roots"] = RaisingIterListLiar()
        self._drive_all()

    def test_iterating_list_liar_serves_its_healthy_rows(self):
        rows = [{"id": "r", "path": str(self.root)}, _liar(dict)]
        liar = type(
            "IterListLiar",
            (object,),
            {
                "__class__": property(lambda self: list),
                "__iter__": lambda self: iter(rows),
            },
        )()
        self.settings["roots"] = liar
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("r", [x["id"] for x in resp.json()["roots"]])


class LiarRowsStayImmuneTests(_FilesSandbox):
    """Impostor rows inside a clean list: each drops alone via the per-row
    guard (the unbound ``dict.get`` TypeErrors on the missing dict layout),
    and the healthy sibling keeps serving."""

    def _drive_with_sibling(self, bomb_row):
        self.settings["roots"] = [bomb_row, {"id": "r", "path": str(self.root)}]
        self._drive_all()
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("r", [x["id"] for x in resp.json()["roots"]])
        listing = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        self.assertIn("a.txt", [i["name"] for i in listing.json()["items"]])

    def test_dict_liar_row_drops_alone(self):
        self._drive_with_sibling(_liar(dict))

    def test_items_liar_row_drops_alone(self):
        self._drive_with_sibling(ItemsLiarRow())

    def test_str_liar_row_drops_alone(self):
        self._drive_with_sibling(_liar(str))

    def test_str_liar_with_raising_str_drops_alone(self):
        self._drive_with_sibling(StrLiarBadStr())


class LiarRowFieldsStayImmuneTests(_FilesSandbox):
    """Impostor *values* inside an otherwise clean row: every field launders
    through ``_as_text``/``_root_label``, whose unbound base calls sit in
    trys, so the field degrades (basename fallback) instead of 500ing."""

    def _drive_row(self, row):
        self.settings["roots"] = [row, {"id": "r2", "path": str(self.root)}]
        self._drive_all()

    def test_bytes_liar_id(self):
        self._drive_row({"id": _liar(bytes), "path": str(self.root)})

    def test_bytes_liar_name(self):
        self._drive_row({"id": "r", "name": _liar(bytes), "path": str(self.root)})

    def test_bool_liar_id(self):
        self._drive_row({"id": _liar(bool), "path": str(self.root)})

    def test_str_liar_path(self):
        self._drive_row({"id": "r", "path": _liar(str)})

    def test_real_str_lying_bytes_id_still_serves(self):
        self.settings["roots"] = [
            {"id": StrLyingBytes("r"), "path": str(self.root)}
        ]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_real_str_lying_bytes_path_still_serves(self):
        self.settings["roots"] = [
            {"id": "r", "path": StrLyingBytes(str(self.root))}
        ]
        self._drive_all()


class LiarUploadCapStaysImmuneTests(_FilesSandbox):
    """Upload-cap liars: a bool-liar answers the 512 default at the guarded
    gate; int/str-liars fail ``_finite_int``'s conversion try the same way.
    The upload itself completes under the default cap."""

    def _upload_ok(self):
        resp = client().post(
            "/api/files/upload",
            data={"path": str(self.root)},
            files={"file": ("cap13.bin", b"payload")},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_bool_liar_cap(self):
        self.settings["max_upload_mb"] = _liar(bool)
        self.assertEqual(files_svc._max_upload_mb(), 512)
        self._upload_ok()

    def test_int_liar_cap(self):
        self.settings["max_upload_mb"] = _liar(int)
        self.assertEqual(files_svc._max_upload_mb(), 512)
        self._upload_ok()

    def test_str_liar_cap(self):
        self.settings["max_upload_mb"] = _liar(str)
        self.assertEqual(files_svc._max_upload_mb(), 512)
        self._upload_ok()

    def test_bool_liar_show_hidden_keeps_the_listing(self):
        self.settings["show_hidden"] = _liar(bool)
        resp = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)


# ── _setting unit pins ───────────────────────────────────────────────────────

class SettingHelperTests(unittest.TestCase):
    def _patch(self, section):
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: section
        )
        patched.start()
        self.addCleanup(patched.stop)

    def test_eq_bomb_key_answers_the_default(self):
        self._patch({EqBombKey("roots"): ["x"]})
        self.assertIsNone(files_svc._setting("roots"))
        self.assertEqual(files_svc._setting("roots", 512), 512)

    def test_str_subclass_bomb_key_answers_the_default(self):
        self._patch({StrEqBombKey("roots"): ["x"]})
        self.assertIsNone(files_svc._setting("roots"))

    def test_ordinary_values_unchanged(self):
        self._patch({"roots": ["x"], "max_upload_mb": 64})
        self.assertEqual(files_svc._setting("roots"), ["x"])
        self.assertEqual(files_svc._setting("max_upload_mb"), 64)
        self.assertIsNone(files_svc._setting("absent"))

    def test_raising_section_provider_answers_the_default(self):
        patched = mock.patch.object(
            files_svc,
            "settings_section",
            side_effect=RuntimeError("section provider bomb"),
        )
        patched.start()
        self.addCleanup(patched.stop)
        self.assertEqual(files_svc._setting("roots", "d"), "d")


if __name__ == "__main__":
    unittest.main()
