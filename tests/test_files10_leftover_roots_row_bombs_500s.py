"""Tenth leftover-500s sweep of the Files page, over the real mounted app.

The whole known zoo (dict/list-subclass bombs including the unbound-base
classes, self-``__str__`` encode bombs, bytes ``decode`` bombs, huge hex
ints, lone-surrogate JSON escapes, FIFO/symlink-loop/surrogate-name
filesystem leftovers, torn/hex-int/FIFO plists, vanished FileBrowser
binaries, deep JSON bodies) was re-driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` against every mounted Files
route.  One live leftover class was found and fixed:

* **A roots row whose dict-subclass ``.get`` raised outside the enumerated
  arm 500'd every Files route.**  ``default_roots()`` read the configured
  rows with bound calls (``r.get("path")`` / ``r["path"]``), and its
  per-row guard only caught ``(OSError, ValueError, TypeError,
  RuntimeError)``.  ``settings_section()`` launders the section mapping but
  not the rows inside it, so a leftover dict *subclass* whose ``.get``
  raised anything else — a KeyError get-bomb, say — escaped the guard and
  answered a raw ``Internal Server Error`` on GET /api/files,
  /api/files/list, download, mkdir, rename, delete and upload alike,
  because ``_resolve_safe()`` starts at ``default_roots()``.  The row reads
  now use the unbound ``dict.get`` (the settings_section convention — the
  builtin reads the C-level storage, bypassing the override), so a
  get/getitem-bomb row *serves* its real keys instead of dropping, and the
  per-row arm is broad like the ``list()`` guard above it, so whatever a
  bombing row value raises costs that one row, never the whole page.

Two sibling degradations in ``_as_text()`` got the unbound-base treatment
at the same time (the config._env_text / audit._utf8_text convention):

* a str subclass whose ``__str__`` answers *self* and whose bound
  ``encode`` raises rode the final scrub's ``value.encode(...)`` out of
  the launderer — as a root ``id``/``name`` it dropped the whole root row
  where the files9 int-bomb pin degrades to the basename;
* a bytes subclass overriding ``decode`` blew the bytes branch the same
  way.  Both now go through ``str.encode`` / ``bytes.decode`` unbound and
  degrade the one value.

The stays-immune batteries pin neighbours probed and found already coded:
lone-surrogate JSON escapes on the write routes, deep JSON bodies, and the
whole-row RuntimeError bombs of the files9 wave under the new row-serving
behaviour.
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
    """The body must be strictly renderable UTF-8 with no lone surrogates."""
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")


def _code(test: unittest.TestCase, resp) -> str:
    _assert_clean(test, resp)
    try:
        detail = resp.json()["detail"]
    except (ValueError, KeyError, TypeError):
        test.fail(f"uncoded body: {resp.status_code} {resp.text[:200]!r}")
    test.assertIsInstance(detail, dict, f"uncoded detail: {detail!r}")
    return detail.get("code", "")


# ── The leftover bomb classes ────────────────────────────────────────────────

class GetKeyErrRow(dict):
    """The fixed class: ``.get`` raises OUTSIDE the old enumerated arm."""

    def get(self, *a, **k):
        raise KeyError("get keyerror bomb")


class GetItemBombRow(dict):
    def __getitem__(self, key):
        raise LookupError("getitem bomb")


class OddBoolBomb:
    """Truthiness bomb whose exception type is deliberately not RuntimeError."""

    def __bool__(self):
        raise ArithmeticError("bool bomb")


class SelfStrEncodeBomb(str):
    """str() answers *self* (skipping CPython's exact-str copy), then the
    bound ``encode`` raises — the modules5 encode-bomb shape."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("str encode bomb")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


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
        (self.root / "a.txt").write_text("hi")
        self.settings = {"roots": [{"id": "r", "path": str(self.root)}]}
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: self.settings
        )
        patched.start()
        self.addCleanup(patched.stop)


# ── Fixed leak: the .get bomb row outside the old enumerated arm ────────────

class RootsRowGetBombTests(_FilesSandbox):
    """Pre-fix, every one of these answered a raw uncoded 500 on every route:
    the KeyError out of the bound ``.get`` escaped the (OSError, ValueError,
    TypeError, RuntimeError) per-row arm inside ``default_roots()``."""

    def setUp(self):
        super().setUp()
        self.settings["roots"] = [
            GetKeyErrRow({"id": "bomb", "path": str(self.root)}),
            {"id": "r", "path": str(self.root)},
        ]

    def _assert_below_500(self, resp, route: str):
        _assert_clean(self, resp)
        self.assertLess(resp.status_code, 500, f"{route}: {resp.text[:200]}")

    def test_every_files_route_survives_the_keyerror_get_bomb_row(self):
        for route, resp in [
            ("GET /api/files", client().get("/api/files")),
            ("GET /api/files/list", client().get("/api/files/list")),
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
                    json={"path": str(self.root), "name": "d10", "root_id": "r"},
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
                    files={"file": ("up10.bin", b"payload")},
                ),
            ),
        ]:
            self._assert_below_500(resp, route)

    def test_the_bomb_row_serves_its_real_keys_via_the_unbound_get(self):
        # The row's dict storage is genuine; only its bound ``.get`` is
        # hostile.  The unbound read makes the row a working root.
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        ids = [r["id"] for r in resp.json()["roots"]]
        self.assertEqual(ids, ["bomb", "r"])

    def test_listing_through_the_bomb_row_id_works(self):
        resp = client().get("/api/files/list", params={"root_id": "bomb"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        names = [i["name"] for i in resp.json()["items"]]
        self.assertIn("a.txt", names)

    def test_getitem_bomb_row_also_serves(self):
        self.settings["roots"] = [
            GetItemBombRow({"id": "gi", "path": str(self.root)}),
        ]
        resp = client().get("/api/files/list", params={"root_id": "gi"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_odd_exception_bool_bomb_path_value_costs_one_row_not_the_page(self):
        # bool() of the path value raises ArithmeticError — no enumerated
        # arm can anticipate a truthiness bomb's type; the broad per-row
        # guard drops the row and the sibling keeps serving.
        self.settings["roots"] = [
            {"id": "bad", "path": OddBoolBomb()},
            {"id": "r", "path": str(self.root)},
        ]
        resp = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)

    def test_unit_default_roots_survives_the_keyerror_get_bomb(self):
        roots = files_svc.default_roots()
        self.assertEqual([r["id"] for r in roots], ["bomb", "r"])


# ── Fixed degradations: unbound str.encode / bytes.decode in _as_text ───────

class AsTextUnboundBaseTests(_FilesSandbox):
    """A bombed id/name now degrades to the basename (the files9 int-bomb
    pin), instead of the encode/decode bomb dropping the whole root row."""

    def test_selfstr_encode_bomb_id_degrades_to_the_basename(self):
        self.settings["roots"] = [
            {"id": SelfStrEncodeBomb("r"), "path": str(self.root)},
        ]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        roots = resp.json()["roots"]
        self.assertEqual(len(roots), 1, "the encode bomb dropped the root row")
        self.assertEqual(roots[0]["id"], "r")

    def test_bytes_decode_bomb_name_serves_via_the_unbound_decode(self):
        # The bytes storage is genuine; only the bound ``decode`` is hostile.
        # ``bytes.decode`` unbound reads it, so the real name serves.
        self.settings["roots"] = [
            {"id": "r", "name": BytesDecodeBomb(b"n"), "path": str(self.root)},
        ]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        roots = resp.json()["roots"]
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["name"], "n")

    def test_unit_as_text_survives_the_unbound_base_bombs(self):
        self.assertEqual(files_svc._as_text(SelfStrEncodeBomb("x")), "x")
        self.assertEqual(files_svc._as_text(BytesDecodeBomb(b"x")), "x")
        self.assertEqual(files_svc._as_text(b"ok"), "ok")
        # encode(..., "replace") substitutes "?", the pre-fix scrub's shape.
        self.assertEqual(files_svc._as_text("\ud800x"), "?x")


# ── Stays-immune pins: neighbours probed and found already coded ────────────

class SurrogateJsonEscapeStaysImmuneTests(_FilesSandbox):
    """``json.loads('"\\ud800"')`` yields a real lone surrogate server-side —
    the honest vector for the write routes.  Coded answers, clean bodies."""

    def _raw(self, route: str, body: str):
        return client().post(
            route,
            content=body.encode("ascii"),
            headers={"content-type": "application/json"},
        )

    def test_lone_surrogate_escapes_stay_coded_on_every_write_route(self):
        for route, body in [
            ("/api/files/delete", '{"path": "\\ud800x", "root_id": "r"}'),
            ("/api/files/delete", '{"path": "/x", "root_id": "\\ud800"}'),
            (
                "/api/files/mkdir",
                '{"path": "%s", "name": "\\ud800d", "root_id": "r"}' % self.root,
            ),
            (
                "/api/files/rename",
                '{"path": "%s", "new_name": "\\ud800n", "root_id": "r"}'
                % (self.root / "a.txt"),
            ),
        ]:
            resp = self._raw(route, body)
            _assert_clean(self, resp)
            self.assertLess(resp.status_code, 500, f"{route}: {resp.text[:200]}")
            self.assertGreaterEqual(resp.status_code, 400)

    def test_deeply_nested_json_body_is_the_parser_4xx(self):
        deep = "[" * 3000 + "]" * 3000
        resp = self._raw("/api/files/delete", '{"path": %s}' % deep)
        _assert_clean(self, resp)
        self.assertLess(resp.status_code, 500, resp.text[:200])
        self.assertGreaterEqual(resp.status_code, 400)

    def test_happy_path_still_renders_after_the_sweep(self):
        resp = client().get(
            "/api/files/list", params={"path": str(self.root), "root_id": "r"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("a.txt", [i["name"] for i in resp.json()["items"]])


if __name__ == "__main__":
    unittest.main()
