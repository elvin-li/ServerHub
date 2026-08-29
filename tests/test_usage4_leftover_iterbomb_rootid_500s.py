"""Fourth leftover-500s sweep of the usage routes, over the real mounted app.

The hunted classes (collections that pass ``isinstance`` but refuse
*iteration*, already-int over-cap numbers, lone UTF-8 surrogates, the
vanished-mdutil 503) were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  Usage3 sealed the surrogate / over-cap /
mdutil classes at the HTTP layer; this hunt found ``usage_svc.scan_roots``
was skipped by the iteration-bomb sweep that already fixed the NAS, UPS and
storage routers, plus one bare ``str()`` its share-name fix left behind on
the sibling loop.  Each of these was a live HTTP 500 on the pre-fix tree,
on all four GET routes at once (``_resolve`` calls ``scan_roots`` too):

* ``scan_roots`` iterated ``files_svc.default_roots()`` and
  ``shares_svc.list_smb_shares()`` results unguarded — a list subclass whose
  ``__iter__`` raises passed the ``isinstance(..., (list, tuple))`` gate and
  500'd GET /api/storage/usage, /usage/tree, /usage/largest and
  /usage/duplicates outright.  Fixed by materializing the iteration under
  its own guard (the ups_svc/storage_svc rule): the unreadable listing
  collapses to empty, and the *other* root sources still contribute;
* the root-entry loop rendered ``id`` / ``name`` with a bare ``str()`` — a
  leftover value that is *already* a >4300-digit int (YAML/plist hex loads
  with ``int(x, 16)``, exempt from CPython's int(str) parse cap) raised the
  digit-cap ValueError out of ``scan_roots``.  This is the exact class the
  usage3 sweep fixed for SMB share *names* one loop below; the root entries
  kept the pre-fix shape.  The values now route through ``_as_text``'s
  str() probe: the unrenderable id takes the same "root" fallback a None id
  always took, the unrenderable name scrubs to "", and sane numeric ids
  keep their string form (coerce, never gate).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import files_svc, usage_svc  # noqa: E402

#: plistlib's ``<integer>`` handler runs ``int(x, 16)`` for the ``0x`` form,
#: which CPython's 4300-digit str->int parse cap does not bound, so the
#: leftover arrives *already-int* and only fails at render time.
_HUGE_INT = int("F" * 4400, 16)

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _IterBombList(list):
    """Passes ``isinstance(x, (list, tuple))``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


_WALK_ROUTES = (
    "/api/storage/usage/tree",
    "/api/storage/usage/largest",
    "/api/storage/usage/duplicates",
)


class _TempRoots(unittest.TestCase):
    """Two real walkable directories to stand in for roots / shares."""

    def setUp(self):
        self.root_a = Path(tempfile.mkdtemp(prefix="usage4-a-"))
        self.root_b = Path(tempfile.mkdtemp(prefix="usage4-b-"))
        (self.root_a / "data.bin").write_bytes(b"x" * 2048)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for root in (self.root_a, self.root_b):
            for child in sorted(root.rglob("*"), reverse=True):
                child.unlink() if child.is_file() else child.rmdir()
            root.rmdir()


class DefaultRootsIterationBombTests(_TempRoots):
    """A roots listing that refuses iteration must cost its own section,
    never the request.  Pre-fix every route here was an unhandled 500."""

    def _pinned(self, shares):
        return (
            mock.patch.object(
                files_svc, "default_roots",
                return_value=_IterBombList([{"id": "t", "path": str(self.root_a)}]),
            ),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=shares),
        )

    def test_overview_stays_200_and_the_shares_still_contribute(self):
        patches = self._pinned([{"name": "good", "path": str(self.root_b)}])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [(r["id"], r["path"]) for r in body["roots"]],
            [("share-good", str(self.root_b))],
        )

    def test_walk_routes_answer_the_coded_shape_not_a_500(self):
        """With every root source empty the honest answer is the coded
        files.no_roots 400 — pre-fix the bomb 500'd before the check."""
        patches = self._pinned([])
        for route in _WALK_ROUTES:
            with self.subTest(route=route), patches[0], patches[1]:
                resp = _client().get(route)
                self.assertEqual(resp.status_code, 400, resp.text[:200])
                self.assertEqual(
                    resp.json()["detail"]["code"], "files.no_roots",
                )

    def test_surviving_share_tree_is_still_walkable(self):
        (self.root_b / "keep.bin").write_bytes(b"y" * 1024)
        patches = self._pinned([{"name": "good", "path": str(self.root_b)}])
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree", params={"path": str(self.root_b)},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual([c["name"] for c in body["children"]], ["keep.bin"])


class SharesIterationBombTests(_TempRoots):
    """The share listing bomb must cost the shares section only: the
    configured roots survive and stay walkable.  A *non-empty* bomb, so the
    ``or []`` falsy fallback cannot mask the iteration itself."""

    def _pinned(self):
        return (
            mock.patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "t", "name": "t", "path": str(self.root_a)}],
            ),
            mock.patch(
                "hub.shares_svc.list_smb_shares",
                return_value=_IterBombList([{"name": "x", "path": str(self.root_b)}]),
            ),
        )

    def test_all_four_routes_stay_coded_not_500(self):
        patches = self._pinned()
        with patches[0], patches[1]:
            overview = _client().get("/api/storage/usage")
        self.assertEqual(overview.status_code, 200, overview.text[:200])
        body = overview.json()
        _starlette(body)
        self.assertEqual(
            [r["path"] for r in body["roots"]], [str(self.root_a)],
        )
        for route in _WALK_ROUTES:
            with self.subTest(route=route), patches[0], patches[1]:
                resp = _client().get(route)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())

    def test_the_surviving_root_still_lists_its_files(self):
        patches = self._pinned()
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage/tree", params={"root_id": "t"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            [c["name"] for c in resp.json()["children"]], ["data.bin"],
        )


class RootEntryOverCapIdNamePinTests(_TempRoots):
    """The bare-str() leftover on root entries (fails pre-fix): an already-int
    over-cap id or name must take the fallback, never the digit-cap 500, and
    the sibling root must survive with its own id intact."""

    def _pinned(self, entries):
        return (
            mock.patch.object(files_svc, "default_roots", return_value=entries),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=[]),
        )

    def test_over_cap_id_takes_the_none_id_fallback(self):
        patches = self._pinned([
            {"id": _HUGE_INT, "name": "a", "path": str(self.root_a)},
            {"id": "good", "name": "good", "path": str(self.root_b)},
        ])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        by_path = {r["path"]: r for r in body["roots"]}
        self.assertEqual(by_path[str(self.root_a)]["id"], "root")
        self.assertEqual(by_path[str(self.root_b)]["id"], "good")

    def test_over_cap_name_scrubs_to_empty_and_the_sibling_survives(self):
        patches = self._pinned([
            {"id": "a", "name": _HUGE_INT, "path": str(self.root_a)},
            {"id": "good", "name": "good", "path": str(self.root_b)},
        ])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        by_path = {r["path"]: r for r in resp.json()["roots"]}
        self.assertEqual(by_path[str(self.root_a)]["name"], "")
        self.assertEqual(by_path[str(self.root_b)]["name"], "good")

    def test_sibling_root_stays_walkable_by_its_own_id(self):
        """Pre-fix the raise dropped the whole allowlist, so the sibling's
        tree answered a 500 instead of listing."""
        (self.root_b / "keep.bin").write_bytes(b"z" * 1024)
        patches = self._pinned([
            {"id": _HUGE_INT, "name": "a", "path": str(self.root_a)},
            {"id": "good", "name": "good", "path": str(self.root_b)},
        ])
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree", params={"root_id": "good"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            [c["name"] for c in resp.json()["children"]], ["keep.bin"],
        )

    def test_numeric_and_surrogate_ids_coerce_never_gate(self):
        """The str() probe coerces: sane YAML numeric ids keep their string
        form, and a lone-surrogate id scrubs instead of 500ing the body."""
        patches = self._pinned([
            {"id": 123, "name": 456, "path": str(self.root_a)},
            {"id": "s\ud800", "name": "n\ud800", "path": str(self.root_b)},
        ])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn("\ud800", resp.text)
        by_path = {r["path"]: r for r in resp.json()["roots"]}
        self.assertEqual(by_path[str(self.root_a)]["id"], "123")
        self.assertEqual(by_path[str(self.root_a)]["name"], "456")
        self.assertEqual(by_path[str(self.root_b)]["id"], "s?")
        self.assertEqual(by_path[str(self.root_b)]["name"], "n?")


class ScanRootsUnitContractTests(_TempRoots):
    """Service-level contract, independent of the router mount."""

    def test_both_listings_bombed_answers_an_empty_list(self):
        with (
            mock.patch.object(
                files_svc, "default_roots", return_value=_IterBombList([{}]),
            ),
            mock.patch(
                "hub.shares_svc.list_smb_shares",
                return_value=_IterBombList([{}]),
            ),
        ):
            roots = usage_svc.scan_roots()
        _starlette(roots)
        self.assertEqual(roots, [])

    def test_over_cap_root_id_never_raises_out_of_scan_roots(self):
        with (
            mock.patch.object(
                files_svc, "default_roots",
                return_value=[{"id": _HUGE_INT, "path": str(self.root_a)}],
            ),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=[]),
        ):
            roots = usage_svc.scan_roots()
        _starlette(roots)
        self.assertEqual(
            [(r["id"], r["path"]) for r in roots],
            [("root", str(self.root_a))],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
