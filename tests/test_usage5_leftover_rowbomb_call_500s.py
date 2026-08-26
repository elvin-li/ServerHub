"""Fifth leftover-500s sweep of the usage routes, over the real mounted app.

The hunted classes were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  Three live leaks survived the
usage/usage2/usage3/usage4 batteries, all in ``usage_svc.scan_roots`` on
seams those pins stopped short of — each one 500'd GET /api/storage/usage,
/usage/tree, /usage/largest and /usage/duplicates at once (``_resolve``
calls ``scan_roots`` too):

* usage4 guarded the *iteration* of ``files_svc.default_roots()`` (the
  iteration-bomb fix) but not the **call**: a default_roots that raised
  outright still 500'd every usage route — the exact seam pool5 fixed in
  ``storage_pool_svc._candidates``, and the asymmetry was sitting in plain
  sight: the sibling seam (``shares_svc.list_smb_shares``) has carried a
  call guard all along.  The call now sits under the guard and the shares
  section still contributes its roots;

* one hostile **row** cost the whole allowlist, twice: a dict *subclass*
  passes the ``isinstance(entry, dict)`` gate with a ``.get`` that raises
  (pool5's row-bomb, the passes-the-gate-refuses-the-protocol class one
  level below the iteration bomb) and raised out of the roots loop — and
  the shares loop had the identical seam.  Rows now degrade individually:
  the hostile row drops, its healthy siblings keep contributing;

* the same per-row guard also retires the **bool-bomb** variant the old
  loop tripped one expression later: ``entry.get("id") or "root"`` calls
  ``__bool__`` on the raw leftover, and a value (or a str-subclass path
  under ``not path``) whose ``__bool__`` raises 500'd every route before
  ``_as_text``'s str() probe ever ran.

The rest of the battery pins classes the probe proved immune at the HTTP
layer, so a regression cannot ship silently: a leftover FIFO inside a
walked tree (never opened, never hangs — tree, largest and duplicates all
finish, and duplicates still hashes the real pair sitting next to it), an
invalid-UTF-8 filename rendering scrubbed through a strictly-UTF-8 body,
a symlink loop answering the coded 404, and a FIFO scan target answering
the coded not_a_dir 400.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import files_svc, usage_svc  # noqa: E402

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


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment ``.get`` is called —
    the iteration bomb one level down (pool5's row-bomb class)."""

    def get(self, *args, **kwargs):
        raise ValueError("get bomb")


class _BoolBomb:
    """A leftover whose truthiness itself raises: ``x or "root"`` trips it
    before any str() probe runs."""

    def __bool__(self):
        raise ValueError("bool bomb")

    def __str__(self):
        return "boolbomb"


class _BoolBombStr(str):
    """Passes ``isinstance(x, str)``; raises under ``not path``."""

    def __bool__(self):
        raise ValueError("bool bomb")


_WALK_ROUTES = (
    "/api/storage/usage/tree",
    "/api/storage/usage/largest",
    "/api/storage/usage/duplicates",
)

_ALL_ROUTES = ("/api/storage/usage",) + _WALK_ROUTES


class _TempRoots(unittest.TestCase):
    """Two real walkable directories to stand in for roots / shares."""

    def setUp(self):
        self.root_a = Path(tempfile.mkdtemp(prefix="usage5-a-"))
        self.root_b = Path(tempfile.mkdtemp(prefix="usage5-b-"))
        (self.root_a / "data.bin").write_bytes(b"x" * 2048)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for root in (self.root_a, self.root_b):
            for child in sorted(root.rglob("*"), reverse=True):
                if child.is_symlink() or not child.is_dir():
                    child.unlink()
                else:
                    child.rmdir()
            root.rmdir()

    def _pinned(self, roots, shares):
        if callable(roots):
            first = mock.patch.object(files_svc, "default_roots", side_effect=roots)
        else:
            first = mock.patch.object(files_svc, "default_roots", return_value=roots)
        return (
            first,
            mock.patch("hub.shares_svc.list_smb_shares", return_value=shares),
        )


class DefaultRootsRaisingCallTests(_TempRoots):
    """A roots listing that raises at the *call* (not just iteration) must
    cost its own section, never the request — pre-fix every route here was
    an unhandled 500 (these fail on the pre-fix tree)."""

    def test_overview_stays_200_and_the_shares_still_contribute(self):
        for exc in (ValueError("boom"), OSError(5, "eio"), RecursionError("deep")):
            patches = self._pinned(
                exc, [{"name": "good", "path": str(self.root_b)}],
            )
            with self.subTest(exc=type(exc).__name__), patches[0], patches[1]:
                resp = _client().get("/api/storage/usage")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                _starlette(body)
                self.assertEqual(
                    [(r["id"], r["path"]) for r in body["roots"]],
                    [("share-good", str(self.root_b))],
                )

    def test_walk_routes_answer_the_coded_shape_not_a_500(self):
        """With every root source gone the honest answer is the coded
        files.no_roots 400 — pre-fix the raise 500'd before the check."""
        patches = self._pinned(ValueError("boom"), [])
        for route in _WALK_ROUTES:
            with self.subTest(route=route), patches[0], patches[1]:
                resp = _client().get(route)
                self.assertEqual(resp.status_code, 400, resp.text[:200])
                self.assertEqual(resp.json()["detail"]["code"], "files.no_roots")

    def test_surviving_share_tree_is_still_walkable(self):
        (self.root_b / "keep.bin").write_bytes(b"y" * 1024)
        patches = self._pinned(
            OSError(5, "eio"), [{"name": "good", "path": str(self.root_b)}],
        )
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree", params={"path": str(self.root_b)},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual([c["name"] for c in body["children"]], ["keep.bin"])


class RootEntryRowBombTests(_TempRoots):
    """One hostile row must drop alone; its healthy sibling keeps
    contributing and stays walkable (these fail on the pre-fix tree)."""

    def _rows(self, hostile):
        # Hostile row first, so the pre-fix raise is what would have to cost
        # the sibling behind it.
        return [hostile, {"id": "good", "name": "good", "path": str(self.root_a)}]

    def test_get_bomb_row_drops_but_the_sibling_renders(self):
        patches = self._pinned(self._rows(_GetBombDict()), [])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [(r["id"], r["path"]) for r in body["roots"]],
            [("good", str(self.root_a))],
        )

    def test_bool_bomb_id_row_drops_but_the_sibling_renders(self):
        """``entry.get("id") or "root"`` calls __bool__ before _as_text's
        str() probe ever runs — the raise must cost the row, not the route."""
        hostile = {"id": _BoolBomb(), "name": "n", "path": str(self.root_b)}
        patches = self._pinned(self._rows(hostile), [])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            [r["id"] for r in resp.json()["roots"]], ["good"],
        )

    def test_bool_bomb_str_subclass_path_row_drops(self):
        """Passes the ``isinstance(path, str)`` gate; raises under
        ``not path``.  Same per-row degrade."""
        hostile = {"id": "x", "name": "x", "path": _BoolBombStr(str(self.root_b))}
        patches = self._pinned(self._rows(hostile), [])
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            [r["path"] for r in resp.json()["roots"]], [str(self.root_a)],
        )

    def test_all_four_routes_stay_coded_next_to_a_bomb_row(self):
        patches = self._pinned(self._rows(_GetBombDict()), [])
        for route in _ALL_ROUTES:
            with self.subTest(route=route), patches[0], patches[1]:
                resp = _client().get(route)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())

    def test_sibling_root_stays_walkable_by_its_own_id(self):
        patches = self._pinned(self._rows(_GetBombDict()), [])
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree", params={"root_id": "good"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            [c["name"] for c in resp.json()["children"]], ["data.bin"],
        )


class ShareRowBombTests(_TempRoots):
    """The shares loop had the identical per-row seam: a get-bomb share must
    cost its own row, never the request or its sibling shares (fails on the
    pre-fix tree)."""

    def _pinned_shares(self):
        return self._pinned([], [
            _GetBombDict(),
            {"name": "good", "path": str(self.root_b)},
        ])

    def test_sibling_share_survives_the_bomb_row(self):
        patches = self._pinned_shares()
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [(r["id"], r["path"]) for r in body["roots"]],
            [("share-good", str(self.root_b))],
        )

    def test_surviving_share_tree_still_lists(self):
        (self.root_b / "keep.bin").write_bytes(b"z" * 1024)
        patches = self._pinned_shares()
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree", params={"path": str(self.root_b)},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            [c["name"] for c in resp.json()["children"]], ["keep.bin"],
        )


class ScanRootsUnitContractTests(_TempRoots):
    """Service-level contract, independent of the router mount."""

    def test_raising_default_roots_answers_the_shares_only(self):
        with (
            mock.patch.object(
                files_svc, "default_roots", side_effect=RecursionError("deep"),
            ),
            mock.patch(
                "hub.shares_svc.list_smb_shares",
                return_value=[{"name": "s", "path": str(self.root_a)}],
            ),
        ):
            roots = usage_svc.scan_roots()
        _starlette(roots)
        self.assertEqual(
            [(r["id"], r["path"]) for r in roots],
            [("share-s", str(self.root_a))],
        )

    def test_bomb_rows_in_both_loops_drop_alone(self):
        with (
            mock.patch.object(
                files_svc, "default_roots",
                return_value=[
                    _GetBombDict(),
                    {"id": "a", "name": "a", "path": str(self.root_a)},
                ],
            ),
            mock.patch(
                "hub.shares_svc.list_smb_shares",
                return_value=[
                    _GetBombDict(),
                    {"name": "b", "path": str(self.root_b)},
                ],
            ),
        ):
            roots = usage_svc.scan_roots()
        _starlette(roots)
        self.assertEqual(
            [(r["id"], r["path"]) for r in roots],
            [("a", str(self.root_a)), ("share-b", str(self.root_b))],
        )


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
class LeftoverFifoStaysImmunePins(_TempRoots):
    """A leftover FIFO inside a walked tree is never opened and never hangs:
    the walk classifies it as neither file nor dir and moves on, and the
    duplicates funnel still hashes the real pair sitting next to it."""

    def setUp(self):
        super().setUp()
        # A real duplicate pair above the 1 MB floor, so the pin proves the
        # hash stages ran to completion next to the FIFO rather than the
        # walk having quietly skipped everything.
        (self.root_a / "dup1.bin").write_bytes(b"D" * (1024 * 1024 + 7))
        (self.root_a / "dup2.bin").write_bytes(b"D" * (1024 * 1024 + 7))
        os.mkfifo(self.root_a / "leftover.fifo")

    def test_walk_routes_finish_promptly_with_a_fifo_in_the_tree(self):
        patches = self._pinned(
            [{"id": "t", "name": "t", "path": str(self.root_a)}], [],
        )
        started = time.monotonic()
        for route in _WALK_ROUTES:
            with self.subTest(route=route), patches[0], patches[1]:
                resp = _client().get(route)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())
        # Far inside the scan budgets: an opened FIFO would block until the
        # wall-clock ceiling (20-25s per route) instead.
        self.assertLess(time.monotonic() - started, 15.0)

    def test_duplicates_still_hashes_the_real_pair_next_to_the_fifo(self):
        patches = self._pinned(
            [{"id": "t", "name": "t", "path": str(self.root_a)}], [],
        )
        with patches[0], patches[1]:
            resp = _client().get("/api/storage/usage/duplicates")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        groups = resp.json()["groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)
        self.assertNotIn("leftover.fifo", resp.text)

    def test_fifo_as_scan_target_is_the_coded_400(self):
        patches = self._pinned(
            [{"id": "t", "name": "t", "path": str(self.root_a)}], [],
        )
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree",
                params={"path": str(self.root_a / "leftover.fifo")},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "files.not_a_dir")


class HostileTreeStaysImmunePins(_TempRoots):
    """Real-filesystem hostility reachable without any seam patching."""

    def _patches(self):
        return self._pinned(
            [{"id": "t", "name": "t", "path": str(self.root_a)}], [],
        )

    def test_invalid_utf8_filename_renders_scrubbed_over_strict_utf8(self):
        """os.scandir hands back a surrogateescape name; the body must stay
        strictly UTF-8-renderable with the name scrubbed, never a 500."""
        raw = os.path.join(os.fsencode(self.root_a), b"bad\xffname.bin")
        fd = os.open(raw, os.O_CREAT | os.O_WRONLY)
        try:
            os.write(fd, b"z" * 4096)
        finally:
            os.close(fd)
        self.addCleanup(os.unlink, raw)
        patches = self._patches()
        for route in ("/api/storage/usage/tree", "/api/storage/usage/largest"):
            with self.subTest(route=route), patches[0], patches[1]:
                resp = _client().get(route)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                resp.text.encode("utf-8")
                # _as_text encodes with errors="replace", so the torn byte
                # renders as "?" (the same scrub every lone surrogate takes).
                self.assertIn("bad?name.bin", resp.text)

    def test_symlink_loop_target_is_the_coded_404(self):
        (self.root_a / "loop").symlink_to(self.root_a / "loop")
        patches = self._patches()
        with patches[0], patches[1]:
            resp = _client().get(
                "/api/storage/usage/tree",
                params={"path": str(self.root_a / "loop")},
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "files.not_found")


if __name__ == "__main__":
    unittest.main(verbosity=2)
