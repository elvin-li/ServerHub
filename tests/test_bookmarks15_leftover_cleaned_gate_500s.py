"""Bookmarks leftover leftover lists: the final ``_jsonable`` publish gate.

``list_bookmarks`` used to ask the unbound-looking ``isinstance(cleaned, dict)``
after the walk.  ``isinstance`` still consults a lying ``__class__`` whenever
the real-MRO check misses, so a leftover whose cleaned payload *claimed* dict
without mapping storage (or whose ``__class__`` property raised) 500'd
GET /api/bookmarks *after* every probe had already succeeded — the last
seam before Starlette's encoder.  ``_isinst`` fails closed like every other
gate in this module; a non-mapping cleaned answer falls back to the already-
built payload ``v`` (itself a plain dict of jsonable cells).
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc


class _ClassBomb:
    """``isinstance`` consults ``__class__`` after the real-type miss."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class BookmarksCleanedGatePins(unittest.TestCase):
    def test_source_uses_isinst_not_bare_isinstance_on_cleaned(self):
        from pathlib import Path

        src = Path(bookmarks_svc.__file__).read_text(encoding="utf-8")
        self.assertIn("return cleaned if _isinst(cleaned, dict) else v", src)
        self.assertNotIn("return cleaned if isinstance(cleaned, dict) else v", src)

    def test_class_bomb_cleaned_falls_back_without_500(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

        def fake_jsonable(value, depth=0):
            return _ClassBomb()

        with mock.patch.object(bookmarks_svc, "_jsonable", side_effect=fake_jsonable), \
             mock.patch.object(bookmarks_svc, "_cfg_get", return_value=[]), \
             mock.patch.object(bookmarks_svc, "_backend_index", return_value={}):
            out = bookmarks_svc.list_bookmarks()
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("bookmarks"), [])
        self.assertIn("up", out)
        self.assertIn("checked_at", out)
