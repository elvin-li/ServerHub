"""Eighth leftover-500s sweep of the Logs surfaces, over the real app.

logs7 sealed the ``encode`` / ``st_size`` seams: it laundered a
self-``__str__`` str subclass through the unbound ``str.__str__`` in
``_config_text`` (so a poisoned ``encode`` on an *id* or *name* could no
longer 500 the page), and read ``st_size`` through unbound
``int.__index__`` / ``float.__float__``.  But one coercion on the same
surface stayed *bound*: ``_entries`` built the on-disk path with

    p = Path(os.path.expanduser(str(raw_path)))

under a narrow ``except (OSError, ValueError, TypeError, RuntimeError)``.
The id and name fields reach text through ``_config_text``'s unbound
launder, yet ``path`` alone still went through the plain ``str(...)``.  A
``log_sources`` ``path`` that is a *str subclass* whose ``__str__``
raises anything outside that narrow tuple — a plain ``KeyError`` /
``LookupError`` / ``StopIteration`` leftover, the shape a poisoned cache
entry takes — dispatched into the override and raised straight past the
catch, 500'ing GET /api/logs AND GET /api/logs/{id} at once (the tail
re-lists through ``log_sources()``).

The fix, in hub/logs_svc.py, keeps to the established conventions: the
exact-str launder ``str.__str__`` for the str branch (the json6 rule the
id/name fields already use), so the subclass copies its *carried path
text* to an exact str and the source keeps listing and tailing its real
file; and a broadened ``except Exception`` around the ``expanduser`` /
``Path`` build (like ``_stat_size`` / ``_config_text``), so a non-str
``path`` leftover whose own ``str()`` bombs drops that one entry instead
of the whole page.

Stays-immune pins ride along: a str-subclass path whose ``__str__``
returns *itself* still lists and tails (it was already fine, but it is
the neighbour of the reproduced bomb); and a plain object ``path`` whose
``str()`` bombs drops only its row while a sane sibling still lists and
that bomb's own tail is an honest 404.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.parse
from unittest import mock

from fastapi.testclient import TestClient

from hub import logs_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


class PathStrRaisesKeyError(str):
    """``str(x)`` dispatches into a ``__str__`` that raises a leftover the
    narrow catch never listed; the real path text sits underneath it."""

    def __str__(self):
        raise KeyError("leftover path __str__ bomb")


class PathStrRaisesLookup(str):
    def __str__(self):
        raise LookupError("leftover path __str__ bomb")


class PathStrRaisesStopIter(str):
    def __str__(self):
        raise StopIteration()


class PathSelfStr(str):
    """``str(x)`` keeps the subclass (``__str__`` returns self)."""

    def __str__(self):
        return self


class ObjPathStrBomb:
    """A non-str ``path`` leftover whose own ``str()`` bombs: the entry
    drops, the page does not."""

    def __bool__(self):
        return True

    def __str__(self):
        raise KeyError("leftover object path bomb")


class _LogsSandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log_path = os.path.join(self._tmp.name, "sane.log")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write("line-one\nline-two\n")

    def _list(self, cfg_value):
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))["sources"]

    def _tail(self, cfg_value, source_id="s1", expect=200):
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            resp = _client().get(
                "/api/logs/" + urllib.parse.quote(source_id, safe=""))
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class PathStrSubclassBombTests(_LogsSandbox):
    """A str-subclass ``path`` whose ``__str__`` raises: the carried text
    lists and tails its real file — no 500 on either route."""

    def _each_bomb(self):
        return (PathStrRaisesKeyError(self.log_path),
                PathStrRaisesLookup(self.log_path),
                PathStrRaisesStopIter(self.log_path))

    def test_raising_str_path_lists_its_real_file(self):
        for bomb in self._each_bomb():
            with self.subTest(kind=type(bomb).__name__):
                cfg_value = {"log_sources": [{"id": "s1", "path": bomb}]}
                rows = self._list(cfg_value)
                # Laundered to its carried path text, not dropped: the real
                # file underneath the poisoned override is stat'ed.
                self.assertEqual(
                    [(r["id"], r["exists"], r["size"]) for r in rows],
                    [("s1", True, 18)])

    def test_raising_str_path_tails_its_real_file(self):
        for bomb in self._each_bomb():
            with self.subTest(kind=type(bomb).__name__):
                cfg_value = {"log_sources": [{"id": "s1", "path": bomb}]}
                payload = self._tail(cfg_value, source_id="s1")
                self.assertEqual(payload["log"], "line-one\nline-two")
                self.assertEqual(payload["lines"], 2)
                self.assertTrue(payload["exists"])

    def test_bomb_beside_a_sane_source_never_costs_the_page(self):
        cfg_value = {"log_sources": [
            {"id": "boom", "path": PathStrRaisesKeyError(self.log_path)},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["boom", "sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)


class StaysImmuneTests(_LogsSandbox):
    """Neighbours of the reproduced bomb, pinned so they cannot regress."""

    def test_self_str_path_still_lists_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "path": PathSelfStr(self.log_path)}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("s1", True)])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)

    def test_object_path_str_bomb_drops_only_its_own_entry(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": ObjPathStrBomb()},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        # The poisoned object cannot become a path — its row drops, the
        # page and the sane sibling stand.
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)
        # Its own tail is an honest 404, not a 500.
        self._tail(cfg_value, "junk", expect=404)


class SanitizerUnitPins(unittest.TestCase):
    """The launder itself: a raising-``__str__`` str subclass yields its
    carried text as an exact str."""

    def test_str_dunder_launders_raising_subclass_to_exact_str(self):
        out = str.__str__(PathStrRaisesKeyError("/var/log/keep.log"))
        self.assertEqual(out, "/var/log/keep.log")
        self.assertIs(type(out), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
