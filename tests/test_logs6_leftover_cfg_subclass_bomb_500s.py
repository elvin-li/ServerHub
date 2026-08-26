"""Sixth leftover-500s sweep of the Logs surfaces, over the real app.

The find: hub/logs_svc._entries never got the subclass-bomb hardening the
rest of the tree standardized on (the ups_svc ``_mapping_get`` /
jobs ``_truthy`` / modules5 unbound ``list.__iter__`` conventions).
Driven through ``create_app()`` + ``TestClient(raise_server_exceptions=
False)``, eight junk shapes each 500'd BOTH GET /api/logs and
GET /api/logs/{id} at once on the pre-fix tree:

* a dict-subclass ``.get`` bomb as the whole cfg() root — the very first
  read, ``cfg().get("log_sources")``, raised before anything was listed;
* a list-subclass ``__bool__`` bomb as ``log_sources`` — the emptiness
  test ``not sources`` detonated it;
* a list-subclass ``__iter__`` bomb as ``log_sources`` — the entry walk;
* a dict-subclass ``.get`` bomb as one entry — ``s.get("path")``;
* a dict-subclass ``__getitem__`` bomb as one entry — the later
  ``s["path"]`` re-read after ``.get`` had already answered;
* a ``__bool__`` bomb as one entry's ``path`` value — the truth test
  hidden in ``not s.get("path")``;
* an int-subclass ``__str__`` bomb as an ``id`` — ``_config_text``'s
  ``str()`` probe only caught ValueError (the digit cap), so a RuntimeError
  bomb sailed past it;
* the same ``__str__`` bomb as a ``name``.

Fixes, all in hub/logs_svc.py, all the established conventions:
``_mapping_get`` (ups_svc) for the root / entry field reads, ``_truthy``
(jobs) for the path truth test, unbound ``list.__len__`` /
``list.__iter__`` (modules5) for the sources walk, and a broad catch on
``_config_text``'s ``str()`` probe.  The unbound reads keep the sane data
stored underneath a poisoned override, so a bombed container costs
nothing and a bombed field costs only its entry.

Stays-immune pins riding along: a YAML hex int id (``0x2A`` → ``"42"``)
still lists and tails; an over-cap int (``16 ** 4400``, hex construction
dodges the parse cap) as id or path drops only its entry; a leftover FIFO
occupying a configured path neither hangs nor 500s either route; a lone
surrogate in id/name lists scrubbed and tails through the published id;
bytes id/path replace-decode.
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


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class _DictGetItemBomb(dict):
    def __getitem__(self, *a):
        raise RuntimeError("leftover __getitem__ bomb")


class _ListBoolBomb(list):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")

    __repr__ = __str__


#: An already-parsed int past CPython's 4300-digit int->str cap.  Hex/pow
#: construction dodges the int(str) *parse* cap the same way YAML hex does.
_HUGE = 16 ** 4400


class _LogsSandbox(unittest.TestCase):
    """A real on-disk log so the surviving entry can prove it still tails."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log_path = os.path.join(self._tmp.name, "sane.log")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write("line-one\nline-two\n")
        self.sane = {"id": "s1", "name": "Sane", "path": self.log_path}

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


class LogsCfgSubclassBombTests(_LogsSandbox):
    """Each pre-fix 500 shape now costs at most its entry, never the page."""

    def _survives(self, cfg_value):
        rows = self._list(cfg_value)
        self.assertIn("s1", [r["id"] for r in rows])
        payload = self._tail(cfg_value)
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_get_bomb_as_the_whole_config_answers_both_routes(self):
        # No log_sources hide underneath the bomb, so the defaults list —
        # the point is the 200/coded-404, where both routes 500'd before.
        cfg_value = _DictGetBomb()
        rows = self._list(cfg_value)
        self.assertIsInstance(rows, list)
        payload = self._tail(cfg_value, expect=404)
        self.assertEqual(payload["detail"]["code"], "logs.unknown_source")

    def test_bool_bomb_sources_list_keeps_its_real_entry(self):
        # Unbound list.__len__ reads the real emptiness underneath the
        # poisoned __bool__, so the sane entry is not even degraded to the
        # defaults list — it lists and tails.
        self._survives({"log_sources": _ListBoolBomb([dict(self.sane)])})

    def test_iter_bomb_sources_list_keeps_its_real_entry(self):
        self._survives({"log_sources": _ListIterBomb([dict(self.sane)])})

    def test_get_bomb_entry_keeps_its_real_fields(self):
        # dict.get reads the storage underneath the override: a subclass
        # that only poisoned its method keeps its sane source.
        self._survives({"log_sources": [_DictGetBomb(self.sane)]})

    def test_getitem_bomb_entry_keeps_its_real_fields(self):
        self._survives({"log_sources": [_DictGetItemBomb(self.sane)]})

    def test_bool_bomb_path_costs_the_entry_not_the_page(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": _BoolBomb()}, dict(self.sane)]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["s1"])
        self._survives(cfg_value)

    def test_int_str_bomb_id_costs_the_entry_not_the_page(self):
        cfg_value = {"log_sources": [
            {"id": _IntStrBomb(7), "path": self.log_path}, dict(self.sane)]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["s1"])
        self._survives(cfg_value)

    def test_int_str_bomb_name_keeps_the_entry_under_its_id(self):
        cfg_value = {"log_sources": [
            {"id": "y", "name": _IntStrBomb(7), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([(r["id"], r["name"]) for r in rows], [("y", "y")])
        payload = self._tail(cfg_value, source_id="y")
        self.assertEqual(payload["lines"], 2)


class LogsZooStaysImmuneTests(_LogsSandbox):
    """Adjacent zoo shapes that were already clean stay pinned that way."""

    def test_hex_int_id_lists_and_tails_as_its_digits(self):
        cfg_value = {"log_sources": [{"id": 0x2A, "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["42"])
        payload = self._tail(cfg_value, source_id="42")
        self.assertEqual(payload["lines"], 2)

    def test_over_cap_int_id_and_path_drop_only_their_entry(self):
        cfg_value = {"log_sources": [
            {"id": _HUGE, "path": self.log_path},
            {"id": "h", "path": _HUGE},
            dict(self.sane),
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["s1"])
        self._tail(cfg_value)

    def test_fifo_source_neither_hangs_nor_500s(self):
        fifo = os.path.join(self._tmp.name, "fifo.log")
        os.mkfifo(fifo)
        cfg_value = {"log_sources": [{"id": "f", "path": fifo}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("f", False)])
        payload = self._tail(cfg_value, source_id="f")
        self.assertFalse(payload["exists"])
        self.assertEqual(payload["log"], "(file does not exist)")

    def test_surrogate_id_lists_scrubbed_and_tails_by_published_id(self):
        cfg_value = {"log_sources": [
            {"id": "a\ud800b", "name": "n\udfffm", "path": self.log_path}]}
        rows = self._list(cfg_value)
        published = rows[0]["id"]
        # The strict UTF-8 decode above already proved no surrogate leaked.
        self.assertEqual(published, "a?b")
        payload = self._tail(cfg_value, source_id=published)
        self.assertEqual(payload["lines"], 2)

    def test_bytes_id_and_path_replace_decode_and_tail(self):
        cfg_value = {"log_sources": [
            {"id": b"b\xffid", "path": os.fsencode(self.log_path)}]}
        rows = self._list(cfg_value)
        published = rows[0]["id"]
        self.assertEqual(published, "b\ufffdid")
        self.assertTrue(rows[0]["exists"])
        payload = self._tail(cfg_value, source_id=published)
        self.assertEqual(payload["lines"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
