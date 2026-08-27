"""Seventh leftover-500s sweep of the Logs surfaces, over the real app.

logs6 sealed the cfg-reader subclass bombs (``_mapping_get`` / ``_truthy``
/ unbound ``list.__len__``/``__iter__``), but hub/logs_svc.py kept three
*bound* coercions in play, and each one still 500'd BOTH GET /api/logs and
GET /api/logs/{id} at once on the pre-fix tree (driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)``):

* ``_utf8_text`` ended with the bound ``text.encode("utf-8", "replace")``.
  ``str(x)`` of a str subclass with the default ``__str__`` launders to an
  exact str — but a subclass whose ``__str__`` returns *itself* (the json6
  class) keeps the subclass, and a poisoned ``encode`` riding an ``id`` or
  ``name`` detonated while publishing the row;
* ``_config_text`` and ``_entries`` laundered bytes ids/paths through
  ``bytes(value)``, which dispatches into a subclass ``__bytes__``
  override — one such bomb raised before anything was listed;
* ``_stat_size`` converted ``st_size`` with bound ``int(...)`` /
  ``float(...)`` under a narrow catch, so an int-subclass
  ``__int__``/``__index__`` bomb (or a float-subclass ``__float__`` bomb)
  riding a poisoned stat raised RuntimeError past it after the file had
  already been found.

Fixes, all in hub/logs_svc.py, all the established conventions: unbound
``str.encode`` (json6) as ``_utf8_text``'s last step, the exact-str
launder ``str.__str__`` in ``_config_text``'s str branch, unbound
``bytes.decode``/``bytearray.decode`` for the bytes branches (fs-encoding
in ``_entries`` so surrogateescape names survive), and unbound
``int.__index__`` / ``float.__float__`` (settings8) with a broad catch in
``_stat_size``.  The unbound reads keep the sane data stored underneath a
poisoned override, so a bombed field keeps its carried text/number instead
of costing the page.

Stays-immune pins riding along: a bytes/bytearray-subclass *decode* bomb
id still lists via the unbound base decode; a self-``__str__`` subclass
path still lists and tails; an over-cap ``st_size`` int and a
non-finite ``st_size`` float still degrade to size 0, never 500.
"""
from __future__ import annotations

import json
import os
import pathlib
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


class SelfStr(str):
    """``str(x)`` keeps the subclass (``__str__`` returns self); the bound
    ``.encode`` then dispatched into the bomb."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover encode bomb")


class BytesDunderBomb(bytes):
    """``bytes(x)`` dispatches into ``__bytes__`` — the old launder's seam."""

    def __bytes__(self):
        raise RuntimeError("leftover __bytes__ bomb")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover decode bomb")


class ByteArrayDecodeBomb(bytearray):
    def decode(self, *a, **k):
        raise RuntimeError("leftover decode bomb")


class IntStatBomb(int):
    """Poisoned conversions; the real number sits underneath the override."""

    def __int__(self):
        raise RuntimeError("leftover __int__ bomb")

    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")


class FloatStatBomb(float):
    def __float__(self):
        raise RuntimeError("leftover __float__ bomb")

    def __int__(self):
        raise RuntimeError("leftover __int__ bomb")


#: An already-parsed int past CPython's 4300-digit int->str cap.
_HUGE = 16 ** 4400


class _FakeStat:
    """A stat result whose ``st_size`` alone is swapped for a leftover."""

    def __init__(self, real, size):
        self._real, self._size = real, size

    def __getattr__(self, name):
        return getattr(self._real, name)

    @property
    def st_size(self):
        return self._size


def _bomb_path_cls(size):
    class _BombPath(type(pathlib.Path())):
        def stat(self, **kw):
            return _FakeStat(os.stat(str(self), **kw), size)

    return _BombPath


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


class SelfStrEncodeBombTests(_LogsSandbox):
    """The json6 class as id/name: the carried text lists, nothing 500s."""

    def test_encode_bomb_id_lists_its_text_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": SelfStr("x"), "path": self.log_path}, dict(self.sane)]}
        rows = self._list(cfg_value)
        # Laundered, not dropped: the subclass carries real text.
        self.assertEqual([r["id"] for r in rows], ["x", "s1"])
        payload = self._tail(cfg_value, source_id="x")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_encode_bomb_name_keeps_the_entry_under_its_text(self):
        cfg_value = {"log_sources": [
            {"id": "y", "name": SelfStr("Nightly"), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["name"]) for r in rows], [("y", "Nightly")])
        payload = self._tail(cfg_value, source_id="y")
        self.assertEqual(payload["name"], "Nightly")
        self.assertEqual(payload["lines"], 2)

    def test_encode_bomb_path_stays_immune(self):
        cfg_value = {"log_sources": [
            {"id": "sp", "path": SelfStr(self.log_path)}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("sp", True)])
        payload = self._tail(cfg_value, source_id="sp")
        self.assertEqual(payload["lines"], 2)


class BytesSubclassBombTests(_LogsSandbox):
    """``__bytes__`` / bound-``decode`` bombs: unbound base decode keeps
    the carried bytes' real text."""

    def test_dunder_bytes_bomb_id_lists_its_text_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": BytesDunderBomb(b"bid"), "path": self.log_path},
            dict(self.sane)]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["bid", "s1"])
        payload = self._tail(cfg_value, source_id="bid")
        self.assertEqual(payload["lines"], 2)

    def test_dunder_bytes_bomb_path_still_names_the_real_file(self):
        cfg_value = {"log_sources": [
            {"id": "p", "path": BytesDunderBomb(os.fsencode(self.log_path))},
            dict(self.sane)]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("p", True), ("s1", True)])
        payload = self._tail(cfg_value, source_id="p")
        self.assertEqual(payload["log"], "line-one\nline-two")

    def test_decode_bomb_ids_stay_immune(self):
        for bomb in (BytesDecodeBomb(b"bid"), ByteArrayDecodeBomb(b"bid")):
            with self.subTest(kind=type(bomb).__name__):
                cfg_value = {"log_sources": [
                    {"id": bomb, "path": self.log_path}]}
                rows = self._list(cfg_value)
                self.assertEqual([r["id"] for r in rows], ["bid"])
                self._tail(cfg_value, source_id="bid")


class StatSizeBombTests(_LogsSandbox):
    """Poisoned ``st_size`` conversions: the real number is recovered."""

    def _with_stat(self, size):
        return mock.patch.object(logs_svc, "Path", _bomb_path_cls(size))

    def test_int_conversion_bomb_recovers_the_real_size(self):
        with self._with_stat(IntStatBomb(7)):
            cfg_value = {"log_sources": [dict(self.sane)]}
            rows = self._list(cfg_value)
            self.assertEqual(
                [(r["id"], r["size"]) for r in rows], [("s1", 7)])
            payload = self._tail(cfg_value)
            self.assertEqual(payload["size"], 7)
            self.assertEqual(payload["lines"], 2)

    def test_float_conversion_bomb_recovers_the_real_size(self):
        with self._with_stat(FloatStatBomb(7.0)):
            cfg_value = {"log_sources": [dict(self.sane)]}
            rows = self._list(cfg_value)
            self.assertEqual(
                [(r["id"], r["size"]) for r in rows], [("s1", 7)])
            self._tail(cfg_value)

    def test_over_cap_and_non_finite_sizes_degrade_to_zero(self):
        junks = (("over-cap-int", _HUGE),
                 ("inf", FloatStatBomb(float("inf"))),
                 ("nan", FloatStatBomb(float("nan"))),
                 ("negative", IntStatBomb(-3)))
        for label, junk in junks:
            with self.subTest(junk=label):
                with self._with_stat(junk):
                    cfg_value = {"log_sources": [dict(self.sane)]}
                    rows = self._list(cfg_value)
                    self.assertEqual(
                        [(r["id"], r["size"]) for r in rows], [("s1", 0)])
                    payload = self._tail(cfg_value)
                    self.assertEqual(payload["size"], 0)


class SanitizerUnitPins(unittest.TestCase):
    """The helpers themselves: launders keep text, surrogates still scrub."""

    def test_utf8_text_launders_encode_bomb_to_exact_str(self):
        out = logs_svc._utf8_text(SelfStr("keep"))
        self.assertEqual(out, "keep")
        self.assertIs(type(out), str)

    def test_utf8_text_still_scrubs_lone_surrogates(self):
        out = logs_svc._utf8_text("a\ud800b")
        self.assertEqual(out, "a?b")
        out.encode("utf-8")

    def test_config_text_launders_str_subclass_to_exact_str(self):
        out = logs_svc._config_text(SelfStr("keep"))
        self.assertEqual(out, "keep")
        self.assertIs(type(out), str)

    def test_config_text_unbound_decodes_bytes_bombs(self):
        for bomb in (BytesDunderBomb(b"b\xffid"), ByteArrayDecodeBomb(b"bid")):
            with self.subTest(kind=type(bomb).__name__):
                out = logs_svc._config_text(bomb)
                self.assertIs(type(out), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
