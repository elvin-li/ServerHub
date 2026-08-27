"""Eighth leftover-500s sweep: brew listing / autostart / _json_safe surfaces.

Hunted over ``create_app()`` + TestClient(raise_server_exceptions=False),
after brew7 sealed the fallback tail, the toggle tails and the nested
brew_cache._json_safe subclass bombs.  This sweep found two live 500s and a
family of row-wipes of the same subclass-bomb class, all fixed here:

GET /api/brew/services (JSON path, brew_svc.list_services)
* the ``isinstance(data, list) and data`` truth test ran *outside* the try
  around the provider call, so a leftover list-subclass snapshot whose
  ``__bool__`` (or ``__len__``, which ``bool()`` falls back to) raises
  **500'd** the listing.  The gate now tests an exact list built through
  unbound ``list.__iter__``.
* a list-subclass ``__iter__`` bomb, or a dict-subclass row whose ``get``
  raises, used to blow the whole JSON walk into the text fallback and wipe
  every row.  Unbound ``list.__iter__`` / ``dict.get`` reads now cost at
  most the poisoned value — the brew_cache._json_safe convention.

GET /api/apps/autostart (autostart_svc._brew_service_items)
* the same ``__iter__`` / ``get`` bombs (plus a str-subclass status whose
  bound ``.lower()`` raises and a bytes-subclass file whose bound
  ``.decode`` raises) used to raise into overview()'s _safe fallback and
  wipe every Homebrew row from the page.  Same unbound reads.

brew_cache._load (the shared snapshot everything reads)
* ``if rc == 0`` dispatched into a leftover numeric-subclass ``__eq__``
  bomb and raised out of _load, discarding the *fresh* rows the spawn had
  just produced; ``_plain_rc`` now coerces the rc first.
* a list-subclass stdout whose ``__iter__`` raises blew the bound filter in
  _services_from_output the same way; the filter iterates unbound now.
* a malformed spawn result (wrong-arity stub tuple) used to raise out of
  the ``rc, out, _ =`` unpack and wipe the last-good snapshot instead of
  degrading to the keep-last-good tail.

None of this reopens the brew6/brew7 pins: the fallback tail, the toggle
tails, the plist-write 409 and the nested field bombs keep their tests.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import autostart_svc, brew_cache, brew_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_client = None


def client() -> TestClient:
    global _client
    if _client is None:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        # The SPA's failure mode is what is under test, not exception
        # propagation into the test process.
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


class _BoolBombList(list):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _LenBombList(list):
    """No ``__bool__`` override: ``bool()`` falls back to ``__len__``."""

    def __len__(self):
        raise RuntimeError("len bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _GetBombDict(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")

    def items(self):
        raise RuntimeError("items bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class _LowerBombStr(str):
    def lower(self):
        raise RuntimeError("lower bomb")

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class BrewListProviderShapeTests(unittest.TestCase):
    """GET /api/brew/services: hostile snapshot shapes from the provider."""

    def _get(self, data):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=data),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def test_bool_bomb_list_renders_its_rows_not_500(self):
        # The `and data` gate ran outside the try: this used to be HTTP 500.
        resp = self._get(_BoolBombList([{"name": "redis", "status": "started"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["id"] for r in resp.json()["services"]], ["redis"]
        )

    def test_len_bomb_list_renders_its_rows_not_500(self):
        # bool() of a list subclass without __bool__ dispatches __len__.
        resp = self._get(_LenBombList([{"name": "redis", "status": "started"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["id"] for r in resp.json()["services"]], ["redis"]
        )

    def test_iter_bomb_list_keeps_its_real_rows(self):
        # Used to wipe every row into the (empty) text fallback.
        resp = self._get(_IterBombList([{"name": "redis", "status": "started"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")

    def test_get_bomb_row_keeps_its_real_pairs(self):
        resp = self._get([
            _GetBombDict(name="redis", status="started", exit_code=0),
            {"name": "glances", "status": "none"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(sorted(rows), ["glances", "redis"])
        self.assertEqual(rows["redis"]["status"], "started")
        self.assertEqual(rows["redis"]["exit_code"], 0)

    def test_plain_rows_still_render_unchanged(self):
        resp = self._get([{"name": "redis", "status": "started",
                           "user": "svc", "exit_code": 0}])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(rows["redis"]["user"], "svc")
        self.assertEqual(rows["redis"]["state"], "ok")


class AutostartBrewProviderShapeTests(unittest.TestCase):
    """GET /api/apps/autostart: the brew collector survives hostile shapes."""

    def _brew_rows(self, data) -> dict:
        with (
            mock.patch.object(autostart_svc, "_is_file", return_value=True),
            mock.patch.object(
                autostart_svc, "brew_services_list", return_value=data
            ),
            mock.patch.object(autostart_svc, "sh", return_value=(0, "", "")),
        ):
            autostart_svc.overview.invalidate()
            resp = client().get("/api/apps/autostart?force=true")
            autostart_svc.overview.invalidate()
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {
            i["name"]: i for i in resp.json()["items"]
            if i.get("kind") == "brew"
        }

    def test_iter_bomb_list_keeps_the_brew_rows(self):
        # Used to raise into overview()'s _safe fallback: zero brew rows.
        rows = self._brew_rows(
            _IterBombList([{"name": "redis", "status": "started"}])
        )
        self.assertEqual(sorted(rows), ["redis"])
        self.assertTrue(rows["redis"]["running"])

    def test_get_bomb_row_keeps_the_sibling_rows(self):
        rows = self._brew_rows([
            _GetBombDict(name="redis", status="started"),
            {"name": "glances", "status": "none"},
        ])
        self.assertEqual(sorted(rows), ["glances", "redis"])
        self.assertTrue(rows["redis"]["running"])
        self.assertFalse(rows["glances"]["running"])

    def test_lower_bomb_status_still_renders_the_row(self):
        # The bound ``.lower()`` used to dispatch into the subclass override.
        rows = self._brew_rows([
            {"name": "redis", "status": _LowerBombStr("Started")},
        ])
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")
        self.assertTrue(rows["redis"]["running"])

    def test_decode_bomb_file_still_renders_the_row(self):
        rows = self._brew_rows([
            {"name": "redis", "status": "started",
             "file": _DecodeBombBytes(b"/nonexistent/homebrew.mxcl.redis.plist")},
        ])
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(
            rows["redis"]["plist"], "/nonexistent/homebrew.mxcl.redis.plist"
        )

    def test_non_list_snapshot_degrades_to_no_rows_not_a_wipe_of_the_page(self):
        rows = self._brew_rows({"name": "redis"})
        self.assertEqual(rows, {})


class BrewCacheLoadTailTests(unittest.TestCase):
    """The shared snapshot loader survives hostile spawn results."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", self.disk)
        patched.start()
        self.addCleanup(patched.stop)
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)

    def _get(self, spawn):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=spawn),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return [r["id"] for r in resp.json()["services"]]

    def test_eq_bomb_rc_zero_still_publishes_the_fresh_rows(self):
        # ``if rc == 0`` used to raise out of _load and wipe the snapshot.
        ids = self._get(
            (_EqBombInt(0), '[{"name":"a","status":"started"}]', "")
        )
        self.assertEqual(ids, ["a"])

    def test_eq_bomb_nonzero_rc_still_reads_as_failure(self):
        ids = self._get(
            (_EqBombInt(2), '[{"name":"a","status":"started"}]', "")
        )
        self.assertEqual(ids, [])

    def test_iter_bomb_stdout_list_publishes_its_rows(self):
        # A stub already returning a parsed list, but as an __iter__-bomb
        # subclass: the bound filter used to blow the fresh snapshot.
        ids = self._get(
            (0, _IterBombList([{"name": "a", "status": "started"}]), "")
        )
        self.assertEqual(ids, ["a"])

    def test_wrong_arity_spawn_tuple_keeps_the_last_good_disk_snapshot(self):
        # The ``rc, out, _ =`` unpack used to ValueError out of _load and
        # wipe the rows the on-disk journal still had.
        self.disk.write_text(
            json.dumps([{"name": "redis", "status": "started"}]),
            encoding="utf-8",
        )
        ids = self._get((0, '[{"name":"x","status":"started"}]'))
        self.assertEqual(ids, ["redis"])

    def test_clean_spawn_still_round_trips(self):
        ids = self._get((0, '[{"name":"a","status":"started"}]', ""))
        self.assertEqual(ids, ["a"])


if __name__ == "__main__":
    unittest.main()
