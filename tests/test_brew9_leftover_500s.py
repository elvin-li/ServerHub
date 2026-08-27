"""Ninth leftover-500s sweep: brew listing / autostart / _json_safe surfaces.

Hunted over ``create_app()`` + TestClient(raise_server_exceptions=False),
after brew8 sealed the listing truth-test and provider-shape row wipes.
This sweep found one new class with three live 500s plus a family of
row/snapshot wipes, all fixed here: a leftover object whose ``__class__``
is a *raising property*.  When the type check fails, CPython's isinstance
consults ``value.__class__`` — so every ``isinstance`` gate that ran
outside a try dispatched straight into the bomb.  (A real subclass never
reaches that lookup: the type check answers first, so the guarded
``_isinstance`` only reclassifies impostors.)

GET /api/brew/services (brew_svc.list_services) — live 500s
* ``isinstance(data, list)`` on the provider snapshot ran outside the
  provider try: a ``__class__``-bomb snapshot **500'd** the listing.
* the fallback tail's ``_plain_rc(rc)`` / ``isinstance(out, ...)`` probes
  run outside the spawn try: a ``__class__``-bomb rc or stdout **500'd**
  the fallback the same way.

Row/snapshot wipes of the same class, now costing only the poisoned value
* one ``__class__``-bomb element in the provider list blew the
  ``isinstance(s, dict)`` filter and wiped every sibling row into the text
  fallback; a bomb *field* blew ``_json_safe``/``_as_text`` the same way.
* brew_cache: a bomb rc raised out of ``_load`` via ``_plain_rc`` and
  discarded the last-good snapshot; a bomb stdout / element / field /
  mapping *key* did the same via ``_services_from_output`` /
  ``_copy_items`` / ``_json_safe``.
* brew_cache._brew_busy: ``bytes(captured)`` dispatched a bytes-subclass
  ``__bytes__`` bomb (RuntimeError escaped the narrow except tuple).
* autostart_svc._brew_service_items: the ``isinstance(data, list)`` gate
  and the field probes ran outside any try, so one bomb wiped every
  Homebrew row into overview()'s _safe fallback.
* brew_svc._json_safe had no depth cap: a two-object ``isoformat`` cycle
  recursed until wherever RecursionError happened to land (it survived
  only by luck of which frame blew).  Capped like brew_cache's.

Stays-immune pins (no new 500 found; behaviour pinned so it stays)
* a leftover FIFO at the brew-services disk snapshot: read_text_capped
  opens O_NONBLOCK and rejects non-regular files, so the read degrades
  instead of parking the request until a writer appears.
* a >4300-digit number in live `brew services list --json` output: the
  parse_int hook drops the number, keeps the document (json.loads digit-cap
  ValueError class).
* an unbound-method ``isoformat`` (the datetime *class* as a field value):
  the TypeError is caught and the field degrades to None.
* a float-subclass rc whose ``__eq__``/``__float__`` raises: unbound
  ``float.__float__`` dodges the override in brew_cache._plain_rc.
"""
from __future__ import annotations

import datetime
import json
import os
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


class _ClassBomb:
    """isinstance() consults ``__class__`` when the type check fails."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _BytesBombBytes(bytes):
    def __bytes__(self):
        raise RuntimeError("bytes bomb")


class _FloatBombRc(float):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    def __float__(self):
        raise RuntimeError("float bomb")

    __hash__ = float.__hash__


class _IsoCycleA:
    def isoformat(self):
        return _IsoCycleB()


class _IsoCycleB:
    def isoformat(self):
        return _IsoCycleA()


class BrewListClassBombTests(unittest.TestCase):
    """GET /api/brew/services: raising-__class__ leftovers on the JSON path."""

    def _get(self, data, sh=(1, "", "")):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=data),
            mock.patch.object(brew_svc, "sh", return_value=sh),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def test_class_bomb_snapshot_degrades_to_the_text_fallback_not_500(self):
        # isinstance(data, list) ran outside the provider try: HTTP 500.
        resp = self._get(
            _ClassBomb(),
            sh=(0, "Name Status User File\nredis started svc\n", ""),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")

    def test_class_bomb_element_keeps_the_sibling_rows(self):
        # One bomb element used to blow the isinstance(s, dict) filter and
        # wipe every sibling into the (empty) text fallback.
        resp = self._get([_ClassBomb(), {"name": "redis", "status": "started"}])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["id"] for r in resp.json()["services"]], ["redis"]
        )

    def test_class_bomb_field_costs_only_that_field(self):
        # A bomb value used to blow _json_safe's first probe inside the loop
        # try and wipe both rows.
        resp = self._get([
            {"name": "redis", "status": "started", "user": _ClassBomb()},
            {"name": "glances", "status": "none"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(sorted(rows), ["glances", "redis"])
        self.assertIsNone(rows["redis"]["user"])
        self.assertEqual(rows["redis"]["status"], "started")


class BrewListFallbackTailClassBombTests(unittest.TestCase):
    """The text-fallback tail runs outside the spawn try; bombs 500'd it."""

    def _get(self, sh):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=[]),
            mock.patch.object(brew_svc, "sh", return_value=sh),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def test_class_bomb_rc_reads_as_failure_not_500(self):
        # _plain_rc's isinstance(value, bool) dispatched the bomb: HTTP 500.
        resp = self._get((_ClassBomb(), "Name Status\nredis started\n", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_class_bomb_stdout_degrades_to_no_rows_not_500(self):
        # isinstance(out, (str, bytes, bytearray)) dispatched it: HTTP 500.
        resp = self._get((0, _ClassBomb(), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])


class BrewCacheClassBombTests(unittest.TestCase):
    """brew_cache._load survives raising-__class__ spawn results."""

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
        return {r["id"]: r for r in resp.json()["services"]}

    def _prime_disk(self):
        self.disk.write_text(
            json.dumps([{"name": "redis", "status": "started"}]),
            encoding="utf-8",
        )

    def test_class_bomb_rc_keeps_the_last_good_disk_snapshot(self):
        # _plain_rc used to raise out of _load and wipe the last-good rows.
        self._prime_disk()
        rows = self._get((_ClassBomb(), '[{"name":"a","status":"started"}]', ""))
        self.assertEqual(sorted(rows), ["redis"])

    def test_class_bomb_stdout_keeps_the_last_good_disk_snapshot(self):
        # _services_from_output's isinstance(out, list) used to raise the
        # same way.
        self._prime_disk()
        rows = self._get((0, _ClassBomb(), ""))
        self.assertEqual(sorted(rows), ["redis"])

    def test_class_bomb_element_keeps_the_fresh_sibling_rows(self):
        rows = self._get(
            (0, [_ClassBomb(), {"name": "a", "status": "started"}], "")
        )
        self.assertEqual(sorted(rows), ["a"])

    def test_class_bomb_field_costs_only_that_field(self):
        rows = self._get(
            (0, [{"name": "a", "status": "started", "user": _ClassBomb()}], "")
        )
        self.assertEqual(sorted(rows), ["a"])
        self.assertIsNone(rows["a"]["user"])

    def test_class_bomb_mapping_key_keeps_the_row(self):
        # One bomb *key* used to blow _json_safe's dict branch in
        # _copy_items and wipe the whole snapshot.
        row = {"name": "a", "status": "started"}
        row[_ClassBomb()] = "leftover"
        rows = self._get((0, [row], ""))
        self.assertEqual(sorted(rows), ["a"])
        self.assertEqual(rows["a"]["status"], "started")

    def test_bytes_bomb_pgrep_stdout_cannot_raise_out_of_brew_busy(self):
        # bytes(captured) dispatched the subclass __bytes__ bomb; the
        # RuntimeError escaped the narrow except tuple and raised out of
        # _load via _brew_busy.  The real buffer content must survive.
        proc = mock.Mock()
        proc.returncode = 0
        proc.stdout = _BytesBombBytes(b"123\n")
        with mock.patch.object(
            brew_cache.subprocess, "run", return_value=proc
        ):
            self.assertTrue(brew_cache._brew_busy())


class AutostartBrewClassBombTests(unittest.TestCase):
    """GET /api/apps/autostart: the brew collector survives __class__ bombs."""

    def _page(self, data):
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
        return resp.json()["items"]

    def _brew_rows(self, data) -> dict:
        return {
            i["name"]: i for i in self._page(data) if i.get("kind") == "brew"
        }

    def test_class_bomb_snapshot_costs_only_the_brew_group(self):
        # The isinstance(data, list) gate ran outside any try: the raise
        # used to land in overview()'s _safe and wipe the collector.  A
        # non-list snapshot has no rows to keep, but the other groups must
        # keep rendering.
        items = self._page(_ClassBomb())
        self.assertEqual(
            [i for i in items if i.get("kind") == "brew"], []
        )
        self.assertTrue(
            any(i.get("kind") == "script" for i in items),
            "sibling groups vanished with the brew snapshot",
        )

    def test_class_bomb_element_keeps_the_sibling_brew_rows(self):
        rows = self._brew_rows(
            [_ClassBomb(), {"name": "redis", "status": "started"}]
        )
        self.assertEqual(sorted(rows), ["redis"])
        self.assertTrue(rows["redis"]["running"])

    def test_class_bomb_file_field_still_renders_the_row(self):
        rows = self._brew_rows([
            {"name": "redis", "status": "started", "file": _ClassBomb()},
        ])
        self.assertEqual(sorted(rows), ["redis"])
        self.assertIsNone(rows["redis"]["plist"])


class BrewStaysImmunePins(unittest.TestCase):
    """Vectors probed and found already sealed; pinned so they stay sealed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", self.disk)
        patched.start()
        self.addCleanup(patched.stop)
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)

    def _get_via_cache(self, spawn):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=spawn),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {r["id"]: r for r in resp.json()["services"]}

    def test_fifo_at_the_disk_snapshot_degrades_instead_of_parking(self):
        # read_text_capped opens O_NONBLOCK and rejects non-regular files
        # (OSError EINVAL), so a leftover FIFO cannot wedge the request.
        os.mkfifo(self.disk)
        self.assertIsNone(brew_cache._read_disk_file())
        rows = self._get_via_cache((1, "", ""))
        self.assertEqual(rows, {})

    def test_hugeint_in_live_output_drops_the_number_keeps_the_document(self):
        # json.loads of a >4300-digit literal is the digit-cap ValueError
        # for the whole document; the parse_int hook keeps the rows.
        out = (
            '[{"name":"a","status":"started","exit_code":'
            + "9" * 5000 + "}]"
        )
        rows = self._get_via_cache((0, out, ""))
        self.assertEqual(sorted(rows), ["a"])
        self.assertIsNone(rows["a"]["exit_code"])

    def test_float_subclass_rc_bomb_still_publishes_the_fresh_rows(self):
        # Unbound float.__float__ dodges the override in _plain_rc.
        rows = self._get_via_cache(
            (_FloatBombRc(0.0), '[{"name":"a","status":"started"}]', "")
        )
        self.assertEqual(sorted(rows), ["a"])

    def _get_listing(self, data):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=data),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {r["id"]: r for r in resp.json()["services"]}

    def test_isoformat_two_object_cycle_costs_only_the_field(self):
        # brew_svc._json_safe now carries the same depth cap as
        # brew_cache's; the cycle degrades to None deterministically.
        rows = self._get_listing([
            {"name": "redis", "status": "started", "user": _IsoCycleA()},
            {"name": "glances", "status": "none"},
        ])
        self.assertEqual(sorted(rows), ["glances", "redis"])
        self.assertIsNone(rows["redis"]["user"])

    def test_unbound_isoformat_method_degrades_to_none(self):
        # The datetime *class* as a field value: getattr finds the unbound
        # isoformat, calling it TypeErrors (missing self), caught -> None.
        rows = self._get_listing([
            {"name": "redis", "status": "started",
             "user": datetime.datetime, "exit_code": 0},
        ])
        self.assertEqual(sorted(rows), ["redis"])
        self.assertIsNone(rows["redis"]["user"])
        self.assertEqual(rows["redis"]["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
