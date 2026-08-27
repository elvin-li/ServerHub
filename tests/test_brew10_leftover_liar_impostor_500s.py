"""Tenth leftover-500s sweep: lying ``__class__`` impostors on the brew surfaces.

Hunted over ``create_app()`` + TestClient(raise_server_exceptions=False),
after brew9 sealed the *raising*-``__class__`` property bombs.  The
health10/json9 sibling class stayed live here: an object whose ``__class__``
property *returns* a claimed type (bool/str/bytes/list/dict) while the real
object is a plain object.  It passes every ``_isinstance`` gate — CPython's
isinstance consults ``__class__`` when the exact-type check misses — and
then detonates the unbound base descriptor the gate was guarding
(``bytes.decode`` / ``str.encode`` / ``dict.get`` / ``dict.items`` /
``list.__iter__`` / ``int()``), because that C-level call checks the real
type and refuses the impostor with TypeError.

Live 500s found and fixed here (all reproduced through the real app):
* GET /api/brew/services — a bool-liar ``user``/``file``/``exit_code``
  rode through both ``_json_safe`` launderers' old ``return value`` arm
  raw and 500'd Starlette's ``allow_nan=False`` encoder (provider path
  and brew_cache path alike).
* GET /api/brew/services — the fallback tail runs outside the spawn try:
  a bool-liar rc blew ``_plain_rc``'s bare ``int(value)``; a str/bytes-liar
  stdout blew ``_as_text``'s unbound encode/decode.  Raw 500s.
* POST /api/brew/services/{name}/action — the post-spawn tail runs outside
  its try: a bool-liar rc and a str/bytes-liar ``msg`` 500'd the action
  after brew had already finished, the same way.

Row/snapshot wipes of the same class, now costing only the poisoned value:
* a dict-liar element passed the ``_isinstance(s, dict)`` filter and then
  ``dict.get`` refused it inside the loop-wide try, wiping every sibling
  row into the text fallback; per-row guard now.
* a str/bytes-liar field raised out of ``_json_safe`` and wiped the row set.
* brew_cache: a bool-liar rc / list-liar / str-liar stdout raised out of
  ``_load`` (via ``_plain_rc`` / ``_services_from_output`` / ``_as_text``)
  and discarded the last-good disk snapshot; a dict-liar element, a
  bytes-liar mapping key and a list-liar nested field raised out of
  ``_copy_items`` and wiped the whole fresh snapshot.

Stays-immune pins (no new 500 found; behaviour pinned so it stays):
* an int-liar rc: ``int.__index__`` already ran inside a try, so it reads
  as failure (listing) / "exit unknown" (action) instead of raising.
* a list-liar provider snapshot: ``list.__iter__`` already ran inside a
  try, so the listing degrades to the text fallback.
* a genuine int-subclass rc whose ``__eq__``/``__ne__`` raises: unbound
  ``int.__index__`` dodges the override (the brew9 float pin, int rank).
* _brew_busy: a str/bytes-liar pgrep stdout answers False, never raises.

Fixes keep the unbound-base-method convention (a genuine subclass bomb
still launders through the C-level type check) but run the descriptor
inside a try: a liar the descriptor refuses degrades — None for a field,
failure for an rc, honest ``str()`` for text — instead of 500ing.  The
brew6..9 pins are untouched; product version stays 3.9.3.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import brew_cache, brew_svc
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


def _liar(claimed):
    """A lying ``__class__`` impostor: isinstance answers *claimed*, the
    real object is a plain object, so every unbound base descriptor
    (``bytes.decode``, ``dict.get``, ``list.__iter__``, ``int()``...)
    refuses it with TypeError."""

    class _Liar:
        @property
        def __class__(self):
            return claimed

    return _Liar()


class _IntBombRc(int):
    """Genuine int subclass whose comparisons raise (the rc ``__eq__`` class)."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class BrewListLiarImpostorTests(unittest.TestCase):
    """GET /api/brew/services: liars on the provider (JSON) path."""

    def _get(self, data, sh=(1, "", "")):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=data),
            mock.patch.object(brew_svc, "sh", return_value=sh),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def _rows(self, data, sh=(1, "", "")):
        resp = self._get(data, sh=sh)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {r["id"]: r for r in resp.json()["services"]}

    def test_bool_liar_field_renders_a_real_bool_not_500(self):
        # The old ``return value`` arm handed the liar raw to Starlette's
        # encoder: raw 500.  bool is final, so the impostor coerces to its
        # honest truthiness instead.
        rows = self._rows(
            [{"name": "redis", "status": "started", "user": _liar(bool)}]
        )
        self.assertEqual(sorted(rows), ["redis"])
        self.assertIs(rows["redis"]["user"], True)

    def test_str_liar_field_costs_only_that_field(self):
        # Unbound str.encode refused the liar and the raise wiped the row
        # set into the (empty) text fallback.
        rows = self._rows([
            {"name": "redis", "status": "started", "user": _liar(str)},
            {"name": "glances", "status": "none"},
        ])
        self.assertEqual(sorted(rows), ["glances", "redis"])
        self.assertIsNone(rows["redis"]["user"])
        self.assertEqual(rows["redis"]["status"], "started")

    def test_bytes_liar_field_costs_only_that_field(self):
        rows = self._rows(
            [{"name": "redis", "status": "started", "file": _liar(bytes)}]
        )
        self.assertEqual(sorted(rows), ["redis"])
        self.assertIsNone(rows["redis"]["file"])

    def test_dict_liar_element_keeps_the_sibling_rows(self):
        # The liar passed the _isinstance(s, dict) filter, then dict.get
        # refused it inside the loop-wide try: every sibling row wiped.
        rows = self._rows(
            [_liar(dict), {"name": "redis", "status": "started"}]
        )
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")


class BrewListFallbackTailLiarTests(unittest.TestCase):
    """The text-fallback tail runs outside the spawn try; liars 500'd it."""

    def _get(self, sh):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=[]),
            mock.patch.object(brew_svc, "sh", return_value=sh),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def test_bool_liar_rc_reads_as_failure_not_500(self):
        # _plain_rc's bare int(value) dispatched into the impostor: raw 500.
        resp = self._get((_liar(bool), "Name Status\nredis started\n", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_str_liar_stdout_degrades_to_no_rows_not_500(self):
        # The liar passed _isinstance(out, (str, bytes, bytearray)) and
        # unbound str.encode refused it inside _as_text: raw 500.  Its
        # honest one-line __str__ is all header, so no rows parse.
        resp = self._get((0, _liar(str), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_bytes_liar_stdout_degrades_to_no_rows_not_500(self):
        # Same, off unbound bytes.decode.
        resp = self._get((0, _liar(bytes), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_int_liar_rc_stays_a_failure_read_not_500(self):
        # Pin: int.__index__ already ran inside a try, so the impostor
        # degrades to None (failure) instead of raising.
        resp = self._get((_liar(int), "Name Status\nredis started\n", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])


class BrewActionLiarTests(unittest.TestCase):
    """POST /api/brew/services/{name}/action: the post-spawn tail runs
    outside its try; liar rc/msg 500'd the action after brew finished."""

    def _post(self, rc, msg):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped", return_value=(rc, msg)),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "restart"}
            )
        _assert_clean(self, resp)
        return resp

    def test_bool_liar_rc_answers_exit_unknown_not_500(self):
        # _plain_rc's bare int(value) dispatched into the impostor: raw 500
        # after the run had already finished.
        resp = self._post(_liar(bool), "")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "exit unknown")

    def test_bytes_liar_msg_renders_its_honest_str_not_500(self):
        # _as_text's unbound bytes.decode refused the impostor: raw 500.
        resp = self._post(0, _liar(bytes))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertIsInstance(body["message"], str)
        self.assertTrue(body["message"])

    def test_str_liar_msg_renders_its_honest_str_not_500(self):
        # The liar rode the str branch as *text* itself and unbound
        # str.encode refused it: raw 500.
        resp = self._post(0, _liar(str))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertIsInstance(body["message"], str)
        self.assertTrue(body["message"])

    def test_int_liar_rc_stays_exit_unknown_not_500(self):
        # Pin: the int arm's try already absorbed the refused __index__.
        resp = self._post(_liar(int), "done")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "done")

    def test_int_subclass_eq_bomb_rc_still_reads_exit_zero(self):
        # Pin (the rc __eq__ class): unbound int.__index__ dodges the
        # override, so the sentinel probe and ``ok`` render fine.
        resp = self._post(_IntBombRc(0), "")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "exit 0")


class BrewCacheLiarImpostorTests(unittest.TestCase):
    """brew_cache._load and its launderers survive lying impostors."""

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

    def test_bool_liar_field_in_fresh_row_renders_a_real_bool_not_500(self):
        # The liar survived both _json_safe launderers' old ``return
        # value`` arm and 500'd Starlette's encoder through the cache path.
        rows = self._get(
            (0, [{"name": "a", "status": "started", "user": _liar(bool)}], "")
        )
        self.assertEqual(sorted(rows), ["a"])
        self.assertIs(rows["a"]["user"], True)

    def test_str_liar_field_costs_only_that_field(self):
        # Unbound str.encode refused the liar out of _copy_items: the
        # whole fresh snapshot used to wipe.
        rows = self._get(
            (0, [{"name": "a", "status": "started", "user": _liar(str)}], "")
        )
        self.assertEqual(sorted(rows), ["a"])
        self.assertIsNone(rows["a"]["user"])

    def test_dict_liar_element_keeps_the_fresh_sibling_rows(self):
        # The liar passed _copy_items' dict filter and dict.items refused
        # it inside _json_safe: every sibling row wiped.
        rows = self._get((0, [_liar(dict), {"name": "a", "status": "started"}], ""))
        self.assertEqual(sorted(rows), ["a"])

    def test_bool_liar_rc_keeps_the_last_good_disk_snapshot(self):
        # _plain_rc's bare int(value) raised out of _load and discarded
        # the last-good rows.
        self._prime_disk()
        rows = self._get(
            (_liar(bool), '[{"name":"a","status":"started"}]', "")
        )
        self.assertEqual(sorted(rows), ["redis"])

    def test_list_liar_stdout_keeps_the_last_good_disk_snapshot(self):
        # The liar passed _services_from_output's list gates and unbound
        # list.__iter__ refused it out of _load.
        self._prime_disk()
        rows = self._get((0, _liar(list), ""))
        self.assertEqual(sorted(rows), ["redis"])

    def test_str_liar_stdout_keeps_the_last_good_disk_snapshot(self):
        # _as_text's unbound str.encode refused the liar out of _load; its
        # honest __str__ is not JSON, so the read degrades to last-good.
        self._prime_disk()
        rows = self._get((0, _liar(str), ""))
        self.assertEqual(sorted(rows), ["redis"])

    def test_bytes_liar_mapping_key_keeps_the_row(self):
        # Unbound bytes.decode refused the liar *key* out of _json_safe's
        # pair walk: the whole snapshot wiped.  The key now renders its
        # honest __str__ and the row's real pairs survive.
        row = dict([("name", "a"), ("status", "started"), (_liar(bytes), "x")])
        rows = self._get((0, [row], ""))
        self.assertEqual(sorted(rows), ["a"])
        self.assertEqual(rows["a"]["status"], "started")

    def test_list_liar_nested_field_costs_only_that_field(self):
        # The sequence arm's unbound base.__iter__ refused the liar the
        # same way; it degrades to None.
        rows = self._get(
            (0, [{"name": "a", "status": "started", "user": _liar(list)}], "")
        )
        self.assertEqual(sorted(rows), ["a"])
        self.assertIsNone(rows["a"]["user"])


class BrewLiarStaysImmunePins(unittest.TestCase):
    """Vectors probed and found already sealed; pinned so they stay sealed."""

    def test_list_liar_snapshot_degrades_to_the_text_fallback(self):
        # list_services' unbound list.__iter__ already ran inside a try:
        # the liar snapshot reads as no rows and the text fallback answers.
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(
                brew_svc, "brew_services_list", return_value=_liar(list)
            ),
            mock.patch.object(
                brew_svc, "sh",
                return_value=(0, "Name Status\nredis started\n", ""),
            ),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")

    def test_brew_busy_liar_pgrep_stdout_answers_false_never_raises(self):
        # The str-liar's unbound encode TypeError lands in the broad spawn
        # except (continue); the bytes-liar is refused by memoryview inside
        # its own guard.  Both read as "not busy".
        for claimed in (str, bytes):
            proc = mock.Mock()
            proc.returncode = 0
            proc.stdout = _liar(claimed)
            with mock.patch.object(
                brew_cache.subprocess, "run", return_value=proc
            ):
                self.assertFalse(brew_cache._brew_busy())

    def test_plain_rc_int_subclass_eq_bomb_still_publishes_fresh_rows(self):
        # The brew9 float pin at int rank: unbound int.__index__ dodges the
        # __eq__/__ne__ override in brew_cache._plain_rc.
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "brew-services.cache.json"
            with mock.patch.object(brew_cache, "_DISK", disk):
                brew_cache.invalidate_brew_services()
                try:
                    with (
                        mock.patch.object(
                            brew_svc, "_brew_present", return_value=True
                        ),
                        mock.patch.object(
                            brew_cache, "_brew_busy", return_value=False
                        ),
                        mock.patch.object(
                            brew_cache, "sh",
                            return_value=(
                                _IntBombRc(0),
                                '[{"name":"a","status":"started"}]',
                                "",
                            ),
                        ),
                        mock.patch.object(
                            brew_svc, "sh", return_value=(1, "", "")
                        ),
                    ):
                        resp = client().get("/api/brew/services")
                    _assert_clean(self, resp)
                    self.assertEqual(resp.status_code, 200, resp.text[:300])
                    rows = {r["id"]: r for r in resp.json()["services"]}
                    self.assertEqual(sorted(rows), ["a"])
                finally:
                    brew_cache.invalidate_brew_services()


if __name__ == "__main__":
    unittest.main()
