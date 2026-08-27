"""Eleventh leftover-500s sweep of the Logs surfaces, over the real app.

logs9 routed every bare ``isinstance`` through the fail-closed ``_isa`` and
logs8 laundered the *str-subclass* fields through unbound ``str.__str__``,
but three seams still handed poisoned objects past the guards:

- ``cfg()`` itself was called *bare* in ``_entries`` — the
  try/except-around-cfg() union rule ups_svc / status / scheduler_svc /
  smart_test_svc already follow — so a config snapshot provider that raises
  on read 500'd GET /api/logs and GET /api/logs/{id} together.

- ``str(x)`` returns its operand's ``tp_str`` result *verbatim* when that
  result is a str subclass.  An int-subclass id/name whose ``__str__``
  returns a subclass carrying a ``__len__``/``__bool__`` bomb, and a
  date-subclass id/name whose ``isoformat()`` returns a self-``__str__``
  subclass (the json6 convention), both sailed through ``_config_text``
  still armed — and the bare ``if not raw_id:`` truthiness probe in
  ``_entries`` detonated them: the same double 500.

- ``Path`` stores its raw text and parses it *lazily*: a non-str ``path``
  leftover whose ``__str__`` returns a str subclass with a poisoned
  ``__getitem__`` passed the guarded construction, then blew up later
  inside ``_log_path_allowed`` / ``is_file`` — outside every try — and
  500'd both routes.

The fix, in hub/logs_svc.py, is the guarded ``cfg()`` read plus the
``_exact_str`` launder: every text ``_config_text`` publishes and every
path text handed to ``Path`` is copied to an *exact* str through the
unbound ``str.__str__`` (CPython copies non-exact operands), so nothing
poisoned survives into the truthiness probes or pathlib's lazy parse.

Stays-immune pins ride along for the neighbours already absorbed: raising
``isoformat`` *properties* (real date subclass and lying ``__class__``
impostor), encode-bomb subclasses laundered by ``_utf8_text``, plain YAML
dates, non-str isoformat returns, and the >4300-digit int id drop.
"""
from __future__ import annotations

import datetime
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

DEFAULT_IDS = ["autostart", "serverhub", "ha"]


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


class LenBombStr(str):
    """Self-``__str__`` str subclass (json6): ``str(x)`` keeps the subclass,
    so the poisoned ``__len__`` stays armed for any bare truthiness probe."""

    def __str__(self):
        return self

    def __len__(self):
        raise RuntimeError("leftover __len__ bomb")


class BoolBombStr(str):
    def __str__(self):
        return self

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class EncodeBombStr(str):
    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover encode bomb")


class StrBombInt(int):
    """Int subclass whose ``__str__`` hands back the len-bomb subclass —
    ``str(value)`` returns it verbatim."""

    def __str__(self):
        return LenBombStr(int.__repr__(self))


class BoolStrBombInt(int):
    def __str__(self):
        return BoolBombStr(int.__repr__(self))


class EncodeStrBombInt(int):
    def __str__(self):
        return EncodeBombStr(int.__repr__(self))


class IsoSelfStrDate(datetime.date):
    """Date subclass whose isoformat() returns the self-``__str__`` bomb."""

    def isoformat(self):
        return LenBombStr("2024-01-01")


class IsoBoolSelfStrDate(datetime.date):
    def isoformat(self):
        return BoolBombStr("2024-01-01")


class IsoNonStrDate(datetime.date):
    """isoformat() returning a non-str: renders through the str() probe."""

    def isoformat(self):
        return 12345


class IsoPropBombDate(datetime.date):
    """A raising ``isoformat`` *property* on a real date subclass."""

    @property
    def isoformat(self):
        raise RuntimeError("leftover isoformat property bomb")


class DateLiarIsoPropBomb:
    """Lying ``__class__`` claiming date, raising ``isoformat`` property."""

    @property
    def __class__(self):
        return datetime.date

    @property
    def isoformat(self):
        raise RuntimeError("leftover isoformat property bomb (liar)")


class GetitemBombStr(str):
    """Self-``__str__`` subclass whose slicing raises: ``Path`` stores the
    raw text and parses lazily, outside the construction guard."""

    def __str__(self):
        return self

    def __getitem__(self, item):
        raise RuntimeError("leftover __getitem__ bomb")


class PathTextObj:
    """Arbitrary non-str leftover whose ``__str__`` returns the poisoned
    subclass — the shape that used to reach pathlib unlaundered."""

    def __init__(self, text):
        self._text = text

    def __str__(self):
        return GetitemBombStr(self._text)


def _raising_cfg():
    raise RuntimeError("leftover cfg snapshot provider bomb")


class _LogsSandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log_path = os.path.join(self._tmp.name, "sane.log")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write("line-one\nline-two\n")

    def _list(self, cfg_value):
        provider = cfg_value if callable(cfg_value) else (lambda: cfg_value)
        with mock.patch.object(logs_svc, "cfg", provider):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))["sources"]

    def _tail(self, cfg_value, source_id="s1", expect=200):
        provider = cfg_value if callable(cfg_value) else (lambda: cfg_value)
        with mock.patch.object(logs_svc, "cfg", provider):
            resp = _client().get(
                "/api/logs/" + urllib.parse.quote(str(source_id), safe=""))
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class RaisingCfgProviderTests(_LogsSandbox):
    """The reproduced 500: the bare ``cfg()`` call inside ``_entries``."""

    def test_raising_cfg_degrades_listing_to_defaults(self):
        rows = self._list(_raising_cfg)
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)

    def test_raising_cfg_tail_is_an_honest_404(self):
        self._tail(_raising_cfg, "s1", expect=404)


class SelfStrSubclassLeakTests(_LogsSandbox):
    """The reproduced 500s: ``_config_text`` handing a poisoned str
    subclass back verbatim, detonating the bare truthiness probes."""

    def test_int_strbomb_id_still_lists_and_tails_as_text(self):
        cfg_value = {"log_sources": [
            {"id": StrBombInt(42), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("42", True)])
        self.assertEqual(self._tail(cfg_value, "42")["lines"], 2)

    def test_int_boolbomb_id_still_lists_and_tails_as_text(self):
        cfg_value = {"log_sources": [
            {"id": BoolStrBombInt(7), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["7"])
        self.assertEqual(self._tail(cfg_value, "7")["lines"], 2)

    def test_int_strbomb_name_still_lists_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": StrBombInt(42), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([(r["id"], r["name"]) for r in rows], [("s1", "42")])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_iso_selfstr_lenbomb_id_still_lists_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": IsoSelfStrDate(2024, 1, 1), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["2024-01-01"])
        self.assertEqual(self._tail(cfg_value, "2024-01-01")["lines"], 2)

    def test_iso_selfstr_boolbomb_id_still_lists_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": IsoBoolSelfStrDate(2024, 1, 1), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["2024-01-01"])
        self.assertEqual(self._tail(cfg_value, "2024-01-01")["lines"], 2)

    def test_iso_selfstr_lenbomb_name_still_lists_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": IsoSelfStrDate(2024, 1, 1),
             "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["name"]) for r in rows], [("s1", "2024-01-01")])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)


class LazyPathParseBombTests(_LogsSandbox):
    """The reproduced 500: pathlib's lazy parse detonating a poisoned
    str-subclass path text outside every guard."""

    def test_path_obj_with_getitem_bomb_text_still_lists_and_tails(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "path": PathTextObj(self.log_path)}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["path"], r["exists"]) for r in rows],
            [("s1", self.log_path, True)])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_bombed_path_beside_a_sane_sibling_keeps_both(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": PathTextObj(self.log_path)},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["junk", "sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)


class StaysImmuneTests(_LogsSandbox):
    """Neighbours of the reproduced bombs, pinned so they cannot regress."""

    def test_plain_yaml_date_id_lists_as_isoformat_text(self):
        cfg_value = {"log_sources": [
            {"id": datetime.date(2024, 1, 2), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["2024-01-02"])
        self.assertEqual(self._tail(cfg_value, "2024-01-02")["lines"], 2)

    def test_iso_returning_non_str_renders_through_the_str_probe(self):
        cfg_value = {"log_sources": [
            {"id": IsoNonStrDate(2024, 1, 1), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["12345"])
        self.assertEqual(self._tail(cfg_value, "12345")["lines"], 2)

    def test_iso_property_bomb_on_a_real_date_sub_drops_only_its_row(self):
        cfg_value = {"log_sources": [
            {"id": IsoPropBombDate(2024, 1, 1), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_iso_property_bomb_on_a_date_liar_drops_only_its_row(self):
        cfg_value = {"log_sources": [
            {"id": DateLiarIsoPropBomb(), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_encode_bomb_subclass_id_is_laundered_by_utf8_text(self):
        cfg_value = {"log_sources": [
            {"id": EncodeStrBombInt(42), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["42"])
        self.assertEqual(self._tail(cfg_value, "42")["lines"], 2)

    def test_over_cap_int_id_drops_only_its_own_row(self):
        cfg_value = {"log_sources": [
            {"id": 10 ** 5000, "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)


class SanitizerUnitPins(unittest.TestCase):
    """``_exact_str`` itself: exact passthrough, subclass copy, junk None."""

    def test_exact_str_passes_an_exact_str_through(self):
        text = "hello"
        self.assertIs(logs_svc._exact_str(text), text)

    def test_exact_str_copies_a_poisoned_subclass_to_exact_str(self):
        copied = logs_svc._exact_str(LenBombStr("x"))
        self.assertIs(type(copied), str)
        self.assertEqual(copied, "x")

    def test_exact_str_refuses_non_str_values(self):
        self.assertIsNone(logs_svc._exact_str(42))
        self.assertIsNone(logs_svc._exact_str(b"bytes"))
        self.assertIsNone(logs_svc._exact_str(None))

    def test_config_text_always_returns_an_exact_str(self):
        for value in (StrBombInt(42), IsoSelfStrDate(2024, 1, 1),
                      LenBombStr("x"), "plain"):
            out = logs_svc._config_text(value)
            self.assertIs(type(out), str, repr(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
