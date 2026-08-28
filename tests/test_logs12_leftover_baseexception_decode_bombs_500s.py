"""Twelfth leftover-500s sweep of the Logs surfaces, over the real app.

logs9/logs11 sealed every rank of the config-to-row pipeline against bombs
that raise ``Exception`` — but every one of those guards stopped at
``except Exception``.  A fresh hunt over the same mounted routes
(create_app + TestClient, raise_server_exceptions=False) re-armed the
already-sealed vectors with a *BaseException* subclass (the shape a
watchdog/timeout-style leftover raises, the one modules12 just sealed on
its own route) and found them live again as raw 500s on GET /api/logs and
GET /api/logs/{id} together:

- a cfg() provider whose read raises BaseException — past the logs11
  guarded-cfg ``except Exception``;
- a ``__class__`` property with the same raise on the cfg root, the
  ``log_sources`` value, an entry, or an id/name/path field — past
  ``_isa``'s catch and out of every type gate at once;
- a dict-subclass entry ``.get`` bomb — past ``_mapping_get``'s catch one
  line ahead of its own ``dict.get`` salvage;
- a path ``__bool__`` bomb — past ``_truthy``;
- an int-subclass id ``__str__`` bomb and a date-subclass ``isoformat``
  bomb — past ``_config_text``'s catches;
- a path object whose ``__str__`` raises the same shape — past the
  ``Path()`` construction guard in ``_entries``.

The launder reaches every swallow site down to ``except BaseException``
while re-raising genuine control flow (``KeyboardInterrupt``,
``SystemExit``) untouched: a leftover data bomb can no longer 500 the
routes, and a real Ctrl-C or interpreter shutdown still propagates.

The same hunt found all three bytes arms (``_utf8_text``,
``_config_text``, ``_entries``' fs-decode) degrading a rank too coarsely:
each picked the decode base off the *claimed* ``__class__``, so a genuine
``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
``bytes.decode``, rejected by the descriptor, and a perfectly decodable
id/name/path silently vanished from the listing.  Not a 500, but the
wrong degrade rank.  Both base decodes are now tried against the real
storage: the honest layout wins and the source keeps listing and tailing;
a total impostor (real type is neither) still drops exactly as before.

Stays-immune pins ride along: the unbound ``list.__iter__`` snapshot
never runs subclass code, so a bound BaseException ``__iter__`` there
stays inert, and the logs11 Exception-shaped bombs stay closed beside the
widened guards.
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


class _Watchdog(BaseException):
    """A leftover raise that is BaseException-shaped but *not* Exception."""


class ClassBaseBomb:
    """``__class__`` property raising the BaseException subclass."""

    @property
    def __class__(self):  # type: ignore[override]
        raise _Watchdog("class access bomb")


class GetBaseBombDict(dict):
    """Real dict storage; bound ``.get`` raises the BaseException shape."""

    def get(self, *a, **k):
        raise _Watchdog("dict get bomb")


class BoolBaseBomb:
    def __bool__(self):
        raise _Watchdog("bool bomb")


class StrBaseBombInt(int):
    def __str__(self):
        raise _Watchdog("int __str__ bomb")


class IsoBaseBombDate(datetime.date):
    def isoformat(self):
        raise _Watchdog("isoformat bomb")


class StrBaseBombPathObj:
    """Arbitrary non-str path leftover whose ``__str__`` raises the shape."""

    def __str__(self):
        raise _Watchdog("path __str__ bomb")


class ByteArrayLyingBytes(bytearray):
    """Genuine bytearray storage; ``__class__`` claims ``bytes``."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class BytesImpostor:
    """Claims ``bytes`` while carrying neither bytes-like layout."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class IterBaseBombList(list):
    def __iter__(self):
        raise _Watchdog("list iter bomb")


def _raising_base_cfg():
    raise _Watchdog("cfg snapshot provider bomb")


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


class BaseExceptionBombTests(_LogsSandbox):
    """Each vector rode a BaseException subclass past the old
    ``except Exception`` guards and out of both routes raw."""

    def test_base_raising_cfg_degrades_listing_to_defaults(self):
        rows = self._list(_raising_base_cfg)
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)

    def test_base_raising_cfg_tail_is_an_honest_404(self):
        self._tail(_raising_base_cfg, "s1", expect=404)

    def test_class_bomb_as_cfg_root_degrades_to_defaults(self):
        rows = self._list(ClassBaseBomb())
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)

    def test_class_bomb_as_log_sources_value_degrades_to_defaults(self):
        rows = self._list({"log_sources": ClassBaseBomb()})
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)

    def test_class_bomb_entry_drops_alone_beside_a_sane_sibling(self):
        cfg_value = {"log_sources": [
            ClassBaseBomb(),
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_get_bomb_entry_keeps_its_sane_fields_via_dict_get(self):
        cfg_value = {"log_sources": [
            GetBaseBombDict({"id": "s1", "path": self.log_path})]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("s1", True)])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)

    def test_bool_bomb_path_drops_its_row_beside_a_sane_sibling(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": BoolBaseBomb()},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_int_str_bomb_id_drops_its_row_beside_a_sane_sibling(self):
        cfg_value = {"log_sources": [
            {"id": StrBaseBombInt(42), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_isoformat_bomb_id_drops_its_row_beside_a_sane_sibling(self):
        cfg_value = {"log_sources": [
            {"id": IsoBaseBombDate(2024, 1, 1), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_path_str_bomb_drops_its_row_beside_a_sane_sibling(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": StrBaseBombPathObj()},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)


class ControlFlowStillPropagatesTests(_LogsSandbox):
    """The launder must not eat genuine control flow: a Ctrl-C or an
    interpreter shutdown raised mid-listing keeps propagating."""

    def test_keyboardinterrupt_from_cfg_provider_propagates(self):
        def _ki_cfg():
            raise KeyboardInterrupt

        with mock.patch.object(logs_svc, "cfg", _ki_cfg):
            with self.assertRaises(KeyboardInterrupt):
                logs_svc.log_sources()

    def test_systemexit_from_class_property_propagates(self):
        class _SEBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise SystemExit(3)

        with mock.patch.object(logs_svc, "cfg", lambda: _SEBomb()):
            with self.assertRaises(SystemExit):
                logs_svc.log_sources()

    def test_keyboardinterrupt_from_entry_bool_propagates(self):
        class _KIBool:
            def __bool__(self):
                raise KeyboardInterrupt

        cfg_value = {"log_sources": [{"id": "s1", "path": _KIBool()}]}
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            with self.assertRaises(KeyboardInterrupt):
                logs_svc.log_sources()


class DecodeFidelityTests(_LogsSandbox):
    """The claimed-base decode gap: real content behind a lying
    ``__class__`` used to vanish; a total impostor still drops."""

    def test_bytearray_lying_bytes_id_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": ByteArrayLyingBytes(b"logid"), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("logid", True)])
        self.assertEqual(self._tail(cfg_value, "logid")["lines"], 2)

    def test_bytearray_lying_bytes_name_keeps_its_text(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": ByteArrayLyingBytes(b"My Log"),
             "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["name"]) for r in rows], [("s1", "My Log")])
        self.assertEqual(self._tail(cfg_value, "s1")["name"], "My Log")

    def test_bytearray_lying_bytes_path_keeps_listing_and_tailing(self):
        cfg_value = {"log_sources": [
            {"id": "s1",
             "path": ByteArrayLyingBytes(os.fsencode(self.log_path))}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["path"], r["exists"]) for r in rows],
            [("s1", self.log_path, True)])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_total_bytes_impostor_id_still_drops_its_row_alone(self):
        cfg_value = {"log_sources": [
            {"id": BytesImpostor(), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)


class StaysImmuneTests(_LogsSandbox):
    """Neighbours the same hunt confirmed already safe — the unbound
    seams never run subclass code — plus the logs11 Exception-shaped
    coverage pinned beside the widened guards."""

    def test_list_iter_baseexception_stays_inert_via_unbound_snapshot(self):
        cfg_value = {"log_sources": IterBaseBombList([
            {"id": "s1", "path": self.log_path}])}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["s1"])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)

    def test_exception_shaped_class_bomb_stays_closed(self):
        class _ClassExcBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise RuntimeError("class access bomb")

        cfg_value = {"log_sources": [
            _ClassExcBomb(),
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_sane_config_renders_identically(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": "Sane", "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["name"], r["exists"]) for r in rows],
            [("s1", "Sane", True)])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)


class SanitizerUnitPins(unittest.TestCase):
    """The widened helpers directly: decode fidelity in ``_utf8_text``
    and the ``_clamp_lines`` unbound-base read."""

    def test_utf8_text_decodes_a_bytearray_lying_bytes(self):
        self.assertEqual(logs_svc._utf8_text(ByteArrayLyingBytes(b"hi")), "hi")

    def test_clamp_lines_reads_the_real_value_under_an_index_bomb(self):
        class _IndexBombInt(int):
            def __index__(self):
                raise _Watchdog("index bomb")

            def __int__(self):
                raise _Watchdog("int bomb")

        # int.__index__ reads the C-level storage underneath the override,
        # so the caller's real value survives instead of 500ing the tail.
        self.assertEqual(logs_svc._clamp_lines(_IndexBombInt(50)), 50)

    def test_clamp_lines_defaults_on_a_non_int_base_bomb(self):
        class _IntBaseBomb:
            def __int__(self):
                raise _Watchdog("int bomb")

        self.assertEqual(logs_svc._clamp_lines(_IntBaseBomb()), 200)

    def test_clamp_lines_keeps_the_bool_and_none_defaults(self):
        self.assertEqual(logs_svc._clamp_lines(True), 200)
        self.assertEqual(logs_svc._clamp_lines(None), 200)
        self.assertEqual(logs_svc._clamp_lines(7), 10)
        self.assertEqual(logs_svc._clamp_lines(99999), 2000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
