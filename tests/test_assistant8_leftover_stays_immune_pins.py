"""Assistant sweep #8 pins: vectors probed for a new 500 that stayed immune.

Alongside the raising-``__class__`` 500 fixed in
test_assistant8_leftover_class_bomb_500s.py, this sweep probed the mounted
assistant routes with the rest of the leftover matrix and found the earlier
sanitizers already hold.  Pinned here so a refactor cannot quietly reopen
them:

* an ``isoformat`` callable that *returns* junk (a class bomb, ``inf``)
  drops the cell via the recursive ``_jsonable`` walk, never the body;
* a ``__bytes__`` / ``__getattr__`` property bomb object in the snapshot is
  nulled by the walk — nothing in the assistant ever calls ``bytes()``;
* a float-subclass whose ``__float__`` / ``__eq__`` raises (the rc-subclass
  shape) as ``disk_root_pct`` skips the disk threshold on *both* passes of
  the turn — ``_exact_number``'s base coercion, not the raw ``>=``;
* set / frozenset subclasses with ``__iter__`` bombs in a snapshot cell
  still walk their real elements through ``base.__iter__``;
* a dict-subclass mapping whose *keys* are str subclasses riding a
  self-``__str__`` encode bomb renders scrubbed keys, never a 500;
* a memoryview leftover in a snapshot cell is nulled like any other
  unrenderable shape;
* a >4300-digit number literal anywhere in the request body is the coded
  4xx at the HTTP layer (FastAPI turns the digit-cap ValueError — which is
  *not* JSONDecodeError — into its parse-error response), pinned here for
  the nested history placement the earlier body pins did not cover.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import assistant_svc
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ClassBomb:
    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _IsoReturnsBomb:
    def isoformat(self):
        return _ClassBomb()


class _IsoReturnsInf:
    def isoformat(self):
        return float("inf")


class _BytesPropertyBomb:
    @property
    def __bytes__(self):
        raise RuntimeError("bytes bomb")


class _FloatFloatBomb(float):
    def __float__(self):
        raise RuntimeError("float bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = float.__hash__


class _SetIterBomb(set):
    def __iter__(self):
        raise RuntimeError("set iter bomb")


class _FrozensetIterBomb(frozenset):
    def __iter__(self):
        raise RuntimeError("frozenset iter bomb")


class _StrSelfEncodeBomb(str):
    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _DictSub(dict):
    pass


def _status() -> dict:
    return {
        "system": {
            "load": "0.10 / 0.20 / 0.30",
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "disk_pct": 20,
            "disk_used_gb": 1,
            "disk_total_gb": 2,
            "uptime": "1.0 hours",
        },
        "engine_up": True,
        "counts": {"ok": 3, "warn": 0, "down": 0, "stopped": 0},
        "problems": [],
    }


class _QuietCollectors(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        for target, kwargs in (
            ("hub.status.peek_status", {"return_value": _status()}),
            ("hub.status.full_status", {"return_value": {}}),
            ("hub.ollama_svc.status", {"return_value": {"reachable": False}}),
            ("hub.ups_svc.ups_snapshot", {"return_value": {"present": False}}),
        ):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _brief_with_cell(self, cell):
        status = _status()
        status["system"]["load"] = cell
        with mock.patch("hub.status.peek_status", return_value=status):
            resp = self.client.post(
                "/api/assistant/ask",
                json={"query": "", "action": "brief", "locale": "en"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class JsonableLeftoverPins(_QuietCollectors):
    """Unrenderable snapshot cells drop alone; siblings keep answering."""

    def test_isoformat_returning_junk_drops_the_cell(self):
        for cell in (_IsoReturnsBomb(), _IsoReturnsInf()):
            body = self._brief_with_cell(cell)
            self.assertIsNone(body["snapshot"]["load"])
            self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_bytes_property_bomb_is_nulled_not_a_500(self):
        body = self._brief_with_cell(_BytesPropertyBomb())
        self.assertIsNone(body["snapshot"]["load"])
        self.assertEqual(body["snapshot"]["cpu_load_pct"], 1.0)

    def test_memoryview_leftover_is_nulled_not_a_500(self):
        body = self._brief_with_cell(memoryview(b"junk"))
        self.assertIsNone(body["snapshot"]["load"])

    def test_set_subclass_iter_bombs_walk_their_real_elements(self):
        for cell in (_SetIterBomb({"a"}), _FrozensetIterBomb({"a"})):
            body = self._brief_with_cell(cell)
            self.assertEqual(body["snapshot"]["load"], ["a"])

    def test_dict_subclass_with_encode_bomb_keys_renders_scrubbed(self):
        cell = _DictSub({_StrSelfEncodeBomb("k\ud800ey"): "v"})
        body = self._brief_with_cell(cell)
        self.assertEqual(list(body["snapshot"]["load"].values()), ["v"])
        for key in body["snapshot"]["load"]:
            key.encode("utf-8")


class DiskThresholdSubclassPins(_QuietCollectors):
    """rc-subclass ``__float__`` / ``__eq__`` bombs keep their real value."""

    def test_float_bombs_as_disk_pct_honor_the_real_threshold(self):
        # suggest_panels runs once in ask() and again inside the router's
        # error fallback with the same snapshot: a raise on either pass of
        # the raw >= threshold used to be the 500 shape earlier sweeps fixed.
        # The unbound float.__float__ coercion does not dispatch to the
        # subclass override, so the *real* 99% still suggests the disk page.
        for bomb in (_FloatFloatBomb(99.0), _FloatEqBomb(99.0)):
            body = self._brief_with_cell("x")
            snapshot = dict(body["snapshot"])
            snapshot["disk_root_pct"] = bomb
            panels = assistant_svc.suggest_panels(snapshot, "en")
            self.assertIn("main", [p.get("id") for p in panels])

    def test_exact_number_recovers_the_base_value(self):
        for bomb in (_FloatFloatBomb(9.0), _FloatEqBomb(9.0)):
            exact = assistant_svc._exact_number(bomb)
            self.assertIs(type(exact), float)
            self.assertEqual(exact, 9.0)


class HugeNumberBodyPins(_QuietCollectors):
    """The digit-cap ValueError out of ``json.loads`` is a coded 4xx."""

    def _post_raw(self, raw: str):
        return self.client.post(
            "/api/assistant/ask",
            content=raw.encode(),
            headers={"content-type": "application/json"},
        )

    def test_huge_int_nested_in_history_is_a_4xx(self):
        raw = ('{"query": "hi", "history": [{"role": "user", "content": '
               + "9" * 5000 + "}]}")
        resp = self._post_raw(raw)
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        _starlette(resp.json())

    def test_huge_negative_int_field_is_a_4xx(self):
        resp = self._post_raw('{"query": -' + "9" * 5000 + "}")
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        _starlette(resp.json())


if __name__ == "__main__":
    unittest.main()
