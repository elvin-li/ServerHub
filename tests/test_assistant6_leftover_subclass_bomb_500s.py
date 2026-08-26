"""Assistant sweep #6: subclass bombs that rode the router's own error fallback.

A fresh hunt over the mounted assistant routes (GET /api/assistant/catalog,
POST /api/assistant/ask) with a poisoned collector / catalog matrix found
eight genuine leftovers, all raw 500s with traceback:

* an int-subclass ``__bool__`` bomb as ``engine_up`` blew the truthiness in
  ``fallback_brief`` — the value survived ``_jsonable`` untouched (the walk
  returned subclass ints as-is), raised out of ``ask()``, and then raised
  again inside the router's error fallback, which nothing above catches;
* the same double-raise with an int-subclass ``__bool__`` bomb as the load
  cell (``_brief_cell``'s bare ``not value``);
* a float-subclass ``__ge__`` bomb as ``disk_root_pct`` blew the >= 85 disk
  threshold in ``suggest_panels`` on both passes of the turn;
* a dict-subclass ``get`` bomb as a whole catalog row blew ``suggest_panels``'
  by-id map on both passes;
* a dict-subclass ``get`` bomb as a suggested row's title map blew ``_title``
  the same way;
* a str-subclass ``__hash__`` bomb as a suggested row's path blew the dedupe
  set membership in ``suggest_panels`` (the unhashable-set-membership rule);
* an int-subclass id whose ``__str__`` raises anything but the digit-cap
  ValueError escaped ``_panel_id``'s narrow catch and 500'd ask/find;
* a str-subclass path whose ``__str__`` answers *self* skipped CPython's
  exact-str copy inside ``_utf8_text`` and carried its bound ``encode`` bomb
  through the catalog route's try into the final ``_jsonable`` — a raw 500 on
  GET /api/assistant/catalog.

Fixed to the modules5 unbound-base standard: ``_jsonable`` coerces subclass
ints/floats to exact values (``int.__index__`` / ``float.__float__``), walks
dicts via ``dict.items`` and sequences via the base ``__iter__``, decodes
bytes via the unbound base ``decode`` and encodes via the unbound
``str.encode``; ``_dget`` reads mappings underneath a poisoned ``get``
override; ``_truthy`` keeps truthiness bombs falsy; ``_exact_number`` keeps
comparison bombs out of thresholds.  Junk drops a cell or a row — never the
turn, never a 500 — and sane data on a poisoned wrapper survives.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import assistant_svc
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 4400

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _IntBoolBomb(int):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _IntIntBomb(int):
    def __int__(self):
        raise RuntimeError("int bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("str bomb")


class _FloatGeBomb(float):
    def __ge__(self, other):
        raise RuntimeError("ge bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = float.__hash__


class _DictGetBomb(dict):
    def get(self, *args):
        raise RuntimeError("get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _DictBoolBomb(dict):
    def __bool__(self):
        raise RuntimeError("dict bool bomb")


class _BytesDecodeBomb(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _StrSelfEncodeBomb(str):
    """``__str__`` answers self, so CPython never copies to an exact str."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _StrHashBomb(str):
    def __hash__(self):
        raise RuntimeError("hash bomb")


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
        "counts": {"ok": 1, "warn": 0, "down": 0, "stopped": 0},
        "problems": [],
    }


class _QuietCollectors(unittest.TestCase):
    """Route tests with the status / ollama / ups collectors stubbed."""

    def setUp(self):
        self.client = _client()
        for target, kwargs in (
            ("hub.status.peek_status", {"return_value": _status()}),
            ("hub.status.full_status", {}),
            ("hub.ollama_svc.status", {"return_value": {"reachable": False}}),
            ("hub.ups_svc.ups_snapshot", {"return_value": {"present": False}}),
        ):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _brief_with_status(self, status: dict):
        with mock.patch("hub.status.peek_status", return_value=status):
            return self.client.post(
                "/api/assistant/ask",
                json={"query": "", "action": "brief", "locale": "en"},
            )


class SnapshotSubclassBombRouteTests(_QuietCollectors):
    """Fixed leftovers #1-#3: numeric-subclass bombs riding the snapshot."""

    def test_engine_up_bool_bomb_answers_the_brief_not_a_500(self):
        # Used to raise out of fallback_brief's truthiness — inside the
        # router's own error fallback too, which nothing above catches.
        status = _status()
        status["engine_up"] = _IntBoolBomb(1)
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        # _jsonable base-coerces the subclass to an exact 1, so the brief
        # still reads the real engine state instead of dropping it.
        self.assertIn("Docker on", body["text"])

    def test_load_cell_bool_bomb_renders_its_value_not_a_500(self):
        status = _status()
        status["system"]["load"] = _IntBoolBomb(3)
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("load 3", body["text"])

    def test_disk_threshold_ge_bomb_answers_both_kinds_not_a_500(self):
        # Used to raise out of suggest_panels' >= 85 threshold on both
        # passes of the turn.
        status = _status()
        status["system"]["disk_pct"] = _FloatGeBomb(90.0)
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The base coercion keeps the real number: the threshold still fires.
        self.assertIn("main", [p.get("id") for p in body["panels"]])
        with mock.patch("hub.status.peek_status", return_value=status):
            resp = self.client.post(
                "/api/assistant/ask",
                json={"query": "what is going on", "action": "auto", "locale": "en"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_counts_int_bomb_keeps_the_count(self):
        # int() of a subclass whose __int__ raises RuntimeError escaped
        # _safe_int's narrow catch and wiped the snapshot to the minimal
        # brief; the base __index__ coercion keeps the real count.
        status = _status()
        status["counts"]["down"] = _IntIntBomb(2)
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("2 down", body["text"])
        self.assertEqual(body["snapshot"]["counts"]["down"], 2)


class PanelsSubclassBombRouteTests(_QuietCollectors):
    """Fixed leftovers #4-#8: subclass bombs riding the panel catalog."""

    def _with_panels(self, panels):
        return mock.patch.object(assistant_svc, "PANELS", tuple(panels))

    def test_catalog_str_subclass_path_encode_bomb_is_a_200(self):
        # The raw path rode the route's try into the final _jsonable, where
        # the bound encode bomb 500'd GET /api/assistant/catalog.
        row = {
            "id": "docker",
            "path": _StrSelfEncodeBomb("/docker"),
            "title": {"en": "Docker"},
            "aliases": ["docker"],
        }
        with self._with_panels([row]):
            resp = self.client.get("/api/assistant/catalog?locale=en")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["panels"][0]["path"], "/docker")

    def test_find_int_subclass_id_str_bomb_keeps_the_row(self):
        # _panel_id's bare str() caught only the digit-cap ValueError; a
        # RuntimeError __str__ bomb 500'd ask/find via suggest_panels'
        # by-id map on the fallback pass.  int.__index__ keeps the row.
        row = {
            "id": _IntStrBomb(42),
            "path": "/docker",
            "title": {"en": "Docker"},
            "aliases": ["docker"],
        }
        with self._with_panels([row]):
            resp = self.client.post(
                "/api/assistant/ask",
                json={"query": "docker", "action": "find", "locale": "en"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["panels"][0]["id"], "42")

    def test_suggested_row_get_bomb_keeps_the_turn_and_the_row(self):
        # The ollama row is always wanted while the daemon is unreachable,
        # so the poisoned row's ``get`` bomb fired on both passes.
        row = _DictGetBomb({"id": "ollama", "path": "/ollama", "title": {"en": "O"}})
        with self._with_panels([row]):
            resp = self._brief_with_status(_status())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # _dget reads the real storage underneath the override: the sane
        # data on the poisoned wrapper still answers.
        self.assertIn("/ollama", [p.get("path") for p in body["panels"]])

    def test_suggested_title_get_bomb_keeps_the_turn_and_the_title(self):
        row = {
            "id": "ollama",
            "path": "/ollama",
            "title": _DictGetBomb({"en": "O"}),
        }
        with self._with_panels([row]):
            resp = self._brief_with_status(_status())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        titles = {p.get("path"): p.get("title") for p in body["panels"]}
        self.assertEqual(titles.get("/ollama"), "O")

    def test_suggested_path_hash_bomb_keeps_the_turn(self):
        # ``path in seen`` hashes the candidate: the unhashable-set-
        # membership rule, subclass edition.
        row = {
            "id": "ollama",
            "path": _StrHashBomb("/ollama"),
            "title": {"en": "O"},
        }
        with self._with_panels([row]):
            resp = self._brief_with_status(_status())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("/ollama", [p.get("path") for p in body["panels"]])


class SnapshotWipeRegressionTests(_QuietCollectors):
    """Subclass bombs that used to wipe the whole snapshot now keep the data."""

    def test_status_get_bomb_keeps_the_system_cells(self):
        resp = self._brief_with_status(_DictGetBomb(_status()))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("load 0.10 / 0.20 / 0.30", body["text"])
        self.assertIn("1 ok", body["text"])

    def test_status_bool_bomb_keeps_the_system_cells(self):
        # ``peek_status() or full_status()`` used to blow on the subclass
        # truthiness and fall to the empty snapshot.
        resp = self._brief_with_status(_DictBoolBomb(_status()))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("load 0.10 / 0.20 / 0.30", body["text"])

    def test_nested_items_bomb_drops_the_cell_not_the_snapshot(self):
        status = _status()
        status["system"]["load"] = _DictItemsBomb({"a": 1})
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The poisoned cell survives as a plain dict via dict.items; every
        # sibling cell keeps its value.
        self.assertIn("memory used 10%", body["text"])
        self.assertEqual(body["snapshot"]["load"], {"a": 1})

    def test_huge_already_int_count_drops_to_zero_not_a_500(self):
        status = _status()
        status["counts"]["ok"] = _HUGE_INT
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("0 ok", body["text"])
        self.assertIn("memory used 10%", body["text"])


class JsonableUnboundWalkTests(unittest.TestCase):
    """The sanitizer walk itself, held at the function level."""

    def test_int_subclass_coerces_to_the_exact_base_value(self):
        out = assistant_svc._jsonable(_IntBoolBomb(3))
        self.assertIs(type(out), int)
        self.assertEqual(out, 3)
        _starlette(out)

    def test_huge_int_subclass_drops_like_its_inf_sibling(self):
        class HugeBomb(int):
            pass

        self.assertIsNone(assistant_svc._jsonable(HugeBomb(_HUGE_INT)))
        self.assertIsNone(assistant_svc._jsonable(_HUGE_INT))

    def test_float_subclass_coerces_to_the_exact_base_value(self):
        for bomb in (_FloatGeBomb(90.0), _FloatEqBomb(3.5)):
            out = assistant_svc._jsonable(bomb)
            self.assertIs(type(out), float)
            _starlette(out)

    def test_dict_items_bomb_walks_the_real_pairs(self):
        out = assistant_svc._jsonable({"row": _DictItemsBomb({"a": 1})})
        self.assertEqual(out, {"row": {"a": 1}})
        _starlette(out)

    def test_list_iter_bomb_walks_the_real_elements(self):
        out = assistant_svc._jsonable(_ListIterBomb([1, "two"]))
        self.assertEqual(out, [1, "two"])
        _starlette(out)

    def test_bytes_decode_bomb_decodes_via_the_base(self):
        out = assistant_svc._jsonable(_BytesDecodeBomb(b"battery"))
        self.assertEqual(out, "battery")
        _starlette(out)

    def test_isoformat_property_bomb_drops_the_value(self):
        class IsoPropBomb:
            @property
            def isoformat(self):
                raise RuntimeError("iso prop bomb")

        self.assertIsNone(assistant_svc._jsonable(IsoPropBomb()))

    def test_str_subclass_self_encode_bomb_renders_its_text(self):
        out = assistant_svc._jsonable(_StrSelfEncodeBomb("/docker"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "/docker")
        _starlette(out)

    def test_surrogates_in_keys_and_values_stay_renderable(self):
        out = assistant_svc._jsonable({"k\ud800ey": "va\udffflue"})
        _starlette(out)
        self.assertEqual(len(out), 1)


class HelperProbeTests(unittest.TestCase):
    """The new coercion probes, held at the function level."""

    def test_safe_int_base_coerces_subclass_bombs(self):
        self.assertEqual(assistant_svc._safe_int(_IntIntBomb(5)), 5)
        self.assertEqual(assistant_svc._safe_int(_FloatEqBomb(3.5)), 3)
        self.assertEqual(assistant_svc._safe_int(_IntBoolBomb(7)), 7)

    def test_safe_int_keeps_its_old_semantics(self):
        self.assertEqual(assistant_svc._safe_int("7"), 7)
        self.assertEqual(assistant_svc._safe_int(True), 0)
        self.assertEqual(assistant_svc._safe_int(None, 9), 9)
        self.assertEqual(assistant_svc._safe_int(float("inf")), 0)
        self.assertEqual(assistant_svc._safe_int(_HUGE_INT), 0)

    def test_panel_id_keeps_a_renderable_subclass_id(self):
        self.assertEqual(assistant_svc._panel_id(_IntStrBomb(42)), "42")

    def test_panel_id_keeps_its_old_semantics(self):
        self.assertEqual(assistant_svc._panel_id(" x "), "x")
        self.assertEqual(assistant_svc._panel_id(7), "7")
        self.assertEqual(assistant_svc._panel_id(True), "")
        self.assertEqual(assistant_svc._panel_id(None), "")
        self.assertEqual(assistant_svc._panel_id(_HUGE_INT), "")

    def test_exact_number_neutralizes_comparison_bombs(self):
        out = assistant_svc._exact_number(_FloatGeBomb(90.0))
        self.assertIs(type(out), float)
        self.assertGreaterEqual(out, 85)
        self.assertIsNone(assistant_svc._exact_number(float("inf")))
        self.assertIsNone(assistant_svc._exact_number(True))
        self.assertIsNone(assistant_svc._exact_number("90"))

    def test_truthy_never_raises(self):
        self.assertFalse(assistant_svc._truthy(_IntBoolBomb(1)))
        self.assertFalse(assistant_svc._truthy(_DictBoolBomb({"a": 1})))
        self.assertTrue(assistant_svc._truthy(1))
        self.assertFalse(assistant_svc._truthy({}))

    def test_dget_reads_underneath_a_poisoned_get(self):
        self.assertEqual(assistant_svc._dget(_DictGetBomb({"a": 1}), "a"), 1)
        self.assertIsNone(assistant_svc._dget(["not", "a", "dict"], "a"))
        self.assertIsNone(assistant_svc._dget({"a": 1}, "b"))

    def test_fallback_brief_never_raises_on_raw_bombs(self):
        text = assistant_svc.fallback_brief({
            "engine_up": _IntBoolBomb(1),
            "load": _IntBoolBomb(3),
            "counts": _DictGetBomb({"ok": 1, "warn": 0, "down": 0, "stopped": 0}),
            "problems": _ListIterBomb([]),
        })
        _starlette(text)
        self.assertIn("1 ok", text)

    def test_suggest_panels_never_raises_on_raw_bombs(self):
        out = assistant_svc.suggest_panels({
            "counts": _DictGetBomb({"ok": 1, "warn": 0, "down": 0, "stopped": 0}),
            "disk_root_pct": _FloatGeBomb(90.0),
            "ollama": _DictGetBomb({"reachable": True}),
        }, "en")
        _starlette(out)
        # The coerced threshold still fires on the real number.
        self.assertIn("main", [row["id"] for row in out])


if __name__ == "__main__":
    unittest.main()
