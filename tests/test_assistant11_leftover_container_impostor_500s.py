"""Assistant sweep #11: the poisoned PANELS *container*, str-claiming liars,
and mid-walk mutators.

Sweeps #3-#9 sealed every cell and row of the assistant's inputs, but a fresh
hunt over the mounted routes (GET /api/assistant/catalog,
POST /api/assistant/ask via ``create_app()`` + TestClient) found one
**remaining HTTP 500** one level up — the catalog *container* itself:

* ``suggest_panels`` walks ``PANELS`` bare, and it runs a second time
  *inside the router's own error fallback*, where nothing above catches a
  raise.  A leftover container whose ``__iter__`` raises, a lying
  ``__class__`` impostor that rejects the unbound tuple/list descriptor, or
  plain non-sequence junk (``None``, an int) re-raised right there — a raw
  500 on POST /api/assistant/ask for **every action at once** (brief, find,
  ask and page).  GET /api/assistant/catalog survived only because the
  route's own try wipes the payload; the ask fallback had no such net.

Fixed with ``_panel_rows()``: unbound base iteration keeps the real rows of
a subclass whose bound ``__iter__`` is the bomb, and junk shapes fail closed
to an empty catalog every caller's no-rows branch already handles.

Two non-500 leaks the same hunt surfaced are sealed alongside:

* a *lying* ``__class__`` claiming ``str`` passed every ``_isa(..., str)``
  gate and the dispatching ``str()`` rendered its ``repr`` — **a raw memory
  address** — into catalog paths, find hits, suggested rows and the model
  cell.  ``_str_text`` (unbound ``str.__str__``) keeps real str storage,
  drops the impostor, and the "" it coerces to could otherwise have made
  ``resolve_path``'s ``startswith(text + "/")`` probe claim every page turn.
* a *cross-liar* claiming ``bytes`` over **real str storage** was wiped to
  an empty cell by the unbound ``bytes.decode`` rejection even though the
  text sat right there — ``_decode_bytes`` now salvages it field-level.
* a nested cell whose property **mutates its own container mid-walk** used
  to RuntimeError the live ``dict.items`` / set iteration inside
  ``_jsonable`` — outside every catch — and degrade the whole turn to the
  minimal brief.  The materialized walk keeps every sibling cell.
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
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _liar(claim):
    """A leftover whose ``__class__`` *lies*: ``_isa(x, claim)`` is True but
    the real type is neither, so every unbound base descriptor rejects it."""

    class _Liar:
        @property
        def __class__(self):
            return claim

    return _Liar()


class _TupleIterBomb(tuple):
    """Real tuple storage under a bound ``__iter__`` bomb."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _StrClaimsBytes(str):
    """Cross-liar: real str storage whose ``__class__`` claims bytes."""

    @property
    def __class__(self):
        return bytes


class _StrStrBomb(str):
    """Real str storage whose dispatched ``__str__`` raises."""

    def __str__(self):
        raise RuntimeError("str bomb")


class _DictMutator:
    """isoformat property mutates the captured dict mid-walk, then raises."""

    def __init__(self):
        self.parent = None

    @property
    def isoformat(self):
        if self.parent is not None:
            dict.__setitem__(self.parent, "planted-mid-walk", 1)
        raise RuntimeError("iso mutate bomb")


class _SetMutator:
    """isoformat property mutates the captured set mid-walk, then raises."""

    def __init__(self):
        self.parent = None

    def __hash__(self):
        return 1

    @property
    def isoformat(self):
        if self.parent is not None:
            set.add(self.parent, ("planted", id(self)))
        raise RuntimeError("iso mutate bomb")


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


_SANE = {"id": "dashboard", "path": "/", "title": {"en": "Dashboard"}, "aliases": ["home"]}
_DOCKER = {"id": "docker", "path": "/docker", "title": {"en": "Docker"}, "aliases": ["docker"]}
_HEALTH = {"id": "health", "path": "/health", "title": {"en": "Health"}}

_ALL_ACTIONS = (
    {"query": "", "action": "brief"},
    {"query": "docker", "action": "find"},
    {"query": "what is up", "action": "ask"},
    {"query": "", "action": "page", "path": "/"},
)


class _QuietCollectors(unittest.TestCase):
    """Route tests with the status / ollama / ups collectors stubbed."""

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

    def _ask(self, **body):
        payload = {"query": "", "action": "brief", "locale": "en"}
        payload.update(body)
        return self.client.post("/api/assistant/ask", json=payload)

    def _ok(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class PanelsContainer500Tests(_QuietCollectors):
    """The found 500: a poisoned PANELS container re-raised inside the
    router's own error fallback on POST /api/assistant/ask."""

    def _every_action_answers(self, container):
        with mock.patch.object(assistant_svc, "PANELS", container):
            for body in _ALL_ACTIONS:
                self._ok(self._ask(**body))
            self._ok(self.client.get("/api/assistant/catalog?locale=en"))

    def test_tuple_subclass_iter_bomb_answers_every_action(self):
        self._every_action_answers(_TupleIterBomb((_SANE, _DOCKER)))

    def test_lying_tuple_impostor_answers_every_action(self):
        self._every_action_answers(_liar(tuple))

    def test_lying_list_impostor_answers_every_action(self):
        self._every_action_answers(_liar(list))

    def test_none_container_answers_every_action(self):
        self._every_action_answers(None)

    def test_int_container_answers_every_action(self):
        self._every_action_answers(7)

    def test_iter_bomb_keeps_the_real_rows(self):
        # Real tuple storage under the bomb: unbound iteration salvages the
        # catalog instead of failing closed.
        with mock.patch.object(assistant_svc, "PANELS", _TupleIterBomb((_SANE, _DOCKER))):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
            self.assertEqual(sorted(p["id"] for p in body["panels"]), ["dashboard", "docker"])
            find = self._ok(self._ask(query="docker", action="find"))
            self.assertIn("docker", [p.get("id") for p in find["panels"]])

    def test_junk_container_degrades_to_the_brief_not_a_500(self):
        with mock.patch.object(assistant_svc, "PANELS", _liar(tuple)):
            body = self._ok(self._ask())
        self.assertEqual(body["panels"], [])
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)


class StrLiarReprLeakTests(_QuietCollectors):
    """A lying ``__class__`` claiming str used to leak ``repr`` — a raw
    memory address — into the response; the impostor drops instead."""

    def test_catalog_drops_the_liar_path_row_never_its_repr(self):
        rows = ({"id": "evil", "path": _liar(str), "title": {"en": "Evil"}}, _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            resp = self.client.get("/api/assistant/catalog?locale=en")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("0x", resp.text)
        self.assertEqual([p["id"] for p in resp.json()["panels"]], ["docker"])

    def test_find_drops_the_liar_path_row_never_its_repr(self):
        rows = ({"id": "docker", "path": _liar(str), "title": {"en": "Docker"}}, _HEALTH)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            resp = self._ask(query="docker", action="find")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("0x", resp.text)

    def test_suggested_row_with_a_liar_path_drops_never_leaks(self):
        # On battery the fallback wants the dashboard row; its liar path
        # used to render "<... object at 0x...>" as the SPA target.
        rows = ({"id": "dashboard", "path": _liar(str), "title": {"en": "Dash"}}, _HEALTH)
        ups = {"present": True, "source": "battery", "percent": 50, "charging": False}
        with (
            mock.patch("hub.ups_svc.ups_snapshot", return_value=ups),
            mock.patch.object(assistant_svc, "PANELS", rows),
        ):
            resp = self._ask()
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("0x", resp.text)
        self.assertNotIn("dashboard", [p.get("id") for p in resp.json()["panels"]])

    def test_liar_path_cannot_claim_every_page_turn(self):
        # The liar coerces to "" now, and "".startswith(text + "/") would
        # have matched every path — the junk row must not own the turn.
        rows = ({"id": "evil", "path": _liar(str), "title": {"en": "Evil"}}, _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask(query="", action="page", path="/docker/tail"))
        here = body["snapshot"].get("here") or {}
        self.assertNotEqual(here.get("id"), "evil")
        self.assertEqual(here.get("id"), "docker")

    def test_chat_model_liar_falls_back_to_the_picked_model(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": "LLM SAYS HI", "model": _liar(str)},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertEqual(body["model"], "m")
        self.assertTrue(body["used_llm"])
        self.assertNotIn("0x", json.dumps(body))

    def test_snapshot_cell_liar_drops_to_none_never_its_repr(self):
        status = _status()
        status["system"]["uptime"] = _liar(str)
        with mock.patch("hub.status.peek_status", return_value=status):
            resp = self._ask()
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("0x", resp.text)
        self.assertIsNone(resp.json()["snapshot"]["uptime"])


class CrossLiarSalvageTests(_QuietCollectors):
    """Real str storage claiming bytes: the text was right there — salvage
    the cell instead of wiping it to empty."""

    def test_title_cell_keeps_its_real_text(self):
        rows = ({"id": "ollama", "path": "/ollama",
                 "title": {"en": _StrClaimsBytes("Real Title")}}, _HEALTH)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask())
        by_id = {p.get("id"): p for p in body["panels"]}
        self.assertEqual(by_id["ollama"]["title"], "Real Title")

    def test_snapshot_cell_keeps_its_real_text(self):
        status = _status()
        status["system"]["uptime"] = _StrClaimsBytes("9.9 hours")
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["uptime"], "9.9 hours")

    def test_ups_source_keeps_suggesting_the_dashboard(self):
        ups = {"present": True, "source": _StrClaimsBytes("battery"),
               "percent": 42, "charging": False}
        with (
            mock.patch("hub.ups_svc.ups_snapshot", return_value=ups),
            mock.patch.object(assistant_svc, "PANELS", (_SANE, _HEALTH)),
        ):
            body = self._ok(self._ask())
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])
        self.assertEqual(body["snapshot"]["ups"]["source"], "battery")


class MidWalkMutatorTests(_QuietCollectors):
    """A nested cell that mutates its own container mid-walk used to
    RuntimeError the live view iteration and wipe the turn to the brief."""

    def test_mutating_dict_cell_keeps_the_sibling_cells(self):
        bomb = _DictMutator()
        cell = {"a": 1, "trigger": bomb}
        bomb.parent = cell
        status = _status()
        status["system"]["load"] = cell
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["load"]["a"], 1)
        self.assertIsNone(body["snapshot"]["load"]["trigger"])
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")

    def test_mutating_set_cell_keeps_the_sibling_cells(self):
        bomb = _SetMutator()
        cell = {1, bomb}
        bomb.parent = cell
        status = _status()
        status["system"]["load"] = cell
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertIn(1, body["snapshot"]["load"])
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")


class ProbeFunctionTests(unittest.TestCase):
    """The sealed helpers, held at the function level."""

    def test_panel_rows_salvages_real_storage_fails_closed_on_junk(self):
        with mock.patch.object(assistant_svc, "PANELS", _TupleIterBomb((_SANE,))):
            self.assertEqual(assistant_svc._panel_rows(), [_SANE])
        for junk in (_liar(tuple), _liar(list), None, 7, "junk", {"id": "x"},
                     (r for r in ())):
            with mock.patch.object(assistant_svc, "PANELS", junk):
                self.assertEqual(assistant_svc._panel_rows(), [], junk)
        with mock.patch.object(assistant_svc, "PANELS", (_SANE, _DOCKER)):
            self.assertEqual(assistant_svc._panel_rows(), [_SANE, _DOCKER])
        with mock.patch.object(assistant_svc, "PANELS", [_SANE]):
            self.assertEqual(assistant_svc._panel_rows(), [_SANE])

    def test_str_text_keeps_real_storage_drops_the_impostor(self):
        self.assertEqual(assistant_svc._str_text("ok"), "ok")
        self.assertEqual(assistant_svc._str_text(_StrStrBomb("real")), "real")
        self.assertEqual(assistant_svc._str_text(_StrClaimsBytes("real")), "real")
        self.assertIsNone(assistant_svc._str_text(_liar(str)))
        self.assertIsNone(assistant_svc._str_text(42))
        # The scrub happens on the *encode* side, so the replacement is "?".
        out = assistant_svc._str_text("a\ud800b")
        _starlette(out)
        self.assertEqual(out, "a?b")

    def test_jsonable_drops_the_str_liar_keeps_real_subclasses(self):
        self.assertIsNone(assistant_svc._jsonable(_liar(str)))
        out = assistant_svc._jsonable(_StrStrBomb("kept"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "kept")

    def test_utf8_text_salvages_the_str_bomb_drops_the_liar(self):
        # Real storage under a raising ``__str__`` used to wipe to "".
        self.assertEqual(assistant_svc._utf8_text(_StrStrBomb("kept")), "kept")
        self.assertEqual(assistant_svc._utf8_text(_liar(str)), "")
        self.assertEqual(assistant_svc._utf8_text(_StrClaimsBytes("kept")), "kept")

    def test_decode_bytes_salvage_keeps_the_assistant9_pins(self):
        # Cross-liar salvage must not regress the impostor drop.
        self.assertEqual(assistant_svc._decode_bytes(_StrClaimsBytes("kept")), "kept")
        self.assertIsNone(assistant_svc._decode_bytes(_liar(bytes)))
        self.assertIsNone(assistant_svc._decode_bytes(_liar(bytearray)))
        self.assertEqual(assistant_svc._decode_bytes(b"ok"), "ok")

    def test_jsonable_materialized_walks_survive_mid_walk_mutation(self):
        bomb = _DictMutator()
        cell = {"a": 1, "trigger": bomb}
        bomb.parent = cell
        out = assistant_svc._jsonable(cell)
        self.assertEqual(out["a"], 1)
        _starlette(out)
        set_bomb = _SetMutator()
        s = {1, set_bomb}
        set_bomb.parent = s
        rows = assistant_svc._jsonable(s)
        self.assertIn(1, rows)
        _starlette(rows)

    def test_suggest_panels_and_fallback_brief_survive_a_poisoned_container(self):
        # Both run inside the router's error fallback: a raise is a 500.
        snapshot = {"counts": {"ok": 0, "warn": 0, "down": 1, "stopped": 0}}
        for junk in (_TupleIterBomb((_SANE,)), _liar(tuple), None, 7):
            with mock.patch.object(assistant_svc, "PANELS", junk):
                assistant_svc.suggest_panels(snapshot, "en")
                assistant_svc.fallback_brief(snapshot, "en")


if __name__ == "__main__":
    unittest.main()
