"""Assistant sweep #9: lying ``__class__`` impostors past the ``_isa`` gates.

Sweep #8 routed every isinstance gate through ``_isa`` so a *raising*
``__class__`` property can no longer 500 a gate — but ``_isa`` reports a
*lying* ``__class__`` at face value.  A fresh hunt over the mounted assistant
routes (GET /api/assistant/catalog, POST /api/assistant/ask) found two
**remaining HTTP 500s** the earlier sweeps missed, the same class modules9 /
bookmarks9 just sealed:

* a value whose ``__class__`` answers ``bool`` is admitted by
  ``_isa(..., bool)`` and, since ``bool`` is final, is an impostor;
  ``_jsonable`` returned it raw, handing the response encoder a
  non-serializable object.  A leftover ``engine_up`` / ``uptime`` /
  problem-``state`` / ups-``percent`` cell 500'd POST /api/assistant/ask on
  every action at once — the final ``_jsonable(payload)`` in the router runs
  outside every try.
* a value whose ``__class__`` answers ``bytes``/``bytearray`` without a
  C-level buffer reaches ``_utf8_text``'s bytes branch, where the unbound
  ``bytes.decode(value)`` raised TypeError.  As a catalog title cell on a row
  ``suggest_panels`` selects (ollama down, a down count, on-battery), the
  raise repeated *inside the router's own error fallback* — a raw 500.

The same lie on ``dict`` / ``list`` rejected the unbound ``dict.items`` /
``list.__iter__`` descriptors and was a wipe, not a 500: one impostor aliases
cell wiped the whole Cmd+K catalog to ``[]``, an impostor problems / resident
cell dropped its snapshot section, and an impostor peek result skipped the
``full_status()`` retry the sane path still had.

Fixed by running each unbound base call in a try (a raise means "not really
this type", so the impostor drops to ``None``/``""``/``[]`` like the lying
numeric coercions already do) and rendering the bool arm only for
``type(value) is bool``.  ``_isa`` / ``_dget`` and the assistant3-8 pins are
unchanged.
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


class _StrEqBombKey(str):
    """Stored-key bomb: shares the sane key's hash, raises on the compare."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = str.__hash__


class _StrEqBomb(str):
    """A str-subclass cell whose ``__eq__`` raises on any comparison."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = str.__hash__


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


class BoolLiarEncoder500Tests(_QuietCollectors):
    """The found 500: a bool-lying impostor rode ``_jsonable`` to the encoder."""

    def _brief_with_status(self, status):
        with mock.patch("hub.status.peek_status", return_value=status):
            return self._ok(self._ask())

    def test_engine_up_liar_drops_the_cell_not_the_response(self):
        status = _status()
        status["engine_up"] = _liar(bool)
        body = self._brief_with_status(status)
        self.assertIsNone(body["snapshot"]["engine_up"])
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_uptime_liar_keeps_the_sibling_cells(self):
        status = _status()
        status["system"]["uptime"] = _liar(bool)
        body = self._brief_with_status(status)
        self.assertIsNone(body["snapshot"]["uptime"])
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_problem_state_liar_keeps_the_problem_row(self):
        status = _status()
        status["problems"] = [{"name": "web", "state": _liar(bool), "detail": "d"}]
        body = self._brief_with_status(status)
        rows = body["snapshot"]["problems"]
        self.assertEqual([p["name"] for p in rows], ["web"])
        self.assertIsNone(rows[0]["state"])

    def test_ups_percent_liar_keeps_the_ups_section(self):
        ups = {"present": True, "source": "battery", "percent": _liar(bool), "charging": False}
        with mock.patch("hub.ups_svc.ups_snapshot", return_value=ups):
            body = self._ok(self._ask())
        self.assertIsNone(body["snapshot"]["ups"]["percent"])
        self.assertIs(body["snapshot"]["ups"]["charging"], False)

    def test_real_bools_still_render(self):
        body = self._ok(self._ask())
        self.assertIs(body["snapshot"]["engine_up"], True)

    def test_every_action_answers_with_a_liar_in_the_snapshot(self):
        status = _status()
        status["engine_up"] = _liar(bool)
        with mock.patch("hub.status.peek_status", return_value=status):
            for body in (
                {"query": "dashboard", "action": "find"},
                {"query": "", "action": "brief"},
                {"query": "what is up", "action": "ask"},
                {"query": "", "action": "page", "path": "/"},
            ):
                self._ok(self._ask(**body))


class WantedRowBytesLiarTitle500Tests(_QuietCollectors):
    """The found 500: a bytes-lying title cell blew the unbound decode inside
    ``suggest_panels`` — which the router's error fallback runs again."""

    def test_liar_title_on_the_ollama_row_falls_back_to_its_id(self):
        # The stubbed ollama collector is unreachable, so the fallback always
        # selects the "ollama" row; its poisoned title raised on both passes.
        rows = ({"id": "ollama", "path": "/ollama", "title": {"en": _liar(bytes)}}, _HEALTH)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask())
        by_id = {p.get("id"): p for p in body["panels"]}
        self.assertEqual(by_id["ollama"]["title"], "ollama")

    def test_liar_title_on_a_down_count_row_keeps_the_siblings(self):
        status = _status()
        status["counts"] = {"ok": 0, "warn": 0, "down": 2, "stopped": 0}
        rows = ({"id": "services", "path": "/services", "title": {"en": _liar(bytes)}}, _HEALTH)
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch.object(assistant_svc, "PANELS", rows),
        ):
            body = self._ok(self._ask())
        by_id = {p.get("id"): p for p in body["panels"]}
        self.assertEqual(by_id["services"]["title"], "services")
        self.assertIn("health", by_id)

    def test_liar_title_page_turn_on_battery_answers_not_a_500(self):
        # On battery the fallback wants the dashboard row; the page turn also
        # resolves "/" through the same poisoned title — both raised.
        rows = ({"id": "dashboard", "path": "/", "title": {"en": _liar(bytes)}},)
        ups = {"present": True, "source": "battery", "percent": 50, "charging": False}
        with (
            mock.patch("hub.ups_svc.ups_snapshot", return_value=ups),
            mock.patch.object(assistant_svc, "PANELS", rows),
        ):
            body = self._ok(self._ask(query="", action="page", path="/"))
        self.assertEqual(body["snapshot"].get("here", {}).get("id"), "dashboard")
        self.assertEqual(body["snapshot"]["here"]["title"], "dashboard")

    def test_liar_title_answers_every_action_not_a_500(self):
        rows = ({"id": "ollama", "path": "/ollama", "title": {"en": _liar(bytes)}}, _SANE)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            for body in (
                {"query": "dashboard", "action": "find"},
                {"query": "", "action": "brief"},
                {"query": "what is up", "action": "ask"},
                {"query": "", "action": "page", "path": "/"},
            ):
                self._ok(self._ask(**body))


class LiarWipeSealTests(_QuietCollectors):
    """dict/list/bytes lies degrade the cell or the row, never the section."""

    def test_liar_aliases_keep_the_whole_catalog(self):
        # The impostor rejected the unbound list.__iter__ and the route's
        # blanket except wiped every row to [].
        rows = ({"id": "x", "path": "/x", "title": {"en": "X"}, "aliases": _liar(list)}, _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        by_id = {p.get("id"): p for p in body["panels"]}
        self.assertEqual(sorted(by_id), ["docker", "x"])
        self.assertEqual(by_id["x"]["aliases"], [])

    def test_liar_aliases_keep_the_find_turn(self):
        rows = ({"id": "docker", "path": "/docker", "title": {"en": "Docker"},
                 "aliases": _liar(list)},)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask(query="docker", action="find"))
        self.assertIn("docker", [p.get("id") for p in body["panels"]])

    def test_liar_peek_result_retries_full_status(self):
        # dict.__len__ rejected the impostor into the blanket except, which
        # skipped the full_status() retry the sane path still had.
        with (
            mock.patch("hub.status.peek_status", return_value=_liar(dict)),
            mock.patch("hub.status.full_status", return_value=_status()),
        ):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_liar_problems_keep_the_system_cells(self):
        status = _status()
        status["problems"] = _liar(list)
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["problems"], [])
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_liar_resident_keeps_the_ollama_section(self):
        snap = {"reachable": True, "resident": _liar(list)}
        with mock.patch("hub.ollama_svc.status", return_value=snap):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["ollama"]["resident"], [])
        self.assertIs(body["snapshot"]["ollama"]["reachable"], True)

    def test_liar_counts_drop_to_zero_keep_the_siblings(self):
        status = _status()
        status["counts"] = _liar(dict)
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["counts"]["ok"], 0)
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_liar_chat_content_falls_to_the_brief_not_a_wipe(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": _liar(bytes), "model": "m"},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertFalse(body["used_llm"])
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_liar_blurb_page_turn_keeps_the_here_context(self):
        with (
            mock.patch.object(assistant_svc, "PANELS", (_SANE,)),
            mock.patch.object(assistant_svc, "_BLURBS", {"dashboard": {"en": _liar(bytes)}}),
        ):
            body = self._ok(self._ask(query="", action="page", path="/"))
        self.assertEqual(body["snapshot"].get("here", {}).get("id"), "dashboard")
        self.assertEqual(body["snapshot"]["here"]["blurb"], "")

    def test_liar_system_cell_drops_the_cell_keeps_the_siblings(self):
        status = _status()
        status["system"]["load"] = _liar(bytes)
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertIsNone(body["snapshot"]["load"])
        self.assertEqual(body["snapshot"]["cpu_load_pct"], 1.0)

    def test_liar_bytes_stored_key_drops_the_entry_keeps_the_siblings(self):
        status = _status()
        status["system"][_liar(bytes)] = "junk"
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")


class HashShadowAndEqBombPins(_QuietCollectors):
    """Stays-immune: hash-shadowing stored keys and ``__eq__`` bombs."""

    def test_counts_under_a_poisoned_key_are_recovered(self):
        # The bomb key shares "counts"'s hash, so even dict.get hits the
        # poisoned compare; _dget's items-walk recovers the section.
        status = _status()
        status[_StrEqBombKey("counts")] = status.pop("counts")
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_problems_under_a_poisoned_key_are_recovered(self):
        status = _status()
        del status["problems"]
        status[_StrEqBombKey("problems")] = [{"name": "web", "state": "down", "detail": "d"}]
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual([p["name"] for p in body["snapshot"]["problems"]], ["web"])

    def test_eq_bomb_ups_source_still_suggests_the_dashboard(self):
        # The membership probe coerces to exact str first, so the subclass
        # ``__eq__`` never dispatches — on-battery still wants the dashboard.
        ups = {"present": True, "source": _StrEqBomb("battery"),
               "percent": 42, "charging": False}
        with (
            mock.patch("hub.ups_svc.ups_snapshot", return_value=ups),
            mock.patch.object(assistant_svc, "PANELS", (_SANE, _HEALTH)),
        ):
            body = self._ok(self._ask())
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])
        self.assertEqual(body["snapshot"]["ups"]["source"], "battery")

    def test_eq_bomb_chat_content_keeps_the_answer(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": _StrEqBomb("LLM SAYS HI"), "model": "m"},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertIn("LLM SAYS HI", body["text"])
        self.assertTrue(body["used_llm"])


class ProbeFunctionTests(unittest.TestCase):
    """The sealed helpers, held at the function level."""

    def test_decode_bytes_rejects_the_impostor_keeps_real_bytes(self):
        self.assertIsNone(assistant_svc._decode_bytes(_liar(bytes)))
        self.assertIsNone(assistant_svc._decode_bytes(_liar(bytearray)))
        self.assertEqual(assistant_svc._decode_bytes(b"ok"), "ok")
        self.assertEqual(assistant_svc._decode_bytes(bytearray(b"ok")), "ok")

    def test_utf8_text_drops_the_impostor_to_empty(self):
        self.assertEqual(assistant_svc._utf8_text(_liar(bytes)), "")
        self.assertEqual(assistant_svc._utf8_text(_liar(bytearray)), "")
        self.assertEqual(assistant_svc._utf8_text(b"ok"), "ok")

    def test_jsonable_renders_only_real_bools(self):
        self.assertIs(assistant_svc._jsonable(True), True)
        self.assertIs(assistant_svc._jsonable(False), False)
        self.assertIsNone(assistant_svc._jsonable(_liar(bool)))

    def test_jsonable_drops_every_container_impostor(self):
        for claim in (dict, list, tuple, set, frozenset, bytes, bytearray, int, float):
            self.assertIsNone(assistant_svc._jsonable(_liar(claim)), claim)

    def test_jsonable_nested_impostors_drop_only_their_cell(self):
        out = assistant_svc._jsonable({"a": _liar(bool), "b": 1, _liar(bytes): "junk"})
        self.assertEqual(out, {"a": None, "b": 1})
        _starlette(out)

    def test_jsonable_keeps_real_containers(self):
        self.assertEqual(assistant_svc._jsonable({"k": [1, "x"]}), {"k": [1, "x"]})
        self.assertEqual(assistant_svc._jsonable((1, 2)), [1, 2])

    def test_list_rows_answers_real_elements_or_empty(self):
        self.assertEqual(assistant_svc._list_rows([1, 2]), [1, 2])
        self.assertEqual(assistant_svc._list_rows(_liar(list)), [])
        self.assertEqual(assistant_svc._list_rows(None), [])
        self.assertEqual(assistant_svc._list_rows("nope"), [])

        class _IterBomb(list):
            def __iter__(self):
                raise RuntimeError("iter bomb")

        self.assertEqual(assistant_svc._list_rows(_IterBomb([1, 2])), [1, 2])

    def test_dict_len_answers_zero_for_the_impostor(self):
        self.assertEqual(assistant_svc._dict_len({}), 0)
        self.assertEqual(assistant_svc._dict_len({"a": 1}), 1)
        self.assertEqual(assistant_svc._dict_len(_liar(dict)), 0)

    def test_suggest_panels_and_fallback_brief_survive_liar_snapshots(self):
        # Both run inside the router's error fallback: a raise is a 500.
        for snapshot in (
            {"counts": _liar(dict), "problems": _liar(list)},
            {"counts": {"down": _liar(bool)}, "ups": _liar(dict),
             "ollama": _liar(dict), "disk_root_pct": _liar(float),
             "engine_up": _liar(bool), "load": _liar(bytes)},
        ):
            assistant_svc.fallback_brief(snapshot, "en")
            assistant_svc.suggest_panels(snapshot, "en")


if __name__ == "__main__":
    unittest.main()
