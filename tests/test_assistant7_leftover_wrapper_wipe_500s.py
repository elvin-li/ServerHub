"""Assistant sweep #7: poisoned-wrapper wipes past the sealed 500 surface.

A fresh bomb-matrix hunt over the mounted assistant routes (GET
/api/assistant/catalog, POST /api/assistant/ask) — every subclass bomb class
from the earlier sweeps, at every collector / catalog / chat placement,
nested and combined — found **no remaining HTTP 500**: the assistant6
sanitizers hold end to end, including inside the router's own error
fallback.  What the hunt did find is six wipe-class leftovers where a
dict-subclass ``get`` / ``__bool__`` bomb reached a *bound* read the earlier
sweeps missed, and sane data underneath the poisoned wrapper was lost:

* the chat result: ``result.get("content")`` and the bare ``or`` truthiness
  ran *outside* _run_llm's try, so a ``get`` bomb on the result wrapper (or
  a ``__bool__`` bomb riding the reply text) dropped the whole turn to the
  router's rebuilt fallback — losing the model's answer the call already
  had, and rebuilding the snapshot a second time;
* one poisoned catalog row: ``_system_prompt``'s bound ``p.get("path")``
  raised into _run_llm's blanket except, wiping the model's answer for
  *every* turn;
* the ollama status wrapper (and one resident row): ``build_snapshot``'s
  bound reads fell into the blanket except and dropped the whole
  ``snapshot.ollama`` block; ``_pick_model``'s did the same and skipped the
  model the sane data still named, so every turn fell to the template brief
  while the daemon was up;
* the ups status wrapper: same drop for ``snapshot.ups``, losing a real
  on-battery state from the brief.

Fixed with the module's own probes (``_dget`` reads the real storage
underneath a poisoned ``get``; ``_truthy`` keeps truthiness bombs falsy;
``list.__iter__`` walks subclass rows; the new ``_reply_text`` coerces the
reply to exact text *before* any truthiness so a ``__bool__`` bomb keeps
its real words).  Junk drops a cell or a row — never the turn, never the
section — and the no-500 surface is re-pinned here for the new paths,
nested/combined bombs, cyclic and over-deep snapshot values included.
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


class _DictGetBomb(dict):
    def get(self, *args):
        raise RuntimeError("get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _StrBoolBomb(str):
    def __bool__(self):
        raise RuntimeError("str bool bomb")


class _IntBoolBomb(int):
    def __bool__(self):
        raise RuntimeError("int bool bomb")


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

    def _ask(self, **body):
        payload = {"query": "what is up", "action": "ask", "locale": "en"}
        payload.update(body)
        return self.client.post("/api/assistant/ask", json=payload)

    def _with_llm(self, chat_result):
        """Reachable daemon + a stubbed chat result for the LLM turn."""
        return (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch("hub.ollama_svc.chat", return_value=chat_result),
        )


class ChatResultWrapperTests(_QuietCollectors):
    """The chat-result reads past _run_llm's try keep the answer they had."""

    def test_get_bomb_on_the_chat_result_keeps_the_answer(self):
        # The bound result.get("content") ran outside _run_llm's try: the
        # raise dropped the turn to the router's rebuilt fallback and the
        # model's answer was lost.
        st, ch = self._with_llm(_DictGetBomb({"content": "LLM SAYS HI", "model": "m"}))
        with st, ch:
            resp = self._ask()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("LLM SAYS HI", body["text"])
        self.assertTrue(body["used_llm"])

    def test_bool_bomb_on_the_reply_text_keeps_its_words(self):
        # ``result.get("content") or ""`` ran the subclass __bool__: the
        # coerce-first _reply_text keeps the real text instead.
        st, ch = self._with_llm({"content": _StrBoolBomb("LLM SAYS HI"), "model": "m"})
        with st, ch:
            resp = self._ask()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("LLM SAYS HI", body["text"])
        self.assertTrue(body["used_llm"])

    def test_bool_bomb_on_the_model_name_keeps_the_turn(self):
        st, ch = self._with_llm({"content": "LLM SAYS HI", "model": _IntBoolBomb(3)})
        with st, ch:
            resp = self._ask()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("LLM SAYS HI", body["text"])
        # The unusable name falls back to the picked model, never a raise.
        self.assertEqual(body["model"], "m")

    def test_poisoned_catalog_row_keeps_the_llm_turn(self):
        # _system_prompt's bound p.get("path") raised into _run_llm's
        # blanket except: one poisoned row wiped the answer for every turn.
        row = _DictGetBomb({
            "id": "docker", "path": "/docker",
            "title": {"en": "Docker"}, "aliases": ["docker"],
        })
        st, ch = self._with_llm({"content": "LLM SAYS HI", "model": "m"})
        with st, ch, mock.patch.object(assistant_svc, "PANELS", (row,)):
            resp = self._ask()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("LLM SAYS HI", body["text"])
        self.assertTrue(body["used_llm"])


class CollectorWrapperTests(_QuietCollectors):
    """build_snapshot / _pick_model read underneath a poisoned wrapper."""

    def _brief(self):
        return self.client.post(
            "/api/assistant/ask",
            json={"query": "", "action": "brief", "locale": "en"},
        )

    def test_ollama_get_bomb_keeps_the_snapshot_section(self):
        wrapped = _DictGetBomb({"reachable": True, "resident": [{"name": "modelx"}]})
        with mock.patch("hub.ollama_svc.status", return_value=wrapped):
            resp = self._brief()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            body["snapshot"]["ollama"],
            {"reachable": True, "resident": ["modelx"]},
        )

    def test_resident_row_get_bomb_drops_the_row_not_the_section(self):
        snap = {"reachable": True,
                "resident": [_DictGetBomb({"name": "poisoned"}), {"name": "sane"}]}
        with mock.patch("hub.ollama_svc.status", return_value=snap):
            resp = self._brief()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # _dget reads the poisoned row's real storage too: both names answer.
        self.assertEqual(
            body["snapshot"]["ollama"]["resident"], ["poisoned", "sane"],
        )

    def test_ups_get_bomb_keeps_the_on_battery_state(self):
        wrapped = _DictGetBomb({
            "present": True, "source": "battery", "percent": 42, "charging": False,
        })
        with mock.patch("hub.ups_svc.ups_snapshot", return_value=wrapped):
            resp = self._brief()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["snapshot"]["ups"]["source"], "battery")
        self.assertEqual(body["snapshot"]["ups"]["percent"], 42)
        # An on-battery snapshot still suggests the dashboard.
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])

    def test_pick_model_reads_underneath_a_poisoned_status(self):
        wrapped = _DictGetBomb({"reachable": True, "resident": [{"name": "modelx"}]})
        with mock.patch("hub.ollama_svc.status", return_value=wrapped):
            self.assertEqual(assistant_svc._pick_model(), "modelx")

    def test_pick_model_over_cap_name_skips_to_the_sane_sibling(self):
        # A bare str() of the over-cap already-int name used to ValueError
        # into _run_llm's blanket except and lose the sane sibling too.
        snap = {"reachable": True,
                "resident": [{"name": _HUGE_INT}, {"name": "modelx"}]}
        with mock.patch("hub.ollama_svc.status", return_value=snap):
            self.assertEqual(assistant_svc._pick_model(), "modelx")


class NestedAndCombinedNo500Pins(_QuietCollectors):
    """The re-swept no-500 surface: nested, combined, cyclic, over-deep."""

    def _brief_with_status(self, status):
        with mock.patch("hub.status.peek_status", return_value=status):
            return self.client.post(
                "/api/assistant/ask",
                json={"query": "", "action": "brief", "locale": "en"},
            )

    def test_bombs_nested_two_levels_into_a_cell_still_answer(self):
        for bomb in (
            _DictItemsBomb({"a": 1}),
            _BytesDecodeBomb(b"z"),
            _StrSelfEncodeBomb("s"),
            _ListIterBomb([1]),
            _HUGE_INT,
            {"k\ud800": "v\udfff"},
        ):
            status = _status()
            status["system"]["load"] = {"lvl1": [{"lvl2": bomb}]}
            resp = self._brief_with_status(status)
            self.assertEqual(resp.status_code, 200, resp.text[:200])
            _starlette(resp.json())

    def test_cyclic_snapshot_value_answers_not_a_500(self):
        cyc: dict = {}
        cyc["self"] = cyc
        status = _status()
        status["system"]["load"] = cyc
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_over_deep_snapshot_value_answers_not_a_500(self):
        deep: object = "bottom"
        for _ in range(200):
            deep = {"n": [deep]}
        status = _status()
        status["system"]["load"] = deep
        resp = self._brief_with_status(status)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_fully_poisoned_catalog_row_answers_every_route(self):
        row = _DictGetBomb({
            "id": _StrSelfEncodeBomb("docker"),
            "path": _StrSelfEncodeBomb("/docker"),
            "title": _DictGetBomb({"en": _StrSelfEncodeBomb("Docker")}),
            "aliases": _ListIterBomb([_StrSelfEncodeBomb("docker"), _HUGE_INT]),
        })
        with mock.patch.object(assistant_svc, "PANELS", (row,)):
            for resp in (
                self.client.get("/api/assistant/catalog?locale=en"),
                self.client.post("/api/assistant/ask", json={
                    "query": "docker", "action": "find", "locale": "en"}),
                self.client.post("/api/assistant/ask", json={
                    "query": "", "action": "page", "path": "/docker", "locale": "en"}),
            ):
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())


class ReplyTextProbeTests(unittest.TestCase):
    """The new coerce-first reply probe, held at the function level."""

    def test_bool_bomb_keeps_its_real_text(self):
        out = assistant_svc._reply_text(_StrBoolBomb("hello"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "hello")

    def test_bytes_decode_not_repr(self):
        self.assertEqual(assistant_svc._reply_text(_BytesDecodeBomb(b"hi")), "hi")

    def test_falsy_junk_keeps_the_old_empty_drop(self):
        for junk in (None, False, True, 0, 0.0, [], {}):
            self.assertEqual(assistant_svc._reply_text(junk), "")

    def test_truthy_non_text_still_renders(self):
        self.assertEqual(assistant_svc._reply_text(42), "42")

    def test_over_cap_int_drops_the_cell(self):
        self.assertEqual(assistant_svc._reply_text(_HUGE_INT), "")

    def test_surrogates_scrub_to_renderable_text(self):
        out = assistant_svc._reply_text("a\ud800b")
        _starlette(out)
        self.assertIn("a", out)


if __name__ == "__main__":
    unittest.main()
