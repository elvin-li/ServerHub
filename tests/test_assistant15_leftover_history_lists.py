"""Assistant sweep #15: leftover leftover lists on chat history.

The drawer used to walk ``turns.value.filter`` and the LLM seam used to
walk ``history`` with a bare ``isinstance`` / bound ``.get``.  A mapping
leftover history, a list-claiming tuple of honest turns, or a dict-subclass
``get`` bomb on one turn used to 500 POST /api/assistant/ask (or throw in
the SPA) instead of dropping just the junk cells.

Control flow keeps propagating.  Stronger union guards stay pinned.
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


class _GetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class _TupleClaimsList(tuple):
    @property
    def __class__(self):
        return list


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


class HistoryLeftoverTests(unittest.TestCase):
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

    def _ok(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn(" at 0x", resp.text)
        body = resp.json()
        _starlette(body)
        return body

    def test_mapping_history_on_the_wire_does_not_500(self):
        resp = self.client.post(
            "/api/assistant/ask",
            json={
                "query": "hi",
                "action": "ask",
                "locale": "en",
                "history": {"0": {"role": "user", "content": "stale"}},
            },
        )
        # Pydantic rejects a mapping history as 422 — fail-close, never 500.
        self.assertIn(resp.status_code, (200, 422))
        if resp.status_code == 200:
            _starlette(resp.json())

    def test_svc_mapping_history_drops_to_empty_not_500(self):
        with mock.patch("hub.status.peek_status", return_value=_status()):
            body = assistant_svc.ask(
                "hi",
                locale="en",
                action="ask",
                history={"0": {"role": "user", "content": "stale"}},
            )
        self.assertTrue(body.get("ok"))
        _starlette(body)

    def test_tuple_history_claiming_list_keeps_honest_turns(self):
        seen = []

        def _chat(model, messages, _n):
            seen.append(messages)
            return {"content": "LLM SAYS HI", "model": model, "duration_s": 1}

        hist = _TupleClaimsList(({"role": "user", "content": "earlier"},))
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch("hub.ollama_svc.chat", side_effect=_chat),
        ):
            body = assistant_svc.ask(
                "hi", locale="en", action="ask", history=hist,
            )
        self.assertEqual(body["text"], "LLM SAYS HI")
        roles = [m["role"] for m in seen[0]]
        self.assertIn("user", roles)
        self.assertIn("earlier", [m.get("content") for m in seen[0]])

    def test_get_bomb_history_turn_does_not_wipe_the_ask(self):
        seen = []

        def _chat(model, messages, _n):
            seen.append(messages)
            return {"content": "LLM SAYS HI", "model": model, "duration_s": 1}

        hist = [
            _GetBomb(role="user", content="earlier"),
            {"role": "assistant", "content": "ok"},
        ]
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch("hub.ollama_svc.chat", side_effect=_chat),
        ):
            body = assistant_svc.ask(
                "hi", locale="en", action="ask", history=hist,
            )
        self.assertEqual(body["text"], "LLM SAYS HI")
        contents = [m.get("content") for m in seen[0]]
        self.assertIn("earlier", contents)
        self.assertIn("ok", contents)

    def test_union_guard_pins_stay_exact(self):
        self.assertIsNone(assistant_svc._capped_json_int("9" * 5000))
        self.assertEqual(assistant_svc._capped_json_int("42"), 42)
        self.assertIsNone(assistant_svc._jsonable(10 ** 5000))
        self.assertEqual(assistant_svc._list_rows({"0": 1}), [])
        self.assertEqual(assistant_svc._list_rows((1, 2)), [])


if __name__ == "__main__":
    unittest.main()
