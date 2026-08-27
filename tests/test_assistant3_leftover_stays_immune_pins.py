"""Assistant sweep #3: one catalog wipe fixed, the rest pinned at HTTP.

A fresh hunt over the mounted assistant routes (GET /api/assistant/catalog,
POST /api/assistant/ask) reproduced every sweep class end to end — real app,
real Starlette JSON encode — and found one genuine leftover:

* an over-cap *already-int* (>4300 digits, past CPython's int->str digit
  cap) in a panel row's title / alias raised ValueError out of the bare
  ``str()`` in ``catalog()`` / ``_score_panel()`` / ``_title()``.  The
  routes never 500'd — the router's own fallbacks caught it — but the
  failure was a silent wipe: GET /api/assistant/catalog answered
  ``panels: []`` (the Cmd+K catalog went empty), and a find / page turn
  quietly degraded to the generic brief, losing the answer the operator
  asked for.  Fixed with the ``_utf8_text`` str() probe (never an
  ``isinstance(x, str)`` gate — a numeric id under the cap must keep
  rendering), dropping only the unrenderable field, like the sibling
  ``_jsonable`` drop for inf floats.  ``_run_llm`` had the same bare
  ``str()`` on the model's reply *outside* its own try block (bytes
  answered their Python repr; an over-cap int fell to the router's
  rebuilt fallback and lost the page context).

Everything else was already immune (hub/assistant_svc.py grew the
sanitizers in earlier sweeps; the unit-level pins live in
test_assistant_leftover_digit_500s.py and
test_assistant_bookmarks_modules_leftover_500s.py).  Those held only at
the function level — nothing exercised the mounted routes — so the rest
of this file pins the contract at the HTTP layer:

* lone surrogates: a ``\\ud800`` JSON escape in the request body is
  refused by pydantic as the coded 422 (never 500); a poisoned status
  snapshot (surrogate keys AND values) answers a scrubbed 200;
* digit-cap: over-cap already-ints anywhere in the snapshot (values,
  counts, even dict keys) drop field-level and the deterministic brief
  still renders — including inside the router's own error fallback;
* coded 4xx keep their shape end to end (assistant.query_required,
  assistant.bad_action, and the ollama.prompt_too_long registered by the
  mounted app's ollama router import);
* engine-down / vanished daemon: FileNotFoundError from the chat layer
  answers the deterministic 200 brief (the drawer's designed contract —
  never a 500, never a wipe), and a double blow-up (ask() AND the
  fallback's build_snapshot()) still answers the hard-coded brief.

The remaining sweep classes do not apply: the assistant owns no journal
and mutates nothing (the catalog JSONs are read-only, loaded through the
parse_int hook pinned in test_assistant_leftover_digit_500s.py), and it
spawns no process — engine-down 503-after-disk-confirm belongs to the
Ollama page's own routes, while the assistant deliberately answers the
template brief instead.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import assistant_svc
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE = 10 ** 5000

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


def _status(system=None, counts=None, problems=None) -> dict:
    return {
        "system": system if system is not None else {
            "load": "0.10 / 0.20 / 0.30",
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "disk_pct": 20,
            "disk_used_gb": 1,
            "disk_total_gb": 2,
            "uptime": "1.0 hours",
        },
        "engine_up": True,
        "counts": counts if counts is not None else {
            "ok": 1, "warn": 0, "down": 0, "stopped": 0,
        },
        "problems": problems if problems is not None else [],
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

    def _ask(self, body: dict):
        resp = self.client.post("/api/assistant/ask", json=body)
        return resp


#: What a leftover over-cap int in a panel row looks like once it is
#: *already-int* (YAML/plist hex loads uncapped; a future loader swap must
#: not reopen the wipe).  The en title stays sane so the fallthrough shows.
_POISONED_PANELS = (
    {
        "id": "logs",
        "path": "/logs",
        "title": {"en": "Logs", "ja": "ログ", "zh-CN": _HUGE},
        "aliases": [None, "journal", _HUGE, b"\xff\xfe"],
        "weight": _HUGE,
    },
    {
        "id": "health",
        "path": "/health",
        "title": {"en": "Health"},
        "aliases": ["doctor"],
    },
)


class CatalogRouteOverCapPanelTests(_QuietCollectors):
    """One over-cap panel field never wipes GET /api/assistant/catalog."""

    def test_poisoned_row_survives_with_only_the_poison_dropped(self):
        with mock.patch.object(assistant_svc, "PANELS", _POISONED_PANELS):
            resp = self.client.get("/api/assistant/catalog?locale=en")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        by_id = {row["id"]: row for row in body["panels"]}
        # Field-level drop, never the []-wipe: both rows answer, the
        # renderable alias survives, the over-cap alias is gone.
        self.assertIn("logs", by_id)
        self.assertIn("health", by_id)
        self.assertEqual(by_id["logs"]["title"], "Logs")
        self.assertIn("journal", by_id["logs"]["aliases"])
        self.assertNotIn("None", by_id["logs"]["aliases"])

    def test_over_cap_locale_title_falls_through_to_en(self):
        # str() probe with fallthrough, not an isinstance(x, str) gate: the
        # zh-CN request keeps the English title instead of losing the row.
        with mock.patch.object(assistant_svc, "PANELS", _POISONED_PANELS):
            resp = self.client.get("/api/assistant/catalog?locale=zh-CN")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        by_id = {row["id"]: row for row in body["panels"]}
        self.assertEqual(by_id["logs"]["title"], "Logs")

    def test_find_still_matches_next_to_the_poisoned_alias(self):
        with mock.patch.object(assistant_svc, "PANELS", _POISONED_PANELS):
            resp = self._ask({"query": "journal", "action": "find", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The turn stays a find (it used to degrade to the generic brief).
        self.assertEqual(body["kind"], "find")
        self.assertIn("logs", [p.get("id") for p in body["panels"]])

    def test_page_turn_keeps_its_page_next_to_the_poisoned_title(self):
        with mock.patch.object(assistant_svc, "PANELS", _POISONED_PANELS):
            resp = self._ask({
                "query": "", "action": "page", "path": "/logs", "locale": "zh-CN",
            })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["kind"], "page")
        self.assertEqual(body["snapshot"]["here"]["id"], "logs")
        self.assertEqual(body["snapshot"]["here"]["title"], "Logs")


class TitleBlurbProbeTests(unittest.TestCase):
    """The str()-probe fallthrough semantics, held at the function level."""

    def test_title_over_cap_locale_falls_to_en(self):
        panel = {"id": "logs", "title": {"en": "Logs", "zh-CN": _HUGE}}
        self.assertEqual(assistant_svc._title(panel, "zh-CN"), "Logs")

    def test_title_every_candidate_unrenderable_is_empty_not_a_raise(self):
        panel = {"id": _HUGE, "title": {"en": _HUGE}}
        self.assertEqual(assistant_svc._title(panel, "en"), "")

    def test_numeric_title_under_the_cap_keeps_rendering(self):
        # A str() probe, not an isinstance(x, str) gate.
        panel = {"id": "logs", "title": {"en": 42}}
        self.assertEqual(assistant_svc._title(panel, "en"), "42")

    def test_blurb_over_cap_locale_falls_to_en(self):
        with mock.patch.object(
            assistant_svc, "_BLURBS", {"logs": {"en": "Logs.", "ja": _HUGE}}
        ):
            self.assertEqual(assistant_svc._blurb("logs", "ja"), "Logs.")


class RunLlmReplyShapeTests(unittest.TestCase):
    """The model's reply is sanitized before it can raise past the try."""

    def _run(self, result) -> dict:
        with (
            mock.patch.object(assistant_svc, "_pick_model", return_value="m"),
            mock.patch("hub.ollama_svc.chat", return_value=result),
        ):
            return assistant_svc._run_llm("hi", "en", {}, None)

    def test_bytes_content_answers_its_text_not_its_repr(self):
        out = self._run({"content": b"all good", "thinking": "", "model": "m"})
        self.assertEqual(out["text"], "all good")

    def test_over_cap_int_content_drops_to_the_thinking_fallback(self):
        out = self._run({"content": _HUGE, "thinking": "partial", "model": "m"})
        self.assertEqual(out["text"], "partial")

    def test_over_cap_int_content_and_thinking_is_the_no_llm_answer(self):
        # {} keeps ask() on its own fallback (snapshot and page context
        # intact) instead of raising into the router's rebuilt one.
        self.assertEqual(self._run({"content": _HUGE, "thinking": _HUGE}), {})


class AskRouteSurrogateTests(_QuietCollectors):
    """Lone surrogates on the wire never 500 POST /api/assistant/ask."""

    def test_surrogate_escape_in_body_is_the_coded_422(self):
        # A raw \ud800 JSON escape is valid bytes on the wire; pydantic
        # refuses the string (422), it never reaches ask() or a 500.
        resp = self.client.post(
            "/api/assistant/ask",
            content=b'{"query": "no-such-\\ud800-panel", "action": "find", "locale": "en"}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(resp.status_code, 422, resp.text[:200])
        _starlette(resp.json())

    def test_undecodable_body_bytes_are_a_4xx_not_a_500(self):
        resp = self.client.post(
            "/api/assistant/ask",
            content=b'{"query": "\xed\xa0\x80", "action": "find", "locale": "en"}',
            headers={"content-type": "application/json"},
        )
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        _starlette(resp.json())

    def test_percent_encoded_surrogate_locale_keeps_catalog_200(self):
        resp = self.client.get("/api/assistant/catalog?locale=zh%ED%A0%80")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_snapshot_surrogates_in_keys_and_values_answer_scrubbed(self):
        poisoned = _status(
            system={
                "load": "0.10\ud800",
                "load_pct": 1.0,
                "mem_used_pct": 10,
                "disk_pct": 20,
                "disk_used_gb": 1,
                "disk_total_gb": 2,
                "uptime": "1.0 hours",
                "k\ud800ey": "v\ud800al",
            },
            problems=[{"name": "nginx\ud800", "state": "warn", "detail": "x\udfff"}],
        )
        with mock.patch("hub.status.peek_status", return_value=poisoned):
            resp = self._ask({"query": "", "action": "brief", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        self.assertIn("Overview:", body["text"])


class AskRouteDigitCapTests(_QuietCollectors):
    """Over-cap already-ints anywhere in the snapshot never 500 the route."""

    def test_poisoned_snapshot_answers_the_brief_field_level(self):
        poisoned = _status(
            system={
                "load": _HUGE,
                "load_pct": 1.0,
                "mem_used_pct": 10,
                "disk_pct": 20,
                "disk_used_gb": _HUGE,
                "disk_total_gb": 2,
                "uptime": "1.0 hours",
                _HUGE: "keyed",
            },
            counts={"ok": _HUGE, "warn": 1, "down": 0, "stopped": 0},
            problems=[{"name": "nginx", "state": "warn", "detail": _HUGE}],
        )
        with mock.patch("hub.status.peek_status", return_value=poisoned):
            resp = self._ask({"query": "", "action": "brief", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # Field-level drops: the brief renders, the sane count survives,
        # the unrenderable ones read zero / None — never a wipe.
        self.assertIn("Overview:", body["text"])
        self.assertEqual(body["snapshot"]["counts"]["ok"], 0)
        self.assertEqual(body["snapshot"]["counts"]["warn"], 1)
        self.assertIsNone(body["snapshot"]["load"])

    def test_over_cap_query_is_the_coded_400_at_the_http_layer(self):
        # ollama.prompt_too_long is registered by the mounted app's own
        # ollama router import — the coded 400, never the unknown-code 500.
        resp = self._ask({"query": "9" * 600, "action": "ask", "locale": "en"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "ollama.prompt_too_long")

    def test_huge_digit_query_under_the_cap_still_answers(self):
        resp = self._ask({"query": "9" * 499, "action": "ask", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"])


class AskRouteCodedErrorTests(_QuietCollectors):
    """Coded 4xx keep their shape end to end."""

    def test_empty_ask_is_the_coded_400(self):
        resp = self._ask({"query": "", "action": "ask", "locale": "en"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "assistant.query_required")

    def test_bad_action_is_the_coded_400(self):
        resp = self._ask({"query": "x", "action": "bogus", "locale": "en"})
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "assistant.bad_action")


class AskRouteEngineDownTests(_QuietCollectors):
    """Ollama vanished / collectors down keep the deterministic-brief contract."""

    def test_vanished_daemon_answers_the_template_brief(self):
        # FileNotFoundError from the chat layer (binary / socket vanished
        # between the reachable probe and the call) answers the 200 brief —
        # the drawer's designed degradation, never a 500 and never a wipe.
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "qwen3.5:4b"}]},
            ),
            mock.patch("hub.ollama_svc.chat", side_effect=FileNotFoundError("ollama")),
        ):
            resp = self._ask({"query": "status", "action": "brief", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["used_llm"])
        self.assertIn("Overview:", body["text"])

    def test_double_blow_up_still_answers_the_hard_coded_brief(self):
        # ask() raises AND the fallback's own build_snapshot() raises: the
        # router's last-resort counts keep the route at 200.
        with (
            mock.patch.object(assistant_svc, "ask", side_effect=RuntimeError("boom")),
            mock.patch.object(
                assistant_svc, "build_snapshot", side_effect=RuntimeError("boom2"),
            ),
        ):
            resp = self._ask({"query": "x", "action": "brief", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["kind"], "brief")

    def test_poisoned_llm_reply_answers_scrubbed(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch("hub.ollama_svc.chat", return_value={
                "content": "ok\ud800",
                "thinking": b"\xff",
                "model": _HUGE,
                "duration_s": float("inf"),
            }),
        ):
            resp = self._ask({"query": "status", "action": "brief", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        # assistant8: the unrenderable over-cap model cell used to be nulled
        # by the final _jsonable; the str-gated pick now keeps the model this
        # call actually used, matching the assistant7 bool-bomb fallback.
        self.assertEqual(body["model"], "m")
        self.assertIsNone(body["duration_s"])


if __name__ == "__main__":
    unittest.main()
