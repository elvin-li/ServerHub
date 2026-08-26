"""Assistant sweep #4: the numeric-id silent wipe, fixed via the str() probe.

Assistant #3 replaced the bare ``str()`` calls on panel *titles and aliases*
with the ``_utf8_text`` probe, but the row gates themselves stayed
``isinstance(pid, str)``.  A numeric-id catalog row (a hand-edited
``"id": 42`` — or a YAML / plist loader swap, which loads hex/octal
*already-int* and uncapped) therefore vanished from every assistant answer
at once, reproduced end to end over the mounted app:

* GET /api/assistant/catalog dropped the row — the Cmd+K palette lost the
  page entirely;
* a find turn missed the row even when the query hit one of its aliases
  dead-on (POST /api/assistant/ask answered the no-match text);
* a page turn on the row's own path lost its ``here`` context —
  ``snapshot.here`` fell to None and ``panels`` answered empty;
* ``suggest_panels`` keyed its map through the same gate.

Fixed with ``_panel_id``, the ``jobs._task_id`` rule the union already uses
for dashboard registry ids and scheduler job ids: a renderable int coerces
through the ``str()`` probe, an over-cap leftover (whose ``str()`` raises
the same digit-cap ValueError ``json.dumps`` would) drops only its row, and
bool must not become ``"True"``.  The panel *path* keeps its str gate on
purpose — it is the SPA navigation target, and a non-string path is junk
the palette cannot open.

Same class one loader further in: ``_PANEL_WORDS`` ran a bare ``str(w)``
over the intents list at import, so the parse_int hook's None (an over-cap
number literal in assistant_intents.json) minted a ``"none"`` panel word
that blanked the literal query "none", and an *already-int* over-cap word
(loader swap) would have ValueError'd the whole module import.
"""
from __future__ import annotations

import importlib
import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import assistant_svc
from hub import util as hub_util
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


def _status(counts=None) -> dict:
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
        "counts": counts if counts is not None else {
            "ok": 1, "warn": 0, "down": 0, "stopped": 0,
        },
        "problems": [],
    }


#: One numeric-id row (under the cap — must keep working), one over-cap-id
#: row (must drop alone), one bool-id row (must not become "True"), and one
#: sane sibling that proves the drops are row-level, never the []-wipe.
_ID_PANELS = (
    {"id": 42, "path": "/logs", "title": {"en": "Logs"}, "aliases": ["journal"]},
    {"id": _HUGE, "path": "/poisoned", "title": {"en": "Poisoned"}, "aliases": ["poison"]},
    {"id": True, "path": "/boolrow", "title": {"en": "Bool"}, "aliases": ["boolish"]},
    {"id": "health", "path": "/health", "title": {"en": "Health"}, "aliases": ["doctor"]},
)


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
        return self.client.post("/api/assistant/ask", json=body)


class PanelIdProbeTests(unittest.TestCase):
    """The jobs._task_id rule, held at the function level."""

    def test_str_id_is_scrubbed_and_stripped(self):
        self.assertEqual(assistant_svc._panel_id(" logs "), "logs")
        # _utf8_text scrubs on the *encode* side, so the replacement is "?".
        self.assertEqual(assistant_svc._panel_id("l\ud800ogs"), "l?ogs")

    def test_numeric_id_under_the_cap_coerces(self):
        self.assertEqual(assistant_svc._panel_id(42), "42")
        self.assertEqual(assistant_svc._panel_id(2 ** 63), str(2 ** 63))

    def test_over_cap_id_drops_to_empty_not_a_raise(self):
        self.assertEqual(assistant_svc._panel_id(_HUGE), "")

    def test_bool_and_junk_ids_drop(self):
        # bool passes isinstance(int) and must not become "True".
        self.assertEqual(assistant_svc._panel_id(True), "")
        self.assertEqual(assistant_svc._panel_id(False), "")
        self.assertEqual(assistant_svc._panel_id(None), "")
        self.assertEqual(assistant_svc._panel_id(1.5), "")
        self.assertEqual(assistant_svc._panel_id({"id": 1}), "")


class CatalogNumericIdRouteTests(_QuietCollectors):
    """GET /api/assistant/catalog keeps the numeric-id row."""

    def test_numeric_id_row_survives_as_its_str_form(self):
        with mock.patch.object(assistant_svc, "PANELS", _ID_PANELS):
            resp = self.client.get("/api/assistant/catalog?locale=en")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        by_id = {row["id"]: row for row in body["panels"]}
        self.assertIn("42", by_id)
        self.assertEqual(by_id["42"]["path"], "/logs")
        self.assertEqual(by_id["42"]["title"], "Logs")
        self.assertIn("journal", by_id["42"]["aliases"])
        # Row-level drops for the unrenderable and bool ids, never a wipe.
        self.assertIn("health", by_id)
        self.assertNotIn("True", by_id)
        paths = [row["path"] for row in body["panels"]]
        self.assertNotIn("/poisoned", paths)
        self.assertNotIn("/boolrow", paths)


class FindNumericIdRouteTests(_QuietCollectors):
    """A find turn matches the numeric-id row's alias and exact id."""

    def test_alias_hit_answers_the_numeric_id_row(self):
        with mock.patch.object(assistant_svc, "PANELS", _ID_PANELS):
            resp = self._ask({"query": "journal", "action": "find", "locale": "en"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["kind"], "find")
        self.assertIn("42", [p.get("id") for p in body["panels"]])

    def test_exact_numeric_query_matches_the_id_leg(self):
        # The _score_panel id comparison is the probe, not a bare str().
        with mock.patch.object(assistant_svc, "PANELS", _ID_PANELS):
            hits = assistant_svc.match_panels("42", "en")
        self.assertTrue(hits, "exact numeric id must match")
        self.assertEqual(hits[0]["id"], "42")
        self.assertEqual(hits[0]["score"], 100)

    def test_over_cap_id_row_drops_alone_from_find(self):
        with mock.patch.object(assistant_svc, "PANELS", _ID_PANELS):
            self.assertEqual(assistant_svc.match_panels("poison", "en"), [])
            doctor = assistant_svc.match_panels("doctor", "en")
        self.assertEqual([r["id"] for r in doctor], ["health"])


class PageNumericIdRouteTests(_QuietCollectors):
    """A page turn on the numeric-id row's path keeps its here context."""

    def test_page_turn_keeps_here_for_the_numeric_id_row(self):
        with mock.patch.object(assistant_svc, "PANELS", _ID_PANELS):
            resp = self._ask({
                "query": "", "action": "page", "path": "/logs", "locale": "en",
            })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["kind"], "page")
        here = body["snapshot"].get("here")
        self.assertIsNotNone(here, "numeric-id row used to lose the page context")
        self.assertEqual(here["id"], "42")
        self.assertEqual(here["title"], "Logs")
        self.assertEqual([p.get("id") for p in body["panels"]], ["42"])

    def test_over_cap_id_path_stays_the_generic_page_not_a_500(self):
        with mock.patch.object(assistant_svc, "PANELS", _ID_PANELS):
            resp = self._ask({
                "query": "", "action": "page", "path": "/poisoned", "locale": "en",
            })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["snapshot"].get("here"))


class SuggestNumericIdTests(unittest.TestCase):
    """suggest_panels keys and emits the coerced id text."""

    def test_poisoned_id_rows_do_not_break_the_wanted_lookup(self):
        panels = (
            {"id": _HUGE, "path": "/junk", "title": {"en": "Junk"}},
            {"id": True, "path": "/bool", "title": {"en": "Bool"}},
            {"id": "health", "path": "/health", "title": {"en": "Health"}},
            {"id": "dashboard", "path": "/", "title": {"en": "Dashboard"}},
        )
        with mock.patch.object(assistant_svc, "PANELS", panels):
            out = assistant_svc.suggest_panels({"counts": {}}, "en")
        self.assertEqual(
            [row["id"] for row in out], ["dashboard", "health"]
        )
        _starlette(out)

    def test_emitted_id_is_text_even_for_a_numeric_row(self):
        # Emit the coerced form, never the raw int _jsonable would null out
        # past the digit cap.  Wanted ids are literal strings, so a numeric
        # row can only ever surface through catalog/find — but the map and
        # the emitted rows must stay consistent with them.
        panels = (
            {"id": "health", "path": "/health", "title": {"en": "Health"}},
        )
        with mock.patch.object(assistant_svc, "PANELS", panels):
            out = assistant_svc.suggest_panels(
                {"counts": {"down": 1}}, "en"
            )
        for row in out:
            self.assertIsInstance(row["id"], str)


class PanelWordsLoaderTests(unittest.TestCase):
    """_PANEL_WORDS: probe + None-drop instead of a bare str(w)."""

    _INTENTS_MARKER = "\x00ASSISTANT4-INTENTS-MARKER\x00"

    def _reload_with_panel_words(self, panel_word):
        real_read = hub_util.read_text_capped
        real_loads = hub_util.safe_json_loads

        def fake_read(path, cap, *, encoding="utf-8", **kw):
            if str(path).endswith("assistant_intents.json"):
                return self._INTENTS_MARKER
            return real_read(path, cap, encoding=encoding, **kw)

        def fake_loads(s, **kw):
            if s == self._INTENTS_MARKER:
                # Already-parsed shape: ints stay ints, as a YAML/plist
                # loader swap (uncapped hex/octal) would hand them over.
                return {"panel_word": panel_word}
            return real_loads(s, **kw)

        # importlib.reload re-runs ``from hub.util import ...``, so the
        # reloaded module binds these fakes for its import-time loads.
        with (
            mock.patch.object(hub_util, "read_text_capped", fake_read),
            mock.patch.object(hub_util, "safe_json_loads", fake_loads),
        ):
            importlib.reload(assistant_svc)
        self.addCleanup(importlib.reload, assistant_svc)
        return assistant_svc._PANEL_WORDS

    def test_none_from_the_parse_int_hook_is_not_the_none_word(self):
        # str(None) used to mint a "none" panel word that blanked the
        # literal query "none".
        words = self._reload_with_panel_words([None, "Page", "页面"])
        self.assertNotIn("none", words)
        self.assertIn("page", words)

    def test_already_int_over_cap_word_does_not_kill_the_import(self):
        words = self._reload_with_panel_words([_HUGE, "Page", 42])
        self.assertNotIn("", words)
        self.assertIn("page", words)
        # A renderable numeric word coerces like every other probe site.
        self.assertIn("42", words)


if __name__ == "__main__":
    unittest.main()
