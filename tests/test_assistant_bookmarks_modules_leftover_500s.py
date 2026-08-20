"""Leftover 500s on bookmarks, the assistant drawer, and GET /api/modules.

A YAML ``service: [nginx]`` used to TypeError GET /api/bookmarks; leftover
bytes / tuple-inf in the status snapshot and a cold ``full_status`` raise used
to 500 POST /api/assistant/ask (Starlette ``allow_nan=False``); a junk module
registry row used to 500 GET /api/modules.

Follow-up: YAML ``name: 2026-08-19`` / ``!!binary`` / ``.inf`` / ``!!set``
and leftover backend datetime/bytes/inf still 500'd GET /api/bookmarks;
a leftover ``\\ud800`` in a bookmark name, the assistant snapshot, the
find-query echo, or a catalog title still 500'd Starlette's UTF-8 encode.
"""
from __future__ import annotations

import datetime
import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import assistant_svc, bookmarks_svc, modules
from hub.routers import assistant_api


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class BookmarkUnhashableKeyTests(unittest.TestCase):
    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def _list(self, links, overrides=None):
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"quick_links": links, "overrides": overrides or {}},
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(
                bookmarks_svc, "_probe",
                return_value={"ok": True, "status": 200, "ms": 1, "error": None},
            ),
        ):
            return bookmarks_svc.list_bookmarks(force=True)

    def test_list_service_does_not_500_the_bookmark_list(self):
        data = self._list([{
            "name": "Nginx",
            "url": "http://nas.local:8080",
            "service": ["nginx"],
        }])
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["name"], "Nginx")
        _json(data)

    def test_dict_id_does_not_500_resolve(self):
        row = bookmarks_svc._resolve_backend(
            {"name": "x", "url": "http://h", "id": {"nested": True}},
            {"x": {"state": "ok", "kind": "container"}},
        )
        self.assertIsNone(row)

    def test_string_id_still_matches(self):
        backend = {"state": "stopped", "kind": "container", "id": "web"}
        row = bookmarks_svc._resolve_backend(
            {"name": "x", "url": "http://h", "id": "web"},
            {"web": backend},
        )
        self.assertEqual(row["id"], "web")

    def test_yaml_leftover_fields_do_not_500_json(self):
        """``name: 2026-08-19`` / ``!!binary`` / ``.inf`` / ``!!set`` used to 500."""
        data = self._list([
            {"name": datetime.date(2026, 8, 19), "url": "http://h/date", "service": "d"},
            {"name": b"Nginx", "url": "http://h/bytes", "id": b"nginx"},
            {"name": float("inf"), "url": "http://h/inf", "id": float("nan")},
            {"name": "Set", "url": "http://h/set", "service": {"nginx"}},
            {"name": "bot\ud800", "url": "http://h/surr", "service": "surr"},
        ])
        _json(data)
        _starlette(data)
        by_url = {row["url"]: row for row in data["bookmarks"]}
        self.assertEqual(by_url["http://h/date"]["name"], "2026-08-19")
        self.assertEqual(by_url["http://h/bytes"]["name"], "Nginx")
        self.assertIsNone(by_url["http://h/inf"]["name"])
        self.assertEqual(by_url["http://h/set"]["service"], ["nginx"])
        self.assertNotIn("\ud800", by_url["http://h/surr"]["name"])

    def test_leftover_backend_row_does_not_500_json(self):
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"quick_links": [{
                    "name": "Web", "url": "http://h", "id": "web",
                }], "overrides": {}},
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={
                "web": {
                    "state": "ok",
                    "kind": "container",
                    "id": datetime.date(2026, 8, 19),
                    "name": b"web",
                    "status": float("inf"),
                },
            }),
            mock.patch.object(
                bookmarks_svc, "_probe",
                return_value={"ok": True, "status": 200, "ms": 1, "error": None},
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        _json(data)
        _starlette(data)
        backend = data["bookmarks"][0]["backend"]
        self.assertEqual(backend["name"], "web")
        self.assertEqual(backend["id"], "2026-08-19")
        self.assertIsNone(backend["status"])

    def test_override_leftover_name_does_not_500_json(self):
        data = self._list([], overrides={
            "web": {"name": datetime.date(2026, 8, 19), "url": "http://h/ov"},
        })
        _json(data)
        _starlette(data)
        self.assertEqual(data["bookmarks"][0]["name"], "2026-08-19")
        self.assertEqual(data["bookmarks"][0]["url"], "http://h/ov")


class AssistantSnapshotLeftoverTests(unittest.TestCase):
    def _status(self, system, **extra):
        payload = {
            "system": system,
            "engine_up": True,
            "counts": extra.get("counts", {"ok": 1, "warn": 0, "down": 0, "stopped": 0}),
            "problems": extra.get("problems", []),
        }
        return payload

    def test_bytes_and_tuple_inf_do_not_500_json(self):
        """``_jsonable`` used to walk dict/list/float only; bytes and tuple-inf leaked."""
        with (
            mock.patch("hub.status.peek_status", return_value=self._status({
                "load": b"0.10 / 0.20 / 0.30",
                "load_pct": (float("inf"), 1.0),
                "mem_used_pct": 10,
                "disk_pct": 20,
                "disk_used_gb": 1,
                "disk_total_gb": 2,
            })),
            mock.patch("hub.status.full_status"),
            mock.patch("hub.ollama_svc.status", return_value={"reachable": False}),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
        ):
            snap = assistant_svc.build_snapshot()
            out = assistant_svc.ask("status", locale="en", action="brief")
        self.assertEqual(snap["load"], "0.10 / 0.20 / 0.30")
        self.assertEqual(snap["cpu_load_pct"], [None, 1.0])
        _json(snap)
        _json(out)

    def test_cold_status_raise_does_not_500_ask(self):
        """``peek_status() or full_status()`` used to propagate a discovery blow-up."""
        with (
            mock.patch("hub.status.peek_status", return_value=None),
            mock.patch("hub.status.full_status", side_effect=RuntimeError("discovery")),
            mock.patch("hub.ollama_svc.status", return_value={"reachable": False}),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
        ):
            out = assistant_svc.ask("", locale="en", action="brief")
        self.assertEqual(out["kind"], "brief")
        self.assertFalse(out["used_llm"])
        self.assertIn("Overview:", out["text"])
        _json(out)

    def test_pick_model_raise_falls_back(self):
        with mock.patch.object(assistant_svc, "_pick_model", side_effect=RuntimeError("ollama")):
            self.assertEqual(assistant_svc._run_llm("hi", "en", {"load": 1}, None), {})

    def test_system_prompt_bytes_do_not_raise(self):
        text = assistant_svc._system_prompt({"load": b"1.0 / 1.0 / 1.0"}, "en")
        self.assertIn("1.0 / 1.0 / 1.0", text)

    def test_system_prompt_leftover_inf_does_not_raise(self):
        """json.dumps without allow_nan=False used to write Infinity into the prompt."""
        text = assistant_svc._system_prompt({
            "load": float("inf"),
            "blob": b"ok",
            "when": datetime.date(2026, 8, 19),
        }, "en")
        self.assertNotIn("Infinity", text)
        text.encode("utf-8")

    def test_surrogate_snapshot_does_not_500_json(self):
        """A leftover ``\\ud800`` in load / problem name used to 500 the encoder."""
        with (
            mock.patch("hub.status.peek_status", return_value=self._status({
                "load": "0.10\ud800",
                "load_pct": 1.0,
                "mem_used_pct": 10,
                "disk_pct": 20,
                "disk_used_gb": 1,
                "disk_total_gb": 2,
            }, problems=[{"name": "nginx\ud800", "state": "warn", "detail": "x"}])),
            mock.patch("hub.status.full_status"),
            mock.patch("hub.ollama_svc.status", return_value={"reachable": False}),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
        ):
            snap = assistant_svc.build_snapshot()
            out = assistant_svc.ask("status", locale="en", action="brief")
        self.assertNotIn("\ud800", snap["load"])
        self.assertNotIn("\ud800", snap["problems"][0]["name"])
        _starlette(snap)
        _starlette(out)

    def test_surrogate_find_query_does_not_500_json(self):
        """``_find_text`` used to echo the leftover query into the JSON body."""
        with (
            mock.patch.object(assistant_svc, "build_snapshot", return_value={
                "counts": {"ok": 0, "warn": 0, "down": 0, "stopped": 0},
            }),
            mock.patch.object(assistant_svc, "_run_llm", return_value={}),
        ):
            out = assistant_svc.ask("no-such-\ud800-panel", locale="en", action="find")
        self.assertEqual(out["kind"], "find")
        self.assertNotIn("\ud800", out["text"])
        _starlette(out)


class AssistantRouterLeftoverTests(unittest.TestCase):
    def test_ask_jsonables_leftover_payload(self):
        body = assistant_api.AskBody(query="logs", action="find", locale="en")
        with mock.patch.object(assistant_api.assistant_svc, "ask", return_value={
            "ok": True,
            "kind": "find",
            "text": b"Matching panels:",
            "thinking": "",
            "panels": [],
            "snapshot": {"load": (float("inf"), 0.2)},
            "model": None,
            "used_llm": False,
            "duration_s": float("inf"),
        }):
            out = assistant_api.ask(body)
        self.assertEqual(out["text"], "Matching panels:")
        self.assertIsNone(out["duration_s"])
        _json(out)

    def test_ask_swallows_unexpected_errors(self):
        body = assistant_api.AskBody(query="status", action="brief", locale="en")
        with (
            mock.patch.object(
                assistant_api.assistant_svc, "ask",
                side_effect=RuntimeError("collector"),
            ),
            mock.patch.object(
                assistant_api.assistant_svc, "build_snapshot",
                return_value={"counts": {"ok": 0, "warn": 0, "down": 0, "stopped": 0}},
            ),
        ):
            out = assistant_api.ask(body)
        self.assertTrue(out["ok"])
        self.assertEqual(out["kind"], "brief")
        self.assertFalse(out["used_llm"])
        _json(out)

    def test_coded_errors_still_propagate(self):
        body = assistant_api.AskBody(query="", action="ask", locale="en")
        with self.assertRaises(HTTPException) as ctx:
            assistant_api.ask(body)
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "assistant.query_required")

    def test_catalog_raise_returns_empty_not_500(self):
        with mock.patch.object(
            assistant_api.assistant_svc, "catalog", side_effect=RuntimeError("json")
        ):
            out = assistant_api.get_catalog("en")
        self.assertEqual(out["panels"], [])
        _json(out)

    def test_ask_jsonables_surrogate_payload(self):
        body = assistant_api.AskBody(query="logs", action="find", locale="en")
        with mock.patch.object(assistant_api.assistant_svc, "ask", return_value={
            "ok": True,
            "kind": "find",
            "text": "Matching\ud800 panels:",
            "thinking": "",
            "panels": [],
            "snapshot": {"load": "1\ud800", "\ud800": 1},
            "model": None,
            "used_llm": False,
            "duration_s": 0,
        }):
            out = assistant_api.ask(body)
        self.assertNotIn("\ud800", out["text"])
        self.assertNotIn("\ud800", out["snapshot"]["load"])
        _starlette(out)

    def test_catalog_surrogate_title_does_not_500(self):
        with mock.patch.object(
            assistant_api.assistant_svc, "catalog",
            return_value=[{"id": "logs", "path": "/logs", "title": "Logs\ud800", "aliases": []}],
        ):
            out = assistant_api.get_catalog("en")
        self.assertNotIn("\ud800", out["panels"][0]["title"])
        _starlette(out)


class ModuleRegistryLeftoverTests(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)

    def tearDown(self):
        modules.MODULES[:] = self._saved

    def test_junk_row_and_unhashable_category_do_not_500(self):
        modules.MODULES.append("not-a-module")
        modules.MODULES.append({"id": "plugin", "name": "P", "category": ["ops"]})
        rows = modules.list_modules()
        by_cat = modules.modules_by_category()
        ids = {r["id"] for r in rows}
        self.assertIn("plugin", ids)
        self.assertNotIn("not-a-module", ids)
        self.assertIn("other", by_cat)
        _json({"modules": rows, "by_category": by_cat})

    def test_builtin_modules_still_group(self):
        by_cat = modules.modules_by_category()
        self.assertIn("system", by_cat)
        self.assertTrue(any(r["id"] == "dashboard" for r in by_cat["system"]))


class BookmarkProbeExcDetailTests(unittest.TestCase):
    def test_recursing_probe_error_does_not_500(self):
        """str(e) RecursionError used to 500 GET /api/bookmarks."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with (
            mock.patch.object(bookmarks_svc, "_is_blocked_probe_host", return_value=False),
            mock.patch.object(
                bookmarks_svc.urllib.request, "build_opener", side_effect=Recursing(),
            ),
        ):
            out = bookmarks_svc._probe("http://10.0.0.1:9")
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "error")

    def test_infinite_clock_does_not_500_probe(self):
        """int((time.time()-t0)*1000) OverflowError on leftover inf used to 500 GET /api/bookmarks."""
        with (
            mock.patch.object(bookmarks_svc, "_is_blocked_probe_host", return_value=False),
            mock.patch.object(bookmarks_svc.time, "time", return_value=float("inf")),
            mock.patch.object(
                bookmarks_svc.urllib.request, "build_opener", side_effect=OSError("x"),
            ),
        ):
            out = bookmarks_svc._probe("http://10.0.0.1:9")
        _starlette(out)
        self.assertEqual(out["ms"], 0)


class Utf8TextRecursionLeftoverTests(unittest.TestCase):
    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(bookmarks_svc._utf8_text(Recursing()), "Recursing")
        self.assertEqual(assistant_svc._utf8_text(Recursing()), "Recursing")
        _starlette({"k": bookmarks_svc._utf8_text(Recursing())})
        _starlette({"k": assistant_svc._utf8_text(Recursing())})


if __name__ == "__main__":
    unittest.main()
