"""In-panel assistant: catalog match, intent, fallback brief, LLM gating."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import assistant_svc  # noqa: E402


def _code(exc: HTTPException) -> str:
    return (exc.detail or {}).get("code", "")


STATUS = {
    "system": {
        "load": "0.40 / 0.50 / 0.60",
        "load_pct": 5.0,
        "mem_used_pct": 42,
        "mem_total_gb": 64.0,
        "disk_used_gb": 200,
        "disk_total_gb": 500,
        "disk_pct": 40,
        "uptime": "3.2 hours",
    },
    "engine_up": True,
    "counts": {"ok": 12, "warn": 1, "down": 0, "stopped": 3},
    "problems": [
        {"id": "nginx", "name": "nginx", "state": "warn", "detail": "reload pending"},
    ],
}


class CatalogAndMatch(unittest.TestCase):
    def test_catalog_uses_the_requested_locale(self):
        zh = {row["id"]: row["title"] for row in assistant_svc.catalog("zh-CN")}
        en = {row["id"]: row["title"] for row in assistant_svc.catalog("en")}
        self.assertEqual(zh["logs"], "日志")
        self.assertEqual(en["logs"], "Logs")
        self.assertEqual(zh["dashboard"], "仪表盘")

    def test_open_logs_in_chinese_hits_the_logs_panel(self):
        hits = assistant_svc.match_panels("打开日志", "zh-CN")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["id"], "logs")
        self.assertEqual(hits[0]["path"], "/logs")

    def test_docker_alias_hits_containers(self):
        hits = assistant_svc.match_panels("docker", "en")
        self.assertEqual(hits[0]["id"], "containers")

    def test_unknown_name_returns_nothing(self):
        self.assertEqual(assistant_svc.match_panels("definitely-not-a-panel"), [])

    def test_resolve_path_maps_a_route_and_nested_suffix(self):
        row = assistant_svc.resolve_path("/logs", "zh-CN")
        self.assertEqual(row["id"], "logs")
        self.assertEqual(row["path"], "/logs")
        self.assertIn("日志", row["blurb"])
        nested = assistant_svc.resolve_path("/logs/nginx?tail=80", "en")
        self.assertEqual(nested["id"], "logs")
        self.assertIn("logs", nested["blurb"].lower())

    def test_resolve_path_unknown_is_none(self):
        self.assertIsNone(assistant_svc.resolve_path("/no-such-panel"))


class Intent(unittest.TestCase):
    def test_empty_auto_is_a_status_brief(self):
        self.assertEqual(assistant_svc.classify_intent("", "auto"), "brief")

    def test_open_logs_is_find(self):
        self.assertEqual(assistant_svc.classify_intent("打开日志"), "find")

    def test_system_status_phrase_is_brief(self):
        self.assertEqual(assistant_svc.classify_intent("系统状态怎么样"), "brief")

    def test_how_to_question_is_ask_even_with_a_page_name(self):
        self.assertEqual(assistant_svc.classify_intent("日志怎么看"), "ask")

    def test_this_page_phrase_is_page(self):
        self.assertEqual(assistant_svc.classify_intent("本页"), "page")
        self.assertEqual(assistant_svc.classify_intent("explain this page"), "page")

    def test_explicit_action_wins(self):
        self.assertEqual(assistant_svc.classify_intent("打开日志", "brief"), "brief")

    def test_bad_action_is_a_coded_error(self):
        with self.assertRaises(HTTPException) as ctx:
            assistant_svc.classify_intent("hi", "delete")
        self.assertEqual(_code(ctx.exception), "assistant.bad_action")


class SnapshotAndFallback(unittest.TestCase):
    def test_fallback_brief_lists_problems(self):
        snap = {
            "load": "0.40 / 0.50 / 0.60",
            "cpu_load_pct": 5.0,
            "mem_used_pct": 42,
            "mem_total_gb": 64.0,
            "disk_root_pct": 40,
            "disk_root": "200/500 GB",
            "uptime": "3.2 hours",
            "engine_up": True,
            "counts": {"ok": 12, "warn": 1, "down": 0, "stopped": 3},
            "problems": [{"name": "nginx", "state": "warn", "detail": "reload pending"}],
        }
        text = assistant_svc.fallback_brief(snap, "zh-CN")
        self.assertIn("nginx", text)
        self.assertIn("12 ok", text)
        self.assertIn("Needs attention", text)

    def test_suggest_panels_points_at_services_when_something_is_wrong(self):
        snap = {
            "counts": {"ok": 1, "warn": 1, "down": 0, "stopped": 0},
            "disk_root_pct": 40,
            "ollama": {"reachable": True},
        }
        paths = [row["path"] for row in assistant_svc.suggest_panels(snap, "en")]
        self.assertIn("/services", paths)
        self.assertIn("/health", paths)


class AskGating(unittest.TestCase):
    def test_find_does_not_call_the_model(self):
        with (
            mock.patch.object(assistant_svc, "build_snapshot", return_value={
                "counts": {"ok": 1, "warn": 0, "down": 0, "stopped": 0},
                "engine_up": True,
            }),
            mock.patch.object(assistant_svc, "_run_llm") as llm,
        ):
            out = assistant_svc.ask("打开日志", locale="zh-CN")
        self.assertEqual(out["kind"], "find")
        self.assertFalse(out["used_llm"])
        self.assertEqual(out["panels"][0]["id"], "logs")
        llm.assert_not_called()

    def test_brief_falls_back_when_ollama_is_down(self):
        snap = {
            "load": "0.2 / 0.2 / 0.2",
            "cpu_load_pct": 3,
            "mem_used_pct": 30,
            "disk_root_pct": 20,
            "disk_root": "100/500 GB",
            "uptime": "1.0 hours",
            "engine_up": True,
            "counts": {"ok": 4, "warn": 0, "down": 0, "stopped": 0},
            "problems": [],
        }
        with (
            mock.patch.object(assistant_svc, "build_snapshot", return_value=snap),
            mock.patch.object(assistant_svc, "_run_llm", return_value={}),
        ):
            out = assistant_svc.ask("", locale="en", action="brief")
        self.assertEqual(out["kind"], "brief")
        self.assertFalse(out["used_llm"])
        self.assertIn("No service alerts", out["text"])
        self.assertIsNone(out["model"])

    def test_brief_uses_the_resident_model_when_it_answers(self):
        snap = {
            "counts": {"ok": 4, "warn": 0, "down": 0, "stopped": 0},
            "engine_up": True,
            "problems": [],
        }
        with (
            mock.patch.object(assistant_svc, "build_snapshot", return_value=snap),
            mock.patch.object(assistant_svc, "_run_llm", return_value={
                "text": "Host is quiet.",
                "thinking": "",
                "model": "qwen3.5:4b",
                "duration_s": 1.2,
            }),
        ):
            out = assistant_svc.ask("status", locale="en", action="brief")
        self.assertTrue(out["used_llm"])
        self.assertEqual(out["text"], "Host is quiet.")
        self.assertEqual(out["model"], "qwen3.5:4b")

    def test_ask_without_a_question_is_a_coded_error(self):
        with self.assertRaises(HTTPException) as ctx:
            assistant_svc.ask("", action="ask")
        self.assertEqual(_code(ctx.exception), "assistant.query_required")

    def test_empty_find_returns_the_catalog_without_the_model(self):
        with (
            mock.patch.object(assistant_svc, "build_snapshot", return_value={
                "counts": {"ok": 1, "warn": 0, "down": 0, "stopped": 0},
            }),
            mock.patch.object(assistant_svc, "_run_llm") as llm,
        ):
            out = assistant_svc.ask("", locale="en", action="find")
        self.assertEqual(out["kind"], "find")
        self.assertFalse(out["used_llm"])
        self.assertGreaterEqual(len(out["panels"]), 8)
        self.assertEqual(out["panels"][0]["id"], assistant_svc.catalog("en")[0]["id"])
        llm.assert_not_called()

    def test_page_falls_back_to_the_blurb_when_ollama_is_down(self):
        with (
            mock.patch.object(assistant_svc, "build_snapshot", return_value={
                "counts": {"ok": 1, "warn": 0, "down": 0, "stopped": 0},
            }),
            mock.patch.object(assistant_svc, "_run_llm", return_value={}) as llm,
        ):
            out = assistant_svc.ask("", locale="en", action="page", path="/logs")
        self.assertEqual(out["kind"], "page")
        self.assertFalse(out["used_llm"])
        self.assertEqual(out["panels"][0]["id"], "logs")
        self.assertIn("logs", out["text"].lower())
        self.assertEqual(out["snapshot"]["here"]["id"], "logs")
        llm.assert_called_once()

    def test_build_snapshot_reads_cached_status_not_a_forced_rebuild(self):
        with (
            mock.patch("hub.status.peek_status", return_value=STATUS) as peek,
            mock.patch("hub.status.full_status") as full,
            mock.patch("hub.ollama_svc.status", return_value={"reachable": True, "resident": []}),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
        ):
            snap = assistant_svc.build_snapshot()
        peek.assert_called_once()
        full.assert_not_called()
        self.assertEqual(snap["counts"]["warn"], 1)
        self.assertEqual(snap["problems"][0]["name"], "nginx")


class RouterContract(unittest.TestCase):
    def test_endpoints_are_registered(self):
        from hub.routers import assistant_api

        paths = {route.path for route in assistant_api.router.routes}
        self.assertIn("/api/assistant/catalog", paths)
        self.assertIn("/api/assistant/ask", paths)

    def test_the_aggregate_router_includes_the_assistant_routes(self):
        import hub.routers as routers_pkg

        source = (BASE / "hub" / "routers" / "__init__.py").read_text()
        self.assertIn("assistant_api", source)
        self.assertTrue(hasattr(routers_pkg, "assistant_api"))

    def test_error_codes_are_registered_for_the_spa(self):
        from hub.errors import CODES

        self.assertIn("assistant.query_required", CODES)
        self.assertIn("assistant.bad_action", CODES)


if __name__ == "__main__":
    unittest.main()
