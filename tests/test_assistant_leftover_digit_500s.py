"""Leftover >4300-digit ints in the in-panel assistant (digit-cap 500s).

Prior passes pinned the assistant against bytes / inf / datetime / lone
surrogates (test_assistant_bookmarks_modules_leftover_500s.py).  A fresh hunt
through the digit-limit lens — CPython's int<->str 4300-digit ValueError and
YAML/plist hex loads that bypass the ``int(str)`` cap — found four holes:

* ``_jsonable`` passed an *already-int* over-cap value straight through, so
  Starlette's ``json.dumps`` ValueError'd and 500'd POST /api/assistant/ask
  (hub/status.py's sibling ``_jsonable`` already had the ``str()`` probe);
* ``_safe_int`` only guarded the ``int(raw)`` conversion.  An already-int
  over-cap count passed it, and ``fallback_brief``'s bare f-strings then
  raised inside the router's *own error fallback* — a guaranteed 500;
* ``build_snapshot``'s ``disk_root`` f-string raised on an over-cap disk
  size and lost the whole snapshot, not just the one field;
* ``json.loads`` of a >4300-digit number literal is *ValueError*, not
  JSONDecodeError, for the whole document: one poisoned number in
  assistant_panels.json made ``_load_json`` return None and silently wiped
  the entire panel catalog.

Fixed with ``str()`` probes (not ``isinstance(x, str)`` gates — a numeric
id under the cap must keep working) and a ``parse_int`` hook that drops the
over-cap literal to None instead of the whole file.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import assistant_svc
from hub.routers import assistant_api

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE = 10 ** 5000
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _status(system=None, counts=None, problems=None) -> dict:
    return {
        "system": system if system is not None else {
            "load": "0.10 / 0.20 / 0.30",
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "mem_total_gb": 8,
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


class JsonableDigitCapTests(unittest.TestCase):
    def test_over_cap_int_drops_to_none_like_inf(self):
        out = assistant_svc._jsonable({"load": _HUGE, "nested": [{"n": _HUGE}]})
        self.assertIsNone(out["load"])
        self.assertIsNone(out["nested"][0]["n"])
        _starlette(out)

    def test_normal_ints_still_pass(self):
        out = assistant_svc._jsonable({"n": 42, "big": 2 ** 63})
        self.assertEqual(out["n"], 42)
        self.assertEqual(out["big"], 2 ** 63)
        _starlette(out)

    def test_over_cap_key_is_dropped_not_a_500(self):
        # An unrenderable key cannot be kept; the sibling entries must survive.
        out = assistant_svc._jsonable({_HUGE: "v", "k": 1})
        self.assertEqual(out, {"k": 1})
        _starlette(out)


class SafeIntDigitCapTests(unittest.TestCase):
    def test_already_int_over_cap_drops_to_default(self):
        self.assertEqual(assistant_svc._safe_int(_HUGE), 0)
        self.assertEqual(assistant_svc._safe_int(-_HUGE, 7), 7)

    def test_over_cap_digit_string_drops_to_default(self):
        self.assertEqual(assistant_svc._safe_int(_HUGE_DIGITS), 0)

    def test_numeric_string_ids_are_not_silently_dropped(self):
        # A str() probe, not an isinstance(x, str) gate: numeric YAML ids
        # under the cap must keep converting.
        self.assertEqual(assistant_svc._safe_int("12"), 12)
        self.assertEqual(assistant_svc._safe_int(12.9), 12)
        self.assertEqual(assistant_svc._safe_int(2 ** 63), 2 ** 63)


class SnapshotDigitCapTests(unittest.TestCase):
    def _snapshot(self, status):
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch("hub.status.full_status"),
            mock.patch("hub.ollama_svc.status", return_value={"reachable": False}),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
        ):
            return assistant_svc.build_snapshot()

    def test_over_cap_disk_size_loses_the_field_not_the_snapshot(self):
        snap = self._snapshot(_status(system={
            "load": "0.10 / 0.20 / 0.30",
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "disk_pct": 20,
            "disk_used_gb": _HUGE,
            "disk_total_gb": 2,
            "uptime": "1.0 hours",
        }))
        self.assertEqual(snap["load"], "0.10 / 0.20 / 0.30")
        self.assertIn("GB", snap["disk_root"])
        _starlette(snap)

    def test_over_cap_counts_drop_to_zero(self):
        snap = self._snapshot(_status(counts={
            "ok": _HUGE, "warn": 1, "down": 0, "stopped": 0,
        }))
        self.assertEqual(snap["counts"]["ok"], 0)
        self.assertEqual(snap["counts"]["warn"], 1)
        _starlette(snap)

    def test_over_cap_system_value_drops_to_none(self):
        snap = self._snapshot(_status(system={
            "load": _HUGE,
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "disk_pct": 20,
            "disk_used_gb": 1,
            "disk_total_gb": 2,
            "uptime": "1.0 hours",
        }))
        self.assertIsNone(snap["load"])
        _starlette(snap)


class FallbackBriefDigitCapTests(unittest.TestCase):
    def test_over_cap_count_does_not_raise(self):
        text = assistant_svc.fallback_brief({
            "counts": {"ok": _HUGE, "warn": 0, "down": 0, "stopped": 0},
            "problems": [],
        }, "en")
        self.assertIn("Overview:", text)
        self.assertIn("0 ok", text)

    def test_over_cap_load_and_problem_name_do_not_raise(self):
        text = assistant_svc.fallback_brief({
            "load": _HUGE,
            "cpu_load_pct": _HUGE,
            "counts": {"ok": 1, "warn": 0, "down": 1, "stopped": 0},
            "problems": [{"name": _HUGE, "state": "down", "detail": "x"}],
        }, "en")
        self.assertIn("Overview:", text)
        self.assertIn("Needs attention", text)
        text.encode("utf-8")

    def test_normal_brief_shape_is_unchanged(self):
        text = assistant_svc.fallback_brief({
            "load": "0.40 / 0.50 / 0.60",
            "cpu_load_pct": 5.0,
            "mem_used_pct": 42,
            "disk_root_pct": 40,
            "disk_root": "200/500 GB",
            "uptime": "3.2 hours",
            "engine_up": True,
            "counts": {"ok": 12, "warn": 1, "down": 0, "stopped": 3},
            "problems": [{"name": "nginx", "state": "warn", "detail": "reload pending"}],
        }, "en")
        self.assertIn("12 ok", text)
        self.assertIn("1 warn", text)
        self.assertIn("Docker on", text)
        self.assertIn("nginx", text)


class RouterDigitCapTests(unittest.TestCase):
    """POST /api/assistant/ask end to end — Starlette dumps the return value."""

    def _ask(self, status):
        body = assistant_api.AskBody(query="", action="brief", locale="en")
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch("hub.status.full_status"),
            mock.patch("hub.ollama_svc.status", return_value={"reachable": False}),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
        ):
            return assistant_api.ask(body)

    def test_over_cap_counts_do_not_500_ask(self):
        # fallback_brief used to raise inside the router's own except
        # handler, which no upper layer catches — a guaranteed 500.
        out = self._ask(_status(counts={"ok": _HUGE, "warn": 0, "down": 0, "stopped": 0}))
        self.assertTrue(out["ok"])
        self.assertIn("Overview:", out["text"])
        _starlette(out)

    def test_over_cap_snapshot_value_does_not_500_ask(self):
        out = self._ask(_status(system={
            "load": _HUGE,
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "disk_pct": 20,
            "disk_used_gb": 1,
            "disk_total_gb": 2,
            "uptime": "1.0 hours",
        }))
        self.assertTrue(out["ok"])
        self.assertIsNone(out["snapshot"]["load"])
        _starlette(out)

    def test_over_cap_and_surrogate_mixed_payload_stays_clean(self):
        out = self._ask(_status(
            system={
                "load": "0.10\ud800",
                "load_pct": _HUGE,
                "mem_used_pct": 10,
                "disk_pct": 20,
                "disk_used_gb": 1,
                "disk_total_gb": 2,
                "uptime": "1.0 hours",
            },
            problems=[{"name": "nginx\ud800", "state": "warn", "detail": _HUGE}],
        ))
        self.assertNotIn("\ud800", out["snapshot"]["load"])
        self.assertNotIn("\ud800", out["text"])
        _starlette(out)


class CatalogFileDigitCapTests(unittest.TestCase):
    """One poisoned number literal must not wipe the whole catalog."""

    def test_over_cap_literal_does_not_wipe_the_panels_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "assistant_panels.json").write_text(
                '[{"id": "logs", "path": "/logs", "weight": ' + _HUGE_DIGITS + "}]",
                encoding="utf-8",
            )
            with mock.patch.object(assistant_svc, "_HERE", root):
                rows = assistant_svc._load_list("assistant_panels.json")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "logs")
        # The poisoned field itself drops to None; the row survives.
        self.assertIsNone(rows[0]["weight"])

    def test_over_cap_literal_does_not_wipe_the_blurbs_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "assistant_blurbs.json").write_text(
                '{"logs": {"en": "Logs."}, "junk": ' + _HUGE_DIGITS + "}",
                encoding="utf-8",
            )
            with mock.patch.object(assistant_svc, "_HERE", root):
                data = assistant_svc._load_object("assistant_blurbs.json")
        self.assertEqual(data["logs"]["en"], "Logs.")

    def test_over_cap_alias_does_not_become_the_none_alias(self):
        panels = ({
            "id": "logs",
            "path": "/logs",
            "title": {"en": "Logs"},
            # What the parse_int hook leaves behind for an over-cap alias.
            "aliases": [None, "journal"],
        },)
        with mock.patch.object(assistant_svc, "PANELS", panels):
            rows = assistant_svc.catalog("en")
            self.assertEqual(rows[0]["aliases"], ["journal"])
            self.assertEqual(assistant_svc.match_panels("none", "en"), [])
            hits = assistant_svc.match_panels("journal", "en")
        self.assertEqual(hits[0]["id"], "logs")


class EngineDownStaysImmuneTests(unittest.TestCase):
    """Ollama vanished / down keeps the deterministic-brief contract."""

    def test_vanished_daemon_falls_back_to_the_template_brief(self):
        # FileNotFoundError from the chat layer (binary / socket vanished)
        # must answer the deterministic brief, not a 500 and not a wipe.
        with (
            mock.patch("hub.status.peek_status", return_value=_status()),
            mock.patch("hub.status.full_status"),
            mock.patch("hub.ups_svc.ups_snapshot", return_value={"present": False}),
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "qwen3.5:4b"}]},
            ),
            mock.patch("hub.ollama_svc.chat", side_effect=FileNotFoundError("ollama")),
        ):
            out = assistant_svc.ask("status", locale="en", action="brief")
        self.assertTrue(out["ok"])
        self.assertFalse(out["used_llm"])
        self.assertIn("Overview:", out["text"])
        _starlette(out)

    def test_coded_errors_keep_their_shape(self):
        with self.assertRaises(HTTPException) as ctx:
            assistant_svc.ask("", action="ask")
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "assistant.query_required")
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
