"""Assistant sweep #5: the unhashable-ups-source 500, fixed via _utf8_text.

A fresh hunt over the mounted assistant routes (GET /api/assistant/catalog,
POST /api/assistant/ask) with a poisoned collector matrix found one genuine
leftover: ``suggest_panels`` tested the raw UPS snapshot value with
``ups.get("source") in {"battery", "ups"}``.  Set membership hashes the
candidate, so an unhashable leftover source (a YAML ``source: [battery]``
list, or a dict) raised TypeError — and it raised *twice*: once out of
``ask()``, and then again inside the router's own error fallback, which
rebuilds the snapshot from the same poisoned collector and calls
``suggest_panels`` with it.  Nothing above catches that second raise, so
POST /api/assistant/ask answered a raw 500 with traceback whenever the UPS
snapshot carried the junk shape.

Fixed with the ``_utf8_text`` probe the module already uses everywhere else:
a bytes leftover (``b"battery"``) coerces to its text and keeps matching,
junk shapes drop the dashboard suggestion — never the turn, never a 500.

The rest of this file pins the classes that a live probe confirmed already
immune, so they stay that way:

* body-parse layer: a >4300-digit number literal anywhere in the request
  body (``json.loads`` raises the digit-cap *ValueError*, not
  JSONDecodeError) answers a coded 4xx; ``Infinity`` / ``1e999`` literals
  answer a 422 whose echoed input is nulled; a lone-surrogate JSON escape
  in a body *key* answers a renderable 422; a bracket nest bomb answers a
  4xx — all UTF-8-renderable, never a 500;
* catalog file loads: a leftover FIFO occupying assistant_panels.json must
  not park the loader (read_text_capped opens O_NONBLOCK and refuses
  non-regular files), and oversize / torn-UTF-8 / nest-bomb / dir-at-path
  leftovers degrade to the empty catalog, never a raise.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import assistant_svc
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_DIGITS = "9" * 5000

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

    def _ask(self, body: dict):
        return self.client.post("/api/assistant/ask", json=body)


class UpsSourceUnhashableRouteTests(_QuietCollectors):
    """The fixed leftover: junk ups source never 500s POST /api/assistant/ask."""

    def _brief_with_ups(self, ups: dict):
        with mock.patch("hub.ups_svc.ups_snapshot", return_value=ups):
            return self._ask({"query": "", "action": "brief", "locale": "en"})

    def test_list_source_answers_the_brief_not_a_500(self):
        # YAML ``source: [battery]`` shape.  Used to TypeError the set
        # membership in suggest_panels — inside the router's own error
        # fallback too, which nothing above catches: a raw 500.
        resp = self._brief_with_ups({
            "present": True, "source": ["battery"], "percent": 50, "charging": False,
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertIn("Overview:", body["text"])
        # The junk shape drops the dashboard suggestion, never the turn.
        self.assertEqual(body["snapshot"]["ups"]["source"], ["battery"])

    def test_dict_source_answers_the_brief_not_a_500(self):
        resp = self._brief_with_ups({
            "present": True, "source": {"kind": "ups"}, "percent": 50, "charging": False,
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertIn("Overview:", body["text"])

    def test_bytes_source_coerces_and_still_suggests_the_dashboard(self):
        # The _utf8_text probe, not an isinstance(x, str) gate: a bytes
        # leftover keeps matching like the bookmarks-name rule.
        resp = self._brief_with_ups({
            "present": True, "source": b"battery", "percent": 50, "charging": False,
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])

    def test_str_source_behaviour_is_unchanged(self):
        resp = self._brief_with_ups({
            "present": True, "source": "battery", "percent": 50, "charging": False,
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])


class SuggestPanelsSourceProbeTests(unittest.TestCase):
    """The probe semantics, held at the function level."""

    def _suggest(self, source):
        return assistant_svc.suggest_panels({
            "counts": {"ok": 1, "warn": 0, "down": 0, "stopped": 0},
            "ups": {"source": source, "percent": 50, "charging": False},
        }, "en")

    def test_unhashable_sources_do_not_raise(self):
        for junk in (["battery"], {"kind": "ups"}, {"battery"}, [["ups"]]):
            out = self._suggest(junk)
            _starlette(out)
            # Junk drops the battery trigger; the default suggestions answer.
            self.assertTrue(out, "suggestions must never wipe")

    def test_bytes_source_matches_like_its_text(self):
        ids = [row["id"] for row in self._suggest(b"battery")]
        self.assertIn("dashboard", ids)

    def test_none_source_is_not_the_none_match(self):
        # str(None) is "None"; it must not start matching anything.
        wanted_default = [row["id"] for row in self._suggest(None)]
        self.assertEqual(wanted_default, ["dashboard", "health"])


class BodyParseLayerStaysImmuneTests(_QuietCollectors):
    """The HTTP body-parse classes, confirmed immune by a live probe."""

    def _raw(self, content: bytes):
        return self.client.post(
            "/api/assistant/ask",
            content=content,
            headers={"content-type": "application/json"},
        )

    def test_huge_int_literal_field_is_a_coded_4xx(self):
        # json.loads of a >4300-digit literal is ValueError, not
        # JSONDecodeError; FastAPI's body-parse catch answers 400.
        resp = self._raw(
            b'{"query": "x", "weight": ' + _HUGE_DIGITS.encode() + b"}"
        )
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        _starlette(resp.json())

    def test_huge_int_literal_whole_body_is_a_coded_4xx(self):
        resp = self._raw(_HUGE_DIGITS.encode())
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        _starlette(resp.json())

    def test_infinity_literal_echo_is_nulled_in_the_422(self):
        # json.loads accepts Infinity / 1e999 as inf; the app-level
        # validation handler must null the echoed input so Starlette's
        # allow_nan=False encoder renders the 422.
        for content in (b'{"query": Infinity}', b'{"query": 1e999}', b'{"query": "x", "junk": NaN}'):
            resp = self._raw(content)
            self.assertEqual(resp.status_code, 422, resp.text[:200])
            body = resp.json()
            _starlette(body)
            for row in body["detail"]:
                self.assertNotIsInstance(row.get("input"), float)

    def test_surrogate_escape_in_a_body_key_is_a_renderable_422(self):
        # Values were pinned in sweep #3; the *key* echo goes through the
        # 422 loc/input and must stay UTF-8-renderable too.
        resp = self._raw(b'{"query": "x", "\\ud800bad": 1}')
        self.assertEqual(resp.status_code, 422, resp.text[:200])
        _starlette(resp.json())

    def test_bracket_nest_bomb_is_a_coded_4xx(self):
        bomb = b"[" * 20000 + b"]" * 20000
        for content in (bomb, b'{"query": "x", "history": ' + bomb + b"}"):
            resp = self._raw(content)
            self.assertIn(resp.status_code, (400, 422), resp.text[:200])
            _starlette(resp.json())

    def test_undecodable_utf8_body_is_a_coded_4xx(self):
        resp = self._raw(b'{"query": "\xff\xfe"}')
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        _starlette(resp.json())


class CatalogFileLeftoverLoadTests(unittest.TestCase):
    """FIFO / oversize / torn catalog files degrade empty, never hang or raise."""

    def test_fifo_at_the_catalog_path_does_not_park_the_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.mkfifo(root / "assistant_panels.json")
            with mock.patch.object(assistant_svc, "_HERE", root):
                t0 = time.monotonic()
                rows = assistant_svc._load_list("assistant_panels.json")
                elapsed = time.monotonic() - t0
        self.assertEqual(rows, [])
        # A blocking FIFO open parks until a writer appears — forever here.
        self.assertLess(elapsed, 5.0)

    def test_oversize_torn_nested_and_dir_leftovers_degrade_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "assistant_blurbs.json").write_text(
                "x" * (300 * 1024), encoding="utf-8",
            )
            (root / "assistant_intents.json").write_bytes(b"\xff\xfe not utf8")
            (root / "assistant_panels.json").write_text(
                "[" * 20000 + "]" * 20000, encoding="utf-8",
            )
            (root / "asdir.json").mkdir()
            with mock.patch.object(assistant_svc, "_HERE", root):
                self.assertEqual(
                    assistant_svc._load_object("assistant_blurbs.json"), {}
                )
                self.assertEqual(
                    assistant_svc._load_object("assistant_intents.json"), {}
                )
                self.assertEqual(
                    assistant_svc._load_list("assistant_panels.json"), []
                )
                self.assertEqual(assistant_svc._load_object("asdir.json"), {})


if __name__ == "__main__":
    unittest.main()
