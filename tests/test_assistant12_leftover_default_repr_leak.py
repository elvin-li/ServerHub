"""Assistant sweep #12: plain-object junk rendered its default repr — a raw
heap address — into both assistant JSON routes.

Sweep #11 sealed the poisoned PANELS *container* and dropped the
lying-``__class__`` impostors, so a fresh hunt over the mounted routes
(GET /api/assistant/catalog, POST /api/assistant/ask via ``create_app()`` +
TestClient, every collector seam bombed) found **no remaining 500** — but it
found one systemic leak the impostor fixes never covered:

* ``_utf8_text``'s free-text arm coerced *any* leftover through ``str()``.
  A type that never overrode ``__str__``/``__repr__`` answers the default
  ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap address —
  and that text rode verbatim into the response body wherever a cell is
  rendered as text rather than walked by ``_jsonable``: the snapshot's
  ``disk_root`` f-string, a problem ``detail``, a catalog title / blurb /
  alias, and the chat reply itself on POST /api/assistant/ask.
* a *flickering* ``__class__`` property (claims ``str`` on one probe, tells
  the truth on the next) passed an ``_isa(..., str)`` gate at the call site,
  then missed both storage gates inside ``_utf8_text`` and fell into the
  same free arm — leaking an address through a panel ``id`` / ``path`` and
  the chat ``model`` cell that the sweep-#9/#11 liar drops had sealed for
  *stable* liars.
* a function / bound-method leftover and a container cell whose *rendering*
  embeds a default repr (``{'x': <_Junk object at 0x...>}``) carry the
  address inside a C-level or container ``__repr__`` the type-slot probe
  cannot see.

Sealed in ``_utf8_text`` only — the coercion arm, never real str/bytes
storage: a type whose only rendering is the default ``object.__repr__``
drops to ""; anything the coercion renders that still carries CPython's
angle-repr address shape (``... at 0x7f...>``) drops the same way.  Every
caller's existing empty-cell branch launders the junk: the title falls back
to the row id, an alias drops alone, the brief cell answers its em-dash
placeholder, and a junk chat reply degrades the turn to the template brief.
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


class _Junk:
    """A plain leftover object: no ``__str__``/``__repr__`` of its own, so
    its only rendering is the default ``<_Junk object at 0x...>``."""


def _flicker(claim):
    """``__class__`` claims *claim* on odd probes and tells the truth on
    even ones — passes an ``_isa`` gate, then misses the next."""
    state = {"n": 0}

    class _Flicker:
        @property
        def __class__(self):
            state["n"] += 1
            if state["n"] % 2 == 0:
                return type(self)
            return claim

    return _Flicker()


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
        self.assertNotIn(" at 0x", resp.text)
        body = resp.json()
        _starlette(body)
        return body


class SnapshotCellAddressLeakTests(_QuietCollectors):
    """The found leak: a plain-object snapshot cell rendered its default
    repr into the response text of POST /api/assistant/ask."""

    def _bombed_status(self, **overrides):
        status = _status()
        for slot, value in overrides.items():
            if slot in status["system"]:
                status["system"][slot] = value
            else:
                status[slot] = value
        return status

    def test_disk_size_junk_drops_from_the_disk_root_text(self):
        status = self._bombed_status(disk_used_gb=_Junk(), disk_total_gb=_Junk())
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        # The cell launders to empty, the rest of the line survives.
        self.assertEqual(body["snapshot"]["disk_root"], "/ GB")
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")

    def test_problem_detail_junk_drops_to_an_empty_cell(self):
        status = self._bombed_status(
            problems=[{"name": "svc", "state": "down", "detail": _Junk()}],
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        row = body["snapshot"]["problems"][0]
        self.assertEqual(row["name"], "svc")
        self.assertEqual(row["detail"], "")

    def test_container_detail_wrapping_junk_cannot_smuggle_the_address(self):
        # The rendering of a sane-looking dict cell embeds the nested
        # default repr — the belt regex drops the whole coerced cell.
        status = self._bombed_status(
            problems=[{"name": "svc", "state": "down", "detail": {"x": _Junk()}}],
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["problems"][0]["detail"], "")

    def test_every_action_answers_200_with_junk_cells(self):
        status = self._bombed_status(
            disk_used_gb=_Junk(),
            uptime=lambda: 1,
            problems=[{"name": "svc", "state": "down", "detail": [].append}],
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            for body in _ALL_ACTIONS:
                self._ok(self._ask(**body))
            self._ok(self.client.get("/api/assistant/catalog?locale=en"))


class CatalogCellAddressLeakTests(_QuietCollectors):
    """Junk title / blurb / alias cells leaked the same default repr into
    GET /api/assistant/catalog and every find / suggested row."""

    def test_junk_title_falls_back_to_the_row_id(self):
        rows = ({"id": "ollama", "path": "/ollama", "title": {"en": _Junk()}}, _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        by_id = {p["id"]: p for p in body["panels"]}
        self.assertEqual(by_id["ollama"]["title"], "ollama")

    def test_junk_alias_drops_alone_the_row_survives(self):
        row = {"id": "docker", "path": "/docker", "title": {"en": "Docker"},
               "aliases": [_Junk(), "docker"]}
        with mock.patch.object(assistant_svc, "PANELS", (row, _SANE)):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
            find = self._ok(self._ask(query="docker", action="find"))
        by_id = {p["id"]: p for p in body["panels"]}
        self.assertEqual(by_id["docker"]["aliases"], ["docker"])
        self.assertIn("docker", [p.get("id") for p in find["panels"]])

    def test_junk_blurb_cell_drops_to_empty(self):
        with (
            mock.patch.object(assistant_svc, "PANELS", (_SANE, _DOCKER)),
            mock.patch.object(assistant_svc, "_BLURBS", {"dashboard": {"en": _Junk()}}),
        ):
            body = self._ok(self._ask(query="", action="page", path="/"))
        here = body["snapshot"].get("here") or {}
        self.assertEqual(here.get("id"), "dashboard")
        self.assertEqual(here.get("blurb"), "")


class FlickeringClassTests(_QuietCollectors):
    """A flickering ``__class__`` passed the call-site ``_isa(..., str)``
    gate, then missed both storage gates inside ``_utf8_text`` and fell into
    the coercion arm the stable liars never reached."""

    def test_flickering_panel_id_and_path_cannot_leak(self):
        rows = (
            {"id": _flicker(str), "path": "/x", "title": {"en": "X"}},
            {"id": "y", "path": _flicker(str), "title": {"en": "Y"}},
            _DOCKER,
        )
        with mock.patch.object(assistant_svc, "PANELS", rows):
            for body in _ALL_ACTIONS:
                self._ok(self._ask(**body))
            catalog = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        self.assertIn("docker", [p["id"] for p in catalog["panels"]])

    def test_flickering_chat_model_falls_back_to_the_picked_model(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": "LLM SAYS HI", "model": _flicker(str)},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertEqual(body["text"], "LLM SAYS HI")
        self.assertEqual(body["model"], "m")


class ChatReplyAddressLeakTests(_QuietCollectors):
    """Junk chat content rendered its default repr as the assistant's
    *answer text*; it launders to the template brief instead."""

    def test_junk_reply_degrades_to_the_template_brief(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": _Junk(), "thinking": _Junk(), "model": "m"},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertFalse(body["used_llm"])
        self.assertIn("Overview:", body["text"])

    def test_function_reply_cell_cannot_leak_either(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": (lambda: 1), "model": "m"},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertFalse(body["used_llm"])


class ProbeFunctionTests(unittest.TestCase):
    """The sealed coercion arm, held at the function level."""

    def test_default_repr_junk_drops_to_empty(self):
        for junk in (_Junk(), object(), lambda: 1, [].append,
                     {"x": _Junk()}, [_Junk(), 1]):
            self.assertEqual(assistant_svc._utf8_text(junk), "", junk)

    def test_renderable_leftovers_keep_their_text(self):
        # The scrub is surgical: everything the module rendered before —
        # numbers, containers of plain data, the recursing type-name
        # fallback, real subclass storage — still renders.
        self.assertEqual(assistant_svc._utf8_text(42), "42")
        self.assertEqual(assistant_svc._utf8_text(3.5), "3.5")
        self.assertEqual(assistant_svc._utf8_text(True), "True")
        self.assertEqual(assistant_svc._utf8_text({"a": 1}), "{'a': 1}")
        self.assertEqual(assistant_svc._utf8_text([1, "x"]), "[1, 'x']")

        class Recursing:
            def __str__(self):
                return str(self)

        self.assertEqual(assistant_svc._utf8_text(Recursing()), "Recursing")

        class StrStrBomb(str):
            def __str__(self):
                raise RuntimeError("str bomb")

        self.assertEqual(assistant_svc._utf8_text(StrStrBomb("kept")), "kept")

    def test_real_str_storage_is_data_and_stays_verbatim(self):
        # Only the coercion arm is scrubbed: an operator-authored string that
        # happens to carry an address-shaped token is real data.
        text = "kernel fault trace <frame at 0xdeadbeef> captured"
        self.assertEqual(assistant_svc._utf8_text(text), text)
        self.assertEqual(assistant_svc._jsonable(text), text)

    def test_custom_repr_carrying_an_address_shape_drops(self):
        class Handle:
            def __repr__(self):
                return f"<Handle at 0x{id(self):x}>"

        self.assertEqual(assistant_svc._utf8_text(Handle()), "")

    def test_brief_cell_answers_the_placeholder_for_junk(self):
        self.assertEqual(assistant_svc._brief_cell(_Junk()), "—")
        self.assertEqual(assistant_svc._brief_cell(lambda: 1), "—")

    def test_reply_text_drops_junk_keeps_real_text(self):
        self.assertEqual(assistant_svc._reply_text(_Junk()), "")
        self.assertEqual(assistant_svc._reply_text("hi"), "hi")
        self.assertEqual(assistant_svc._reply_text(b"hi"), "hi")


if __name__ == "__main__":
    unittest.main()
