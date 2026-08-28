"""Assistant sweep #13: BaseException-shaped bombs sailed past every
``except Exception`` net on both assistant JSON routes.

Sweep #12 sealed the default-repr address leak, so a fresh hunt over the
mounted routes (GET /api/assistant/catalog, POST /api/assistant/ask via
``create_app()`` + TestClient, every collector seam bombed) hunted the two
leftover classes jobs13/nas13 already found elsewhere:

* every guard in ``hub/assistant_svc.py`` and in the assistant router —
  including the router's own keep-working fallback, where nothing above
  catches a re-raise — stopped at ``except Exception``.  A leftover whose
  hooks raise a *BaseException* subclass (the watchdog/timeout shape) sailed
  past all of them at once: a ``__class__``-property bomb blew ``_isa`` — the
  gate every sanitizer arm stands on — raw out of both routes; a dict-subclass
  ``get`` bomb and a stored shadow-key ``__eq__`` bomb blew ``_dget`` past its
  three nets; ``__bool__``/``__str__``/``__int__``/``isoformat`` bombs blew
  ``_truthy``, ``_utf8_text``, ``_safe_int`` and ``_jsonable``'s tail probe;
  and a collector / chat seam raising one killed the turn instead of
  degrading it to the template brief.
* the claimed-base decode gap (the jobs13/nas13 ``_decode_bytes`` rule):
  the decode base was picked off the *claimed* ``__class__``, so a genuine
  ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
  ``bytes.decode``, refused by the descriptor, and its perfectly decodable
  content went blank — a problem detail or a chat reply emptied at the
  wrong rank even though the text was right there.

Every guard now re-raises genuine control flow (KeyboardInterrupt,
SystemExit) and launders everything else BaseException-shaped exactly like
its Exception twin; the decode arm tries both bases, real layout
first-come.  The stronger union guards stay pinned: the digit-cap
``ValueError`` probes and the parse_int hook keep their exact behavior.
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


class _Boom(BaseException):
    """A BaseException subclass that is *not* Exception — the shape every
    ``except Exception`` net used to wave straight through."""


class _ClassBomb:
    """``__class__`` property raises a BaseException subclass: blows the
    ``isinstance`` probe itself — the gate every sanitizer arm stands on."""

    @property
    def __class__(self):
        raise _Boom("class bomb")


class _BoolBomb:
    def __bool__(self):
        raise _Boom("bool bomb")


class _StrBomb:
    def __str__(self):
        raise _Boom("str bomb")


class _IntBomb:
    def __int__(self):
        raise _Boom("int bomb")


class _GetBomb(dict):
    """Real dict storage underneath a poisoned bound ``get``."""

    def get(self, *args, **kwargs):
        raise _Boom("get bomb")


class _EqBombKey(str):
    """A stored key that shares its hash with the probe key but raises a
    BaseException subclass from ``__eq__`` — even ``dict.get`` dispatches
    the stored key's comparison."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise _Boom("eq bomb")


class _IsoCallBomb:
    def isoformat(self):
        raise _Boom("iso call bomb")


class _IsoAttrBomb:
    @property
    def isoformat(self):
        raise _Boom("iso attr bomb")


class _LyingBytearray(bytearray):
    """Genuine bytearray storage whose ``__class__`` claims ``bytes`` — the
    claimed-base pick handed it to ``bytes.decode``, which refused it."""

    @property
    def __class__(self):
        return bytes


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


class SnapshotBaseExceptionBombTests(_QuietCollectors):
    """The found escape: a BaseException-subclass bomb in a status cell rode
    past every ``except Exception`` net — including the router's own error
    fallback, which rebuilds the same snapshot with nothing above to catch a
    second raise."""

    def _bombed_status(self, **overrides):
        status = _status()
        for slot, value in overrides.items():
            if slot in status["system"]:
                status["system"][slot] = value
            else:
                status[slot] = value
        return status

    def test_class_bomb_engine_up_launders_to_docker_off(self):
        status = self._bombed_status(engine_up=_ClassBomb())
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertIsNone(body["snapshot"]["engine_up"])
        self.assertIn("Docker off", body["text"])

    def test_get_bomb_status_wrapper_keeps_its_real_rows(self):
        # The ups/ollama settings rule, BaseException edition: the bound
        # ``get`` is poisoned but the storage underneath is sane.
        with mock.patch("hub.status.peek_status", return_value=_GetBomb(_status())):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_shadow_key_eq_bomb_recovers_the_section(self):
        # The stored key's __eq__ raises a BaseException subclass out of
        # even dict.get; the items-walk salvage still finds the real rows.
        status = _status()
        status[_EqBombKey("system")] = status.pop("system")
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")

    def test_int_bomb_count_drops_to_zero(self):
        status = self._bombed_status(
            counts={"ok": 3, "warn": 0, "down": _IntBomb(), "stopped": 0},
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["counts"]["down"], 0)
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_str_bomb_detail_drops_to_an_empty_cell(self):
        status = self._bombed_status(
            problems=[{"name": "svc", "state": "down", "detail": _StrBomb()}],
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        row = body["snapshot"]["problems"][0]
        self.assertEqual(row["name"], "svc")
        self.assertEqual(row["detail"], "")

    def test_bool_bomb_reachable_launders_to_false(self):
        with mock.patch(
            "hub.ollama_svc.status",
            return_value={"reachable": _BoolBomb(), "resident": []},
        ):
            body = self._ok(self._ask())
        self.assertIs(body["snapshot"]["ollama"]["reachable"], False)

    def test_every_action_answers_200_with_a_fully_bombed_snapshot(self):
        status = self._bombed_status(
            disk_used_gb=_ClassBomb(),
            uptime=_StrBomb(),
            engine_up=_ClassBomb(),
            counts={"ok": 3, "warn": 0, "down": _IntBomb(), "stopped": 0},
            problems=[{"name": "svc", "state": "down", "detail": _StrBomb()}],
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            for body in _ALL_ACTIONS:
                self._ok(self._ask(**body))
            self._ok(self.client.get("/api/assistant/catalog?locale=en"))


class CatalogBaseExceptionBombTests(_QuietCollectors):
    """A class-bomb row / cell used to blow ``_isa`` raw out of the catalog
    walk, and a ``get``-bomb title map raised past every net."""

    def test_class_bomb_rows_drop_the_sane_row_survives(self):
        rows = (
            _ClassBomb(),
            {"id": _ClassBomb(), "path": "/x", "title": {"en": "X"}},
            _DOCKER,
        )
        with mock.patch.object(assistant_svc, "PANELS", rows):
            catalog = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
            for body in _ALL_ACTIONS:
                self._ok(self._ask(**body))
        self.assertEqual([p["id"] for p in catalog["panels"]], ["docker"])

    def test_get_bomb_title_map_keeps_its_real_title(self):
        rows = (
            {"id": "ollama", "path": "/ollama", "title": _GetBomb({"en": "Ollama Panel"})},
            _DOCKER,
        )
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        by_id = {p["id"]: p for p in body["panels"]}
        self.assertEqual(by_id["ollama"]["title"], "Ollama Panel")


class ChatSeamBaseExceptionBombTests(_QuietCollectors):
    """A poisoned chat seam / result used to kill the turn raw instead of
    degrading it — or losing an answer the call already had."""

    def _llm(self, chat):
        return (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch("hub.ollama_svc.chat", **chat),
        )

    def test_chat_raising_a_baseexception_degrades_to_the_template_brief(self):
        status_p, chat_p = self._llm({"side_effect": _Boom("chat bomb")})
        with status_p, chat_p:
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertFalse(body["used_llm"])
        self.assertIn("Overview:", body["text"])

    def test_get_bomb_chat_result_keeps_the_answer(self):
        status_p, chat_p = self._llm(
            {"return_value": _GetBomb({"content": "LLM SAYS HI", "model": "m"})},
        )
        with status_p, chat_p:
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertTrue(body["used_llm"])
        self.assertEqual(body["text"], "LLM SAYS HI")
        self.assertEqual(body["model"], "m")

    def test_isoformat_bombs_drop_the_duration_keep_the_answer(self):
        for bomb in (_IsoCallBomb(), _IsoAttrBomb()):
            status_p, chat_p = self._llm(
                {"return_value": {"content": "LLM SAYS HI", "model": "m", "duration_s": bomb}},
            )
            with status_p, chat_p:
                body = self._ok(self._ask(query="hi", action="ask"))
            self.assertEqual(body["text"], "LLM SAYS HI")
            self.assertIsNone(body["duration_s"])

    def test_status_seam_raising_a_baseexception_drops_the_section(self):
        with mock.patch("hub.ollama_svc.status", side_effect=_Boom("status bomb")):
            body = self._ok(self._ask())
        self.assertNotIn("ollama", body["snapshot"])
        self.assertIn("Overview:", body["text"])

    def test_ups_seam_raising_a_baseexception_drops_the_section(self):
        with mock.patch("hub.ups_svc.ups_snapshot", side_effect=_Boom("ups bomb")):
            body = self._ok(self._ask())
        self.assertNotIn("ups", body["snapshot"])


class RouterFallbackBaseExceptionTests(_QuietCollectors):
    """The router's own nets: a BaseException subclass out of ask() /
    build_snapshot() / catalog() used to skip the keep-working fallback."""

    def test_ask_seam_baseexception_degrades_to_the_fallback_brief(self):
        with mock.patch("hub.assistant_svc.ask", side_effect=_Boom("ask bomb")):
            body = self._ok(self._ask())
        self.assertTrue(body["ok"])
        self.assertEqual(body["kind"], "brief")
        self.assertIn("Overview:", body["text"])

    def test_double_bomb_ask_and_snapshot_still_answers_200(self):
        with (
            mock.patch("hub.assistant_svc.ask", side_effect=_Boom("ask bomb")),
            mock.patch("hub.assistant_svc.build_snapshot", side_effect=_Boom("snap bomb")),
        ):
            body = self._ok(self._ask())
        self.assertTrue(body["ok"])
        self.assertEqual(body["snapshot"]["counts"], {"ok": 0, "warn": 0, "down": 0, "stopped": 0})

    def test_catalog_seam_baseexception_answers_the_empty_catalog(self):
        with mock.patch("hub.assistant_svc.catalog", side_effect=_Boom("catalog bomb")):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        self.assertTrue(body["ok"])
        self.assertEqual(body["panels"], [])


class ClaimedBaseDecodeTests(_QuietCollectors):
    """The jobs13/nas13 decode rule: a genuine bytearray lying ``bytes``
    used to blank its perfectly decodable cell at the wrong rank."""

    def test_lying_bytearray_detail_keeps_its_text(self):
        status = _status()
        status["problems"] = [
            {"name": "svc", "state": "down", "detail": _LyingBytearray(b"battery low")},
        ]
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["problems"][0]["detail"], "battery low")

    def test_lying_bytearray_chat_reply_keeps_the_answer(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={"content": _LyingBytearray(b"LLM SAYS HI"), "model": "m"},
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertTrue(body["used_llm"])
        self.assertEqual(body["text"], "LLM SAYS HI")


class ControlFlowPassthroughTests(unittest.TestCase):
    """Genuine control flow must keep propagating through the bomb guards:
    swallowing a Ctrl-C or an interpreter shutdown would turn the sanitizer
    into a hang."""

    def test_isa_reraises_a_keyboard_interrupt(self):
        class _CtrlC:
            @property
            def __class__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            assistant_svc._isa(_CtrlC(), dict)

    def test_truthy_reraises_a_system_exit(self):
        class _Exit:
            def __bool__(self):
                raise SystemExit

        with self.assertRaises(SystemExit):
            assistant_svc._truthy(_Exit())

    def test_dget_reraises_a_keyboard_interrupt(self):
        class _CtrlCGet(dict):
            def get(self, *args, **kwargs):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            assistant_svc._dget(_CtrlCGet({"a": 1}), "a")

    def test_utf8_text_reraises_a_system_exit(self):
        class _ExitStr:
            def __str__(self):
                raise SystemExit

        with self.assertRaises(SystemExit):
            assistant_svc._utf8_text(_ExitStr())


class ProbeFunctionTests(unittest.TestCase):
    """The broadened guards at the function level, plus the union-guard
    pins: the stronger precise probes must keep their exact behavior."""

    def test_bomb_shapes_launder_like_their_exception_twins(self):
        self.assertIs(assistant_svc._isa(_ClassBomb(), dict), False)
        self.assertIs(assistant_svc._truthy(_BoolBomb()), False)
        self.assertEqual(assistant_svc._safe_int(_IntBomb()), 0)
        self.assertEqual(assistant_svc._safe_int(_IntBomb(), 7), 7)
        self.assertEqual(assistant_svc._utf8_text(_StrBomb()), "")
        self.assertEqual(assistant_svc._dget(_GetBomb({"a": 1}), "a"), 1)
        self.assertIsNone(assistant_svc._jsonable(_ClassBomb()))
        self.assertIsNone(assistant_svc._jsonable(_IsoCallBomb()))
        self.assertEqual(assistant_svc._brief_cell(_StrBomb()), "—")
        self.assertEqual(assistant_svc._reply_text(_StrBomb()), "")

    def test_shadow_key_bomb_launders_out_of_dget(self):
        row = {_EqBombKey("system"): {"uptime": "1.0 hours"}, "other": 1}
        self.assertEqual(
            assistant_svc._dget(row, "system"), {"uptime": "1.0 hours"},
        )

    def test_decode_bytes_tries_both_bases_real_layout_first_come(self):
        self.assertEqual(assistant_svc._decode_bytes(b"hi"), "hi")
        self.assertEqual(assistant_svc._decode_bytes(bytearray(b"hi")), "hi")
        self.assertEqual(assistant_svc._decode_bytes(_LyingBytearray(b"hi")), "hi")
        self.assertEqual(assistant_svc._utf8_text(_LyingBytearray(b"hi")), "hi")
        self.assertEqual(assistant_svc._jsonable(_LyingBytearray(b"hi")), "hi")

    def test_total_liar_still_drops_its_cell(self):
        class _LyingObject:
            @property
            def __class__(self):
                return bytes

        self.assertIsNone(assistant_svc._decode_bytes(_LyingObject()))
        self.assertEqual(assistant_svc._utf8_text(_LyingObject()), "")

    def test_union_guard_pins_stay_exact(self):
        # The digit-cap probes and the parse_int hook keep their precise
        # ValueError semantics — the sweep strengthens, never weakens.
        self.assertIsNone(assistant_svc._capped_json_int("9" * 5000))
        self.assertEqual(assistant_svc._capped_json_int("42"), 42)
        self.assertIsNone(assistant_svc._jsonable(10 ** 5000))
        self.assertEqual(assistant_svc._safe_int(10 ** 5000, 7), 7)
        self.assertEqual(assistant_svc._exact_number(85.0), 85.0)
        self.assertIsNone(assistant_svc._exact_number(float("inf")))


if __name__ == "__main__":
    unittest.main()
