"""Assistant sweep #14: wrong-rank drops behind a lying ``__class__``, the
default-repr heap address still on the wire as a mapping *key*, and a
mid-walk mutation that wiped the ``_dget`` items-walk salvage.

Sweep #13 sealed the BaseException bomb family, so a fresh hunt over the
mounted routes (GET /api/assistant/catalog, POST /api/assistant/ask via
``create_app()`` + TestClient, every collector seam bombed) hunted the
leftover classes modules14/files16/apps14 already found elsewhere:

* ``isinstance`` consults ``value.__class__`` only after the real-MRO check
  misses, so a lying ``__class__`` steered a leftover into the arm of its
  *claim*, the unbound descriptor there rejected the real layout, and an
  early return threw honest renderable storage away at the wrong rank: a
  genuine float disk threshold claiming int lost the "main" suggestion, a
  bytes uptime claiming str vanished to ``None``, a tuple problems cell
  claiming list blanked the "Needs attention" block, a genuine list PANELS
  container claiming tuple wiped the whole Cmd+K catalog, a numeric panel
  id claiming str unlisted its row, and an int count claiming final bool
  zeroed a live down count.  The rejected arms now fall through to the arm
  the *real* storage matches, probed via ``type(value)`` (``_real``) so the
  lie cannot steer the walk twice; a total impostor — a claim with no
  usable layout underneath — keeps the established drops.
* ``_jsonable``'s dict-key path ran bare ``str(k)`` on any non-str/bytes
  key, so a plain-object key rendered the default ``object.__repr__`` — a
  raw heap address — verbatim as a JSON *key* in nested snapshot cells and
  the chat ``duration_s`` on both assistant routes (the sweep-#12 belt only
  covered value cells).  ``_key_text`` applies the same slot probe +
  address-belt scrub and drops just the unrenderable entry.
* ``_dget``'s items-walk salvage iterated the live ``dict.items`` view, so
  a stored key whose ``__class__`` property *mutates the mapping mid-walk*
  RuntimeError'd the walk and wiped the whole section to ``None`` even
  though the sane entry sat right behind it — the walk now snapshots the
  items first (the sweep-#11 materialization rule at ``_dget`` rank).

Control flow (KeyboardInterrupt, SystemExit) keeps propagating, and the
stronger union guards stay pinned: the digit-cap ``ValueError`` probes, the
parse_int hook and the total-liar drops keep their exact behavior.
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


def _liar(claim):
    """A total impostor: ``__class__`` lies *claim* but the real layout is
    nothing usable — must keep the established drops."""

    class _Liar:
        @property
        def __class__(self):
            return claim

    return _Liar()


class _FloatClaimsInt(float):
    """Genuine float storage whose ``__class__`` lies ``int`` — the int
    arm's ``int.__index__`` refused it and dropped the honest number."""

    @property
    def __class__(self):
        return int


class _IntClaimsBool(int):
    """Genuine int storage claiming final ``bool`` — the bool gates used to
    drop the live number to the default at the wrong rank."""

    @property
    def __class__(self):
        return bool


class _IntClaimsStr(int):
    """A numeric panel id claiming ``str`` — the unbound str read refused
    it and the old "" wipe unlisted the whole row."""

    @property
    def __class__(self):
        return str


class _BytesClaimsStr(bytes):
    """Genuine bytes storage claiming ``str`` — ``_jsonable``'s str arm
    refused it and dropped the perfectly decodable cell to ``None``."""

    @property
    def __class__(self):
        return str


class _TupleClaimsList(tuple):
    """Genuine tuple storage claiming ``list`` — ``list.__iter__`` refused
    it and its walkable rows dropped at the wrong rank."""

    @property
    def __class__(self):
        return list


class _ListClaimsTuple(list):
    """Genuine list storage claiming ``tuple`` — the claimed-base pick
    handed it to ``tuple.__iter__``, which refused it."""

    @property
    def __class__(self):
        return tuple


class _ListClaimsDict(list):
    """Genuine list storage claiming ``dict`` — ``dict.items`` refused it
    and the whole sequence vanished to ``None``."""

    @property
    def __class__(self):
        return dict


class _EqBombKey(str):
    """A stored key that shares the probe key's hash but raises from
    ``__eq__`` — forces ``_dget`` past both ``get`` nets into the
    items-walk salvage."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("eq bomb")


class _MutatorKey:
    """A stored key whose ``__class__`` probe mutates the parent mapping
    once — mid-walk, that used to RuntimeError the live items view."""

    parent = None
    fired = False

    @property
    def __class__(self):
        if self.parent is not None and not self.fired:
            object.__setattr__(self, "fired", True)
            self.parent["__planted__"] = 1
        return type(self)


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
_MAIN = {"id": "main", "path": "/main", "title": {"en": "Main"}}
_SERVICES = {"id": "services", "path": "/services", "title": {"en": "Services"}}

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

    def _bombed_status(self, **overrides):
        status = _status()
        for slot, value in overrides.items():
            if slot in status["system"]:
                status["system"][slot] = value
            else:
                status[slot] = value
        return status


class MappingKeyAddressLeakTests(_QuietCollectors):
    """The found leak: a plain-object *key* in a nested snapshot cell rode
    the bare ``str(k)`` of the dict walk onto the wire as a JSON key —
    ``<_Junk object at 0x7f...>``, a raw heap address."""

    def test_junk_key_in_a_nested_snapshot_cell_never_leaks(self):
        status = self._bombed_status(load={"1m": "0.10", _Junk(): "0.20"})
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        # The unrenderable entry drops alone; the sane one survives.
        self.assertEqual(body["snapshot"]["load"], {"1m": "0.10"})
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")

    def test_junk_key_in_the_chat_duration_never_leaks(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={
                    "content": "LLM SAYS HI",
                    "model": "m",
                    "duration_s": {"s": 1.5, _Junk(): 1},
                },
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertEqual(body["text"], "LLM SAYS HI")
        self.assertEqual(body["duration_s"], {"s": 1.5})

    def test_every_action_answers_clean_with_junk_keys_planted(self):
        status = self._bombed_status(
            load={_Junk(): "0.10"},
            counts={"ok": 3, "warn": 0, "down": 0, "stopped": 0, _Junk(): 1},
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            for body in _ALL_ACTIONS:
                self._ok(self._ask(**body))
            self._ok(self.client.get("/api/assistant/catalog?locale=en"))


class SnapshotWrongRankTests(_QuietCollectors):
    """Honest storage behind a lying ``__class__`` used to vanish from the
    snapshot at the wrong rank while its value rendered fine one arm over."""

    def test_bytes_uptime_claiming_str_keeps_its_text(self):
        status = self._bombed_status(uptime=_BytesClaimsStr(b"1.0 hours"))
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")

    def test_float_disk_pct_claiming_int_keeps_the_threshold(self):
        status = self._bombed_status(disk_pct=_FloatClaimsInt(92.5))
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch.object(assistant_svc, "PANELS", (_MAIN, _SANE)),
        ):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["disk_root_pct"], 92.5)
        # suggest_panels reads the recovered number: disk >= 85 names "main".
        self.assertIn("main", [p["id"] for p in body["panels"]])

    def test_int_down_count_claiming_bool_keeps_the_live_number(self):
        status = self._bombed_status(
            counts={"ok": 3, "warn": 0, "down": _IntClaimsBool(2), "stopped": 0},
        )
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch.object(assistant_svc, "PANELS", (_SERVICES, _SANE)),
        ):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["counts"]["down"], 2)
        self.assertIn("2 down", body["text"])
        self.assertIn("services", [p["id"] for p in body["panels"]])

    def test_tuple_problems_claiming_list_keep_the_attention_block(self):
        status = self._bombed_status(
            problems=_TupleClaimsList(
                ({"name": "svc", "state": "down", "detail": "boom"},),
            ),
        )
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["problems"][0]["name"], "svc")
        self.assertIn("Needs attention:", body["text"])

    def test_list_load_cell_claiming_dict_keeps_its_rows(self):
        status = self._bombed_status(load=_ListClaimsDict(["0.10", "0.20"]))
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["load"], ["0.10", "0.20"])

    def test_mutating_key_cannot_wipe_the_dget_salvage_mid_walk(self):
        # The shadow __eq__ bomb forces _dget past both get nets into the
        # items-walk; the mutator key then grew the mapping mid-walk, which
        # used to RuntimeError the live view and wipe the whole section.
        mutator = _MutatorKey()
        status = {}
        status[mutator] = "junk"
        status[_EqBombKey("system")] = _status()["system"]
        status["engine_up"] = True
        status["counts"] = {"ok": 3, "warn": 0, "down": 0, "stopped": 0}
        status["problems"] = []
        mutator.parent = status
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["uptime"], "1.0 hours")


class CatalogWrongRankTests(_QuietCollectors):
    """The catalog container, an aliases cell and a numeric row id behind a
    lying ``__class__`` used to unlist rows the SPA could open fine."""

    def test_list_panels_container_claiming_tuple_keeps_the_catalog(self):
        rows = _ListClaimsTuple([_SANE, _DOCKER])
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
            for payload in _ALL_ACTIONS:
                self._ok(self._ask(**payload))
        self.assertEqual(
            [p["id"] for p in body["panels"]], ["dashboard", "docker"],
        )

    def test_tuple_aliases_claiming_list_keep_the_find_turn(self):
        row = {"id": "docker", "path": "/docker", "title": {"en": "Docker"},
               "aliases": _TupleClaimsList(("whale",))}
        with mock.patch.object(assistant_svc, "PANELS", (row, _SANE)):
            catalog = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
            find = self._ok(self._ask(query="whale", action="find"))
        by_id = {p["id"]: p for p in catalog["panels"]}
        self.assertEqual(by_id["docker"]["aliases"], ["whale"])
        self.assertIn("docker", [p.get("id") for p in find["panels"]])

    def test_numeric_row_id_claiming_str_keeps_its_row(self):
        rows = ({"id": _IntClaimsStr(42), "path": "/x", "title": {"en": "X"}}, _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        self.assertIn("42", [p["id"] for p in body["panels"]])


class ChatSeamWrongRankTests(_QuietCollectors):
    """A chat duration behind a lying ``__class__`` dropped the cell the
    encoder renders fine."""

    def test_float_duration_claiming_int_keeps_the_number(self):
        with (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch(
                "hub.ollama_svc.chat",
                return_value={
                    "content": "LLM SAYS HI",
                    "model": "m",
                    "duration_s": _FloatClaimsInt(1.5),
                },
            ),
        ):
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertEqual(body["text"], "LLM SAYS HI")
        self.assertEqual(body["duration_s"], 1.5)


class ProbeFunctionTests(unittest.TestCase):
    """The fall-through arms at the function level, plus the pins that must
    not move: total impostors keep their drops, exact probes stay exact."""

    def test_jsonable_recovers_honest_storage_behind_the_lie(self):
        self.assertEqual(assistant_svc._jsonable(_FloatClaimsInt(92.5)), 92.5)
        self.assertEqual(assistant_svc._jsonable(_IntClaimsBool(2)), 2)
        self.assertEqual(assistant_svc._jsonable(_BytesClaimsStr(b"hi")), "hi")
        self.assertEqual(assistant_svc._jsonable(_TupleClaimsList((1, 2))), [1, 2])
        self.assertEqual(assistant_svc._jsonable(_ListClaimsDict([1, 2])), [1, 2])
        self.assertEqual(assistant_svc._jsonable(_IntClaimsStr(42)), 42)

    def test_jsonable_total_impostors_keep_their_drops(self):
        for claim in (bool, int, float, str, bytes, bytearray, dict,
                      list, tuple, set, frozenset):
            self.assertIsNone(assistant_svc._jsonable(_liar(claim)), claim)

    def test_jsonable_key_path_drops_the_address_not_the_mapping(self):
        out = assistant_svc._jsonable({_Junk(): 1, "b": 2, b"k": 3})
        self.assertEqual(out, {"b": 2, "k": 3})
        _starlette(out)
        self.assertNotIn(" at 0x", json.dumps(out))

    def test_key_text_keeps_real_storage_drops_junk(self):
        class _StrClaimsBytes(str):
            @property
            def __class__(self):
                return bytes

        self.assertEqual(assistant_svc._key_text(_StrClaimsBytes("k")), "k")
        self.assertEqual(assistant_svc._key_text(_IntClaimsStr(7)), "7")
        self.assertEqual(assistant_svc._key_text("a\ud800b"), "a?b")
        self.assertEqual(assistant_svc._key_text(5), "5")
        self.assertIsNone(assistant_svc._key_text(_Junk()))
        self.assertIsNone(assistant_svc._key_text(_liar(bytes)))

        class _StrBombKey:
            def __str__(self):
                raise RuntimeError("str bomb")

        self.assertIsNone(assistant_svc._key_text(_StrBombKey()))

    def test_safe_int_and_exact_number_recover_the_real_storage(self):
        self.assertEqual(assistant_svc._safe_int(_FloatClaimsInt(3.0)), 3)
        self.assertEqual(assistant_svc._safe_int(_IntClaimsBool(2)), 2)
        self.assertEqual(assistant_svc._exact_number(_FloatClaimsInt(92.5)), 92.5)
        self.assertEqual(assistant_svc._exact_number(_IntClaimsBool(2)), 2)
        # Total impostors and real bools keep the established defaults.
        self.assertEqual(assistant_svc._safe_int(_liar(int), 7), 7)
        self.assertEqual(assistant_svc._safe_int(True, 7), 7)
        self.assertIsNone(assistant_svc._exact_number(_liar(int)))
        self.assertIsNone(assistant_svc._exact_number(True))

    def test_list_and_panel_rows_try_both_bases_first_come(self):
        rows = _TupleClaimsList(({"name": "x"},))
        self.assertEqual(assistant_svc._list_rows(rows), [{"name": "x"}])
        self.assertEqual(assistant_svc._list_rows(_liar(list)), [])
        # An honestly-typed tuple keeps the old list-shaped gate.
        self.assertEqual(assistant_svc._list_rows((1, 2)), [])
        with mock.patch.object(assistant_svc, "PANELS", _ListClaimsTuple([_SANE])):
            self.assertEqual(assistant_svc._panel_rows(), [_SANE])
        for junk in (_liar(tuple), _liar(list), None, 7):
            with mock.patch.object(assistant_svc, "PANELS", junk):
                self.assertEqual(assistant_svc._panel_rows(), [], junk)

    def test_utf8_text_and_panel_id_recover_the_numeric_id(self):
        self.assertEqual(assistant_svc._utf8_text(_IntClaimsStr(42)), "42")
        self.assertEqual(assistant_svc._panel_id(_IntClaimsStr(42)), "42")
        # Junk claiming str keeps the "" drop — its repr never leaks.
        self.assertEqual(assistant_svc._utf8_text(_liar(str)), "")
        self.assertEqual(assistant_svc._panel_id(_liar(str)), "")
        self.assertEqual(assistant_svc._panel_id(True), "")

    def test_dget_items_walk_survives_a_mid_walk_mutation(self):
        mutator = _MutatorKey()
        mapping = {}
        mapping[mutator] = "junk"
        mapping[_EqBombKey("system")] = {"uptime": "1.0 hours"}
        mutator.parent = mapping
        self.assertEqual(
            assistant_svc._dget(mapping, "system"), {"uptime": "1.0 hours"},
        )

    def test_union_guard_pins_stay_exact(self):
        # The digit-cap probes and the parse_int hook keep their precise
        # ValueError semantics — the sweep strengthens, never weakens.
        self.assertIsNone(assistant_svc._capped_json_int("9" * 5000))
        self.assertEqual(assistant_svc._capped_json_int("42"), 42)
        self.assertIsNone(assistant_svc._jsonable(10 ** 5000))
        self.assertEqual(assistant_svc._safe_int(10 ** 5000, 7), 7)
        self.assertIs(assistant_svc._jsonable(True), True)
        self.assertIsNone(assistant_svc._jsonable(float("inf")))


class ControlFlowPassthroughTests(unittest.TestCase):
    """Genuine control flow must keep propagating through the new seams."""

    def test_key_text_reraises_a_keyboard_interrupt(self):
        class _CtrlCKey:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            assistant_svc._key_text(_CtrlCKey())

    def test_jsonable_seq_arm_reraises_a_system_exit(self):
        class _ExitIter(list):
            def __iter__(self):
                raise SystemExit

        # The unbound base read never dispatches the override, so the rows
        # still walk — but a __class__ property raising control flow out of
        # the gate itself must propagate.
        self.assertEqual(assistant_svc._jsonable(_ExitIter([1])), [1])

        class _CtrlCClass:
            @property
            def __class__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            assistant_svc._jsonable(_CtrlCClass())


if __name__ == "__main__":
    unittest.main()
