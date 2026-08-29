"""Fourteenth leftover-500s sweep of the Jobs domain: mid-walk mutation
RuntimeErrors, default ``object.__repr__`` heap-address leaks, and honest
storage thrown away behind a lying ``__class__``.

jobs13 sealed the BaseException-shaped bombs and the both-bases decode, but
three leftover classes survived it in ``hub.jobs``:

* ``_jsonable``'s dict arm iterated the *live* mapping (bound
  ``value.items()``, no snapshot), so a nested value whose hook — a
  ``__class__`` property fired by ``_isinst``'s own probe — resized its host
  row mid-walk raised RuntimeError("dictionary changed size during
  iteration") out of the "never raises" walk: a raw 500 on
  POST /api/maintenance/{tid}/run (the route calls ``maintenance_tasks()``
  bare) and the whole GET /api/maintenance listing — every sibling task —
  degraded to ``[]`` at the wrong rank.
* ``_utf8_text``'s coercion arm ran ``str()`` on any leftover shape, and for
  a type that never overrode ``__str__`` / ``__repr__`` the answer is the
  default ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap
  address — which a junk task ``desc`` / job-row ``rc`` carried verbatim
  into GET /api/maintenance, a junk mapping *key* rendered as the JSON key
  itself, and a bomb exception carrying a junk arg wrote into the
  ``!! error:`` log line the log route serves verbatim.
* ``isinstance`` consults ``value.__class__`` only after the real-MRO check
  misses, so a lying ``__class__`` steered a leftover into the arm of its
  *claim*, the unbound descriptor there rejected the real layout, and an
  early return threw honest renderable storage away at the wrong rank (the
  bookmarks14/modules14 shape): a genuine str name lying ``int`` vanished
  to ``None``, a genuine int id lying ``str`` dropped its whole task, a
  genuine str lying ``bytes`` blanked in ``_decode_bytes``, a genuine
  mapping lying ``str`` degraded to ``""``, and a sequence-subclass
  ``__iter__`` bomb vaporized its perfectly readable C-level log lines
  through the bound ``list()`` dispatch.

The fixes are the ``_real`` type-slot probe with recover-the-real-storage
fall-throughs, unbound ``dict.items`` / ``base.__iter__`` snapshots on every
container walk, the ``object.__repr__`` slot probe plus the address-regex
belt on the one coercion arm (real str/bytes storage stays verbatim data),
and ``_error_text`` at the seam where an exception is coerced.  These tests
plant each leftover against our own handlers in-process and assert 200
bodies with valid UTF-8 JSON, never a raw raise and never a heap address —
and pin control flow still propagating.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import jobs  # noqa: E402

_APP = None
_ADDR = re.compile(r" at 0x[0-9a-fA-F]+>")


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _MidWalkMutator:
    """A leftover value whose ``__class__`` probe resizes its host row once.

    ``_isinst`` reads ``__class__`` when the real-MRO fast check misses, so
    the very first sanitizer gate of the value's own walk fires the hook —
    exactly mid-iteration of the parent dict's walk.
    """

    def __init__(self):
        self.host = None
        self.fired = False

    @property
    def __class__(self):
        if not self.fired and self.host is not None:
            self.fired = True
            self.host.pop("victim", None)
        raise AttributeError("leftover class probe")


def _mutating_row(tid="t1"):
    bomb = _MidWalkMutator()
    row = {"id": tid, "command": "true", "junk": bomb, "victim": 1}
    bomb.host = row
    return row


class _Junk:
    """No ``__str__`` / ``__repr__`` override: renders the default
    ``object.__repr__`` — a raw heap address."""


class _LyingIntStr(str):
    """Genuine str storage whose ``__class__`` lies ``int``."""

    @property
    def __class__(self):
        return int


class _LyingStrInt(int):
    """Genuine int storage whose ``__class__`` lies ``str``."""

    @property
    def __class__(self):
        return str


class _LyingBytesStr(str):
    """Genuine str storage whose ``__class__`` lies ``bytes``."""

    @property
    def __class__(self):
        return bytes


class _LyingStrDict(dict):
    """Genuine mapping storage whose ``__class__`` lies ``str``."""

    @property
    def __class__(self):
        return str


class _LyingIntFloat(float):
    """Genuine float storage whose ``__class__`` lies ``int``."""

    @property
    def __class__(self):
        return int


class _StrImpostor:
    """A total liar: claims str, no text storage underneath at all."""

    @property
    def __class__(self):
        return str


class _IterBombList(list):
    """Renderable C-level storage behind a bombing bound ``__iter__``."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class MidWalkMutationTests(unittest.TestCase):
    """A hook that resizes its host row mid-walk costs only itself —
    never a RuntimeError 500 and never the sibling rows."""

    def test_jsonable_snapshots_the_dict_walk(self):
        row = _mutating_row()
        cleaned = jobs._jsonable(row)  # used to raise RuntimeError
        self.assertIsInstance(cleaned, dict)
        self.assertEqual(cleaned["id"], "t1")
        _starlette(cleaned)

    def test_run_route_survives_a_mid_walk_mutator(self):
        rows = [_mutating_row("t1"), {"id": "ok", "command": "true"}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}), \
                mock.patch.object(jobs, "start_job", lambda task: None):
            r = _client().post("/api/maintenance/t1/run")
        self.assertEqual(r.status_code, 200, r.text[:300])
        _starlette(r.json())

    def test_listing_keeps_the_siblings_of_a_mid_walk_mutator(self):
        rows = [_mutating_row("junk"), {"id": "ok", "command": "true"}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            r = _client().get("/api/maintenance")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        by_id = {t.get("id"): t for t in payload}
        # The whole listing used to degrade to [] at the wrong rank.
        self.assertIn("ok", by_id)
        self.assertIn("junk", by_id)


class AddressLeakTests(unittest.TestCase):
    """Default ``object.__repr__`` shapes never reach a response body."""

    def test_utf8_text_drops_a_default_repr_object(self):
        self.assertEqual(jobs._utf8_text(_Junk()), "")

    def test_utf8_text_belts_an_embedded_address(self):
        class _Carrier:
            def __str__(self):
                return f"wrapped {_Junk()!r} tail"

        self.assertEqual(jobs._utf8_text(_Carrier()), "")

    def test_utf8_text_keeps_real_text_verbatim(self):
        # Real str storage is data, not coerced rendering: an operator's
        # own "at 0x..." text must survive the belt.
        literal = "grep for ' at 0x1234>' in the log"
        self.assertEqual(jobs._utf8_text(literal), literal)

    def test_listing_carries_no_heap_address(self):
        rows = [{"id": "t1", "command": "true", "desc": _Junk(),
                 _Junk(): "junk-keyed"}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            r = _client().get("/api/maintenance")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIsNone(_ADDR.search(r.text), r.text[:300])
        self.assertEqual(r.json()[0]["desc"], "")

    def test_log_route_carries_no_heap_address_from_a_junk_row(self):
        table = {"t1": {"running": False, "rc": _Junk(),
                        "finished": _Junk(), "log": ["done"]}}
        with mock.patch.object(jobs, "_jobs", table):
            r = _client().get("/api/maintenance/t1/log")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIsNone(_ADDR.search(r.text), r.text[:300])

    def test_watchdog_error_line_carries_no_heap_address(self):
        def _boom(*a, **k):
            raise RuntimeError(_Junk())

        log: list[str] = []
        with mock.patch.object(jobs.subprocess, "Popen", _boom):
            rc = jobs.run_watchdog(["true"], timeout=5, log=log)
        self.assertEqual(rc, -1)
        self.assertEqual(len(log), 1)
        self.assertNotRegex(log[0], _ADDR)
        # The diagnosis is kept: the bomb's type name, not a blank line.
        self.assertEqual(log[0], "!! error: RuntimeError")

    def test_watchdog_error_line_keeps_a_real_message(self):
        def _boom(*a, **k):
            raise RuntimeError("disk full")

        log: list[str] = []
        with mock.patch.object(jobs.subprocess, "Popen", _boom):
            self.assertEqual(jobs.run_watchdog(["true"], timeout=5, log=log),
                             -1)
        self.assertEqual(log, ["!! error: disk full"])


class WrongRankRecoveryTests(unittest.TestCase):
    """Honest storage behind a lying ``__class__`` renders through the arm
    its *real* layout matches instead of vanishing at the claimed rank."""

    def test_jsonable_recovers_str_storage_lying_int(self):
        self.assertEqual(jobs._jsonable(_LyingIntStr("Nightly")), "Nightly")

    def test_jsonable_recovers_float_storage_lying_int(self):
        self.assertEqual(jobs._jsonable(_LyingIntFloat(2.5)), 2.5)

    def test_jsonable_recovers_mapping_storage_lying_str(self):
        self.assertEqual(jobs._jsonable(_LyingStrDict({"a": 1})), {"a": 1})

    def test_jsonable_recovers_iter_bomb_list_storage(self):
        self.assertEqual(jobs._jsonable(_IterBombList([1, "x"])), [1, "x"])

    def test_jsonable_still_drops_a_total_impostor(self):
        self.assertEqual(jobs._jsonable(_StrImpostor()), "")

    def test_decode_bytes_recovers_str_storage_lying_bytes(self):
        self.assertEqual(jobs._decode_bytes(_LyingBytesStr("hello")), "hello")

    def test_task_id_recovers_int_storage_lying_str(self):
        self.assertEqual(jobs._task_id(_LyingStrInt(123)), "123")
        # Established drops stay: a real empty id and a total impostor.
        self.assertEqual(jobs._task_id(""), "")
        self.assertEqual(jobs._task_id(_StrImpostor()), "")

    def test_log_lines_recover_iter_bomb_storage(self):
        self.assertEqual(jobs._log_lines(_IterBombList(["line"])), ["line"])

    def test_name_lying_int_survives_into_the_listing(self):
        rows = [{"id": "t1", "command": "true",
                 "name": _LyingIntStr("Nightly cleanup")}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            r = _client().get("/api/maintenance")
        self.assertEqual(r.status_code, 200, r.text[:300])
        by_id = {t.get("id"): t for t in r.json()}
        # The old int-arm drop degraded the honest name to the id.
        self.assertEqual(by_id["t1"]["name"], "Nightly cleanup")

    def test_int_id_lying_str_keeps_its_task_listed_and_runnable(self):
        rows = [{"id": _LyingStrInt(123), "command": "true"}]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": rows}):
            r = _client().get("/api/maintenance")
            self.assertEqual(r.status_code, 200, r.text[:300])
            by_id = {t.get("id"): t for t in r.json()}
            self.assertIn("123", by_id)
            with mock.patch.object(jobs, "start_job", lambda task: None):
                run = _client().post("/api/maintenance/123/run")
        self.assertEqual(run.status_code, 200, run.text[:300])

    def test_log_route_recovers_an_iter_bomb_log_list(self):
        table = {"t1": {"running": False, "rc": 0,
                        "log": _IterBombList(["all done"])}}
        with mock.patch.object(jobs, "_jobs", table):
            r = _client().get("/api/maintenance/t1/log")
        self.assertEqual(r.status_code, 200, r.text[:300])
        # The bound list() dispatch used to vaporize the readable lines.
        self.assertIn("all done", r.json()["log"])


class ControlFlowPassthroughTests(unittest.TestCase):
    """Genuine control flow keeps propagating through the new seams."""

    def test_jsonable_walk_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb:
                __class__ = property(
                    lambda self, _kind=kind: (_ for _ in ()).throw(_kind()))

            with self.subTest(kind=kind.__name__):
                with self.assertRaises(kind):
                    jobs._jsonable({"a": Bomb()})

    def test_error_text_reraises_control_flow(self):
        for kind in (KeyboardInterrupt, SystemExit):
            class Bomb(Exception):
                def __str__(self, _kind=kind):
                    raise _kind()

            with self.subTest(kind=kind.__name__):
                with self.assertRaises(kind):
                    jobs._error_text(Bomb())


class StaysImmunePins(unittest.TestCase):
    """Semantics the recovery fall-throughs must not have changed."""

    def test_genuine_shapes_still_round_trip(self):
        payload = {"id": "t1", "name": "Nightly", "confirm": True,
                   "rc": 0, "ratio": 2.5, "tags": ["a", 1],
                   "nested": {"k": "v"}, 5: "int-key"}
        cleaned = jobs._jsonable(payload)
        self.assertEqual(cleaned["name"], "Nightly")
        self.assertIs(cleaned["confirm"], True)
        self.assertEqual(cleaned["tags"], ["a", 1])
        self.assertEqual(cleaned["nested"], {"k": "v"})
        self.assertEqual(cleaned["5"], "int-key")
        _starlette(cleaned)

    def test_encoder_poisons_still_drop(self):
        self.assertIsNone(jobs._jsonable(float("inf")))
        self.assertIsNone(jobs._jsonable(float("nan")))
        self.assertIsNone(jobs._jsonable(int("1" * 5000, 16)))

    def test_genuine_decode_and_ids_still_hold(self):
        self.assertEqual(jobs._decode_bytes(b"plain"), "plain")
        self.assertEqual(jobs._decode_bytes(bytearray(b"plain")), "plain")
        self.assertEqual(jobs._task_id(" j1 "), "j1")
        self.assertEqual(jobs._task_id(123), "123")
        self.assertEqual(jobs._task_id(True), "")

    def test_real_probe_reads_the_type_slot(self):
        self.assertIs(jobs._real(_LyingStrInt(1), int), True)
        self.assertIs(jobs._real(_LyingStrInt(1), str), False)
        self.assertIs(jobs._real("x", str), True)


class ProductVersionPin(unittest.TestCase):
    def test_product_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
