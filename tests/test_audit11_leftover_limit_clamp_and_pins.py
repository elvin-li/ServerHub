"""Audit leftover sweep #11: the recent() limit clamp, and the wave-11 zoo.

audit9 sealed record()'s shaping against ``__class__``-property bombs, lying
bool impostors and hash-shadowing kwargs keys.  This sweep re-hunted both
audit readers and record paths over the real mounted app (create_app +
TestClient, raise_server_exceptions=False) with the wave-10/11 shapes those
pins do not hold — stateful/flip-flop lying ``__class__`` impostors,
plain-object hash-shadow keys, self-``__str__`` encode bombs, isoformat
bombs that answer with more bombs, arithmetic >4300-digit ints, and hostile
rows already on disk — and found one live raise:

* **fixed, raise out of recent()** — the limit clamp caught only
  ``(TypeError, ValueError, OverflowError)`` around ``int(limit)``, but
  ``int()`` runs the object's own ``__int__``/``__index__``: a leftover
  whose slot raises RuntimeError (or an int *subclass* whose ``__int__``
  bombs) raised straight out of hub.audit.recent — the reader whose whole
  job is answering "who did this" no matter what.  terminal_svc's
  recent_audit already survived the identical shapes through its ``_isa``
  bool gate + ``except Exception``; recent() now carries the same clamp,
  and a bool / bool-liar limit reads as the default rather than as
  1-row nonsense.

Everything else probed this sweep was already dead; the pins below keep it
that way:

* stateful and flip-flop lying ``__class__`` impostors cost only their own
  field (the unbound base coercions refuse them);
* a plain-object hash-shadow key (not a str subclass — ``__hash__`` matches
  a sibling's text, ``__eq__`` raises) nested in a detail dict costs only
  itself;
* a secret-named self-``__str__``/``lower``/``__contains__`` bomb key still
  classifies as secret and never reaches disk;
* isoformat property bombs, isoformat() returning ``self`` (unbounded
  recursion) and isoformat() returning a further bomb all degrade to None;
* an arithmetic >4300-digit int (and an int-subclass carrying one) drops
  field-level, never the line;
* hostile rows already on disk — over-cap ints top-level and nested,
  ``1e99999`` / ``Infinity`` / ``NaN``, lone-surrogate keys, torn JSON,
  a 200-deep nest, non-dict rows — leave both listing routes answering
  200 with the honest rows intact;
* a FIFO or directory squatting on either trail path leaves record()/
  _audit() silent and both listing routes answering 200.

No new error codes: everything degrades to defaults or drops field-level,
so no locale keys move.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, terminal_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _IntBomb:
    """``int(x)`` runs ``__int__``; RuntimeError is off the old shortlist."""

    def __int__(self):
        raise RuntimeError("int bomb")


class _IndexBomb:
    def __index__(self):
        raise RuntimeError("index bomb")


class _IntSubIntBomb(int):
    """A *real* int underneath; ``int(x)`` still runs the subclass slot."""

    def __int__(self):
        raise RuntimeError("subclass int bomb")


def _bool_liar():
    return type(
        "BoolLiar", (), {"__class__": property(lambda self: bool)}
    )()


def _stateful_liar(claimed, answers=1):
    """``__class__`` answers *claimed* for the first read(s), then raises."""
    state = {"n": 0}

    def _cls(self):
        state["n"] += 1
        if state["n"] <= answers:
            return claimed
        raise RuntimeError("stateful class bomb")

    return type("StatefulLiar", (), {"__class__": property(_cls)})()


def _flip_liar(a, b):
    """``__class__`` alternates between two claims on successive reads."""
    state = {"n": 0}

    def _cls(self):
        state["n"] += 1
        return a if state["n"] % 2 else b

    return type("FlipLiar", (), {"__class__": property(_cls)})()


class _PlainShadowKey:
    """Not a str at all: hashes like its text, equality raises."""

    def __init__(self, text):
        self._t = text

    def __hash__(self):
        return hash(self._t)

    def __eq__(self, other):
        raise RuntimeError("plain shadow eq bomb")

    __ne__ = __eq__

    def __str__(self):
        return self._t


class _SelfStrBombKey(str):
    """``str()`` and ``lower()`` hand back ``self``; every bound probe a
    naive classifier would run against it raises."""

    def __str__(self):
        return self

    def lower(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")

    def strip(self):
        raise RuntimeError("strip bomb")

    def __contains__(self, item):
        raise RuntimeError("contains bomb")


class _IsoPropBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")


class _IsoReturnsSelf:
    def isoformat(self):
        return self


class _IsoReturnsBomb:
    def isoformat(self):
        return _stateful_liar(dict, 0)


#: >4300 decimal digits, built arithmetically — ``int("9"*5000)`` is itself
#: the digit-cap ValueError, which is the point of the shape.
_HUGE = 16 ** 5000


class _HugeIntSub(int):
    pass


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit11-pin-"))
        self.auth_path = self.dir / "auth-audit.jsonl"
        self.term_path = self.dir / "terminal-audit.jsonl"
        for target, name, path in (
            (audit, "AUDIT_PATH", self.auth_path),
            (terminal_svc, "AUDIT_PATH", self.term_path),
        ):
            patched = mock.patch.object(target, name, path)
            patched.start()
            self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _record(self, event="auth.login.failed", **fields) -> dict:
        entry = audit.record(event, **fields)
        _starlette(entry)
        return entry

    def _rows(self) -> list[dict]:
        rows = audit.recent(10)
        _starlette(rows)
        return rows

    def _http_body(self, url="/api/audit/auth?limit=100") -> dict:
        resp = _client().get(url)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class RecentLimitClampTests(_TrailCase):
    """The fix: a leftover limit must degrade to the default, never raise."""

    def setUp(self):
        super().setUp()
        for i in range(3):
            audit.record("auth.login.ok", username=f"amy{i}")

    def test_int_bomb_limit_reads_the_default_window(self):
        # Pre-fix: int(limit) ran the bomb's __int__, RuntimeError is not on
        # the (TypeError, ValueError, OverflowError) shortlist, and recent()
        # raised out of the one reader built to answer no matter what.
        rows = audit.recent(_IntBomb())
        _starlette(rows)
        self.assertEqual(len(rows), 3)

    def test_index_bomb_limit_reads_the_default_window(self):
        rows = audit.recent(_IndexBomb())
        _starlette(rows)
        self.assertEqual(len(rows), 3)

    def test_int_subclass_int_bomb_limit_reads_the_default_window(self):
        # The nastier shape: a *real* int underneath, so every isinstance
        # gate passes — int() still runs the subclass's own bombing slot.
        rows = audit.recent(_IntSubIntBomb(2))
        _starlette(rows)
        self.assertEqual(len(rows), 3)

    def test_bool_and_bool_liar_limits_read_the_default_window(self):
        # A bool limit is a caller bug, not a request for 1 row; the liar
        # (lying __class__ property) must fail closed the same way.
        for lim in (True, False, _bool_liar(), None):
            rows = audit.recent(lim)
            _starlette(rows)
            self.assertEqual(len(rows), 3, f"limit={lim!r}")

    def test_honest_limits_still_clamp(self):
        self.assertEqual(len(audit.recent(2)), 2)
        self.assertEqual(len(audit.recent(-5)), 1)
        self.assertEqual(len(audit.recent(10**9)), 3)

    def test_terminal_recent_audit_survives_the_same_limits(self):
        # Parity pin: the clamp recent() now copies must keep holding on the
        # terminal trail too.
        terminal_svc._audit({"ts": 1, "target": "host", "command": "x"})
        for lim in (_IntBomb(), _IndexBomb(), _IntSubIntBomb(2), _bool_liar()):
            rows = terminal_svc.recent_audit(lim)
            _starlette(rows)
            self.assertEqual(len(rows), 1, f"limit={lim!r}")


class StatefulLiarStaysImmuneTests(_TrailCase):
    """Impostors whose ``__class__`` answers change between reads cost only
    their own field — probed fresh this sweep and found already dead."""

    def test_stateful_and_flip_liars_cost_only_their_fields(self):
        entry = self._record(
            username="amy",
            once=_stateful_liar(dict, 1),
            flip=_flip_liar(dict, str),
            flipb=_flip_liar(bytes, bytearray),
        )
        self.assertEqual(entry.get("username"), "amy")
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("username"), "amy")

    def test_http_read_after_stateful_liars_answers_200(self):
        audit.record(
            "auth.login.ok", username="amy", junk=_stateful_liar(str, 1)
        )
        body = self._http_body()
        self.assertEqual(body["entries"][0].get("username"), "amy")


class PlainShadowKeyStaysImmuneTests(_TrailCase):
    """A hash-shadowing *plain object* key (audit9 pinned only the str
    subclass) must cost itself, never the siblings."""

    def test_plain_shadow_key_in_a_detail_dict_keeps_the_siblings(self):
        detail = {}
        detail[_PlainShadowKey("note")] = "v"
        detail["ok"] = 1
        entry = self._record(username="amy", detail=detail)
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("detail", {}).get("ok"), 1)
        self.assertEqual(self._rows()[0].get("detail", {}).get("ok"), 1)

    def test_secret_named_self_str_bomb_key_never_reaches_disk(self):
        # The classifier runs unbound str.lower on an exact-str copy; the
        # bomb's hostile __contains__/encode never execute, and the value
        # behind the secret-shaped name still vanishes.
        entry = self._record(
            **{_SelfStrBombKey("password"): "hunter2", "username": "amy"}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("password", entry)
        self.assertNotIn(
            "hunter2", self.auth_path.read_text(encoding="utf-8")
        )


class IsoformatBombStaysImmuneTests(_TrailCase):
    def test_isoformat_shapes_cost_only_their_fields(self):
        entry = self._record(
            username="amy",
            prop=_IsoPropBomb(),
            loops=_IsoReturnsSelf(),
            more=_IsoReturnsBomb(),
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._rows()[0].get("username"), "amy")


class HugeIntStaysImmuneTests(_TrailCase):
    def test_over_cap_int_and_subclass_drop_field_level(self):
        entry = self._record(username="amy", n=_HUGE, m=_HugeIntSub(_HUGE))
        self.assertEqual(entry.get("username"), "amy")
        self.assertIsNone(entry.get("n"))
        self.assertIsNone(entry.get("m"))
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("username"), "amy")


class HostileDiskRowsStayImmuneTests(_TrailCase):
    """Rows another writer left on disk must never 500 either listing route."""

    _ROWS = [
        '{"ts": "t", "event": "e", "n": ' + "9" * 5000 + ', "who": "amy"}',
        '{"ts": "t", "event": "e", "deep": {"a": {"b": ' + "9" * 5000 + "}}}",
        '{"ts": "t", "event": "e", "f": 1e99999}',
        '{"ts": "t", "event": "e", "f": Infinity}',
        '{"ts": "t", "event": "e", "f": NaN}',
        '{"\\ud800key": "v", "event": "e"}',
        '{"ts": "t", "event": "e", "s": "\\ud800"}',
        '["not", "a", "dict"]',
        '"just a string"',
        "9" * 5000,
        '{"nest": ' + "[" * 200 + "1" + "]" * 200 + "}",
        "{torn json",
        '{"ts": "t", "event": "auth.login.ok", "username": "amy"}',
    ]

    def test_auth_route_answers_200_and_keeps_the_honest_row(self):
        self.auth_path.write_text("\n".join(self._ROWS) + "\n", encoding="utf-8")
        body = self._http_body()
        events = [e.get("event") for e in body["entries"]]
        self.assertIn("auth.login.ok", events)
        # The over-cap int costs its field, not its row.
        first = body["entries"][0]
        self.assertEqual(first.get("who"), "amy")
        self.assertIsNone(first.get("n"))

    def test_terminal_route_answers_200_over_the_same_rows(self):
        self.term_path.write_text("\n".join(self._ROWS) + "\n", encoding="utf-8")
        body = self._http_body("/api/terminal/history?limit=100")
        self.assertTrue(
            any(e.get("username") == "amy" for e in body["entries"])
        )


class TrailPathSquattersStayImmuneTests(_TrailCase):
    """A FIFO or directory on the trail path: record() stays silent, the
    listing routes answer 200 — never a hang, never a 500."""

    def test_fifo_squatting_on_both_trails(self):
        self.auth_path.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(self.auth_path)
        os.mkfifo(self.term_path)
        entry = audit.record("auth.login.ok", username="amy")
        _starlette(entry)
        self.assertEqual(entry.get("username"), "amy")
        terminal_svc._audit({"ts": 1, "target": "host", "command": "x"})
        self.assertEqual(self._http_body()["entries"], [])
        self.assertEqual(
            self._http_body("/api/terminal/history")["entries"], []
        )

    def test_directory_squatting_on_both_trails(self):
        self.auth_path.mkdir()
        self.term_path.mkdir()
        entry = audit.record("auth.login.ok", username="amy")
        _starlette(entry)
        terminal_svc._audit({"ts": 1, "target": "host", "command": "x"})
        self.assertEqual(self._http_body()["entries"], [])
        self.assertEqual(
            self._http_body("/api/terminal/history")["entries"], []
        )


class RouteLimitJunkStaysImmuneTests(_TrailCase):
    """Absurd query strings must be a 4xx (validation), never a 500."""

    def test_huge_and_junk_limits_answer_4xx(self):
        audit.record("auth.login.ok", username="amy")
        for q in ("9" * 5000, "1e400", "nan", "inf", "0x10",
                  "-" + "9" * 5000):
            for url in ("/api/audit/auth", "/api/terminal/history"):
                resp = _client().get(f"{url}?limit={q}")
                self.assertLess(
                    resp.status_code, 500, f"{url}?limit={q[:20]}"
                )
                _starlette(resp.json())


if __name__ == "__main__":
    unittest.main()
