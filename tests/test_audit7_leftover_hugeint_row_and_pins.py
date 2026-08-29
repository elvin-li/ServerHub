"""Audit leftover sweep #7: the huge-number row loss, plus fresh clean pins.

audit4..6 sealed the reader against fat lines, squatters and poisoned rows,
and record() against subclass bombs through the unbound base reads.  This
sweep re-hunted GET /api/audit/auth and audit.record() over the real mounted
app (create_app + TestClient, raise_server_exceptions=False) and found one
live leftover:

* **fixed** — ``recent()`` parsed rows with a bare ``safe_json_loads``, so a
  >4300-digit number literal in one row raised CPython's str->int digit-cap
  ValueError — *not* JSONDecodeError — out of ``json.loads`` and the
  except-ValueError skip dropped the **entire row**: a leftover huge
  ``attempts``/``ts`` (a hand-edited line, a restored backup — record()'s own
  ``_jsonable`` never writes one) silently hid a sign-in or a privileged
  mutation from the one trail that exists to answer "who did this and when".
  ``terminal_svc.recent_audit`` fixed the same loss for the command trail
  long ago; ``recent()`` now uses the same ``parse_int`` hook, so the huge
  literal loads as None and the row keeps its event and its sibling fields.

Everything else probed clean and is pinned stays-immune: an under-cap
4000-digit int renders; lone-surrogate escapes in event/key/value scrub; a
raw U+2028 inside a row costs only itself (the tail splitlines() tears it);
100-deep and 300-deep nests answer 200; 1e309 floats null; and record()
absorbs an omni dict-subclass bomb (get/items/keys/values/__bool__/__len__/
__iter__/__contains__/__eq__ all raising), a nested list-subclass iter bomb
holding a dict bomb, a self-``__str__`` encode bomb (an object whose
``__str__`` returns a str subclass whose ``encode`` raises), a ``__class__``
property bomb, and decode-bomb / over-cap-int / memoryview dict keys — each
costing at most its own field, never the line, never the request.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit
from hub.app_factory import create_app
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

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


class _OmniBombDict(dict):
    """Every read a shaping pass might be tempted to trust, raising."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")

    def items(self):
        raise RuntimeError("items bomb")

    def keys(self):
        raise RuntimeError("keys bomb")

    def values(self):
        raise RuntimeError("values bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")

    def __len__(self):
        raise RuntimeError("len bomb")

    def __iter__(self):
        raise RuntimeError("iter bomb")

    def __contains__(self, item):
        raise RuntimeError("contains bomb")

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = None


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")

    def __len__(self):
        raise RuntimeError("list len bomb")

    def __bool__(self):
        raise RuntimeError("list bool bomb")


class _EncodeBombStr(str):
    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")

    def __str__(self):
        return self


class _SelfStrEncodeBomb:
    """``str()`` of this hands back a str *subclass* whose encode raises —
    the shape the unbound ``str.encode`` scrub exists for."""

    def __str__(self):
        return _EncodeBombStr("payload")


class _ClassPropBomb:
    """isinstance() falls back to ``__class__`` when the fast path misses;
    a raising property there escapes any isinstance-shaped probe."""

    @property
    def __class__(self):
        raise RuntimeError("class property bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit7-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _get(self, limit="100"):
        return _client().get(f"/api/audit/auth?limit={limit}")

    def _body(self, limit="100") -> dict:
        resp = self._get(limit)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class HugeNumberRowLossTests(_TrailCase):
    """The live fix: an over-cap number costs its field, not the row."""

    def test_overcap_int_row_keeps_its_event_and_siblings(self):
        # Pre-fix: json.loads raised the digit-cap ValueError for the whole
        # line and recent()'s skip hid this failed sign-in entirely.
        self.path.write_text(
            '{"event":"auth.login.failed","username":"amy","attempts":'
            + "9" * 5000 + "}\n",
            encoding="utf-8",
        )
        body = self._body()
        self.assertEqual(
            [e["event"] for e in body["entries"]], ["auth.login.failed"]
        )
        entry = body["entries"][0]
        self.assertEqual(entry["username"], "amy")
        # The unrenderable number itself degrades to None, the _jsonable drop.
        self.assertIsNone(entry["attempts"])

    def test_negative_overcap_int_row_survives_too(self):
        self.path.write_text(
            '{"event":"auth.login.ok","n":-' + "9" * 5000 + "}\n",
            encoding="utf-8",
        )
        body = self._body()
        self.assertEqual([e["event"] for e in body["entries"]], ["auth.login.ok"])
        self.assertIsNone(body["entries"][0]["n"])

    def test_overcap_int_in_the_event_field_still_lists_the_row(self):
        # Even the event slot poisoned: the row shows (event null) rather
        # than vanishing — an invisible trail line is the worse failure.
        self.path.write_text(
            '{"event":' + "9" * 5000 + ',"username":"amy"}\n'
            '{"event":"auth.logout"}\n',
            encoding="utf-8",
        )
        body = self._body()
        self.assertEqual(len(body["entries"]), 2)
        self.assertIsNone(body["entries"][0]["event"])
        self.assertEqual(body["entries"][0]["username"], "amy")
        self.assertEqual(body["entries"][1]["event"], "auth.logout")

    def test_recent_unit_view_matches_the_http_view(self):
        self.path.write_text(
            '{"event":"auth.login.failed","attempts":' + "9" * 4400 + "}\n",
            encoding="utf-8",
        )
        rows = audit.recent(10)
        _starlette(rows)
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        self.assertIsNone(rows[0]["attempts"])

    def test_undercap_int_still_parses_as_a_number(self):
        # The hook must not widen the drop: a renderable int stays an int.
        self.path.write_text(
            '{"event":"x","n":' + "9" * 4000 + "}\n", encoding="utf-8"
        )
        body = self._body()
        self.assertEqual(body["entries"][0]["n"], int("9" * 4000))


class ReaderStaysImmuneTests(_TrailCase):
    """Fresh disk-poison vectors probed this sweep and found already dead."""

    def test_lone_surrogate_escapes_in_event_key_and_value(self):
        self.path.write_text(
            '{"event":"\\ud800evil","user\\udc00":"a","v":"x\\ud800y"}\n',
            encoding="utf-8",
        )
        body = self._body()
        self.assertEqual(len(body["entries"]), 1)

    def test_raw_u2028_inside_a_row_costs_only_itself(self):
        # tail_file_lines splits on splitlines() boundaries, so a raw
        # LINE SEPARATOR tears the row into two non-JSON halves; both are
        # skipped and the sibling row still answers.
        self.path.write_bytes(
            '{"event":"a\u2028b"}\n'.encode("utf-8")
            + b'{"event":"auth.login.ok"}\n'
        )
        body = self._body()
        self.assertIn(
            "auth.login.ok", [e.get("event") for e in body["entries"]]
        )

    def test_100_deep_nest_over_the_jsonable_cap_answers_200(self):
        row = '{"event":"x","d":' + "[" * 100 + "1" + "]" * 100 + "}"
        self.path.write_text(row + "\n", encoding="utf-8")
        body = self._body()
        self.assertEqual(len(body["entries"]), 1)

    def test_300_deep_nest_row_is_skipped_and_the_sibling_survives(self):
        row = '{"event":"x","d":' + "[" * 300 + "1" + "]" * 300 + "}"
        self.path.write_text(
            row + '\n{"event":"auth.login.ok"}\n', encoding="utf-8"
        )
        body = self._body()
        self.assertEqual(
            [e["event"] for e in body["entries"]], ["auth.login.ok"]
        )

    def test_huge_exponent_floats_null_not_500(self):
        self.path.write_text(
            '{"event":"x","f":1e309,"g":-1e309,"h":1e-400}\n',
            encoding="utf-8",
        )
        entry = self._body()["entries"][0]
        self.assertIsNone(entry["f"])
        self.assertIsNone(entry["g"])
        self.assertEqual(entry["h"], 0.0)


class RecordBombPinTests(_TrailCase):
    """Fresh record() field shapes: each costs at most itself, never a raise."""

    def _record(self, **fields) -> dict:
        entry = audit.record("auth.login.failed", **fields)
        _starlette(entry)
        return entry

    def _rows(self) -> list[dict]:
        rows = audit.recent(10)
        _starlette(rows)
        return rows

    def test_omni_dict_bomb_keeps_content_and_still_redacts(self):
        entry = self._record(
            username="amy",
            detail=_OmniBombDict(code=7, password="hunter2"),
        )
        self.assertEqual(entry["username"], "amy")
        self.assertEqual(entry["detail"], {"code": 7})
        self.assertEqual(self._rows()[0]["detail"], {"code": 7})
        self.assertNotIn("hunter2", self.path.read_text(encoding="utf-8"))

    def test_nested_list_bomb_holding_a_dict_bomb_costs_its_subtree(self):
        entry = self._record(
            username="amy",
            detail={"lst": _IterBombList([_OmniBombDict(a=1)]), "ok": 1},
        )
        self.assertEqual(entry["username"], "amy")
        self.assertEqual(entry["detail"]["ok"], 1)
        self.assertEqual(self._rows()[0]["username"], "amy")

    def test_self_str_encode_bomb_object_costs_its_field_not_the_line(self):
        entry = self._record(username="amy", note=_SelfStrEncodeBomb())
        self.assertEqual(entry["username"], "amy")
        self.assertEqual(self._rows()[0]["username"], "amy")

    def test_class_property_bomb_costs_itself_not_the_siblings(self):
        entry = self._record(username="amy", when=_ClassPropBomb())
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._rows()[0].get("username"), "amy")

    def test_class_property_bomb_inside_a_plain_list_keeps_the_line(self):
        entry = self._record(username="amy", xs=[1, _ClassPropBomb(), 2])
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._rows()[0].get("username"), "amy")

    def test_poisoned_dict_keys_cost_themselves(self):
        entry = self._record(
            detail={
                _DecodeBombBytes(b"k\xff"): "v1",
                _HUGE_INT: "v2",
                memoryview(b"k"): "v3",
                "ok": 1,
            }
        )
        self.assertEqual(entry["detail"].get("ok"), 1)
        self.assertEqual(self._rows()[0]["detail"].get("ok"), 1)

    def test_lone_surrogate_username_scrubs_and_the_line_persists(self):
        entry = self._record(username="\ud800amy")
        rows = self._rows()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])

    def test_http_read_after_a_bomb_laden_record_answers_200(self):
        audit.record(
            "auth.login.ok",
            username="amy",
            detail=_OmniBombDict(code=7),
            when=_ClassPropBomb(),
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["entries"][0]["event"], "auth.login.ok")


if __name__ == "__main__":
    unittest.main()
