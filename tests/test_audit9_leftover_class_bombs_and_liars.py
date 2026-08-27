"""Audit leftover sweep #9: __class__ bombs and lying-type impostors.

audit5..7 sealed record()'s shaping against subclass *method* bombs through
the unbound base reads, and audit7 pinned a ``__class__``-property bomb as a
field value.  This sweep re-hunted hub/audit.py over the real mounted app
(create_app + TestClient, raise_server_exceptions=False) with the shapes
those pins do not hold — bombs planted where the bare ``isinstance`` gates
themselves run — and found five live leftovers:

* **fixed, raise out of record()** — the minimal-entry fallback runs
  *outside* both nets, and ``_utf8_text`` opened with a bare isinstance: an
  ``event`` whose ``__class__`` property raised blew the shaping try, landed
  in the fallback, and blew ``_utf8_text`` again — straight into the request
  being audited.  ``_isa`` (fail-closed isinstance) makes ``_utf8_text``
  total, so the fallback cannot raise.

* **fixed, detail wipe** — a ``__class__`` bomb nested in a set/frozenset
  field, planted as a mapping key, or riding in a plain list detonated
  ``_jsonable``'s bare rank gates; record()'s net then degraded the whole
  line to the minimal ts+event shape, wiping the who/where detail the trail
  exists for.  The ``_isa`` gates make the bomb cost only itself.

* **fixed, line wipe** — ``isinstance(value, bool)`` admitted an impostor
  whose lying ``__class__`` property answers ``bool`` and returned it raw;
  record()'s json.dumps (whose C encoder checks the real type) fell to
  ``default=str``, the impostor's ``__str__`` bomb raised inside the disk
  net, and the **entire line** was silently lost — a failed sign-in left no
  trace.  ``type(value) is bool`` refuses the liar (bool cannot be
  subclassed, so nothing legitimate is lost) and the int gate's unbound
  ``int.__index__`` sheds it to None.

* **fixed, detail wipe** — record() popped ``ts``/``event`` and merged
  ``**extra`` on redact() output, which still carries the caller's key
  objects; a hash-shadowing str-subclass key whose ``__eq__`` raises
  detonated the pop and degraded the line to minimal.  extra is now shaped
  through ``_jsonable`` (whose keys are rebuilt as exact str) *before* the
  dict operations.

* **fixed, detail wipe** — ``_is_secret_key`` ran its substring probes on
  ``str(key).lower()``, and both calls hand a str *subclass* straight
  through when ``__str__``/``lower`` return ``self``; the ``in`` probes then
  called a hostile ``__contains__`` outside the try and one poisoned key
  raised out of redact().  Unbound ``str.lower`` on the base type returns an
  exact str the probes can trust.

Stays-immune pins ride along for lying-``__class__`` impostors of dict /
float / str probed fresh this sweep and found already dead (each costs only
its own field through the unbound base coercions), and for honest bools
surviving the exact-type gate.
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


class _ClassPropBomb:
    """isinstance() falls back to ``__class__`` when the fast path misses;
    a raising property there detonates any bare isinstance gate."""

    @property
    def __class__(self):
        raise RuntimeError("class property bomb")


class _BoolLiar:
    """Real type unknown to json's C encoder; ``isinstance(x, bool)`` says
    yes through the lying property, and the __str__ bomb blows default=str."""

    @property
    def __class__(self):
        return bool

    def __str__(self):
        raise RuntimeError("bool liar str bomb")

    __repr__ = __str__


class _DictLiar:
    @property
    def __class__(self):
        return dict


class _FloatLiar:
    @property
    def __class__(self):
        return float

    def __eq__(self, other):
        raise RuntimeError("float liar eq bomb")

    __hash__ = object.__hash__


class _StrLiar:
    @property
    def __class__(self):
        return str


class _ShadowEqKey(str):
    """Hashes like its text but detonates the equality probe a dict lookup
    (record()'s ``extra.pop("ts", ...)``) runs against the stored key."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")


class _ContainsBombKey(str):
    """``str()`` and ``lower()`` both hand back ``self``, so a bound-method
    probe runs ``in`` against the hostile ``__contains__``."""

    def __str__(self):
        return self

    def lower(self):
        return self

    def __contains__(self, item):
        raise RuntimeError("contains bomb")


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit9-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
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

    def _http_body(self) -> dict:
        resp = _client().get("/api/audit/auth?limit=100")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class EventClassBombTests(_TrailCase):
    """The one raise that escaped both nets: a bombed event name."""

    def test_class_bomb_event_does_not_raise_out_of_record(self):
        # Pre-fix: _utf8_text's bare isinstance blew the shaping try, then
        # blew again inside the minimal-entry fallback — outside both nets —
        # and record() raised RuntimeError into the request being audited.
        entry = self._record(event=_ClassPropBomb(), username="amy")
        self.assertEqual(entry.get("username"), "amy")
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("username"), "amy")

    def test_http_read_after_a_bombed_event_answers_200(self):
        audit.record(_ClassPropBomb(), username="amy")
        body = self._http_body()
        self.assertEqual(len(body["entries"]), 1)
        self.assertEqual(body["entries"][0].get("username"), "amy")


class ClassBombDetailWipeTests(_TrailCase):
    """A __class__ bomb must cost only itself, never the line's detail."""

    def test_bomb_inside_a_set_field_keeps_the_siblings(self):
        # Pre-fix: redact() passes sets through untouched, _jsonable's set
        # branch recursed into the bomb, the bare bool gate detonated, and
        # the whole line degraded to ts+event — username gone.
        entry = self._record(username="amy", tags={1, _ClassPropBomb()})
        self.assertEqual(entry.get("username"), "amy")
        self.assertIn(1, entry.get("tags", []))
        self.assertEqual(self._rows()[0].get("username"), "amy")

    def test_bomb_inside_a_frozenset_field_keeps_the_siblings(self):
        entry = self._record(
            username="amy", ftags=frozenset({2, _ClassPropBomb()})
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertIn(2, entry.get("ftags", []))
        self.assertEqual(self._rows()[0].get("username"), "amy")

    def test_bomb_as_a_nested_mapping_key_keeps_the_siblings(self):
        # Pre-fix: _jsonable's key gate ``isinstance(k, (str, bytes, ...))``
        # detonated on the bomb key and the line lost every field.
        entry = self._record(
            username="amy", detail={_ClassPropBomb(): 1, "ok": 2}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("detail", {}).get("ok"), 2)
        self.assertEqual(self._rows()[0].get("detail", {}).get("ok"), 2)

    def test_bomb_inside_a_plain_list_keeps_the_other_elements(self):
        # Stronger than the audit7 pin (which only required the line to
        # survive): redact()'s list rebuild no longer drops the whole field
        # for one poisoned element.
        entry = self._record(username="amy", xs=[1, _ClassPropBomb(), 2])
        self.assertEqual(entry.get("username"), "amy")
        xs = entry.get("xs", [])
        self.assertIn(1, xs)
        self.assertIn(2, xs)
        self.assertEqual(len(xs), 3)

    def test_run_now_with_a_bombed_set_cron_answers_200_and_keeps_detail(self):
        # The wipe as the operator hit it: the job store hands run-now a
        # cron field holding a set with a bomb inside; the route answered
        # 200 either way (record()'s net), but the trail row for the run
        # lost its job name and operator.
        from hub.routers import scheduler_api

        svc = scheduler_api.scheduler_svc
        job = {
            "id": "clsbomb", "name": "nightly", "type": "command",
            "cron": {"* * * * *", _ClassPropBomb()}, "enabled": True,
            "params": {"command": "true"},
        }
        with (
            mock.patch.object(svc, "get_job", lambda jid: dict(job)),
            mock.patch.object(svc, "is_running", lambda jid: False),
            mock.patch.object(svc, "run_job_now", lambda jid: {"ok": True}),
        ):
            resp = _client().post("/api/scheduler/jobs/clsbomb/run-now")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = self._rows()
        self.assertEqual([r["event"] for r in rows], ["scheduler.job.run_now"])
        self.assertEqual(rows[0].get("job_name"), "nightly")
        self.assertIn("* * * * *", rows[0].get("cron", []))


class BoolLiarLineWipeTests(_TrailCase):
    """type(x) is bool, not isinstance: the liar must not cost the line."""

    def test_bool_liar_field_drops_to_none_and_the_line_persists(self):
        # Pre-fix: _jsonable returned the liar raw, json.dumps' default=str
        # hit the __str__ bomb inside the disk net, and the whole line was
        # silently lost — plus the returned entry was not Starlette-encodable.
        entry = self._record(username="amy", flag=_BoolLiar())
        self.assertEqual(entry.get("username"), "amy")
        self.assertIsNone(entry.get("flag"))
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("username"), "amy")

    def test_honest_bools_still_round_trip_through_the_exact_type_gate(self):
        entry = self._record(ok=True, off=False)
        self.assertIs(entry.get("ok"), True)
        self.assertIs(entry.get("off"), False)
        row = self._rows()[0]
        self.assertIs(row.get("ok"), True)
        self.assertIs(row.get("off"), False)


class ShadowKeyDetailWipeTests(_TrailCase):
    """Hash-shadowing keys must not detonate record()'s pop/merge."""

    def test_shadow_ts_key_costs_itself_not_the_line(self):
        # Pre-fix: extra.pop("ts", None) compared the stamp key against the
        # stored shadow key, its __eq__ bomb raised, and the line degraded
        # to minimal.  The stamp must stay record()'s own, never the
        # caller's.  record() is called directly: its ``event`` parameter is
        # positional-only, so the shadow key rides ``**fields`` without the
        # keyword-binding machinery comparing names first.
        entry = audit.record(
            "auth.login.failed", **{_ShadowEqKey("ts"): 1, "username": "amy"}
        )
        _starlette(entry)
        self.assertEqual(entry.get("username"), "amy")
        self.assertTrue(str(entry.get("ts", "")).startswith("20"))
        self.assertEqual(self._rows()[0].get("username"), "amy")

    def test_shadow_event_key_cannot_clobber_the_event_name(self):
        entry = audit.record(
            "auth.login.failed",
            **{_ShadowEqKey("event"): "forged", "who": "amy"},
        )
        _starlette(entry)
        self.assertEqual(entry.get("event"), "auth.login.failed")
        self.assertEqual(entry.get("who"), "amy")
        rows = self._rows()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])


class SecretKeyProbeBombTests(_TrailCase):
    """_is_secret_key must never run ``in`` against a hostile subclass."""

    def test_contains_bomb_top_level_key_keeps_the_line_and_its_field(self):
        # Pre-fix: the substring probes ran on the subclass instance, its
        # __contains__ bomb raised out of redact(), and the line degraded
        # to minimal — every field lost for one poisoned key name.
        entry = self._record(
            **{_ContainsBombKey("note"): "v", "username": "amy"}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("note"), "v")
        self.assertEqual(self._rows()[0].get("note"), "v")

    def test_contains_bomb_nested_key_keeps_its_siblings(self):
        entry = self._record(
            username="amy", detail={_ContainsBombKey("note"): "v", "ok": 1}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("detail"), {"note": "v", "ok": 1})

    def test_secret_named_bomb_key_is_still_redacted(self):
        # The base-str coercion must not open a redaction bypass: a hostile
        # key whose *text* is secret-shaped still classifies and vanishes.
        entry = self._record(
            **{_ContainsBombKey("password"): "hunter2", "username": "amy"}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("password", entry)
        self.assertNotIn("hunter2", self.path.read_text(encoding="utf-8"))


class LyingImpostorStaysImmuneTests(_TrailCase):
    """Impostors probed fresh this sweep and found already dead: each costs
    only its own field through the unbound base coercions."""

    def test_dict_float_and_str_liars_cost_only_their_fields(self):
        entry = self._record(
            username="amy",
            d=_DictLiar(),
            f=_FloatLiar(),
            s=_StrLiar(),
        )
        self.assertEqual(entry.get("username"), "amy")
        # dict liar: redact()'s unbound dict.items read refuses the
        # non-dict and nulls the field before _jsonable ever sees it.
        self.assertIsNone(entry.get("d"))
        # float liar: float.__float__ refuses it before the __eq__ bomb.
        self.assertIsNone(entry.get("f"))
        # str liar: str.encode refuses it -> scrubbed empty text.
        self.assertEqual(entry.get("s"), "")
        rows = self._rows()
        self.assertEqual(rows[0].get("username"), "amy")

    def test_http_read_after_an_impostor_laden_record_answers_200(self):
        audit.record(
            "auth.login.ok",
            username="amy",
            d=_DictLiar(),
            f=_FloatLiar(),
            flag=_BoolLiar(),
            when=_ClassPropBomb(),
        )
        body = self._http_body()
        self.assertEqual(body["entries"][0].get("event"), "auth.login.ok")
        self.assertEqual(body["entries"][0].get("username"), "amy")


if __name__ == "__main__":
    unittest.main()
