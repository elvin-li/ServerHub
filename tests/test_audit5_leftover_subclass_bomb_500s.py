"""Audit leftover sweep #5: subclass bombs escaping record()'s shaping net.

audit4 fixed the fat JSONL line wiping sibling auth rows; the hexint sweep
fixed the digit-cap ValueError costing the whole line.  A fresh hunt over the
same mounted app (create_app + TestClient, raise_server_exceptions=False)
found the reader clean — every disk-poison shape answered 200 — but
``audit.record()`` itself still broke the request it was auditing.  Its
shaping try caught only (ValueError, TypeError, RecursionError), and every
scrub inside ran through *bound* calls on caller-supplied values, so a
subclass bomb raised whatever it liked straight out of record():

* **fixed, live over HTTP** — a job store handing run-now a list-subclass
  ``__iter__`` bomb in ``cron``, or an int-subclass ``__str__`` bomb in
  ``name``, 500'd POST /api/scheduler/jobs/{jid}/run-now from inside
  ``audit.record`` — and the trail kept **no line at all** for the run being
  audited, the exact double failure this module's docstring forbids twice.
* **fixed** — dict-subclass ``items()`` bombs blew ``redact`` and
  ``_jsonable`` (both read via bound ``.items()``); the base ``dict.items``
  read now lists the real storage, so the row's content survives the bomb.
* **fixed** — a float subclass whose ``__ne__``/``__eq__`` raised blew the
  NaN/inf probe ``value != value``; ``float.__float__`` sheds it first.
* **fixed** — a bytes-subclass ``decode`` bomb and a str-subclass
  ``__str__``/``encode`` bomb blew ``_utf8_text``; unbound
  ``bytes.decode``/``str.encode`` now scrub the real payload (a bombed
  event *name* used to degrade to "" — it now keeps its text).
* **fixed** — ``getattr(value, "isoformat", None)`` let a ``__getattr__``
  (or ``isoformat`` property) raising non-AttributeError escape the default.
* **fixed** — record()'s two nets are now ``except Exception``: shaping
  degrades to the minimal ts+event line, the disk phase never re-raises.

Stays-immune pins ride along for reader vectors this sweep re-probed and
found already dead (none previously pinned): a directory or a self-symlink
occupying the trail path, non-dict scalar rows, a binary-garbage line,
``1e400``/``Infinity``/``NaN`` literals, and NUL/control escapes — all
answer 200 with a UTF-8-renderable body on GET /api/audit/auth.
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


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _GetBombDict(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__

    def __index__(self):
        raise RuntimeError("index bomb")


class _NeBombFloat(float):
    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __hash__ = float.__hash__


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class _StrBombStr(str):
    def __str__(self):
        raise RuntimeError("str bomb")

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError("getattr bomb")


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit5-bomb-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _record(self, **fields) -> dict:
        entry = audit.record("auth.login.failed", **fields)
        _starlette(entry)
        return entry

    def _only_row(self) -> dict:
        rows = audit.recent(10)
        _starlette(rows)
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        return rows[0]


class DictSubclassBombTests(_TrailCase):
    """items()/get() bombs must cost at most a field, never the line."""

    def test_items_bomb_detail_keeps_the_line_and_its_content(self):
        # Pre-fix: redact()'s bound value.items() raised RuntimeError out of
        # record() into the request being audited, and no line was written.
        entry = self._record(username="bob", detail=_ItemsBombDict(code=7))
        self.assertEqual(entry["username"], "bob")
        # The base dict.items read sees the real storage: content survives.
        self.assertEqual(entry["detail"], {"code": 7})
        self.assertEqual(self._only_row()["detail"], {"code": 7})

    def test_nested_items_bomb_costs_only_its_subtree(self):
        entry = self._record(
            username="bob",
            detail={"inner": _ItemsBombDict(code=7), "kept": "yes"},
        )
        self.assertEqual(entry["detail"]["kept"], "yes")
        self.assertEqual(entry["detail"]["inner"], {"code": 7})
        self.assertEqual(self._only_row()["username"], "bob")

    def test_get_bomb_detail_records_through_the_base_read(self):
        entry = self._record(detail=_GetBombDict(a=1))
        self.assertEqual(entry["detail"], {"a": 1})

    def test_secret_keys_inside_a_subclass_dict_are_still_redacted(self):
        # The base-read fix must not open a redaction bypass: keys still
        # classify, secret ones still vanish.
        entry = self._record(detail=_ItemsBombDict(password="hunter2", ok=1))
        self.assertNotIn("password", entry["detail"])
        self.assertEqual(entry["detail"]["ok"], 1)
        self.assertNotIn("hunter2", self.path.read_text(encoding="utf-8"))


class NumericSubclassBombTests(_TrailCase):
    """Base coercion first, then the existing digit-cap / finite probes."""

    def test_int_str_bomb_keeps_its_number(self):
        # Pre-fix: the digit-cap str() probe caught only ValueError, so the
        # subclass __str__ RuntimeError raised out of record().
        entry = self._record(attempts=_StrBombInt(5))
        self.assertEqual(entry["attempts"], 5)
        self.assertEqual(self._only_row()["attempts"], 5)

    def test_overcap_int_wearing_the_bomb_subclass_still_drops_to_none(self):
        entry = self._record(username="bob", attempts=_StrBombInt(_HUGE_INT))
        self.assertIsNone(entry["attempts"])
        self.assertEqual(self._only_row()["username"], "bob")

    def test_float_ne_bomb_keeps_its_number(self):
        # Pre-fix: the NaN probe ``value != value`` called the subclass
        # __ne__ and the bomb escaped the shaping net.
        entry = self._record(elapsed=_NeBombFloat(1.5))
        self.assertEqual(entry["elapsed"], 1.5)
        self.assertEqual(self._only_row()["elapsed"], 1.5)

    def test_nonfinite_float_wearing_the_bomb_subclass_still_drops(self):
        entry = self._record(username="bob", elapsed=_NeBombFloat("inf"))
        self.assertIsNone(entry["elapsed"])
        self.assertEqual(self._only_row()["username"], "bob")


class SequenceAndTextBombTests(_TrailCase):
    def test_list_iter_bomb_keeps_its_elements(self):
        # Pre-fix: the list comprehension called the subclass __iter__.
        entry = self._record(window=_IterBombList([1, 2]))
        self.assertEqual(entry["window"], [1, 2])
        self.assertEqual(self._only_row()["window"], [1, 2])

    def test_bytes_decode_bomb_still_decodes_scrubbed(self):
        entry = self._record(blob=_DecodeBombBytes(b"a\xffb"))
        self.assertEqual(entry["blob"], "a\ufffdb")

    def test_str_subclass_bomb_value_keeps_its_text(self):
        # Pre-fix behaviour before this sweep's _utf8_text rework: the bound
        # encode() bomb degraded the value to "".
        entry = self._record(username=_StrBombStr("amy"))
        self.assertEqual(entry["username"], "amy")
        self.assertEqual(self._only_row()["username"], "amy")

    def test_str_subclass_bomb_event_name_keeps_its_text(self):
        entry = audit.record(_StrBombStr("auth.login.ok"), username="amy")
        _starlette(entry)
        self.assertEqual(entry["event"], "auth.login.ok")
        rows = audit.recent(10)
        self.assertEqual([r["event"] for r in rows], ["auth.login.ok"])


class ObjectProtocolBombTests(_TrailCase):
    def test_getattr_bomb_object_costs_its_field_not_the_line(self):
        # Pre-fix: getattr(value, "isoformat", None) let the __getattr__
        # RuntimeError escape the default and blow record().
        entry = self._record(username="bob", when=_GetattrBomb())
        self.assertEqual(entry["username"], "bob")
        self.assertEqual(self._only_row()["username"], "bob")

    def test_isoformat_property_bomb_costs_its_field_not_the_line(self):
        entry = self._record(username="bob", when=_IsoPropertyBomb())
        self.assertEqual(entry["username"], "bob")
        self.assertEqual(self._only_row()["username"], "bob")


class RedactUnitTests(unittest.TestCase):
    """The redaction pass itself must absorb the same bombs."""

    def test_items_bomb_dict_redacts_to_none_not_a_raise(self):
        class Hostile(dict):
            def items(self):
                raise RuntimeError("items bomb")

            def keys(self):
                raise RuntimeError("keys bomb")

        hostile = Hostile()
        # dict(Hostile) storage is what the base read sees; make the storage
        # itself hold a secret and require it dropped, not leaked.
        dict.__setitem__(hostile, "token", "s3cret")
        dict.__setitem__(hostile, "user", "amy")
        out = audit.redact({"detail": hostile})
        self.assertEqual(out, {"detail": {"user": "amy"}})

    def test_iter_bomb_list_redacts_through_the_base_read(self):
        # The base __iter__ read sees the real storage: the elements survive
        # (and still recurse through redaction), the bomb never raises.
        self.assertEqual(
            audit.redact({"xs": _IterBombList([{"token": "s", "n": 1}])}),
            {"xs": [{"n": 1}]},
        )


class RunNowLive500Tests(unittest.TestCase):
    """The bombs as the operator hit them: POST run-now used to 500."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit5-http-"))
        patched = mock.patch.object(
            audit, "AUDIT_PATH", self.dir / "auth-audit.jsonl"
        )
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _run_now(self, job):
        from hub.routers import scheduler_api

        svc = scheduler_api.scheduler_svc
        with (
            mock.patch.object(svc, "get_job", lambda jid: dict(job)),
            mock.patch.object(svc, "is_running", lambda jid: False),
            mock.patch.object(svc, "run_job_now", lambda jid: {"ok": True}),
        ):
            return _client().post(f"/api/scheduler/jobs/{job['id']}/run-now")

    def test_iterbomb_cron_answers_200_and_the_run_leaves_a_trail(self):
        # Pre-fix: 500 from inside audit.record, and recent() held no line
        # for the run at all — the double failure the module forbids.
        resp = self._run_now({
            "id": "iterbomb", "name": "j", "type": "command",
            "cron": _IterBombList(["* * * * *"]), "enabled": True,
            "params": {"command": "true"},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = audit.recent(10)
        self.assertEqual([r["event"] for r in rows], ["scheduler.job.run_now"])
        self.assertEqual(rows[0]["cron"], ["* * * * *"])
        _starlette(rows)

    def test_int_str_bomb_name_answers_200_and_keeps_the_number(self):
        resp = self._run_now({
            "id": "intbomb", "name": _StrBombInt(7), "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true"},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = audit.recent(10)
        self.assertEqual(rows[0]["job_name"], 7)
        _starlette(rows)


class ReaderStaysImmuneTests(unittest.TestCase):
    """Disk-poison vectors re-probed this sweep and found already dead."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit5-reader-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _get(self):
        resp = _client().get("/api/audit/auth?limit=100")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body

    def test_directory_at_the_trail_path_answers_empty(self):
        self.path.mkdir()
        self.assertEqual(self._get()["entries"], [])

    def test_self_symlink_at_the_trail_path_answers_empty(self):
        self.path.symlink_to(self.path)
        self.assertEqual(self._get()["entries"], [])

    def test_non_dict_scalar_rows_are_skipped_not_500(self):
        self.path.write_text(
            '["a"]\n"str"\n123\nnull\ntrue\n{"event":"auth.login.ok"}\n',
            encoding="utf-8",
        )
        body = self._get()
        self.assertEqual(
            [e["event"] for e in body["entries"]], ["auth.login.ok"]
        )

    def test_binary_garbage_line_is_skipped_not_500(self):
        self.path.write_bytes(
            b"\xff\xfe\x00garbage\x00\n" + b'{"event":"auth.login.ok"}\n'
        )
        body = self._get()
        self.assertEqual(
            [e["event"] for e in body["entries"]], ["auth.login.ok"]
        )

    def test_nonfinite_literals_are_nulled_not_500(self):
        # json.loads accepts Infinity/NaN and parses 1e400 to inf; Starlette's
        # allow_nan=False encoder would 500 on any of them raw.
        self.path.write_text(
            '{"event": "x", "a": Infinity, "b": NaN, "c": -Infinity,'
            ' "d": 1e400}\n',
            encoding="utf-8",
        )
        entry = self._get()["entries"][0]
        for field in ("a", "b", "c", "d"):
            self.assertIsNone(entry[field])

    def test_nul_and_control_escapes_render_not_500(self):
        self.path.write_text(
            '{"event": "a\\u0000b", "k\\u0001": "v\\u001f"}\n',
            encoding="utf-8",
        )
        self.assertEqual(self._get()["entries"][0]["event"], "a\x00b")


if __name__ == "__main__":
    unittest.main()
