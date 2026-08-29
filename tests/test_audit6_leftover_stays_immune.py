"""Audit leftover sweep #6: fresh zoo probes came back clean — pin them.

Five prior sweeps sealed this surface (fat lines, hex-YAML huge ints, flock
failures, record()-shaping raises, subclass method bombs through the unbound
base reads).  This sweep re-hunted GET /api/audit/auth and audit.record()
over the real mounted app (create_app + TestClient,
raise_server_exceptions=False) with vectors none of the earlier pins hold:

* **reader** — a symlink pointing at a FIFO squatting the trail, a UTF-8 BOM
  glued to the first row, a row with trailing garbage after valid JSON, and a
  non-ASCII-digit ``limit`` — every one answers 200 (or pydantic's 422), never
  a hang or a 500, and poisoned rows cost only themselves.
* **writer, over HTTP** — a dict-subclass ``__bool__`` bomb (the one dunder
  the audit5 dict pins skipped) and a set-subclass ``__iter__``/
  ``__contains__`` bomb in job fields: POST run-now answers 200 and the trail
  keeps the row with its real content via the unbound base reads.
* **writer, via record()** — ``keys()``/``__len__`` dict bombs, frozenset
  iter bombs, memoryview/complex/bytes scalars, and a key whose ``__hash__``
  raises on the redact rebuild: each costs at most its own field, the line
  always persists, and Starlette's allow_nan=False encode accepts both the
  returned entry and the re-read rows.
* **writer, filesystem squatters** — a FIFO occupying the ``.lock`` sibling
  is unlinked and replaced (no hang, line persists); a directory occupying
  the trail path itself swallows the write but record() still returns the
  minimal entry and the reader answers empty instead of 500.

Everything here is a stays-immune pin: no production change rode along,
because the hunt found no live leftover.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None

#: Generous ceiling for the hang guards.  The FIFO paths complete in
#: milliseconds when healthy; a regression parks os.open forever.
_HANG_GUARD_S = 20.0


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _guarded(case: unittest.TestCase, fn):
    """Run *fn* on a thread so a FIFO-hang regression fails instead of
    wedging the whole suite run."""
    box: dict = {}

    def worker():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["exc"] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(_HANG_GUARD_S)
    case.assertFalse(t.is_alive(), "call hung: a FIFO parked an open() again")
    if "exc" in box:
        raise box["exc"]
    return box["value"]


class _BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _KeysLenBombDict(dict):
    def keys(self):
        raise RuntimeError("keys bomb")

    def __len__(self):
        raise RuntimeError("len bomb")


class _IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("set iter bomb")

    def __contains__(self, item):
        raise RuntimeError("set contains bomb")


class _IterBombFrozen(frozenset):
    def __iter__(self):
        raise RuntimeError("frozenset iter bomb")


class _FlipHashKey(str):
    """Hashable when the caller builds the dict, raising on every rehash —
    the shape that hits redact()'s rebuild insert, not the original insert."""

    calls = 0

    def __hash__(self):
        type(self).calls += 1
        if type(self).calls > 1:
            raise RuntimeError("hash flip bomb")
        return str.__hash__(self)


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit6-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _get(self, limit="100"):
        resp = _client().get(f"/api/audit/auth?limit={limit}")
        return resp


class ReaderSquatterAndRowPoisonTests(_TrailCase):
    """Disk shapes GET /api/audit/auth must absorb, probed fresh this sweep."""

    def test_symlink_to_a_fifo_answers_empty_not_a_hang(self):
        fifo = self.dir / "backing-fifo"
        os.mkfifo(fifo)
        self.path.symlink_to(fifo)
        resp = _guarded(self, self._get)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["entries"], [])

    def test_bom_prefixed_first_row_costs_only_itself(self):
        # json.loads refuses a leading U+FEFF, so the glued row is skipped;
        # the sibling rows behind it must still answer.
        self.path.write_bytes(
            "\ufeff".encode("utf-8")
            + b'{"event":"auth.login.ok"}\n{"event":"auth.logout"}\n'
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual([e["event"] for e in body["entries"]], ["auth.logout"])

    def test_trailing_garbage_after_valid_json_costs_only_its_row(self):
        self.path.write_text(
            '{"event":"auth.login.failed"} trailing junk\n'
            '{"event":"auth.login.ok"}\n',
            encoding="utf-8",
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(
            [e["event"] for e in body["entries"]], ["auth.login.ok"]
        )

    def test_non_ascii_digit_limit_is_pydantics_422_not_a_500(self):
        # int("١٠٠") succeeds in Python but must not be reinterpreted here:
        # pydantic's strict query parsing refuses it as a documented 422.
        resp = self._get(limit="١٠٠")
        self.assertEqual(resp.status_code, 422, resp.text[:300])
        _starlette(resp.json())


class RunNowSubclassBombHTTPTests(unittest.TestCase):
    """__bool__ / set-dunder bombs as the operator would hit them."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit6-http-"))
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

    def test_bool_bomb_params_dict_answers_200_and_keeps_the_trail_row(self):
        # The one dict dunder the audit5 pins skipped: truthiness.  Nothing
        # in record()'s shaping may evaluate ``if value:`` on a caller dict.
        resp = self._run_now({
            "id": "boolbomb", "name": "j", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": _BoolBombDict(command="true"),
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = audit.recent(10)
        _starlette(rows)
        self.assertEqual([r["event"] for r in rows], ["scheduler.job.run_now"])

    def test_set_subclass_iter_bomb_name_answers_200(self):
        resp = self._run_now({
            "id": "setbomb", "name": _IterBombSet({"j"}), "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true"},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = audit.recent(10)
        _starlette(rows)
        self.assertEqual([r["event"] for r in rows], ["scheduler.job.run_now"])
        # The unbound base read listed the real storage, not the bomb.
        self.assertEqual(rows[0]["job_name"], ["j"])


class RecordShapePinTests(_TrailCase):
    """Fresh record() field shapes: each costs at most itself, never a raise."""

    def _record(self, **fields) -> dict:
        entry = audit.record("auth.login.failed", **fields)
        _starlette(entry)
        return entry

    def _rows(self) -> list[dict]:
        rows = audit.recent(10)
        _starlette(rows)
        return rows

    def test_keys_and_len_bomb_dict_records_its_real_content(self):
        entry = self._record(detail=_KeysLenBombDict(code=7))
        self.assertEqual(entry["detail"], {"code": 7})
        self.assertEqual(self._rows()[0]["detail"], {"code": 7})

    def test_set_and_frozenset_iter_bombs_keep_their_elements(self):
        entry = self._record(
            tags=_IterBombSet({"a"}), ftags=_IterBombFrozen({"b"})
        )
        self.assertEqual(entry["tags"], ["a"])
        self.assertEqual(entry["ftags"], ["b"])
        self.assertEqual(self._rows()[0]["tags"], ["a"])

    def test_memoryview_complex_and_raw_bytes_render_not_raise(self):
        entry = self._record(
            mv=memoryview(b"abc"), cx=complex(1, 2), raw=b"\xff\xfe"
        )
        self.assertEqual(entry["cx"], "(1+2j)")
        self.assertEqual(entry["raw"], "\ufffd\ufffd")
        self.assertIsInstance(entry["mv"], str)
        _starlette(self._rows())

    def test_flip_hash_key_costs_itself_and_the_line_persists(self):
        _FlipHashKey.calls = 0
        entry = self._record(detail={_FlipHashKey("k"): "v", "ok": 1})
        self.assertEqual(entry["detail"], {"ok": 1})
        rows = self._rows()
        self.assertEqual([r["event"] for r in rows], ["auth.login.failed"])
        self.assertEqual(rows[0]["detail"], {"ok": 1})


class FilesystemSquatterWritePinTests(_TrailCase):
    """Squatters on the write path: never a hang, never a raise."""

    def test_fifo_at_the_lock_sibling_is_replaced_and_the_line_persists(self):
        lock = self.path.with_name(self.path.name + ".lock")
        os.mkfifo(lock)
        entry = _guarded(
            self, lambda: audit.record("auth.login.ok", username="amy")
        )
        _starlette(entry)
        self.assertEqual(entry["username"], "amy")
        rows = audit.recent(10)
        self.assertEqual([r["event"] for r in rows], ["auth.login.ok"])
        # The squatter was unlinked and a regular flock target recreated.
        self.assertTrue(stat.S_ISREG(os.lstat(lock).st_mode))

    def test_fifo_at_the_trail_itself_swallows_the_write_without_a_hang(self):
        os.mkfifo(self.path)
        entry = _guarded(
            self, lambda: audit.record("auth.login.ok", username="amy")
        )
        _starlette(entry)
        self.assertEqual(entry["username"], "amy")
        resp = _guarded(self, self._get)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["entries"], [])

    def test_directory_at_the_trail_swallows_the_write_and_reads_empty(self):
        self.path.mkdir()
        entry = audit.record("auth.login.ok", username="amy")
        _starlette(entry)
        self.assertEqual(entry["event"], "auth.login.ok")
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["entries"], [])


if __name__ == "__main__":
    unittest.main()
