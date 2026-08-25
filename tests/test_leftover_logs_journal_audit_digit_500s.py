"""Second pass over the logs / journal / audit parsers for leftover
>4300-digit numbers and inf clocks.

The first pass (test_leftover_terminal_logs_audit_jobs_digit_500s.py) covered
the limit clamps, the cron fields and the poisoned *huge-digit* trail lines —
those are a ValueError inside ``json.loads`` itself, so the line is skipped.
This hunt covered what that shape does not:

* **fixed** — ``logs_svc._stat_size`` wrapped ``int(path.stat().st_size)`` in
  a try, but ``int(...)`` only guards *conversions*: a leftover FUSE/SMB
  ``st_size`` that is already a >4300-digit int passed through untouched, and
  CPython's int->str digit limit then ValueError'd Starlette's ``json.dumps``
  — 500ing GET /api/logs (``log_sources``) and GET /api/logs/{id}
  (``tail_log``) after the tail had already been read.  The helper now
  applies the same ``float()`` junk test as ``files_svc._finite_int`` (the
  guard that fixed this exact class on GET /api/files/list), so anything
  beyond float range falls back to 0;
* the ``Infinity`` / ``NaN`` literal trail line: unlike the huge-digit shape,
  Python's ``json.loads`` *accepts* those extensions, so the line parses and
  the value must be nulled before Starlette's allow_nan=False encoder sees
  it.  ``audit.recent`` (GET /api/audit/auth), ``terminal_svc.recent_audit``
  (GET /api/terminal/history) and ``scheduler_svc.runs`` /
  ``last_runs_by_job`` (GET /api/scheduler/runs, /jobs) all route the parsed
  row through their ``_jsonable``, which nulls non-finite floats — pinned
  here so a refactor cannot drop the scrub;
* ``audit.record`` with poisoned caller fields: a leftover inf float is
  nulled by ``_jsonable`` before the dump, and a >4300-digit int (whose
  ``json.dumps`` is the int->str ValueError) is swallowed by record()'s
  logging-never-breaks-the-request try — the sign-in that triggered the
  record still succeeds and the rest of the trail still renders.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import audit, logs_svc, scheduler_svc, terminal_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_INT = 10 ** 5000
#: Under the digit cap, but far past float range: ``float()`` is the guard.
_BIG_INT = 10 ** 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _FakeStatPath:
    """Duck-typed path whose stat() reports a chosen st_size."""

    def __init__(self, size):
        self._size = size

    def stat(self):
        return mock.Mock(st_size=self._size)


class LogsStatSizeHugeIntTests(unittest.TestCase):
    """GET /api/logs and /api/logs/{id} carry ``size`` through _stat_size."""

    def test_huge_digit_int_st_size_is_zero_not_a_500(self):
        # int(huge) succeeds — no conversion to trip on — so before the
        # float() junk test the value reached Starlette's json.dumps, whose
        # int->str digit cap is ValueError.
        self.assertEqual(logs_svc._stat_size(_FakeStatPath(_HUGE_INT)), 0)
        _starlette({"size": logs_svc._stat_size(_FakeStatPath(_HUGE_INT))})

    def test_under_cap_400_digit_st_size_is_zero_too(self):
        # Renders fine as JSON, but the same float() test files_svc applies
        # rejects it: no real filesystem reports a 10^400-byte file.
        self.assertEqual(logs_svc._stat_size(_FakeStatPath(_BIG_INT)), 0)

    def test_inf_nan_and_negative_still_fall_back(self):
        for size in (float("inf"), float("-inf"), float("nan"), -5, None, "junk"):
            with self.subTest(size=str(size)[:12]):
                self.assertEqual(logs_svc._stat_size(_FakeStatPath(size)), 0)

    def test_sane_size_passes_through(self):
        self.assertEqual(logs_svc._stat_size(_FakeStatPath(2048)), 2048)

    def _patched_env(self, log_path: Path):
        real_stat = Path.stat

        def fake_stat(p, **kwargs):
            st = real_stat(p, **kwargs)
            if str(p) == str(log_path):
                return mock.Mock(st_mode=st.st_mode, st_size=_HUGE_INT)
            return st

        return (
            mock.patch.object(
                logs_svc, "cfg",
                lambda: {"log_sources": [
                    {"id": "pin", "name": "Pin", "path": str(log_path)},
                ]},
            ),
            mock.patch.object(Path, "stat", fake_stat),
        )

    def test_log_sources_renders_with_a_huge_st_size(self):
        with tempfile.TemporaryDirectory(prefix="logs-size-pin-") as tmp:
            log_path = Path(tmp) / "pin.log"
            log_path.write_text("first\nsecond\n", encoding="utf-8")
            cfg_patch, stat_patch = self._patched_env(log_path)
            with cfg_patch, stat_patch:
                out = logs_svc.log_sources()
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["exists"])
        self.assertEqual(out[0]["size"], 0)
        _starlette(out)

    def test_tail_log_renders_with_a_huge_st_size(self):
        with tempfile.TemporaryDirectory(prefix="logs-size-pin-") as tmp:
            log_path = Path(tmp) / "pin.log"
            log_path.write_text("first\nsecond\n", encoding="utf-8")
            cfg_patch, stat_patch = self._patched_env(log_path)
            with cfg_patch, stat_patch:
                out = logs_svc.tail_log("pin")
        self.assertTrue(out["exists"])
        self.assertEqual(out["size"], 0)
        self.assertIn("second", out["log"])
        _starlette(out)


class InfinityTrailLinePinTests(unittest.TestCase):
    """``json.loads`` accepts ``Infinity``/``NaN`` literals, so unlike the
    huge-digit line the row *parses* — the readers must null the value
    before Starlette's allow_nan=False encoder sees it."""

    _LINE = '{"ts": Infinity, "who": "amy", "rc": NaN, "neg": -Infinity}\n'

    def _trail(self, tmp: Path, name: str) -> Path:
        p = tmp / name
        p.write_text(self._LINE, encoding="utf-8")
        return p

    def test_auth_audit_nulls_the_literals_not_a_500(self):
        with tempfile.TemporaryDirectory(prefix="auth-inf-pin-") as tmp:
            path = self._trail(Path(tmp), "auth-audit.jsonl")
            with mock.patch.object(audit, "AUDIT_PATH", path):
                rows = audit.recent()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["ts"])
        self.assertIsNone(rows[0]["rc"])
        self.assertIsNone(rows[0]["neg"])
        self.assertEqual(rows[0]["who"], "amy")
        _starlette(rows)

    def test_terminal_history_nulls_the_literals_not_a_500(self):
        with tempfile.TemporaryDirectory(prefix="term-inf-pin-") as tmp:
            path = self._trail(Path(tmp), "terminal-audit.jsonl")
            with mock.patch.object(terminal_svc, "AUDIT_PATH", path):
                rows = terminal_svc.recent_audit()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["ts"])
        self.assertEqual(rows[0]["who"], "amy")
        _starlette(rows)

    def test_scheduler_runs_null_the_literals_not_a_500(self):
        line = '{"ts": Infinity, "job": "backup", "rc": -Infinity}\n'
        with tempfile.TemporaryDirectory(prefix="runs-inf-pin-") as tmp:
            path = Path(tmp) / "schedule-runs.jsonl"
            path.write_text(line, encoding="utf-8")
            with mock.patch.object(scheduler_svc, "RUNS_PATH", path):
                rows = scheduler_svc.runs()
                by_job = scheduler_svc.last_runs_by_job()
        self.assertEqual([r["job"] for r in rows], ["backup"])
        self.assertIsNone(rows[0]["ts"])
        self.assertIsNone(by_job["backup"]["rc"])
        _starlette(rows)
        _starlette(by_job)


class AuditRecordPoisonedFieldPinTests(unittest.TestCase):
    """Logging never breaks the request: record() must survive poisoned
    caller fields, and the trail must keep rendering afterwards."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit-record-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree, not unlink+rmdir: record() takes secure_io.file_lock, which
        # leaves a lock file beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_inf_field_is_nulled_and_written(self):
        entry = audit.record("auth.login.ok", username="amy", elapsed=float("inf"))
        self.assertIsNone(entry["elapsed"])
        _starlette(entry)
        rows = audit.recent()
        self.assertEqual(rows[-1]["event"], "auth.login.ok")
        self.assertIsNone(rows[-1]["elapsed"])
        _starlette(rows)

    def test_huge_digit_int_field_does_not_raise_or_poison_the_trail(self):
        # json.dumps of a >4300-digit int is the int->str ValueError; it is
        # swallowed inside record() (the line is dropped, never half-written),
        # so the sign-in succeeds and the earlier history still renders.
        audit.record("auth.login.ok", username="amy")
        entry = audit.record("auth.login.failed", attempts=_HUGE_INT)
        self.assertIsInstance(entry, dict)
        rows = audit.recent()
        self.assertEqual([r["event"] for r in rows], ["auth.login.ok"])
        _starlette(rows)


if __name__ == "__main__":
    unittest.main()
