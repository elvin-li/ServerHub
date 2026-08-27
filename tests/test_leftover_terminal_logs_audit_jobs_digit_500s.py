"""Leftover >4300-digit numbers / inf clocks in the terminal, logs, audit and
scheduler-jobs parsers.

Prior passes guarded the SMART/top/pmset, sysctl, share-ACL, network/WireGuard,
PhotosHub/files/shares and Ollama/health/usage/gateway digit parsers against
CPython's 4300-digit str->int ValueError (and the inf shapes a leftover clock
makes of the same math).  This hunt covered the remaining corners —
hub/terminal_svc.py, hub/terminal_pty.py, hub/logs_svc.py, hub/audit.py and
hub/scheduler_svc.py plus their routers — and found one real leftover plus a
set of already-guarded survivors:

* **fixed** — the terminal engine's run receipt (``terminal_svc._run``)
  computed ``int((time.time() - started) * 1000)`` bare.  The repo's leftover
  ``time.time() = inf`` clock makes that elapsed time nan/inf: ``int(nan)`` is
  ValueError and ``int(inf)`` OverflowError, which 500'd POST
  /api/terminal/run *after* the command had already executed.  The same math
  in hub/terminal_pty.py's ``pty_end`` audit and hub/vm_console.py's
  ``vm_console_end`` audit raised out of a ``finally``, skipping the session
  release (leaking a slot toward ``too_many_sessions``) and the socket close.
  All three now go through ``terminal_svc._duration_ms``, which answers a
  finite non-negative int;
* the terminal history pane (``recent_audit``): a poisoned audit line whose
  ``ts`` is a >4300-digit literal used to be a ValueError inside
  ``json.loads`` itself and the whole line was skipped; since term7 the
  parse_int hook loads the huge literal as None and the row survives.
  An over-cap or inf ``limit`` still falls back to 50;
* the auth audit trail (``audit.recent``): same skip-the-poisoned-line shape
  for GET /api/audit/auth, and an over-cap ``limit`` falls back to 100;
* the central log tail (``logs_svc``): an over-cap ``lines`` string falls back
  to the 200 default, an under-cap-but-huge int clamps at 2000, and GET
  /api/logs/{id} renders the tail either way;
* the scheduler (jobs): an over-cap step / value / range in a cron field is
  the same ValueError as any other bad field, so ``valid_cron`` answers False
  (POST /api/scheduler/jobs is a coded 400, not a 500), ``next_run_ts``
  answers None (GET /api/scheduler/jobs renders), and the engine tick skips
  the job instead of aborting; a poisoned run-journal line is skipped and an
  over-cap ``runs`` limit falls back to 50.
"""
from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import audit, logs_svc, scheduler_svc, terminal_pty, terminal_svc, vm_console

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Under the cap: ``int()`` succeeds, so the *next* operation is what matters.
_BIG_DIGITS = "9" * 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class TerminalRunDurationClockPinTests(unittest.TestCase):
    """POST /api/terminal/run (host and container) receipts go through _run."""

    def test_inf_clock_answers_zero_duration_not_a_500(self):
        # started and ended both read inf: inf - inf is nan, and int(nan)
        # ValueError'd the receipt after the command had already executed.
        with mock.patch.object(terminal_svc.time, "time", return_value=float("inf")):
            result = terminal_svc._run(["/bin/echo", "leftover"], 5)
        self.assertTrue(result["ok"])
        self.assertEqual(result["duration_ms"], 0)
        self.assertIn("leftover", result["stdout"])
        _starlette(result)

    def test_duration_helper_eats_every_leftover_shape(self):
        for started, ended in (
            (float("inf"), float("inf")),   # nan elapsed: int(nan) ValueError
            (0.0, float("inf")),            # inf elapsed: int(inf) OverflowError
            (float("nan"), 1.0),
            (None, 1.0),                    # TypeError from the subtraction
            ("0", 1.0),
        ):
            with self.subTest(started=started, ended=ended):
                self.assertEqual(terminal_svc._duration_ms(started, ended), 0)

    def test_backwards_clock_clamps_at_zero(self):
        self.assertEqual(terminal_svc._duration_ms(5.0, 4.0), 0)

    def test_sane_clock_still_measures(self):
        self.assertEqual(terminal_svc._duration_ms(1.0, 2.5), 1500)
        result = terminal_svc._run(["/bin/echo", "hi"], 5)
        self.assertTrue(result["ok"])
        self.assertIsInstance(result["duration_ms"], int)
        self.assertGreaterEqual(result["duration_ms"], 0)

    def test_pty_and_vm_console_end_audits_use_the_guard(self):
        # Both end audits run inside a ``finally``: a bare int() raising there
        # skipped the session release and the socket close.  Pin the call
        # sites to the guarded helper.
        for module in (terminal_pty, vm_console):
            with self.subTest(module=module.__name__):
                source = inspect.getsource(module)
                self.assertIn("terminal_svc._duration_ms(", source)
                self.assertNotIn("int((time.monotonic() - started)", source)


class TerminalHistoryPoisonedLinePinTests(unittest.TestCase):
    """GET /api/terminal/history reads the audit trail through recent_audit."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term-audit-pin-"))
        self.path = self.dir / "terminal-audit.jsonl"
        self.path.write_text(
            '{"ts": ' + _HUGE_DIGITS + ', "command": "poison"}\n'
            '{"ts": ' + _BIG_DIGITS + ', "command": "under-cap"}\n'
            '{"ts": 1, "target": "host", "command": "ls", "rc": 0}\n',
            encoding="utf-8",
        )
        patched = mock.patch.object(terminal_svc, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.path.unlink(missing_ok=True)
        self.dir.rmdir()

    def test_huge_digit_line_keeps_its_row_not_a_500(self):
        # json.loads used to raise the 4300-digit ValueError for the whole
        # line and the poisoned row vanished from the shell audit view;
        # term7's parse_int hook loads the huge literal as None instead.
        entries = terminal_svc.recent_audit()
        self.assertEqual(
            [e["command"] for e in entries], ["poison", "under-cap", "ls"]
        )
        self.assertIsNone(entries[0]["ts"])
        _starlette(entries)

    def test_under_cap_400_digit_ts_still_renders(self):
        entries = terminal_svc.recent_audit()
        by_command = {e["command"]: e for e in entries}
        self.assertEqual(by_command["under-cap"]["ts"], int(_BIG_DIGITS))
        _starlette(entries)

    def test_huge_and_inf_limits_fall_back_to_fifty(self):
        for limit in (_HUGE_DIGITS, float("inf")):
            with self.subTest(limit=str(limit)[:12]):
                entries = terminal_svc.recent_audit(limit=limit)
                self.assertEqual(entries[-1]["command"], "ls")


class AuthAuditTrailPinTests(unittest.TestCase):
    """GET /api/audit/auth reads the trail through audit.recent."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="auth-audit-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        self.path.write_text(
            '{"ts": ' + _HUGE_DIGITS + ', "event": "poison"}\n'
            '{"ts": "2026-08-25 02:00:00", "event": "auth.login.ok", "username": "amy"}\n',
            encoding="utf-8",
        )
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.path.unlink(missing_ok=True)
        self.dir.rmdir()

    def test_huge_digit_line_is_skipped_not_a_500(self):
        entries = audit.recent()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event"], "auth.login.ok")
        _starlette([audit.redact(e) for e in entries])

    def test_huge_limit_falls_back_to_one_hundred(self):
        entries = audit.recent(limit=_HUGE_DIGITS)
        self.assertEqual(len(entries), 1)
        _starlette(entries)


class LogsTailDigitPinTests(unittest.TestCase):
    """GET /api/logs/{id} clamps its line count through _clamp_lines."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="logs-pin-"))
        self.path = self.dir / "pin.log"
        self.path.write_text("first line\nsecond line\n", encoding="utf-8")
        patched = mock.patch.object(
            logs_svc, "cfg",
            lambda: {"log_sources": [{"id": "pin", "name": "Pin", "path": str(self.path)}]},
        )
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.path.unlink(missing_ok=True)
        self.dir.rmdir()

    def test_huge_digit_lines_string_falls_back_to_the_default(self):
        self.assertEqual(logs_svc._clamp_lines(_HUGE_DIGITS), 200)

    def test_inf_lines_falls_back_to_the_default(self):
        self.assertEqual(logs_svc._clamp_lines(float("inf")), 200)

    def test_under_cap_huge_int_clamps_at_the_ceiling(self):
        # An int object has no str->int conversion to trip on; the clamp
        # bounds it instead.
        self.assertEqual(logs_svc._clamp_lines(10 ** 6000), 2000)

    def test_tail_renders_with_an_over_cap_lines_value(self):
        out = logs_svc.tail_log("pin", lines=_HUGE_DIGITS)
        self.assertTrue(out["exists"])
        self.assertIn("second line", out["log"])
        self.assertEqual(out["lines"], 2)
        _starlette(out)


class SchedulerJobsCronDigitPinTests(unittest.TestCase):
    """POST /api/scheduler/jobs validates, GET renders, and the tick fires
    through parse_cron — an over-cap field is a ValueError inside int()
    itself, the same signal as any other bad field, and every caller
    already absorbs it."""

    _POISONED = (
        f"*/{_HUGE_DIGITS} * * * *",     # over-cap step
        f"{_HUGE_DIGITS} * * * *",       # over-cap value
        f"1-{_HUGE_DIGITS} * * * *",     # over-cap range end
        f"{_BIG_DIGITS} * * * *",        # under the cap: bounds check catches it
    )

    def test_over_cap_fields_are_invalid_not_a_500(self):
        for expr in self._POISONED:
            with self.subTest(expr=expr[:16]):
                self.assertFalse(scheduler_svc.valid_cron(expr))

    def test_next_run_answers_none_for_a_poisoned_expression(self):
        for expr in self._POISONED:
            with self.subTest(expr=expr[:16]):
                self.assertIsNone(scheduler_svc.next_run_ts(expr))

    def test_tick_skips_the_poisoned_job_instead_of_aborting(self):
        saved = scheduler_svc._last_minute
        self.addCleanup(setattr, scheduler_svc, "_last_minute", saved)
        scheduler_svc._last_minute = None
        job = {
            "id": "poison", "name": "poison", "type": "command",
            "enabled": True, "cron": f"*/{_HUGE_DIGITS} * * * *",
        }
        with mock.patch.object(scheduler_svc, "list_jobs", return_value=[job]):
            launched = scheduler_svc._tick_once(now_ts=1_700_000_000.0)
        self.assertEqual(launched, [])

    def test_sane_cron_still_parses(self):
        self.assertTrue(scheduler_svc.valid_cron("*/5 * * * *"))
        ts = scheduler_svc.next_run_ts("0 4 * * *", after_ts=1_700_000_000.0)
        self.assertIsInstance(ts, int)


class SchedulerRunsJournalPinTests(unittest.TestCase):
    """GET /api/scheduler/runs reads the journal through runs()."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="sched-runs-pin-"))
        self.path = self.dir / "scheduler-runs.jsonl"
        self.path.write_text(
            '{"ts": ' + _HUGE_DIGITS + ', "job": "poison"}\n'
            '{"ts": 1, "job": "backup", "status": "ok", "rc": 0}\n',
            encoding="utf-8",
        )
        patched = mock.patch.object(scheduler_svc, "RUNS_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        self.path.unlink(missing_ok=True)
        self.dir.rmdir()

    def test_huge_digit_line_is_skipped_not_a_500(self):
        rows = scheduler_svc.runs()
        self.assertEqual([r["job"] for r in rows], ["backup"])
        _starlette(rows)

    def test_huge_limit_falls_back_to_fifty(self):
        rows = scheduler_svc.runs(limit=_HUGE_DIGITS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
