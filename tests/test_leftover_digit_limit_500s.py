"""Leftover >4300-digit numeric strings: CPython's str->int cap is ValueError.

Prior passes pinned the 400-digit class (``int()`` succeeded and the float
division OverflowError'd).  CPython additionally refuses str->int past 4300
digits with ValueError, which ``isdigit()`` does not defend against: a
``hw.ncpu`` / ``hw.memsize`` line past the cap used to 500
GET /api/system/diagnostics (probe_ncpu / probe_mem_gb raised through
fan_out) and GET /api/system/host (``int(ncpu)`` one line below the
already-guarded ``_mem_gb``).

The same battery pins the paths that already survive this class — brew's
cache parser, the maintenance timeout clamp, the scheduler cron grammar and
the audit list's limit filter — so a refactor cannot quietly reintroduce it.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from hub import audit, brew_cache, brew_svc, jobs, scheduler_svc, tools_svc
from hub.routers import scheduler_api, system_extra

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: An int already past the cap: power-of-two bases are exempt from the
#: str->int limit, which is exactly how YAML hex/octal leftovers mint one.
_HUGE_INT = 1 << 20000


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class DiagnosticsDigitLimitTests(unittest.TestCase):
    def test_huge_sysctl_digits_do_not_500_diagnostics(self):
        """>4300-digit hw.ncpu / hw.memsize ValueError'd GET /api/system/diagnostics."""
        def fake_sh(argv, **kwargs):
            last = argv[-1] if argv else ""
            if last in ("hw.ncpu", "hw.memsize"):
                return 0, _HUGE_DIGITS, ""
            if argv and argv[0].endswith("hostname"):
                return 0, "nas.local", ""
            return 1, "", ""

        with (
            patch.object(tools_svc, "sh", side_effect=fake_sh),
            patch.object(tools_svc, "engine_up", return_value=False),
            patch.object(tools_svc, "host_ip", return_value="10.0.0.2"),
        ):
            data = tools_svc.diagnostics()
        self.assertIsNone(data["ncpu"])
        self.assertIsNone(data["mem_gb"])
        self.assertEqual(data["hostname"], "nas.local")
        _starlette(data)

    def test_huge_ncpu_does_not_500_host_snapshot(self):
        """>4300-digit hw.ncpu ValueError'd GET /api/system/host next to guarded memsize."""
        def fake_sh(argv, **kwargs):
            last = argv[-1] if argv else ""
            if last in ("hw.ncpu", "hw.memsize"):
                return 0, _HUGE_DIGITS, ""
            if argv and argv[0].endswith("hostname"):
                return 0, "nas.local", ""
            return 0, "ok", ""

        with (
            patch.object(system_extra, "is_high", return_value=False),
            patch.object(system_extra, "sh", fake_sh),
            patch.object(system_extra, "default_interface", return_value="en0"),
            patch.object(system_extra, "_iface_addresses", return_value=[]),
            patch.object(system_extra, "host_ip", return_value="10.0.0.2"),
            patch.object(system_extra, "peek_engine", return_value=False),
        ):
            snap = system_extra._host_snapshot(True)
        self.assertIsNone(snap["ncpu"])
        self.assertIsNone(snap["mem_total_gb"])
        self.assertEqual(snap["hostname"], "nas.local")
        _starlette(snap)

    def test_huge_tools_clamps_do_not_500(self):
        """Tools query clamps already absorb the same class; pin them."""
        self.assertEqual(tools_svc._clamp_int(_HUGE_DIGITS, 25, 5, 100), 25)
        with patch.object(tools_svc, "sh", return_value=(1, "", "")):
            result = tools_svc.net_ping("localhost", count=_HUGE_DIGITS)
        self.assertEqual(result["count"], 3)
        _starlette(result)


class BrewDigitLimitPinTests(unittest.TestCase):
    def test_huge_exit_code_json_falls_back_not_500(self):
        """`brew services list --json` with a >4300-digit int keeps the rows.

        Refusing the document whole (the previous pin) was itself the
        silent-loss bug: `_load` discarded the *fresh* snapshot and
        republished the stale last-good with a new TTL, so a start/stop
        stayed invisible while brew printed that number.  The parse_int
        hook now drops just the poisoned number, same as the docker_cli /
        notify_channels decoders (tests/test_brew_leftover_hugeint_
        snapshot_loss.py pins the full path).
        """
        blob = '[{"name": "redis", "status": "started", "exit_code": %s}]' % _HUGE_DIGITS
        rows = brew_cache._services_from_output(blob)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "redis")
        self.assertIsNone(rows[0]["exit_code"])

    def test_overcap_int_fields_do_not_500_list(self):
        """A hex-minted over-cap int in a row used to 500 GET /api/brew/services.

        str->int refuses >4300 decimal digits, but base-16 is exempt, so a
        YAML/stub leftover can still hand `_json_safe` an int whose str() is
        ValueError.  The surrogate name rides along so the same row also pins
        the UTF-8 encode.
        """
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(
                brew_svc, "brew_services_list",
                return_value=[{
                    "name": "redis\ud800", "status": "started",
                    "exit_code": _HUGE_INT, "user": _HUGE_INT, "file": None,
                }],
            ),
        ):
            rows = brew_svc.list_services()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["exit_code"])
        self.assertIsNone(rows[0]["user"])
        self.assertNotIn("\ud800", rows[0]["name"])
        _starlette(rows)

    def test_overcap_rc_does_not_500_action(self):
        """`f"exit {rc}"` with an over-cap rc ValueError'd POST the action."""
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(brew_svc, "run_capped", return_value=(_HUGE_INT, "")),
            patch.object(brew_svc, "invalidate_brew_services"),
            patch.object(brew_svc, "invalidate_status"),
        ):
            out = brew_svc.service_action("redis", "stop")
        self.assertEqual(out, {"ok": False, "message": "exit unknown"})
        _starlette(out)

    def test_cache_strips_overcap_ints_before_publish(self):
        """Nested or top-level, an over-cap int must not reach the encoder."""
        cleaned = brew_cache._copy_items([{
            "name": "x",
            "exit_code": _HUGE_INT,
            "meta": {"pid": _HUGE_INT, "ok": 3},
        }])
        self.assertIsNone(cleaned[0]["exit_code"])
        self.assertIsNone(cleaned[0]["meta"]["pid"])
        self.assertEqual(cleaned[0]["meta"]["ok"], 3)
        _starlette(cleaned)

    def test_cache_drops_overcap_int_keys(self):
        """An over-cap int *key* cannot be rendered either; pin the drop."""
        out = brew_cache._json_safe({_HUGE_INT: "x", "name": "redis"})
        self.assertEqual(out, {"name": "redis"})
        _starlette(out)

    def test_brew_list_survives_raising_cache(self):
        """A ValueError out of the shared cache degrades to the text parse."""
        with (
            patch.object(brew_svc.os.path, "isfile", return_value=True),
            patch.object(brew_svc, "brew_services_list", side_effect=ValueError("digits")),
            patch.object(
                brew_svc, "sh",
                return_value=(0, "Name Status User File\nredis started a /x\n", ""),
            ),
        ):
            rows = brew_svc.list_services()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "redis")
        _starlette(rows)


class MaintenanceDigitLimitPinTests(unittest.TestCase):
    def test_huge_timeout_is_clamped_not_500(self):
        self.assertEqual(jobs._clamp_timeout(_HUGE_DIGITS), jobs.JOB_TIMEOUT_DEFAULT)
        self.assertEqual(jobs._clamp_timeout(10 ** 5000), jobs.JOB_TIMEOUT_MAX)

    def test_huge_digit_task_fields_stay_encodable(self):
        """A digit-string field rides through as text, never re-parsed to int."""
        with patch.object(jobs, "cfg", return_value={
            "maintenance": [{
                "id": "trim", "name": _HUGE_DIGITS, "desc": "", "timeout": _HUGE_DIGITS,
            }],
        }):
            tasks = jobs.maintenance_tasks()
        self.assertIn("trim", tasks)
        _starlette(tasks)


class SchedulerDigitLimitPinTests(unittest.TestCase):
    def test_huge_cron_digits_are_refused_not_500(self):
        self.assertFalse(scheduler_svc.valid_cron(f"{_HUGE_DIGITS} * * * *"))
        self.assertFalse(scheduler_svc.valid_cron(f"*/{_HUGE_DIGITS} * * * *"))
        self.assertIsNone(scheduler_svc.next_run_ts(f"{_HUGE_DIGITS} * * * *"))

    def test_huge_cron_is_coded_bad_cron(self):
        body = scheduler_api.JobBody(
            name="nightly", type="command",
            cron=f"*/{_HUGE_DIGITS} * * * *",
            params={"command": "true"},
        )
        with self.assertRaises(HTTPException) as ctx:
            scheduler_api._validated_record(body, "job-1")
        self.assertEqual(_code(ctx.exception), "scheduler.bad_cron")
        self.assertEqual(ctx.exception.status_code, 400)


class AuditListFilterDigitLimitPinTests(unittest.TestCase):
    def test_huge_limit_is_clamped_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth-audit.jsonl"
            path.write_text(
                json.dumps({"ts": "t", "event": "auth.login.ok", "username": "a"}) + "\n",
                encoding="utf-8",
            )
            with patch.object(audit, "AUDIT_PATH", path):
                for junk in (_HUGE_DIGITS, float("inf"), None, [500]):
                    rows = audit.recent(junk)
                    self.assertEqual(len(rows), 1)
                    _starlette([audit.redact(r) for r in rows])

    def test_huge_digit_journal_int_costs_its_field_not_500(self):
        """An over-cap int field nulls; the row keeps its event (audit7)."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth-audit.jsonl"
            path.write_text(
                '{"ts": "t", "event": "auth.login.ok", "retry": %s}\n'
                '{"ts": "t", "event": "auth.logout"}\n' % _HUGE_DIGITS,
                encoding="utf-8",
            )
            with patch.object(audit, "AUDIT_PATH", path):
                rows = audit.recent(10)
        self.assertEqual(
            [r["event"] for r in rows], ["auth.login.ok", "auth.logout"]
        )
        self.assertIsNone(rows[0]["retry"])
        _starlette(rows)


if __name__ == "__main__":
    unittest.main()
