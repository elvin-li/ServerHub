"""Scheduler sweep 3: the leftover classes re-probed here are already immune.

This sweep reproduced every class against the live router and found the fixes
from the earlier passes in place (hub/scheduler_svc.py `_jsonable` /
`_utf8_text` / `_job_id`, hub/errors.py `_jsonable_param`, hub/rsync_svc.py
`_has_control_chars` / `_run_preview`'s confirmed-vanish probe, and the
app-level RequestValidationError handler).  Nothing needed changing; these
tests pin the exact probes so the immunity cannot regress silently:

* **Surrogates in keys AND values.**  A lone ``\\ud800`` in a *journal record
  key*, a stored *param key*, or their values must be scrubbed before dict
  keys / JSON, never 500 Starlette's ``ensure_ascii=False`` + UTF-8 encode.

* **Over-cap ints (CPython's 4300-digit int->str cap).**  YAML hex loads
  uncapped (``int(raw, 16)`` is exempt), so already-int leftovers reach bare
  ``str()`` / the JSON encoder; the guards use a ``str()`` probe rather than
  ``isinstance`` gates, so numeric YAML values are dropped only when
  unrenderable.  ``json.loads`` of a >4300-digit number literal raises plain
  ValueError, *not* JSONDecodeError — one bad journal line must be skipped
  without wiping the sibling records, and a request body carrying one must
  answer 4xx with nothing stored.

* **Vanished CLI.**  The coded ``rsync.unavailable`` 503 fires only after a
  fresh on-disk probe on the FileNotFoundError path (pinned in
  tests/test_cli_missing_scheduler_leftover_503.py); here the *timeout* path
  is pinned to keep its original uncoded ``{ok, rc: 124}`` shape and to leave
  the probe cache alone.

* **os.kill / bool pids.**  Audited: the only kill paths in this domain
  (hub/jobs.run_watchdog, hub/rsync_svc._kill_group) signal pids that come
  from a live ``subprocess.Popen``, never from YAML/JSON — nothing to pin.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI  # noqa: E402

from hub import audit, config, rsync_svc, scheduler_svc  # noqa: E402
from hub.routers.scheduler_api import router as scheduler_router  # noqa: E402

#: Loads through YAML/plist hex parsing (uncapped); unrenderable by str().
OVER_CAP_HEX = "0x" + "f" * 5000
OVER_CAP_INT = int("f" * 5000, 16)
#: A >4300-digit decimal literal: json.loads raises ValueError (the int->str
#: cap's twin, the str->int cap), not JSONDecodeError.
OVER_CAP_DIGITS = "9" * 5000


async def _asgi_request(method, path, *, payload=None, raw_body=None, query=None):
    app = FastAPI()
    app.include_router(scheduler_router)
    if raw_body is not None:
        body = raw_body
    else:
        body = json.dumps(payload).encode() if payload is not None else b""
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(),
        "query_string": urlencode(query or {}).encode(), "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(raw or b"{}")


def request(method, path, *, payload=None, raw_body=None, query=None):
    return asyncio.run(
        _asgi_request(method, path, payload=payload, raw_body=raw_body, query=query)
    )


def _encodable(body) -> None:
    """The exact render Starlette performs: ensure_ascii=False then UTF-8."""
    json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + run journal, audit captured away."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-sched3-{os.getpid()}-{id(self)}"
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.root = root
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", root / "data"),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        runs = mock.patch.object(scheduler_svc, "RUNS_PATH", root / "data" / "runs.jsonl")
        runs.start()
        self.addCleanup(runs.stop)
        recorder = mock.patch.object(audit, "record", lambda *a, **k: {})
        recorder.start()
        self.addCleanup(recorder.stop)

    def _write_yaml(self, text: str) -> None:
        (self.root / "services.yaml").write_text(text, encoding="utf-8")
        config.reload_cfg()


class SurrogateKeysAndValuesPins(_Sandbox):
    """Lone surrogates in dict *keys* as well as values are scrubbed
    everywhere a scheduler payload is journalled or served."""

    def test_record_run_scrubs_surrogate_keys_and_over_cap_values(self):
        scheduler_svc._record_run({
            "ts": 1, "job": "j\ud800x", "name": OVER_CAP_INT, "status": "failed",
            "rc": OVER_CAP_INT, "tail": "x\ud800y", "\ud800key": "\ud800val",
        })
        text = scheduler_svc.RUNS_PATH.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        # The record must be *kept* (scrubbed), not silently dropped.
        self.assertEqual(len(lines), 1, lines)
        rec = json.loads(lines[0])
        self.assertNotIn("\ud800", json.dumps(rec, ensure_ascii=False))
        self.assertIsNone(rec["name"])
        self.assertIsNone(rec["rc"])
        self.assertEqual(rec["status"], "failed")

        status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        _encodable(body)

    def test_journal_surrogate_key_and_value_do_not_500_runs(self):
        # json.dumps with the default ensure_ascii keeps the \ud800 escape,
        # and json.loads on the read side turns it back into a lone surrogate.
        scheduler_svc.RUNS_PATH.write_text(
            json.dumps({
                "ts": 1_700_000_000, "job": "job-s", "status": "ok", "rc": 0,
                "\ud800key": "\ud800val", "tail": "ok\ud800",
            }) + "\n",
            encoding="utf-8",
        )
        status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        _encodable(body)
        self.assertEqual(body["runs"][0]["job"], "job-s")
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))

    def test_stored_job_surrogate_param_key_and_value_are_scrubbed(self):
        job = {
            "id": "job-sk", "name": "n", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true", "\ud800key": "\ud800val"},
        }
        with mock.patch.object(scheduler_svc, "list_jobs", return_value=[job]):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        _encodable(body)
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        # The scrub keeps the entry (encode-replace "?"), it does not drop it.
        params = body["jobs"][0]["params"]
        self.assertEqual(params["command"], "true")
        self.assertIn("?key", params)
        self.assertEqual(params["?key"], "?val")


class OverCapIntJournalAndBodyPins(_Sandbox):
    """Over-cap number literals: one bad journal line is skipped without
    wiping siblings, and a request body carrying one stores nothing."""

    def test_huge_number_journal_line_skips_only_that_line(self):
        good = json.dumps({"ts": 1_700_000_001, "job": "job-ok", "status": "ok", "rc": 0})
        scheduler_svc.RUNS_PATH.write_text(
            '{"ts": 1700000000, "job": "job-huge", "status": "ok", "rc": '
            + OVER_CAP_DIGITS + "}\n" + good + "\n",
            encoding="utf-8",
        )
        # json.loads of the first line raises ValueError, not JSONDecodeError.
        status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        _encodable(body)
        self.assertEqual([r["job"] for r in body["runs"]], ["job-ok"])
        # The single-pass reader used by GET /api/scheduler/jobs agrees.
        self.assertEqual(list(scheduler_svc.last_runs_by_job()), ["job-ok"])
        # And nothing rewrote the journal: reading must never wipe it.
        text = scheduler_svc.RUNS_PATH.read_text(encoding="utf-8")
        self.assertIn("job-huge", text)
        self.assertIn("job-ok", text)

    def test_huge_int_body_literal_is_refused_with_nothing_stored(self):
        for field_json in (
            '"timeout":' + OVER_CAP_DIGITS,
            '"params":{"command":"echo hi","n":' + OVER_CAP_DIGITS + "}",
        ):
            raw = (
                '{"name":"n","type":"command","cron":"30 3 * * *","enabled":true,'
                '"params":{"command":"echo hi"},' + field_json + "}"
            ).encode()
            status, body = request("POST", "/api/scheduler/jobs", raw_body=raw)
            self.assertLess(status, 500, body)
            self.assertGreaterEqual(status, 400, body)
            _encodable(body)
            self.assertEqual(scheduler_svc.list_jobs(), [], body)

    def test_hex_yaml_cron_element_survives_list_and_tick(self):
        """A YAML cron *field* written as over-cap hex must read as an
        unparsable expression (never fires), not abort the list or the
        engine minute for sibling jobs."""
        self._write_yaml(f"""
schedules:
  - id: hex-cron
    name: hex-cron
    type: command
    cron: [{OVER_CAP_HEX}, 3, "*", "*", "*"]
    enabled: true
    params: {{command: echo hi}}
  - id: good-job
    name: good
    type: command
    cron: "* * * * *"
    enabled: true
    params: {{command: echo hi}}
""")
        status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        _encodable(body)
        rows = {j["id"]: j for j in body["jobs"]}
        self.assertIn("hex-cron", rows)
        self.assertIsNone(rows["hex-cron"]["next_run"])
        self.assertIn("good-job", rows)

        with (
            mock.patch.object(scheduler_svc, "_last_minute", None),
            mock.patch.object(scheduler_svc.threading, "Thread") as thread,
        ):
            launched = scheduler_svc._tick_once(time.time())
        self.assertEqual(launched, ["good-job"])
        self.assertEqual(thread.call_count, 1)

    def test_hex_yaml_exclude_is_a_logged_run_failure_not_a_raise(self):
        """A YAML-stored over-cap exclude hits ``str()`` inside validation;
        the runner contract turns it into a log line and rc -1 — the engine
        thread and run-now never see the ValueError."""
        log: list[str] = []
        rc = rsync_svc.run_job(
            {"direction": "push", "src": "/", "dest": "/backup-target",
             "exclude": [OVER_CAP_INT]},
            log=log, timeout=5,
        )
        self.assertEqual(rc, -1)
        self.assertTrue(any(line.startswith("!!") for line in log), log)
        _encodable({"log": log})


class PreviewTimeoutShapePin(unittest.TestCase):
    """The vanished-CLI 503 must not creep into the timeout path: a dry run
    that exceeds its deadline keeps the original uncoded ``rc: 124`` shape
    and leaves the probe cache alone."""

    def test_timeout_keeps_uncoded_shape_and_probe_cache(self):
        dropped = mock.Mock()
        with mock.patch.object(rsync_svc, "invalidate", dropped):
            summary = rsync_svc._run_preview(
                ["/bin/sh", "-c", "sleep 30"], itemize=False, timeout=1,
            )
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["rc"], 124)
        self.assertIn("timeout", summary["message"])
        dropped.assert_not_called()
        _encodable(summary)


if __name__ == "__main__":
    unittest.main()
