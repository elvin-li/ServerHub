"""Scheduler sweep 4: numeric-YAML-id mutations, plus stays-immune HTTP pins.

The genuine leftover this sweep fixes is an identity mismatch, not a 500: a
hand-edited numeric YAML ``id: 123`` was *listed* by GET /api/scheduler/jobs
(the raw int rode through ``_jsonable``) and *fired by the engine* (``_job_id``
coerces via the ``str()`` probe), but ``get_job`` / ``delete_job`` /
``set_enabled`` / ``save_job`` compared with raw ``==`` — so the path string
``"123"`` never matched the stored int and every enable/update/delete/run-now
mis-404'd ``scheduler.not_found`` while the engine kept firing the job.  There
was no way to stop it through the API.  The fix is ``_matches_id`` (the same
str()-probe rule as ``_job_id``, per the numeric-ids invariant) and serving
the coerced id in the row so the UI's URLs name what the lookups match.

The rest of this file pins classes re-probed against the live routers and
found already immune, so the immunity cannot regress silently:

* **Preview validation beats the availability 503 only when truthful.**  With
  a usable binary recorded, a surrogate ``src``, an inf ``bwlimit_kbps`` and a
  mapping ``direction`` answer their coded 400s (never 500, never the
  misleading ``rsync.unavailable``); with no binary recorded the up-front 503
  wins whatever the params, and stays a 503 — not a 500 while encoding it.

* **Journal literals json.loads itself produces.**  ``NaN`` / ``Infinity`` /
  ``1e999`` parse to nan/inf floats (no exception), and non-dict lines parse
  fine too — GET /api/scheduler/runs must drop the poison but keep the record
  (and its siblings), and reading must never rewrite the journal.

* **The Scheduler page's system tab route.**  GET /api/scheduler is served by
  hub/routers/unraid_parity.py from real on-disk plists; an over-cap hex
  ``<integer>`` (``int(raw, 16)`` dodges the str->int digit cap) in
  StartInterval or a calendar Minute must not 500 the route or drop the
  sibling timer.  (Service-level pins live in the tools sweep; this is the
  HTTP-layer pin on the route the Scheduler page actually calls.)

* **The bridged SMART row.**  A poisoned smart_test_svc schedule (over-cap
  ``last_run`` int, bytes fields) must degrade the read-only system row, never
  500 GET /api/scheduler/jobs.
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

from hub import audit, config, rsync_svc, scheduler_svc, tools_svc  # noqa: E402
from hub.routers.scheduler_api import router as scheduler_router  # noqa: E402
from hub.routers.unraid_parity import router as parity_router  # noqa: E402

#: Loads through YAML/plist hex parsing (uncapped); unrenderable by str().
OVER_CAP_HEX = "0x" + "f" * 5000
OVER_CAP_INT = int("f" * 5000, 16)


async def _asgi_request(method, path, *, payload=None, raw_body=None, query=None,
                        extra_router=None):
    app = FastAPI()
    app.include_router(scheduler_router)
    if extra_router is not None:
        app.include_router(extra_router)
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


def request(method, path, **kw):
    return asyncio.run(_asgi_request(method, path, **kw))


def _encodable(body) -> None:
    """The exact render Starlette performs: ensure_ascii=False then UTF-8."""
    json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + run journal, audit captured away."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-sched4-{os.getpid()}-{id(self)}"
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
        self.audited: list[dict] = []
        recorder = mock.patch.object(
            audit, "record", lambda event, **f: self.audited.append({"event": event, **f}) or {},
        )
        recorder.start()
        self.addCleanup(recorder.stop)

    def _write_yaml(self, text: str) -> None:
        (self.root / "services.yaml").write_text(text, encoding="utf-8")
        config.reload_cfg()


_NUMERIC_ID_YAML = """
schedules:
  - id: 123
    name: numeric
    type: command
    cron: "30 3 * * *"
    enabled: true
    params: {command: echo hi}
  - id: keeper
    name: keeper
    type: command
    cron: "30 4 * * *"
    enabled: true
    params: {command: echo hi}
"""


class NumericYamlIdMutations(_Sandbox):
    """A numeric YAML id fires as its str() form; the mutation routes must
    match that same identity instead of mis-404ing the running job."""

    def test_row_serves_the_string_identity_the_engine_uses(self):
        self._write_yaml(_NUMERIC_ID_YAML)
        status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        _encodable(body)
        ids = [j["id"] for j in body["jobs"]]
        # The row must carry what enable/delete/run URLs will send back.
        self.assertEqual(ids, ["123", "keeper"])

    def test_enable_route_reaches_the_numeric_id_job(self):
        self._write_yaml(_NUMERIC_ID_YAML)
        status, body = request(
            "POST", "/api/scheduler/jobs/123/enable", payload={"enabled": False},
        )
        self.assertEqual(status, 200, body)
        _encodable(body)
        self.assertFalse(body["job"]["enabled"])
        stored = {scheduler_svc._job_id(j): j for j in scheduler_svc.list_jobs()}
        self.assertFalse(stored["123"]["enabled"])
        self.assertTrue(stored["keeper"]["enabled"])
        # The engine agrees the job is now off: its matching minute launches
        # nothing (3:30 local on a Monday matches "30 3 * * *").
        t = time.struct_time((2026, 8, 24, 3, 30, 0, 0, 236, -1))
        self.assertFalse(scheduler_svc.cron_matches("30 3 * * *", t) and
                         scheduler_svc.job_enabled(stored["123"]))

    def test_update_route_normalises_the_stored_id(self):
        self._write_yaml(_NUMERIC_ID_YAML)
        status, body = request(
            "PUT", "/api/scheduler/jobs/123",
            payload={"name": "renamed", "type": "command", "cron": "0 5 * * *",
                     "enabled": True, "params": {"command": "echo hi"}},
        )
        self.assertEqual(status, 200, body)
        _encodable(body)
        self.assertEqual(body["job"]["id"], "123")
        stored = scheduler_svc.list_jobs()
        self.assertEqual([j.get("id") for j in stored], ["123", "keeper"])
        self.assertEqual(stored[0]["name"], "renamed")

    def test_delete_route_removes_only_the_numeric_id_job(self):
        self._write_yaml(_NUMERIC_ID_YAML)
        status, body = request("DELETE", "/api/scheduler/jobs/123")
        self.assertEqual(status, 200, body)
        self.assertEqual(
            [j.get("id") for j in scheduler_svc.list_jobs()], ["keeper"],
        )

    def test_run_now_route_reaches_the_numeric_id_job(self):
        self._write_yaml(_NUMERIC_ID_YAML)
        with mock.patch.object(scheduler_svc.threading, "Thread") as thread:
            status, body = request("POST", "/api/scheduler/jobs/123/run-now")
        self.assertEqual(status, 200, body)
        _encodable(body)
        self.assertTrue(body.get("ok"), body)
        self.assertEqual(thread.call_count, 1)

    def test_run_now_respects_the_running_guard_for_the_coerced_id(self):
        """The whole identity chain agrees: the engine journals/guards the
        job as "123", so a second run-now answers the coded 409."""
        self._write_yaml(_NUMERIC_ID_YAML)
        with mock.patch.object(scheduler_svc, "_running", {"123"}):
            status, body = request("POST", "/api/scheduler/jobs/123/run-now")
        self.assertEqual(status, 409, body)
        self.assertEqual(body["detail"]["code"], "scheduler.running")

    def test_create_with_the_rendered_id_is_a_409_not_a_duplicate(self):
        self._write_yaml(_NUMERIC_ID_YAML)
        status, body = request(
            "POST", "/api/scheduler/jobs",
            payload={"id": "123", "name": "clash", "type": "command",
                     "cron": "* * * * *", "enabled": True,
                     "params": {"command": "echo hi"}},
        )
        self.assertEqual(status, 409, body)
        self.assertEqual(body["detail"]["code"], "scheduler.exists")
        self.assertEqual(len(scheduler_svc.list_jobs()), 2)

    def test_float_yaml_id_matches_its_integer_rendering(self):
        self._write_yaml("""
schedules:
  - id: 123.0
    name: floaty
    type: command
    cron: "30 3 * * *"
    enabled: true
    params: {command: echo hi}
""")
        status, body = request("DELETE", "/api/scheduler/jobs/123")
        self.assertEqual(status, 200, body)
        self.assertEqual(scheduler_svc.list_jobs(), [])

    def test_idless_and_unrenderable_id_jobs_never_match_a_path(self):
        """The coercion must not widen matching: a job with no id (or an
        over-cap hex id whose str() cannot render) matches no path string."""
        self._write_yaml(f"""
schedules:
  - name: no-id
    type: command
    cron: "30 3 * * *"
    enabled: true
    params: {{command: echo hi}}
  - id: {OVER_CAP_HEX}
    name: overcap-id
    type: command
    cron: "30 3 * * *"
    enabled: true
    params: {{command: echo hi}}
""")
        for path in ("/api/scheduler/jobs/no-id", "/api/scheduler/jobs/None"):
            status, body = request("DELETE", path)
            self.assertEqual(status, 404, body)
        self.assertEqual(len(scheduler_svc.list_jobs()), 2)


_AVAILABLE = {
    "available": True, "path": "/bin/false", "variant": "rsync3", "version": "3.2.7",
    "supports": {"itemize": True, "progress2": True, "compress": True, "bwlimit": True},
}
_UNAVAILABLE = {
    "available": False, "path": "", "variant": "none", "version": "",
    "supports": {"itemize": False, "progress2": False, "compress": False, "bwlimit": False},
}


class PreviewValidationVsAvailabilityPins(unittest.TestCase):
    """Bad preview params answer their coded 400s when a binary is recorded;
    the up-front 503 wins only when it is truthful — and neither path 500s."""

    _BAD_BODIES = (
        ("surrogate src", b'{"direction":"push","src":"/a\\ud800","dest":"/b"}',
         "rsync.bad_path"),
        ("inf bwlimit", b'{"direction":"push","src":"/tmp","dest":"/b","bwlimit_kbps":1e999}',
         "rsync.bad_params"),
        ("mapping direction", b'{"direction":{"a":1},"src":"/tmp","dest":"/b"}',
         "rsync.bad_direction"),
        ("huge-float src", b'{"direction":"push","src":1e999,"dest":"/b"}',
         "rsync.bad_path"),
    )

    def test_coded_400s_when_a_binary_is_recorded(self):
        for label, raw, code in self._BAD_BODIES:
            with mock.patch.object(rsync_svc, "binary_info", return_value=_AVAILABLE):
                status, body = request(
                    "POST", "/api/backups/rsync/preview", raw_body=raw,
                )
            self.assertEqual(status, 400, (label, body))
            self.assertEqual(body["detail"]["code"], code, label)
            _encodable(body)

    def test_truthful_503_when_no_binary_is_recorded(self):
        for label, raw, _code in self._BAD_BODIES:
            with mock.patch.object(rsync_svc, "binary_info", return_value=_UNAVAILABLE):
                status, body = request(
                    "POST", "/api/backups/rsync/preview", raw_body=raw,
                )
            self.assertEqual(status, 503, (label, body))
            self.assertEqual(body["detail"]["code"], "rsync.unavailable", label)
            _encodable(body)


class JournalParseableLiteralPins(_Sandbox):
    """NaN / Infinity / 1e999 and non-dict lines parse *successfully* out of
    json.loads — the read side must scrub or skip them without wiping
    siblings, and reading must never rewrite the journal."""

    def test_nan_inf_and_non_dict_lines_do_not_500_or_wipe(self):
        lines = [
            '{"ts": 1, "job": "j-inf", "status": "ok", "rc": Infinity}',
            '{"ts": 2, "job": "j-nan", "status": "ok", "rc": NaN, "duration": 1e999}',
            '[1, 2, 3]',
            '"just a string"',
            'null',
            '{"ts": 3, "job": "good", "status": "ok", "rc": 0}',
        ]
        payload = "\n".join(lines) + "\n"
        scheduler_svc.RUNS_PATH.write_text(payload, encoding="utf-8")
        status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        _encodable(body)
        by_job = {r.get("job"): r for r in body["runs"]}
        self.assertIn("good", by_job)
        # The poisoned records are kept with the poison dropped, not lost.
        self.assertIn("j-inf", by_job)
        self.assertIsNone(by_job["j-inf"]["rc"])
        self.assertIn("j-nan", by_job)
        self.assertIsNone(by_job["j-nan"]["rc"])
        self.assertIsNone(by_job["j-nan"]["duration"])
        # Reading never rewrites: the journal is byte-identical afterwards.
        self.assertEqual(
            scheduler_svc.RUNS_PATH.read_text(encoding="utf-8"), payload,
        )
        # The single-pass reader behind GET /api/scheduler/jobs agrees.
        self.assertEqual(
            set(scheduler_svc.last_runs_by_job()), {"j-inf", "j-nan", "good"},
        )


class LaunchdRouteHexPlistPin(unittest.TestCase):
    """GET /api/scheduler (the Scheduler page's system tab) reads real
    on-disk plists; over-cap hex integers must not 500 the route."""

    def test_hex_plist_integers_do_not_500_the_route(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "a.hexint.plist").write_text(
                '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
                '<key>Label</key><string>a.hexint</string>'
                f'<key>StartInterval</key><integer>{OVER_CAP_HEX}</integer>'
                '</dict></plist>', encoding="utf-8",
            )
            (agents / "b.hexcal.plist").write_text(
                '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
                '<key>Label</key><string>b.hexcal</string>'
                '<key>StartCalendarInterval</key><dict>'
                f'<key>Minute</key><integer>{OVER_CAP_HEX}</integer></dict>'
                '</dict></plist>', encoding="utf-8",
            )
            (agents / "c.good.plist").write_text(
                '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
                '<key>Label</key><string>c.good</string>'
                '<key>StartInterval</key><integer>60</integer>'
                '</dict></plist>', encoding="utf-8",
            )
            with mock.patch.object(
                tools_svc.os.path, "expanduser", return_value=str(agents),
            ):
                status, body = request(
                    "GET", "/api/scheduler", extra_router=parity_router,
                )
        self.assertEqual(status, 200, body)
        _encodable(body)
        rows = {t["label"]: t for t in body["timers"]}
        # The sibling timer survives; the hex-calendar entry keeps its row
        # with the unrenderable minute dropped; the interval-only over-cap
        # entry has nothing left to show and is skipped.
        self.assertIn("c.good", rows)
        self.assertEqual(rows["c.good"]["interval_sec"], 60)
        self.assertIn("b.hexcal", rows)
        self.assertIsNone(rows["b.hexcal"]["calendar"]["Minute"])
        self.assertNotIn("a.hexint", rows)
        self.assertEqual(body["count"], len(body["timers"]))


class SmartBridgePins(_Sandbox):
    """A poisoned SMART schedule degrades the read-only system row, never
    500s GET /api/scheduler/jobs."""

    def _jobs_with_schedule(self, schedule):
        import hub.smart_test_svc as smart_test_svc
        with mock.patch.object(smart_test_svc, "get_schedule", return_value=schedule):
            return request("GET", "/api/scheduler/jobs")

    def test_over_cap_last_run_is_dropped_not_a_500(self):
        status, body = self._jobs_with_schedule({
            "interval": "weekly", "kind": "short",
            "devices": ["disk0"], "last_run": OVER_CAP_INT,
        })
        self.assertEqual(status, 200, body)
        _encodable(body)
        row = body["system"][0]
        self.assertEqual(row["id"], "smart-selftest")
        self.assertTrue(row["enabled"])
        # float(OVER_CAP_INT) overflows; the row falls back to "never ran".
        self.assertEqual(row["last_run"], 0)

    def test_bytes_fields_degrade_the_row_not_the_list(self):
        status, body = self._jobs_with_schedule({
            "interval": b"weekly", "kind": b"short",
            "devices": {"not": "a list"}, "last_run": float("inf"),
        })
        self.assertEqual(status, 200, body)
        _encodable(body)
        row = body["system"][0]
        self.assertFalse(row["enabled"])
        self.assertEqual(row["devices"], [])

    def test_non_dict_schedule_omits_the_row_not_the_list(self):
        for schedule in ("not-a-dict", None, 42):
            status, body = self._jobs_with_schedule(schedule)
            self.assertEqual(status, 200, body)
            self.assertEqual(body["system"], [])
            _encodable(body)


if __name__ == "__main__":
    unittest.main()
