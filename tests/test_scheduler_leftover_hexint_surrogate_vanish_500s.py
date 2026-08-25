"""Scheduler sweep leftovers: hex-YAML over-cap ids, surrogate commands, confirmed vanish.

Three classes of leftover, each pinned by tests that fail on the pre-fix code:

* **Over-cap hex YAML ints.**  ``yaml.safe_load`` parses ``id: 0xFFF…`` via
  ``int(raw, 16)``, which is exempt from CPython's 4300-digit str->int cap —
  so a hand-edited leftover loads fine and ``scheduler_svc._job_id``'s
  ``str(raw)`` then raised the int->str digit-cap ValueError.  That 500'd
  GET /api/scheduler/jobs (the list endpoint calls ``_job_id`` per row before
  ``_jsonable`` can drop the value) and aborted the whole engine tick, so
  every *other* job silently lost that minute.

* **Lone-surrogate command text.**  ``_command_text`` refused control
  characters but not the JSON ``"\\ud800"`` escape, which can never be
  spawned (Popen's argv/env UTF-8 encode refuses it).  POST
  /api/scheduler/jobs sailed it into mutate()'s YAML dump, which failed, and
  the operator got the misleading coded 503 ``settings.save_failed`` — a
  disk-trouble answer to a typo — instead of the 400 ``scheduler.bad_params``
  its control-character siblings get.  A stored leftover reached the runner
  and died in the spawn instead of the clean "no command configured" refusal.

* **Vanished-CLI 503 only after disk confirm.**  ``rsync_svc._run_preview``
  classified Popen's FileNotFoundError as the coded ``rsync.unavailable`` 503
  on the exception alone and dropped the cached probe.  execve also ENOENTs
  for a *still-present* file whose interpreter/loader is gone, so a truthful
  probe was discarded and the SPA told the operator "no usable rsync binary
  was found on this host" while the binary sat on disk.  Classification now
  confirms the binary is gone with a fresh disk probe (the vms/brew rule),
  probing only on that failure path; the confirmed-gone case keeps the coded
  503 and the probe drop pinned by tests/test_cli_missing_scheduler_leftover_503.py.
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

from fastapi import FastAPI, HTTPException  # noqa: E402

from hub import audit, config, rsync_svc, scheduler_svc  # noqa: E402
from hub.routers.scheduler_api import router as scheduler_router  # noqa: E402

#: Loads through yaml/plist hex parsing (uncapped), unrenderable by str().
OVER_CAP_HEX = "0x" + "f" * 5000
OVER_CAP_INT = int("f" * 5000, 16)


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


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + run journal + captured audit records."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-schedleft-{os.getpid()}-{id(self)}"
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
        self.audited: list[tuple[str, dict]] = []
        recorder = mock.patch.object(
            audit, "record",
            lambda event, **fields: self.audited.append((event, fields)) or {},
        )
        recorder.start()
        self.addCleanup(recorder.stop)

    def _write_yaml(self, text: str) -> None:
        (self.root / "services.yaml").write_text(text, encoding="utf-8")
        config.reload_cfg()


class OverCapHexIntJobIdTests(_Sandbox):
    """A YAML hex ``id`` past the digit cap must read as "no id", never raise."""

    def test_job_id_reads_over_cap_int_as_no_id(self):
        # Pre-fix: str(raw) raised the digit-cap ValueError out of _job_id.
        self.assertEqual(scheduler_svc._job_id({"id": OVER_CAP_INT}), "")

    def test_list_endpoint_survives_a_hex_id_leftover(self):
        self._write_yaml(f"""
schedules:
  - id: {OVER_CAP_HEX}
    name: hex-leftover
    type: command
    cron: "* * * * *"
    enabled: true
    params: {{command: echo hi}}
  - id: good-job
    name: good
    type: command
    cron: "30 3 * * *"
    enabled: true
    params: {{command: echo hi}}
""")
        status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        names = [j.get("name") for j in body["jobs"]]
        self.assertEqual(names, ["hex-leftover", "good"])
        # The unrenderable id is dropped like its inf-float siblings, and the
        # whole payload must survive the allow_nan=False UTF-8 encode.
        self.assertIsNone(body["jobs"][0]["id"])
        self.assertEqual(body["jobs"][1]["id"], "good-job")
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_tick_still_fires_sibling_jobs(self):
        """Pre-fix the digit-cap ValueError aborted the whole minute: the
        engine loop survived (broad except) but every other job's trigger
        was silently lost."""
        jobs = [
            {"id": OVER_CAP_INT, "name": "hex", "type": "command",
             "cron": "* * * * *", "enabled": True, "params": {"command": "echo hi"}},
            {"id": "good-job", "name": "good", "type": "command",
             "cron": "* * * * *", "enabled": True, "params": {"command": "echo hi"}},
        ]
        with (
            mock.patch.object(scheduler_svc, "list_jobs", lambda: [dict(j) for j in jobs]),
            mock.patch.object(scheduler_svc, "_last_minute", None),
            mock.patch.object(scheduler_svc.threading, "Thread") as thread,
        ):
            launched = scheduler_svc._tick_once(time.time())
        self.assertEqual(launched, ["good-job"])
        self.assertEqual(thread.call_count, 1)


class SurrogateCommandTests(_Sandbox):
    """A lone-surrogate command is refused at the boundary with the coded 400."""

    def _create(self, command):
        body = {
            "name": "nightly", "type": "command", "cron": "30 3 * * *",
            "enabled": True, "params": {"command": command},
        }
        return request("POST", "/api/scheduler/jobs", payload=body)

    def test_command_text_refuses_a_lone_surrogate(self):
        self.assertEqual(scheduler_svc._command_text("echo \ud800"), "")
        self.assertEqual(scheduler_svc._command_text(["echo", "\ud800"]), "")

    def test_create_answers_the_coded_400_not_save_failed(self):
        """Pre-fix the surrogate sailed into the YAML dump and the operator
        got the misleading 503 settings.save_failed for a typo."""
        status, body = self._create("echo \ud83d")
        self.assertEqual(status, 400, body)
        self.assertEqual(body["detail"]["code"], "scheduler.bad_params")
        self.assertEqual(body["detail"]["params"]["field"], "command")
        # Nothing may be stored by a refused create.
        self.assertEqual(scheduler_svc.list_jobs(), [])

    def test_encodable_unicode_commands_still_save(self):
        """The refusal is the encode boundary, not an ASCII filter: a real
        (astral, non-surrogate) emoji command keeps working."""
        status, body = self._create("echo '\U0001f680 done'")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["job"]["params"]["command"], "echo '\U0001f680 done'")

    def test_runner_refuses_a_stored_surrogate_cleanly(self):
        """A hand-edited leftover must journal the clean "no command
        configured" failure instead of dying in the spawn's UTF-8 encode."""
        log: list[str] = []
        rc = scheduler_svc._run_command(
            {"id": "left", "params": {"command": "echo \ud800"}}, log
        )
        self.assertEqual(rc, -1)
        self.assertTrue(any("no command configured" in line for line in log), log)


class RsyncPreviewVanishConfirmTests(unittest.TestCase):
    """The vanished-CLI 503 fires only after a disk probe confirms the gone
    binary; a still-present binary whose spawn ENOENTs keeps the truthful
    uncoded shape and its probe cache."""

    PARAMS = {"direction": "push", "src": "/", "dest": "/backup-target"}

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-rsyncvanish-{os.getpid()}-{id(self)}"
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with rsync_svc._preview_guard:
            rsync_svc._preview_running.clear()

    def _probe(self, path) -> dict:
        return {
            "available": True, "path": str(path), "variant": "rsync3",
            "version": "3.2.7",
            "supports": {"itemize": True, "progress2": True,
                         "compress": True, "bwlimit": True},
        }

    def test_present_binary_spawn_enoent_is_not_classified(self):
        """Pre-fix this answered the 503 and dropped a truthful probe."""
        present = self.root / "rsync-present"
        present.write_text("#!/definitely/not/an/interpreter\n")
        present.chmod(0o755)
        dropped = mock.Mock()
        with (
            mock.patch.object(rsync_svc, "binary_info",
                              lambda force=False: self._probe(present)),
            mock.patch.object(rsync_svc, "invalidate", dropped),
            mock.patch.object(rsync_svc.subprocess, "Popen",
                              side_effect=FileNotFoundError(2, "No such file or directory")),
        ):
            summary = rsync_svc.preview(dict(self.PARAMS))
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["rc"], -1)
        self.assertIn("No such file", summary["message"])
        dropped.assert_not_called()
        json.dumps(summary, ensure_ascii=False, allow_nan=False).encode("utf-8")
        with rsync_svc._preview_guard:
            self.assertEqual(rsync_svc._preview_running, set(),
                             "the uncoded refusal must not leave the job marked busy")

    def test_confirmed_gone_binary_keeps_the_coded_503(self):
        gone = self.root / "rsync-gone"
        dropped = mock.Mock()
        with (
            mock.patch.object(rsync_svc, "binary_info",
                              lambda force=False: self._probe(gone)),
            mock.patch.object(rsync_svc, "invalidate", dropped),
            mock.patch.object(rsync_svc.subprocess, "Popen",
                              side_effect=FileNotFoundError(2, "No such file or directory")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                rsync_svc.preview(dict(self.PARAMS))
        self.assertEqual(ctx.exception.status_code, 503)
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "rsync.unavailable")
        dropped.assert_called_once_with()

    def test_unstattable_binary_reads_as_gone(self):
        """A path the disk cannot even answer for (dying mount, leftover NUL)
        is not confirmably present: the coded 503 wins over a guess."""
        self.assertFalse(rsync_svc._binary_on_disk("rsync\x00path"))
        self.assertFalse(rsync_svc._binary_on_disk(""))


if __name__ == "__main__":
    unittest.main()
