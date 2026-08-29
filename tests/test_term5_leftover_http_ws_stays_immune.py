"""Terminal leftover sweep #5: stays-immune pins for the vectors terms 1-4 skipped.

A fresh hunt over GET /api/terminal, POST /api/terminal/run,
GET /api/terminal/history and the PTY WebSocket replayed every leftover
class against the mounted app.  Besides the cancelled-teardown reservation
leak (pinned in test_term5_leftover_pty_cancel_leak.py), no live 500 or
hang remains — these pins hold the contracts the probe verified but no
prior sweep had written down:

* a leftover FIFO occupying the audit trail must not hang or 500 anything:
  history answers ``{"entries": []}`` (tail_file_lines' O_NONBLOCK +
  regular-file check raises the OSError recent_audit already eats), the run
  route still executes and answers 200 (append_text's ENXIO/EINVAL is
  swallowed by _audit's logging-never-breaks-the-request except), and a
  symlink squatting the trail that points at a FIFO is the same coded
  answer — the class that wedged GET /api/metrics before its own sweep;
* a FIFO squatting the flock *sidecar* (terminal-audit.jsonl.lock) is
  dodged by _lock_fd's lstat + unlink, so the run still executes and its
  line still lands in the trail;
* exotic settings.terminal scalars YAML can actually produce — a
  self-referential list (anchors survive safe_load), ``!!set``,
  ``!!binary`` bytes, a date, ``.nan`` — render GET /api/terminal and
  POST /api/terminal/run as coded/fallback payloads, never an encoder 500;
* a host PTY whose requested shell is a real file that is not executable
  (Popen PermissionError, an OSError the FileNotFoundError-only handler
  used to miss) is the coded terminal.runtime_not_found frame, and the
  reservation is released;
* a live PTY session survives the control frames term4 never sent — an
  empty binary frame, list/bool/huge-int-literal resize dimensions, null /
  non-str / 1e309 ``input`` data, a bare ``NaN`` document — and still
  closes cleanly;
* the input budget: a second 60KB binary frame crosses MAX_INPUT_BYTES and
  is the ``input_limit`` close, never an exception, with the reservation
  released.
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import terminal_pty, terminal_svc
from hub.auth import require_auth

#: Past json.loads' str->int conversion cap: parsing raises ValueError.
_HUGE_DIGITS = "9" * 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


async def _admin_auth(_websocket):
    return ("tok", "admin")


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _TerminalSandbox(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term5-pin-"))
        self.audit = self.dir / "terminal-audit.jsonl"
        patched = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.client = _client()

    def _cfg(self, **section):
        patched = mock.patch.object(
            terminal_svc, "settings_section", return_value=section
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _bounded(self, fn, seconds: float = 30.0):
        """Run *fn* on a worker with a deadline: a FIFO must not hang it."""
        box: dict = {}

        def _run():
            try:
                box["value"] = fn()
            except Exception as exc:  # noqa: BLE001 - surfaced below
                box["exc"] = exc

        worker = threading.Thread(target=_run, daemon=True)
        worker.start()
        worker.join(seconds)
        if worker.is_alive():
            self.fail(f"request hung past {seconds}s (leftover FIFO class)")
        if "exc" in box:
            raise box["exc"]
        return box["value"]


class AuditFifoPinTests(_TerminalSandbox):
    """A leftover FIFO on the audit trail: coded answers, never a hang."""

    def test_history_with_a_fifo_at_the_audit_path_is_empty_200(self):
        os.mkfifo(self.audit)
        resp = self._bounded(lambda: self.client.get("/api/terminal/history"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json(), {"entries": []})

    def test_run_with_a_fifo_at_the_audit_path_still_executes(self):
        os.mkfifo(self.audit)
        self._cfg(host_enabled=True, shell="/bin/sh")
        resp = self._bounded(
            lambda: self.client.post(
                "/api/terminal/run", json={"command": "echo fifo-pin"}
            )
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIn("fifo-pin", resp.json()["stdout"])

    def test_history_with_a_symlink_to_a_fifo_is_empty_200(self):
        fifo = self.dir / "real.fifo"
        os.mkfifo(fifo)
        self.audit.symlink_to(fifo)
        resp = self._bounded(lambda: self.client.get("/api/terminal/history"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json(), {"entries": []})

    def test_run_with_a_fifo_lock_sidecar_still_audits(self):
        os.mkfifo(str(self.audit) + ".lock")
        self._cfg(host_enabled=True, shell="/bin/sh")
        resp = self._bounded(
            lambda: self.client.post(
                "/api/terminal/run", json={"command": "echo lock-pin"}
            )
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIn("lock-pin", resp.json()["stdout"])
        # _lock_fd unlinked the squatter and the line still landed.
        self.assertIn("lock-pin", self.audit.read_text(encoding="utf-8"))


class ExoticSettingsScalarPinTests(_TerminalSandbox):
    """settings.terminal shapes YAML can really produce must render coded."""

    def _shapes(self):
        selfref = yaml.safe_load("cwd: &a\n  - *a")["cwd"]
        return {
            "selfref-anchor-list": {"cwd": selfref},
            "yaml-set": {"shell": {1, 2}},
            "yaml-binary-bytes": {"shell": b"\xff\xfe"},
            "yaml-date": {"cwd": datetime.date(2024, 1, 1)},
            "yaml-nan": {"cwd": float("nan")},
            "dict-shell": {"shell": {"\ud800": 1}},
            "inf-host-enabled": {"host_enabled": float("inf")},
        }

    def test_status_renders_every_shape(self):
        for name, section in self._shapes().items():
            with self.subTest(name=name):
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=section
                ):
                    resp = self.client.get("/api/terminal")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())
                self.assertNotIn("\ud800", resp.text)

    def test_run_executes_under_every_shape(self):
        for name, section in self._shapes().items():
            with self.subTest(name=name):
                merged = {"host_enabled": True, **section}
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=merged
                ):
                    resp = self.client.post(
                        "/api/terminal/run", json={"command": "echo shape-pin"}
                    )
                # An unusable configured shell falls back or is refused as
                # the rc-127 receipt; either way a rendered 200, never a 500.
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())


class _PtySandbox(_TerminalSandbox):
    def setUp(self):
        super().setUp()
        patched = mock.patch.object(
            terminal_pty, "authenticate_websocket", new=_admin_auth
        )
        patched.start()
        self.addCleanup(patched.stop)
        with terminal_pty._sessions_lock:
            terminal_pty._sessions.clear()

    def tearDown(self):
        with terminal_pty._sessions_lock:
            leaked = dict(terminal_pty._sessions)
            terminal_pty._sessions.clear()
        self.assertEqual(leaked, {}, "PTY session reservation leaked")

    def _drain_to_close(self, ws, budget: int = 1000) -> list:
        frames = []
        for _ in range(budget):
            message = ws.receive()
            frames.append(message)
            if message["type"] == "websocket.close":
                return frames
        self.fail(f"server never closed; last frames: {frames[-3:]!r}")


class PtyLeftoverFramePinTests(_PtySandbox):
    def _open_host(self):
        self._cfg(host_enabled=True, shell="/bin/sh")
        return self.client.websocket_connect("/api/terminal/ws?target=host")

    def test_non_executable_shell_is_the_coded_runtime_frame(self):
        # /etc/hostname is a real file, so _argv's is_file gate passes and
        # the spawn raises PermissionError — an OSError the old
        # FileNotFoundError-only handler missed as an unhandled task death.
        self._cfg(host_enabled=True)
        with self.client.websocket_connect(
            "/api/terminal/ws?target=host&shell=%2Fetc%2Fhostname"
        ) as ws:
            frames = self._drain_to_close(ws, budget=50)
        texts = [f.get("text") for f in frames if f.get("text")]
        self.assertTrue(
            any("terminal.runtime_not_found" in t for t in texts), frames
        )

    def test_term5_control_frames_do_not_kill_the_session(self):
        with self._open_host() as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            _starlette(ready)
            ws.send_bytes(b"")  # empty binary frame
            ws.send_text('{"type":"resize","cols":[1],"rows":{"a":1}}')
            ws.send_text('{"type":"resize","cols":true,"rows":false}')
            ws.send_text(
                '{"type":"resize","cols":' + _HUGE_DIGITS + ',"rows":5}'
            )
            ws.send_text('{"type":"input","data":null}')
            ws.send_text('{"type":"input","data":1e309}')
            ws.send_text('{"type":{"a":1}}')
            ws.send_text("NaN")
            ws.send_text('{"type":"ping","x":"\\ud800"}')
            # Leading newline: the junk data frames left a torn line.
            ws.send_text('{"type":"input","data":"\\nexit\\n"}')
            frames = self._drain_to_close(ws)
        self.assertTrue(
            any(f.get("bytes") for f in frames), "no PTY output before close"
        )

    def test_second_binary_frame_over_the_input_budget_is_the_limit_close(self):
        with self._open_host() as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            chunk = b":" * 60000
            ws.send_bytes(chunk)
            ws.send_bytes(chunk)  # crosses MAX_INPUT_BYTES (64KB)
            self._drain_to_close(ws)


if __name__ == "__main__":
    unittest.main()
