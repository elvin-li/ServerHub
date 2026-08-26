"""Terminal leftover sweep #4: transport-layer pins over the mounted app.

A fresh hunt across the Terminal surface — GET /api/terminal,
POST /api/terminal/run, GET /api/terminal/history, the docker-exec twin
POST /api/containers/{name}/exec, and (new for this sweep) the interactive
PTY WebSocket at /api/terminal/ws — replayed every leftover class: surrogate
escapes in body keys AND values, option-shaped / over-length / >4300-digit
container names, iterbomb bodies, huge-int JSON literals (ValueError, not
JSONDecodeError), invalid-UTF-8 bodies and query strings, hostile control
frames, and the vanished docker CLI.

No live 500 was found: terms 1–3 fixed the service layer (``_config_text``,
``_jsonable``, ``_docker_vanished``) and FastAPI's body-parse catch-all
absorbs the parser-level ValueErrors.  What *was* uncovered is the entire
WebSocket transport: nothing in the suite ever drove the mounted
``/api/terminal/ws`` route through Starlette, so a regression in the accept /
reject / frame-handling paths (a 500 during the upgrade, an unhandled
exception killing the event loop task, a leaked session reservation that
ratchets toward the 429 lockout) would ship silently.  These pins hold the
route contracts end-to-end:

* handshake refusals are coded error frames (host_disabled / no_container /
  bad_target), never a raised exception;
* a live host session survives every hostile control frame — JSON array,
  iterbomb nesting, resize with ``1e309`` / hex-string dimensions,
  surrogate-escape input, non-str ``data`` — and still closes cleanly;
* a text frame over MAX_MESSAGE_BYTES is the ``input_limit`` close, not an
  exception;
* a docker CLI that vanished before the container spawn is the coded
  ``terminal.runtime_not_found`` frame (FileNotFoundError from the spawn IS
  the disk confirm on this path), never an unhandled 500;
* every close — error, limit, vanished-CLI, normal exit — releases its
  session reservation, so refused upgrades cannot ratchet the per-user /
  global caps into a permanent ``terminal.too_many_sessions`` lockout;
* invalid-UTF-8 percent-encoded query params are a coded refusal.

Plus the one-shot HTTP vectors terms 1–3 did not pin at the route layer:
surrogate-escape run bodies (values and keys), hostile container names on
the run route, iterbomb / huge-int / invalid-UTF-8 raw bodies, an audit path
occupied by a directory, and the exec twin's surrogate / NUL command
receipts.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import terminal_pty, terminal_svc
from hub.auth import require_auth

#: Past the str->int conversion cap: json.loads of this raises ValueError.
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
    """Stand-in for the session check; the PTY security tests own the real one."""
    return ("tok", "admin")


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _TerminalSandbox(unittest.TestCase):
    """Throwaway audit trail + patched terminal settings, mounted-app client."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term4-pin-"))
        self.audit = self.dir / "terminal-audit.jsonl"
        patched = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patched.start()
        self.addCleanup(patched.stop)
        # The audit writer leaves its flock sidecar next to the trail.
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.client = _client()

    def _cfg(self, **section):
        patched = mock.patch.object(
            terminal_svc, "settings_section", return_value=section
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _post_raw(self, path: str, raw):
        return self.client.post(
            path, content=raw, headers={"content-type": "application/json"}
        )


class _PtySandbox(_TerminalSandbox):
    """Adds the WebSocket auth stand-in and asserts no session leaks."""

    def setUp(self):
        super().setUp()
        patched = mock.patch.object(
            terminal_pty, "authenticate_websocket", new=_admin_auth
        )
        patched.start()
        self.addCleanup(patched.stop)

    def tearDown(self):
        # Every accept/reject path must release its reservation: a leak here
        # ratchets toward a permanent terminal.too_many_sessions lockout.
        with terminal_pty._sessions_lock:
            leaked = dict(terminal_pty._sessions)
            terminal_pty._sessions.clear()
        self.assertEqual(leaked, {}, "PTY session reservation leaked")

    def _drain_to_close(self, ws, budget: int = 1000) -> list:
        """Read frames until the server closes; the route must close, not raise."""
        frames = []
        for _ in range(budget):
            message = ws.receive()
            frames.append(message)
            if message["type"] == "websocket.close":
                return frames
        self.fail(f"server never closed; last frames: {frames[-3:]!r}")


class PtyHandshakeRefusalPinTests(_PtySandbox):
    """Refused upgrades are coded error frames + close, never an exception."""

    def test_host_target_while_disabled_is_the_coded_4403_frame(self):
        self._cfg(host_enabled=False)
        with self.client.websocket_connect("/api/terminal/ws?target=host") as ws:
            message = ws.receive_json()
        self.assertEqual(
            message, {"type": "error", "code": "terminal.host_disabled"}
        )
        _starlette(message)

    def test_container_target_without_a_container_is_the_coded_4400_frame(self):
        with self.client.websocket_connect("/api/terminal/ws?target=container") as ws:
            message = ws.receive_json()
        self.assertEqual(message["type"], "error")
        self.assertEqual(message["code"], "terminal.no_container")

    def test_unknown_target_is_a_coded_refusal(self):
        # %2e%2e: an option/path-shaped target must never reach a spawn.
        with self.client.websocket_connect("/api/terminal/ws?target=%2e%2e") as ws:
            message = ws.receive_json()
        self.assertEqual(message["type"], "error")

    def test_invalid_utf8_query_params_are_a_coded_refusal(self):
        # Percent-encoded lone-surrogate bytes in container/shell: the
        # sanitizers must refuse them as data, not raise during the upgrade.
        with self.client.websocket_connect(
            "/api/terminal/ws?target=container&container=%ED%A0%80&shell=%ff"
        ) as ws:
            message = ws.receive_json()
        self.assertEqual(message["type"], "error")
        _starlette(message)


class PtyLiveSessionPinTests(_PtySandbox):
    """A real PTY session over the mounted route survives hostile frames."""

    def _open_host(self):
        self._cfg(host_enabled=True, shell="/bin/sh")
        # Over-cap digit cols (int(str) ValueError past the conversion cap)
        # and 1e309 rows must clamp to defaults, not kill the handshake.
        return self.client.websocket_connect(
            "/api/terminal/ws?target=host&shell=%2Fbin%2Fsh"
            "&cols=" + _HUGE_DIGITS + "&rows=1e309"
        )

    def test_hostile_control_frames_do_not_kill_the_session(self):
        with self._open_host() as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            _starlette(ready)
            # Non-object JSON, torn JSON, iterbomb nesting, resize with
            # inf / hex-string dimensions, surrogate-escape input, and a
            # non-str data payload: each used to be a session-killing class.
            ws.send_text("[]")
            ws.send_text('"oops"')
            ws.send_text("{")
            ws.send_text("[" * 6000 + "]" * 6000)
            ws.send_text('{"type":"resize","cols":1e309,"rows":"0x10"}')
            ws.send_text('{"type":"input","data":"echo \\ud800leftover\\n"}')
            ws.send_text('{"type":"input","data":{"a":1}}')
            ws.send_text('{"type":"ping"}')
            # Leading newline: the non-str data frame left a torn line.
            ws.send_text('{"type":"input","data":"\\nexit\\n"}')
            frames = self._drain_to_close(ws)
        # The shell ran and exited: bytes flowed back before the close.
        self.assertTrue(
            any(f.get("bytes") for f in frames),
            "no PTY output before close",
        )

    def test_text_frame_over_the_message_cap_is_the_input_limit_close(self):
        with self._open_host() as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            ws.send_text("x" * (terminal_pty.MAX_MESSAGE_BYTES + 10))
            self._drain_to_close(ws)

    def test_audit_records_the_pty_start_and_end(self):
        with self._open_host() as ws:
            ready = ws.receive_json()
            self.assertEqual(ready["type"], "ready", ready)
            ws.send_text('{"type":"input","data":"exit\\n"}')
            self._drain_to_close(ws)
        events = [
            json.loads(line).get("event")
            for line in self.audit.read_text(encoding="utf-8").splitlines()
        ]
        self.assertIn("pty_start", events)
        self.assertIn("pty_end", events)


class PtyVanishedDockerPinTests(_PtySandbox):
    """Container PTY with the docker CLI gone from disk."""

    def test_vanished_cli_is_the_coded_runtime_not_found_frame(self):
        # The spawn's FileNotFoundError IS the disk confirm on this path:
        # the coded frame must come back, never an unhandled 500 that kills
        # the upgrade with an empty close.
        gone = self.dir / "docker-gone"
        with mock.patch.object(terminal_pty, "DOCKER", str(gone)):
            with self.client.websocket_connect(
                "/api/terminal/ws?target=container&container=app"
            ) as ws:
                frames = self._drain_to_close(ws, budget=20)
        texts = [f.get("text") for f in frames if f.get("text")]
        self.assertTrue(
            any("terminal.runtime_not_found" in t for t in texts), frames
        )


class RunRouteLeftoverBodyPinTests(_TerminalSandbox):
    """POST /api/terminal/run with the body shapes terms 1-3 never sent."""

    def test_surrogate_escape_command_is_the_rc127_receipt_not_a_500(self):
        # JSON "\ud800" parses to a lone-surrogate str; the spawn refuses it
        # (fsencode cannot represent it) and the receipt must render.
        self._cfg(host_enabled=True, shell="/bin/sh")
        resp = self._post_raw(
            "/api/terminal/run", '{"command":"echo \\ud800leftover"}'
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["rc"], 127)
        self.assertNotIn("\ud800", resp.text)
        _starlette(body)

    def test_surrogate_escape_body_key_is_ignored_and_the_command_runs(self):
        self._cfg(host_enabled=True, shell="/bin/sh")
        resp = self._post_raw(
            "/api/terminal/run", '{"\\ud800":"x","command":"echo term4-key"}'
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertTrue(body["ok"], body)
        self.assertIn("term4-key", body["stdout"])
        self.assertNotIn("\ud800", resp.text)

    def test_hostile_container_names_are_the_coded_400(self):
        # Surrogate, option-shaped, and >4300-digit names must all be refused
        # before any argv is built (the same guard as the exec twin).
        for name, raw in (
            ("surrogate", '"\\ud800"'),
            ("option", '"-H"'),
            ("huge-digits", '"' + _HUGE_DIGITS + '"'),
        ):
            with self.subTest(name=name):
                resp = self._post_raw(
                    "/api/terminal/run",
                    '{"command":"true","target":"container","container":' + raw + "}",
                )
                self.assertEqual(resp.status_code, 400, resp.text[:200])
                self.assertEqual(
                    resp.json()["detail"]["code"], "cli.invalid_value"
                )

    def test_surrogate_escape_container_cwd_keeps_a_scrubbed_receipt(self):
        # The cwd is spliced into the exec's shell string; the surrogate makes
        # the spawn unrepresentable, and the echoed-back cwd must be scrubbed.
        self._cfg()
        resp = self._post_raw(
            "/api/terminal/run",
            '{"command":"true","target":"container","container":"app","cwd":"\\ud800"}',
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["rc"], 127)
        self.assertNotIn("\ud800", resp.text)

    def test_parser_level_poison_bodies_are_400_not_500(self):
        # json.loads raises ValueError (not JSONDecodeError) on the huge-int
        # literal, RecursionError on the iterbomb, UnicodeDecodeError on the
        # invalid-UTF-8 bytes: each must be the body-parse 400, never a 500.
        self._cfg(host_enabled=True, shell="/bin/sh")
        for name, raw in (
            ("huge-int timeout", '{"command":"true","timeout":' + _HUGE_DIGITS + "}"),
            ("huge-int document", _HUGE_DIGITS),
            ("iterbomb", "[" * 20000 + "]" * 20000),
            ("invalid utf-8", b'{"command":"\xff\xfe"}'),
        ):
            with self.subTest(name=name):
                resp = self._post_raw("/api/terminal/run", raw)
                self.assertIn(resp.status_code, (400, 422), resp.text[:200])


class AuditPathOccupiedPinTests(_TerminalSandbox):
    """A leftover directory squatting on the audit path must not 500 anything."""

    def test_run_still_executes_and_history_answers_empty(self):
        self.audit.mkdir()
        self._cfg(host_enabled=True, shell="/bin/sh")
        resp = self.client.post("/api/terminal/run", json={"command": "echo dir-pin"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIn("dir-pin", resp.json()["stdout"])
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json(), {"entries": []})


class ExecTwinLeftoverPinTests(_TerminalSandbox):
    """POST /api/containers/{name}/exec — the Terminal page's docker-exec twin.

    Engine-down / vanished-CLI 503s are pinned in test_engine_down_leftover_
    503.py; these are the hostile-input receipts that never reach a spawn.
    """

    def test_surrogate_and_option_names_are_the_coded_400(self):
        for name, path in (
            ("surrogate", "/api/containers/%ED%A0%80/exec"),
            ("option", "/api/containers/-H/exec"),
            ("huge-digits", "/api/containers/" + "9" * 3000 + "/exec"),
        ):
            with self.subTest(name=name):
                resp = self.client.post(path, json={"command": "true"})
                self.assertEqual(resp.status_code, 400, resp.text[:200])
                self.assertEqual(
                    resp.json()["detail"]["code"], "cli.invalid_value"
                )

    def test_surrogate_escape_command_is_the_invalid_argv_receipt(self):
        # The argv guard refuses the unrepresentable command before any
        # docker spawn, so this receipt is deterministic with or without a
        # docker CLI on the host — and it must render, never 500.
        resp = self._post_raw(
            "/api/containers/app/exec", '{"command":"echo \\ud800"}'
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertNotIn("\ud800", resp.text)
        _starlette(body)

    def test_nul_command_is_the_invalid_argv_receipt(self):
        resp = self.client.post(
            "/api/containers/app/exec", json={"command": "tr\x00ue"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertFalse(resp.json()["ok"])

    def test_off_allowlist_shell_is_the_coded_400(self):
        resp = self.client.post(
            "/api/containers/app/exec",
            json={"command": "true", "shell": "/bin/evil"},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "container.bad_shell")


if __name__ == "__main__":
    unittest.main()
