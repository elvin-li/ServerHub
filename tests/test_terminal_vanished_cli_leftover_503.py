"""Terminal leftover sweep #3: the vanished docker CLI on container runs.

A fresh hunt over the mounted terminal routes (GET /api/terminal,
POST /api/terminal/run, GET /api/terminal/history) replayed every sweep
class — surrogate keys AND values, YAML-hex over-cap ints, >4300-digit
JSON literals, inf/nan clocks and limits, deep nesting, NUL — and found
one genuine leftover:

* **fixed** — ``run_container`` classified only the *engine-down message
  pattern* (``looks_engine_down`` + forced probe).  ``terminal_svc._run``
  collapses a FileNotFoundError spawn into its own sentinel — ``rc 127`` +
  ``"not found: <docker path>"`` — which that regex never matches, so a
  docker CLI that vanished between requests (OrbStack uninstalled
  mid-session, a dying mount) came back 200 as the *command's own output*:
  a raw untranslated receipt the SPA cannot explain, while the Containers
  page, actions, tools, compose and catalog all answer the coded 503 for
  the same docker-unreachable state.  ``_docker_vanished`` now feeds the
  same classifier: sentinel match, then **disk confirm on the failure path
  only**, and the forced ``engine_up`` probe stays the final arbiter (it
  cannot answer "up" while the CLI is gone).

Everything else was already immune at the HTTP layer; the pins below hold
the mounted-route contracts so a refactor cannot quietly reopen them:

* GET /api/terminal renders 200 with YAML-hex over-cap and lone-surrogate
  cwd/shell settings (fallbacks, never a 500);
* GET /api/terminal/history skips only the poisoned line — a >4300-digit
  literal is ValueError inside ``json.loads`` itself, never a wiped
  journal — and scrubs surrogate *keys* as well as values; ``Infinity``
  values are nulled field-level, the row survives;
* POST /api/terminal/run with a >4300-digit ``timeout`` literal dies
  inside FastAPI's body parse as a plain ValueError (not JSONDecodeError)
  and is answered as a 4xx, never a 500.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import terminal_svc
from hub.auth import require_auth

#: A real int object past CPython's 4300-digit int->str cap (YAML hex
#: parsing has no digit limit).
_HEX_HUGE = yaml.safe_load("v: 0x" + "F" * 5000)["v"]
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


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _TerminalSandbox(unittest.TestCase):
    """Throwaway audit trail + patched terminal settings for route tests."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term-vanish-pin-"))
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

    def _engine(self, up: bool):
        patched = mock.patch.object(
            terminal_svc, "engine_up", lambda force=False: up
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _docker(self, path) -> None:
        patched = mock.patch.object(terminal_svc, "DOCKER", str(path))
        patched.start()
        self.addCleanup(patched.stop)

    def _run_container(self, command="echo hi"):
        return self.client.post(
            "/api/terminal/run",
            json={"command": command, "target": "container", "container": "app"},
        )


class VanishedDockerCliTests(_TerminalSandbox):
    """POST /api/terminal/run (container) when the docker CLI is gone."""

    def test_vanished_cli_answers_the_coded_503(self):
        # Real spawn against a path that does not exist: _run collapses the
        # FileNotFoundError into its rc-127 sentinel.  This used to come back
        # 200 with the sentinel as the command's own stderr.
        self._cfg()
        self._docker(self.dir / "docker-gone")
        self._engine(False)
        resp = self._run_container()
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "container.engine_down")
        _starlette(resp.json())

    def test_the_503_is_raised_after_the_audit_line(self):
        # The trail is the only record of what was typed into a root-capable
        # shell; the classification must not erase the attempt.
        self._cfg()
        self._docker(self.dir / "docker-gone")
        self._engine(False)
        self._run_container(command="echo audited")
        lines = self.audit.read_text(encoding="utf-8").splitlines()
        self.assertTrue(
            any(json.loads(l).get("command") == "echo audited" for l in lines)
        )

    def test_sentinel_output_with_the_cli_on_disk_keeps_the_receipt(self):
        # A container command whose own output *is* the sentinel while the
        # CLI is still present must keep its receipt verbatim — the disk
        # confirm is what stops the misclassification.
        on_disk = self.dir / "docker-here"
        on_disk.write_text("#!/bin/sh\n", encoding="utf-8")
        self._cfg()
        self._docker(on_disk)
        self._engine(False)
        receipt = {
            "ok": False, "rc": 127, "stdout": "",
            "stderr": f"not found: {on_disk}", "truncated": False,
            "duration_ms": 0,
        }
        with mock.patch.object(terminal_svc, "_run", return_value=dict(receipt)):
            resp = self._run_container()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["rc"], 127)

    def test_probe_answering_up_keeps_the_receipt(self):
        # The forced engine_up probe stays the final arbiter, matching the
        # looks_engine_down contract.
        gone = self.dir / "docker-gone"
        self._cfg()
        self._docker(gone)
        self._engine(True)
        receipt = {
            "ok": False, "rc": 127, "stdout": "",
            "stderr": f"not found: {gone}", "truncated": False,
            "duration_ms": 0,
        }
        with mock.patch.object(terminal_svc, "_run", return_value=dict(receipt)):
            resp = self._run_container()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["rc"], 127)

    def test_engine_down_message_still_answers_the_coded_503(self):
        # The pre-existing message-pattern branch must survive the fold.
        self._cfg()
        self._engine(False)
        receipt = {
            "ok": False, "rc": 1, "stdout": "",
            "stderr": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
            "truncated": False, "duration_ms": 0,
        }
        with mock.patch.object(terminal_svc, "_run", return_value=dict(receipt)):
            resp = self._run_container()
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "container.engine_down")

    def test_host_run_with_a_missing_shell_keeps_its_rc127_receipt(self):
        # The host path's rc-127 answer is the honest receipt for the
        # operator's own configured shell; the docker classifier must not
        # reach it.
        self._cfg(host_enabled=True, shell=str(self.dir / "shell-gone"))
        self._engine(False)
        resp = self.client.post("/api/terminal/run", json={"command": "echo hi"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["rc"], 127)
        self.assertIn("not found", body["stderr"])


class DockerVanishedHelperTests(unittest.TestCase):
    """The sentinel-plus-disk-confirm gate itself."""

    def test_non_127_rc_is_never_the_sentinel(self):
        with mock.patch.object(terminal_svc, "DOCKER", "/definitely/not/here"):
            self.assertFalse(terminal_svc._docker_vanished(
                {"rc": 1, "stderr": "not found: /definitely/not/here"}
            ))

    def test_unrelated_stderr_is_not_the_sentinel(self):
        with mock.patch.object(terminal_svc, "DOCKER", "/definitely/not/here"):
            self.assertFalse(terminal_svc._docker_vanished(
                {"rc": 127, "stderr": "sh: docker: command not found"}
            ))

    def test_sentinel_with_the_cli_absent_is_vanished(self):
        with mock.patch.object(terminal_svc, "DOCKER", "/definitely/not/here"):
            self.assertTrue(terminal_svc._docker_vanished(
                {"rc": 127, "stderr": "not found: /definitely/not/here"}
            ))

    def test_a_dying_mount_counts_as_gone(self):
        # A NUL in the path makes Path.exists() raise ValueError, the same
        # non-answer as EIO/ESTALE on a dying mount: the CLI is not
        # spawnable from there either way.
        with mock.patch.object(terminal_svc, "DOCKER", "/tmp/\x00docker"):
            self.assertTrue(terminal_svc._docker_vanished(
                {"rc": 127, "stderr": "not found: /tmp/\x00docker"}
            ))


class TerminalRoutesStayImmunePinTests(_TerminalSandbox):
    """HTTP-layer pins for the classes that were already immune."""

    def test_status_route_renders_hex_huge_and_surrogate_settings(self):
        for name, cfg in (
            ("hex-cwd", {"cwd": _HEX_HUGE}),
            ("hex-shell", {"shell": _HEX_HUGE}),
            ("surrogate-cwd", {"cwd": "/tmp/\ud800"}),
            ("surrogate-shell", {"shell": "/bin/\ud800"}),
            ("surrogate-key", {"k\ud800": "v", "cwd": "/tmp"}),
        ):
            with self.subTest(name=name):
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=cfg
                ):
                    resp = self.client.get("/api/terminal")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())

    def test_history_route_skips_only_the_poisoned_lines(self):
        # One >4300-digit line, one Infinity value, one surrogate key, one
        # deep nest, one non-dict, one non-JSON — the sane rows survive and
        # the journal is never wiped whole.
        self.audit.write_text(
            '{"ts": ' + _HUGE_DIGITS + ', "command": "poison"}\n'
            '{"ts": Infinity, "command": "inf-line"}\n'
            '{"\ud800key": "v", "command": "surrogate-key"}\n'
            + "[" * 6000 + "]" * 6000 + "\n"
            + '[1, 2, 3]\n'
            'not json at all\n'
            '{"ts": 1, "command": "sane", "rc": 0}\n',
            encoding="utf-8", errors="surrogatepass",
        )
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        commands = [e.get("command") for e in body["entries"]]
        self.assertIn("sane", commands)
        self.assertIn("inf-line", commands)      # Infinity ts nulled, row kept
        self.assertIn("surrogate-key", commands)  # key scrubbed, row kept
        self.assertNotIn("poison", commands)      # over-cap line skipped alone
        self.assertNotIn("\ud800", resp.text)

    def test_history_route_infinity_value_is_nulled_field_level(self):
        self.audit.write_text(
            '{"ts": Infinity, "command": "inf-line", "rc": 0}\n',
            encoding="utf-8",
        )
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200)
        row = resp.json()["entries"][0]
        self.assertIsNone(row["ts"])
        self.assertEqual(row["rc"], 0)

    def test_run_route_huge_digit_timeout_body_is_a_4xx_not_a_500(self):
        # json.loads of a >4300-digit literal raises ValueError, *not*
        # JSONDecodeError; the route must answer a coded 4xx.
        self._cfg(host_enabled=True)
        resp = self.client.post(
            "/api/terminal/run",
            content='{"command": "echo hi", "timeout": ' + _HUGE_DIGITS + "}",
            headers={"content-type": "application/json"},
        )
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])

    def test_history_route_over_cap_limit_is_a_422_not_a_500(self):
        resp = self.client.get(f"/api/terminal/history?limit={_HUGE_DIGITS}")
        self.assertEqual(resp.status_code, 422, resp.text[:200])


if __name__ == "__main__":
    unittest.main()
