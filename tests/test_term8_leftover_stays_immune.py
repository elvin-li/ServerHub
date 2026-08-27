"""Terminal leftover sweep #8: stays-immune pins for the seams term 7 skipped.

A fresh hunt over the terminal settings JSON surfaces (GET /api/terminal,
POST /api/terminal/run, GET /api/terminal/history, and the terminal branch
of GET/PUT /api/settings) replayed the leftover zoo against the mounted app
through the REAL disk paths — poisoned services.yaml documents on disk (not
mocked ``settings_section``) and poisoned/misshapen terminal-audit.jsonl
nodes — plus over-cap numeric literals in the request bodies themselves.

No live raw 500 remains.  These pins hold the contracts the probe verified
but no prior sweep had written down:

* a >4300-digit JSON int literal in a POST /api/terminal/run body (the
  ``timeout`` int field, the ``command`` str field, an undeclared field)
  and in the PUT /api/settings *terminal branch* is the body-parse 400 —
  ``json.loads`` raises the digit-cap ValueError, not JSONDecodeError, so
  it rides FastAPI's catch-all body handler, never a raw 500 — and nothing
  lands on disk; the same digits in the history ``limit`` query param are
  pydantic's 422;
* a YAML key longer than the scanner's 1024-char simple-key limit (a
  leftover over-cap hex int pasted as a *key* inside settings.terminal)
  makes the whole document unparseable: reads degrade to defaults with the
  host shell reading as *disabled* (the safe default for the RCE gate),
  the run route is the coded 403, and PUT /api/settings refuses with the
  coded 503 ``settings.config_unreadable`` leaving the file byte-identical
  — never a wipe, never a raw 500;
* a self-referential ``settings.terminal`` anchor and a ``<<`` merge-key
  section survive ``yaml.safe_load`` on the real file: GET /api/terminal
  renders, the run executes, and a PUT through the deep_merge cycle guard
  re-dumps a file that still parses with the auth block intact;
* a directory, a self-pointing symlink, or a read-only file squatting the
  audit trail: the run still executes and answers its 200 receipt
  (``_audit`` never breaks the request) and history answers 200;
* audit line shapes term 7's digit-cap fix did not enumerate — an over-cap
  *negative* int, an over-cap digit-run float (``float(str)`` is uncapped:
  it parses to inf and drops field-level), a 1e99999 exponent, an over-cap
  ``rc``, non-dict JSON documents (list / scalar / string), a BOM-prefixed
  line, trailing garbage, duplicate keys — each keeps every healthy row
  and stays Starlette-encodable.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import config, terminal_svc
from hub.auth import require_auth

#: Past CPython's int(str) digit cap: json.loads raises ValueError (not
#: JSONDecodeError) building the literal.
_HUGE_DIGITS = "9" * 4400

JSON_HDR = {"Content-Type": "application/json"}

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


class _DiskSandbox(unittest.TestCase):
    """Real services.yaml + data dir + audit path, no mocked sections."""

    #: Overridden per class; written verbatim to the scratch services.yaml.
    yaml_body = (
        "settings:\n"
        "  auth:\n"
        "    enabled: true\n"
        "    username: admin\n"
        "    password_hash: sentinel-hash\n"
        "  terminal:\n"
        "    host_enabled: true\n"
    )

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        self.audit = data / "terminal-audit.jsonl"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (terminal_svc, "AUDIT_PATH", self.audit),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        self.yaml_path.write_text(self.yaml_body, encoding="utf-8")
        config.reload_cfg()
        self.client = _client()

    def assert_coded_not_500(self, response, status: int) -> dict:
        self.assertEqual(response.status_code, status, response.text[:300])
        body = response.json()
        _starlette(body)
        return body


class RunBodyDigitCapPinTests(_DiskSandbox):
    """>4300-digit JSON int literals on the terminal routes: the body-parse
    400 (or pydantic's 422 for the query param), never the raw 500 that
    json.loads' digit-cap ValueError — not JSONDecodeError — would be if a
    body parser only caught the decode error."""

    def test_run_and_terminal_patch_bodies_answer_400(self):
        huge = _HUGE_DIGITS.encode()
        before = self.yaml_path.read_bytes()
        for label, method, path, body in (
            ("run timeout int field", "POST", "/api/terminal/run",
             b'{"command": "echo hi", "target": "host", "timeout": ' + huge + b"}"),
            ("run int for str command", "POST", "/api/terminal/run",
             b'{"command": ' + huge + b', "target": "host"}'),
            ("run undeclared field", "POST", "/api/terminal/run",
             b'{"command": "echo hi", "target": "host", "extra": ' + huge + b"}"),
            ("run negative int", "POST", "/api/terminal/run",
             b'{"command": "echo hi", "target": "host", "timeout": -' + huge + b"}"),
            ("terminal branch cwd int", "PUT", "/api/settings",
             b'{"terminal": {"cwd": ' + huge + b"}}"),
            ("terminal branch gate int", "PUT", "/api/settings",
             b'{"terminal": {"host_enabled": ' + huge + b"}}"),
        ):
            with self.subTest(label=label):
                response = self.client.request(
                    method, path, content=body, headers=JSON_HDR
                )
                self.assertEqual(response.status_code, 400, response.text[:300])
                _starlette(response.json())
        # Every refused body was refused before the route ran: nothing landed.
        self.assertEqual(self.yaml_path.read_bytes(), before)
        # And no phantom audit line was written for a command that never ran.
        self.assertFalse(self.audit.exists())

    def test_huge_history_limit_is_the_422(self):
        for query in (_HUGE_DIGITS, "-" + _HUGE_DIGITS):
            with self.subTest(query=query[:8]):
                response = self.client.get(
                    "/api/terminal/history", params={"limit": query}
                )
                self.assert_coded_not_500(response, 422)


class ScannerKeyLimitPinTests(_DiskSandbox):
    """A leftover over-cap hex int pasted as a KEY inside settings.terminal
    is longer than the YAML scanner's 1024-char simple-key limit, so the
    whole document stops parsing.  Reads degrade to safe defaults, the RCE
    gate reads as disabled, and the mutate side refuses coded — the file
    stays byte-identical, never wiped, never a raw 500."""

    yaml_body = (
        "settings:\n"
        "  auth:\n"
        "    enabled: true\n"
        "    username: admin\n"
        "    password_hash: sentinel-hash\n"
        "  terminal:\n"
        "    host_enabled: true\n"
        "    " + "0x" + "F" * 5000 + ": leftover\n"
    )

    def test_terminal_status_degrades_to_the_safe_default(self):
        body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        # The stored gate was true, but an unparseable document must read as
        # disabled: for the host-shell RCE gate the fallback is the lock.
        self.assertIs(body["host_enabled"], False)

    def test_run_is_the_coded_403_not_a_500(self):
        response = self.client.post(
            "/api/terminal/run", json={"command": "echo hi", "target": "host"}
        )
        body = self.assert_coded_not_500(response, 403)
        self.assertEqual(body["detail"]["code"], "terminal.host_disabled")

    def test_settings_read_and_history_stay_up(self):
        self.assert_coded_not_500(self.client.get("/api/settings"), 200)
        body = self.assert_coded_not_500(
            self.client.get("/api/terminal/history"), 200
        )
        self.assertEqual(body["entries"], [])

    def test_terminal_patch_refuses_coded_and_the_file_is_intact(self):
        before = self.yaml_path.read_bytes()
        response = self.client.put(
            "/api/settings", json={"terminal": {"host_enabled": False}}
        )
        body = self.assert_coded_not_500(response, 503)
        self.assertEqual(body["detail"]["code"], "settings.config_unreadable")
        self.assertEqual(self.yaml_path.read_bytes(), before)


class CyclicAndMergeKeySectionPinTests(_DiskSandbox):
    """A self-referential anchor and a ``<<`` merge key riding the stored
    terminal section: reads render, the run executes, and the PUT round
    trip re-dumps a file that still parses with the auth block intact."""

    yaml_body = (
        "settings:\n"
        "  auth:\n"
        "    enabled: true\n"
        "    username: admin\n"
        "    password_hash: sentinel-hash\n"
        "  shared: &m\n"
        "    cwd: /tmp\n"
        "  terminal: &t\n"
        "    <<: *m\n"
        "    host_enabled: true\n"
        "    self: *t\n"
    )

    def test_terminal_status_renders_200(self):
        body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        self.assertIs(body["host_enabled"], True)
        self.assertEqual(body["cwd"], "/tmp")

    def test_run_executes_over_the_cycle(self):
        response = self.client.post(
            "/api/terminal/run", json={"command": "echo term8-ok", "target": "host"}
        )
        body = self.assert_coded_not_500(response, 200)
        self.assertIn("term8-ok", body["stdout"])
        self.assertEqual(body["rc"], 0)

    def test_put_round_trip_keeps_the_file_parseable(self):
        response = self.client.put(
            "/api/settings", json={"terminal": {"shell": "/bin/sh"}}
        )
        self.assert_coded_not_500(response, 200)
        # The re-dumped document must load again (safe_dump writes aliases
        # for the recursive node rather than hanging or raising) and keep
        # every sibling key.
        on_disk = yaml.safe_load(self.yaml_path.read_text())
        self.assertEqual(
            on_disk["settings"]["auth"]["password_hash"], "sentinel-hash"
        )
        terminal = on_disk["settings"]["terminal"]
        self.assertEqual(terminal["shell"], "/bin/sh")
        self.assertIs(terminal["host_enabled"], True)
        self.assertEqual(terminal["cwd"], "/tmp")


class AuditSinkShapePinTests(_DiskSandbox):
    """Misshapen nodes squatting the audit trail during a live host run:
    the command still executes and answers its 200 receipt (the trail is
    best-effort by design), and history answers 200.  Term 5 pinned the
    FIFO; the directory / symlink-loop / read-only shapes were never sent."""

    def _occupy(self, shape: str) -> None:
        if shape == "dir":
            self.audit.mkdir()
        elif shape == "symloop":
            self.audit.symlink_to(self.audit)
        elif shape == "readonly":
            self.audit.write_text("")
            os.chmod(self.audit, 0o400)
            self.addCleanup(lambda: os.chmod(self.audit, 0o600))

    def test_run_and_history_survive_every_sink_shape(self):
        for shape in ("dir", "symloop", "readonly"):
            with self.subTest(shape=shape):
                if self.audit.is_symlink() or self.audit.exists():
                    # Reset between subtests.
                    if self.audit.is_dir() and not self.audit.is_symlink():
                        self.audit.rmdir()
                    else:
                        self.audit.unlink()
                self._occupy(shape)
                response = self.client.post(
                    "/api/terminal/run",
                    json={"command": "echo sink-ok", "target": "host"},
                )
                body = self.assert_coded_not_500(response, 200)
                self.assertIn("sink-ok", body["stdout"])
                history = self.assert_coded_not_500(
                    self.client.get("/api/terminal/history"), 200
                )
                self.assertIsInstance(history["entries"], list)
                _starlette(history["entries"])


class AuditLineZooPinTests(_DiskSandbox):
    """Audit line shapes term 7's digit-cap fix did not enumerate: each one
    keeps every healthy row around it and the response stays encodable."""

    def _history(self) -> list[dict]:
        body = self.assert_coded_not_500(
            self.client.get("/api/terminal/history"), 200
        )
        _starlette(body["entries"])
        return body["entries"]

    def test_over_cap_negative_int_keeps_the_row(self):
        self.audit.write_text(
            '{"ts": -' + _HUGE_DIGITS + ', "command": "neg-row", "rc": 0}\n'
        )
        entries = self._history()
        self.assertEqual([e.get("command") for e in entries], ["neg-row"])
        # int("-9…") past the digit cap is the same ValueError the positive
        # spelling raises; the parse hook drops the field, not the row.
        self.assertIsNone(entries[0]["ts"])
        self.assertEqual(entries[0]["rc"], 0)

    def test_over_cap_digit_run_float_keeps_the_row(self):
        # float(str) has no digit cap: the literal parses to inf, and the
        # response sanitizer drops the unencodable field, not the row.
        self.audit.write_text(
            '{"ts": ' + _HUGE_DIGITS + '.5, "command": "float-row", "rc": 0}\n'
            '{"ts": 1e99999, "command": "exp-row", "rc": 0}\n'
        )
        entries = self._history()
        self.assertEqual(
            [e.get("command") for e in entries], ["float-row", "exp-row"]
        )
        self.assertIsNone(entries[0]["ts"])
        self.assertIsNone(entries[1]["ts"])

    def test_over_cap_rc_keeps_the_row(self):
        self.audit.write_text(
            '{"ts": 1, "command": "rc-row", "rc": ' + _HUGE_DIGITS + "}\n"
        )
        entries = self._history()
        self.assertEqual([e.get("command") for e in entries], ["rc-row"])
        self.assertIsNone(entries[0]["rc"])
        self.assertEqual(entries[0]["ts"], 1)

    def test_non_dict_documents_are_skipped_not_raised(self):
        self.audit.write_text(
            json.dumps({"ts": 1, "command": "head-row", "rc": 0}) + "\n"
            "[1, 2]\n"
            "42\n"
            '"just a string"\n'
            "null\n"
            "true\n"
            + json.dumps({"ts": 2, "command": "tail-row", "rc": 0}) + "\n"
        )
        entries = self._history()
        self.assertEqual(
            [e.get("command") for e in entries], ["head-row", "tail-row"]
        )

    def test_bom_garbage_and_duplicate_key_lines_never_500(self):
        self.audit.write_text(
            '\ufeff{"ts": 1, "command": "bom-row"}\n'
            '{"ts": 2, "command": "garbage-row"} trailing\n'
            '{"ts": 3, "command": "first", "command": "dup-row"}\n'
            + json.dumps({"ts": 4, "command": "tail-row"}) + "\n",
            encoding="utf-8",
        )
        entries = self._history()
        commands = [e.get("command") for e in entries]
        # The BOM line and the trailing-garbage line are corrupt documents
        # (skipped); duplicate keys parse last-wins; the tail row survives.
        self.assertEqual(commands, ["dup-row", "tail-row"])


if __name__ == "__main__":
    unittest.main()
