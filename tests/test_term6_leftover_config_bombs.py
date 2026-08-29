"""Terminal leftover sweep #6: subclass method bombs in settings.terminal.

A fresh hunt over GET /api/terminal, POST /api/terminal/run,
GET /api/terminal/history and the PTY WebSocket replayed the leftover zoo
against the mounted app and found one genuinely live class terms 1-5 never
sent: *subclass method bombs riding on config values*.  ``settings_section``
launders the section into a plain dict, but the values survive as-is, and
the terminal service still probed them with bound calls:

* **fixed** — a leftover ``host_enabled`` whose ``__bool__`` raises blew the
  bare ``bool(...)`` in ``host_enabled()``: a 500 on GET /api/terminal and
  POST /api/terminal/run, and an unhandled exception straight out of the PTY
  WebSocket handshake (``_argv`` only catches PermissionError/ValueError).
  ``_cfg_truthy`` now treats an unreadable truthiness as unset — for an RCE
  gate, off is also the safe default;
* **fixed** — a leftover ``cwd``/``shell`` whose ``__bool__`` raises blew
  the bare ``value or fallback`` truthiness chains in ``status()``,
  ``run_host`` and ``_resolve_cwd``: the same 500 pair, plus the PTY
  handshake crash *after* the session was reserved (``_resolve_cwd`` runs
  inside ``_argv``);
* **fixed** — a leftover str-subclass ``cwd`` whose ``.strip()`` raises rode
  through ``_config_text``'s ``isinstance(value, str)`` pass untouched and
  blew ``_resolve_cwd``: a 500 on POST /api/terminal/run and the same PTY
  crash.  ``_config_text`` now always returns an *exact* ``str`` (unbound
  base copy), so no subclass method bomb can ride along;
* **hardened** — ``_jsonable`` got the modules5 unbound convention every
  sibling service already uses (``dict.items``, ``base.__iter__``,
  ``int.__index__``, ``float.__float__``, base ``bytes.decode``, a guarded
  ``getattr`` probe), pinned here as stays-immune unit contracts.

Every pin drives the mounted app (create_app + TestClient,
raise_server_exceptions=False) except the ``_jsonable`` unit contracts.
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


class _BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _BoolBombInt(int):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _BoolBombStr(str):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _StripBombStr(str):
    def strip(self, *args):
        raise RuntimeError("leftover strip bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _EqBombFloat(float):
    __hash__ = float.__hash__

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover __ne__ bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("leftover decode bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError("leftover __getattr__ bomb")


#: The bomb shapes that were live 500s / handshake crashes before the fix.
def _bomb_sections():
    return {
        "bool-bomb host_enabled dict-subclass": {
            "host_enabled": _BoolBombDict({"x": 1})
        },
        "bool-bomb host_enabled int-subclass": {"host_enabled": _BoolBombInt(1)},
        "bool-bomb cwd": {"cwd": _BoolBombStr("/tmp")},
        "bool-bomb shell": {"shell": _BoolBombStr("/bin/sh")},
        "strip-bomb cwd": {"cwd": _StripBombStr("/tmp")},
        "strip-bomb shell": {"shell": _StripBombStr("/bin/sh")},
    }


class _TerminalSandbox(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term6-pin-"))
        self.audit = self.dir / "terminal-audit.jsonl"
        patched = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.client = _client()

    def _cfg(self, section: dict):
        patched = mock.patch.object(
            terminal_svc, "settings_section", return_value=section
        )
        patched.start()
        self.addCleanup(patched.stop)


class StatusConfigBombPinTests(_TerminalSandbox):
    """GET /api/terminal renders 200 fallbacks under every bomb shape."""

    def test_every_bomb_shape_renders_200(self):
        for name, section in _bomb_sections().items():
            with self.subTest(name=name):
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=section
                ):
                    resp = self.client.get("/api/terminal")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                _starlette(resp.json())

    def test_bool_bomb_host_enabled_reads_as_disabled(self):
        # An unreadable truthiness on the RCE gate must fail *closed*.
        for section in (
            {"host_enabled": _BoolBombDict({"x": 1})},
            {"host_enabled": _BoolBombInt(1)},
        ):
            with self.subTest(shape=type(section["host_enabled"]).__name__):
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=section
                ):
                    resp = self.client.get("/api/terminal")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self.assertIs(resp.json()["host_enabled"], False)


class RunConfigBombPinTests(_TerminalSandbox):
    """POST /api/terminal/run under the same bomb shapes."""

    def test_bool_bomb_host_enabled_is_the_coded_403(self):
        self._cfg({"host_enabled": _BoolBombDict({"x": 1})})
        resp = self.client.post("/api/terminal/run", json={"command": "true"})
        self.assertEqual(resp.status_code, 403, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "terminal.host_disabled")

    def test_run_still_executes_under_every_cwd_shell_bomb(self):
        for name, section in _bomb_sections().items():
            if "host_enabled" in section:
                continue
            with self.subTest(name=name):
                merged = {"host_enabled": True, "shell": "/bin/sh", **section}
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=merged
                ):
                    resp = self.client.post(
                        "/api/terminal/run", json={"command": "echo term6-pin"}
                    )
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                # A bombed configured shell falls back (or is the rc-127
                # receipt); a bombed cwd falls back to a real directory and
                # the command still runs.
                _starlette(body)
                if "shell" not in section:
                    self.assertIn("term6-pin", body["stdout"])

    def test_history_still_renders_after_a_bombed_run(self):
        self._cfg({"host_enabled": True, "shell": "/bin/sh",
                   "cwd": _BoolBombStr("/tmp")})
        resp = self.client.post(
            "/api/terminal/run", json={"command": "echo term6-hist"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        entries = resp.json()["entries"]
        self.assertTrue(
            any(e.get("command") == "echo term6-hist" for e in entries), entries
        )
        _starlette(entries)


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


class PtyConfigBombPinTests(_PtySandbox):
    """The PTY handshake under the bomb shapes: coded frames or a live
    session — never an exception raised out of the route."""

    def test_bool_bomb_host_enabled_is_the_coded_refusal_frame(self):
        # This used to raise RuntimeError straight out of the WebSocket
        # handler before the session was even reserved.
        for section in (
            {"host_enabled": _BoolBombDict({"x": 1})},
            {"host_enabled": _BoolBombInt(1)},
        ):
            with self.subTest(shape=type(section["host_enabled"]).__name__):
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=section
                ):
                    with self.client.websocket_connect(
                        "/api/terminal/ws?target=host"
                    ) as ws:
                        message = ws.receive_json()
                self.assertEqual(
                    message,
                    {"type": "error", "code": "terminal.host_disabled"},
                )
                _starlette(message)

    def test_cwd_bombs_still_reach_a_live_session(self):
        # These used to raise out of _resolve_cwd *after* the reservation,
        # killing the handshake with an unhandled exception.
        for name, cwd in (
            ("bool-bomb", _BoolBombStr("/tmp")),
            ("strip-bomb", _StripBombStr("/tmp")),
        ):
            with self.subTest(name=name):
                section = {"host_enabled": True, "shell": "/bin/sh", "cwd": cwd}
                with mock.patch.object(
                    terminal_svc, "settings_section", return_value=section
                ):
                    with self.client.websocket_connect(
                        "/api/terminal/ws?target=host"
                    ) as ws:
                        ready = ws.receive_json()
                        self.assertEqual(ready["type"], "ready", ready)
                        _starlette(ready)
                        ws.send_text('{"type":"input","data":"exit\\n"}')
                        self._drain_to_close(ws)


class JsonableUnboundStaysImmunePinTests(unittest.TestCase):
    """The modules5 unbound contract on terminal_svc._jsonable: nested
    subclass method bombs coerce or drop field-level, never raise."""

    def _render(self, value):
        cleaned = terminal_svc._jsonable(value)
        _starlette(cleaned)
        return cleaned

    def test_dict_items_bomb_still_walks_the_real_entries(self):
        cleaned = self._render({"row": _ItemsBombDict({"a": 1})})
        self.assertEqual(cleaned, {"row": {"a": 1}})

    def test_sequence_and_set_iter_bombs_keep_the_real_elements(self):
        cleaned = self._render({"l": _IterBombList([1, 2]), "s": _IterBombSet({3})})
        self.assertEqual(cleaned["l"], [1, 2])
        self.assertEqual(cleaned["s"], [3])

    def test_int_str_bomb_coerces_to_the_exact_int(self):
        cleaned = self._render({"n": _StrBombInt(7)})
        self.assertEqual(cleaned, {"n": 7})
        self.assertIs(type(cleaned["n"]), int)

    def test_float_eq_bomb_coerces_and_inf_still_drops(self):
        cleaned = self._render(
            {"f": _EqBombFloat(1.5), "inf": _EqBombFloat("inf")}
        )
        self.assertEqual(cleaned["f"], 1.5)
        self.assertIsNone(cleaned["inf"])

    def test_bytes_decode_bomb_uses_the_base_decode(self):
        cleaned = self._render({"b": _DecodeBombBytes(b"\xffok")})
        self.assertEqual(cleaned, {"b": "\ufffdok"})

    def test_getattr_bomb_is_the_str_fallback_not_a_raise(self):
        cleaned = self._render({"o": _GetattrBomb()})
        self.assertIsInstance(cleaned["o"], str)

    def test_bomb_keys_are_scrubbed_not_raised(self):
        cleaned = self._render({_StrBombInt(5): "kept", "ok": 1})
        self.assertEqual(cleaned, {"ok": 1})


if __name__ == "__main__":
    unittest.main()
