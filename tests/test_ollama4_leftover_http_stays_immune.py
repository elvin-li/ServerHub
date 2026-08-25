"""Fourth leftover-500s sweep of the Ollama surface, over the real app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — numeric YAML ids, huge-number JSON journals, vanished-CLI /
engine-down 503-vs-500) were re-reproduced against every route the Ollama
page mounts:

    GET  /api/ollama/status           GET  /api/ollama/pull/log
    POST /api/ollama/pull             POST /api/ollama/models/delete
    POST /api/ollama/models/unload    POST /api/ollama/test
    POST /api/ollama/chat

One live leak was found and fixed: ``ollama_svc._api`` parsed daemon bodies
with a bare ``safe_json_loads`` — no ``parse_int`` hook, unlike brew_cache /
shares_svc / docker_cli / notify_channels.  A single >4300-digit integer
literal anywhere in a daemon answer made ``json.loads`` itself raise the
digit-cap ValueError (NOT JSONDecodeError), so one unrenderable ``size`` in
/api/tags wiped the *entire* models AND resident lists behind a
"response is not json" lie on GET /api/ollama/status, and one huge
``eval_count`` beside a perfectly good generation discarded the whole answer
into the 502 ``generate_failed`` — for unload, *after* the daemon had already
dropped the model, so the panel reported failure for an action that
succeeded.  The hook loads the huge literal as None and ``_safe_int`` /
``_jsonable`` bound the field (:class:`HugeIntDaemonBodyHttpTests` fails on
the pre-fix tree).

Everything else was already immune at the service level (ollama1-3's
``_jsonable`` / ``_safe_int`` / ``settings_text`` probes, the hex-plist and
surrogate-stem guards, the vanished-CLI and engine-down confirm-then-503
classifiers) — but none of those pins exercises request routing, Pydantic
body parsing, app_factory's sanitizing RequestValidationError handler, or
Starlette's strict UTF-8 render of the final body.  This battery pins the
whole cycle through ``create_app()``:

* a >4300-digit integer literal in a request body: ``json.loads`` raises
  ValueError (NOT JSONDecodeError) for the whole document, and FastAPI's
  body-parse guard answers 400, never a 500;
* a JSON ``\\ud800`` escape in a typed str field is refused by Pydantic
  (``string_unicode``) and the 422 body — which echoes the input — must
  survive the strict UTF-8 encode;
* the hostile on-disk zoo (hex ``<integer>`` LaunchAgent past the digit cap,
  a surrogate plist stem) plus a daemon speaking lone-surrogate JSON renders
  GET /api/ollama/status as 200 clean UTF-8;
* engine-down on the mutating daemon routes is the coded 503
  ``ollama.unreachable`` only after the failure-path probe confirms it;
  timeouts keep their generic 502 shape and never probe;
* the vanished-CLI rm sentinel is the coded 503 only after a disk confirm;
  a still-present binary keeps the coded ``rm_failed``;
* POST /api/ollama/chat answers a coded JSON error before any stream when
  the connect fails, and forwards raw NDJSON untouched when it works.
"""
from __future__ import annotations

import asyncio
import json
import plistlib
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from hub import ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = b"9" * 5000
#: Hex digits past the cap once parsed (plistlib routes 0x… via int(x, 16)).
_HEX_HUGE = "0x" + "f" * 5000

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None, query=b""):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        # Park instead of announcing a disconnect: a StreamingResponse under
        # BaseHTTPMiddleware treats an early http.disconnect as an abort.
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": query,
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None, query=b""):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body, query=query))


def _err_code(text: str) -> str:
    return (json.loads(text).get("detail") or {}).get("code", "")


class _FakeResp:
    """The minimal read surface ``_api`` / ``start_chat_stream`` use."""

    def __init__(self, raw: bytes, lines: list[bytes] | None = None):
        self._raw = raw
        self._lines = list(lines or [])

    def read(self, n: int = -1) -> bytes:
        out, self._raw = self._raw, b""
        return out

    def readline(self, n: int = -1) -> bytes:
        return self._lines.pop(0) if self._lines else b""

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _refused() -> urllib.error.URLError:
    return urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))


class _OllamaHttp(unittest.TestCase):
    """Fixed settings, sequenced daemon opens, saved pull state."""

    def setUp(self):
        super().setUp()
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}})
        patched.start()
        self.addCleanup(patched.stop)
        self._saved_pull = {k: (list(v) if isinstance(v, list) else v)
                            for k, v in ollama_svc._pull.items()}
        ollama_svc._pull.update(
            running=False, rc=None, model=None, started=None, finished=None, log=[],
        )
        self.addCleanup(ollama_svc._pull.update, self._saved_pull)
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _open_seq(self, *effects):
        """Patch ``_ollama_open`` with a call-counting side-effect sequence."""
        calls = []

        def fake_open(req, timeout):
            calls.append(req.full_url)
            effect = effects[min(len(calls), len(effects)) - 1]
            if isinstance(effect, BaseException):
                raise effect
            return effect

        patched = mock.patch.object(ollama_svc, "_ollama_open", side_effect=fake_open)
        patched.start()
        self.addCleanup(patched.stop)
        return calls

    def _agents_dir(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-ollama4-"))
        self.addCleanup(self._rm_tree, tmp)
        patched = mock.patch.object(ollama_svc, "AGENTS_DIR", tmp)
        patched.start()
        self.addCleanup(patched.stop)
        return tmp

    @staticmethod
    def _rm_tree(tmp: Path) -> None:
        for child in tmp.iterdir():
            child.unlink()
        tmp.rmdir()


class HugeIntDaemonBodyHttpTests(_OllamaHttp):
    """The fixed leak: one unrenderable number costs the field, not the payload.

    Fails on the pre-fix tree: ``json.loads`` raised the digit-cap ValueError
    for the whole daemon body, so status lost every model behind a
    "response is not json" error and test/unload discarded good answers
    into their 502s.
    """

    def test_status_keeps_the_models_when_one_size_is_huge(self):
        self._agents_dir()
        version = _FakeResp(b'{"version": "0.32.9"}')
        tags = _FakeResp(
            b'{"models": ['
            b'{"name": "poisoned:4b", "size": ' + _HUGE_DIGITS + b','
            b' "details": {"context_length": ' + _HUGE_DIGITS + b'}},'
            b'{"name": "qwen3:4b", "size": 3413361762,'
            b' "details": {"family": "qwen3"}}'
            b']}'
        )
        ps = _FakeResp(
            b'{"models": [{"name": "qwen3:4b", "size_vram": ' + _HUGE_DIGITS + b','
            b' "expires_at": "2318-01-01T00:00:00Z"}]}'
        )
        self._open_seq(version, tags, ps)
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            status, text = request("GET", "/api/ollama/status", query=b"force=true")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertTrue(payload["reachable"])
        self.assertEqual(payload["error"], "")
        names = [m["name"] for m in payload["models"]]
        self.assertEqual(names, ["poisoned:4b", "qwen3:4b"])
        by_name = {m["name"]: m for m in payload["models"]}
        # The unrenderable number is dropped/bounded; the sibling keeps its own.
        self.assertEqual(by_name["poisoned:4b"]["size"], 0)
        self.assertIsNone(by_name["poisoned:4b"]["context_length"])
        self.assertEqual(by_name["qwen3:4b"]["size"], 3413361762)
        resident = payload["resident"][0]
        self.assertEqual(resident["size_vram"], 0)
        self.assertTrue(resident["forever"])

    def test_quick_test_answer_survives_huge_counters(self):
        self._open_seq(_FakeResp(
            b'{"response": "the answer", "eval_count": ' + _HUGE_DIGITS + b','
            b' "eval_duration": ' + _HUGE_DIGITS + b'}'
        ))
        status, text = request(
            "POST", "/api/ollama/test",
            body={"model": "qwen3:4b", "prompt": "hi"},
        )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["response"], "the answer")
        self.assertEqual(payload["eval_count"], 0)
        self.assertIsNone(payload["tokens_per_s"])

    def test_unload_success_is_not_reported_as_failure(self):
        # The daemon already dropped the model; a huge counter beside the
        # confirmation must not turn the success into the 502 unload_failed.
        calls = self._open_seq(_FakeResp(
            b'{"done": true, "eval_count": ' + _HUGE_DIGITS + b'}'
        ))
        status, text = request(
            "POST", "/api/ollama/models/unload", body={"model": "qwen3:4b"},
        )
        self.assertEqual(status, 200, text[:300])
        self.assertTrue(json.loads(text)["ok"])
        # Success never spends a confirm probe.
        self.assertEqual(len(calls), 1)

    def test_nonstreaming_chat_survives_huge_counters(self):
        # The svc-level fallback twin of the streaming route shares _api.
        self._open_seq(_FakeResp(
            b'{"message": {"role": "assistant", "content": "hey"},'
            b' "eval_count": ' + _HUGE_DIGITS + b','
            b' "eval_duration": ' + _HUGE_DIGITS + b'}'
        ))
        result = ollama_svc.chat("qwen3:4b", [{"role": "user", "content": "hi"}])
        self.assertTrue(result["ok"])
        self.assertEqual(result["content"], "hey")
        self.assertEqual(result["eval_count"], 0)
        self.assertIsNone(result["tokens_per_s"])
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")


class StatusHostileZooHttpTests(_OllamaHttp):
    """GET /api/ollama/status with the full leftover zoo, end to end."""

    def test_disk_zoo_and_surrogate_daemon_render_clean_utf8(self):
        agents = self._agents_dir()
        # Hex <integer> past the digit cap: repr(pl) raises ValueError.
        (agents / "local.ollama.serve.plist").write_bytes((
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
            ' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            "<key>Label</key><string>local.ollama.serve</string>\n"
            "<key>ProgramArguments</key><array>"
            "<string>/opt/homebrew/bin/ollama</string><string>serve</string></array>\n"
            f"<key>Nice</key><integer>{_HEX_HUGE}</integer>\n"
            "</dict></plist>\n"
        ).encode())
        # No Label key: discovery falls back to the surrogate file stem.
        (agents / "local.ollama\udcff.plist").write_bytes(plistlib.dumps({
            "ProgramArguments": ["/opt/homebrew/bin/ollama", "serve"],
        }))
        # The daemon itself speaks lone-surrogate JSON (\ud800 escapes parse).
        version = _FakeResp(b'{"version": "0.32\\ud800"}')
        tags = _FakeResp(
            b'{"models": [{"name": "q\\ud800x", "size": 1,'
            b' "details": {"family": "f\\udc80"}, "\\ud800k": 1}]}'
        )
        ps = _FakeResp(b'{"models": []}')
        self._open_seq(version, tags, ps)
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            status, text = request("GET", "/api/ollama/status", query=b"force=true")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertNotIn("\udcff", text)
        self.assertNotIn("Exceeds the limit", text)
        payload = json.loads(text)
        # The poisoned hex plist is skipped; the surrogate stem is scrubbed.
        self.assertEqual(len(payload["service"]["candidates"]), 1)
        self.assertTrue(payload["models"][0]["name"].startswith("q"))

    def test_daemon_down_status_still_answers_200(self):
        self._agents_dir()
        self._open_seq(_refused())
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            status, text = request("GET", "/api/ollama/status", query=b"force=true")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["reachable"])
        self.assertFalse(payload["installed"])

    def test_pull_log_route_answers_the_idle_shape(self):
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["running"])
        self.assertEqual(payload["log"], "")


class BodyParseGuardHttpTests(_OllamaHttp):
    """Hostile request bodies through the real app's parse + 422 handler."""

    def test_huge_int_literal_in_a_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError, not JSONDecodeError;
        # FastAPI's body-parse guard must map it to 400.
        status, text = request(
            "POST", "/api/ollama/test",
            raw_body=b'{"model": "m", "prompt": "hi", "num_predict": '
                     + _HUGE_DIGITS + b"}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_escape_in_a_str_field_is_422_with_a_clean_body(self):
        # Pydantic refuses the lone surrogate (string_unicode) and the 422
        # body echoes the input; app_factory's sanitizing handler must keep
        # scrubbing it before Starlette's strict UTF-8 encode.
        status, text = request(
            "POST", "/api/ollama/pull", raw_body=b'{"model": "a\\ud800b"}',
        )
        self.assertEqual(status, 422, text[:300])
        self.assertNotIn("\ud800", text)

    def test_flag_shaped_model_name_is_the_coded_400(self):
        status, text = request("POST", "/api/ollama/pull", body={"model": "-rf"})
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_err_code(text), "ollama.bad_model_name")

    def test_pull_without_the_cli_is_the_coded_503(self):
        with mock.patch.object(ollama_svc, "binary_path", return_value=None):
            status, text = request(
                "POST", "/api/ollama/pull", body={"model": "qwen3:4b"},
            )
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(_err_code(text), "ollama.not_installed")


class DeleteRouteHttpTests(_OllamaHttp):
    """rm's could-not-run sentinel is the 503, but only after a disk confirm."""

    def test_delete_without_confirm_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/ollama/models/delete",
            body={"model": "qwen3:4b", "confirm": False},
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(_err_code(text), "ollama.confirm_required")

    def test_vanished_cli_is_the_coded_503_through_the_route(self):
        # The real spawn path: binary_path answered a moment ago, the file is
        # gone by Popen time, run_watchdog eats FileNotFoundError into -1,
        # and the disk re-check confirms the CLI is no longer there.
        with mock.patch.object(
            ollama_svc, "binary_path",
            side_effect=["/nonexistent/bin/ollama", None],
        ):
            status, text = request(
                "POST", "/api/ollama/models/delete",
                body={"model": "qwen3:4b", "confirm": True},
            )
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(_err_code(text), "ollama.not_installed")

    def test_rm_failure_with_a_present_binary_keeps_the_coded_500(self):
        with (
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/fake/bin/ollama",
            ),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=1),
        ):
            status, text = request(
                "POST", "/api/ollama/models/delete",
                body={"model": "qwen3:4b", "confirm": True},
            )
        self.assertEqual(status, 500, text[:300])
        self.assertEqual(_err_code(text), "ollama.rm_failed")


class EngineDownRouteHttpTests(_OllamaHttp):
    """Connection refused, confirmed by a fresh probe, is the coded 503."""

    def test_refused_unload_is_the_coded_503(self):
        self._open_seq(_refused(), _refused())
        status, text = request(
            "POST", "/api/ollama/models/unload", body={"model": "qwen3:4b"},
        )
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(_err_code(text), "ollama.unreachable")

    def test_timeout_keeps_the_502_and_never_probes(self):
        calls = self._open_seq(urllib.error.URLError(TimeoutError("timed out")))
        status, text = request(
            "POST", "/api/ollama/test", body={"model": "qwen3:4b", "prompt": "hi"},
        )
        self.assertEqual(status, 502, text[:300])
        self.assertEqual(_err_code(text), "ollama.generate_failed")
        self.assertEqual(len(calls), 1)

    def test_refused_chat_is_a_coded_json_503_not_a_dead_stream(self):
        self._open_seq(_refused(), _refused())
        status, text = request(
            "POST", "/api/ollama/chat",
            body={"model": "qwen3:4b",
                  "messages": [{"role": "user", "content": "hi"}]},
        )
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(_err_code(text), "ollama.unreachable")

    def test_working_chat_streams_the_daemon_ndjson_untouched(self):
        lines = [
            b'{"message":{"role":"assistant","content":"he"},"done":false}\n',
            b'{"message":{"role":"assistant","content":"y"},"done":true}\n',
        ]
        self._open_seq(_FakeResp(b"", lines=lines))
        status, text = request(
            "POST", "/api/ollama/chat",
            body={"model": "qwen3:4b",
                  "messages": [{"role": "user", "content": "hi"}]},
        )
        self.assertEqual(status, 200, text[:300])
        got = [json.loads(line) for line in text.splitlines() if line]
        self.assertEqual(len(got), 2)
        self.assertTrue(got[-1]["done"])


if __name__ == "__main__":
    unittest.main()
