"""Fifth leftover-500s sweep of the Ollama surface, over the real app.

One live leak was found and fixed: ``GET /api/ollama/pull/log`` served the
in-memory ``_pull`` row **raw**.  Its own docstring says it is "the same
shape the maintenance log endpoint serves" — but the maintenance twin
(:func:`hub.jobs.job_log` / ``job_state``) was hardened against junk
in-memory rows long ago while the Ollama copy never was, and
GET /api/ollama/status only survives the same rows because :func:`status`
re-walks its whole snapshot through ``_jsonable``.  Four junk-row shapes
were live 500s (:class:`PullLogJunkRowHttpTests` fails on the pre-fix tree):

* a leftover lone surrogate in one log line — Starlette's strict UTF-8
  encode of the response body raised UnicodeEncodeError;
* ``log: [bytes, None, 5]`` — ``str.join`` TypeError'd;
* an ``rc`` past CPython's 4300-digit int->str cap (a hex-loaded
  already-int dodges the parse-side cap) — ``json.dumps`` itself raised
  the digit-cap ValueError;
* ``rc: inf`` — the ``allow_nan=False`` encoder raised ValueError.

The fix mirrors the jobs hardening: ``pull_state`` coerces through
``_jsonable`` and ``pull_log`` joins only str/bytes lines, then scrubs.

Everything else probed here stays immune and is pinned so it cannot
regress (141 hostile scenarios were driven through ``create_app()``):

* hand-edited ``settings.ollama.url`` shapes that pass the origin gate but
  cannot be dialed — out-of-range port (socket OverflowError is not
  OSError), non-numeric port (http.client InvalidURL), a NUL, and a torn
  IPv6 paste (urlsplit ValueError, rejected up front) — status answers 200
  with a coded-unreachable error field, and the mutating routes answer the
  coded 502/503, never a raw 500;
* the on-disk LaunchAgents zoo beyond ollama4's: a FIFO occupying a
  ``.plist`` path (O_NONBLOCK EINVAL, no hang), a truncated XML plist
  (ExpatError), an array-root plist, a bytes ``Label``, a directory named
  ``*.plist``, and a multi-MB plist past the read cap — all skipped, the
  clean sibling still discovered;
* daemon bodies with bare ``NaN`` / ``Infinity`` literals (json.loads
  parses them by default; ``allow_nan=False`` would 500 at encode time);
* request bodies with ``NaN`` / ``Infinity`` / ``1e400`` in a typed int
  field, and a UTF-8 BOM prefix — coded 4xx/422 with a clean body;
* a streaming chat NDJSON line at the 64 KiB cap is drained, the stream
  stays 200 and forwards only complete lines.
"""
from __future__ import annotations

import asyncio
import json
import os
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit str<->int conversion limit — as an
#: *already-int* (the YAML/plist hex form loads via int(x, 16), uncapped).
_HUGE_INT = int("f" * 5000, 16)

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
    detail = json.loads(text).get("detail")
    return detail.get("code", "") if isinstance(detail, dict) else ""


class _FakeResp:
    """The minimal read surface ``_api`` / ``start_chat_stream`` use."""

    def __init__(self, raw: bytes = b"{}", lines: list[bytes] | None = None):
        self._raw = raw
        self._lines = list(lines or [])

    def read(self, n: int = -1) -> bytes:
        out, self._raw = self._raw, b""
        return out

    def readline(self, n: int = -1) -> bytes:
        if not self._lines:
            return b""
        line = self._lines[0]
        if n is not None and 0 <= n < len(line):
            # Honour the cap the way http.client does: return a prefix and
            # keep the remainder for the next call.
            self._lines[0] = line[n:]
            return line[:n]
        return self._lines.pop(0)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _OllamaHttp(unittest.TestCase):
    """Fixed settings, sequenced daemon opens, saved pull state."""

    def setUp(self):
        super().setUp()
        self._settings: dict = {}
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": self._settings})
        patched.start()
        self.addCleanup(patched.stop)
        saved_pull = {k: (list(v) if isinstance(v, list) else v)
                      for k, v in ollama_svc._pull.items()}

        def restore_pull():
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved_pull)

        self.addCleanup(restore_pull)
        ollama_svc._pull.clear()
        ollama_svc._pull.update(
            running=False, rc=None, model=None, started=None, finished=None, log=[],
        )
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
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-ollama5-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        patched = mock.patch.object(ollama_svc, "AGENTS_DIR", tmp)
        patched.start()
        self.addCleanup(patched.stop)
        return tmp

    def _set_pull(self, **row):
        ollama_svc._pull.clear()
        ollama_svc._pull.update(row)

    def _status(self):
        return request("GET", "/api/ollama/status", query=b"force=true")


class PullLogJunkRowHttpTests(_OllamaHttp):
    """The fixed leak: GET /api/ollama/pull/log survives a junk in-memory row.

    Fails on the pre-fix tree: the route served ``_pull`` raw, so each of
    these rows escaped as an unhandled exception (a raw HTTP 500).
    """

    def test_surrogate_log_line_renders_clean_utf8(self):
        self._agents_dir()
        self._set_pull(running=False, rc=0, model="m1", started="10:00:00",
                       finished="10:00:05", log=["pulled \ud800 manifest"])
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        self.assertIn("manifest", payload["log"])

    def test_bytes_none_and_int_log_entries_do_not_typeerror_join(self):
        self._agents_dir()
        self._set_pull(running=False, rc=0, model="m1", started="x",
                       finished="y", log=[b"\xffbinary\xff", None, 5, "kept"])
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        # str lines survive, bytes decode with replacement, junk is dropped.
        self.assertIn("kept", payload["log"])
        self.assertIn("binary", payload["log"])
        self.assertNotIn("5", payload["log"].splitlines())

    def test_over_digit_cap_rc_is_dropped_not_a_500(self):
        self._agents_dir()
        self._set_pull(running=False, rc=_HUGE_INT, model="m1", started="x",
                       finished="y", log=["line"])
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        self.assertIsNone(json.loads(text)["rc"])

    def test_inf_rc_is_dropped_not_a_500(self):
        self._agents_dir()
        self._set_pull(running=False, rc=float("inf"), model="m1", started="x",
                       finished="y", log=[])
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        self.assertIsNone(json.loads(text)["rc"])

    def test_missing_keys_and_nonlist_log_still_answer_the_shape(self):
        self._agents_dir()
        self._set_pull()  # a fully torn row: every key missing
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["running"])
        self.assertEqual(payload["log"], "")
        self._set_pull(running=1, rc=None, model=None, started=None,
                       finished=None, log="one string line")
        status, text = request("GET", "/api/ollama/pull/log")
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["log"], "one string line")

    def test_status_route_stays_immune_to_the_same_junk_row(self):
        # status() always re-walked its snapshot through _jsonable; pin that
        # the same rows keep rendering there too.
        self._agents_dir()
        self._open_seq(ConnectionRefusedError(61, "refused"))
        self._set_pull(running=False, rc=_HUGE_INT, model={"x": 1}, started="x",
                       finished="y", log=["ok \ud800"])
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            status, text = self._status()
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertIsNone(json.loads(text)["pull"]["rc"])


class HostileSettingsUrlHttpTests(_OllamaHttp):
    """Hand-edited URLs that pass the origin gate but cannot be dialed."""

    def _daemon_absent(self):
        return (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        )

    def _status_200(self, url):
        self._settings["ollama"] = {"url": url}
        p1, p2 = self._daemon_absent()
        with p1, p2:
            status, text = self._status()
        # type(url), not repr(url): repr of the over-digit-cap int would
        # raise the very ValueError this battery hunts.
        self.assertEqual(status, 200, f"{type(url).__name__} url -> {text[:300]}")
        return json.loads(text)

    def test_out_of_range_port_is_a_200_with_an_error_field(self):
        # socket raises OverflowError (not OSError) for port 99999; the
        # status collector must keep answering 200 with the reason.
        self._agents_dir()
        payload = self._status_200("http://127.0.0.1:99999")
        self.assertFalse(payload["reachable"])
        self.assertTrue(payload["error"])

    def test_nonnumeric_port_is_a_200_with_an_error_field(self):
        # http.client raises InvalidURL (a ValueError) past urllib's OSError
        # wrap; the collector must not leak it.
        self._agents_dir()
        payload = self._status_200("http://127.0.0.1:abc")
        self.assertFalse(payload["reachable"])

    def test_torn_ipv6_paste_falls_back_to_the_default_url(self):
        # urlsplit('http://[::1') is ValueError on 3.12; the origin gate
        # already refuses it, so base_url falls back instead of raising.
        self._agents_dir()
        payload = self._status_200("http://[::1")
        self.assertEqual(payload["url"], ollama_svc.DEFAULT_URL)
        self.assertTrue(payload["url_rejected"])

    def test_nul_and_over_digit_cap_urls_keep_the_page_up(self):
        self._agents_dir()
        self._status_200("http://127.0.0.1\x00:11434")
        # An already-int url past the digit cap: settings_text's str() probe
        # eats the ValueError and the default takes over.
        payload = self._status_200(_HUGE_INT)
        self.assertEqual(payload["url"], ollama_svc.DEFAULT_URL)

    def test_mutating_route_keeps_a_coded_error_on_an_undialable_port(self):
        self._agents_dir()
        self._settings["ollama"] = {"url": "http://127.0.0.1:99999"}
        status, text = request(
            "POST", "/api/ollama/models/unload", body={"model": "m1"},
        )
        self.assertIn(status, (502, 503), text[:300])
        self.assertIn(_err_code(text), ("ollama.unload_failed", "ollama.unreachable"))


class PlistZooHttpTests(_OllamaHttp):
    """On-disk LaunchAgent junk beyond ollama4's zoo: skipped, never a 500."""

    def test_fifo_truncated_arrayroot_bytes_and_oversize_plists_are_skipped(self):
        agents = self._agents_dir()
        # Truncated XML: plistlib raises ExpatError (not InvalidFileException).
        (agents / "trunc.ollama.plist").write_bytes(
            b'<?xml version="1.0"?><plist><dict><key>Label')
        # Array root: pl.get would AttributeError without the isinstance gate.
        (agents / "arrayroot.plist").write_bytes(plistlib.dumps(["ollama", "serve"]))
        # Bytes Label with invalid UTF-8: must decode with replacement.
        (agents / "labelbytes.plist").write_bytes(plistlib.dumps(
            {"Label": b"\xffollama\xff", "ProgramArguments": ["/x/ollama"]}))
        # Past the 256 KiB read cap: OSError(EFBIG), skipped.
        (agents / "huge.ollama.plist").write_bytes(b"<plist>" + b"a" * (300 * 1024))
        # A directory occupying a .plist name: OSError(EISDIR)-shaped skip.
        (agents / "dir.ollama.plist").mkdir()
        # A FIFO occupying a .plist path: O_NONBLOCK EINVAL, no request hang.
        if hasattr(os, "mkfifo"):
            os.mkfifo(agents / "fifo.ollama.plist")
        # The one healthy agent must still be discovered beside the junk.
        (agents / "clean.plist").write_bytes(plistlib.dumps({
            "Label": "local.ollama.serve",
            "ProgramArguments": ["/opt/homebrew/bin/ollama", "serve"],
        }))
        self._open_seq(ConnectionRefusedError(61, "refused"))
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            status, text = self._status()
        self.assertEqual(status, 200, text[:300])
        candidates = json.loads(text)["service"]["candidates"]
        self.assertIn("local.ollama.serve", candidates)
        for label in candidates:
            label.encode("utf-8")  # strict: no lone surrogates survive


class DaemonConstantsHttpTests(_OllamaHttp):
    """Bare NaN / Infinity literals in a daemon body must not reach the encoder.

    ``json.loads`` parses them by default; Starlette's ``allow_nan=False``
    encoder would 500 on any that leak into the response.
    """

    def test_status_drops_nan_and_infinity_fields(self):
        self._agents_dir()
        version = _FakeResp(b'{"version": NaN}')
        tags = _FakeResp(b'{"models": [{"name": "m1", "size": Infinity,'
                         b' "details": {"context_length": -Infinity}}]}')
        ps = _FakeResp(b'{"models": []}')
        self._open_seq(version, tags, ps)
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/ollama"),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            status, text = self._status()
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("Infinity", text)
        self.assertNotIn("NaN", text)
        model = json.loads(text)["models"][0]
        self.assertEqual(model["name"], "m1")
        self.assertEqual(model["size"], 0)
        self.assertIsNone(model["context_length"])

    def test_quick_test_survives_infinity_counters(self):
        self._agents_dir()
        self._open_seq(_FakeResp(
            b'{"response": "hey", "eval_count": Infinity, "eval_duration": NaN}'
        ))
        status, text = request(
            "POST", "/api/ollama/test", body={"model": "m1", "prompt": "hi"},
        )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertEqual(payload["response"], "hey")
        self.assertEqual(payload["eval_count"], 0)
        self.assertIsNone(payload["tokens_per_s"])

    def test_non_object_daemon_roots_keep_coded_errors(self):
        self._agents_dir()
        for body in (b'["x"]', b'"hi"', b"7", b"\xff\xfe", b"<html>bad</html>"):
            with self.subTest(body=body):
                self._open_seq(_FakeResp(body), _FakeResp(body))
                status, text = request(
                    "POST", "/api/ollama/models/unload", body={"model": "m1"},
                )
                self.assertIn(status, (502, 503), text[:300])
                self.assertIn(
                    _err_code(text), ("ollama.unload_failed", "ollama.unreachable"),
                )


class RequestBodyConstantsHttpTests(_OllamaHttp):
    """NaN / Infinity / 1e400 in a typed int field, BOM prefix: coded, clean."""

    def test_nan_infinity_and_1e400_num_predict_are_4xx_not_500(self):
        self._agents_dir()
        for raw in (
            b'{"model":"m1","prompt":"hi","num_predict": NaN}',
            b'{"model":"m1","prompt":"hi","num_predict": Infinity}',
            b'{"model":"m1","prompt":"hi","num_predict": 1e400}',
        ):
            with self.subTest(raw=raw):
                status, text = request("POST", "/api/ollama/test", raw_body=raw)
                self.assertIn(status, (400, 422), text[:300])
                json.loads(text)  # the error body itself must be valid JSON

    def test_bom_prefixed_body_parses_and_never_raw_500s(self):
        # FastAPI tolerates a UTF-8 BOM prefix (utf-8-sig decode), so the
        # body parses and the route runs end to end; pin that it stays a
        # clean 200 rather than tripping anything downstream.
        self._agents_dir()
        self._open_seq(_FakeResp(b'{"response": "ok", "done": true}'))
        status, text = request(
            "POST", "/api/ollama/test",
            raw_body=b'\xef\xbb\xbf{"model":"m1","prompt":"hi"}',
        )
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["response"], "ok")

    def test_invalid_utf8_body_is_a_coded_400(self):
        self._agents_dir()
        status, text = request(
            "POST", "/api/ollama/pull", raw_body=b'{"model":"\xff\xfe"}',
        )
        self.assertIn(status, (400, 422), text[:300])


class ChatStreamCapHttpTests(_OllamaHttp):
    """A monster NDJSON line is drained, not forwarded; the stream survives."""

    def test_oversize_line_is_dropped_and_the_stream_completes(self):
        self._agents_dir()
        lines = [
            b"a" * (ollama_svc.MAX_NDJSON_LINE + 10) + b"\n",
            b'{"message":{"role":"assistant","content":"ok"},"done":true}\n',
        ]
        self._open_seq(_FakeResp(b"", lines=lines))
        status, text = request(
            "POST", "/api/ollama/chat",
            body={"model": "m1", "messages": [{"role": "user", "content": "hi"}]},
        )
        self.assertEqual(status, 200, text[:300])
        rows = [json.loads(line) for line in text.splitlines() if line]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["done"])


if __name__ == "__main__":
    unittest.main()
