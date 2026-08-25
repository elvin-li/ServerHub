"""Fourth leftover-500s sweep of the cloudflared domain, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the hex-minted form that arrives already-int —
huge-number JSON journals wiping state, vanished-CLI 503-vs-500, option
injection, FIFO journals) were re-reproduced against every route the panel
mounts for Cloudflare Tunnel:

    GET  /api/cloudflared/status          GET  /api/cloudflared/logs
    POST /api/cloudflared/create          POST /api/cloudflared/start
    POST /api/cloudflared/start-token     POST /api/cloudflared/route-dns
    POST /api/cloudflared/restart         POST /api/cloudflared/stop
    POST /api/cloudflared/uninstall-service

No live leak was found: cf3's service-layer hardening (``_jsonable_state``
scrubbing, the ``_json_int`` decode hook, the ``str()``-probe ``_tunnel_argv``,
``_cli_vanished``'s disk confirm) already covers every vector.  But those pins
all drive ``cloudflared_svc`` directly — none exercises request routing,
Pydantic body parsing, app_factory's sanitizing handlers, the route's audit
line, or Starlette's strict UTF-8 render of the final body.  This battery pins
the whole cycle through ``create_app()`` so the immunity cannot silently
regress at the layer the SPA (and the Apps tunnel list) actually talks to:

* a >4300-digit decimal literal in serverhub-state.json costs that field,
  never ``active_tunnel`` / ``mode``, the journal, or the request — and a
  mutating read-modify-write over HTTP keeps every sibling key on disk;
* lone-surrogate keys AND values in the journal are scrubbed before
  Starlette's strict UTF-8 encode; a ``\\ud800`` escape in a request body is
  the sanitized 422, its body still strictly decodable;
* an already-int over-cap leftover (hex-minted, so ``int(x, 16)`` dodged the
  parse-time cap) drops to None through the ``str()`` probe;
* a >4300-digit integer literal in a request body is FastAPI's body-parse
  400 (``json.loads`` raises ValueError, NOT JSONDecodeError), never 500;
* ``--all`` / ``--help`` / ``-h.example`` in name/tunnel/hostname slots stay
  the coded 400 (option injection);
* a cloudflared that vanished mid-request answers the coded 503 only after
  the filesystem confirms it is gone; the same ``not found`` sentinel while
  the binary is still on disk keeps the raw result (no false 503);
* a FIFO planted at the state journal cannot park GET /status;
* an unreachable Cloudflare surfaces ``tunnels_error`` (the Apps tunnel list
  error-vs-empty split) instead of a silent empty list or a 500;
* the mutating routes still write their TUNNEL_CHANGED audit line.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import audit, cloudflared_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_INT = int("f" * 4400, 16)

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
        return {"type": "http.disconnect"}

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
    return asyncio.run(
        _asgi_request(method, path, body=body, raw_body=raw_body, query=query)
    )


class _CloudflaredSandbox(unittest.TestCase):
    """Every module-level path constant redirected into a private temp tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cf4-http-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.cf_home = root / "cf"
        self.cf_home.mkdir()
        self.state_file = self.state_dir / "serverhub-state.json"
        self.cert = self.cf_home / "cert.pem"
        for name, value in {
            "STATE_DIR": self.state_dir,
            "STATE_FILE": self.state_file,
            "TOKEN_FILE": self.state_dir / "tunnel.token",
            "LOG_FILE": self.state_dir / "tunnel.log",
            "LOGIN_PID": self.state_dir / "login.pid",
            "LOGIN_LOG": self.state_dir / "login.log",
            "LOGIN_URL_FILE": self.state_dir / "login.url",
            "CF_HOME": self.cf_home,
            "CERT": self.cert,
            "CONFIG_YML": self.cf_home / "config.yml",
            "PLIST": root / "local.cloudflared-tunnel.plist",
        }.items():
            patcher = mock.patch.object(cloudflared_svc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        cloudflared_svc.invalidate_tunnels()
        self.addCleanup(cloudflared_svc.invalidate_tunnels)


class StatusJournalPoisonHttpTests(_CloudflaredSandbox):
    def test_over_cap_literal_keeps_active_tunnel_over_http(self):
        """One >4300-digit counter must cost its field, never the snapshot."""
        self.state_file.write_text(
            '{"mode": "token", "tunnel_name": "home", "leftover": %s}'
            % _HUGE_DIGITS
        )
        status, body = request("GET", "/api/cloudflared/status")
        self.assertEqual(status, 200)
        snap = json.loads(body)
        self.assertEqual(snap["active_tunnel"], "home")
        self.assertEqual(snap["mode"], "token")

    def test_surrogate_keys_and_values_render_strictly_over_http(self):
        self.state_file.write_text(
            '{"tunnel_name": "home\\ud800", "mo\\ud800de": "tok\\ud800en"}'
        )
        status, body = request("GET", "/api/cloudflared/status")
        self.assertEqual(status, 200)
        self.assertNotIn("\ud800", body)
        self.assertEqual(json.loads(body)["active_tunnel"], "home?")

    def test_nonfinite_journal_values_are_nulled_over_http(self):
        self.state_file.write_text('{"tunnel_name": Infinity, "updated": NaN}')
        status, body = request("GET", "/api/cloudflared/status")
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)["active_tunnel"])

    def test_already_int_over_cap_leftover_is_nulled_over_http(self):
        """Hex-minted over-cap int dodges the parse-time cap; the str() probe
        must drop it before Starlette's encoder raises the digit-cap ValueError.
        In ``tunnel_name`` it rides straight into ``active_tunnel``."""
        with mock.patch.object(
            cloudflared_svc, "_load_state",
            return_value={"tunnel_name": _HUGE_INT, "mode": "token"},
        ):
            status, body = request("GET", "/api/cloudflared/status")
        self.assertEqual(status, 200)
        snap = json.loads(body)
        self.assertIsNone(snap["active_tunnel"])
        self.assertEqual(snap["mode"], "token")

    def test_fifo_journal_does_not_park_or_500_status(self):
        os.mkfifo(self.state_file)
        status, body = request("GET", "/api/cloudflared/status")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_unreachable_cloudflare_surfaces_tunnels_error_not_500(self):
        """The Apps tunnel list splits error from empty on ``tunnels_error``."""
        self.state_file.write_text("{}")
        self.cert.write_text("x" * 64)
        with mock.patch.object(
            cloudflared_svc, "list_tunnels", side_effect=RuntimeError("edge down"),
        ):
            status, body = request("GET", "/api/cloudflared/status")
        self.assertEqual(status, 200)
        snap = json.loads(body)
        self.assertEqual(snap["tunnels"], [])
        self.assertIn("edge down", snap["tunnels_error"])


class ReadModifyWriteHttpTests(_CloudflaredSandbox):
    def test_uninstall_keeps_sibling_keys_despite_over_cap_literal(self):
        """The mutating read-modify-write used to persist the {} wipe to disk."""
        self.state_file.write_text(
            '{"mode": "token", "tunnel_name": "home", "keep": "me",'
            ' "leftover": %s}' % _HUGE_DIGITS
        )
        status, body = request("POST", "/api/cloudflared/uninstall-service")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        raw = json.loads(self.state_file.read_text())
        self.assertEqual(raw["keep"], "me")
        self.assertIsNone(raw["leftover"])
        # tunnel_name / mode are what uninstall removes on purpose.
        self.assertNotIn("tunnel_name", raw)


class RequestBodyPoisonHttpTests(_CloudflaredSandbox):
    def test_option_like_values_stay_coded_400(self):
        for path, body, code in (
            ("/api/cloudflared/create", {"name": "--all"},
             "cloudflared.invalid_name"),
            ("/api/cloudflared/start", {"tunnel": "--help"},
             "cloudflared.invalid_name"),
            ("/api/cloudflared/route-dns",
             {"tunnel": "home", "hostname": "-h.example"},
             "cloudflared.route_args_required"),
        ):
            with self.subTest(path=path):
                status, raw = request("POST", path, body=body)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(raw)["detail"]["code"], code)

    def test_surrogate_escape_body_is_sanitized_422_not_500(self):
        for path, raw_body in (
            ("/api/cloudflared/create", b'{"name": "ab\\ud800cd"}'),
            ("/api/cloudflared/start", b'{"tunnel": "ab\\ud800cd"}'),
            ("/api/cloudflared/route-dns",
             b'{"tunnel": "home", "hostname": "a\\ud800b.example"}'),
        ):
            with self.subTest(path=path):
                status, body = request("POST", path, raw_body=raw_body)
                self.assertEqual(status, 422)
                self.assertNotIn("\ud800", body)
                json.loads(body)

    def test_over_cap_int_literal_body_is_body_parse_400_not_500(self):
        """json.loads of the literal raises bare ValueError, not
        JSONDecodeError; the body-parse handler must still answer 400."""
        for path, raw_body in (
            ("/api/cloudflared/create",
             b'{"name": "ok", "extra": ' + _HUGE_DIGITS.encode() + b"}"),
            ("/api/cloudflared/start",
             b'{"tunnel": ' + _HUGE_DIGITS.encode() + b"}"),
        ):
            with self.subTest(path=path):
                status, body = request("POST", path, raw_body=raw_body)
                self.assertEqual(status, 400)
                json.loads(body)

    def test_logs_query_abuse_never_500s(self):
        for query, expect in (
            (b"lines=" + _HUGE_DIGITS.encode(), 422),
            (b"lines=nan", 422),
            (b"lines=1e3", 422),
            (b"lines=-5", 200),
        ):
            with self.subTest(query=query[:24]):
                status, body = request("GET", "/api/cloudflared/logs", query=query)
                self.assertEqual(status, expect)
                json.loads(body)

    def test_start_token_junk_and_big_int_token_stay_coded(self):
        import base64

        blob = ('{"a": %s}' % ("1" * 2500)).encode("ascii")
        big_int_token = base64.urlsafe_b64encode(blob).decode().rstrip("=")
        self.assertTrue(big_int_token.startswith("eyJ"))
        for token, expect in (("x" * 200, 400), (big_int_token, 400),
                              ("e" * 4001, 422)):
            with self.subTest(expect=expect):
                status, body = request(
                    "POST", "/api/cloudflared/start-token", body={"token": token},
                )
                self.assertEqual(status, expect)
                if expect == 400:
                    self.assertEqual(
                        json.loads(body)["detail"]["code"],
                        "cloudflared.invalid_token",
                    )

    def test_restart_with_nested_journal_name_is_coded_400(self):
        self.state_file.write_text('{"tunnel_name": {"a": 1}}')
        self.cert.write_text("x" * 64)
        status, body = request("POST", "/api/cloudflared/restart")
        self.assertEqual(status, 400)
        self.assertEqual(
            json.loads(body)["detail"]["code"], "cloudflared.invalid_name",
        )

    def test_restart_with_empty_journal_is_ok_false_not_500(self):
        self.state_file.write_text("{}")
        status, body = request("POST", "/api/cloudflared/restart")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])


class VanishedCliHttpTests(_CloudflaredSandbox):
    """503 only after the disk confirms the binary is gone (invariant 3)."""

    def setUp(self):
        super().setUp()
        self.state_file.write_text("{}")
        self.cert.write_text("x" * 64)

    def test_vanished_cli_is_coded_503_on_every_spawn_route(self):
        with (
            mock.patch.object(
                cloudflared_svc, "_bin", return_value="/nonexistent/cloudflared",
            ),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(-1, "", "not found"),
            ),
        ):
            for method, path, body in (
                ("POST", "/api/cloudflared/route-dns",
                 {"tunnel": "home", "hostname": "h.example"}),
                ("POST", "/api/cloudflared/create", {"name": "home"}),
                ("POST", "/api/cloudflared/start", {"tunnel": "home"}),
            ):
                with self.subTest(path=path):
                    status, raw = request(method, path, body=body)
                    self.assertEqual(status, 503)
                    self.assertEqual(
                        json.loads(raw)["detail"]["code"],
                        "cloudflared.not_installed",
                    )

    def test_sentinel_with_binary_still_on_disk_keeps_raw_result(self):
        """A still-present cloudflared that printed exactly ``not found`` and
        died must keep its raw result, never the false 503."""
        present = Path(self._tmp.name) / "cloudflared-present"
        present.write_text("#!/bin/sh\n")
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value=str(present)),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(-1, "", "not found"),
            ),
        ):
            status, raw = request(
                "POST", "/api/cloudflared/route-dns",
                body={"tunnel": "home", "hostname": "h.example"},
            )
        self.assertEqual(status, 200)
        out = json.loads(raw)
        self.assertFalse(out["ok"])
        self.assertIn("not found", out["message"])


class MutationAuditHttpTests(_CloudflaredSandbox):
    def test_stop_route_writes_tunnel_changed_audit_line(self):
        before = [
            e for e in audit.recent(1000)
            if e.get("event") == audit.TUNNEL_CHANGED
        ]
        status, body = request("POST", "/api/cloudflared/stop")
        self.assertEqual(status, 200)
        json.loads(body)
        after = [
            e for e in audit.recent(1000)
            if e.get("event") == audit.TUNNEL_CHANGED
        ]
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual(after[-1].get("action"), "stop")


if __name__ == "__main__":
    unittest.main()
