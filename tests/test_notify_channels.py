"""Multi-channel notification centre: routing, isolation, secrecy.

Four properties the alert pipeline depends on:

* **Routing** — per-channel ``min_level`` / ``notify_resolve`` decide who
  receives what; the legacy Home Assistant settings keep working as an
  implicit channel with their historical ``include_warn`` semantics.
* **Isolation** — one channel raising must neither sink its siblings nor
  propagate out of ``dispatch()``, because the caller is the single alert
  thread and a dead alert thread is silent.
* **Secrecy** — bot tokens and SMTP passwords live in the 0600 credentials
  file and are never echoed by the channels API.
* **No real network** — every sender is exercised against mocks.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import alerts, config, notify_channels  # noqa: E402


class _Sandbox(unittest.TestCase):
    """Scratch config + secrets file, so no test touches the real install."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-notify-{os.getpid()}-{id(self)}"
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", data),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        secrets = mock.patch.object(notify_channels, "SECRETS_FILE", data / "notify-credentials.json")
        secrets.start()
        self.addCleanup(secrets.stop)

    def use_cfg(self, notify_cfg: dict):
        patched = mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: notify_cfg)
        patched.start()
        self.addCleanup(patched.stop)


def _recording_sender(calls: list, name: str, ok: bool = True, raise_=False):
    def sender(ch, secrets, title, message, **kw):
        if raise_:
            raise RuntimeError(f"{name} exploded")
        calls.append((name, ch.get("id"), title, message, kw.get("level"), kw.get("event")))
        return {"ok": ok, "message": name}
    return sender


class DispatchRoutingTests(_Sandbox):
    def test_min_level_filters_per_channel(self):
        calls: list = []
        self.use_cfg({"channels": [
            {"id": "n1", "type": "ntfy", "topic": "t", "min_level": "warn"},
            {"id": "n2", "type": "ntfy", "topic": "t", "min_level": "down"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"ntfy": _recording_sender(calls, "ntfy")}):
            notify_channels.dispatch("T", "warn msg", level="warn")
        self.assertEqual([c[1] for c in calls], ["n1"], "min_level=down must not receive a warn")

        calls.clear()
        with mock.patch.dict(notify_channels._SENDERS, {"ntfy": _recording_sender(calls, "ntfy")}):
            notify_channels.dispatch("T", "down msg", level="down")
        self.assertEqual([c[1] for c in calls], ["n1", "n2"], "down goes to every channel")

    def test_resolve_events_respect_notify_resolve(self):
        calls: list = []
        self.use_cfg({"channels": [
            {"id": "quiet", "type": "slack", "notify_resolve": False},
            {"id": "loud", "type": "slack", "notify_resolve": True},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"slack": _recording_sender(calls, "slack")}):
            notify_channels.dispatch("T", "recovered", level="ok", event="resolved")
        self.assertEqual([c[1] for c in calls], ["loud"])

    def test_disabled_channel_is_skipped_but_targeted_test_bypasses(self):
        calls: list = []
        self.use_cfg({"channels": [
            {"id": "off", "type": "discord", "enabled": False},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"discord": _recording_sender(calls, "discord")}):
            notify_channels.dispatch("T", "m", level="down")
            self.assertEqual(calls, [], "a disabled channel must stay silent")
            # The per-channel test button exists to verify a channel before
            # enabling it, so an explicit target bypasses the filter.
            notify_channels.dispatch("T", "m", event="test", channel_id="off")
        self.assertEqual([c[1] for c in calls], ["off"])

    def test_one_broken_channel_does_not_sink_the_others_or_raise(self):
        calls: list = []
        self.use_cfg({"channels": [
            {"id": "boom", "type": "telegram", "chat_id": "1"},
            {"id": "fine", "type": "slack"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {
            "telegram": _recording_sender(calls, "telegram", raise_=True),
            "slack": _recording_sender(calls, "slack"),
        }):
            result = notify_channels.dispatch("T", "m", level="down")
        self.assertEqual([c[0] for c in calls], ["slack"], "the healthy channel still sends")
        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["failed"], 1)
        boom = next(r for r in result["results"] if r["id"] == "boom")
        self.assertFalse(boom["ok"])
        self.assertIn("exploded", boom["message"])

    def test_a_send_via_raise_does_not_sink_dispatch(self):
        self.use_cfg({"channels": [
            {"id": "fine", "type": "slack"},
        ]})
        with mock.patch.object(
            notify_channels, "_send_via", side_effect=RuntimeError("future boom"),
        ):
            result = notify_channels.dispatch("T", "m", level="down")
        self.assertEqual(result["failed"], 1)
        self.assertFalse(result["results"][0]["ok"])
        self.assertIn("future boom", result["results"][0]["message"])

    def test_no_matching_channel_reports_instead_of_raising(self):
        self.use_cfg({})
        result = notify_channels.dispatch("T", "m", level="down")
        self.assertFalse(result["ok"])
        self.assertEqual(result["results"], [])

    def test_unhashable_channel_type_does_not_500(self):
        """``type: [ntfy]`` used to TypeError inside ``x in CHANNEL_TYPES``."""
        raw = {"channels": [
            {"id": "bad", "type": ["ntfy"]},
            {"id": "also", "type": {"ntfy": 1}},
            {"id": "ok", "type": "slack"},
        ]}
        self.assertEqual([c["id"] for c in notify_channels.channels(raw)], ["ok"])

    def test_unhashable_type_does_not_sink_dispatch(self):
        calls: list = []
        self.use_cfg({"channels": [
            {"id": "bad", "type": ["ntfy"]},
            {"id": "ok", "type": "slack"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {
            "slack": _recording_sender(calls, "slack"),
        }):
            result = notify_channels.dispatch("T", "m", level="down")
        self.assertEqual([c[1] for c in calls], ["ok"])
        self.assertEqual(result["sent"], 1)

    def test_sender_returning_none_does_not_raise(self):
        """A None (or list) result used to AttributeError outside _send_via's try."""
        self.use_cfg({"channels": [{"id": "x", "type": "slack"}]})
        with mock.patch.dict(notify_channels._SENDERS, {"slack": lambda *a, **k: None}):
            result = notify_channels.dispatch("T", "m", level="down")
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed"], 1)
        self.assertIn("invalid sender response", result["results"][0]["message"])


class DispatchBudgetTests(_Sandbox):
    """Channels send concurrently and the whole call is budget-bounded.

    The caller is the single alert thread: with serial sends, six channels on
    a dead network stacked their per-socket-op timeouts into minutes of stall,
    holding back down/resolve, SMART and UPS alerts (a countdown scenario).
    """

    def test_a_stuck_channel_neither_blocks_dispatch_nor_sinks_the_fast_one(self):
        import time as _time

        def stuck_sender(ch, secrets, title, message, **kw):
            _time.sleep(2.0)
            return {"ok": True, "message": "far too late"}

        calls: list = []
        self.use_cfg({"channels": [
            {"id": "stuck", "type": "email", "host": "h", "to": "a@x.com"},
            {"id": "fast", "type": "slack"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {
            "email": stuck_sender,
            "slack": _recording_sender(calls, "slack"),
        }), mock.patch.object(notify_channels, "DISPATCH_BUDGET", 0.4):
            t0 = _time.monotonic()
            result = notify_channels.dispatch("T", "m", level="down")
            elapsed = _time.monotonic() - t0

        self.assertLess(elapsed, 1.5, "dispatch must return once the budget expires")
        stuck = next(r for r in result["results"] if r["id"] == "stuck")
        self.assertFalse(stuck["ok"])
        self.assertIn("timed out", stuck["message"])
        fast = next(r for r in result["results"] if r["id"] == "fast")
        self.assertTrue(fast["ok"], "the fast channel's result must not be lost")
        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["failed"], 1)

    def test_channels_send_concurrently_not_serially(self):
        import time as _time

        def napping(ch, secrets, title, message, **kw):
            _time.sleep(0.3)
            return {"ok": True, "message": "sent"}

        self.use_cfg({"channels": [
            {"id": f"c{i}", "type": "slack"} for i in range(4)
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"slack": napping}):
            t0 = _time.monotonic()
            result = notify_channels.dispatch("T", "m", level="down")
            elapsed = _time.monotonic() - t0
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sent"], 4)
        self.assertLess(
            elapsed, 1.0,
            "four 0.3s channels must overlap; serial sends would take 1.2s",
        )
        # Order stays the configured order, not completion order.
        self.assertEqual([r["id"] for r in result["results"]],
                         ["c0", "c1", "c2", "c3"])


class LegacyHomeAssistantTests(_Sandbox):
    """The pre-channels settings.notify keys keep working, unrewritten."""

    def _urlopen_recorder(self, requests: list):
        class _Resp:
            status = 200
            def read(self, n=-1):
                return b"ok"
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, timeout=None):
            requests.append((req.full_url, json.loads(req.data.decode()), dict(req.headers)))
            return _Resp()
        return fake_urlopen

    def test_legacy_webhook_config_is_dispatched_as_a_channel(self):
        requests: list = []
        self.use_cfg({"enabled": True, "ha_webhook_url": "http://ha.lan:8123/api/webhook/x"})
        with mock.patch.object(notify_channels._OPENER, "open", self._urlopen_recorder(requests)):
            result = notify_channels.dispatch("Title", "Body", level="down")
        self.assertTrue(result["ok"], result)
        url, payload, _ = requests[0]
        self.assertEqual(url, "http://ha.lan:8123/api/webhook/x")
        # The historical payload shape survives the refactor.
        self.assertEqual(payload, {"title": "Title", "message": "Body", "text": "Title: Body"})

    def test_legacy_token_service_path_survives(self):
        requests: list = []
        self.use_cfg({
            "enabled": True,
            "ha_url": "http://ha.lan:8123",
            "ha_token": "tok123",
            "ha_service": "notify.mobile_app",
        })
        with mock.patch.object(notify_channels._OPENER, "open", self._urlopen_recorder(requests)):
            notify_channels.dispatch("T", "M", level="down")
        url, payload, headers = requests[0]
        self.assertEqual(url, "http://ha.lan:8123/api/services/notify/mobile_app")
        self.assertEqual(payload, {"title": "T", "message": "M"})
        self.assertEqual(headers.get("Authorization"), "Bearer tok123")

    def test_legacy_include_warn_false_blocks_warns_only(self):
        requests: list = []
        self.use_cfg({
            "enabled": True,
            "include_warn": False,
            "ha_webhook_url": "http://ha.lan/api/webhook/x",
        })
        with mock.patch.object(notify_channels._OPENER, "open", self._urlopen_recorder(requests)):
            notify_channels.dispatch("T", "warn", level="warn")
            self.assertEqual(requests, [])
            notify_channels.dispatch("T", "down", level="down")
        self.assertEqual(len(requests), 1)

    def test_legacy_disabled_sends_nothing(self):
        requests: list = []
        self.use_cfg({"enabled": False, "ha_webhook_url": "http://ha.lan/api/webhook/x"})
        with mock.patch.object(notify_channels._OPENER, "open", self._urlopen_recorder(requests)):
            result = notify_channels.dispatch("T", "m", level="down")
        self.assertEqual(requests, [])
        self.assertFalse(result["ok"])

    def test_send_ha_notify_delegates_with_routing_hints(self):
        with mock.patch.object(notify_channels, "dispatch", return_value={"ok": True}) as d:
            alerts.send_ha_notify("T", "M", level="warn")
        d.assert_called_once_with("T", "M", level="warn", event=None)


class EffectiveSettingsTests(_Sandbox):
    """notify_settings() widens the global gates when channels want more."""

    def test_pure_legacy_config_passes_through_unchanged(self):
        raw = {"enabled": False, "include_warn": False}
        self.assertEqual(notify_channels.effective_settings(raw), raw)

    def test_enabled_channel_opens_the_gates(self):
        raw = {
            "enabled": False,
            "channels": [{"id": "n", "type": "ntfy", "topic": "t", "min_level": "warn"}],
        }
        eff = notify_channels.effective_settings(raw)
        self.assertTrue(eff["enabled"])
        self.assertTrue(eff["include_warn"])
        self.assertTrue(eff["notify_resolve"])

    def test_down_only_channels_do_not_open_the_warn_gate(self):
        raw = {"channels": [{
            "id": "n", "type": "ntfy", "topic": "t",
            "min_level": "down", "notify_resolve": False,
        }]}
        eff = notify_channels.effective_settings(raw)
        self.assertTrue(eff["enabled"])
        self.assertNotIn("include_warn", eff)
        self.assertNotIn("notify_resolve", eff)


class SenderTests(_Sandbox):
    """Each sender against mocks — shapes, auth, SSRF, zero real traffic."""

    def test_email_uses_starttls_login_and_all_recipients(self):
        import socket

        smtp = mock.MagicMock()
        resolved = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0))]
        with mock.patch("smtplib.SMTP", return_value=smtp) as ctor, \
             mock.patch("hub.http_guard.socket.getaddrinfo", return_value=resolved):
            res = notify_channels._send_email(
                {"host": "smtp.example.com", "port": 2525, "tls": "starttls",
                 "username": "u@example.com", "to": "a@x.com, b@y.com"},
                {"password": "pw"},
                "Subject line", "Body text",
            )
        self.assertTrue(res["ok"], res)
        # Connect is pinned to the checked IP; EHLO/SNI stay on the hostname.
        ctor.assert_called_once_with(timeout=notify_channels.TIMEOUT)
        smtp.connect.assert_called_once_with("smtp.example.com", 2525)
        self.assertEqual(smtp._host, "smtp.example.com")
        smtp.starttls.assert_called_once()
        starttls_ctx = smtp.starttls.call_args.kwargs.get("context")
        self.assertIsNotNone(starttls_ctx)
        import ssl
        self.assertEqual(starttls_ctx.verify_mode, ssl.CERT_REQUIRED)
        smtp.login.assert_called_once_with("u@example.com", "pw")
        msg = smtp.send_message.call_args[0][0]
        self.assertEqual(msg["Subject"], "Subject line")
        self.assertEqual(msg["To"], "a@x.com, b@y.com")
        smtp.quit.assert_called_once()

    def test_email_refuses_a_metadata_host(self):
        with mock.patch("smtplib.SMTP") as ctor:
            res = notify_channels._send_email(
                {"host": "169.254.169.254", "to": "a@x.com"}, {}, "T", "M",
            )
        self.assertFalse(res["ok"])
        ctor.assert_not_called()

    def test_email_failure_is_reported_not_raised(self):
        import socket

        resolved = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0))]
        with mock.patch("smtplib.SMTP", side_effect=OSError("connection refused")), \
             mock.patch("hub.http_guard.socket.getaddrinfo", return_value=resolved):
            res = notify_channels._send_email(
                {"host": "smtp.example.com", "to": "a@x.com"}, {}, "T", "M",
            )
        self.assertFalse(res["ok"])
        self.assertIn("connection refused", res["message"])

    def _capture_post(self):
        recorded: list = []
        def fake_post(url, payload, headers=None):
            recorded.append((url, payload, headers or {}))
            return {"ok": True, "status": 200}
        return recorded, fake_post

    def test_ntfy_publishes_json_with_priority_and_bearer(self):
        recorded, fake = self._capture_post()
        with mock.patch.object(notify_channels, "_post", fake):
            notify_channels._send_ntfy(
                {"server": "https://ntfy.example/", "topic": "srv"},
                {"token": "tk_x"}, "T", "M", level="down",
            )
        url, payload, headers = recorded[0]
        self.assertEqual(url, "https://ntfy.example/")
        self.assertEqual(payload["topic"], "srv")
        self.assertEqual(payload["priority"], 5)
        self.assertEqual(headers["Authorization"], "Bearer tk_x")

    def test_telegram_discord_slack_webhook_shapes(self):
        recorded, fake = self._capture_post()
        with mock.patch.object(notify_channels, "_post", fake):
            notify_channels._send_telegram({"chat_id": "42"}, {"bot_token": "bt"}, "T", "M")
            notify_channels._send_discord({}, {"webhook_url": "https://d/x"}, "T", "M")
            notify_channels._send_slack({}, {"webhook_url": "https://s/x"}, "T", "M")
            notify_channels._send_webhook({}, {"url": "https://w/x"}, "T", "M", level="warn", event="problem")
        self.assertEqual(recorded[0][0], "https://api.telegram.org/botbt/sendMessage")
        self.assertEqual(recorded[0][1]["chat_id"], "42")
        self.assertEqual(recorded[1][1]["content"], "**T**\nM")
        self.assertEqual(recorded[2][1]["text"], "*T*\nM")
        self.assertEqual(recorded[3][1]["level"], "warn")
        self.assertEqual(recorded[3][1]["text"], "T: M")

    def test_http_url_ok_does_not_500_on_torn_ipv6(self):
        for url in ("http://[::1", "http://[", "http://[]"):
            self.assertFalse(notify_channels._http_url_ok(url), url)

    def test_post_refuses_non_http_schemes(self):
        # file:// or gopher:// must never leave the box (SSRF guard), and the
        # refusal happens before any socket is opened.
        with mock.patch.object(notify_channels._OPENER, "open") as opener:
            res = notify_channels._post("file:///etc/passwd", {"a": 1})
        self.assertFalse(res["ok"])
        opener.assert_not_called()

    def test_post_dumps_recursion_is_not_500(self):
        """json.dumps RecursionError is not ValueError; leftover nested body used to 500."""
        with mock.patch.object(notify_channels.json, "dumps", side_effect=RecursionError), \
             mock.patch.object(notify_channels._OPENER, "open") as opener:
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertFalse(res["ok"])
        opener.assert_not_called()
        src = Path(notify_channels.__file__).read_text(encoding="utf-8")
        body = src[src.index("def _post"): src.index("\ndef _recipients")]
        self.assertIn("_json_safe(payload)", body)
        self.assertIn("RecursionError", body)

    def test_post_recursing_exc_does_not_500(self):
        """str(e) RecursionError used to 500 POST /api/alerts/test."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(
            notify_channels, "_open_request", side_effect=Recursing(),
        ), mock.patch("hub.http_guard.socket.getaddrinfo", return_value=[
            (__import__("socket").AF_INET, __import__("socket").SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
        ]):
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertFalse(res["ok"])
        json.dumps(res, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(res["message"], "error")

    def test_post_refuses_metadata_and_link_local(self):
        with mock.patch.object(notify_channels._OPENER, "open") as opener:
            for url in (
                "http://169.254.169.254/latest/meta-data",
                "http://2852039166/",
                "http://[fe80::1]/hook",
                "http://metadata/latest/meta-data",
            ):
                res = notify_channels._post(url, {"a": 1})
                self.assertFalse(res["ok"], url)
        opener.assert_not_called()

    def test_post_caps_the_response_body(self):
        class _Huge:
            status = 200
            def __init__(self):
                self.asked = None
            def read(self, n=-1):
                self.asked = n
                return b"x" * (n if n and n > 0 else 10_000_000)
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        huge = _Huge()
        with mock.patch.object(notify_channels, "_open_request", return_value=huge), \
             mock.patch("hub.http_guard.socket.getaddrinfo", return_value=[
                 (__import__("socket").AF_INET, __import__("socket").SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
             ]):
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertTrue(res["ok"], res)
        self.assertEqual(huge.asked, 200)
        self.assertEqual(res["body"], "x" * 200)

    def test_post_caps_http_error_bodies(self):
        err = urllib.error.HTTPError(
            "https://hooks.example.com/x", 500, "boom", hdrs={}, fp=None,
        )
        err.read = lambda n=-1: b"y" * (n if n and n > 0 else 10_000_000)
        closed = []
        err.close = lambda: closed.append(True)
        with mock.patch.object(notify_channels, "_open_request", side_effect=err), \
             mock.patch("hub.http_guard.socket.getaddrinfo", return_value=[
                 (__import__("socket").AF_INET, __import__("socket").SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
             ]):
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertFalse(res["ok"])
        self.assertIn("HTTP 500", res["message"])
        self.assertNotIn("y" * 201, res["message"])
        self.assertTrue(closed)

    def test_post_refuses_redirects(self):
        from hub.http_guard import RedirectRefused

        with mock.patch.object(
            notify_channels, "_open_request",
            side_effect=RedirectRefused("redirect to http://evil/ refused"),
        ), mock.patch("hub.http_guard.socket.getaddrinfo", return_value=[
            (__import__("socket").AF_INET, __import__("socket").SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
        ]):
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertFalse(res["ok"])
        self.assertIn("redirect", res["message"])

    def test_post_pins_connect_to_the_resolved_ip(self):
        import socket

        recorded = []

        class _Ok:
            status = 200
            def read(self, n=-1):
                return b"ok"
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        def fake_open(req, timeout, dest_ip=None):
            recorded.append(dest_ip)
            return _Ok()

        with mock.patch.object(notify_channels, "_open_request", fake_open), \
             mock.patch("hub.http_guard.socket.getaddrinfo", return_value=[
                 (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
             ]):
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertTrue(res["ok"], res)
        self.assertEqual(recorded, ["203.0.113.10"])

    def test_post_does_not_follow_a_second_dns_lookup(self):
        """The IP checked at allow-time is the IP passed to the opener.

        A resolver that flips to metadata on the next getaddrinfo used to
        be what urllib would connect to.  The pin keeps the first answer.
        """
        import socket

        answers = [
            [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0))],
            [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))],
        ]

        def fake_gai(host, *args, **kwargs):
            return answers.pop(0) if answers else answers[-1:]

        recorded = []

        class _Ok:
            status = 200
            def read(self, n=-1):
                return b"ok"
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        def fake_open(req, timeout, dest_ip=None):
            recorded.append(dest_ip)
            return _Ok()

        with mock.patch.object(notify_channels, "_open_request", fake_open), \
             mock.patch("hub.http_guard.socket.getaddrinfo", side_effect=fake_gai):
            res = notify_channels._post("https://hooks.example.com/x", {"a": 1})
        self.assertTrue(res["ok"], res)
        self.assertEqual(recorded, ["203.0.113.10"])

    def test_missing_mandatory_secret_fails_cleanly(self):
        for sender, ch in (
            (notify_channels._send_telegram, {"chat_id": "1"}),
            (notify_channels._send_discord, {}),
            (notify_channels._send_slack, {}),
            (notify_channels._send_webhook, {}),
        ):
            res = sender(ch, {}, "T", "M")
            self.assertFalse(res["ok"], sender.__name__)


class SecretStorageTests(_Sandbox):
    def test_secrets_file_is_private_and_partial_updates_merge(self):
        notify_channels.set_channel_secrets("c1", {"bot_token": "tok-a"})
        notify_channels.set_channel_secrets("c1", {"other": "x", "bot_token": None})
        mode = notify_channels.SECRETS_FILE.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, "channel secrets must never be world-readable")
        self.assertEqual(
            notify_channels.channel_secrets("c1"),
            {"bot_token": "tok-a", "other": "x"},
            "None must mean keep, not clear",
        )
        notify_channels.set_channel_secrets("c1", {"bot_token": ""})
        self.assertEqual(notify_channels.channel_secrets("c1"), {"other": "x"})

    def test_deleting_a_channel_drops_its_secrets(self):
        notify_channels.set_channel_secrets("gone", {"url": "https://x/hook"})
        notify_channels.drop_channel_secrets("gone")
        self.assertEqual(notify_channels.channel_secrets("gone"), {})

    def test_control_characters_are_refused_before_anything_is_stored(self):
        # A token pasted with a trailing newline makes urllib raise with the
        # full URL — token included — in the exception text, which lands in a
        # 0644 error log.  Refuse at the storage boundary.
        from fastapi import HTTPException

        for bad in ("tok\n123", "tok\t123", "tok\x00", "tok\x7f"):
            with self.subTest(bad=bad), self.assertRaises(HTTPException) as ctx:
                notify_channels.set_channel_secrets("c1", {"bot_token": bad})
            self.assertEqual(ctx.exception.detail["code"], "notify.secret_control_chars")
        self.assertEqual(notify_channels.channel_secrets("c1"), {},
                         "a refused write must not persist anything")

    def test_recursing_secret_value_is_coded_not_500(self):
        """leftover ``str(value)`` RecursionError used to 500 PUT notify secrets."""
        from fastapi import HTTPException

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        with self.assertRaises(HTTPException) as ctx:
            notify_channels.set_channel_secrets("c1", {"bot_token": Recursing()})
        self.assertEqual(ctx.exception.detail["code"], "notify.secret_control_chars")
        json.dumps(ctx.exception.detail, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ChannelApiTests(_Sandbox):
    """CRUD + test endpoint through the real app; secrets never echoed."""

    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from hub import audit
        from hub.app_factory import create_app
        from hub.auth import require_auth

        self.app = create_app()
        self.app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(self.app.dependency_overrides.clear)
        self.client = TestClient(self.app)
        self.audited: list[tuple[str, dict]] = []
        recorder = mock.patch.object(
            audit, "record",
            lambda event, **fields: self.audited.append((event, fields)) or {},
        )
        recorder.start()
        self.addCleanup(recorder.stop)

    def test_crud_round_trip_never_echoes_secrets(self):
        create = self.client.post("/api/alerts/channels", json={
            "type": "telegram",
            "name": "Family bot",
            "min_level": "down",
            "config": {"chat_id": "-100200"},
            "secrets": {"bot_token": "123:SECRET-TOKEN"},
        })
        self.assertEqual(create.status_code, 200, create.text)
        cid = create.json()["channel"]["id"]
        self.assertNotIn("SECRET-TOKEN", create.text)

        listed = self.client.get("/api/alerts/channels")
        self.assertEqual(listed.status_code, 200)
        self.assertNotIn("SECRET-TOKEN", listed.text)
        ch = next(c for c in listed.json()["channels"] if c["id"] == cid)
        self.assertTrue(ch["has"]["bot_token"], "the UI needs to know a token is stored")
        self.assertEqual(ch["config"]["chat_id"], "-100200")

        # Editing without re-sending the secret keeps the stored one.
        update = self.client.put(f"/api/alerts/channels/{cid}", json={
            "type": "telegram",
            "name": "Family bot",
            "min_level": "warn",
            "config": {"chat_id": "-100200"},
            "secrets": {},
        })
        self.assertEqual(update.status_code, 200, update.text)
        self.assertEqual(notify_channels.channel_secrets(cid)["bot_token"], "123:SECRET-TOKEN")

        delete = self.client.delete(f"/api/alerts/channels/{cid}")
        self.assertEqual(delete.status_code, 200)
        self.assertEqual(notify_channels.channel_secrets(cid), {})
        self.assertEqual(notify_channels.get_channel(cid), None)

    def test_create_rejects_missing_required_secret_and_bad_urls(self):
        r = self.client.post("/api/alerts/channels", json={
            "type": "discord", "name": "d", "secrets": {},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.missing_field")

        r = self.client.post("/api/alerts/channels", json={
            "type": "webhook", "name": "w",
            "secrets": {"url": "file:///etc/passwd"},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.bad_url")

        r = self.client.post("/api/alerts/channels", json={
            "type": "webhook", "name": "meta",
            "secrets": {"url": "http://169.254.169.254/latest/meta-data"},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.bad_url")

        r = self.client.post("/api/alerts/channels", json={
            "type": "webhook", "name": "v6",
            "secrets": {"url": "http://[::1"},
        })
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "notify.bad_url")
        # The rejected secret must not linger in the store.
        self.assertEqual(notify_channels._load_secrets(), {})

        r = self.client.post("/api/alerts/channels", json={"type": "carrier-pigeon"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.bad_type")

    def test_missing_required_field_is_machine_readable(self):
        r = self.client.post("/api/alerts/channels", json={
            "type": "ntfy", "name": "n", "config": {"server": "https://ntfy.sh"},
        })
        self.assertEqual(r.status_code, 400)
        detail = r.json()["detail"]
        self.assertEqual(detail["code"], "notify.missing_field")
        self.assertEqual(detail["params"]["field"], "topic")

    def test_channel_test_endpoint_targets_one_channel(self):
        self.client.post("/api/alerts/channels", json={
            "id": "slack-ops", "type": "slack", "name": "Ops",
            "secrets": {"webhook_url": "https://hooks.slack.com/services/x"},
        })
        calls: list = []
        with mock.patch.dict(notify_channels._SENDERS, {"slack": _recording_sender(calls, "slack")}):
            r = self.client.post("/api/alerts/channels/slack-ops/test")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"], r.text)
        self.assertEqual([c[1] for c in calls], ["slack-ops"])

        missing = self.client.post("/api/alerts/channels/nope/test")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["detail"]["code"], "notify.not_found")

    def test_crud_and_test_send_leave_audit_records_without_secrets(self):
        from hub import audit

        self.client.post("/api/alerts/channels", json={
            "id": "tg-fam", "type": "telegram", "name": "Family bot",
            "config": {"chat_id": "-1"},
            "secrets": {"bot_token": "123:AUDIT-SECRET"},
        })
        self.client.put("/api/alerts/channels/tg-fam", json={
            "type": "telegram", "name": "Family bot", "min_level": "down",
            "config": {"chat_id": "-1"}, "secrets": {},
        })
        with mock.patch.dict(notify_channels._SENDERS, {"telegram": _recording_sender([], "tg")}):
            self.client.post("/api/alerts/channels/tg-fam/test")
        self.client.delete("/api/alerts/channels/tg-fam")

        events = [e for e, _ in self.audited]
        self.assertEqual(events, [
            audit.NOTIFY_CHANNEL_CREATED,
            audit.NOTIFY_CHANNEL_UPDATED,
            audit.NOTIFY_CHANNEL_TESTED,
            audit.NOTIFY_CHANNEL_DELETED,
        ])
        for event, fields in self.audited:
            self.assertEqual(fields.get("channel_id"), "tg-fam", event)
            self.assertEqual(fields.get("channel_type"), "telegram", event)
            self.assertNotIn("AUDIT-SECRET", repr(fields), event)

    def test_channel_type_is_immutable(self):
        self.client.post("/api/alerts/channels", json={
            "id": "hook-a", "type": "webhook", "name": "w",
            "secrets": {"url": "https://w.example/x"},
        })
        r = self.client.put("/api/alerts/channels/hook-a", json={
            "type": "slack", "name": "w",
            "secrets": {"webhook_url": "https://hooks.slack.com/x"},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.type_immutable")
        # The refused write must not have touched the stored secrets either.
        self.assertEqual(
            set(notify_channels.channel_secrets("hook-a")), {"url"},
            "the old type's secret must survive, the new type's must not appear",
        )

    def test_create_never_inherits_orphaned_secrets(self):
        # A half-completed delete can leave secrets behind without a channel;
        # a new channel under the same id must start from a clean slate.
        notify_channels.set_channel_secrets("ntfy-1", {"token": "STALE-TOKEN"})
        r = self.client.post("/api/alerts/channels", json={
            "id": "ntfy-1", "type": "ntfy", "name": "n",
            "config": {"topic": "srv"}, "secrets": {},
        })
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(notify_channels.channel_secrets("ntfy-1"), {},
                         "stale secrets must be wiped, not silently adopted")

    def test_secret_with_control_chars_is_refused_via_the_api(self):
        r = self.client.post("/api/alerts/channels", json={
            "id": "tg-bad", "type": "telegram", "name": "t",
            "config": {"chat_id": "-1"},
            "secrets": {"bot_token": "123:SECRET\n"},
        })
        self.assertEqual(r.status_code, 400)
        detail = r.json()["detail"]
        self.assertEqual(detail["code"], "notify.secret_control_chars")
        self.assertEqual(detail["params"]["field"], "bot_token")
        self.assertEqual(notify_channels._load_secrets(), {})
        self.assertIsNone(notify_channels.get_channel("tg-bad"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
