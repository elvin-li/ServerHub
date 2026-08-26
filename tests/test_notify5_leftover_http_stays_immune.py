"""Fifth Notify-domain sweep: stays-immune pins over ground no prior suite holds.

A fresh probe matrix (create_app + TestClient, raise_server_exceptions=False;
474 probes over GET/POST/PUT/DELETE /api/alerts/channels[/{cid}[/test]],
GET /api/alerts, POST /api/alerts/test and POST /api/alerts/check) found
**no live leftover 500**: every hostile store, node and request answered a
coded 4xx/422, a deliberate coded 503, or a degraded 200 — always with a
UTF-8-renderable JSON body, never a hang.  What no prior suite pins through
the real HTTP app:

* the *whole services.yaml document* poisoned (oversize past the 1MB read
  cap, torn to binary, over-deep, replaced by a bare list/scalar) while the
  notify routes read and write it: reads must keep degrading to 200 and the
  channel writes must refuse with the coded 503 — never rewrite the file
  from the ``{}`` snapshot, never 500;
* leftover FIFO / directory / dangling-symlink nodes squatting services.yaml
  itself (and its ``.lock`` sibling) under the notify routes: no hang, no 500;
* hostile *channel rows* driven end-to-end over HTTP: unhashable
  ``type: [ntfy]``, ``!!set`` / ``!!binary`` / date / over-deep config
  values, dict-valued ``enabled`` / ``to``, over-cap YAML-hex ports and
  URLs, non-list ``channels:``, non-dict rows — list, per-channel test,
  sibling create, PUT and DELETE all stay coded;
* the legacy Home Assistant implicit channel fed leftovers (over-cap hex
  token/service/url, list/dict-valued fields, ``notify:`` not a mapping)
  through POST /api/alerts/test;
* journal lines GET /api/alerts never pinned: non-dict JSON scalars, ``t``
  as list/dict/negative-over-cap/superscript-digits (``isdigit()`` is True,
  ``int()`` still raises), one multi-hundred-KB line;
* request corners the alerts5 suite never sent: non-string secret values,
  surrogate *keys* in config/secrets, ``extra=forbid`` junk, NUL / control
  bytes in secret values, a 100KB config key, 5000 config keys, empty /
  null / list bodies, float-string and hex ``limit`` query params;
* the create *failure path* over a leftover FIFO store: refusing a channel
  whose mandatory secret is missing runs drop_channel_secrets against the
  FIFO — it must neither hang nor mask the coded 400.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import alerts, audit, auth, config, notify_channels
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: YAML hex loads through ``int(x, 16)``, which is exempt from the digit
#: cap — the resulting int exists but its ``str()`` raises ValueError.
_HEX_HUGE = "0x" + "f" * 5000

#: A FIFO route probe that parks longer than this has hung on the node.
_HANG_BUDGET = 10.0

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _Notify5Sandbox(unittest.TestCase):
    """Scratch config + journal + secrets, and the real app's TestClient."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify5-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = Path(tmp)
        self.data = self.root / "data"
        self.data.mkdir()
        self.yaml = self.root / "services.yaml"
        self.journal = self.data / "alerts.jsonl"
        self.state = self.data / "alert_state.json"
        self.secrets = self.data / "notify-credentials.json"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (alerts, "ALERTS_FILE", self.journal),
            (alerts, "STATE_FILE", self.state),
            (notify_channels, "SECRETS_FILE", self.secrets),
            (audit, "AUDIT_PATH", self.data / "auth-audit.jsonl"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def write_config(self, text: str) -> None:
        self.yaml.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def write_rows(self, rows: str) -> None:
        self.write_config("settings:\n  notify:\n    channels:\n" + rows)

    def raw(self, path: str, body: bytes | str, method: str = "POST"):
        content = body if isinstance(body, bytes) else body.encode("utf-8")
        return self.client.request(
            method, path, content=content,
            headers={"content-type": "application/json"},
        )

    def assert_renderable(self, resp):
        """The body must be UTF-8 JSON with no lone surrogate leaking out."""
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False).encode("utf-8")
        return parsed

    def assert_coded(self, resp, label: str = ""):
        """Coded response contract: never a raw 500, always renderable."""
        self.assertLess(resp.status_code, 500 if resp.status_code != 503 else 504,
                        label)
        self.assertNotEqual(resp.status_code, 500, label)
        body = self.assert_renderable(resp)
        if resp.status_code == 503:
            # A 503 is only acceptable as the *deliberate* coded refusal.
            self.assertIsInstance(body, dict, label)
            detail = body.get("detail")
            self.assertIsInstance(detail, dict, label)
            self.assertTrue(detail.get("code"), label)
        return body

    _CREATE = ('{"type": "ntfy", "id": "p1", "config": {"server": '
               '"http://127.0.0.1:9", "topic": "t"}, "secrets": {}}')
    _PUT = ('{"type": "ntfy", "config": {"server": "http://127.0.0.1:9", '
            '"topic": "u"}, "secrets": {}}')

    def sweep_notify_routes(self, label: str) -> None:
        """Every notify surface must answer coded and renderable."""
        self.assert_coded(self.client.get("/api/alerts/channels"),
                          f"{label} GET channels")
        self.assert_coded(self.client.get("/api/alerts"), f"{label} GET alerts")
        self.assert_coded(self.client.post("/api/alerts/test"),
                          f"{label} POST test")
        self.assert_coded(self.raw("/api/alerts/channels", self._CREATE),
                          f"{label} POST create")
        self.assert_coded(self.raw("/api/alerts/channels/p1", self._PUT, "PUT"),
                          f"{label} PUT")
        self.assert_coded(self.client.post("/api/alerts/channels/p1/test"),
                          f"{label} per-channel test")
        self.assert_coded(self.client.delete("/api/alerts/channels/p1"),
                          f"{label} DELETE")
        self.assert_coded(self.client.post("/api/alerts/check"),
                          f"{label} POST check")


class YamlDocumentPoisonRoutePins(_Notify5Sandbox):
    """The whole services.yaml document poisoned, driven through the notify
    routes.  Reads degrade to 200; channel writes refuse with the coded 503
    (``settings.config_unreadable``) and the on-disk bytes stay untouched —
    a refused write must never persist the ``{}`` snapshot."""

    def _assert_reads_degrade_writes_refuse(self, blob: bytes):
        self.yaml.write_bytes(blob)
        config.reload_cfg()
        g = self.client.get("/api/alerts/channels")
        self.assertEqual(g.status_code, 200)
        self.assert_renderable(g)
        r = self.raw("/api/alerts/channels", self._CREATE)
        self.assertEqual(r.status_code, 503, blob[:40])
        self.assertEqual(
            self.assert_renderable(r)["detail"]["code"],
            "settings.config_unreadable",
        )
        d = self.client.delete("/api/alerts/channels/p1")
        self.assertEqual(d.status_code, 503)
        self.assertEqual(self.yaml.read_bytes(), blob)

    def test_oversize_config_reads_degrade_writes_refuse_coded(self):
        self._assert_reads_degrade_writes_refuse(
            b"x: " + b"y" * (1024 * 1024 + 100)
        )

    def test_binary_config_reads_degrade_writes_refuse_coded(self):
        self._assert_reads_degrade_writes_refuse(b"\xff\xfe\x00services:")

    def test_over_deep_config_reads_degrade_writes_refuse_coded(self):
        self._assert_reads_degrade_writes_refuse(
            b"a: " + b"[" * 20000 + b"]" * 20000
        )

    def test_bare_list_config_reads_degrade_writes_refuse_coded(self):
        """A whole-document paste (compose file, bare list) is content the
        operator can still rescue; the channel write must not bury it."""
        self._assert_reads_degrade_writes_refuse(b"- 1\n- 2\n")

    def test_bare_scalar_config_reads_degrade_writes_refuse_coded(self):
        self._assert_reads_degrade_writes_refuse(b"42\n")

    def test_config_nodes_never_hang_or_500(self):
        """FIFO / directory / dangling symlink squatting services.yaml holds
        no YAML to lose: reads degrade, the create may proceed — but nothing
        hangs and nothing 500s."""
        for node in ("fifo", "dir", "symlink"):
            if self.yaml.is_dir():
                self.yaml.rmdir()
            else:
                self.yaml.unlink(missing_ok=True)
            if node == "fifo":
                os.mkfifo(self.yaml)
            elif node == "dir":
                self.yaml.mkdir()
            else:
                self.yaml.symlink_to(self.data / "vanished")
            config.reload_cfg()
            started = time.monotonic()
            g = self.client.get("/api/alerts/channels")
            c = self.raw("/api/alerts/channels", self._CREATE)
            self.assertLess(time.monotonic() - started, _HANG_BUDGET, node)
            self.assertEqual(g.status_code, 200, node)
            self.assert_coded(c, node)
            self.client.delete("/api/alerts/channels/p1")

    def test_config_lock_fifo_never_hangs_the_create(self):
        os.mkfifo(self.data / ".services.yaml.lock")
        started = time.monotonic()
        r = self.raw("/api/alerts/channels", self._CREATE)
        self.assertLess(time.monotonic() - started, _HANG_BUDGET)
        self.assert_coded(r, "lock fifo")


class HostileChannelRowRoutePins(_Notify5Sandbox):
    """Hand-edited channel rows driven end-to-end over HTTP: every notify
    surface must stay coded whatever one row holds."""

    ROWS = {
        "unhashable-type": "      - id: a1\n        type: [ntfy]\n        topic: t\n",
        "dict-type": "      - id: a1\n        type: {a: b}\n        topic: t\n",
        "channels-not-a-list": None,
        "rows-not-dicts": "      - 42\n      - [x]\n      - id: ok1\n        type: ntfy\n        topic: t\n",
        "set-topic": "      - id: a1\n        type: ntfy\n        topic: !!set {x: null}\n",
        "binary-topic": "      - id: a1\n        type: ntfy\n        topic: !!binary aGVsbG8=\n",
        "date-name": "      - id: a1\n        type: ntfy\n        topic: t\n        name: 2026-08-19\n",
        "over-deep-topic": "      - id: a1\n        type: ntfy\n        topic: "
                           + "[" * 200 + "1" + "]" * 200 + "\n",
        "dict-enabled": "      - id: a1\n        type: ntfy\n        topic: t\n        enabled: {a: b}\n",
        "unhashable-min-level": "      - id: a1\n        type: ntfy\n        topic: t\n        min_level: [warn]\n",
        "dict-email-to": "      - id: a1\n        type: email\n        host: h\n        to: {a: b}\n",
        "hex-over-cap-email-to": f"      - id: a1\n        type: email\n        host: h\n        to: [{_HEX_HUGE}]\n",
        "hex-over-cap-port": "      - id: a1\n        type: email\n        host: h\n"
                             f"        to: [x@y]\n        port: {_HEX_HUGE}\n",
        "hex-over-cap-server": f"      - id: a1\n        type: ntfy\n        topic: t\n        server: {_HEX_HUGE}\n",
        "hex-over-cap-ha-url": f"      - id: a1\n        type: home_assistant\n        ha_url: {_HEX_HUGE}\n",
        "list-ha-service": "      - id: a1\n        type: home_assistant\n        ha_service: [a, b]\n",
        "duplicate-numeric-and-str-id": "      - id: 123\n        type: ntfy\n        topic: t\n"
                                        "      - id: '123'\n        type: ntfy\n        topic: u\n",
    }

    def test_every_hostile_row_keeps_every_route_coded(self):
        for name, rows in self.ROWS.items():
            with self.subTest(row=name):
                if rows is None:
                    self.write_config("settings:\n  notify:\n    channels: {a: b}\n")
                else:
                    self.write_rows(rows)
                self.sweep_notify_routes(name)

    def test_hostile_row_cid_routes_stay_coded(self):
        """PUT / per-channel test / DELETE addressed *at* the hostile row."""
        self.write_rows(self.ROWS["unhashable-type"])
        for method, path in (
            ("PUT", "/api/alerts/channels/a1"),
            ("POST", "/api/alerts/channels/a1/test"),
            ("DELETE", "/api/alerts/channels/a1"),
        ):
            body = self._PUT if method == "PUT" else b""
            r = (self.raw(path, body, method) if method == "PUT"
                 else self.client.request(method, path))
            self.assert_coded(r, f"{method} {path}")


class LegacyHaPoisonRoutePins(_Notify5Sandbox):
    """The implicit legacy Home Assistant channel fed leftovers through
    POST /api/alerts/test: dispatch claims it never raises — the route must
    answer 200 with a renderable per-channel failure, never 500."""

    DOCS = {
        "hex-over-cap-token": f"settings:\n  notify:\n    enabled: true\n    ha_token: {_HEX_HUGE}\n",
        "hex-over-cap-service": "settings:\n  notify:\n    enabled: true\n"
                                f"    ha_token: x\n    ha_service: {_HEX_HUGE}\n",
        "hex-over-cap-url": "settings:\n  notify:\n    enabled: true\n"
                            f"    ha_token: x\n    ha_url: {_HEX_HUGE}\n",
        "dict-service": "settings:\n  notify:\n    enabled: true\n    ha_token: x\n    ha_service: {a: b}\n",
        "list-webhook-url": "settings:\n  notify:\n    enabled: true\n    ha_webhook_url: [a]\n",
        "surrogate-webhook-url": 'settings:\n  notify:\n    enabled: true\n'
                                 '    ha_webhook_url: "http://127.0.0.1:9/\\ud800"\n',
        "notify-not-a-mapping": "settings:\n  notify: [x]\n",
        "notify-a-string": "settings:\n  notify: hello\n",
    }

    def test_legacy_poison_test_route_answers_200_renderable(self):
        for name, doc in self.DOCS.items():
            with self.subTest(doc=name):
                self.write_config(doc)
                r = self.client.post("/api/alerts/test")
                self.assertEqual(r.status_code, 200, name)
                body = json.dumps(self.assert_renderable(r), ensure_ascii=False)
                self.assertNotIn("\ud800", body, name)
                g = self.client.get("/api/alerts/channels")
                self.assertEqual(g.status_code, 200, name)
                self.assert_renderable(g)


class JournalLinePoisonRoutePins(_Notify5Sandbox):
    """alerts.jsonl line shapes GET /api/alerts has never been pinned on."""

    def _get_alerts(self) -> list:
        r = self.client.get("/api/alerts?limit=500")
        self.assertEqual(r.status_code, 200)
        body = self.assert_renderable(r)
        self.assertIsInstance(body["alerts"], list)
        return body["alerts"]

    def test_non_dict_json_lines_are_skipped_not_500(self):
        self.journal.write_bytes(b'42\n"str"\n[1,2]\nnull\ntrue\n{"t": 3}\n')
        rows = self._get_alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["t"], 3)

    def test_t_as_list_and_dict_render_null_not_500(self):
        self.journal.write_bytes(b'{"t": [1]}\n{"t": {"a": 1}}\n')
        for row in self._get_alerts():
            self.assertIsNone(row["t"])

    def test_negative_over_cap_digit_t_renders_null_not_500(self):
        """``"-" + "9"*5000`` passes the sign/isdigit gate; ``int()`` on it
        is the digit-cap ValueError and must drop the value, not the route."""
        self.journal.write_bytes(
            b'{"t": "-' + _HUGE_DIGITS.encode() + b'", "message": "m"}\n'
        )
        rows = self._get_alerts()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["t"])

    def test_superscript_digit_t_renders_null_not_500(self):
        """``"¹²³".isdigit()`` is True but ``int("¹²³")`` raises — the
        isdigit gate alone used to let this ValueError out."""
        self.journal.write_text('{"t": "\u00b9\u00b2\u00b3"}\n', encoding="utf-8")
        rows = self._get_alerts()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["t"])

    def test_multi_hundred_kb_line_never_ooms_or_500s(self):
        self.journal.write_bytes(
            b'{"t": 1, "message": "' + b"x" * 300000 + b'"}\n'
            b'{"t": 2, "message": "ok"}\n'
        )
        rows = self._get_alerts()
        # The tail byte-cap may drop the torn huge line; the route must
        # still answer with the intact one.
        self.assertTrue(any(r.get("t") == 2 for r in rows))

    def test_blank_and_whitespace_lines_answer_empty_not_500(self):
        self.journal.write_bytes(b"\n\n   \n\t\n")
        self.assertEqual(self._get_alerts(), [])

    def test_hostile_limit_variants_stay_coded(self):
        for q in ("1.5", "true", "0x10", "%ED%A0%80", "null", ""):
            r = self.client.get(f"/api/alerts?limit={q}")
            self.assert_coded(r, f"limit={q!r}")
            self.assertLess(r.status_code, 500)


class HostileBodyCornerPins(_Notify5Sandbox):
    """Inbound request corners the alerts5 suite never sent.  Every one must
    answer a coded 4xx/422 (or a scrubbed accept), never a raw 500."""

    def test_hostile_bodies_stay_coded_on_post_and_put(self):
        bodies = {
            "config-not-a-dict": '{"type": "ntfy", "config": [1], "secrets": {}}',
            "secret-value-int": '{"type": "ntfy", "config": {"topic": "t"}, '
                                '"secrets": {"token": 5}}',
            "secret-value-nested": '{"type": "ntfy", "config": {"topic": "t"}, '
                                   '"secrets": {"token": {"a": 1}}}',
            "surrogate-secret-key": '{"type": "ntfy", "config": {"topic": "t"}, '
                                    '"secrets": {"\\ud800": "v"}}',
            "surrogate-config-key": '{"type": "ntfy", "config": {"\\ud800": "v", '
                                    '"topic": "t", "server": "http://127.0.0.1:9"}, '
                                    '"secrets": {}}',
            "config-value-dict": '{"type": "ntfy", "config": {"topic": {"a": "b"}, '
                                 '"server": "http://127.0.0.1:9"}, "secrets": {}}',
            "mixed-list-elements": '{"type": "email", "config": {"host": "h", '
                                   '"to": [["a"], {"b": 1}, null, 1.5]}, "secrets": {}}',
            "surrogate-min-level": '{"type": "ntfy", "min_level": "\\ud800", '
                                   '"config": {"topic": "t"}, "secrets": {}}',
            "oversize-id": '{"type": "ntfy", "id": "' + "a" * 100000
                           + '", "config": {"topic": "t"}, "secrets": {}}',
            "name-not-a-str": '{"type": "ntfy", "name": 42, '
                              '"config": {"topic": "t"}, "secrets": {}}',
            "extra-forbid-field": '{"type": "ntfy", "bogus": 1, '
                                  '"config": {"topic": "t"}, "secrets": {}}',
            "type-not-a-str": '{"type": [1], "config": {}, "secrets": {}}',
            "newline-secret": '{"type": "ntfy", "config": {"topic": "t", '
                              '"server": "http://127.0.0.1:9"}, '
                              '"secrets": {"token": "a\\nb"}}',
            "nul-secret": '{"type": "ntfy", "config": {"topic": "t", '
                          '"server": "http://127.0.0.1:9"}, '
                          '"secrets": {"token": "a\\u0000b"}}',
            "huge-config-key": '{"type": "ntfy", "config": {"' + "k" * 100000
                               + '": "v", "topic": "t"}, "secrets": {}}',
            "many-config-keys": '{"type": "ntfy", "config": {'
                                + ",".join(f'"k{i}": "v"' for i in range(5000))
                                + ', "topic": "t"}, "secrets": {}}',
            "empty-body": "",
            "bare-null": "null",
            "bare-list": "[]",
        }
        for name, body in bodies.items():
            with self.subTest(body=name):
                self.assert_coded(
                    self.raw("/api/alerts/channels", body), f"POST {name}"
                )
                self.assert_coded(
                    self.raw("/api/alerts/channels/p1", body, "PUT"),
                    f"PUT {name}",
                )

    def test_control_char_secret_is_the_coded_400(self):
        """A token pasted with a trailing newline must be refused with the
        coded 400 (urllib would otherwise leak the full token-bearing URL
        into a 0644 error log)."""
        r = self.raw(
            "/api/alerts/channels",
            '{"type": "ntfy", "config": {"topic": "t", '
            '"server": "http://127.0.0.1:9"}, '
            '"secrets": {"token": "a\\nb"}}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            self.assert_renderable(r)["detail"]["code"],
            "notify.secret_control_chars",
        )


class SecretsFifoFailurePathPins(_Notify5Sandbox):
    """The create *failure path* over a leftover FIFO store: refusing a
    channel whose mandatory secret is missing runs drop_channel_secrets
    against the FIFO — it must neither hang nor mask the coded 400."""

    def test_missing_required_secret_over_fifo_store_is_coded_not_hung(self):
        os.mkfifo(self.secrets)
        started = time.monotonic()
        r = self.raw(
            "/api/alerts/channels",
            '{"type": "telegram", "id": "tg1", '
            '"config": {"chat_id": "1"}, "secrets": {}}',
        )
        self.assertLess(time.monotonic() - started, _HANG_BUDGET)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            self.assert_renderable(r)["detail"]["code"], "notify.missing_field"
        )

    def test_create_with_secret_over_fifo_store_replaces_the_node(self):
        os.mkfifo(self.secrets)
        started = time.monotonic()
        r = self.raw(
            "/api/alerts/channels",
            '{"type": "telegram", "id": "tg2", '
            '"config": {"chat_id": "1"}, "secrets": {"bot_token": "x"}}',
        )
        self.assertLess(time.monotonic() - started, _HANG_BUDGET)
        self.assertEqual(r.status_code, 200)
        self.assert_renderable(r)
        self.assertEqual(
            notify_channels.channel_secrets("tg2").get("bot_token"), "x"
        )


class EverythingPoisonedAtOncePins(_Notify5Sandbox):
    """All four stores poisoned simultaneously: the combined state must not
    find a crack between the per-store sanitizers."""

    def test_all_stores_poisoned_every_route_stays_coded(self):
        self.write_config(
            'settings:\n  notify:\n    enabled: true\n    ha_token: "x"\n'
            "    channels:\n"
            '      - id: "\\ud800"\n        type: ntfy\n        topic: t\n'
            "      - id: 123\n        type: ntfy\n        topic: t\n"
            "      - id: ok1\n        type: ntfy\n        topic: t\n"
            "        server: http://127.0.0.1:9\n"
        )
        self.journal.write_bytes(
            '{"\\ud800": 1, "t": '.encode() + _HUGE_DIGITS.encode() + b"}\n"
        )
        self.state.write_bytes(
            '{"\\ud800": "warn", "n": '.encode() + _HUGE_DIGITS.encode() + b"}"
        )
        self.secrets.write_text(
            '{"ok1": {"token": "s\\ud800"}, "\\ud800": {"x": '
            + _HUGE_DIGITS + "}}",
            encoding="utf-8",
        )
        self.sweep_notify_routes("combo")
        # The numeric row must stay addressable, and no surrogate may leak.
        t = self.client.post("/api/alerts/channels/123/test")
        self.assertEqual(t.status_code, 200)
        self.assertNotIn(
            "\ud800",
            json.dumps(self.assert_renderable(t), ensure_ascii=False),
        )
        d = self.client.delete("/api/alerts/channels/123")
        self.assertEqual(d.status_code, 200)


if __name__ == "__main__":
    unittest.main()
