"""Fifth Alerts-domain sweep: hostile-request pins over the notify routes.

A fresh probe matrix (create_app + TestClient, raise_server_exceptions=False;
355 probes over every mounted /api/alerts* route) found **no live leftover
500**: hostile JSON bodies, hostile cid path params, poisoned services.yaml /
notify-credentials.json and leftover FIFO / directory / symlink nodes all
answer coded 4xx or the deliberate coded 503s.  What the prior alerts /
alerts2 / alerts3 / alerts4 / notify suites do not pin is the *inbound
request* surface itself — they probe leftover disk state and function-level
sanitizers, but nobody sends hostile bytes at POST/PUT /api/alerts/channels
through the real app.  A regression in any of these layers would ship green:

* FastAPI's body-parse guard: ``json.loads`` of a >4300-digit number in a
  request body raises CPython's digit-cap *ValueError*, not JSONDecodeError,
  and invalid-UTF-8 body bytes raise UnicodeDecodeError — both must stay the
  coded 400, never a 500;
* escaped lone surrogates in body slots (``type``, config values, secret
  values): the error path must render its own body (``notify.bad_type``
  echoes the user's ``type`` into params), and the accept path must land a
  services.yaml the loader can still read plus a credentials file that stays
  valid JSON — scrubbed, never a poisoned store;
* hostile ``{cid}`` path params (percent-encoded lone surrogate, %00,
  oversize, over-cap digit runs) stay ``notify.bad_id``;
* leftover FIFO / directory / dangling-symlink nodes at
  notify-credentials.json and its ``.lock`` sibling never hang a request
  (O_NONBLOCK + S_ISREG in read_text_capped / secure_io) and never 500;
* a poisoned credentials file: reads keep answering 200, an unreadable
  store refuses the write with the coded 503 (bytes on disk untouched),
  and a huge-digit token dropped by the parse_int hook must never cost a
  sibling channel its stored secret on the next innocent write.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import alerts, audit, auth, config, notify_channels
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _Alerts5Sandbox(unittest.TestCase):
    """Scratch config + journal + secrets, and the real app's TestClient."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-alerts5-")
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

    def write_ntfy_row(self) -> None:
        """One loopback ntfy channel row (no send ever leaves the host)."""
        self.write_config(
            "settings:\n  notify:\n    channels:\n"
            "      - id: n1\n        type: ntfy\n        topic: t\n"
            "        server: http://127.0.0.1:9\n"
        )

    def raw(self, path: str, body: bytes | str, method: str = "POST"):
        """Send raw JSON bytes so hostile payloads reach the parser verbatim
        (the ``json=`` helper would refuse to encode them client-side)."""
        content = body if isinstance(body, bytes) else body.encode("utf-8")
        return self.client.request(
            method, path, content=content,
            headers={"content-type": "application/json"},
        )

    def assert_renderable(self, resp) -> dict | list:
        """The body must be UTF-8 JSON with no lone surrogate leaking out."""
        parsed = resp.json()
        text = json.dumps(parsed, ensure_ascii=False)
        text.encode("utf-8")  # raises on a leaked lone surrogate
        return parsed


class HostileBodyRoutePins(_Alerts5Sandbox):
    """Hostile inbound JSON at POST/PUT /api/alerts/channels."""

    def test_surrogate_type_is_coded_400_with_renderable_body(self):
        """``notify.bad_type`` echoes the user's ``type`` into the error
        params; an escaped lone surrogate there must not 500 the error
        body under Starlette's UTF-8 encode."""
        r = self.raw("/api/alerts/channels",
                     '{"type": "\\ud800", "config": {}, "secrets": {}}')
        self.assertEqual(r.status_code, 400)
        detail = self.assert_renderable(r)["detail"]
        self.assertEqual(detail["code"], "notify.bad_type")

    def test_surrogate_name_is_422_never_500(self):
        """pydantic's str validation refuses a lone surrogate in ``name``;
        the custom validation handler must render that 422 cleanly."""
        r = self.raw("/api/alerts/channels",
                     '{"type": "ntfy", "name": "n\\ud800", '
                     '"config": {"topic": "t"}, "secrets": {}}')
        self.assertEqual(r.status_code, 422)
        self.assert_renderable(r)

    def test_surrogate_config_and_secret_values_round_trip_scrubbed(self):
        """An accepted surrogate config/secret value must land a store both
        readers can still load — scrubbed, never a poisoned services.yaml
        or credentials file."""
        r = self.raw("/api/alerts/channels",
                     '{"type": "ntfy", "id": "s1", "name": "clean", '
                     '"config": {"server": "http://127.0.0.1:9", '
                     '"topic": "t\\ud800"}, '
                     '"secrets": {"token": "x\\ud800"}}')
        self.assertEqual(r.status_code, 200)
        self.assert_renderable(r)
        # services.yaml written by the save must still parse as a mapping
        # and still hold the row.
        config.reload_cfg()
        self.assertIsInstance(config._read_disk(), dict)
        self.assertEqual(len(notify_channels.channels()), 1)
        # The credentials file must be valid JSON and the secret readable.
        self.assertIsInstance(json.loads(self.secrets.read_text()), dict)
        self.assertTrue(notify_channels.channel_secrets("s1").get("token"))
        # GET must answer 200 with no surrogate anywhere in the body.
        g = self.client.get("/api/alerts/channels")
        self.assertEqual(g.status_code, 200)
        body = json.dumps(self.assert_renderable(g), ensure_ascii=False)
        self.assertNotIn("\ud800", body)
        self.assertTrue(g.json()["channels"][0]["has"]["token"])
        # The channel stays operable: test (loopback refusal) and PUT work.
        t = self.client.post("/api/alerts/channels/s1/test")
        self.assertEqual(t.status_code, 200)
        self.assert_renderable(t)
        p = self.raw("/api/alerts/channels/s1",
                     '{"type": "ntfy", "config": {"server": '
                     '"http://127.0.0.1:9", "topic": "t2"}, "secrets": {}}',
                     method="PUT")
        self.assertEqual(p.status_code, 200)

    def test_over_cap_digit_int_in_body_is_coded_400(self):
        """``json.loads`` of a >4300-digit number is CPython's digit-cap
        *ValueError*, not JSONDecodeError; FastAPI's body-parse guard must
        keep answering the coded 400, never a raw 500."""
        cases = (
            '{"type": "ntfy", "config": {"topic": ' + _HUGE_DIGITS
            + '}, "secrets": {}}',
            '{"type": "email", "config": {"host": "h", "to": ['
            + _HUGE_DIGITS + ']}, "secrets": {}}',
            _HUGE_DIGITS,
        )
        for body in cases:
            r = self.raw("/api/alerts/channels", body)
            self.assertEqual(r.status_code, 400)
            self.assert_renderable(r)

    def test_invalid_utf8_body_is_coded_400(self):
        r = self.raw("/api/alerts/channels", b'\xff\xfe{"type": "x"}')
        self.assertEqual(r.status_code, 400)
        self.assert_renderable(r)
        # /api/alerts/test declares no body: hostile bytes are ignored, the
        # route answers 200 (dispatch result) — never a decode 500.
        r = self.raw("/api/alerts/test", b"\xff\xfe\x00")
        self.assertEqual(r.status_code, 200)
        self.assert_renderable(r)

    def test_deeply_nested_body_is_coded_400(self):
        r = self.raw("/api/alerts/channels",
                     '{"type": "ntfy", "config": {"topic": '
                     + "[" * 12000 + "1" + "]" * 12000 + '}, "secrets": {}}')
        self.assertEqual(r.status_code, 400)
        self.assert_renderable(r)

    def test_infinity_nan_literals_never_500_and_stay_renderable(self):
        """``json.loads`` accepts Infinity/NaN literals; whatever lands must
        never reach Starlette's allow_nan=False encoder unscrubbed."""
        for body in (
            '{"type": "ntfy", "config": {"server": "http://127.0.0.1:9", '
            '"topic": Infinity}, "secrets": {}}',
            '{"type": "ntfy", "config": {"server": "http://127.0.0.1:9", '
            '"topic": NaN}, "secrets": {}}',
            '{"type": "email", "config": {"host": "h", "port": 1e999, '
            '"to": ["a@b"]}, "secrets": {}}',
        ):
            r = self.raw("/api/alerts/channels", body)
            self.assertLess(r.status_code, 500, body[:60])
            self.assert_renderable(r)
        g = self.client.get("/api/alerts/channels")
        self.assertEqual(g.status_code, 200)
        self.assert_renderable(g)

    def test_torn_ipv6_urls_are_coded_400(self):
        """``urlsplit("http://[::1")`` raises ValueError; both the secret
        URL and the config ``server`` checks must answer notify.bad_url."""
        for body in (
            '{"type": "webhook", "config": {}, '
            '"secrets": {"url": "http://[::1"}}',
            '{"type": "ntfy", "config": {"server": "http://[::1", '
            '"topic": "t"}, "secrets": {}}',
        ):
            r = self.raw("/api/alerts/channels", body)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(
                self.assert_renderable(r)["detail"]["code"], "notify.bad_url"
            )


class HostileCidRoutePins(_Alerts5Sandbox):
    """Hostile {cid} path params on PUT / DELETE / per-channel test."""

    _PUT_BODY = '{"type": "ntfy", "config": {"topic": "t"}, "secrets": {}}'

    def _assert_bad_id(self, cid: str):
        r = self.raw(f"/api/alerts/channels/{cid}", self._PUT_BODY, "PUT")
        self.assertEqual(r.status_code, 400, f"PUT {cid[:32]}")
        self.assertEqual(
            self.assert_renderable(r)["detail"]["code"], "notify.bad_id"
        )
        r = self.client.delete(f"/api/alerts/channels/{cid}")
        self.assertEqual(r.status_code, 400, f"DELETE {cid[:32]}")
        r = self.client.post(f"/api/alerts/channels/{cid}/test")
        self.assertEqual(r.status_code, 400, f"test {cid[:32]}")
        self.assert_renderable(r)

    def test_percent_encoded_surrogate_cid_is_coded_400(self):
        """%ED%A0%80 is the UTF-8 encoding of a lone surrogate — invalid
        UTF-8 after percent-decode.  Must stay notify.bad_id, never a
        decode 500."""
        self._assert_bad_id("%ED%A0%80")

    def test_nul_and_binary_cid_are_coded_400(self):
        self._assert_bad_id("%00")
        self._assert_bad_id("%ff%fe")

    def test_oversize_and_over_cap_digit_cid_are_coded_400(self):
        self._assert_bad_id("a" * 5000)
        self._assert_bad_id(_HUGE_DIGITS)

    def test_legacy_sentinel_cid_is_coded_400(self):
        """The implicit legacy channel id is deliberately outside the id
        charset; addressing it directly must be bad_id, not a lookup."""
        self._assert_bad_id("__legacy_home_assistant__")


class SecretsNodeRoutePins(_Alerts5Sandbox):
    """Leftover non-file nodes at notify-credentials.json and its lock:
    requests must neither hang (FIFO parks a plain open) nor 500."""

    _CREATE = ('{"type": "webhook", "id": "w9", "config": {}, '
               '"secrets": {"url": "http://127.0.0.1:9/h"}}')

    def _assert_routes_survive(self):
        g = self.client.get("/api/alerts/channels")
        self.assertEqual(g.status_code, 200)
        self.assert_renderable(g)
        c = self.raw("/api/alerts/channels", self._CREATE)
        self.assertEqual(c.status_code, 200)
        d = self.client.delete("/api/alerts/channels/n1")
        self.assertEqual(d.status_code, 200)

    def test_fifo_secrets_file_never_hangs_or_500s(self):
        self.write_ntfy_row()
        os.mkfifo(self.secrets)
        self._assert_routes_survive()

    def test_fifo_secrets_lock_sibling_never_hangs_or_500s(self):
        self.write_ntfy_row()
        os.mkfifo(self.secrets.with_name(self.secrets.name + ".lock"))
        self._assert_routes_survive()

    def test_directory_secrets_file_answers_coded(self):
        self.write_ntfy_row()
        self.secrets.mkdir()
        self._assert_routes_survive()

    def test_dangling_symlink_secrets_file_answers_coded(self):
        self.write_ntfy_row()
        self.secrets.symlink_to(self.root / "vanished-target")
        self._assert_routes_survive()


class SecretsFilePoisonWritePins(_Alerts5Sandbox):
    """Poisoned credentials file through the HTTP write path."""

    _PUT = ('{"type": "ntfy", "config": {"server": "http://127.0.0.1:9", '
            '"topic": "t"}, "secrets": {"token": "new"}}')

    def test_huge_digit_token_never_wipes_sibling_on_write(self):
        """A >4300-digit stored number is dropped by the parse_int hook —
        just the number.  The next innocent PUT must keep the sibling
        channel's secret; a whole-document ValueError used to rewrite the
        file from ``{}`` and wipe every sibling."""
        self.write_ntfy_row()
        self.secrets.write_text(
            '{"n1": {"token": ' + _HUGE_DIGITS + '}, '
            '"sib": {"token": "keep-me"}}'
        )
        r = self.raw("/api/alerts/channels/n1", self._PUT, "PUT")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(notify_channels.channel_secrets("n1").get("token"), "new")
        self.assertEqual(
            notify_channels.channel_secrets("sib").get("token"), "keep-me"
        )

    def test_unreadable_store_reads_200_write_refuses_coded_503(self):
        """Oversize / binary / over-deep files: every read keeps degrading
        to 200, the write refuses with the coded 503, and the on-disk bytes
        stay byte-identical — a refused write must never destroy the store
        an operator could still fix by hand."""
        payloads = (
            ('{"pad": "' + "x" * 300000 + '"}').encode(),
            b"\xff\xfe\x00garbage",
            ('{"k":' * 12000 + "1" + "}" * 12000).encode(),
        )
        for blob in payloads:
            self.write_ntfy_row()
            self.secrets.write_bytes(blob)
            g = self.client.get("/api/alerts/channels")
            self.assertEqual(g.status_code, 200)
            self.assert_renderable(g)
            r = self.raw("/api/alerts/channels/n1", self._PUT, "PUT")
            self.assertEqual(r.status_code, 503)
            self.assertEqual(
                self.assert_renderable(r)["detail"]["code"],
                "notify.secrets_unreadable",
            )
            self.assertEqual(self.secrets.read_bytes(), blob)
            self.secrets.unlink()

    def test_surrogate_keys_in_store_write_path_stays_coded(self):
        """Escaped ``"\\ud800"`` keys/values in the file load as lone
        surrogates; the write path must scrub them rather than crash or
        persist a store the next reader refuses."""
        self.write_ntfy_row()
        self.secrets.write_text(
            '{"\\ud800": {"token": "x"}, "n1": {"token": "y\\ud800"}}'
        )
        r = self.raw("/api/alerts/channels/n1", self._PUT, "PUT")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(notify_channels.channel_secrets("n1").get("token"), "new")
        # Rewritten store must be plain valid JSON with no lone surrogate.
        text = self.secrets.read_text(encoding="utf-8")
        self.assertIsInstance(json.loads(text), dict)
        g = self.client.get("/api/alerts/channels")
        self.assertEqual(g.status_code, 200)
        self.assertNotIn(
            "\ud800", json.dumps(self.assert_renderable(g), ensure_ascii=False)
        )


if __name__ == "__main__":
    unittest.main()
