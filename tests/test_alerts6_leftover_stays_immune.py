"""Alerts sweep #6, immune side: hostile probes that already answer coded.

The same hunt that found the check-sanitizer 500s (see
test_alerts6_leftover_check_sanitizer_500s) also probed these classes over
the mounted alerts routes and found them **already sealed** by the prior
alerts / notify / status sweeps.  Pinned so a narrowed except clause or a
reverted guard cannot ship green:

* hostile legacy ``settings.notify`` webhook URLs (torn IPv6 paste, an
  out-of-range port — ``urlsplit(...).port`` is ValueError —,
  ``http.client.InvalidURL``-class control characters, a non-ASCII scheme)
  answer 200 with per-channel failure results on POST /api/alerts/test,
  never a raise out of dispatch();
* the same URL zoo stored as a webhook channel's secret answers 200 on the
  per-channel test route;
* hand-edited YAML channel rows (numeric id, ``!!binary`` server, YAML-date
  topic/min_level, an over-cap hex id, ``!!set`` type, a scalar row) render
  GET /api/alerts/channels, POST /api/alerts/test and POST /api/alerts/check
  as coded 200s with a renderable body;
* hostile freshness targets in services.yaml (over-cap hex id, ``.inf``
  max_age_hours, ``!!binary`` pattern, YAML-date label) stay contained by
  check_once's per-check wrapper;
* journal ``t`` stamps beyond the prior pins (a >4300-digit *string*,
  non-ASCII digits that pass ``isdigit()`` both int()-parseable and not,
  list/dict/bool stamps) render null (or the coerced int), never a 500;
* a sender raising an exception whose ``__str__`` answers a str subclass
  with a bound ``encode`` bomb still answers 200 on POST /api/alerts/test
  (the dispatch double-catch plus the hardened ``_utf8_text``);
* a leftover FIFO occupying the ``alert_state.json.lock`` sibling runs the
  check unlocked instead of wedging or raising;
* a dict-subclass ``.get`` bomb as the whole ``settings.notify`` section
  degrades on both POST /api/alerts/check and POST /api/alerts/test.
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


class _DictGetBomb(dict):
    def get(self, *a):
        raise RuntimeError("get bomb")


class _SelfStrBomb(str):
    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _StrBombExc(Exception):
    def __str__(self):
        return _SelfStrBomb("boom")


class _Alerts6ImmuneSandbox(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-alerts6-immune-")
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

    def assert_renderable(self, resp):
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return parsed


class HostileLegacyWebhookUrlPins(_Alerts6ImmuneSandbox):
    """POST /api/alerts/test over a hand-edited legacy notify config: every
    URL failure mode is a per-channel result, never a raise."""

    _URLS = (
        "http://[::1",                                # torn IPv6 paste
        "http://127.0.0.1:99999999999999999999/x",    # urlsplit .port ValueError
        "http://127.0.0.1:9/a b\tc",                  # InvalidURL control chars
        "htt\u00e9p://127.0.0.1/",                    # non-ASCII scheme
    )

    def test_legacy_webhook_url_zoo_answers_200(self):
        for url in self._URLS:
            self.write_config(
                "settings:\n  notify:\n    enabled: true\n"
                f"    ha_webhook_url: \"{url}\"\n"
            )
            r = self.client.post("/api/alerts/test")
            self.assertEqual(r.status_code, 200, url)
            body = self.assert_renderable(r)
            self.assertFalse(body["ok"], url)
            self.assertEqual(body["failed"], 1, url)

    def test_stored_webhook_secret_url_zoo_answers_200(self):
        for url in ("http://[::1",
                    "http://127.0.0.1:99999999999999999999/x",
                    "http://127.0.0.1:9/a\x00b"):
            self.write_config(
                "settings:\n  notify:\n    channels:\n"
                "      - id: w1\n        type: webhook\n"
            )
            self.secrets.write_text(json.dumps({"w1": {"url": url}}))
            r = self.client.post("/api/alerts/channels/w1/test")
            self.assertEqual(r.status_code, 200, url[:32])
            body = self.assert_renderable(r)
            self.assertFalse(body["ok"], url[:32])
            self.secrets.unlink()


class WeirdYamlChannelRowPins(_Alerts6ImmuneSandbox):
    """Hand-edited channel rows the YAML loader produces as non-str /
    non-dict leftovers must render, test and sweep as coded 200s."""

    _YAML = (
        "settings:\n  notify:\n    channels:\n"
        "      - id: 123\n        type: ntfy\n        topic: 2026-08-19\n"
        "        server: !!binary aGVsbG8=\n"
        "      - id: 0xFF" + "F" * 4400 + "\n        type: ntfy\n        topic: t\n"
        "      - id: d1\n        type: !!set {a, b}\n"
        "      - .inf\n"
        "      - id: n2\n        type: ntfy\n        topic: .inf\n"
        "        min_level: 2026-08-19\n        enabled: !!binary aGk=\n"
    )

    def test_get_channels_renders_coded_200(self):
        self.write_config(self._YAML)
        r = self.client.get("/api/alerts/channels")
        self.assertEqual(r.status_code, 200)
        body = self.assert_renderable(r)
        ids = [c["id"] for c in body["channels"]]
        # The numeric id coerces, the over-cap hex id and the set-typed row
        # drop themselves (never the route), the scalar row drops.
        self.assertIn("123", ids)
        self.assertIn("n2", ids)
        self.assertNotIn("d1", ids)

    def test_alerts_test_and_check_answer_200(self):
        self.write_config(self._YAML)
        r = self.client.post("/api/alerts/test")
        self.assertEqual(r.status_code, 200)
        self.assert_renderable(r)
        r = self.client.post("/api/alerts/check")
        self.assertEqual(r.status_code, 200)
        self.assert_renderable(r)


class HostileFreshnessTargetPins(_Alerts6ImmuneSandbox):
    def test_hostile_targets_stay_contained(self):
        self.write_config(
            "settings:\n  freshness:\n    targets:\n"
            "      - id: 0xFF" + "F" * 4400 + "\n        label: L\n"
            "        pattern: '/tmp/*'\n        max_age_hours: .inf\n"
            "      - id: t2\n        label: 2026-08-19\n"
            "        pattern: !!binary aGk=\n        max_age_hours: 1\n"
        )
        r = self.client.post("/api/alerts/check")
        self.assertEqual(r.status_code, 200)
        self.assert_renderable(r)


class JournalStampPins(_Alerts6ImmuneSandbox):
    def test_hostile_t_stamps_render_null_or_coerce(self):
        """Beyond the prior alerts pins: a >4300-digit *string* stamp, both
        non-ASCII digit families (Arabic-Indic parses via int(), superscript
        passes isdigit() but int() refuses), list/dict/bool stamps."""
        self.journal.write_text(
            '{"t": "' + _HUGE_DIGITS + '", "id": "a"}\n'
            '{"t": "\u0662\u0662", "id": "b"}\n'
            '{"t": "\u00b2\u00b2", "id": "c"}\n'
            '{"t": [1], "id": "d"}\n'
            '{"t": {"x": 1}, "id": "e"}\n'
            '{"t": true, "id": "f"}\n'
        )
        r = self.client.get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        by_id = {a["id"]: a for a in self.assert_renderable(r)["alerts"]}
        self.assertIsNone(by_id["a"]["t"])
        self.assertEqual(by_id["b"]["t"], 22)
        for rid in ("c", "d", "e", "f"):
            self.assertIsNone(by_id[rid]["t"], rid)


class DispatchExceptionPins(_Alerts6ImmuneSandbox):
    def test_sender_exception_with_bomb_str_answers_200(self):
        """A sender raising an exception whose ``__str__`` answers a
        self-``__str__`` str subclass with a bound ``encode`` bomb: the
        hardened ``_utf8_text`` renders its text, the result stays a
        per-channel failure — never a raise out of dispatch()."""
        self.write_config(
            "settings:\n  notify:\n    channels:\n"
            "      - id: n1\n        type: ntfy\n        topic: t\n"
            "        server: http://127.0.0.1:9\n"
        )

        def _bomb_sender(*a, **k):
            raise _StrBombExc()

        with mock.patch.dict(notify_channels._SENDERS, {"ntfy": _bomb_sender}):
            r = self.client.post("/api/alerts/test")
        self.assertEqual(r.status_code, 200)
        body = self.assert_renderable(r)
        self.assertFalse(body["ok"])
        self.assertEqual(body["results"][0]["message"], "boom")


class NotifySectionBombPins(_Alerts6ImmuneSandbox):
    def test_notify_section_get_bomb_check_and_test_answer_200(self):
        """A leftover in-memory ``settings.notify`` that is a dict subclass
        with a bombing ``.get`` degrades on both alert routes."""
        bomb = _DictGetBomb({})
        with mock.patch.object(
            config, "settings_section",
            lambda name: bomb if name == "notify" else {},
        ):
            r = self.client.post("/api/alerts/check")
            self.assertEqual(r.status_code, 200)
            r = self.client.post("/api/alerts/test")
            self.assertEqual(r.status_code, 200)
            self.assert_renderable(r)


class StateLockNodePins(_Alerts6ImmuneSandbox):
    def test_fifo_state_lock_sibling_never_hangs_or_500s(self):
        os.mkfifo(self.state.with_name(self.state.name + ".lock"))
        r = self.client.post("/api/alerts/check")
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
