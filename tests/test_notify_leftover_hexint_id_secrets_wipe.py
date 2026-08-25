"""Leftover notify 500s the earlier hardening sweeps missed: hex-YAML
over-cap channel ids, numeric ids behind an isinstance gate, the secrets/
state wipe from one over-cap number, and surrogate mapping keys that were
scrubbed only at write time.

* YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
  CPython's 4300-digit conversion limit), so a hand-edited leftover
  ``channels: [{id: 0xFF…}]`` arrived *already-int* and the bare ``str()``
  inside ``public_channel`` / ``dispatch`` raised the digit-cap ValueError —
  500ing GET /api/alerts/channels and breaking dispatch()'s never-raises
  contract on the single alert thread;
* a plain numeric YAML ``id: 123`` needs the str() probe, not a strict
  ``isinstance(id, str)`` / ``==`` gate: the row showed in the list but
  PUT/DELETE/test all compared ``123 == "123"`` and 404'd forever, and
  save_channel's upsert appended a duplicate row instead of replacing;
* ``json.loads`` of a >4300-digit number raises the digit-cap *ValueError*
  (not JSONDecodeError) for the whole document: one poisoned number made
  ``_load_secrets`` return ``{}`` and the very next write rewrote
  notify-credentials.json from that empty snapshot — every sibling channel's
  secrets silently lost.  ``alerts._load_state`` had the same wipe: cooldown
  maps and per-service history gone, so every still-bad condition was
  re-announced on every sweep;
* ``_write_secrets`` / ``_save_state`` scrubbed surrogate keys at *write*
  time only, so a leftover escaped ``"\\ud800…"`` key in either file became
  an in-memory lookup key (and sender input on the alert thread) that no
  downstream UTF-8 encode survives.  Keys are now scrubbed on load, before
  they become lookup keys.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import alerts, config, notify_channels  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000
#: The raw digit run, for on-disk JSON leftovers.
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hub.routers.notify_api import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + secrets file, so no test touches a real install."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-notify-leftover-{os.getpid()}-{id(self)}"
        )
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.data = data
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", data),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        secrets = mock.patch.object(
            notify_channels, "SECRETS_FILE", data / "notify-credentials.json"
        )
        secrets.start()
        self.addCleanup(secrets.stop)

    def use_cfg(self, notify_cfg: dict):
        patched = mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: notify_cfg)
        patched.start()
        self.addCleanup(patched.stop)

    def write_yaml(self, body: str):
        (self.root / "services.yaml").write_text(body, encoding="utf-8")
        config.reload_cfg()


class OverCapHexIdTests(_Sandbox):
    """A hex-YAML id past the digit cap drops the row, never the route."""

    def test_hex_yaml_id_loads_past_the_digit_cap(self):
        """The vector this file guards: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        import yaml

        loaded = yaml.safe_load("id: 0x" + "f" * 5000)
        self.assertIsInstance(loaded["id"], int)
        with self.assertRaises(ValueError):
            str(loaded["id"])

    def test_over_cap_id_does_not_500_channels_list(self):
        """GET /api/alerts/channels 500'd on ``str(id)`` before the secrets
        lookup; the healthy sibling must survive, the poisoned row drop."""
        self.use_cfg({"channels": [
            {"id": _HUGE_INT, "type": "ntfy", "topic": "t"},
            {"id": "fine", "type": "slack"},
        ]})
        r = _client().get("/api/alerts/channels")
        self.assertEqual(r.status_code, 200, r.text)
        ids = [c["id"] for c in r.json()["channels"]]
        self.assertEqual(ids, ["fine"])

    def test_over_cap_id_does_not_raise_public_channel(self):
        out = notify_channels.public_channel({"id": _HUGE_INT, "type": "ntfy", "topic": "t"})
        _starlette(out)

    def test_over_cap_id_does_not_raise_dispatch(self):
        """dispatch() runs on the single alert thread and claims it never
        raises; ``str(id)`` on the over-cap int broke that contract and the
        healthy sibling channel went silent with it."""
        calls: list = []

        def sender(ch, secrets, title, message, **kw):
            calls.append(ch.get("id"))
            return {"ok": True, "message": "sent"}

        self.use_cfg({"channels": [
            {"id": _HUGE_INT, "type": "ntfy", "topic": "t"},
            {"id": "fine", "type": "slack"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"slack": sender, "ntfy": sender}):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        self.assertEqual(calls, ["fine"])
        self.assertTrue(res["ok"], res)

    def test_id_text_probe(self):
        self.assertEqual(notify_channels._id_text("abc"), "abc")
        self.assertEqual(notify_channels._id_text(123), "123")
        self.assertEqual(notify_channels._id_text(_HUGE_INT), "")
        self.assertEqual(notify_channels._id_text(None), "")
        self.assertEqual(notify_channels._id_text(True), "")


class NumericYamlIdTests(_Sandbox):
    """``id: 123`` must behave as "123" everywhere, via the str() probe."""

    _YAML = (
        "settings:\n"
        "  notify:\n"
        "    channels:\n"
        "      - id: 123\n"
        "        type: ntfy\n"
        "        topic: t\n"
    )

    def test_numeric_id_is_listed_as_string(self):
        self.use_cfg({"channels": [{"id": 123, "type": "ntfy", "topic": "t"}]})
        r = _client().get("/api/alerts/channels")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual([c["id"] for c in r.json()["channels"]], ["123"])

    def test_numeric_id_is_reachable_by_get_channel(self):
        """The strict ``==`` gate listed the row but 404'd PUT/DELETE/test."""
        self.use_cfg({"channels": [{"id": 123, "type": "ntfy", "topic": "t"}]})
        got = notify_channels.get_channel("123")
        self.assertIsNotNone(got, "numeric YAML id listed but unreachable")
        self.assertEqual(got["id"], "123")

    def test_numeric_id_delete_route_succeeds(self):
        self.write_yaml(self._YAML)
        r = _client().delete("/api/alerts/channels/123")
        self.assertEqual(r.status_code, 200, r.text)
        config.reload_cfg()
        self.assertEqual(notify_channels.channels(), [])

    def test_numeric_id_test_route_succeeds(self):
        self.use_cfg({"channels": [{"id": 123, "type": "ntfy", "topic": "t"}]})
        with mock.patch.dict(
            notify_channels._SENDERS,
            {"ntfy": lambda *a, **k: {"ok": True, "message": "sent"}},
        ):
            r = _client().post("/api/alerts/channels/123/test")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["ok"], r.text)

    def test_numeric_id_upsert_replaces_not_duplicates(self):
        """save_channel used to append a second ``"123"`` row next to the
        int one; every later edit then flip-flopped between the two."""
        self.write_yaml(self._YAML)
        notify_channels.save_channel({"id": "123", "type": "ntfy", "topic": "t2"})
        config.reload_cfg()
        rows = (config.cfg().get("settings") or {}).get("notify", {}).get("channels")
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["topic"], "t2")

    def test_create_collides_with_numeric_id(self):
        """POST of id "123" over YAML ``id: 123`` is a duplicate, not a
        silent shadow row."""
        self.write_yaml(self._YAML)
        r = _client().post("/api/alerts/channels", json={
            "id": "123", "type": "ntfy", "config": {"topic": "x"}, "secrets": {},
        })
        self.assertEqual(r.status_code, 409, r.text)
        self.assertEqual(r.json()["detail"]["code"], "notify.exists")


class SecretsWipeTests(_Sandbox):
    """One over-cap number in notify-credentials.json must not cost every
    sibling channel its secrets on the next write."""

    def test_over_cap_number_does_not_wipe_sibling_secrets(self):
        sf = self.data / "notify-credentials.json"
        sf.write_text(
            '{"tg": {"bot_token": "KEEP"}, "junk": ' + _HUGE_DIGITS + "}",
            encoding="utf-8",
        )
        self.assertEqual(
            notify_channels.channel_secrets("tg"), {"bot_token": "KEEP"},
            "one poisoned number used to empty the whole load",
        )
        notify_channels.set_channel_secrets("slk", {"webhook_url": "https://hooks.example/x"})
        self.assertEqual(
            notify_channels.channel_secrets("tg").get("bot_token"), "KEEP",
            "sibling write used to rewrite the file from an empty snapshot",
        )
        on_disk = json.loads(sf.read_text())
        self.assertEqual(on_disk["tg"]["bot_token"], "KEEP")
        self.assertIsNone(on_disk["junk"], "the poisoned number drops, not the file")

    def test_over_cap_number_does_not_wipe_on_drop(self):
        sf = self.data / "notify-credentials.json"
        sf.write_text(
            '{"tg": {"bot_token": "KEEP"}, "gone": {"url": "x"}, "junk": '
            + _HUGE_DIGITS + "}",
            encoding="utf-8",
        )
        notify_channels.drop_channel_secrets("gone")
        on_disk = json.loads(sf.read_text())
        self.assertEqual(on_disk["tg"]["bot_token"], "KEEP")
        self.assertNotIn("gone", on_disk)


class SurrogateKeyScrubOnLoadTests(_Sandbox):
    """Mapping keys are scrubbed on load, before they become lookup keys."""

    def test_surrogate_secret_key_scrubbed_before_lookup(self):
        """An escaped ``"\\ud800…"`` key parses to a lone-surrogate str key;
        channel_secrets used to hand it to the senders on the alert thread,
        where no UTF-8 encode (urllib header, SMTP login) survives it."""
        sf = self.data / "notify-credentials.json"
        sf.write_text('{"tg": {"bot_token": "KEEP", "\\ud800junk": "x"}}', encoding="utf-8")
        got = notify_channels.channel_secrets("tg")
        _starlette(got)
        self.assertEqual(got.get("bot_token"), "KEEP")
        self.assertTrue(all("\ud800" not in k for k in got))

    def test_surrogate_secret_value_scrubbed_on_load(self):
        sf = self.data / "notify-credentials.json"
        sf.write_text('{"tg": {"bot_token": "tok\\ud800en"}}', encoding="utf-8")
        got = notify_channels.channel_secrets("tg")
        _starlette(got)
        self.assertNotIn("\ud800", got.get("bot_token") or "")


class AlertStateWipeTests(unittest.TestCase):
    """alert_state.json survives one poisoned number / surrogate key."""

    def setUp(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state_file = Path(tmp.name) / "alert_state.json"
        patched = mock.patch.object(alerts, "STATE_FILE", self.state_file)
        patched.start()
        self.addCleanup(patched.stop)

    def test_over_cap_number_does_not_wipe_state(self):
        """One >4300-digit cooldown stamp used to make _load_state return {},
        so cooldowns and per-service history vanished and every still-bad
        condition re-announced on every sweep."""
        self.state_file.write_text(
            '{"svc-a": "down", "_resource_last": {"cpu": ' + _HUGE_DIGITS + "}}",
            encoding="utf-8",
        )
        st = alerts._load_state()
        self.assertEqual(st.get("svc-a"), "down", "state wiped by one poisoned number")
        self.assertIsNone(st["_resource_last"]["cpu"])

    def test_surrogate_state_key_scrubbed_on_load(self):
        """_save_state scrubbed at write time only, so a raw-loaded surrogate
        key never matched the next save and the file rewrote every sweep."""
        self.state_file.write_text('{"svc-a": "down", "\\ud800svc": "warn"}', encoding="utf-8")
        st = alerts._load_state()
        _starlette(st)
        self.assertEqual(st.get("svc-a"), "down")
        self.assertTrue(all("\ud800" not in k for k in st))


if __name__ == "__main__":
    unittest.main()
