"""Fourth Alerts-domain sweep: the rejected-edit secret wipe, plus HTTP pins.

A fresh probe matrix over every mounted /api/alerts* route (create_app +
TestClient, raise_server_exceptions=False) — hostile bodies, hostile cid
path params, poisoned services.yaml / notify-credentials.json, FIFO /
directory / device / symlink-loop nodes, legacy-HA type leftovers — found
exactly one live leftover:

* ``PUT /api/alerts/channels/{cid}`` with ``secrets: {"url": ""}`` (or any
  ``""`` clear of a ``secret_required`` field: webhook ``url``, telegram
  ``bot_token``, discord/slack ``webhook_url``) answered the coded 400
  ``notify.missing_field`` — but ``set_channel_secrets`` had already
  persisted the clear before ``_require_secrets`` ran.  The "rejected"
  edit destroyed the stored credential: the channel still listed as
  configured, and every later alert dispatch on it failed with nothing but
  a warn-level log line.  Silent notification loss is the worst failure
  mode an alerting system has.  ``set_channel_secrets`` now validates the
  merged map under its own lock *before* anything lands on disk.

The rest of this module pins probe corners no earlier suite covered at the
HTTP layer, so the only 5xx anywhere stays the *deliberate* coded 503s
(``settings.config_unreadable`` / ``notify.secrets_unreadable``):

* the data/ directory replaced by a regular file (GET/check/list answer
  200; the secrets write refuses with the coded 503);
* alerts.jsonl as a symlink to /dev/null and as a symlink loop;
* a legacy-HA over-cap hex token (uncapped ``int(x, 16)`` YAML load whose
  ``str()`` is the digit-cap ValueError) on POST /api/alerts/test.
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

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _AlertsSandbox(unittest.TestCase):
    """Scratch config + journal + secrets, and the real app's TestClient."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-alerts4-")
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

    def make_webhook(self) -> str:
        r = self.client.post("/api/alerts/channels", json={
            "type": "webhook", "name": "w1", "min_level": "warn",
            "config": {}, "secrets": {"url": "http://127.0.0.1:9/hook"},
        })
        self.assertEqual(r.status_code, 200)
        return r.json()["channel"]["id"]


class RejectedSecretClearMustNotWipeTests(_AlertsSandbox):
    """The live leftover this sweep found: a coded-400 PUT that had already
    destroyed the stored credential."""

    def test_clearing_a_required_secret_is_refused_before_the_wipe(self):
        cid = self.make_webhook()
        r = self.client.put(f"/api/alerts/channels/{cid}", json={
            "type": "webhook", "name": "w1", "min_level": "warn",
            "config": {}, "secrets": {"url": ""},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.missing_field")
        # The stored secret must survive the refused edit: it used to be
        # gone here, and every later dispatch failed "missing url".
        self.assertEqual(
            notify_channels.channel_secrets(cid).get("url"),
            "http://127.0.0.1:9/hook",
        )
        probe = self.client.post(f"/api/alerts/channels/{cid}/test")
        self.assertEqual(probe.status_code, 200)
        message = probe.json()["results"][0]["message"]
        # Connection refused (nothing listens on :9) proves the send was
        # attempted with the stored URL; "required field is missing" would
        # mean the wipe persisted.
        self.assertNotIn("required field is missing", message)

    def test_telegram_token_clear_is_refused_before_the_wipe(self):
        r = self.client.post("/api/alerts/channels", json={
            "type": "telegram", "name": "t1", "config": {"chat_id": "1"},
            "secrets": {"bot_token": "123:abc"},
        })
        self.assertEqual(r.status_code, 200)
        cid = r.json()["channel"]["id"]
        r = self.client.put(f"/api/alerts/channels/{cid}", json={
            "type": "telegram", "name": "t1", "config": {"chat_id": "1"},
            "secrets": {"bot_token": ""},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(
            notify_channels.channel_secrets(cid).get("bot_token"), "123:abc"
        )

    def test_none_still_means_keep_and_the_edit_lands(self):
        cid = self.make_webhook()
        r = self.client.put(f"/api/alerts/channels/{cid}", json={
            "type": "webhook", "name": "renamed", "min_level": "down",
            "config": {}, "secrets": {"url": None},
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["channel"]["name"], "renamed")
        self.assertEqual(
            notify_channels.channel_secrets(cid).get("url"),
            "http://127.0.0.1:9/hook",
        )

    def test_clearing_an_optional_secret_still_clears(self):
        """ntfy's token is not secret_required; "" must keep deleting it."""
        r = self.client.post("/api/alerts/channels", json={
            "type": "ntfy", "name": "n1",
            "config": {"server": "http://127.0.0.1:9", "topic": "t"},
            "secrets": {"token": "tok"},
        })
        self.assertEqual(r.status_code, 200)
        cid = r.json()["channel"]["id"]
        self.assertEqual(notify_channels.channel_secrets(cid).get("token"), "tok")
        r = self.client.put(f"/api/alerts/channels/{cid}", json={
            "type": "ntfy", "name": "n1",
            "config": {"server": "http://127.0.0.1:9", "topic": "t"},
            "secrets": {"token": ""},
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(notify_channels.channel_secrets(cid), {})

    def test_create_missing_required_secret_leaves_no_orphan_row(self):
        r = self.client.post("/api/alerts/channels", json={
            "type": "webhook", "name": "w2", "config": {}, "secrets": {},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.missing_field")
        if self.secrets.exists():
            self.assertEqual(json.loads(self.secrets.read_text() or "{}"), {})

    def test_hand_edited_channel_with_no_stored_secret_put_stays_coded(self):
        """A YAML-only channel row has no credentials file entry; a PUT that
        does not supply the mandatory secret answers the same coded 400 as
        before (now from the pre-write check)."""
        self.write_config(
            "settings:\n  notify:\n    channels:\n"
            "      - id: h1\n        type: webhook\n        name: h1\n"
        )
        r = self.client.put("/api/alerts/channels/h1", json={
            "type": "webhook", "name": "h1", "config": {}, "secrets": {},
        })
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["detail"]["code"], "notify.missing_field")


class ExoticDiskNodeRoutePins(_AlertsSandbox):
    """Probe corners with no prior HTTP pin: the routes stay coded."""

    def test_data_dir_replaced_by_a_file_stays_coded(self):
        shutil.rmtree(self.data)
        self.data.write_text("i am a file")
        c = self.client
        self.assertEqual(c.get("/api/alerts").status_code, 200)
        self.assertEqual(c.post("/api/alerts/check").status_code, 200)
        self.assertEqual(c.get("/api/alerts/channels").status_code, 200)
        # The secrets write cannot even stat its file (ENOTDIR): the coded
        # refusal, never an unhandled 500.
        r = c.post("/api/alerts/channels", json={
            "type": "webhook", "config": {},
            "secrets": {"url": "http://127.0.0.1:9/h"},
        })
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["detail"]["code"], "notify.secrets_unreadable")

    def test_journal_symlink_to_devnull_answers_200(self):
        if not Path("/dev/null").exists():
            self.skipTest("/dev/null unavailable")
        self.journal.symlink_to("/dev/null")
        self.assertEqual(self.client.get("/api/alerts").status_code, 200)
        self.assertEqual(self.client.post("/api/alerts/check").status_code, 200)

    def test_journal_symlink_loop_answers_200(self):
        (self.data / "loop-a").symlink_to(self.data / "loop-b")
        (self.data / "loop-b").symlink_to(self.data / "loop-a")
        os.symlink(self.data / "loop-a", self.journal)
        r = self.client.get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["alerts"], [])
        self.assertEqual(self.client.post("/api/alerts/check").status_code, 200)

    def test_legacy_ha_over_cap_hex_token_test_route_stays_200(self):
        """YAML hex loads uncapped; str() of the token is the digit-cap
        ValueError inside the sender — a per-channel failure, never a 500."""
        self.write_config(
            "settings:\n  notify:\n    enabled: true\n"
            "    ha_url: http://127.0.0.1:9\n"
            "    ha_token: 0x" + "F" * 5000 + "\n"
        )
        r = self.client.post("/api/alerts/test")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["ok"])


if __name__ == "__main__":
    unittest.main()
