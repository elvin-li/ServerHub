"""Eighth Notify-domain leftover sweep: the DELETE-side secrets orphan,
plus stays-immune pins for the wave's remaining bomb classes.

A fresh probe matrix over the real app (create_app + TestClient,
raise_server_exceptions=False; the six channel routes plus
POST /api/alerts/test driven over unreadable / FIFO / directory secrets
files, YAML anchor cycles in the notify block, huge-number and
Infinity/NaN/surrogate JSON request bodies, stale-cache torn-config
writes) found **no live 500** — and two state bugs in the orphan class
notify7 opened (both the DELETE-side mirrors of its create-side find):

* DELETE /api/alerts/channels/{cid} removes the channel row first
  (``config.mutate``) and drops the stored credential second
  (``drop_channel_secrets``).  When notify-credentials.json exists but
  cannot be read back — torn to non-UTF-8 by power loss, grown past the
  256KB read cap, corrupt JSON — the drop's ``{}`` snapshot holds no rows:
  the delete answered **200** while the bot token / webhook URL it claimed
  to destroy stayed behind on the hand-recoverable disk, an orphaned live
  credential no channel row references, invisible to GET and unreachable
  by a second DELETE.  The delete now refuses first with the coded 503 the
  secrets writes already use (``notify.secrets_unreadable``), before the
  row is gone; the file the operator can still fix stays byte-identical.

* A half-completed *earlier* delete (row gone, credentials write failed)
  leaves orphaned secrets under an id with no channel row.  The retried
  DELETE used to 404 without touching them — the orphan had no recovery
  path short of hand-editing the file.  ``delete_channel`` now drops the
  id's secrets unconditionally, so the retry purges the orphan even while
  it still answers 404 for the missing row.

Everything else this sweep probed was already sealed and is pinned here so
a refactor cannot reopen it:

* a >4300-digit number in a real JSON request body (config value, secret
  value): ``json.loads`` raises the digit-cap *ValueError*, not
  JSONDecodeError, and FastAPI's body-parse net answers the coded 400 —
  nothing is created and the siblings stay intact;
* ``Infinity`` / ``NaN`` literals in a config list ride through a create:
  the write lands, services.yaml stays loadable, and every later read
  (cold reload included) stays renderable under allow_nan=False;
* a lone-surrogate secret value via a real HTTP body: stored scrubbed
  (never raw on disk), the has-flag answers True, and both test routes
  stay coded;
* a leftover FIFO squatting notify-credentials.json (or its ``.lock``
  sibling): every channel route stays coded, no hang, and a create still
  replaces the node;
* recursive YAML anchors (a cycle in a config value, the channels list,
  or the notify map itself): all six routes and dispatch() stay coded
  and renderable.
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


_GOOD_YAML = (
    "settings:\n  notify:\n    channels:\n"
    "      - id: c1\n        type: ntfy\n        topic: t\n"
    "      - id: tg1\n        type: telegram\n        chat_id: '42'\n"
)

#: Past CPython's 4300-digit int<->str conversion cap.
_HUGE_DIGITS = "9" * 5000


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify8Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify8-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = Path(tmp)
        self.data = self.root / "data"
        self.data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        self.secrets_path = self.data / "notify-credentials.json"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (alerts, "ALERTS_FILE", self.data / "alerts.jsonl"),
            (alerts, "STATE_FILE", self.data / "alert_state.json"),
            (notify_channels, "SECRETS_FILE", self.secrets_path),
            (audit, "AUDIT_PATH", self.data / "auth-audit.jsonl"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        senders = mock.patch.dict(
            notify_channels._SENDERS,
            {t: _stub_sender for t in notify_channels._SENDERS},
        )
        senders.start()
        self.addCleanup(senders.stop)
        self.addCleanup(config.reload_cfg)
        self.yaml_path.write_text(_GOOD_YAML, encoding="utf-8")
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def assert_renderable(self, resp):
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return parsed

    def assert_not_500(self, resp, label: str = ""):
        self.assertNotEqual(resp.status_code, 500, f"{label}: {resp.text[:200]}")
        return self.assert_renderable(resp)

    def listed_ids(self) -> set:
        body = self.assert_not_500(self.client.get("/api/alerts/channels"))
        return {c["id"] for c in body["channels"]}

    def store_telegram_secret(self) -> None:
        r = self.client.put(
            "/api/alerts/channels/tg1",
            json={"type": "telegram", "config": {"chat_id": "42"},
                  "secrets": {"bot_token": "tok-live"}})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(
            notify_channels.channel_secrets("tg1"), {"bot_token": "tok-live"})

    def sweep_channel_routes(self, label: str) -> None:
        self.assert_not_500(self.client.get("/api/alerts/channels"),
                            f"{label} GET channels")
        self.assert_not_500(
            self.client.post("/api/alerts/channels",
                             json={"type": "ntfy", "id": "px",
                                   "config": {"topic": "t"}}),
            f"{label} POST create",
        )
        self.assert_not_500(
            self.client.put("/api/alerts/channels/c1",
                            json={"type": "ntfy", "config": {"topic": "u"}}),
            f"{label} PUT",
        )
        self.assert_not_500(self.client.post("/api/alerts/channels/c1/test"),
                            f"{label} per-channel test")
        self.assert_not_500(self.client.delete("/api/alerts/channels/c1"),
                            f"{label} DELETE")
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            f"{label} POST alerts test")


class DeleteWithUnreadableSecretsRefusesPins(_Notify8Sandbox):
    """The sweep's find: a DELETE while notify-credentials.json cannot be
    read back must refuse coded (row and file intact), never answer 200 and
    strand the stored credential as an orphan on the recoverable disk."""

    def _assert_refused_delete_left_no_orphan(self, corrupt_bytes: bytes):
        self.secrets_path.write_bytes(corrupt_bytes)
        before = self.secrets_path.read_bytes()
        r = self.client.delete("/api/alerts/channels/tg1")
        self.assertEqual(r.status_code, 503, r.text[:200])
        body = self.assert_renderable(r)
        self.assertEqual(body["detail"]["code"], "notify.secrets_unreadable")
        # The unreadable file is never rewritten (or emptied) by the refusal.
        self.assertEqual(self.secrets_path.read_bytes(), before)
        # And the row is still there: listed, and deletable once fixed.
        self.assertIn("tg1", self.listed_ids())

    def test_torn_secrets_file_refuses_delete_with_row_intact(self):
        self._assert_refused_delete_left_no_orphan(b"\xff\xfe torn by power loss")

    def test_corrupt_json_secrets_file_refuses_delete_with_row_intact(self):
        self._assert_refused_delete_left_no_orphan(b'{"tg1": {"bot_token"')

    def test_oversize_secrets_file_refuses_delete_with_row_intact(self):
        pad = b'{"pad": "' + b"x" * (300 * 1024) + b'"}'
        self._assert_refused_delete_left_no_orphan(pad)

    def test_list_root_secrets_file_refuses_delete_with_row_intact(self):
        self._assert_refused_delete_left_no_orphan(b'["a whole-document paste"]')

    def test_delete_recovers_after_the_file_is_restored(self):
        self._assert_refused_delete_left_no_orphan(b"\xff\xfe torn")
        self.secrets_path.write_text(
            '{"tg1": {"bot_token": "tok-live"}}', encoding="utf-8")
        r = self.client.delete("/api/alerts/channels/tg1")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertNotIn("tg1", self.listed_ids())
        # The credential really is destroyed with the row.
        self.assertEqual(notify_channels.channel_secrets("tg1"), {})
        self.assertNotIn("tok-live",
                         self.secrets_path.read_text(encoding="utf-8"))

    def test_delete_still_destroys_only_its_own_rows_secrets(self):
        # A healthy sibling's stored secret survives the delete.
        self.store_telegram_secret()
        r = self.client.put(
            "/api/alerts/channels/c1",
            json={"type": "ntfy", "config": {"topic": "t"},
                  "secrets": {"token": "sibling-tok"}})
        self.assertEqual(r.status_code, 200, r.text[:200])
        r = self.client.delete("/api/alerts/channels/tg1")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(notify_channels.channel_secrets("tg1"), {})
        self.assertEqual(
            notify_channels.channel_secrets("c1"), {"token": "sibling-tok"})

    def test_missing_secrets_file_still_deletes(self):
        # Nothing to preserve: the delete proceeds as before.
        r = self.client.delete("/api/alerts/channels/tg1")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertNotIn("tg1", self.listed_ids())

    def test_fifo_secrets_node_still_deletes(self):
        # A leftover non-regular node holds no rows: proceed, never hang.
        os.mkfifo(self.secrets_path)
        r = self.client.delete("/api/alerts/channels/tg1")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertNotIn("tg1", self.listed_ids())


class RetriedDeletePurgesOrphanedSecretsPins(_Notify8Sandbox):
    """The second find: an id whose row is already gone (a half-completed
    earlier delete) but whose secrets remain must be purgeable by DELETE —
    the 404 stays, the orphan does not."""

    def test_delete_of_rowless_id_purges_its_orphaned_secrets(self):
        self.secrets_path.write_text(
            '{"ghost1": {"bot_token": "orphan-tok"},'
            ' "c1": {"token": "sibling-tok"}}', encoding="utf-8")
        self.assertNotIn("ghost1", self.listed_ids())
        r = self.client.delete("/api/alerts/channels/ghost1")
        # No row, so the response stays the coded 404 — but the orphaned
        # credential is destroyed rather than stranded forever.
        self.assertEqual(r.status_code, 404, r.text[:200])
        self.assertEqual(
            self.assert_renderable(r)["detail"]["code"], "notify.not_found")
        self.assertEqual(notify_channels.channel_secrets("ghost1"), {})
        text = self.secrets_path.read_text(encoding="utf-8")
        self.assertNotIn("orphan-tok", text)
        # The purge never touches a sibling channel's stored secret.
        self.assertEqual(
            notify_channels.channel_secrets("c1"), {"token": "sibling-tok"})

    def test_purged_orphan_cannot_be_inherited_by_a_new_channel(self):
        self.secrets_path.write_text(
            '{"ghost1": {"bot_token": "orphan-tok"}}', encoding="utf-8")
        self.client.delete("/api/alerts/channels/ghost1")
        r = self.client.post(
            "/api/alerts/channels",
            json={"type": "telegram", "id": "ghost1",
                  "config": {"chat_id": "7"},
                  "secrets": {"bot_token": "fresh-tok"}})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(
            notify_channels.channel_secrets("ghost1"),
            {"bot_token": "fresh-tok"})


class HugeNumberRequestBodyStaysImmunePins(_Notify8Sandbox):
    """A >4300-digit number in a real JSON request body: ``json.loads``
    raises the digit-cap ValueError (not JSONDecodeError), and the
    body-parse net answers the coded 400 — nothing lands on disk."""

    def _post_raw(self, raw: str):
        return self.client.post(
            "/api/alerts/channels", content=raw,
            headers={"content-type": "application/json"})

    def test_huge_int_config_value_is_coded_400(self):
        r = self._post_raw(
            '{"type": "ntfy", "id": "hx", "config": {"topic": '
            + _HUGE_DIGITS + '}}')
        self.assertEqual(r.status_code, 400, r.text[:200])
        self.assert_renderable(r)
        self.assertNotIn("hx", self.listed_ids())

    def test_huge_int_secret_value_is_coded_400_and_writes_nothing(self):
        r = self._post_raw(
            '{"type": "ntfy", "id": "hx", "config": {"topic": "t"},'
            ' "secrets": {"token": ' + _HUGE_DIGITS + '}}')
        self.assertEqual(r.status_code, 400, r.text[:200])
        self.assert_renderable(r)
        self.assertFalse(self.secrets_path.exists())

    def test_huge_int_put_body_is_coded_400_and_row_unchanged(self):
        r = self.client.put(
            "/api/alerts/channels/c1",
            content='{"type": "ntfy", "config": {"topic": "t", "port": '
                    + _HUGE_DIGITS + '}}',
            headers={"content-type": "application/json"})
        self.assertEqual(r.status_code, 400, r.text[:200])
        self.assert_renderable(r)
        self.assertIn("c1", self.listed_ids())


class InfNanBodyValuesStaysImmunePins(_Notify8Sandbox):
    """``Infinity`` / ``NaN`` literals parse as float inf/nan and ride into
    a stored config list: the write must land, services.yaml must stay
    loadable, and every later read stays renderable (allow_nan=False)."""

    def test_infinity_in_a_config_list_survives_create_and_reload(self):
        r = self.client.post(
            "/api/alerts/channels",
            content='{"type": "email", "id": "e1", "config":'
                    ' {"host": "h", "to": [Infinity, NaN, "a@b"]}}',
            headers={"content-type": "application/json"})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assert_renderable(r)
        self.assert_not_500(self.client.get("/api/alerts/channels"),
                            "inf-list GET")
        # Cold reload: the on-disk services.yaml must still parse whole.
        config.reload_cfg()
        self.assertIn("e1", self.listed_ids())
        self.assert_not_500(self.client.post("/api/alerts/channels/e1/test"),
                            "inf-list test")
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            "inf-list alerts test")


class SurrogateSecretBodyStaysImmunePins(_Notify8Sandbox):
    """A lone-surrogate secret value via a real HTTP body is stored
    scrubbed — never raw on disk — and every read/send path stays coded."""

    def test_surrogate_secret_value_is_scrubbed_and_routes_stay_coded(self):
        r = self.client.post(
            "/api/alerts/channels",
            content='{"type": "ntfy", "id": "s1", "config": {"topic": "t"},'
                    ' "secrets": {"token": "tok\\ud800tail"}}',
            headers={"content-type": "application/json"})
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = self.assert_renderable(r)
        self.assertIs(body["channel"]["has"]["token"], True)
        # The file on disk is strict-UTF-8 readable: no raw surrogate.
        text = self.secrets_path.read_text(encoding="utf-8")
        self.assertNotIn("\\ud800", text.lower())
        stored = notify_channels.channel_secrets("s1")
        stored_tok = stored.get("token", "")
        self.assertTrue(stored_tok.startswith("tok"))
        stored_tok.encode("utf-8")
        self.assert_not_500(self.client.post("/api/alerts/channels/s1/test"),
                            "surrogate secret test")
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            "surrogate secret alerts test")


class FifoSecretsNodesStaysImmunePins(_Notify8Sandbox):
    """A leftover FIFO squatting notify-credentials.json (or its ``.lock``
    sibling): every channel route stays coded — O_NONBLOCK opens mean no
    hang — and a create still replaces the node."""

    def test_fifo_at_secrets_file_all_routes_survive(self):
        os.mkfifo(self.secrets_path)
        self.sweep_channel_routes("fifo secrets")

    def test_fifo_at_secrets_lock_all_routes_survive(self):
        os.mkfifo(str(self.secrets_path) + ".lock")
        self.sweep_channel_routes("fifo secrets lock")

    def test_create_replaces_the_fifo_with_a_regular_file(self):
        os.mkfifo(self.secrets_path)
        r = self.client.post(
            "/api/alerts/channels",
            json={"type": "telegram", "id": "tg9",
                  "config": {"chat_id": "9"},
                  "secrets": {"bot_token": "tok-9"}})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertTrue(self.secrets_path.is_file())
        self.assertEqual(
            notify_channels.channel_secrets("tg9"), {"bot_token": "tok-9"})


class YamlAnchorCycleStaysImmunePins(_Notify8Sandbox):
    """Recursive YAML anchors in the notify block: safe_load builds a truly
    cyclic structure, and every route plus dispatch() must stay coded."""

    def _plant_yaml(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def test_cycle_in_a_config_value_all_routes_survive(self):
        self._plant_yaml(
            "settings:\n  notify:\n    channels:\n"
            "      - id: c1\n        type: ntfy\n        topic: t\n"
            "        junk: &a {self: *a}\n")
        self.sweep_channel_routes("cycle config value")

    def test_cycle_through_the_channels_list_all_routes_survive(self):
        self._plant_yaml(
            "settings:\n  notify:\n    channels: &c\n"
            "      - id: c1\n        type: ntfy\n        topic: t\n"
            "        nest: *c\n")
        self.sweep_channel_routes("cycle channels list")

    def test_cycle_on_the_notify_map_never_kills_dispatch(self):
        self._plant_yaml(
            "settings:\n  notify: &n\n    enabled: true\n    self: *n\n"
            "    channels:\n"
            "      - id: c1\n        type: ntfy\n        topic: t\n")
        self.sweep_channel_routes("cycle notify map")
        out = notify_channels.dispatch("t", "m", level="down", event=None)
        self.assertIsInstance(out, dict)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
