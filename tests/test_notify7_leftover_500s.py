"""Seventh Notify-domain leftover sweep: the failed-create secrets orphan,
plus stays-immune pins for the wave's remaining bomb classes.

A fresh probe matrix over the real app (create_app + TestClient,
raise_server_exceptions=False; ~350 route/shape pairs: subclass bombs in
every stored channel field, self-``__str__`` encode bombs, surrogate and
digit-cap scalars via cfg snapshots / hand-written services.yaml / on-disk
notify-credentials.json / real JSON request bodies, bomb-shaped sender
results, unreadable-config and leftover-node disk states) found **one live
leftover**, and it is a state bug rather than a 500:

* POST /api/alerts/channels writes the mandatory secret first
  (``set_channel_secrets``) and persists the channel row second
  (``save_channel``).  When services.yaml has turned unreadable (torn to
  non-UTF-8 by power loss, grown past the 1MB read cap, replaced by a bare
  list), ``config.mutate`` correctly refuses the row write with the coded
  503 ``settings.config_unreadable`` and leaves the file intact — but the
  bot token / webhook URL just written for the never-created channel stayed
  behind in notify-credentials.json: an orphaned live credential no channel
  row references, invisible to GET and unreachable by DELETE.  The create
  path already wiped orphans *before* writing (the half-completed-delete
  guard) and already dropped them when ``_require_secrets`` refused;
  ``save_channel`` now sits inside the same cleanup net.

Everything else this sweep probed was already sealed and is pinned here so
a refactor cannot reopen it:

* a str subclass whose ``__str__`` answers *self* (skipping CPython's
  exact-str fast path) carrying a bound ``encode`` bomb — and its
  ``__eq__``-bomb sibling — in stored ``id`` / ``type`` / ``min_level`` /
  ``name`` / config values: all six channel routes and POST
  /api/alerts/test stay coded and the real text still renders
  (``_utf8_text`` encodes through unbound ``str.encode``);
* bomb-shaped *sender results* through dispatch()'s never-raises contract:
  a dict-subclass ``.get`` bomb result, a ``__bool__`` bomb ``ok``, an
  over-cap-int / lone-surrogate / bytes-subclass ``decode``-bomb message,
  a raising sender whose exception's own ``__str__`` raises;
* a >4300-digit number *nested* inside one channel's stored secrets
  (``json.loads`` raises the digit-cap ValueError, not JSONDecodeError,
  without the parse_int hook): reads stay coded and a sibling channel's
  secret survives the next merge — the file is never rewritten from an
  ``{}`` snapshot.
"""
from __future__ import annotations

import json
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


class SelfStrEncodeBomb(str):
    """``__str__`` answers *self*, so the exact-str fast path never copies
    the subclass away and the bound ``encode`` bomb rides into every
    downstream UTF-8 scrub."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover self-str encode bomb")


class SelfStrEqBomb(SelfStrEncodeBomb):
    def __eq__(self, other):
        raise RuntimeError("leftover self-str __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class DictGetBombResult(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover result .get bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover bytes decode bomb")


class ExcStrBomb(Exception):
    def __str__(self):
        raise RuntimeError("leftover exception __str__ bomb")


#: Past CPython's 4300-digit int<->str conversion cap.
_HUGE_INT = 10 ** 5000
_HUGE_DIGITS = "9" * 5000

_GOOD_YAML = (
    "settings:\n  notify:\n    channels:\n"
    "      - id: c1\n        type: ntfy\n        topic: t\n"
)


def _row(**kw):
    base = {"id": "c1", "type": "ntfy", "topic": "t"}
    base.update(kw)
    return base


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify7Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify7-")
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
        self.client = TestClient(app(), raise_server_exceptions=False)

    def plant(self, notify: dict) -> None:
        """Install *notify* as the live cfg() snapshot (the leftover)."""
        patched = mock.patch.object(
            config, "cfg", lambda: {"settings": {"notify": notify}}
        )
        patched.start()
        self.addCleanup(patched.stop)

    def assert_renderable(self, resp):
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return parsed

    def assert_not_500(self, resp, label: str = ""):
        self.assertNotEqual(resp.status_code, 500, f"{label}: {resp.text[:200]}")
        return self.assert_renderable(resp)

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

    def listed(self) -> dict:
        body = self.assert_not_500(self.client.get("/api/alerts/channels"))
        return {c["id"]: c for c in body["channels"]}


class FailedCreateOrphanedSecretsPins(_Notify7Sandbox):
    """The sweep's find: a create refused at save_channel (coded 503,
    services.yaml intact) must not leave the just-written mandatory secret
    orphaned in notify-credentials.json."""

    _TELEGRAM = {"type": "telegram", "id": "tg1",
                 "config": {"chat_id": "42"},
                 "secrets": {"bot_token": "tok-abc"}}

    def _stored_secret_ids(self) -> str:
        try:
            return self.secrets_path.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError):
            return ""

    def _assert_refused_create_left_no_orphan(self, corrupt_bytes: bytes):
        self.yaml_path.write_bytes(corrupt_bytes)
        config.reload_cfg()
        before = self.yaml_path.read_bytes()
        r = self.client.post("/api/alerts/channels", json=self._TELEGRAM)
        self.assertEqual(r.status_code, 503, r.text[:200])
        body = self.assert_renderable(r)
        self.assertEqual(body["detail"]["code"], "settings.config_unreadable")
        # The unreadable file is never rewritten from an {} snapshot.
        self.assertEqual(self.yaml_path.read_bytes(), before)
        # And the never-created channel's credential does not stay behind.
        self.assertNotIn("tg1", self._stored_secret_ids())
        self.assertNotIn("tok-abc", self._stored_secret_ids())

    def test_torn_services_yaml_refuses_create_without_orphaned_secret(self):
        self._assert_refused_create_left_no_orphan(b"\xff\xfe torn by power loss")

    def test_oversize_services_yaml_refuses_create_without_orphaned_secret(self):
        pad = "settings: {}\n# " + "x" * (1024 * 1024 + 100) + "\n"
        self._assert_refused_create_left_no_orphan(pad.encode("utf-8"))

    def test_list_root_services_yaml_refuses_create_without_orphaned_secret(self):
        self._assert_refused_create_left_no_orphan(b"- a whole-document paste\n")

    def test_cleanup_never_touches_a_sibling_channels_secrets(self):
        # A healthy sibling's stored secret must survive the refused create.
        self.yaml_path.write_text(_GOOD_YAML, encoding="utf-8")
        config.reload_cfg()
        r = self.client.put(
            "/api/alerts/channels/c1",
            json={"type": "ntfy", "config": {"topic": "t"},
                  "secrets": {"token": "sibling-tok"}})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self._assert_refused_create_left_no_orphan(b"\xff\xfe torn")
        self.assertEqual(
            notify_channels.channel_secrets("c1"), {"token": "sibling-tok"})

    def test_create_recovers_after_the_file_is_restored(self):
        self._assert_refused_create_left_no_orphan(b"\xff\xfe torn")
        self.yaml_path.write_text(_GOOD_YAML, encoding="utf-8")
        config.reload_cfg()
        r = self.client.post("/api/alerts/channels", json=self._TELEGRAM)
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = self.assert_renderable(r)
        self.assertIs(body["channel"]["has"]["bot_token"], True)
        self.assertEqual(
            notify_channels.channel_secrets("tg1"), {"bot_token": "tok-abc"})

    def test_require_secrets_refusal_still_drops_the_write(self):
        """The pre-existing cleanup arm: a backstop refusal after the
        secrets write must keep dropping them (pinned so the widened net
        cannot regress the original branch)."""
        self.yaml_path.write_text("settings: {}\n", encoding="utf-8")
        config.reload_cfg()
        with mock.patch.object(notify_channels, "channel_secrets",
                               return_value={}):
            r = self.client.post("/api/alerts/channels", json=self._TELEGRAM)
        self.assertEqual(r.status_code, 400, r.text[:200])
        self.assertNotIn("tg1", self._stored_secret_ids())

    def test_masked_cleanup_failure_keeps_the_coded_503(self):
        """A *cleanup* drop that itself raises (disk dying mid-cleanup) must
        not trade the coded refusal for a 500.  Only the post-failure call
        is broken here: the pre-write orphan wipe runs the real function,
        whose internals all swallow their own errors."""
        self.yaml_path.write_bytes(b"\xff\xfe torn")
        config.reload_cfg()
        real_drop = notify_channels.drop_channel_secrets
        calls = []

        def drop(cid):
            calls.append(cid)
            if len(calls) == 1:
                return real_drop(cid)
            raise OSError("EIO mid-cleanup")

        with mock.patch.object(notify_channels, "drop_channel_secrets",
                               side_effect=drop):
            r = self.client.post("/api/alerts/channels", json=self._TELEGRAM)
        self.assertEqual(r.status_code, 503, r.text[:200])
        self.assertEqual(
            self.assert_renderable(r)["detail"]["code"],
            "settings.config_unreadable")
        # Both the pre-write wipe and the cleanup ran.
        self.assertEqual(calls, ["tg1", "tg1"])


class SelfStrEncodeBombStaysImmunePins(_Notify7Sandbox):
    """A self-``__str__`` str subclass with a bound ``encode`` bomb (and its
    ``__eq__`` sibling) in every stored field: the unbound ``str.encode``
    scrub keeps all six channel routes and the dispatch sweep coded, and the
    real text still renders."""

    def test_encode_bomb_in_each_stored_field_all_routes_survive(self):
        for field, value in (
            ("id", SelfStrEncodeBomb("c1")),
            ("type", SelfStrEncodeBomb("ntfy")),
            ("min_level", SelfStrEncodeBomb("warn")),
            ("name", SelfStrEncodeBomb("panel")),
            ("topic", SelfStrEncodeBomb("t")),
        ):
            with self.subTest(field=field):
                self.plant({"channels": [_row(**{field: value})]})
                self.sweep_channel_routes(f"selfstr {field}")

    def test_eq_bomb_variant_in_each_stored_field_all_routes_survive(self):
        for field, value in (
            ("id", SelfStrEqBomb("c1")),
            ("type", SelfStrEqBomb("ntfy")),
            ("min_level", SelfStrEqBomb("warn")),
            ("topic", SelfStrEqBomb("t")),
        ):
            with self.subTest(field=field):
                self.plant({"channels": [_row(**{field: value})]})
                self.sweep_channel_routes(f"selfstr-eq {field}")

    def test_bombed_row_still_renders_its_real_text(self):
        self.plant({"channels": [_row(name=SelfStrEncodeBomb("panel"),
                                      topic=SelfStrEncodeBomb("alerts"))]})
        rows = self.listed()
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["name"], "panel")
        self.assertEqual(rows["c1"]["config"]["topic"], "alerts")

    def test_legacy_ha_selfstr_token_never_kills_the_test_route(self):
        self.plant({"enabled": True,
                    "ha_token": SelfStrEncodeBomb("tok"),
                    "ha_url": SelfStrEncodeBomb("http://localhost:8123")})
        r = self.client.post("/api/alerts/test")
        self.assert_not_500(r, "legacy selfstr token")


class SenderResultBombStaysImmunePins(_Notify7Sandbox):
    """Bomb-shaped *results* out of a channel sender: dispatch()'s
    never-raises contract holds and both test routes stay renderable."""

    def setUp(self):
        super().setUp()
        self.yaml_path.write_text(_GOOD_YAML, encoding="utf-8")
        config.reload_cfg()

    def _with_sender(self, fn):
        return mock.patch.dict(notify_channels._SENDERS, {"ntfy": fn})

    def _sweep_test_routes(self, label):
        r = self.client.post("/api/alerts/channels/c1/test")
        self.assertEqual(r.status_code, 200, f"{label}: {r.text[:200]}")
        self.assert_renderable(r)
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            f"{label} alerts test")
        out = notify_channels.dispatch("t", "m", level="down", event=None)
        self.assertIsInstance(out, dict)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_dict_subclass_get_bomb_result(self):
        with self._with_sender(
                lambda *a, **k: DictGetBombResult(ok=True, message="m")):
            self._sweep_test_routes("get-bomb result")

    def test_bool_bomb_ok_flag_result(self):
        with self._with_sender(lambda *a, **k: {"ok": BoolBomb(),
                                                "message": "m"}):
            self._sweep_test_routes("bool-bomb ok")

    def test_overcap_int_message_result(self):
        with self._with_sender(lambda *a, **k: {"ok": False,
                                                "message": _HUGE_INT}):
            self._sweep_test_routes("over-cap message")

    def test_surrogate_message_result(self):
        with self._with_sender(lambda *a, **k: {"ok": False,
                                                "message": "\ud800oops"}):
            self._sweep_test_routes("surrogate message")

    def test_bytes_decode_bomb_message_result(self):
        with self._with_sender(lambda *a, **k: {"ok": False,
                                                "message": BytesDecodeBomb(b"m")}):
            self._sweep_test_routes("decode-bomb message")

    def test_raising_sender_whose_exception_str_also_raises(self):
        with self._with_sender(mock.Mock(side_effect=ExcStrBomb())):
            self._sweep_test_routes("exc __str__ bomb")


class NestedHugeSecretsStaysImmunePins(_Notify7Sandbox):
    """A >4300-digit number *nested* inside one channel's stored secrets:
    ``int()`` under json.loads is the digit-cap ValueError, not
    JSONDecodeError — the parse_int hook drops the number, never the file,
    so a sibling channel's secret survives the next merge."""

    def setUp(self):
        super().setUp()
        self.yaml_path.write_text(
            _GOOD_YAML + "      - id: c2\n        type: ntfy\n        topic: u\n",
            encoding="utf-8")
        config.reload_cfg()

    def test_nested_huge_number_keeps_the_file_and_the_siblings(self):
        self.secrets_path.write_text(
            '{"c2": {"token": "sibling-tok"}, '
            '"c1": {"junk": {"deep": ' + _HUGE_DIGITS + '}}}',
            encoding="utf-8")
        rows = self.listed()
        self.assertIs(rows["c2"]["has"]["token"], True)
        # The merge (a PUT on the poisoned channel) must not rewrite the
        # file from an {} snapshot and wipe the sibling.
        r = self.client.put(
            "/api/alerts/channels/c1",
            json={"type": "ntfy", "config": {"topic": "t"},
                  "secrets": {"token": "new-tok"}})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(
            notify_channels.channel_secrets("c2"), {"token": "sibling-tok"})
        self.assertEqual(
            notify_channels.channel_secrets("c1").get("token"), "new-tok")

    def test_huge_number_as_whole_secret_value_reads_degrade_coded(self):
        self.secrets_path.write_text(
            '{"c1": {"token": ' + _HUGE_DIGITS + '}}', encoding="utf-8")
        rows = self.listed()
        # The number dropped to None: the flag reads as absent, never a 500.
        self.assertIs(rows["c1"]["has"]["token"], False)
        self.assert_not_500(self.client.post("/api/alerts/channels/c1/test"),
                            "huge secret test")


if __name__ == "__main__":
    unittest.main()
