"""Ninth Notify-domain leftover sweep: ``__class__``-property / impostor /
hash-shadow-key bombs, over the real app.

notify6 sealed the *bound-dunder* subclass bombs (``.get`` / ``items`` /
``__iter__`` / ``__bool__`` / ``__eq__`` / ``decode`` overrides) behind the
modules5 unbound convention, but every one of those seals fronted a **bare
``isinstance`` gate** — and ``hub/notify_channels.py`` never got the ``_isa``
fail-closed helper the later leftover waves added everywhere else (ups_svc,
smart_test_svc, storage_svc, vms_svc, …).  Driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` with the hostile store planted
as the live ``cfg()`` snapshot, **84 route/shape pairs were live raw HTTP
500s** (or raises out of never-raises paths) on the pre-fix tree:

* **A leftover whose ``__class__`` is a raising property.**  ``isinstance``
  consults ``value.__class__`` when the exact-type check misses, so one such
  value detonated the sanitizer gates themselves: planted as the whole
  ``settings.notify`` section (``settings_section``'s dict gate, reached
  through ``_raw_notify_cfg`` — five of the six channel routes at once, plus
  a raise out of ``alerts.notify_settings()`` into ``emit_alert``'s callers,
  the UPS shutdown policy among them), as the ``channels:`` list or a row
  (``_mapping_get`` / ``_plain_row``), as an ``id`` / ``type`` value
  (``_id_text``), as an ``enabled`` / ``min_level`` / ``notify_resolve``
  flag (``_truthy``, also raising out of :func:`dispatch` on the alert
  engine's single thread), as any config field (``_json_safe`` /
  ``_utf8_text``'s heads — GET /api/alerts/channels), and as every legacy
  Home Assistant field (``_legacy_target`` inside dispatch — POST
  /api/alerts/test).
* **A *lying* ``__class__`` impostor** (claims dict/list/bytes/bool, is
  not): it passed the isinstance gate, and the unbound base call behind it
  — ``dict.items`` / ``list.__iter__`` / ``bytes.decode`` — TypeError'd
  outside any try into the same 500s.  The bool liar rode through
  ``_truthy`` *verbatim*, leaking a non-encodable object into
  ``public_channel``'s ``enabled`` field (a 500 under Starlette's encoder)
  and carrying its own ``__bool__`` bomb into ``_channel_wants`` inside
  dispatch.
* **A hash-shadowing str-subclass mapping key** (``StrEqBomb("id")`` —
  same hash as the plain key, ``__eq__`` raises): it survived the old
  ``dict(ch)`` C-level copy verbatim, and every later ``ch.get("id")`` /
  ``ch["id"] = cid`` probe of that slot detonated the stored key's
  comparison — all six channel routes and the dispatch sweep at once.

Fixes, the established conventions: ``_isa`` (fail-closed isinstance) in
hub/notify_channels.py behind every type gate, ``type(x) is bool`` heads in
``_truthy`` / ``_json_safe``, try-wrapped unbound base calls for the
impostors, exact-str key laundering in ``_plain_row``, and try-wrapped
section reads in ``_raw_notify_cfg`` / ``alerts.notify_settings``.

Stays-immune pins ride along for the shapes the hunt re-probed and found
already sealed: the notify-section bomb against POST /api/alerts/test
(dispatch alone wrapped its cfg read), a ClassBomb nested as a *mapping key*
inside a config field (``_json_safe``'s key try), a FIFO squatting
notify-credentials.json (read_text_capped's O_NONBLOCK + S_ISREG EINVAL),
a >4300-digit number inside the secrets file (``_capped_json_int`` drops the
number alone — no ``{}`` snapshot, so the next write cannot wipe siblings),
and the unreadable-services.yaml create refusing with the coded 503
(``settings.config_unreadable`` via ``_read_disk_for_mutate``) while the
file stays byte-identical and no orphan secret is left behind.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import alerts, audit, auth, config, notify_channels  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class ClassPropertyBomb:
    """``isinstance`` against any class runs the property — and it raises."""

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("leftover __class__ bomb")


class LyingDict:
    """Claims to be a dict; the unbound ``dict.items`` TypeErrors on it."""

    @property
    def __class__(self):  # noqa: D105
        return dict


class LyingList:
    """Claims to be a list; the unbound ``list.__iter__`` TypeErrors on it."""

    @property
    def __class__(self):  # noqa: D105
        return list


class LyingBytes:
    """Claims to be bytes; the unbound base decode TypeErrors on it."""

    @property
    def __class__(self):  # noqa: D105
        return bytes


class LyingStr:
    """Claims to be str; ``str.__str__`` TypeErrors on it."""

    @property
    def __class__(self):  # noqa: D105
        return str


class LyingBool:
    """Claims to be bool; used to ride through ``_truthy`` verbatim."""

    @property
    def __class__(self):  # noqa: D105
        return bool


class LyingBoolBoolBomb(LyingBool):
    """The bool liar carrying its own ``__bool__`` bomb into dispatch."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("bool bomb behind the lying __class__")


class StrEqBombKey(str):
    """Hash-shadows its plain text; comparing against it raises."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("hash-shadow key eq bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


def _row(**kw):
    base = {"id": "c1", "type": "ntfy", "topic": "t"}
    base.update(kw)
    return base


def _notify_cfg(notify) -> dict:
    return {"settings": {"notify": notify}}


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify9Sandbox(unittest.TestCase):
    """Scratch state dirs, offline senders, and a hostile live cfg() snapshot."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify9-")
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
        # Never a network send: every dispatch in this suite hits a stub.
        senders = mock.patch.dict(
            notify_channels._SENDERS,
            {"ntfy": _stub_sender, "home_assistant": _stub_sender,
             "email": _stub_sender},
        )
        senders.start()
        self.addCleanup(senders.stop)
        self.addCleanup(config.reload_cfg)
        self.client = TestClient(app(), raise_server_exceptions=False)

    def plant(self, cfg_data) -> None:
        """Install *cfg_data* as the live cfg() snapshot (the leftover)."""
        patched = mock.patch.object(config, "cfg", lambda: cfg_data)
        patched.start()
        self.addCleanup(patched.stop)

    def assert_renderable(self, resp):
        """The body must be UTF-8 JSON with no lone surrogate leaking out."""
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return parsed

    def assert_not_500(self, resp, label: str = ""):
        self.assertNotEqual(resp.status_code, 500, f"{label}: {resp.text[:200]}")
        return self.assert_renderable(resp)

    _CREATE = {"type": "ntfy", "id": "px", "config": {"topic": "t"}, "secrets": {}}
    _PUT = {"type": "ntfy", "config": {"topic": "u"}, "secrets": {}}

    def sweep_channel_routes(self, label: str) -> None:
        """Every channel surface plus the global test answer coded, never 500."""
        self.assert_not_500(self.client.get("/api/alerts/channels"),
                            f"{label} GET channels")
        self.assert_not_500(
            self.client.post("/api/alerts/channels", json=self._CREATE),
            f"{label} POST create",
        )
        self.assert_not_500(
            self.client.put("/api/alerts/channels/c1", json=self._PUT),
            f"{label} PUT",
        )
        self.assert_not_500(self.client.post("/api/alerts/channels/c1/test"),
                            f"{label} per-channel test")
        self.assert_not_500(self.client.delete("/api/alerts/channels/c1"),
                            f"{label} DELETE")
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            f"{label} POST alerts test")

    def assert_dispatch_contract(self, label: str) -> dict:
        """dispatch() must never raise — it runs on the alert thread."""
        try:
            out = notify_channels.dispatch("t", "m", level="down", event=None)
        except Exception as exc:  # pragma: no cover - the pre-fix failure
            self.fail(f"{label}: dispatch raised {exc!r}")
        self.assertIsInstance(out, dict)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return out

    def listed(self) -> list:
        body = self.assert_not_500(self.client.get("/api/alerts/channels"))
        return body["channels"]


class ClassBombStorePins(_Notify9Sandbox):
    """A ``__class__``-property bomb anywhere in the store cannot 500."""

    def test_whole_notify_section_bomb_all_routes_survive(self):
        # Pre-fix: settings_section's bare isinstance ran the property and
        # 500'd GET/POST channels, PUT/DELETE/{cid}/test through
        # _raw_notify_cfg (dispatch alone had wrapped the read).
        self.plant(_notify_cfg(ClassPropertyBomb()))
        self.sweep_channel_routes("notify-section bomb")
        self.assert_dispatch_contract("notify-section bomb")
        self.assertEqual(self.listed(), [])

    def test_notify_settings_reads_a_section_bomb_as_unconfigured(self):
        # Pre-fix: the raise escaped alerts.notify_settings() into
        # emit_alert's callers — the UPS shutdown policy among them.
        self.plant(_notify_cfg(ClassPropertyBomb()))
        out = alerts.notify_settings()
        self.assertIsInstance(out, dict)

    def test_channels_value_bomb_all_routes_survive(self):
        self.plant(_notify_cfg({"channels": ClassPropertyBomb()}))
        self.sweep_channel_routes("channels-value bomb")
        self.assert_dispatch_contract("channels-value bomb")

    def test_row_bomb_drops_alone_and_sibling_survives(self):
        self.plant(_notify_cfg({"channels": [ClassPropertyBomb(),
                                             _row(id="ok1")]}))
        self.sweep_channel_routes("row bomb")
        self.assert_dispatch_contract("row bomb")
        self.assertIn("ok1", [c["id"] for c in self.listed()])

    def test_id_bomb_renders_as_text_and_sibling_survives(self):
        self.plant(_notify_cfg({"channels": [_row(id=ClassPropertyBomb()),
                                             _row(id="ok1")]}))
        self.sweep_channel_routes("id bomb")
        ids = [c["id"] for c in self.listed()]
        self.assertIn("ok1", ids)
        for cid in ids:
            self.assertIsInstance(cid, str)

    def test_type_bomb_drops_the_row_not_the_route(self):
        self.plant(_notify_cfg({"channels": [_row(type=ClassPropertyBomb()),
                                             _row(id="ok1")]}))
        self.sweep_channel_routes("type bomb")
        ids = [c["id"] for c in self.listed()]
        self.assertNotIn("c1", ids)
        self.assertIn("ok1", ids)

    def test_flag_bombs_read_as_junk_not_500(self):
        for field in ("enabled", "min_level", "notify_resolve"):
            with self.subTest(field=field):
                self.plant(_notify_cfg(
                    {"channels": [_row(**{field: ClassPropertyBomb()})]}))
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)
                # Whatever the junk reads as, the public row stays exactly
                # encodable: bools exact, min_level a plain string.
                self.assertIs(type(rows["c1"]["enabled"]), bool)
                self.assertIs(type(rows["c1"]["notify_resolve"]), bool)
                self.assertIsInstance(rows["c1"]["min_level"], str)
                self.sweep_channel_routes(f"flag bomb {field}")
                self.assert_dispatch_contract(f"flag bomb {field}")

    def test_min_level_bomb_ranks_as_the_warn_default(self):
        self.assertEqual(
            notify_channels._min_rank({"min_level": ClassPropertyBomb()}),
            notify_channels.LEVELS["warn"],
        )

    def test_config_field_bombs_keep_the_row_rendering(self):
        for field in ("topic", "name"):
            with self.subTest(field=field):
                self.plant(_notify_cfg(
                    {"channels": [_row(**{field: ClassPropertyBomb()})]}))
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)

    def test_email_to_bomb_keeps_get_alive_and_send_soft_fails(self):
        self.plant(_notify_cfg({"channels": [
            {"id": "e1", "type": "email", "host": "h",
             "to": ClassPropertyBomb()}]}))
        self.assertIn("e1", [c["id"] for c in self.listed()])
        # The recipients read degrades to the coded missing-field soft fail,
        # never an exception, even without the sender stub.
        self.assertEqual(notify_channels._recipients(ClassPropertyBomb()), [])

    def test_legacy_ha_field_bombs_never_kill_dispatch(self):
        for legacy in ({"ha_token": ClassPropertyBomb()},
                       {"enabled": ClassPropertyBomb(), "ha_token": "x"},
                       {"ha_webhook_url": ClassPropertyBomb()},
                       {"ha_token": "x", "notify_resolve": ClassPropertyBomb()}):
            with self.subTest(legacy=legacy):
                self.plant(_notify_cfg(legacy))
                self.assert_dispatch_contract("legacy bomb")
                r = self.client.post("/api/alerts/test")
                self.assert_not_500(r, "legacy bomb alerts test")

    def test_effective_settings_survives_class_bomb_flags(self):
        raw = {"channels": [_row(enabled=ClassPropertyBomb(),
                                 notify_resolve=ClassPropertyBomb(),
                                 min_level=ClassPropertyBomb())]}
        out = notify_channels.effective_settings(raw)
        self.assertIsInstance(out, dict)


class LyingClassImpostorPins(_Notify9Sandbox):
    """A lying ``__class__`` passes the gate; the unbound call must not 500."""

    def test_lying_list_channels_value_all_routes_survive(self):
        # Pre-fix: list.__iter__(rows) TypeError'd out of channels().
        self.plant(_notify_cfg({"channels": LyingList()}))
        self.sweep_channel_routes("lying-list channels")
        self.assert_dispatch_contract("lying-list channels")
        self.assertEqual(self.listed(), [])

    def test_lying_dict_row_drops_alone(self):
        self.plant(_notify_cfg({"channels": [LyingDict(), _row(id="ok1")]}))
        self.sweep_channel_routes("lying-dict row")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_lying_impostor_config_values_degrade_not_500(self):
        # Pre-fix: dict.items / list.__iter__ / bytes.decode each
        # TypeError'd out of _json_safe on GET /api/alerts/channels.
        for value, expect in ((LyingDict(), None), (LyingList(), None),
                              (LyingBytes(), "")):
            with self.subTest(value=type(value).__name__):
                self.plant(_notify_cfg({"channels": [_row(topic=value)]}))
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)
                self.assertEqual(rows["c1"]["config"].get("topic"),
                                 expect if expect is not None else None)

    def test_lying_str_id_drops_the_row_not_the_route(self):
        self.plant(_notify_cfg({"channels": [_row(id=LyingStr()),
                                             _row(id="ok1")]}))
        self.sweep_channel_routes("lying-str id")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_lying_bool_enabled_reads_as_an_exact_bool(self):
        # Pre-fix: _truthy's isinstance returned the liar verbatim and the
        # non-encodable object 500'd GET /api/alerts/channels.
        self.plant(_notify_cfg({"channels": [_row(enabled=LyingBool())]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertIs(type(rows["c1"]["enabled"]), bool)
        self.sweep_channel_routes("lying-bool enabled")

    def test_lying_bool_carrying_a_bool_bomb_never_kills_dispatch(self):
        # Pre-fix: the liar rode through _truthy into _channel_wants' truth
        # test and its __bool__ bomb raised out of dispatch() on the alert
        # thread (and 500'd POST /api/alerts/test).
        self.plant(_notify_cfg({"channels": [_row(enabled=LyingBoolBoolBomb())]}))
        self.assert_dispatch_contract("lying-bool bool-bomb")
        self.sweep_channel_routes("lying-bool bool-bomb")

    def test_truthy_always_answers_an_exact_bool(self):
        self.assertIs(notify_channels._truthy(LyingBool()), True)
        self.assertIs(notify_channels._truthy(LyingBoolBoolBomb()), False)
        self.assertIs(notify_channels._truthy(ClassPropertyBomb()), True)
        self.assertIs(notify_channels._truthy(True), True)
        self.assertIs(notify_channels._truthy(False), False)


class HashShadowKeyPins(_Notify9Sandbox):
    """A hash-shadowing str-subclass mapping key cannot 500 — and the
    shadowed field keeps its value under the laundered plain key."""

    def test_shadowed_id_key_row_stays_fully_addressable(self):
        # Pre-fix: every ch.get("id") / ch["id"] = cid probe of the slot ran
        # the stored key's __eq__ — all six routes and the dispatch sweep.
        row = {StrEqBombKey("id"): "c1", "type": "ntfy", "topic": "t"}
        self.plant(_notify_cfg({"channels": [row, _row(id="ok1")]}))
        self.sweep_channel_routes("shadowed id key")
        self.assert_dispatch_contract("shadowed id key")
        rows = {c["id"]: c for c in self.listed()}
        # Salvage: str.__str__ copies the real key text, so the row answers
        # to its own id — the per-channel test reaches it, never a 404.
        self.assertIn("c1", rows)
        self.assertIn("ok1", rows)
        r = self.client.post("/api/alerts/channels/c1/test")
        self.assertEqual(r.status_code, 200, r.text[:200])

    def test_shadowed_type_key_keeps_the_row(self):
        row = {"id": "c1", StrEqBombKey("type"): "ntfy", "topic": "t"}
        self.plant(_notify_cfg({"channels": [row, _row(id="ok1")]}))
        self.sweep_channel_routes("shadowed type key")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["type"], "ntfy")

    def test_shadowed_enabled_key_keeps_its_stored_flag(self):
        row = {"id": "c1", "type": "ntfy",
               StrEqBombKey("enabled"): False, "topic": "t"}
        self.plant(_notify_cfg({"channels": [row]}))
        self.sweep_channel_routes("shadowed enabled key")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIs(rows["c1"]["enabled"], False)

    def test_plain_row_launders_shadow_keys_to_exact_str(self):
        out = notify_channels._plain_row(
            {StrEqBombKey("id"): "c1", "type": "ntfy"})
        self.assertEqual(out.get("id"), "c1")
        self.assertTrue(all(type(k) is str for k in out))


class EverythingBombedAtOncePins(_Notify9Sandbox):
    """All the ninth-wave shapes in one store: no crack between the guards."""

    def test_combined_store_every_route_survives(self):
        self.plant(_notify_cfg({
            "enabled": ClassPropertyBomb(),
            "ha_token": "x",
            "notify_resolve": ClassPropertyBomb(),
            "channels": [
                ClassPropertyBomb(),
                LyingDict(),
                {StrEqBombKey("id"): "c1", "type": "ntfy",
                 "topic": LyingBytes(), "enabled": LyingBoolBoolBomb(),
                 "min_level": ClassPropertyBomb()},
                _row(id="ok1", topic={"k": ClassPropertyBomb(), "sane": 1}),
            ],
        }))
        self.sweep_channel_routes("combined")
        self.assert_dispatch_contract("combined")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertIn("ok1", rows)
        self.assertEqual(rows["ok1"]["config"]["topic"].get("sane"), 1)


class StaysImmunePins(_Notify9Sandbox):
    """Shapes the hunt re-probed and found already sealed stay that way."""

    def test_section_bomb_against_the_global_test_route(self):
        # dispatch() had wrapped its own cfg read all along; pinned so a
        # refactor cannot trade the wrap for the (now fixed) helper alone.
        self.plant(_notify_cfg(ClassPropertyBomb()))
        r = self.client.post("/api/alerts/test")
        self.assert_not_500(r, "section bomb alerts test")

    def test_class_bomb_as_a_nested_config_key_drops_alone(self):
        # _json_safe's key scrub is try-wrapped: the bomb key drops, the
        # sane sibling entry survives on the same mapping.
        self.plant(_notify_cfg({"channels": [
            _row(topic={ClassPropertyBomb(): 1, "sane": 2})]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"]["topic"].get("sane"), 2)

    def test_fifo_squatting_the_secrets_file_never_hangs_or_500s(self):
        # read_text_capped opens O_NONBLOCK and refuses non-regular files
        # (OSError EINVAL), which the secrets reads degrade to {} and the
        # write path replaces — GET answers instead of parking forever.
        os.mkfifo(self.secrets_path)
        self.plant(_notify_cfg({"channels": [_row()]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertIs(rows["c1"]["has"]["token"], False)

    def test_huge_int_in_the_secrets_file_drops_alone_no_wipe(self):
        # int() past the 4300-digit cap is ValueError (not JSONDecodeError)
        # for the whole document; _capped_json_int drops the number alone,
        # so the sibling channel's secret survives *and* the next write
        # cannot rewrite the file from a {} snapshot.
        self.secrets_path.write_text(
            '{"c1": {"token": "keep"}, "junk": {"n": %s}}' % ("9" * 5000),
            encoding="utf-8",
        )
        self.plant(_notify_cfg({"channels": [_row()]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertIs(rows["c1"]["has"]["token"], True)
        notify_channels.set_channel_secrets("other", {"token": "x"})
        self.assertEqual(
            notify_channels.channel_secrets("c1"), {"token": "keep"})

    def test_unreadable_services_yaml_create_refuses_503_file_intact(self):
        # config.mutate -> _read_disk_for_mutate: the torn services.yaml
        # refuses with the coded 503 and stays byte-identical; the create's
        # cleanup net leaves no orphan secret behind for the never-created
        # channel.
        self.yaml_path.write_bytes(b"settings:\n  \xff\xfe torn\n")
        before = self.yaml_path.read_bytes()
        r = self.client.post("/api/alerts/channels", json={
            "type": "telegram", "id": "tg9", "config": {"chat_id": "1"},
            "secrets": {"bot_token": "tok"},
        })
        self.assertEqual(r.status_code, 503, r.text[:200])
        body = self.assert_renderable(r)
        self.assertEqual(body["detail"]["code"], "settings.config_unreadable")
        self.assertEqual(self.yaml_path.read_bytes(), before)
        self.assertEqual(notify_channels.channel_secrets("tg9"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
