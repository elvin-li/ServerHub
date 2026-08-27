"""Eleventh Notify-domain leftover sweep: *plain-object* hash-shadowing
mapping keys, over the real app.

notify9 sealed the hash-shadowing **str-subclass** key (``StrEqBomb("id")``)
by laundering str-subclass keys to exact str inside ``_plain_row`` — but the
launder was gated on ``_isa(k, str)``, so a **plain-object** shadow key
(``__hash__`` answering the same hash as ``"id"`` / ``"type"`` / a flag
name, ``__eq__`` that raises — or answers a comparison *result* whose
``__bool__`` raises) survived the plain copy verbatim.  CPython's dict
lookup compares the *stored* key against the probe, so every later
``ch.get("id")`` / ``ch["id"] = cid`` on the colliding slot detonated the
leftover key's own comparison.  Driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` with the hostile store planted
as the live ``cfg()`` snapshot, **38 route/shape pairs were live raw HTTP
500s** (or raises out of never-raises paths) on the pre-fix tree:

* a shadow key on a row's ``id`` / ``type`` slot: all six
  /api/alerts/channels routes and POST /api/alerts/test at once, plus a
  raise out of :func:`hub.notify_channels.dispatch` on the alert engine's
  single thread and out of :func:`hub.notify_channels.effective_settings`;
* a shadow key on ``enabled`` / ``min_level`` / ``notify_resolve`` /
  ``name`` / ``topic``: GET /api/alerts/channels, the per-channel test,
  DELETE, and the effective_settings widening;
* the ``__eq__``-answers-a-``__bool__``-bomb variant of all of the above
  (the comparison result detonates inside ``PyObject_IsTrue``, one C call
  later than the raising ``__eq__``);
* a shadow key on the *section's* global ``enabled`` / ``include_warn`` /
  ``notify_resolve`` slots: ``effective_settings``' widening writes
  (``out["enabled"] = True`` on the bare ``dict(raw)`` copy) detonated the
  stored key — alerts.notify_settings() fell back to the raw legacy flags,
  whose ``_mapping_get`` read the shadowed flag as junk, and every explicit
  channel **silently stopped notifying** (no 500, which is worse: nobody
  sees a silent alerting outage).

Fixes, the established conventions: ``_plain_row`` drops every key that is
not exact-str after the launder (no schema read ever looks a row field up
under a non-str key, so nothing observable is lost), and
``effective_settings`` widens on a ``_plain_row`` laundered copy instead of
the bare ``dict(raw)`` — the writes always land and the widening survives
field-level.

Stays-immune pins ride along for the wave-11 shapes the hunt probed and
found already sealed: shadow keys replacing *section-level* fields
(``channels`` / legacy Home Assistant slots) degrade through
``_mapping_get``'s double try; a shadow key nested in a config sub-dict
renders through ``_json_safe``'s ``_utf8_text`` key scrub; nested lying
``__class__`` impostors inside a list config value; ``isoformat``-property
and ``__getattr__`` bombs; a str-subclass id whose ``__str__`` answers
*self* carrying a bound ``encode`` bomb; and the request-driven extremes
(a deeply-nested JSON body, a JSON number past the int digit cap) answering
coded 400s out of the body-parse guards.
"""
from __future__ import annotations

import json
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


class ObjShadowKey:
    """Plain-object key: same hash as its target text, ``__eq__`` raises.

    Not a str subclass, so notify9's ``_plain_row`` launder never touched
    it — it rode the plain-dict copy verbatim and every later lookup of the
    colliding slot ran this comparison.
    """

    def __init__(self, text: str):
        self._t = text

    def __hash__(self):  # noqa: D105
        return hash(self._t)

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover obj shadow key eq bomb")

    __ne__ = __eq__


class _CmpResultBoolBomb:
    def __bool__(self):  # noqa: D105
        raise RuntimeError("comparison-result bool bomb")


class ObjShadowCmpBoolBombKey:
    """``__eq__`` answers an object whose ``__bool__`` raises.

    One C call later than the raising ``__eq__``: the dict lookup runs
    ``PyObject_IsTrue`` on the comparison result and detonates there.
    """

    def __init__(self, text: str):
        self._t = text

    def __hash__(self):  # noqa: D105
        return hash(self._t)

    def __eq__(self, other):  # noqa: D105
        return _CmpResultBoolBomb()

    __ne__ = __eq__


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


class IsoPropBomb:
    """A raising ``isoformat`` property: the getattr probe must not 500."""

    @property
    def isoformat(self):  # noqa: D105
        raise RuntimeError("isoformat property bomb")


class GetattrBomb:
    """``__getattr__`` raising non-AttributeError on *any* attribute."""

    def __getattr__(self, name):  # noqa: D105
        raise RuntimeError(f"getattr bomb: {name}")


class SelfStrEncodeBomb(str):
    """``__str__`` answers *self*, so the bound ``encode`` bomb survives a
    bare ``str()`` copy; only the unbound ``str.encode`` scrub defuses it."""

    def __str__(self):  # noqa: D105
        return self

    def encode(self, *a, **k):  # noqa: D102
        raise RuntimeError("bound encode bomb")


class ShadowRowDict(dict):
    """A dict *subclass* row whose C-level storage holds the shadow key."""


def _row(**kw):
    base = {"id": "c1", "type": "ntfy", "topic": "t"}
    base.update(kw)
    return base


def _shadowed_row(key_cls, field: str, value="x") -> dict:
    """A channel row whose *field* key slot is held by a shadow-key bomb.

    A shadow key and its plain-text twin can never coexist in one dict
    (either insertion runs the bomb comparison), so the bomb *replaces*
    the field — exactly the shape a leftover writer leaves behind.
    """
    row = _row()
    row.pop(field, None)
    row[key_cls(field)] = value
    return row


def _notify_cfg(notify) -> dict:
    return {"settings": {"notify": notify}}


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify11Sandbox(unittest.TestCase):
    """Scratch state dirs, offline senders, and a hostile live cfg() snapshot."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify11-")
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


class RowObjectShadowKeyPins(_Notify11Sandbox):
    """A plain-object shadow key in a channel row cannot 500 any route."""

    def test_shadowed_id_key_drops_the_row_not_the_route(self):
        # Pre-fix: every ch.get("id") / ch["id"] = cid probe of the slot ran
        # the stored key's __eq__ — all six routes, POST /api/alerts/test,
        # dispatch() and effective_settings() at once.  Unlike the notify9
        # str-subclass twin there is no real text to salvage (the key is not
        # a str), so the row degrades to id-less and drops alone.
        self.plant(_notify_cfg({"channels": [
            _shadowed_row(ObjShadowKey, "id", "c1"), _row(id="ok1")]}))
        self.sweep_channel_routes("obj-shadow id key")
        self.assert_dispatch_contract("obj-shadow id key")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_shadowed_type_key_drops_the_row_not_the_route(self):
        self.plant(_notify_cfg({"channels": [
            _shadowed_row(ObjShadowKey, "type", "ntfy"), _row(id="ok1")]}))
        self.sweep_channel_routes("obj-shadow type key")
        self.assert_dispatch_contract("obj-shadow type key")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_shadowed_flag_and_config_keys_degrade_field_level(self):
        # Pre-fix: GET /api/alerts/channels, the per-channel test and DELETE
        # each 500'd on the first .get of the shadowed slot; the row itself
        # is sane, so it must keep rendering with the field's default.
        for field in ("enabled", "min_level", "notify_resolve", "name", "topic"):
            with self.subTest(field=field):
                self.plant(_notify_cfg({"channels": [
                    _shadowed_row(ObjShadowKey, field), _row(id="ok1")]}))
                self.sweep_channel_routes(f"obj-shadow {field} key")
                self.assert_dispatch_contract(f"obj-shadow {field} key")
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)
                self.assertIn("ok1", rows)
                self.assertIs(type(rows["c1"]["enabled"]), bool)
                self.assertIsInstance(rows["c1"]["min_level"], str)

    def test_cmp_result_bool_bomb_key_is_the_same_class(self):
        # The __eq__-answers-a-__bool__-bomb variant detonates one C call
        # later (PyObject_IsTrue on the comparison result), outside every
        # except net that only guarded the compare itself.
        self.plant(_notify_cfg({"channels": [
            _shadowed_row(ObjShadowCmpBoolBombKey, "id", "c1"),
            _row(id="ok1")]}))
        self.sweep_channel_routes("cmp-result bool-bomb id key")
        self.assert_dispatch_contract("cmp-result bool-bomb id key")
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])

    def test_dict_subclass_row_with_shadow_key_in_storage(self):
        # _plain_row's unbound dict.items walk reads the C-level storage of
        # a subclass row too: the shadow key must drop there just the same.
        row = ShadowRowDict(_row())
        del row["topic"]
        dict.__setitem__(row, ObjShadowKey("topic"), "x")
        self.plant(_notify_cfg({"channels": [row, _row(id="ok1")]}))
        self.sweep_channel_routes("subclass row shadow key")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertNotIn("topic", rows["c1"]["config"])

    def test_effective_settings_survives_row_shadow_keys(self):
        # Pre-fix: c.get("enabled", True) on the un-laundered row raised out
        # of effective_settings into alerts.notify_settings' fallback.
        for field in ("id", "enabled", "notify_resolve"):
            with self.subTest(field=field):
                raw = {"channels": [_shadowed_row(ObjShadowKey, field),
                                    _row(id="ok1", enabled=True)]}
                out = notify_channels.effective_settings(raw)
                self.assertIsInstance(out, dict)
                self.assertIs(out.get("enabled"), True)

    def test_plain_row_drops_every_non_str_key(self):
        out = notify_channels._plain_row(
            {ObjShadowKey("id"): "x", "type": "ntfy", 1: "int-key",
             None: "none-key", ("t",): "tuple-key"})
        self.assertEqual(out, {"type": "ntfy"})
        self.assertTrue(all(type(k) is str for k in out))

    def test_plain_row_still_launders_str_subclass_keys(self):
        # The notify9 salvage stays: a str-subclass key keeps its value
        # under the laundered plain-text key.
        class StrKey(str):
            def __eq__(self, other):  # noqa: D105
                raise RuntimeError("str-subclass eq bomb")
            __ne__ = __eq__
            __hash__ = str.__hash__

        out = notify_channels._plain_row({StrKey("id"): "c1", "type": "ntfy"})
        self.assertEqual(out.get("id"), "c1")
        self.assertTrue(all(type(k) is str for k in out))


class SectionShadowKeyPins(_Notify11Sandbox):
    """Shadow keys replacing *section-level* fields degrade field-level."""

    def test_shadowed_channels_key_empties_the_list_not_the_route(self):
        # The channels list under a bomb key is unreadable without running
        # its comparison; _mapping_get's double try degrades to "no
        # channels" while every route keeps answering.
        section = {ObjShadowKey("channels"): [_row()], "ha_token": "x"}
        self.plant(_notify_cfg(section))
        self.sweep_channel_routes("section shadow channels key")
        self.assert_dispatch_contract("section shadow channels key")
        self.assertEqual(self.listed(), [])

    def test_shadowed_legacy_fields_degrade_field_level(self):
        # Only the shadowed slot is lost; a sibling legacy field on a plain
        # key keeps the implicit Home Assistant channel alive.
        section = {ObjShadowKey("ha_token"): "x",
                   "ha_webhook_url": "http://example.com/hook",
                   "enabled": True}
        self.plant(_notify_cfg(section))
        out = self.assert_dispatch_contract("section shadow ha_token key")
        self.assertEqual(out.get("sent"), 1)
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            "section shadow ha_token key alerts test")

    def test_widening_survives_shadowed_global_flags(self):
        # Pre-fix: out["enabled"] = True on the bare dict(raw) copy ran the
        # stored bomb key's comparison; alerts.notify_settings() fell back
        # to the raw legacy flags, _mapping_get read the shadowed flag as
        # junk, and every explicit channel silently stopped notifying.
        raw = {"channels": [_row(enabled=True, min_level="info")],
               ObjShadowKey("enabled"): "junk",
               ObjShadowKey("include_warn"): "junk",
               ObjShadowKey("notify_resolve"): "junk"}
        out = notify_channels.effective_settings(raw)
        self.assertIsInstance(out, dict)
        self.assertIs(out.get("enabled"), True)
        self.assertIs(out.get("include_warn"), True)
        self.assertIs(out.get("notify_resolve"), True)
        self.assertTrue(all(type(k) is str for k in out))

    def test_notify_settings_keeps_notifying_end_to_end(self):
        raw = {"channels": [_row(enabled=True, min_level="info")],
               ObjShadowKey("enabled"): "junk"}
        self.plant(_notify_cfg(raw))
        n = alerts.notify_settings()
        self.assertIsInstance(n, dict)
        self.assertIs(n.get("enabled"), True)

    def test_pure_legacy_raw_still_passes_through_untouched(self):
        # The widening copy only runs once an enabled explicit channel
        # exists; a pure-legacy section must keep the identity contract.
        raw = {"enabled": True, "ha_token": "x"}
        self.assertIs(notify_channels.effective_settings(raw), raw)


class StaysImmunePins(_Notify11Sandbox):
    """Wave-11 shapes the hunt probed and found already sealed stay that way."""

    def test_shadow_key_nested_in_a_config_sub_dict_renders(self):
        # _json_safe walks entries (never lookups) and scrubs keys through
        # _utf8_text, so the bomb key renders as its repr text and the sane
        # sibling entry survives on the same mapping.
        self.plant(_notify_cfg({"channels": [
            _row(topic={ObjShadowKey("k"): 1, "sane": 2})]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"]["topic"].get("sane"), 2)
        self.sweep_channel_routes("nested shadow key")

    def test_nested_lying_impostors_inside_a_list_config_value(self):
        # The try-wrapped unbound base calls hold one recursion level down:
        # each impostor degrades to None inside the list, siblings survive.
        self.plant(_notify_cfg({"channels": [
            _row(topic=[LyingDict(), LyingList(), "ok"])]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"]["topic"], [None, None, "ok"])
        self.sweep_channel_routes("nested lying impostors")

    def test_isoformat_property_and_getattr_bombs_degrade(self):
        # getattr's default only swallows AttributeError; the probe's own
        # try is what keeps a property / __getattr__ bomb out of the 500.
        for value in (IsoPropBomb(), GetattrBomb()):
            with self.subTest(value=type(value).__name__):
                self.plant(_notify_cfg({"channels": [_row(topic=value)]}))
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)
                self.sweep_channel_routes(f"{type(value).__name__} topic")

    def test_self_str_encode_bomb_id_and_min_level(self):
        # __str__ answering *self* skips CPython's exact-str copy, so only
        # the unbound str.encode scrub keeps the bound bomb out of the
        # response encoder — and out of dispatch on the alert thread.
        self.plant(_notify_cfg({"channels": [
            _row(id=SelfStrEncodeBomb("c1"),
                 min_level=SelfStrEncodeBomb("warn"))]}))
        self.sweep_channel_routes("self-str encode bomb")
        self.assert_dispatch_contract("self-str encode bomb")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["min_level"], "warn")

    def test_deeply_nested_request_body_answers_a_coded_400(self):
        # Request-driven, not leftover: the config value cap refuses the
        # blob long before services.yaml (or any renderer) sees it.
        nest = {"end": "x"}
        for _ in range(3000):
            nest = {"n": nest}
        r = self.client.post("/api/alerts/channels", json={
            "type": "ntfy", "id": "deep1", "config": {"topic": nest},
            "secrets": {}})
        self.assertEqual(r.status_code, 400, r.text[:200])
        body = self.assert_renderable(r)
        self.assertEqual(body["detail"]["code"], "notify.value_too_long")

    def test_extreme_depth_and_huge_number_bodies_never_500(self):
        # json.loads' RecursionError (depth) and the int digit-cap
        # ValueError (a >4300-digit number) both surface as the body-parse
        # guard's coded 400, never a raw 500.
        depth = 200000
        deep = ('{"type":"ntfy","id":"d2","secrets":{},"config":{"topic":'
                + '{"n":' * depth + '"x"' + '}' * depth + '}}')
        huge = ('{"type":"ntfy","id":"d3","secrets":{},"config":'
                '{"topic":"t","port":' + "9" * 20000 + '}}')
        for label, payload in (("deep", deep), ("huge-number", huge)):
            with self.subTest(label=label):
                r = self.client.post(
                    "/api/alerts/channels", content=payload,
                    headers={"Content-Type": "application/json"})
                self.assertEqual(r.status_code, 400, r.text[:200])
                self.assert_renderable(r)


class EverythingShadowedAtOncePins(_Notify11Sandbox):
    """All the eleventh-wave shapes in one store: no crack between guards."""

    def test_combined_store_every_route_survives(self):
        row = _row(id="c1")
        row.pop("topic")
        row[ObjShadowKey("topic")] = "x"
        row.pop("id")
        row[ObjShadowCmpBoolBombKey("id")] = "c1"
        self.plant(_notify_cfg({
            "ha_webhook_url": "http://example.com/hook",
            ObjShadowKey("enabled"): "junk",
            ObjShadowKey("notify_resolve"): "junk",
            "channels": [
                row,
                _shadowed_row(ObjShadowKey, "type"),
                _row(id="ok1", topic={ObjShadowKey("k"): 1, "sane": 2},
                     enabled=True),
            ],
        }))
        self.sweep_channel_routes("combined")
        self.assert_dispatch_contract("combined")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("ok1", rows)
        self.assertEqual(rows["ok1"]["config"]["topic"].get("sane"), 2)
        out = notify_channels.effective_settings({
            ObjShadowKey("enabled"): "junk",
            "channels": [_row(id="ok1", enabled=True)]})
        self.assertIs(out.get("enabled"), True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
