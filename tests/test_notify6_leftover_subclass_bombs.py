"""Sixth Notify-domain leftover sweep: cfg-cache subclass bombs, over the real app.

The find: ``hub/notify_channels.py`` never got the subclass-bomb hardening the
rest of the tree standardized on (the modules5 unbound convention:
``hub.ups_svc._mapping_get``, ``hub.jobs._truthy``, ``hub.modules._jsonable``'s
unbound ``dict.items`` / ``base.__iter__`` / ``int.__index__`` /
``float.__float__`` / ``bytes.decode``).  Driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` with the hostile store planted
as the live ``cfg()`` snapshot, **33 route/shape pairs were live raw HTTP
500s** on the pre-fix tree:

* a list-subclass ``__iter__`` bomb as ``settings.notify.channels``, a
  dict-subclass ``.get`` bomb row, and a str-subclass ``__eq__`` bomb id
  each 500'd ALL six channel routes (GET/POST /api/alerts/channels,
  PUT/DELETE /api/alerts/channels/{cid}, POST .../test) *and*
  POST /api/alerts/test — the last through :func:`dispatch`, which runs on
  the alert engine's single thread under a never-raises contract, so the
  same leftover silently killed every scheduled alert sweep;
* a ``__bool__`` bomb as ``enabled`` / ``min_level`` / ``notify_resolve``
  detonated the truth tests hidden in ``bool(ch.get("enabled", True))`` and
  ``ch.get("min_level") or "warn"`` (GET channels; ``enabled`` also 500'd
  POST /api/alerts/test via ``_channel_wants``);
* scalar/nested bombs in a config field blew ``_json_safe`` /
  ``_utf8_text``'s bound probes on GET /api/alerts/channels: a bytes-subclass
  ``decode`` bomb, an int-subclass ``__str__`` bomb (only ValueError was
  caught by the digit-cap probe), a float-subclass ``__eq__`` bomb (the
  NaN/inf probes), a dict-subclass ``items()`` bomb, a torn-pairs ``items()``
  (unpack ValueError), a list-subclass ``__iter__`` bomb, a ``__getattr__``
  bomb and a raising ``isoformat`` property (getattr's default only swallows
  AttributeError);
* a ``__bool__`` bomb in the legacy Home Assistant block (``enabled`` /
  ``ha_token``) raised out of ``_legacy_target`` inside dispatch() and
  500'd POST /api/alerts/test.

Fixes, all in hub/notify_channels.py, all the established conventions:
``_mapping_get`` / ``_truthy`` / ``_pick`` for every cfg read and truth
test, a C-level ``dict(row)`` copy plus exact-str id/type coercion
(``str.__str__``) in :func:`channels` / :func:`public_channel`, and the
modules5 unbound-base treatment inside ``_json_safe`` / ``_utf8_text``.

Salvage, not just survival: the bombed subclass's *real* data still renders
(``dict.get`` / ``dict.items`` / ``base.__iter__`` read the C-level storage
underneath the override), and a bombed row stays addressable by PUT and the
per-channel test.

Stays-immune pins ride along for the vectors that were already dead: a
dict-subclass ``keys()`` bomb row (the ``{**ch}`` / ``dict(ch)`` C copy),
an int-subclass ``__str__`` bomb as id (``_id_text``'s broad catch), an
int-subclass ``__str__`` bomb as type (dropped by the isinstance-str gate),
and a str-subclass ``__hash__`` bomb as type (exact-str coercion before the
``in CHANNEL_TYPES`` membership hash).
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from contextlib import ExitStack
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


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class DictKeysBomb(dict):
    def keys(self):
        raise RuntimeError("leftover keys bomb")


class DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class TriplesItems(dict):
    """items() yields a 3-tuple — the ``for k, v`` unpack used to ValueError."""

    def items(self):
        return [("a", 1, 2)]


class ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover list __iter__ bomb")


class IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover int __str__ bomb")

    __repr__ = __str__


class FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("leftover float __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover bytes decode bomb")


class StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("leftover str __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class StrHashBomb(str):
    def __hash__(self):
        raise RuntimeError("leftover str __hash__ bomb")


class GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError(f"leftover getattr bomb: {name}")


class IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("leftover isoformat bomb")


def _row(**kw):
    base = {"id": "c1", "type": "ntfy", "topic": "t"}
    base.update(kw)
    return base


def _notify_cfg(notify) -> dict:
    return {"settings": {"notify": notify}}


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify6Sandbox(unittest.TestCase):
    """Scratch state dirs, offline senders, and a hostile live cfg() snapshot."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify6-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = Path(tmp)
        self.data = self.root / "data"
        self.data.mkdir()
        for target, attr, value in (
            (config, "YAML_PATH", self.root / "services.yaml"),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (alerts, "ALERTS_FILE", self.data / "alerts.jsonl"),
            (alerts, "STATE_FILE", self.data / "alert_state.json"),
            (notify_channels, "SECRETS_FILE", self.data / "notify-credentials.json"),
            (audit, "AUDIT_PATH", self.data / "auth-audit.jsonl"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        # Never a network send: every dispatch in this suite hits a stub.
        senders = mock.patch.dict(
            notify_channels._SENDERS,
            {"ntfy": _stub_sender, "home_assistant": _stub_sender},
        )
        senders.start()
        self.addCleanup(senders.stop)
        self.addCleanup(config.reload_cfg)
        self.client = TestClient(app(), raise_server_exceptions=False)

    def plant(self, cfg_data: dict) -> None:
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

    def listed(self) -> list:
        body = self.assert_not_500(self.client.get("/api/alerts/channels"))
        return body["channels"]


class ChannelsWalkBombRoutePins(_Notify6Sandbox):
    """The channels() walk itself: iterbomb list, .get-bomb row, __eq__-bomb id.
    Each used to 500 all six channel routes and POST /api/alerts/test."""

    def test_channels_list_iterbomb_all_routes_and_rows_survive(self):
        self.plant(_notify_cfg({"channels": ListIterBomb([_row()])}))
        self.sweep_channel_routes("channels iterbomb")
        # Salvage: list.__iter__ reads the real elements under the override.
        self.assertIn("c1", [c["id"] for c in self.listed()])

    def test_dict_get_bomb_row_all_routes_and_its_data_survive(self):
        self.plant(_notify_cfg({"channels": [DictGetBomb(_row())]}))
        self.sweep_channel_routes("get-bomb row")
        rows = {c["id"]: c for c in self.listed()}
        # Salvage: dict(row) copies the C-level storage underneath the
        # override, so the bombed row keeps its sane channel data.
        self.assertIn("c1", rows)
        self.assertEqual(rows["c1"]["config"].get("topic"), "t")

    def test_str_eq_bomb_id_all_routes_survive_and_row_stays_addressable(self):
        self.plant(_notify_cfg({"channels": [_row(id=StrEqBomb("c1"))]}))
        self.sweep_channel_routes("eq-bomb id")
        # Salvage: str.__str__ copies the real text, so the row answers to
        # its own id — the per-channel test reaches it, never a 404.
        r = self.client.post("/api/alerts/channels/c1/test")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = self.assert_renderable(r)
        self.assertEqual([res["id"] for res in body["results"]], ["c1"])

    def test_bool_bomb_flags_read_as_junk_not_500(self):
        for field in ("enabled", "min_level", "notify_resolve"):
            with self.subTest(field=field):
                self.plant(_notify_cfg({"channels": [_row(**{field: BoolBomb()})]}))
                rows = {c["id"]: c for c in self.listed()}
                self.assertIn("c1", rows)
                # A bomb flag is junk, not consent: enabled fails closed,
                # min_level falls back to the "warn" default.
                if field == "min_level":
                    self.assertEqual(rows["c1"]["min_level"], "warn")
                else:
                    self.assertIs(rows[
                        "c1"][field], False)
                self.sweep_channel_routes(f"bool-bomb {field}")

    def test_enabled_bool_bomb_never_kills_the_dispatch_sweep(self):
        """dispatch() runs on the alert engine's single thread under a
        never-raises contract; the enabled bomb used to violate it."""
        self.plant(_notify_cfg({"channels": [_row(enabled=BoolBomb())]}))
        out = notify_channels.dispatch("t", "m", level="down", event=None)
        self.assertIsInstance(out, dict)
        r = self.client.post("/api/alerts/test")
        self.assert_not_500(r, "alerts test enabled bomb")


class JsonSafeScalarBombPins(_Notify6Sandbox):
    """Scalar / nested bombs in a stored config field: GET /api/alerts/channels
    used to 500 out of _json_safe's own probes.  The real data must render."""

    def _topic(self, value):
        self.plant(_notify_cfg({"channels": [_row(topic=value)]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        return rows["c1"]["config"].get("topic")

    def test_bytes_decode_bomb_value_still_decodes(self):
        self.assertEqual(self._topic(BytesDecodeBomb(b"x")), "x")

    def test_int_str_bomb_keeps_its_number(self):
        self.assertEqual(self._topic(IntStrBomb(9)), 9)

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        """Coercion cannot resurrect the unrenderable: past CPython's digit
        cap the value drops exactly like its plain-int sibling."""
        self.assertIsNone(self._topic(IntStrBomb(10 ** 5000)))

    def test_float_eq_bomb_keeps_its_value(self):
        self.assertEqual(self._topic(FloatEqBomb(1.5)), 1.5)

    def test_inf_wearing_the_eq_bomb_subclass_still_drops(self):
        self.assertIsNone(self._topic(FloatEqBomb(float("inf"))))

    def test_nested_items_bomb_is_read_through_the_base_view(self):
        self.assertEqual(self._topic(DictItemsBomb(a=1)), {"a": 1})

    def test_torn_pairs_items_reads_the_real_storage(self):
        self.assertEqual(self._topic(TriplesItems(real="kept")), {"real": "kept"})

    def test_list_iterbomb_value_keeps_its_elements(self):
        self.assertEqual(self._topic(ListIterBomb([1, "x"])), [1, "x"])

    def test_getattr_bomb_falls_back_to_text(self):
        self.assertIn("GetattrBomb", self._topic(GetattrBomb()))

    def test_isoformat_property_bomb_falls_back_to_text(self):
        self.assertIn("IsoPropertyBomb", self._topic(IsoPropertyBomb()))

    def test_name_bytes_decode_bomb_still_decodes(self):
        self.plant(_notify_cfg({"channels": [_row(name=BytesDecodeBomb(b"panel"))]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["name"], "panel")


class DispatchLegacyBombPins(_Notify6Sandbox):
    """__bool__ bombs in the legacy Home Assistant block used to raise out of
    _legacy_target inside dispatch() and 500 POST /api/alerts/test."""

    def test_legacy_enabled_bool_bomb_test_route_survives(self):
        self.plant(_notify_cfg({"enabled": BoolBomb(), "ha_token": "x"}))
        r = self.client.post("/api/alerts/test")
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assert_renderable(r)

    def test_legacy_token_bool_bomb_test_route_survives(self):
        self.plant(_notify_cfg({"ha_token": BoolBomb()}))
        r = self.client.post("/api/alerts/test")
        self.assert_not_500(r, "legacy token bomb")

    def test_dispatch_direct_call_never_raises_on_the_bombed_store(self):
        self.plant(_notify_cfg({
            "enabled": BoolBomb(),
            "ha_token": BoolBomb(),
            "channels": ListIterBomb([DictGetBomb(_row(enabled=BoolBomb()))]),
        }))
        out = notify_channels.dispatch("t", "m", level="warn", event=None)
        self.assertIsInstance(out, dict)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_effective_settings_survives_bomb_flags(self):
        """alerts.notify_settings' fallback used to eat the raise and
        silently drop every explicit channel from the alert gates."""
        raw = {"channels": [_row(enabled=BoolBomb(),
                                 notify_resolve=BoolBomb(),
                                 min_level=BoolBomb())]}
        out = notify_channels.effective_settings(raw)
        self.assertIsInstance(out, dict)


class EverythingBombedAtOncePins(_Notify6Sandbox):
    """All the shapes in one store: the combined state must not find a crack
    between the per-field guards."""

    def test_combined_bomb_store_every_route_survives(self):
        self.plant(_notify_cfg({
            "enabled": BoolBomb(),
            "ha_token": "x",
            "include_warn": BoolBomb(),
            "notify_resolve": BoolBomb(),
            "channels": ListIterBomb([
                DictGetBomb(_row(id=StrEqBomb("c1"), enabled=BoolBomb(),
                                 min_level=BoolBomb(),
                                 topic=DictItemsBomb(a=BytesDecodeBomb(b"v")),
                                 name=IntStrBomb(3))),
                DictKeysBomb(_row(id=123, topic=FloatEqBomb(2.5))),
                42,
                _row(id="ok1"),
            ]),
        }))
        self.sweep_channel_routes("combined")
        rows = {c["id"]: c for c in self.listed()}
        self.assertIn("c1", rows)
        self.assertIn("123", rows)
        self.assertIn("ok1", rows)
        self.assertEqual(rows["c1"]["config"]["topic"], {"a": "v"})
        self.assertEqual(rows["123"]["config"]["topic"], 2.5)


class StaysImmunePins(_Notify6Sandbox):
    """Vectors that were already dead — pinned so a refactor cannot reopen."""

    def test_keys_bomb_row_with_numeric_id_is_neutralized_by_the_copy(self):
        self.plant(_notify_cfg({"channels": [DictKeysBomb(_row(id=123))]}))
        rows = {c["id"]: c for c in self.listed()}
        # dict(row) copies through the C-level storage: the keys() override
        # never runs and the numeric id behaves as its string form.
        self.assertIn("123", rows)
        r = self.client.post("/api/alerts/channels/123/test")
        self.assertEqual(r.status_code, 200, r.text[:200])

    def test_int_str_bomb_id_keeps_its_number(self):
        self.plant(_notify_cfg({"channels": [_row(id=IntStrBomb(7))]}))
        # _id_text's broad catch never let this one 500; the base str()
        # renders the real number.
        self.assertIn("7", [c["id"] for c in self.listed()])

    def test_int_str_bomb_type_drops_the_row_not_the_route(self):
        self.plant(_notify_cfg({"channels": [_row(type=IntStrBomb(5)),
                                             _row(id="ok1")]}))
        ids = [c["id"] for c in self.listed()]
        self.assertNotIn("c1", ids)
        self.assertIn("ok1", ids)

    def test_str_hash_bomb_type_cannot_detonate_the_membership_probe(self):
        """``ctype in CHANNEL_TYPES`` hashes the key; exact-str coercion
        before the lookup keeps a __hash__ bomb subclass out of it."""
        self.plant(_notify_cfg({"channels": [_row(type=StrHashBomb("ntfy"))]}))
        self.sweep_channel_routes("hash-bomb type")
        self.assertIn("c1", [c["id"] for c in self.listed()])


if __name__ == "__main__":
    unittest.main()
