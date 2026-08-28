"""Thirteenth Notify-domain leftover sweep: lying-``__class__`` wrong-rank
degrades, mid-walk mutation tears, and default-repr heap-address leaks,
over the real app.

``isinstance`` consults ``value.__class__`` only after the real-MRO check
misses, so a lying ``__class__`` steered a stored channel value into the
arm of its *claim*, the unbound descriptor there rejected the real layout,
and the early return threw away honest renderable storage — degrade at
the wrong rank (the logs13/audit13 shape, one wave after notify12 sealed
the claimed-base pick inside ``_decode_bytes`` itself).  Driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` with the
hostile store planted as the live ``cfg()`` snapshot, HEAD showed:

* a genuine bytes / int / date id claiming ``str`` hit ``_id_text``'s str
  arm, ``str.__str__`` refused the real layout, and the whole row silently
  unlisted — invisible to GET /api/alerts/channels and unreachable by
  PUT/DELETE/test — although ``b"chan1"`` / ``123`` render perfectly;
* a genuine str name / topic / min_level claiming ``bytes`` entered
  ``_utf8_text``'s decode arm, both base decodes rejected the str layout,
  and the honest text vanished to ``""`` — the name fell back to the id,
  the topic rendered empty, and a ``min_level: "down"`` degraded to
  "warn", silently widening what the channel gets notified about;
* a genuine int port claiming ``float``, a genuine tuple recipient list
  claiming ``list`` and a genuine list claiming ``dict`` each dropped to
  None out of ``_json_safe``'s claimed arms;
* ``_json_safe`` iterated the *live* ``dict.items`` view, so a nested
  value's ``__class__`` property that resized its parent mapping mid-walk
  raised RuntimeError ("dictionary changed size during iteration")
  straight out of the sanitizer — a raw 500 on GET /api/alerts/channels;
* ``channels()`` walked the *live* cfg rows list, so a bomb id's hook
  that popped rows mid-walk silently unlisted every honest sibling;
* ``_id_text`` / ``_utf8_text`` coerced a type that never overrode
  ``__str__``/``__repr__`` through ``str()``, rendering the default
  ``object.__repr__`` — ``<X object at 0x7f…>``, a raw heap address —
  verbatim into channel ids, names and config cells on the wire;
* an id whose ``__str__`` manufactured an ``__eq__``-bomb str *subclass*
  broke ``_id_text``'s exact-str promise, and every later ``== cid``
  (get_channel behind POST/PUT/DELETE/test) detonated the stored
  comparison — a raw 500 on four routes at once.

Fixes, the established conventions: the failure paths fall through to the
arm the real storage matches (``_decode_bytes_or_none`` distinguishes a
legitimate empty decode from a both-bases rejection), ``list(...)``
snapshots both walks before any leftover hook runs, the bookmarks/
assistant slot-probe + ``_ADDR_REPR_RE`` belt scrub only the free-text
coercion arms, ``_id_text`` launders its tail to an exact str, and every
new path keeps the BaseException union guards with the ``_CONTROL_FLOW``
re-raise.  Total impostors — a claim with no renderable layout underneath
— keep their earlier drop shapes.
"""
from __future__ import annotations

import datetime
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


class LyingStrBytes(bytes):
    """Genuine bytes storage whose ``__class__`` claims ``str``."""

    @property
    def __class__(self):  # noqa: D105
        return str


class LyingStrBytearray(bytearray):
    """Genuine bytearray storage whose ``__class__`` claims ``str``."""

    @property
    def __class__(self):  # noqa: D105
        return str


class LyingStrInt(int):
    """Genuine int storage whose ``__class__`` claims ``str``."""

    @property
    def __class__(self):  # noqa: D105
        return str


class LyingStrDate(datetime.date):
    """Genuine date storage whose ``__class__`` claims ``str``."""

    @property
    def __class__(self):  # noqa: D105
        return str


class LyingBytesStr(str):
    """Genuine str storage whose ``__class__`` claims ``bytes``."""

    @property
    def __class__(self):  # noqa: D105
        return bytes


class LyingFloatInt(int):
    """Genuine int storage whose ``__class__`` claims ``float``."""

    @property
    def __class__(self):  # noqa: D105
        return float


class LyingListTuple(tuple):
    """Genuine tuple storage whose ``__class__`` claims ``list``."""

    @property
    def __class__(self):  # noqa: D105
        return list


class LyingDictList(list):
    """Genuine list storage whose ``__class__`` claims ``dict``."""

    @property
    def __class__(self):  # noqa: D105
        return dict


class TotalStrImpostor:
    """Claims str, carries no renderable layout at all."""

    @property
    def __class__(self):  # noqa: D105
        return str


class TotalDictImpostor:
    @property
    def __class__(self):  # noqa: D105
        return dict


class TotalListImpostor:
    @property
    def __class__(self):  # noqa: D105
        return list


class TotalBytesImpostor:
    @property
    def __class__(self):  # noqa: D105
        return bytes


class PlainJunk:
    """Never overrode ``__str__``/``__repr__``: str() answers a heap address."""


class EqBombStr(str):
    """str subclass whose ``__eq__`` raises — poison for every ``== cid``."""

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover eq bomb")

    __ne__ = __eq__


class ReprStrBomb:
    """An id whose ``__str__`` manufactures the ``__eq__``-bomb subclass."""

    def __str__(self):  # noqa: D105
        return EqBombStr("c9")


class CtrlCClassProp:
    @property
    def __class__(self):  # noqa: D105
        raise KeyboardInterrupt


class CtrlCStr:
    def __str__(self):  # noqa: D105
        raise KeyboardInterrupt


def _row(**kw):
    base = {"id": "c1", "type": "ntfy", "topic": "t"}
    base.update(kw)
    return base


def _notify_cfg(notify) -> dict:
    return {"settings": {"notify": notify}}


def _stub_sender(*_a, **_k) -> dict:
    return {"ok": True, "message": "sent"}


class _Notify13Sandbox(unittest.TestCase):
    """Scratch state dirs, offline senders, and a hostile live cfg() snapshot."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-notify13-")
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
        # Never a network send: the stubbed types cover every row these
        # suites plant (email included — its rows here are GET-side only,
        # but the per-channel test button must stay offline too).
        senders = mock.patch.dict(
            notify_channels._SENDERS,
            {"ntfy": _stub_sender, "email": _stub_sender,
             "home_assistant": _stub_sender},
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
        parsed = resp.json()
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return parsed

    def assert_not_500(self, resp, label: str = ""):
        self.assertNotEqual(resp.status_code, 500, f"{label}: {resp.text[:200]}")
        return self.assert_renderable(resp)

    _CREATE = {"type": "ntfy", "id": "px", "config": {"topic": "t"}, "secrets": {}}
    _PUT = {"type": "ntfy", "config": {"topic": "u"}, "secrets": {}}

    def sweep_channel_routes(self, label: str, cid: str = "c1") -> None:
        self.assert_not_500(self.client.get("/api/alerts/channels"),
                            f"{label} GET channels")
        self.assert_not_500(
            self.client.post("/api/alerts/channels", json=self._CREATE),
            f"{label} POST create",
        )
        self.assert_not_500(
            self.client.put(f"/api/alerts/channels/{cid}", json=self._PUT),
            f"{label} PUT",
        )
        self.assert_not_500(self.client.post(f"/api/alerts/channels/{cid}/test"),
                            f"{label} per-channel test")
        self.assert_not_500(self.client.delete(f"/api/alerts/channels/{cid}"),
                            f"{label} DELETE")
        self.assert_not_500(self.client.post("/api/alerts/test"),
                            f"{label} POST alerts test")

    def assert_dispatch_contract(self, label: str, **kw) -> dict:
        try:
            out = notify_channels.dispatch(
                "t", "m", **({"level": "down", "event": None} | kw))
        except BaseException as exc:  # pragma: no cover - the pre-fix failure
            self.fail(f"{label}: dispatch raised {exc!r}")
        self.assertIsInstance(out, dict)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return out

    def listed(self) -> list:
        body = self.assert_not_500(self.client.get("/api/alerts/channels"))
        return body["channels"]


class WrongRankIdRecoveryPins(_Notify13Sandbox):
    """Honest id storage behind a lying ``str`` claim keeps its row listed
    and reachable — HEAD silently unlisted it (the wrong-rank degrade)."""

    def test_bytes_id_claiming_str_lists_and_stays_reachable(self):
        self.plant(_notify_cfg({"channels": [
            _row(id=LyingStrBytes(b"bch")), _row(id="ok1")]}))
        ids = [c["id"] for c in self.listed()]
        self.assertIn("bch", ids)
        self.assertIn("ok1", ids)
        r = self.assert_not_500(self.client.post("/api/alerts/channels/bch/test"),
                                "bytes-claiming-str per-channel test")
        self.assertTrue(r.get("ok"), r)
        self.sweep_channel_routes("bytes-claiming-str id", cid="bch")
        self.assert_dispatch_contract("bytes-claiming-str id")

    def test_bytearray_id_claiming_str_decodes_through_the_real_base(self):
        self.plant(_notify_cfg({"channels": [
            _row(id=LyingStrBytearray(b"ach"))]}))
        self.assertIn("ach", [c["id"] for c in self.listed()])

    def test_int_and_date_ids_claiming_str_keep_their_rendering(self):
        self.plant(_notify_cfg({"channels": [
            _row(id=LyingStrInt(123)),
            _row(id=LyingStrDate(2026, 8, 28), topic="u")]}))
        ids = [c["id"] for c in self.listed()]
        self.assertIn("123", ids)
        self.assertIn("2026-08-28", ids)
        for cid in ids:
            self.assertIs(type(cid), str)
        r = self.assert_not_500(self.client.post("/api/alerts/channels/123/test"),
                                "int-claiming-str per-channel test")
        self.assertTrue(r.get("ok"), r)

    def test_total_str_impostor_id_still_drops_the_row_alone(self):
        # A claim with no renderable layout underneath keeps the old drop:
        # recovery must never resurrect junk (and never leak its repr).
        self.plant(_notify_cfg({"channels": [
            _row(id=TotalStrImpostor()), _row(id="ok1")]}))
        self.assertEqual([c["id"] for c in self.listed()], ["ok1"])
        self.sweep_channel_routes("total str impostor id", cid="ok1")


class WrongRankTextRecoveryPins(_Notify13Sandbox):
    """Honest str storage behind a lying ``bytes`` claim keeps its text."""

    def test_name_topic_min_level_claiming_bytes_render_real_text(self):
        self.plant(_notify_cfg({"channels": [
            _row(name=LyingBytesStr("Real Name"),
                 topic=LyingBytesStr("real-topic"),
                 min_level=LyingBytesStr("down"))]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["name"], "Real Name")
        self.assertEqual(rows["c1"]["config"]["topic"], "real-topic")
        self.assertEqual(rows["c1"]["min_level"], "down")
        self.sweep_channel_routes("str-claiming-bytes fields")

    def test_min_level_claiming_bytes_keeps_its_routing_rank(self):
        # HEAD degraded the honest "down" to the "warn" default — silently
        # widening what the channel gets notified about.  A warn-level
        # dispatch must not match; a down-level one must.
        self.plant(_notify_cfg({"channels": [
            _row(min_level=LyingBytesStr("down"), enabled=True)]}))
        out = self.assert_dispatch_contract("min_level rank warn", level="warn")
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("results"), [])
        out = self.assert_dispatch_contract("min_level rank down", level="down")
        self.assertTrue(out.get("ok"), out)
        self.assertEqual(out.get("sent"), 1)

    def test_total_bytes_impostor_field_keeps_the_old_empty_degrade(self):
        self.plant(_notify_cfg({"channels": [
            _row(topic=TotalBytesImpostor())]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"].get("topic"), "")


class WrongRankConfigValuePins(_Notify13Sandbox):
    """Claimed numeric / container arms recover the real storage."""

    def test_port_claiming_float_keeps_its_number(self):
        self.plant(_notify_cfg({"channels": [
            _row(id="m1", type="email", host="smtp.example.com",
                 to="a@b.c", port=LyingFloatInt(587))]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["m1"]["config"].get("port"), 587)

    def test_recipient_tuple_claiming_list_keeps_its_elements(self):
        self.plant(_notify_cfg({"channels": [
            _row(id="m1", type="email", host="smtp.example.com",
                 to=LyingListTuple(("a@b.c", "d@e.f")))]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["m1"]["config"].get("to"), ["a@b.c", "d@e.f"])

    def test_list_claiming_dict_keeps_its_elements(self):
        self.plant(_notify_cfg({"channels": [
            _row(topic=LyingDictList(["x", "y"]))]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"].get("topic"), ["x", "y"])

    def test_total_container_impostors_keep_their_old_none_degrade(self):
        self.plant(_notify_cfg({"channels": [
            _row(topic=[TotalDictImpostor(), TotalListImpostor(), "ok"])]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"]["topic"], [None, None, "ok"])


class MidWalkMutationPins(_Notify13Sandbox):
    """A leftover hook resizing its parent container mid-walk cannot tear
    the sanitizer's iteration — HEAD 500'd or silently unlisted siblings."""

    @staticmethod
    def _mutating_mapping() -> dict:
        d = {}

        class Mutator:
            @property
            def __class__(self):  # noqa: D105
                if "planted" in d:
                    del d["planted"]
                return type(self)

            def __str__(self):  # noqa: D105
                return "mut"

        d["a"] = Mutator()
        d["planted"] = 1
        d["sane"] = 2
        return d

    def test_nested_mapping_resize_cannot_500_the_listing(self):
        # HEAD: _json_safe iterated the live dict.items view; the hook's
        # delete raised RuntimeError out of GET /api/alerts/channels raw.
        self.plant(_notify_cfg({"channels": [
            _row(topic=self._mutating_mapping())]}))
        rows = {c["id"]: c for c in self.listed()}
        self.assertEqual(rows["c1"]["config"]["topic"].get("sane"), 2)
        self.sweep_channel_routes("mid-walk mapping resize")

    def test_row_pop_mid_walk_cannot_unlist_honest_siblings(self):
        # HEAD: channels() walked the live cfg rows list, the bomb id's
        # hook popped the tail, and every honest sibling behind it — and
        # the bomb row itself, through the wrong-rank str arm — vanished
        # from all six routes at once.
        rows = []

        class PopIdBomb:
            @property
            def __class__(self):  # noqa: D105
                while len(rows) > 1:
                    rows.pop()
                return str

            def __str__(self):  # noqa: D105
                return "m1"

        rows.append(_row(id=PopIdBomb()))
        rows.append(_row(id="ok1"))
        self.plant(_notify_cfg({"channels": rows}))
        listed = [c["id"] for c in self.listed()]
        self.assertIn("ok1", listed)
        self.assertIn("m1", listed)
        self.assert_dispatch_contract("mid-walk row pop")


class HeapAddressLeakPins(_Notify13Sandbox):
    """Default ``object.__repr__`` output — a raw heap address — must never
    reach the wire through id / name / config coercion."""

    def test_plain_junk_never_leaks_an_address_on_the_listing(self):
        self.plant(_notify_cfg({"channels": [
            _row(id=PlainJunk()),
            _row(id="ok1", name=PlainJunk(), topic=PlainJunk())]}))
        resp = self.client.get("/api/alerts/channels")
        self.assert_not_500(resp, "plain junk listing")
        self.assertNotIn(" at 0x", resp.text)
        ids = [c["id"] for c in self.listed()]
        # The junk id holds no renderable layout: its row drops alone.
        self.assertEqual(ids, ["ok1"])

    def test_plain_junk_never_leaks_an_address_through_dispatch(self):
        self.plant(_notify_cfg({"channels": [
            _row(id="ok1", topic=PlainJunk(), enabled=True)]}))
        resp = self.client.post("/api/alerts/test")
        self.assert_not_500(resp, "plain junk global test")
        self.assertNotIn(" at 0x", resp.text)
        out = self.assert_dispatch_contract("plain junk dispatch")
        self.assertNotIn(" at 0x", json.dumps(out))


class ExactStrIdPromisePins(_Notify13Sandbox):
    """An id coercion answering an ``__eq__``-bomb str subclass cannot
    detonate the ``== cid`` comparisons behind POST/PUT/DELETE/test."""

    def test_eq_bomb_str_subclass_id_cannot_500_the_lookup_routes(self):
        self.plant(_notify_cfg({"channels": [
            _row(id=ReprStrBomb()), _row(id="ok1")]}))
        # HEAD: get_channel's ``ch.get("id") == cid`` raised the stored
        # subclass's __eq__ — POST create, PUT, DELETE and both test
        # routes 500'd raw at once.
        self.sweep_channel_routes("eq-bomb str-subclass id", cid="c9")
        ids = [c["id"] for c in self.listed()]
        self.assertIn("c9", ids)
        for cid in ids:
            self.assertIs(type(cid), str)
        r = self.assert_not_500(self.client.post("/api/alerts/channels/c9/test"),
                                "eq-bomb id per-channel test")
        self.assertTrue(r.get("ok"), r)
        self.assert_dispatch_contract("eq-bomb str-subclass id")


class ControlFlowPassthroughPins(unittest.TestCase):
    """Genuine control flow keeps propagating through every new path."""

    def test_new_arms_reraise_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._id_text(CtrlCStr())
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._utf8_text(CtrlCStr())
        with self.assertRaises(KeyboardInterrupt):
            notify_channels._json_safe({"k": CtrlCClassProp()})
        with self.assertRaises(KeyboardInterrupt):
            notify_channels.channels({"channels": [
                {"id": CtrlCClassProp(), "type": "ntfy"}]})


class EverythingAtOncePins(_Notify13Sandbox):
    """All the thirteenth-wave shapes in one store: no crack between arms."""

    def test_combined_store_recovers_and_survives(self):
        self.plant(_notify_cfg({"channels": [
            _row(id=LyingStrBytes(b"bch"),
                 name=LyingBytesStr("Real Name"),
                 topic=self._combined_topic(),
                 min_level=LyingBytesStr("down")),
            _row(id=PlainJunk()),
            _row(id=ReprStrBomb(), topic="u"),
            _row(id="ok1"),
        ]}))
        resp = self.client.get("/api/alerts/channels")
        body = self.assert_not_500(resp, "combined listing")
        self.assertNotIn(" at 0x", resp.text)
        rows = {c["id"]: c for c in body["channels"]}
        self.assertIn("ok1", rows)
        self.assertIn("c9", rows)
        self.assertEqual(rows["bch"]["name"], "Real Name")
        self.assertEqual(rows["bch"]["min_level"], "down")
        self.assertEqual(rows["bch"]["config"]["topic"].get("sane"), 2)
        self.sweep_channel_routes("combined", cid="bch")
        self.assert_dispatch_contract("combined")

    @staticmethod
    def _combined_topic() -> dict:
        return MidWalkMutationPins._mutating_mapping()


if __name__ == "__main__":
    unittest.main(verbosity=2)
