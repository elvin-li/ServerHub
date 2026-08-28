"""Bookmarks sweep #13: BaseException-shaped bombs and the claimed-base decode gap.

A fresh route-level hunt after the sweep-#12 default-repr seal found two
leftover classes still live on GET /api/bookmarks (driven end to end via
``create_app()`` + ``TestClient(raise_server_exceptions=False)``) — the
assistant13/jobs13/nas13 families, live on this surface too:

* **BaseException past every net.**  Every guard in ``hub.bookmarks_svc``
  stopped at ``except Exception``, so a leftover whose hooks raise a
  *BaseException* subclass (the watchdog/timeout shape) sailed past every
  catch at once and 500'd the route raw: a ``__class__``-property bomb blew
  ``_isinst`` — the gate every sanitizer arm stands on; ``__bool__`` /
  ``__str__`` / ``__index__`` bombs blew ``_truthy``, ``_utf8_text``,
  ``_key_text`` and ``_jsonable``; a stored shadow key blew ``_mapping_get``
  and ``_cfg_get``; a row bombing ``resolve_value``'s walk escaped the
  absorbing nets on the request thread; a collector bombing the pool thread
  re-raised verbatim at ``f_idx.result()`` past its Exception-only net; and
  one bomb url raising out of ``_probe``'s seams cost the whole fan_out
  batch after every healthy sibling's probe had already succeeded.

* **The claimed-base decode gap.**  ``_decode_bytes`` picked its base off
  the *claimed* ``__class__``, so a genuine ``bytearray`` lying ``bytes``
  was handed to ``bytes.decode``, refused by the descriptor, and its
  perfectly decodable content dropped to the empty cell.

Sealed the assistant13 way: every guard re-raises genuine control flow
(KeyboardInterrupt, SystemExit) and launders everything else
BaseException-shaped exactly like its Exception twin; the decode arm tries
both bases, real layout first-come, then falls back to really-str storage.
The pinned union guards are kept intact: ``resolve_value`` stays
raise-on-junk (only the absorbing nets widened), and the digit-cap
``except ValueError`` probes in ``_key_text`` / ``_jsonable`` stay exactly
that narrow — the operand is an exact int by then.

A 500 is the leak; a 200 with the bomb cell degraded and every healthy
sibling kept is the pass.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc


class Boom(BaseException):
    """Not an Exception: the shape that sailed past every old net."""


class ClassBomb:
    """``__class__`` is a raising property — blows every ``isinstance``."""

    @property
    def __class__(self):
        raise Boom("class bomb")


class BoolBomb:
    def __bool__(self):
        raise Boom("bool bomb")


class StrBomb:
    def __str__(self):
        raise Boom("str bomb")


class IndexBombInt(int):
    def __index__(self):
        raise Boom("index bomb")


class BoomItemsDict(dict):
    """Trips ``resolve_value``'s walk with a BaseException subclass."""

    def items(self):
        raise Boom("items bomb")


class ExcItemsDict(dict):
    """Exception-shaped sibling bomb: keeps the whole list raw (bookmarks5)."""

    def items(self):
        raise RuntimeError("items bomb")


class ShadowKey(str):
    """Hash-shadowing key: hashes like the real key, ``__eq__`` raises Boom."""

    def __eq__(self, other):
        raise Boom("shadow eq bomb")

    __hash__ = str.__hash__


class IsoBomb:
    def isoformat(self):
        raise Boom("iso bomb")


class GetattrBomb:
    def __getattr__(self, name):
        raise Boom("getattr bomb")


class IterBombList(list):
    def __iter__(self):
        raise Boom("iter bomb")


class FindBombStr(str):
    """A url whose ``find`` bombs urlsplit inside ``_probe``'s own try."""

    def find(self, *a, **k):
        raise Boom("find bomb")


class LyingBytes(bytearray):
    """Genuine bytearray storage; ``__class__`` claims bytes."""

    @property
    def __class__(self):
        return bytes


class StrLyingBytes(str):
    """Real str storage; ``__class__`` claims bytes — text must recover."""

    @property
    def __class__(self):
        return bytes


class TotalLiar:
    """Claims bytes, holds neither buffer nor str storage — junk drops."""

    @property
    def __class__(self):
        return bytes


class Interrupter:
    """Genuine control flow must keep propagating through every guard."""

    @property
    def __class__(self):
        raise KeyboardInterrupt

    def __bool__(self):
        raise KeyboardInterrupt

    def __str__(self):
        raise KeyboardInterrupt


def _probe_ok(url, timeout: float = 3.0) -> dict:
    return {"ok": True, "status": 200, "ms": 1, "error": None}


_GOOD = {"name": "good", "url": "http://good.lan"}


class _HttpPinBase(unittest.TestCase):
    """Shared client + cache hygiene for the real-route pins."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def _client(self):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _get(self, cfg_value, idx: dict | None = None):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch.object(bookmarks_svc, "_backend_index",
                              return_value=idx or {}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})

    def _assert_ok(self, resp):
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return resp.json()

    def _by_url(self, body) -> dict:
        return {r["url"]: r for r in body["bookmarks"]}


class LinkBombHttpPins(_HttpPinBase):
    """BaseException bombs riding link rows must degrade, not 500."""

    def test_class_bomb_name_answers_200_siblings_kept(self):
        body = self._assert_ok(self._get({
            "quick_links": [{"name": ClassBomb(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["name"], "")
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_bool_bomb_url_row_drops_alone(self):
        body = self._assert_ok(self._get({
            "quick_links": [{"name": "a", "url": BoolBomb()}, dict(_GOOD)],
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_str_bomb_name_degrades_to_empty(self):
        body = self._assert_ok(self._get({
            "quick_links": [{"name": StrBomb(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["name"], "")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_boom_items_row_survives_plain_copy(self):
        """resolve_value stays raise-on-junk; the widened absorb keeps the row."""
        body = self._assert_ok(self._get({
            "quick_links": [BoomItemsDict(name="a", url="http://a.lan"),
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_shadow_url_key_in_raw_kept_row_degrades(self):
        """An Exception sibling keeps the list raw; the Boom shadow key must
        cost only its own field, not the route."""
        body = self._assert_ok(self._get({
            "quick_links": [{ShadowKey("url"): "http://a.lan", "name": "a"},
                            ExcItemsDict(url="http://b.lan"),
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://b.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class ConfigSeamHttpPins(_HttpPinBase):
    """BaseException bombs at the config seam must degrade, not 500."""

    def test_cfg_raising_boom_answers_200_empty(self):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg",
                              side_effect=Boom("cfg bomb")),
            mock.patch.object(bookmarks_svc, "_backend_index",
                              return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        body = self._assert_ok(resp)
        self.assertEqual(body["bookmarks"], [])

    def test_boom_shadow_quick_links_answers_200_empty(self):
        body = self._assert_ok(self._get({
            ShadowKey("quick_links"): [dict(_GOOD)], "overrides": {}}))
        self.assertEqual(body["bookmarks"], [])

    def test_boom_shadow_overrides_keeps_quick_links(self):
        body = self._assert_ok(self._get({
            "quick_links": [dict(_GOOD)],
            ShadowKey("overrides"): {"o": {"url": "http://o.lan"}}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_boom_override_row_drops_alone(self):
        body = self._assert_ok(self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"bad": BoomItemsDict(url="http://bad.lan"),
                          "ok": {"url": "http://ov.lan"}}}))
        by_url = self._by_url(body)
        self.assertIn("http://ov.lan", by_url)
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class BackendSeamHttpPins(_HttpPinBase):
    """BaseException bombs off the inventory pool must degrade, not 500."""

    def test_collector_boom_answers_200_links_kept(self):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value={
                "quick_links": [dict(_GOOD)], "overrides": {}}),
            mock.patch("hub.vms_svc.list_utm_vms",
                       side_effect=Boom("collector bomb")),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[
                {"id": "svc", "name": "svc", "state": "stopped",
                 "status": "stopped"}]),
            mock.patch("hub.discovery.containers.discover_containers",
                       return_value=([], None)),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        body = self._assert_ok(resp)
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_backend_index_boom_at_result_answers_200(self):
        """``Future.result()`` re-raises verbatim — the widened net absorbs."""
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value={
                "quick_links": [dict(_GOOD)], "overrides": {}}),
            mock.patch.object(bookmarks_svc, "_backend_index",
                              side_effect=Boom("index bomb")),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        body = self._assert_ok(resp)
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_boom_backend_row_drops_alone(self):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value={
                "quick_links": [{"name": "a", "url": "http://a.lan",
                                 "service": "svc"}, dict(_GOOD)],
                "overrides": {}}),
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[
                {ShadowKey("state"): "x", "id": BoolBomb()},
                {"id": "svc", "name": "svc", "state": "stopped",
                 "status": "stopped"}]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch("hub.discovery.containers.discover_containers",
                       return_value=([], None)),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        body = self._assert_ok(resp)
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class ProbeSeamUnitPins(unittest.TestCase):
    """A bomb inside ``_probe``'s own seams degrades to the error row."""

    def test_find_bomb_url_answers_error_row(self):
        out = bookmarks_svc._probe(FindBombStr("http://a.lan"))
        self.assertIs(out["ok"], False)
        self.assertIsNone(out["status"])

    def test_probe_ms_boom_reads_zero(self):
        class RsubBomb:
            def __rsub__(self, other):
                raise Boom("clock bomb")

        self.assertEqual(bookmarks_svc._probe_ms(RsubBomb()), 0)


class DecodeGapUnitPins(unittest.TestCase):
    """Both bases, real layout first-come; really-str storage recovers."""

    def test_real_bytearray_lying_bytes_decodes(self):
        self.assertEqual(bookmarks_svc._decode_bytes(LyingBytes(b"real-text")),
                         "real-text")

    def test_real_str_lying_bytes_recovers_text(self):
        self.assertEqual(bookmarks_svc._decode_bytes(StrLyingBytes("keep")),
                         "keep")

    def test_total_liar_drops_to_empty(self):
        self.assertEqual(bookmarks_svc._decode_bytes(TotalLiar()), "")

    def test_utf8_text_routes_lying_bytearray_through(self):
        self.assertEqual(bookmarks_svc._utf8_text(LyingBytes(b"real-text")),
                         "real-text")

    def test_exact_bytes_still_decode(self):
        self.assertEqual(bookmarks_svc._decode_bytes(b"a\xffb"), "a\ufffdb")


class GuardUnitPins(unittest.TestCase):
    """Each widened guard launders Boom exactly like its Exception twin."""

    def test_isinst_class_bomb_is_false(self):
        self.assertFalse(bookmarks_svc._isinst(ClassBomb(), str))

    def test_truthy_bool_bomb_is_false(self):
        self.assertFalse(bookmarks_svc._truthy(BoolBomb()))

    def test_utf8_text_str_bomb_is_empty(self):
        self.assertEqual(bookmarks_svc._utf8_text(StrBomb()), "")

    def test_key_text_index_bomb_reads_storage(self):
        """Unbound ``int.__index__`` reads C-level storage past the bomb."""
        self.assertEqual(bookmarks_svc._key_text(IndexBombInt(5)), "5")

    def test_mapping_get_boom_shadow_key_defaults(self):
        row = {ShadowKey("url"): "http://a.lan", "name": "a"}
        self.assertIsNone(bookmarks_svc._mapping_get(row, "url"))
        self.assertEqual(bookmarks_svc._mapping_get(row, "name"), "a")

    def test_cfg_get_boom_shadow_sibling_still_reads(self):
        with mock.patch.object(bookmarks_svc, "cfg", return_value={
                ShadowKey("overrides"): {"x": 1}, "quick_links": [1]}):
            self.assertEqual(bookmarks_svc._cfg_get("quick_links"), [1])

    def test_jsonable_iso_bomb_drops_alone(self):
        out = bookmarks_svc._jsonable({"good": "yes", "bad": IsoBomb()})
        self.assertEqual(out["good"], "yes")

    def test_jsonable_getattr_bomb_drops_alone(self):
        out = bookmarks_svc._jsonable({"good": "yes", "bad": GetattrBomb()})
        self.assertEqual(out["good"], "yes")

    def test_jsonable_iter_bomb_list_drops_alone(self):
        out = bookmarks_svc._jsonable({"good": "yes",
                                       "bad": IterBombList([1, 2])})
        self.assertEqual(out["good"], "yes")
        self.assertIsNone(out["bad"])

    def test_jsonable_digit_cap_probe_stays_valueerror_only(self):
        """The pinned union guard: an over-cap exact int still drops clean."""
        big = int("f" * 5000, 16)
        self.assertIsNone(bookmarks_svc._jsonable(big))
        self.assertEqual(bookmarks_svc._jsonable(42), 42)


class ControlFlowStaysUnitPins(unittest.TestCase):
    """Genuine control flow must keep propagating through every guard."""

    def test_isinst_reraises_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            bookmarks_svc._isinst(Interrupter(), str)

    def test_truthy_reraises_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            bookmarks_svc._truthy(Interrupter())

    def test_utf8_text_reraises_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            bookmarks_svc._utf8_text(Interrupter())


if __name__ == "__main__":
    unittest.main()
