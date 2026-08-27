"""Bookmarks sweep #9: leftover ``__class__`` impostors that survive the type
gate and then 500 the JSON encode, plus the ``allow_nan=False`` bool-liar.

Sweep #8 routed every ``isinstance`` gate through :func:`hub.bookmarks_svc.
_isinst`, so a *raising* ``__class__`` property can no longer 500 a gate.  But
``_isinst`` deliberately reports a *lying* ``__class__`` at face value (a value
that answers ``int`` is admitted to the numeric arm, which then coerces or
drops it).  That left two leftovers where a liar is admitted past the gate and
then blows an *unbound base op* or the response encoder, both outside a try, on
GET /api/bookmarks:

* a value whose ``__class__`` answers ``bytes`` / ``bytearray`` without the
  matching C-level buffer reaches ``_jsonable``'s bytes branch, and
  ``_decode_bytes`` calls ``bytes.decode(value)`` — the unbound base has no
  buffer to read and raises ``TypeError``.  A link ``name`` / ``id`` /
  ``service`` (or a backend row field) that is such an impostor 500'd the
  route at encode time even though the row's url was fine.  Fixed by guarding
  ``_decode_bytes`` to fall back to ``""``.

* a value whose ``__class__`` answers ``bool`` is admitted by ``_isinst(...,
  bool)`` and, pre-fix, ``_jsonable`` returned it unchanged — but ``bool`` is
  final, so an admitted non-``bool`` is an impostor, and Starlette's
  ``allow_nan=False`` encoder cannot serialise it and 500'd the route.  Fixed
  by returning the value only when ``type(value) is bool`` and dropping the
  impostor to ``None`` otherwise (the lying-int treatment).

Every HTTP pin drives ``create_app()`` + ``TestClient(raise_server_exceptions=
False)``: a raw 500 is a leftover; a 200 list with the impostor degraded and
every healthy sibling kept is the pass.  The remaining classes named in the
sweep brief — hash-shadowing / unhashable / hash-bomb urls, a str-subclass
``__eq__`` bomb, and dict-subclass ``.get`` / ``.items`` / ``__bool__`` row
bombs — were probed and already immune; they are pinned here so they stay so.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc


class BytesLiar:
    """``__class__`` answers ``bytes`` but there is no C-level buffer.

    ``_isinst(x, (bytes, bytearray))`` reports True (not an error); the unbound
    ``bytes.decode(x)`` in ``_decode_bytes`` then has nothing to read.
    """

    @property
    def __class__(self):
        return bytes


class ByteArrayLiar:
    @property
    def __class__(self):
        return bytearray


class BoolLiar:
    """``__class__`` answers ``bool`` but the value is not a real bool."""

    @property
    def __class__(self):
        return bool


class EqBombStr(str):
    """A str subclass whose ``==`` raises — asked first even on the right."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = str.__hash__


class UnhashableStr(str):
    """A str subclass that is unhashable — the classic membership leftover."""

    __hash__ = None


class HashBombStr(str):
    """A str subclass whose ``__hash__`` raises."""

    def __hash__(self):
        raise RuntimeError("hash bomb")


class GetBombDict(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


class BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb")


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

    def _get(self, cfg_value: dict, idx: dict | None = None):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch.object(bookmarks_svc, "_backend_index",
                              return_value=idx or {}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})


class LiarEncodeHttpPins(_HttpPinBase):
    """The two live 500s, pinned end to end on the real route."""

    def test_bytes_liar_name_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": BytesLiar(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://a.lan"]["name"], "")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_bytearray_liar_id_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "id": ByteArrayLiar()}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_bytes_liar_backend_name_answers_200(self):
        idx = {"svc": {"state": "up", "kind": "vm",
                       "name": BytesLiar(), "id": "svc"}}
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=idx)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_bool_liar_name_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": BoolLiar(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertIsNone(by_url["http://a.lan"]["name"])
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_bool_liar_service_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": BoolLiar()}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_bool_liar_backend_id_answers_200(self):
        idx = {"svc": {"state": "up", "kind": "vm",
                       "name": "svc", "id": BoolLiar()}}
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=idx)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_bytes_liar_url_drops_alone(self):
        """A bytes-liar url is not an exact-str url: the row drops, the
        healthy sibling is kept, and the route still answers 200."""
        resp = self._get({
            "quick_links": [{"name": "a", "url": BytesLiar()}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(urls, ["http://good.lan"])


class LiarEncodeStaysImmuneHttpPins(_HttpPinBase):
    """Vectors already immune before this sweep — pinned so they stay that way."""

    def test_eq_bomb_link_url_stays_200(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": EqBombStr("http://a.lan")},
                            dict(_GOOD)],
            "overrides": {"o": {"url": "http://a.lan", "name": "O"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_unhashable_str_url_stays_200(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": UnhashableStr("http://a.lan")},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_hash_bomb_url_stays_200(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": HashBombStr("http://a.lan")},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_get_bomb_row_stays_200(self):
        resp = self._get({
            "quick_links": [GetBombDict({"name": "a", "url": "http://a.lan"}),
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_items_bomb_overrides_stays_200(self):
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": ItemsBombDict({"o": {"url": "http://o.lan",
                                              "name": "O"}})})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_bool_bomb_row_stays_200(self):
        resp = self._get({
            "quick_links": [BoolBombDict({"name": "a", "url": "http://a.lan"}),
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class DecodeBytesUnitPins(unittest.TestCase):
    """``_decode_bytes`` on a lying ``__class__`` does not raise."""

    def test_bytes_liar_returns_empty(self):
        self.assertEqual(bookmarks_svc._decode_bytes(BytesLiar()), "")

    def test_bytearray_liar_returns_empty(self):
        self.assertEqual(bookmarks_svc._decode_bytes(ByteArrayLiar()), "")

    def test_real_bytes_still_decode(self):
        self.assertEqual(bookmarks_svc._decode_bytes(b"hi"), "hi")

    def test_real_bytes_subclass_decode_bomb_survives(self):
        class DecodeBomb(bytes):
            def decode(self, *a, **k):
                raise RuntimeError("decode bomb")

        self.assertEqual(bookmarks_svc._decode_bytes(DecodeBomb(b"hi")), "hi")


class JsonableLiarUnitPins(unittest.TestCase):
    """``_jsonable`` drops the impostors instead of raising / leaking them."""

    def test_bytes_liar_leaf_is_empty_str(self):
        self.assertEqual(bookmarks_svc._jsonable(BytesLiar()), "")

    def test_bool_liar_leaf_is_dropped(self):
        self.assertIsNone(bookmarks_svc._jsonable(BoolLiar()))

    def test_real_bool_leaf_preserved(self):
        self.assertIs(bookmarks_svc._jsonable(True), True)
        self.assertIs(bookmarks_svc._jsonable(False), False)

    def test_none_leaf_preserved(self):
        self.assertIsNone(bookmarks_svc._jsonable(None))

    def test_bool_liar_leaf_siblings_kept(self):
        out = bookmarks_svc._jsonable({"good": "yes", "bad": BoolLiar()})
        self.assertEqual(out["good"], "yes")
        self.assertIsNone(out["bad"])

    def test_bytes_liar_leaf_siblings_kept(self):
        out = bookmarks_svc._jsonable({"good": "yes", "bad": BytesLiar()})
        self.assertEqual(out["good"], "yes")
        self.assertEqual(out["bad"], "")


if __name__ == "__main__":
    unittest.main()
