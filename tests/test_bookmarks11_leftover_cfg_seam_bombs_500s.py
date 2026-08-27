"""Bookmarks sweep #11: leftover bombs at the config seam and the dedupe
truthiness read — vectors the previous ten sweeps never carried.

Two families were still live 500s on GET /api/bookmarks (driven end to end via
``create_app()`` + ``TestClient(raise_server_exceptions=False)``):

* **The config seam.** ``cfg().get("quick_links")`` / ``…("overrides")`` ran
  bare at four call sites, three of them on the request thread.  A ``cfg``
  that raises, answers a non-mapping (None after a torn reload), carries a
  dict-subclass ``.get`` bomb across the *whole* config, or holds a
  hash-shadowing key — a str-subclass whose ``__hash__`` matches
  ``"quick_links"`` / ``"overrides"`` but whose ``__eq__`` raises (one
  subclass key degrades the dict to the generic lookup, so even an exact-str
  probe key asks the stored bomb's ``__eq__`` first) — all 500'd the route
  before a single link was looked at.  Fixed by :func:`hub.bookmarks_svc.
  _cfg_get`: try around ``cfg()``, an ``_isinst`` mapping gate, the unbound
  ``dict.get`` (reads the C-level storage past a bomb ``.get``), and an
  item-scan fallback so a shadowed ``overrides`` key costs only itself and
  never takes ``quick_links`` with it.

* **The dedupe truthiness read.**  The ordered loop ran ``not u`` on the raw
  url before laundering it.  A lying ``__class__`` str impostor with a bomb
  ``__bool__`` (admitted by ``_isinst``, never laundered because it is not a
  real str), and a raw-kept real str subclass ``__bool__`` / ``__len__`` bomb
  (``resolve_value`` is raise-on-junk, so one bomb sibling row keeps the whole
  list raw), both 500'd the route from this loop — after every probe had
  already succeeded.  Fixed by taking the ``_utf8_text`` exact-str copy first,
  so the truthiness / hash / membership reads never ask the leftover anything.

A raw 500 is a leftover; a 200 with the bomb degraded field-level and every
healthy sibling kept is the pass.  Adjacent vectors probed and already immune
(dict-liar config, str-liar with a raising ``__str__``, isoformat property
bombs) are pinned so they stay so.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc


class BoolBombStr(str):
    """A str subclass whose ``__bool__`` raises — asked by a bare ``not u``."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class LenBombStr(str):
    """A str subclass whose ``__len__`` raises — ``bool()``'s other route."""

    def __len__(self):
        raise RuntimeError("len bomb")


class StrLiarBoolBomb:
    """``__class__`` answers str; ``__bool__`` raises.

    ``_isinst(x, str)`` admits it (a lying ``__class__`` is not an error —
    the bookmarks8 rule) but ``resolve_value`` never launders it because it
    is not a *real* str, so it used to reach the bare ``not u`` raw.
    """

    @property
    def __class__(self):
        return str

    def __bool__(self):
        raise RuntimeError("liar bool bomb")


class StrLiarStrBomb:
    """``__class__`` answers str; ``__str__`` raises — already immune, pinned."""

    @property
    def __class__(self):
        return str

    def __str__(self):
        raise RuntimeError("str bomb")


class DictLiar:
    """``__class__`` answers dict without the C-level storage."""

    @property
    def __class__(self):
        return dict


class GetBombDict(dict):
    """The usage5 row class riding the *whole* config mapping."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBombDict(dict):
    """One bomb row: trips ``resolve_value`` so the whole list stays raw."""

    def items(self):
        raise RuntimeError("items bomb")


class ShadowKey(str):
    """Hash-shadowing key: hashes like the real key, ``__eq__`` raises."""

    def __eq__(self, other):
        raise RuntimeError("shadow eq bomb")

    __hash__ = str.__hash__


class IsoBomb:
    """``isoformat`` is a raising property — already immune, pinned."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


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

    def _get(self, cfg_value=None, *, cfg_raises=None, idx: dict | None = None):
        client = self._client()
        kw = (
            {"side_effect": cfg_raises}
            if cfg_raises is not None
            else {"return_value": cfg_value}
        )
        with (
            mock.patch.object(bookmarks_svc, "cfg", **kw),
            mock.patch.object(bookmarks_svc, "_backend_index",
                              return_value=idx or {}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})


class CfgSeamHttpPins(_HttpPinBase):
    """The config-seam 500s, pinned end to end on the real route."""

    def test_cfg_raising_answers_200_empty(self):
        resp = self._get(cfg_raises=RuntimeError("cfg bomb"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["bookmarks"], [])
        self.assertEqual((body["up"], body["stopped"], body["down"]), (0, 0, 0))

    def test_cfg_none_answers_200_empty(self):
        resp = self._get(None)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["bookmarks"], [])

    def test_cfg_non_mapping_answers_200_empty(self):
        resp = self._get(["not", "a", "mapping"])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["bookmarks"], [])

    def test_cfg_get_bomb_subclass_answers_200_links_kept(self):
        """The unbound ``dict.get`` reads past the bomb: links still render."""
        resp = self._get(GetBombDict(
            {"quick_links": [dict(_GOOD)], "overrides": {}}))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_cfg_shadow_quick_links_answers_200_empty(self):
        """The shadowed key itself is unreadable — it degrades, not 500s."""
        resp = self._get({ShadowKey("quick_links"): [dict(_GOOD)],
                          "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["bookmarks"], [])

    def test_cfg_shadow_overrides_keeps_quick_links(self):
        """One bomb key costs only itself: quick_links must survive."""
        resp = self._get({"quick_links": [dict(_GOOD)],
                          ShadowKey("overrides"): {"o": {"url": "http://o.lan"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class UrlTruthinessHttpPins(_HttpPinBase):
    """The dedupe-loop ``not u`` 500s, pinned end to end."""

    def test_str_liar_bool_bomb_url_drops_alone(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": StrLiarBoolBomb()},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(urls, ["http://good.lan"])

    def test_raw_kept_bool_bomb_url_answers_200(self):
        """The items-bomb sibling keeps the list raw; the bomb url still renders."""
        resp = self._get({
            "quick_links": [
                ItemsBombDict({"name": "trip", "url": "http://trip.lan"}),
                {"name": "a", "url": BoolBombStr("http://a.lan")},
                dict(_GOOD),
            ],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://trip.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_raw_kept_len_bomb_url_answers_200(self):
        resp = self._get({
            "quick_links": [
                ItemsBombDict({"name": "trip", "url": "http://trip.lan"}),
                {"name": "a", "url": LenBombStr("http://a.lan")},
                dict(_GOOD),
            ],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class AdjacentStaysImmuneHttpPins(_HttpPinBase):
    """Vectors probed this sweep and already immune — pinned so they stay so."""

    def test_dict_liar_cfg_answers_200_empty(self):
        resp = self._get(DictLiar())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["bookmarks"], [])

    def test_str_liar_str_bomb_url_drops_alone(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": StrLiarStrBomb()},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(urls, ["http://good.lan"])

    def test_isoformat_property_bomb_name_stays_200(self):
        resp = self._get({
            "quick_links": [{"name": IsoBomb(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class CfgGetUnitPins(unittest.TestCase):
    """``_cfg_get`` degrades every config-level bomb without raising."""

    def _with(self, value=None, *, raises=None):
        kw = (
            {"side_effect": raises} if raises is not None
            else {"return_value": value}
        )
        return mock.patch.object(bookmarks_svc, "cfg", **kw)

    def test_plain_dict_reads_through(self):
        with self._with({"quick_links": [1]}):
            self.assertEqual(bookmarks_svc._cfg_get("quick_links"), [1])

    def test_missing_key_is_none(self):
        with self._with({}):
            self.assertIsNone(bookmarks_svc._cfg_get("quick_links"))

    def test_raising_cfg_is_none(self):
        with self._with(raises=RuntimeError("cfg bomb")):
            self.assertIsNone(bookmarks_svc._cfg_get("quick_links"))

    def test_non_mapping_is_none(self):
        with self._with(42):
            self.assertIsNone(bookmarks_svc._cfg_get("quick_links"))

    def test_dict_liar_is_none(self):
        with self._with(DictLiar()):
            self.assertIsNone(bookmarks_svc._cfg_get("quick_links"))

    def test_get_bomb_subclass_reads_through(self):
        with self._with(GetBombDict({"quick_links": [1]})):
            self.assertEqual(bookmarks_svc._cfg_get("quick_links"), [1])

    def test_shadowed_requested_key_is_none(self):
        with self._with({ShadowKey("quick_links"): [1]}):
            self.assertIsNone(bookmarks_svc._cfg_get("quick_links"))

    def test_shadowed_sibling_key_still_reads(self):
        with self._with({ShadowKey("overrides"): {"x": 1},
                         "quick_links": [1]}):
            self.assertEqual(bookmarks_svc._cfg_get("quick_links"), [1])


if __name__ == "__main__":
    unittest.main()
