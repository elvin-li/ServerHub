"""Bookmarks sweep #12: launder default-repr address leaks out of the route.

A fresh route-level hunt after the sweep-#11 cfg-seam seal found no remaining
500s on GET /api/bookmarks (driven end to end via ``create_app()`` +
``TestClient(raise_server_exceptions=False)``), but one systemic leak — the
assistant12 family, live on this surface too:

* **The free-text coercion arm.**  ``_utf8_text`` ran ``str()`` on any
  leftover shape, and for a type that never overrode ``__str__`` /
  ``__repr__`` the answer is the default ``object.__repr__`` —
  ``<X object at 0x7f...>``, a raw heap address — which rode verbatim into
  the JSON body from every rendered cell: a junk link ``name`` / ``id`` /
  ``service``, an override sid carried into the merged row's ``name`` /
  ``id`` / ``service``, and a backend row's ``state`` / ``status`` /
  ``name`` / ``id`` / ``detail``.  A lying ``__class__`` claiming str (and a
  flickering ``__class__`` property that passes one ``_isinst(x, str)`` gate
  and misses the next) leaked the same way through the dispatching ``str()``.

* **The dict-key pre-coercion.**  ``_jsonable``'s mapping branch coerced a
  non-text key through a raw ``str(k)`` before the ``_utf8_text`` scrub, so
  a junk *key* rendered its heap address as the JSON key itself, one rank
  above the value scrub.

Sealed in ``hub.bookmarks_svc`` the assistant12 way, in the coercion arm
only — real str/bytes storage is data and stays verbatim:

* ``_str_text`` (unbound ``str.__str__``) reads really-str storage without
  dispatching an override, so a subclass ``__str__`` bomb now keeps its text
  and a str impostor drops to ``""`` instead of leaking its repr;
* a slot probe on the real ``type(value)`` drops plain-object junk (both
  slots still ``object``'s) before ``str()`` runs;
* the ``_ADDR_REPR_RE`` belt drops what the probe cannot see — function /
  bound-method reprs and a rendering that embeds a default repr;
* the mapping branch routes keys through ``_utf8_text`` with no raw
  ``str(k)``; a junk key drops its pair alone, siblings survive, and int /
  float keys still coerce exactly as before.

A body carrying ``" at 0x"`` is the leak; a 200 with the junk cell degraded
to its empty/fallback form and every healthy sibling kept is the pass.
"""
from __future__ import annotations

import itertools
import unittest
from unittest import mock

from hub import bookmarks_svc


class Junk:
    """Plain object: the default ``object.__repr__`` carries a heap address."""


class StrLiar:
    """``__class__`` answers str; the real type renders the default repr."""

    @property
    def __class__(self):
        return str


class Flicker:
    """``__class__`` alternates str / own type per access.

    Passes one ``_isinst(x, str)`` gate and misses the next, so it used to
    reach the dispatching ``str()`` and leak its default repr.
    """

    def __init__(self):
        self._n = itertools.count()

    @property
    def __class__(self):
        return str if next(self._n) % 2 == 0 else Flicker


class IsoJunk:
    """``isoformat()`` answers junk — the recursion must scrub it too."""

    def isoformat(self):
        return Junk()


class StrBombStr(str):
    """Real str storage riding a ``__str__`` bomb — data, not junk."""

    def __str__(self):
        raise RuntimeError("str bomb")


class SelfStrEncodeBomb(str):
    """``__str__`` answers *self*; the bound ``encode`` raises."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class RecurStr:
    def __str__(self):
        raise RecursionError("recur")


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

    def _assert_clean(self, resp):
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotIn(" at 0x", resp.text, resp.text[:300])
        return resp.json()


class LinkFieldLeakHttpPins(_HttpPinBase):
    """Junk riding a link's rendered cells must not leak an address."""

    def test_junk_name_degrades_and_siblings_survive(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": Junk(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["name"], "")
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_junk_id_and_service_stay_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "id": Junk(), "service": Junk()},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_str_liar_name_stays_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": StrLiar(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["name"], "")

    def test_flicker_class_name_stays_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": Flicker(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_lambda_service_stays_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": lambda: None},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_iso_junk_name_stays_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": IsoJunk(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")


class OverrideLeakHttpPins(_HttpPinBase):
    """A junk override sid / name rides into the merged row — scrubbed."""

    def test_junk_sid_merged_row_stays_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {Junk(): {"url": "http://ov.lan"}}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertIn("http://ov.lan", by_url)
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_junk_override_name_falls_back_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"svc": {"url": "http://ov.lan", "name": Junk()}}}))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertIn("http://ov.lan", by_url)


class BackendRowLeakHttpPins(_HttpPinBase):
    """Junk riding a backend row's rendered cells must not leak an address."""

    def _idx(self, **junk) -> dict:
        row = {"state": "stopped", "status": "stopped", "kind": "vm",
               "name": "svc", "id": "svc"}
        row.update(junk)
        return {"svc": row}

    def test_junk_backend_name_and_id_stay_clean(self):
        body = self._assert_clean(self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=self._idx(name=Junk(), id=Junk())))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")
        self.assertEqual(by_url["http://a.lan"]["backend"]["name"], "")

    def test_junk_backend_state_and_status_stay_clean(self):
        # A junk state never matched a state literal before either: the row
        # keeps its probe path, and no address reaches the body.
        body = self._assert_clean(self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=self._idx(state=Junk(), status=Junk())))
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_inventory_row_junk_fields_stay_clean(self):
        """The seam through the real ``_backend_index`` collectors."""
        client = self._client()
        row = {"id": "svc", "name": Junk(), "state": "stopped",
               "status": "stopped"}
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value={
                "quick_links": [{"name": "a", "url": "http://a.lan",
                                 "service": "svc"}],
                "overrides": {}}),
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[row]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch("hub.discovery.containers.discover_containers",
                       return_value=([], None)),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        body = self._assert_clean(resp)
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")


class JsonableKeyLeakPins(unittest.TestCase):
    """A junk mapping *key* must not render its address as the JSON key."""

    def test_junk_key_pair_drops_alone(self):
        out = bookmarks_svc._jsonable({"good": "yes", Junk(): "bad"})
        self.assertEqual(out, {"good": "yes"})

    def test_lambda_key_pair_drops_alone(self):
        out = bookmarks_svc._jsonable({"good": "yes", (lambda: None): "bad"})
        self.assertEqual(out, {"good": "yes"})

    def test_int_key_still_coerces(self):
        self.assertEqual(bookmarks_svc._jsonable({5: "v"}), {"5": "v"})

    def test_real_empty_str_key_stays(self):
        self.assertEqual(bookmarks_svc._jsonable({"": "v"}), {"": "v"})

    def test_junk_value_still_degrades_in_place(self):
        out = bookmarks_svc._jsonable({"good": "yes", "bad": Junk()})
        self.assertEqual(out["good"], "yes")
        self.assertEqual(out["bad"], "")


class Utf8TextUnitPins(unittest.TestCase):
    """The coercion arm drops address shapes; real text storage is data."""

    def test_plain_junk_drops_to_empty(self):
        self.assertEqual(bookmarks_svc._utf8_text(Junk()), "")

    def test_lambda_drops_to_empty(self):
        self.assertEqual(bookmarks_svc._utf8_text(lambda: None), "")

    def test_bound_method_drops_to_empty(self):
        self.assertEqual(bookmarks_svc._utf8_text(Junk().__init__), "")

    def test_str_liar_drops_to_empty(self):
        self.assertEqual(bookmarks_svc._utf8_text(StrLiar()), "")

    def test_rendering_embedding_default_repr_drops(self):
        self.assertEqual(bookmarks_svc._utf8_text({"x": Junk()}), "")

    def test_real_str_with_address_shape_stays_verbatim(self):
        """Data is data: real str storage is never scrubbed by the belt."""
        text = "probe failed at 0xDEADBEEF> marker"
        self.assertEqual(bookmarks_svc._utf8_text(text), text)

    def test_str_subclass_str_bomb_keeps_storage_text(self):
        out = bookmarks_svc._utf8_text(StrBombStr("keep"))
        self.assertEqual(out, "keep")
        self.assertIs(type(out), str)

    def test_encode_bomb_still_answers_exact_str(self):
        out = bookmarks_svc._utf8_text(SelfStrEncodeBomb("n"))
        self.assertEqual(out, "n")
        self.assertIs(type(out), str)

    def test_surrogate_still_scrubbed(self):
        out = bookmarks_svc._utf8_text("a\ud800b")
        self.assertEqual(out, "a?b")
        out.encode("utf-8")

    def test_recursion_error_still_answers_type_name(self):
        self.assertEqual(bookmarks_svc._utf8_text(RecurStr()), "RecurStr")

    def test_int_and_float_still_coerce(self):
        self.assertEqual(bookmarks_svc._utf8_text(5), "5")
        self.assertEqual(bookmarks_svc._utf8_text(1.5), "1.5")


class StrTextUnitPins(unittest.TestCase):
    """``_str_text`` reads really-str storage; impostors answer None."""

    def test_exact_str_reads_through(self):
        self.assertEqual(bookmarks_svc._str_text("hi"), "hi")

    def test_subclass_bomb_reads_storage(self):
        self.assertEqual(bookmarks_svc._str_text(StrBombStr("hi")), "hi")

    def test_liar_is_none(self):
        self.assertIsNone(bookmarks_svc._str_text(StrLiar()))

    def test_non_str_is_none(self):
        self.assertIsNone(bookmarks_svc._str_text(5))


if __name__ == "__main__":
    unittest.main()
