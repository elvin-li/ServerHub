"""Bookmarks sweep #6: nested unbound-base bombs and raw-kept url set bombs.

Sweep #5 sealed the dict-subclass ``.get`` / ``items()`` / ``__bool__`` /
``__iter__`` row-bomb class, but ``hub/bookmarks_svc.py`` never got the
modules5 *unbound-base* treatment (``int.__index__``, ``float.__float__``,
``bytes.decode`` via the base type, ``str.encode`` unbound), and the final
dedupe still hashed raw urls.  This sweep found **twelve live 500s** on
GET /api/bookmarks, all fixed in ``hub/bookmarks_svc.py``:

* an int-subclass ``__str__`` bomb riding ``service:`` raised past
  ``_key_text``'s ValueError-only catch (the digit-cap probe) out of
  ``_resolve_backend``'s lookup, and the same bomb riding ``id:`` raised
  out of ``_jsonable``'s int branch at encode time;
* a float-subclass ``__eq__``/``__ne__`` bomb blew ``_jsonable``'s NaN/inf
  probes (``value != value``);
* a bytes-subclass ``.decode`` bomb blew both bound ``decode`` calls
  (``_utf8_text`` and ``_jsonable``'s bytes branch);
* a str subclass whose ``__str__`` answers *self* and whose bound
  ``encode`` raises rode ``_utf8_text``'s final encode to a 500 — at name
  rank through ``_jsonable`` and at key rank through ``_key_text`` (these
  need the raw-kept path: a laundering ``resolve_value`` copies strings
  to exact str, but one items-bomb sibling keeps the whole list raw);
* a dict subclass whose ``items()`` answers non-pairs (``[1, 2]``)
  TypeError'd the ``for k, v in items`` unpack *outside* the guarded
  ``list()`` just above it;
* an object whose ``__getattr__`` raises a non-AttributeError blew the
  bare ``getattr(value, "isoformat", None)`` in ``_jsonable``'s tail;
* a raw-kept url str subclass whose ``__hash__`` raises — or is ``None``,
  the classic unhashable-membership leftover — 500'd the final dedupe out
  of ``u in seen`` / ``seen.add(u)``;
* a raw-kept url str subclass with an ``__eq__`` bomb 500'd the override
  merge dedupe: the subclass reflected-first rule calls the bomb even
  when it sits on the right of ``l.get("url") == ov["url"]``.

All pins drive ``create_app()`` + ``TestClient(raise_server_exceptions=
False)``: a raw 500 is a leftover, the 200 list with the bomb field
degraded and every healthy sibling kept is the pass.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import bookmarks_svc


class IntStrBomb(int):
    """Passes isinstance(x, int); str() raises a non-ValueError."""

    def __str__(self):
        raise RuntimeError("int str bomb")


class FloatCmpBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    __hash__ = float.__hash__


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class SelfStrEncodeBomb(str):
    """str() answers *self* (skipping CPython's exact-str copy), then the
    bound ``encode`` raises — the modules5 encode-bomb shape."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("str encode bomb")


class NonPairItems(dict):
    """items() answers non-pairs: the unpack bomb, not the raise bomb."""

    def items(self):
        return [1, 2]


class IsoGetattrBomb:
    """getattr(x, 'isoformat', None) only swallows AttributeError."""

    def __getattr__(self, name):
        raise RuntimeError("getattr bomb")


class HashBombStr(str):
    def __hash__(self):
        raise RuntimeError("hash bomb")


class UnhashableStr(str):
    __hash__ = None


class EqBombStr(str):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = str.__hash__


class ItemsBomb(dict):
    """resolve_value's laundering raises on this row, so its *siblings*
    stay raw in the list (the bookmarks5 all-or-nothing fallback)."""

    def items(self):
        raise RuntimeError("items bomb")


#: Past CPython's 4300-digit int->str cap; hex construction is exempt
#: from the str->int side of the limit.
_OVERCAP_INT = int("f" * 3600, 16)


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

    def _get(self, cfg_value: dict):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})


class IntSubclassStrBombHttpPins(_HttpPinBase):
    """__str__-bomb int subclasses in key and rendered positions."""

    def test_bomb_service_still_answers_200_and_keys_by_value(self):
        """_key_text's bare str() raised out of _resolve_backend's lookup."""
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": IntStrBomb(7)}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 2)
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["service"], 7)

    def test_bomb_id_still_answers_200_at_encode_time(self):
        """_jsonable's int branch caught ValueError only."""
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "id": IntStrBomb(7)}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["id"], 7)

    def test_overcap_int_subclass_id_drops_alone(self):
        """Base coercion must still feed the digit-cap probe: an over-cap
        subclass id renders null instead of ValueError'ing json.dumps."""
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "id": IntStrBomb(_OVERCAP_INT)}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertIsNone(by_url["http://a.lan"]["id"])
        self.assertEqual(by_url["http://good.lan"]["name"], "good")


class JsonableValueBombHttpPins(_HttpPinBase):
    """Bombs riding rendered link fields into the final scrub."""

    def test_float_cmp_bomb_name_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": FloatCmpBomb(1.5), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["name"], 1.5)

    def test_bytes_decode_bomb_name_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": BytesDecodeBomb(b"n"),
                             "url": "http://a.lan"}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["name"], "n")

    def test_non_pair_items_name_answers_200(self):
        """list(value.items()) succeeded; the k, v unpack then TypeError'd."""
        resp = self._get({
            "quick_links": [{"name": NonPairItems(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["name"], {})

    def test_getattr_bomb_name_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": IsoGetattrBomb(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertIsInstance(by_url["http://a.lan"]["name"], str)
        self.assertEqual(by_url["http://good.lan"]["name"], "good")


class RawKeptEncodeBombHttpPins(_HttpPinBase):
    """Encode bombs need the raw-kept path: one ItemsBomb sibling keeps the
    whole quick_links list unlaundered past resolve_value."""

    def test_encode_bomb_name_answers_200(self):
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": SelfStrEncodeBomb("n"),
                             "url": "http://a.lan"}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["name"], "n")

    def test_encode_bomb_service_answers_200(self):
        """_key_text -> _utf8_text's final bound encode was the raise."""
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": "a", "url": "http://a.lan",
                             "service": SelfStrEncodeBomb("s")}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["service"], "s")

    def test_encode_bomb_url_answers_200(self):
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": "x",
                             "url": SelfStrEncodeBomb("http://x.lan")},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertIn("http://x.lan", urls)
        self.assertIn("http://good.lan", urls)


class RawKeptUrlSetBombHttpPins(_HttpPinBase):
    """Raw-kept url subclasses against the dedupe set and the merge any()."""

    def test_hash_bomb_url_answers_200_with_both_rows(self):
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": "h", "url": HashBombStr("http://h.lan")},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(sorted(urls), ["http://good.lan", "http://h.lan"])

    def test_unhashable_url_answers_200_with_both_rows(self):
        """The literal unhashable-set-membership leftover: __hash__ = None."""
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": "u", "url": UnhashableStr("http://u.lan")},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(sorted(urls), ["http://good.lan", "http://u.lan"])

    def test_eq_bomb_url_beside_override_answers_200(self):
        """The merge dedupe compared raw: subclass reflected-first calls the
        bomb __eq__ even on the right of ``l.get("url") == ov["url"]``."""
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": "e", "url": EqBombStr("http://e.lan")},
                            dict(_GOOD)],
            "overrides": {"o": {"url": "http://o.lan", "name": "O"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        names = [r["name"] for r in body["bookmarks"]]
        self.assertIn("good", names)
        self.assertIn("O", names)
        self.assertIn("e", names)

    def test_eq_bomb_url_matching_override_stays_deduped(self):
        """The laundered compare must still dedupe an identical url."""
        resp = self._get({
            "quick_links": [ItemsBomb(),
                            {"name": "e", "url": EqBombStr("http://o.lan")},
                            dict(_GOOD)],
            "overrides": {"o": {"url": "http://o.lan", "name": "O"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(sorted(urls), ["http://good.lan", "http://o.lan"])


class KeyTextUnitPins(unittest.TestCase):
    """The lookup key coercion itself."""

    def test_int_str_bomb_keys_by_base_value(self):
        self.assertEqual(bookmarks_svc._key_text(IntStrBomb(7)), "7")

    def test_overcap_int_subclass_is_dropped(self):
        self.assertIsNone(bookmarks_svc._key_text(IntStrBomb(_OVERCAP_INT)))

    def test_overcap_exact_int_still_dropped(self):
        self.assertIsNone(bookmarks_svc._key_text(_OVERCAP_INT))

    def test_encode_bomb_str_is_scrubbed(self):
        self.assertEqual(bookmarks_svc._key_text(SelfStrEncodeBomb("s")), "s")

    def test_plain_keys_unchanged(self):
        self.assertEqual(bookmarks_svc._key_text("cam"), "cam")
        self.assertEqual(bookmarks_svc._key_text(8080), "8080")


class JsonableUnitPins(unittest.TestCase):
    """The scrub itself: bombs coerce or drop alone, output stays encodable."""

    def _encodable(self, out):
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_int_str_bomb_coerces_to_exact_int(self):
        out = bookmarks_svc._jsonable({"id": IntStrBomb(7), "ok": 1})
        self.assertEqual(out, {"id": 7, "ok": 1})
        self.assertIs(type(out["id"]), int)
        self._encodable(out)

    def test_overcap_int_subclass_drops_alone(self):
        out = bookmarks_svc._jsonable({"id": IntStrBomb(_OVERCAP_INT), "ok": 1})
        self.assertEqual(out, {"id": None, "ok": 1})
        self._encodable(out)

    def test_float_cmp_bomb_coerces_to_exact_float(self):
        out = bookmarks_svc._jsonable({"f": FloatCmpBomb(1.5), "ok": 1})
        self.assertEqual(out, {"f": 1.5, "ok": 1})
        self.assertIs(type(out["f"]), float)
        self._encodable(out)

    def test_float_cmp_bomb_inf_still_drops(self):
        out = bookmarks_svc._jsonable({"f": FloatCmpBomb("inf"), "ok": 1})
        self.assertEqual(out, {"f": None, "ok": 1})
        self._encodable(out)

    def test_bytes_decode_bomb_decodes_via_base(self):
        out = bookmarks_svc._jsonable({"b": BytesDecodeBomb(b"n"), "ok": 1})
        self.assertEqual(out, {"b": "n", "ok": 1})
        self._encodable(out)

    def test_encode_bomb_str_scrubs_via_unbound_encode(self):
        out = bookmarks_svc._jsonable({"s": SelfStrEncodeBomb("n"), "ok": 1})
        self.assertEqual(out, {"s": "n", "ok": 1})
        self.assertIs(type(out["s"]), str)
        self._encodable(out)

    def test_non_pair_items_drops_pairs_not_siblings(self):
        out = bookmarks_svc._jsonable({"m": NonPairItems(), "ok": 1})
        self.assertEqual(out, {"m": {}, "ok": 1})
        self._encodable(out)

    def test_getattr_bomb_survives_isoformat_probe(self):
        out = bookmarks_svc._jsonable({"o": IsoGetattrBomb(), "ok": 1})
        self.assertEqual(out["ok"], 1)
        self.assertIsInstance(out["o"], str)
        self._encodable(out)


class Utf8TextUnitPins(unittest.TestCase):
    def test_bytes_decode_bomb(self):
        self.assertEqual(bookmarks_svc._utf8_text(BytesDecodeBomb(b"n")), "n")

    def test_encode_bomb_answers_exact_str(self):
        out = bookmarks_svc._utf8_text(SelfStrEncodeBomb("n"))
        self.assertEqual(out, "n")
        self.assertIs(type(out), str)

    def test_surrogate_still_scrubbed(self):
        out = bookmarks_svc._utf8_text("a\ud800b")
        self.assertEqual(out, "a?b")
        out.encode("utf-8")  # Starlette's encode cannot 500 on it


class BackendIndexBombSidUnitPins(unittest.TestCase):
    """A bomb override sid used to raise out of _backend_index (absorbed at
    f_idx.result()) and silently wipe the collected rows."""

    def test_int_str_bomb_sid_keeps_collected_rows(self):
        with (
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[
                {"id": "vm1", "name": "web", "state": "stopped",
                 "status": "stopped", "backend": "utm"}]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([], None),
            ),
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"quick_links": [], "overrides": {
                    IntStrBomb(5): {"expected": "stopped",
                                    "url": "http://b.lan"}}},
            ),
        ):
            idx = bookmarks_svc._backend_index()
        self.assertIn("vm1", idx)
        self.assertIn("web", idx)
        # The bomb sid still keys by its base value.
        self.assertIn("5", idx)


if __name__ == "__main__":
    unittest.main()
