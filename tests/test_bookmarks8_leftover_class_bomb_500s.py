"""Bookmarks sweep #8: leftover ``__class__``-property bombs on the type gates.

Sweeps #5–#7 sealed the dict-subclass ``.get`` / ``.items`` / ``__bool__``
row bombs, the unbound-base coercions, the hexid / surrogate keys, and the
raw ``==`` / ``in`` compare bombs.  Every one of those fixes still *starts*
with a bare ``isinstance`` gate, and CPython's ``isinstance`` reads the
operand's ``__class__`` whenever the real-type fast check misses.  So a
leftover value whose ``__class__`` is a *raising property* — the modules8
class — blew straight through the gate itself, before any of the earlier
hardening could run.  This sweep found four live 500s on GET /api/bookmarks,
all fixed in ``hub/bookmarks_svc.py`` by routing the sanitizer type gates
through :func:`hub.bookmarks_svc._isinst`:

* ``overrides:`` is a ``__class__`` bomb — ``_plain_dict(cfg().get(
  "overrides"))`` in the merge loop 500'd out of its unguarded
  ``isinstance(value, dict)``;
* a ``quick_links`` *row* is a ``__class__`` bomb — the row plain-dict
  comprehension 500'd the same way;
* a link ``service:`` value is a ``__class__`` bomb — ``_resolve_backend``
  → ``_index_lookup`` → ``_key_text``'s ``isinstance(value, bool)`` 500'd
  at backend-resolution time;
* a link ``name:`` / ``id:`` value is a ``__class__`` bomb — the final
  ``_jsonable`` scrub 500'd out of ``isinstance(value, bool)`` at encode
  time even though the row's url was fine.

A *lying* ``__class__`` (answers ``int`` but is not one) is not an error:
``_isinst`` still reports its claim, and the numeric arm's unbound base
coercion drops it exactly as before.  Stays-immune pins cover that, the
already-guarded override-url path, and a bomb backend-row ``state``.

All HTTP pins drive ``create_app()`` + ``TestClient(raise_server_
exceptions=False)``: a raw 500 is a leftover; the 200 list with the bomb
degraded and every healthy sibling kept is the pass.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc


class ClassBomb:
    """Non-dict / non-str whose ``__class__`` property raises.

    ``isinstance(bomb, dict)`` misses the real-type fast check (its true
    type is ``ClassBomb``), falls back to reading ``bomb.__class__``, and
    raises out of the gate.
    """

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class LyingIntClass:
    """``__class__`` answers ``int`` but the value is not one.

    ``_isinst(x, int)`` reports True (that is not an error); the numeric
    arm then fails ``int.__index__`` and drops the value.
    """

    @property
    def __class__(self):
        return int


class StrKey(str):
    """A str *subclass* mapping key — knocks dict's C-level fast path."""

    __hash__ = str.__hash__


class StrKeyDict(dict):
    """A dict *subclass* keyed by str subclasses."""


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


class ClassBombHttpPins(_HttpPinBase):
    """The four live 500s, pinned end to end on the real route."""

    def test_overrides_class_bomb_answers_200(self):
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": ClassBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_quick_links_row_class_bomb_answers_200(self):
        resp = self._get({
            "quick_links": [ClassBomb(), dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_link_service_class_bomb_answers_200(self):
        """Reaches _resolve_backend → _index_lookup → _key_text's gate."""
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": ClassBomb()}, dict(_GOOD)],
            "overrides": {}}, idx={"svc": {"state": "stopped", "kind": "vm",
                                           "name": "svc", "id": "svc"}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_link_name_class_bomb_answers_200(self):
        """Reaches the final ``_jsonable`` scrub; the row's url is fine."""
        resp = self._get({
            "quick_links": [{"name": ClassBomb(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_link_id_class_bomb_answers_200(self):
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "id": ClassBomb()}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_link_url_class_bomb_drops_alone(self):
        """A ``__class__``-bomb url is not a probeable url: it drops, the
        healthy sibling is kept, and the route still answers 200."""
        resp = self._get({
            "quick_links": [{"name": "a", "url": ClassBomb()}, dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        urls = [r["url"] for r in resp.json()["bookmarks"]]
        self.assertEqual(urls, ["http://good.lan"])


class ClassBombStaysImmuneHttpPins(_HttpPinBase):
    """Vectors already immune — pinned so they stay that way."""

    def test_override_url_class_bomb_stays_200(self):
        """resolve_value raises on the bomb and the merge loop's own
        try/except drops the override — the healthy sibling is kept."""
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"o": {"url": ClassBomb(), "name": "O"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_backend_row_state_class_bomb_stays_200(self):
        """A ``__class__``-bomb backend ``state`` scrubs to "" in
        ``_cmp_text`` and the bookmark simply probes normally."""
        idx = {"svc": {"state": ClassBomb(), "status": "x", "kind": "vm",
                       "name": "svc", "id": "svc"}}
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=idx)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "ok")

    def test_lying_int_class_link_field_stays_200(self):
        """A value whose ``__class__`` lies as ``int`` is coerced-then-
        dropped by ``_jsonable``, not raised through it."""
        resp = self._get({
            "quick_links": [{"name": LyingIntClass(), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertIsNone(by_url["http://a.lan"]["name"])
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class IsinstUnitPins(unittest.TestCase):
    """The gate helper itself."""

    def test_bomb_answers_false_not_raise(self):
        self.assertFalse(bookmarks_svc._isinst(ClassBomb(), dict))
        self.assertFalse(bookmarks_svc._isinst(ClassBomb(), (str, int)))
        self.assertFalse(bookmarks_svc._isinst(ClassBomb(), bool))

    def test_real_types_still_report_true(self):
        self.assertTrue(bookmarks_svc._isinst({}, dict))
        self.assertTrue(bookmarks_svc._isinst("x", str))
        self.assertTrue(bookmarks_svc._isinst(True, bool))

    def test_lying_int_reports_its_claim(self):
        self.assertTrue(bookmarks_svc._isinst(LyingIntClass(), int))


class HelperClassBombUnitPins(unittest.TestCase):
    """Each sanitizer helper drops the bomb instead of raising."""

    def test_plain_dict_bomb_is_none(self):
        self.assertIsNone(bookmarks_svc._plain_dict(ClassBomb()))

    def test_cmp_text_bomb_is_empty(self):
        self.assertEqual(bookmarks_svc._cmp_text(ClassBomb()), "")

    def test_key_text_bomb_is_none(self):
        self.assertIsNone(bookmarks_svc._key_text(ClassBomb()))

    def test_utf8_text_bomb_does_not_raise(self):
        out = bookmarks_svc._utf8_text(ClassBomb())
        self.assertIsInstance(out, str)
        out.encode("utf-8")

    def test_jsonable_bomb_leaf_drops_siblings_kept(self):
        out = bookmarks_svc._jsonable({"good": "yes", "bad": ClassBomb()})
        self.assertEqual(out["good"], "yes")
        self.assertIn("bad", out)

    def test_jsonable_lying_int_leaf_is_dropped(self):
        self.assertIsNone(bookmarks_svc._jsonable(LyingIntClass()))

    def test_index_lookup_bomb_key_is_none(self):
        self.assertIsNone(bookmarks_svc._index_lookup({"a": {}}, ClassBomb()))

    def test_resolve_backend_bomb_link_is_none(self):
        self.assertIsNone(bookmarks_svc._resolve_backend(ClassBomb(), {}))


class DictSubclassStrKeyStaysImmune(unittest.TestCase):
    """A dict subclass keyed by str subclasses copies through the fast path."""

    def test_plain_dict_str_subclass_keys_preserved(self):
        src = StrKeyDict({StrKey("a"): 1, StrKey("b"): 2})
        out = bookmarks_svc._plain_dict(src)
        self.assertIsInstance(out, dict)
        self.assertIs(type(out), dict)
        self.assertEqual(out[StrKey("a")], 1)
        self.assertEqual(out["b"], 2)


if __name__ == "__main__":
    unittest.main()
