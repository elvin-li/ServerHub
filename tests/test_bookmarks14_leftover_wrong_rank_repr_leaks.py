"""Bookmarks sweep #14: lying-``__class__`` wrong-rank recovery, nested
unbound reads, and the error-cell address leak on GET /api/bookmarks.

A fresh route-level hunt after the sweep-#13 BaseException seal (driven end
to end via ``create_app()`` + ``TestClient(raise_server_exceptions=False)``)
found no remaining raw 500s — every walk already snapshots before running
leftover hooks (the modules13 mid-walk mutation class is not live here) and
the cfg provider seam is fully fronted by ``_cfg_get`` — but three leftover
fidelity/leak classes, the modules14/users14 families live on this surface:

* **Wrong-rank degrades behind a lying ``__class__``.**  ``isinstance``
  consults ``value.__class__`` only after the real-MRO check misses, so a
  lying claim steered a leftover into the arm of its *claim*, the unbound
  descriptor there rejected the real layout, and an early return threw
  honest renderable storage away at the wrong rank: ``_jsonable`` dropped a
  genuine str/float claiming int, an int claiming final bool, a sequence
  claiming dict to ``None`` and degraded a genuine mapping claiming
  str/bytes to ``""``; ``_key_text`` dropped a genuine str ``service:``
  lying int/bool, so a stopped VM's bookmark probed red instead of gray.
  The rejected arms now fall through to the arm the *real* storage matches,
  probed via ``type(value)`` (``_real``) so the lie cannot steer the walk
  twice; total impostors keep their established drops.

* **Nested bound reads.**  ``_jsonable``'s dict arm dispatched the bound
  ``value.items()`` and its sequence arm the bound ``list(value)``, and the
  ``quick_links`` materialisation dispatched ``list(raw_links)``, so a
  subclass ``items()`` / ``__iter__`` bomb vaporized its perfectly
  renderable C-level storage (a nested map/list field to ``None``, the
  whole link list to ``[]``) even though the raise itself was absorbed.
  Unbound snapshots (``dict.items`` / ``base.__iter__``) read the real
  storage without running the override.

* **The error-cell address leak.**  ``exc_detail`` renders an exception's
  message objects through ``str()``, so a probe failure carrying a junk arg
  — or an ``HTTPError`` whose ``reason`` is junk — answered the default
  ``object.__repr__``: ``<X object at 0x7f...>``, a raw heap address, which
  the row's ``error`` cell carried verbatim onto the wire.  The final
  ``_jsonable`` scrub cannot catch it there (by then the cell is real str
  storage — data, kept verbatim per the bookmarks12 pin), so the
  ``_error_text`` belt sits at the seam where the exception is coerced.

The pinned union guards ride along untouched: ``resolve_value`` stays
raise-on-junk, the digit-cap ``except ValueError`` probes stay exactly that
narrow, every new guard is ``except BaseException`` with the
``_CONTROL_FLOW`` re-raise, and ``_isinst`` / ``_real`` stay fail-closed.

A dropped honest cell or an ``" at 0x"`` body is the leak; a 200 with the
real storage recovered (or the address scrubbed) and every healthy sibling
kept is the pass.
"""
from __future__ import annotations

import unittest
import urllib.error
from unittest import mock

from hub import bookmarks_svc


class Junk:
    """Plain object: the default ``object.__repr__`` carries a heap address."""


class StrClaimInt(str):
    """Genuine str storage; ``__class__`` lies int — the int arm's unbound
    ``int.__index__`` refuses it, and the old walk dropped the text."""

    @property
    def __class__(self):
        return int


class StrClaimBool(str):
    """Genuine str storage lying final bool — the old bool gates dropped it."""

    @property
    def __class__(self):
        return bool


class IntClaimBool(int):
    """Genuine int storage lying bool — final ``bool`` has no impostor arm,
    so the old ``_jsonable`` dropped the honest number to None."""

    @property
    def __class__(self):
        return bool


class FloatClaimInt(float):
    """Genuine float storage lying int — refused by ``int.__index__``."""

    @property
    def __class__(self):
        return int


class MapClaimStr(dict):
    """Genuine dict storage lying str — used to degrade to ``""``."""

    @property
    def __class__(self):
        return str


class MapClaimBytes(dict):
    """Genuine dict storage lying bytes — both base decodes refuse it."""

    @property
    def __class__(self):
        return bytes


class SeqClaimMap(list):
    """Genuine list storage lying dict — ``dict.items`` refuses it."""

    @property
    def __class__(self):
        return dict


class TupleClaimList(tuple):
    """Genuine tuple storage lying list — ``list.__iter__`` refuses it."""

    @property
    def __class__(self):
        return list


class ItemsBombMap(dict):
    """Real dict storage; bound ``items()`` raises — the nested-rank bomb."""

    def items(self):
        raise RuntimeError("items bomb")


class IterBombSeq(list):
    """Real list storage; bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class ExcItemsDict(dict):
    """Exception-shaped sibling bomb: keeps the whole list raw (bookmarks5),
    so the lying rows above ride into the loops unlaundered."""

    def items(self):
        raise RuntimeError("items bomb")


class BoolLiar:
    """Total impostor claiming final bool — keeps the None drop."""

    @property
    def __class__(self):
        return bool


class BytesLiar:
    """Total impostor claiming bytes — keeps the ``""`` drop."""

    @property
    def __class__(self):
        return bytes


class StrLiar:
    """Total impostor claiming str — keeps the ``""`` drop (and must not
    file a mapping value under a fabricated ``""`` key)."""

    @property
    def __class__(self):
        return str


class FindBombJunk(str):
    """A url whose ``find`` raises an exception *carrying a junk arg*: the
    rendered message is the arg's default repr — a raw heap address."""

    def find(self, *a, **k):
        raise RuntimeError(Junk())


class StrBombInterrupt(Exception):
    """Genuine control flow out of a message hook must keep propagating."""

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

    def _get(self, cfg_value, idx: dict | None = None, probe=_probe_ok):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch.object(bookmarks_svc, "_backend_index",
                              return_value=idx or {}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=probe),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})

    def _assert_ok(self, resp):
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return resp.json()

    def _by_url(self, body) -> dict:
        return {r["url"]: r for r in body["bookmarks"]}


class WrongRankLinkFieldHttpPins(_HttpPinBase):
    """Honest storage behind a lying ``__class__`` must render, not drop.

    Every case rides the raw-kept path: the ExcItemsDict sibling keeps the
    whole list raw past ``resolve_value``'s all-or-nothing fallback, so the
    lying value reaches ``_compose_result`` and the final ``_jsonable``.
    """

    def _links(self, row: dict) -> list:
        return [row, ExcItemsDict(url="http://raw.lan"), dict(_GOOD)]

    def test_str_lying_int_name_recovers_text(self):
        body = self._assert_ok(self._get({
            "quick_links": self._links(
                {"name": StrClaimInt("Real Name"), "url": "http://a.lan"}),
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["name"], "Real Name")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_int_lying_bool_id_recovers_value(self):
        body = self._assert_ok(self._get({
            "quick_links": self._links(
                {"name": "a", "url": "http://a.lan", "id": IntClaimBool(7)}),
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["id"], 7)

    def test_map_lying_str_name_renders_entries(self):
        body = self._assert_ok(self._get({
            "quick_links": self._links(
                {"name": MapClaimStr({"t": "x"}), "url": "http://a.lan"}),
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["name"], {"t": "x"})

    def test_seq_lying_dict_name_renders_elements(self):
        body = self._assert_ok(self._get({
            "quick_links": self._links(
                {"name": SeqClaimMap(["x"]), "url": "http://a.lan"}),
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["name"], ["x"])

    def test_nested_items_bomb_name_recovers_entries(self):
        """The nested unbound read: the bomb keeps the list raw by itself."""
        body = self._assert_ok(self._get({
            "quick_links": [
                {"name": ItemsBombMap({"t": "x"}), "url": "http://a.lan"},
                dict(_GOOD)],
            "overrides": {}}))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["name"], {"t": "x"})
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class WrongRankServiceKeyHttpPins(_HttpPinBase):
    """A lying ``service:`` key must keep its backend match — gray, not red."""

    _IDX = {"svc": {"state": "stopped", "status": "stopped", "kind": "vm",
                    "name": "svc", "id": "svc"}}

    def _links(self, service) -> list:
        return [{"name": "a", "url": "http://a.lan", "service": service},
                ExcItemsDict(url="http://raw.lan"), dict(_GOOD)]

    def test_str_lying_int_service_reads_stopped(self):
        body = self._assert_ok(self._get({
            "quick_links": self._links(StrClaimInt("svc")),
            "overrides": {}}, idx=dict(self._IDX)))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_str_lying_bool_service_reads_stopped(self):
        body = self._assert_ok(self._get({
            "quick_links": self._links(StrClaimBool("svc")),
            "overrides": {}}, idx=dict(self._IDX)))
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")


class QuickLinksRankHttpPins(_HttpPinBase):
    """The list-rank unbound snapshot: honest rows survive the claim/bomb."""

    def test_iter_bomb_quick_links_recovers_rows(self):
        body = self._assert_ok(self._get({
            "quick_links": IterBombSeq([dict(_GOOD)]), "overrides": {}}))
        self.assertEqual([r["url"] for r in body["bookmarks"]],
                         ["http://good.lan"])
        self.assertEqual(body["up"], 1)

    def test_tuple_lying_list_quick_links_still_renders(self):
        """Stays-immune: the real-tuple read already survived pre-fix."""
        body = self._assert_ok(self._get({
            "quick_links": TupleClaimList((dict(_GOOD),)), "overrides": {}}))
        self.assertEqual([r["url"] for r in body["bookmarks"]],
                         ["http://good.lan"])


class ErrorCellLeakHttpPins(_HttpPinBase):
    """A probe failure carrying junk must not put a heap address on the wire."""

    def test_probe_raise_with_junk_arg_scrubs_the_error_cell(self):
        def bomb(url, timeout: float = 3.0):
            raise RuntimeError(Junk())

        resp = self._get({"quick_links": [dict(_GOOD)], "overrides": {}},
                         probe=bomb)
        body = self._assert_ok(resp)
        self.assertNotIn(" at 0x", resp.text, resp.text[:300])
        by_url = self._by_url(body)
        self.assertEqual(by_url["http://good.lan"]["health"], "error")
        self.assertEqual(by_url["http://good.lan"]["error"], "error")


class ProbeErrorLeakUnitPins(unittest.TestCase):
    """The error belt at ``_probe``'s own seams."""

    def test_find_bomb_junk_arg_answers_scrubbed_error_row(self):
        out = bookmarks_svc._probe(FindBombJunk("http://a.lan"))
        self.assertIs(out["ok"], False)
        self.assertIsNone(out["status"])
        self.assertNotIn(" at 0x", out["error"])

    def test_http_error_junk_reason_answers_scrubbed_row(self):
        err = urllib.error.HTTPError("http://a.lan", 503, Junk(), None, None)
        opener = mock.Mock()
        opener.open.side_effect = err
        with mock.patch.object(bookmarks_svc.urllib.request, "build_opener",
                               return_value=opener):
            out = bookmarks_svc._probe("http://a.lan")
        self.assertEqual(out["status"], 503)
        self.assertNotIn(" at 0x", out["error"])

    def test_error_text_junk_arg_degrades_to_error(self):
        self.assertEqual(bookmarks_svc._error_text(RuntimeError(Junk())),
                         "error")

    def test_error_text_plain_message_passes_through(self):
        self.assertEqual(bookmarks_svc._error_text(RuntimeError("boom")),
                         "boom")

    def test_error_text_reraises_control_flow(self):
        with self.assertRaises(KeyboardInterrupt):
            bookmarks_svc._error_text(StrBombInterrupt())


class JsonableWrongRankUnitPins(unittest.TestCase):
    """Each rejected arm falls through to the arm the real storage matches."""

    def test_str_lying_int_recovers_text(self):
        out = bookmarks_svc._jsonable(StrClaimInt("keep"))
        self.assertEqual(out, "keep")
        self.assertIs(type(out), str)

    def test_int_lying_bool_recovers_exact_int(self):
        out = bookmarks_svc._jsonable(IntClaimBool(7))
        self.assertEqual(out, 7)
        self.assertIs(type(out), int)

    def test_float_lying_int_recovers_exact_float(self):
        out = bookmarks_svc._jsonable(FloatClaimInt(1.5))
        self.assertEqual(out, 1.5)
        self.assertIs(type(out), float)

    def test_map_lying_str_renders_entries(self):
        self.assertEqual(bookmarks_svc._jsonable(MapClaimStr({"t": "x"})),
                         {"t": "x"})

    def test_map_lying_bytes_renders_entries(self):
        self.assertEqual(bookmarks_svc._jsonable(MapClaimBytes({"t": "x"})),
                         {"t": "x"})

    def test_seq_lying_dict_renders_elements(self):
        self.assertEqual(bookmarks_svc._jsonable(SeqClaimMap(["x"])), ["x"])

    def test_nested_items_bomb_recovers_entries(self):
        out = bookmarks_svc._jsonable({"bad": ItemsBombMap({"t": "x"}),
                                       "good": 1})
        self.assertEqual(out, {"bad": {"t": "x"}, "good": 1})

    def test_nested_iter_bomb_recovers_elements(self):
        self.assertEqual(bookmarks_svc._jsonable(IterBombSeq([1, 2])), [1, 2])

    def test_str_liar_key_drops_its_entry(self):
        """A lying-str key with no text storage must not fabricate ``""``."""
        out = bookmarks_svc._jsonable({StrLiar(): "v", "good": 1})
        self.assertEqual(out, {"good": 1})

    def test_total_impostors_keep_their_drops(self):
        self.assertIsNone(bookmarks_svc._jsonable(BoolLiar()))
        self.assertEqual(bookmarks_svc._jsonable(BytesLiar()), "")
        self.assertEqual(bookmarks_svc._jsonable(StrLiar()), "")

    def test_real_scalars_and_digit_cap_stay_pinned(self):
        """The pinned union guard rides along untouched."""
        self.assertIs(bookmarks_svc._jsonable(True), True)
        self.assertEqual(bookmarks_svc._jsonable(42), 42)
        self.assertIsNone(bookmarks_svc._jsonable(int("f" * 5000, 16)))

    def test_real_empty_str_key_still_stays(self):
        self.assertEqual(bookmarks_svc._jsonable({"": "v"}), {"": "v"})


class KeyTextWrongRankUnitPins(unittest.TestCase):
    """``_key_text`` keys off the real storage, not the claim."""

    def test_str_lying_int_keys_by_text(self):
        self.assertEqual(bookmarks_svc._key_text(StrClaimInt("svc")), "svc")

    def test_str_lying_bool_keys_by_text(self):
        self.assertEqual(bookmarks_svc._key_text(StrClaimBool("svc")), "svc")

    def test_real_bool_still_drops(self):
        self.assertIsNone(bookmarks_svc._key_text(True))

    def test_plain_keys_unchanged(self):
        self.assertEqual(bookmarks_svc._key_text("cam"), "cam")
        self.assertEqual(bookmarks_svc._key_text(8080), "8080")

    def test_non_text_storage_still_drops(self):
        self.assertIsNone(bookmarks_svc._key_text(2.5))
        self.assertIsNone(bookmarks_svc._key_text(BoolLiar()))
        self.assertIsNone(bookmarks_svc._key_text(StrLiar()))


class RealProbeUnitPins(unittest.TestCase):
    """``_real`` reads the C-level type slot and fails closed."""

    def test_real_storage_wins_over_the_claim(self):
        self.assertTrue(bookmarks_svc._real(StrClaimInt("x"), str))
        self.assertFalse(bookmarks_svc._real(StrClaimInt("x"), int))
        self.assertFalse(bookmarks_svc._real(BoolLiar(), bool))


if __name__ == "__main__":
    unittest.main()
