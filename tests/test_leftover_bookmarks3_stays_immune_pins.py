"""Bookmarks stays-immune pins: the leftover-500 classes hold, end to end.

This sweep re-ran the four leftover classes over ``hub/bookmarks_svc.py``
and GET /api/bookmarks and found **no live hole** — the three prior passes
(test_assistant_bookmarks_modules_leftover_500s, test_leftover_bookmarks_
digit_500s, test_leftover_bookmarks_hexid_surrogate_key_500s,
test_modules_bookmarks_leftover_hexint_surrogate_vanish_500s) already
sealed the module.  What was still *unpinned* is pinned here so a
regression cannot land silently:

* the real route: every prior bookmark test emulates Starlette with a bare
  ``json.dumps``.  These pins go through ``create_app()`` + TestClient so
  the actual response path (ensure_ascii=False, allow_nan=False, UTF-8
  encode) is the thing under test;
* hostile *mapping keys inside a link row* — a YAML ``"k\\ud800": v`` or an
  uncapped hex-int key rides the link dict all the way into ``_jsonable``'s
  dict branch; the surrogate key must scrub and the over-cap int key must
  drop (``str(k)`` raises the digit-cap ValueError) without taking sibling
  keys with it;
* the ``list_bookmarks`` override→link merge loop (distinct from
  ``_backend_index``'s override loop, which is already pinned): an
  over-cap-int override *sid* becomes ``name``/``id``/``service`` of a
  synthesised link and an over-cap-int override *url* synthesises a link
  no probe can use — neither may 500 the endpoint;
* an unencodable probe URL (lone surrogate in the hostname) must keep its
  row: ``_probe`` absorbs the codec error before any socket is opened and
  the row renders red with the error text, rather than vanishing or
  raising — the silent-loss half of the class.

The other sweep classes are N/A by construction and asserted so:

* vanished-CLI 503: GET /api/bookmarks deliberately never 503s — each
  ``_backend_index`` collector absorbs its own CLI failure and the links
  fall back to plain HTTP probes (pinned below: a raising inventory still
  renders the list);
* os.kill / bool pids: nothing in hub/bookmarks_svc.py signals a pid
  (no ``os.kill`` / ``signal.`` call sites exist in the module);
* huge-number ``json.loads``: the bookmark chain parses no JSON — links
  come from cfg() YAML and probe answers are status ints from http.client.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import bookmarks_svc

#: Uncapped constructions: int("9"*5000) itself would trip the digit cap.
_HUGE_INT = 10 ** 5000
_HEX_HUGE = int("f" * 4000, 16)


def _probe_ok(url: str, timeout: float = 3.0) -> dict:
    return {"ok": True, "status": 200, "ms": 1, "error": None}


class RealRouteEncoderPins(unittest.TestCase):
    """GET /api/bookmarks through the real app: Starlette does the encoding."""

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

    def test_surrogate_keys_and_values_answer_200_scrubbed(self):
        resp = self._get({
            "quick_links": [{
                "name": "n\ud800",
                "url": "http://a.lan/\ud800",
                "k\ud800": "v\ud800",
            }],
            "overrides": {"cam\ud800": {"url": "http://cam.lan/\ud800",
                                        "name": "o\ud800"}},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn("\ud800", resp.text)
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 2)
        self.assertEqual(body["up"], 2)

    def test_hex_huge_int_in_every_field_answers_200(self):
        resp = self._get({
            "quick_links": [{
                "name": _HEX_HUGE, "url": "http://a.lan", "id": _HEX_HUGE,
                "service": _HEX_HUGE, "vm": _HEX_HUGE, "backend_id": _HEX_HUGE,
                _HUGE_INT: _HEX_HUGE,
            }],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 1)
        # json.dumps cannot render the over-cap fields at all — dropped.
        self.assertIsNone(body["bookmarks"][0]["name"])
        self.assertIsNone(body["bookmarks"][0]["id"])

    def test_over_cap_override_sid_and_url_answer_200(self):
        """The list_bookmarks merge loop, not _backend_index's override loop:
        ``name = ov.get("name") or sid`` puts the raw sid into the link."""
        resp = self._get({
            "quick_links": [],
            "overrides": {_HUGE_INT: {"url": _HUGE_INT, "name": _HUGE_INT}},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # An int url can never be an <a href>; the row is dropped, not 500'd.
        self.assertEqual(resp.json()["bookmarks"], [])


class LinkMappingKeyPins(unittest.TestCase):
    """Hostile keys *inside* a link dict ride into _jsonable's dict branch."""

    def test_jsonable_drops_over_cap_int_key_keeps_siblings(self):
        out = bookmarks_svc._jsonable({_HUGE_INT: "v", "ok": 1})
        self.assertEqual(out, {"ok": 1})
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_jsonable_scrubs_surrogate_key_keeps_row(self):
        out = bookmarks_svc._jsonable({"k\ud800": "v", "ok": 1})
        self.assertEqual(out["ok"], 1)
        self.assertFalse(any("\ud800" in k for k in out))
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class UnencodableProbeUrlPins(unittest.TestCase):
    """A lone surrogate in the probe URL: error row, never a raise or a drop."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def test_probe_absorbs_the_codec_error_before_any_socket(self):
        with mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("a socket must never be opened"),
        ):
            out = bookmarks_svc._probe("http://h\ud800ost.lan/p")
        self.assertFalse(out["ok"])
        self.assertIsNone(out["status"])
        self.assertTrue(out["error"])

    def test_surrogate_url_bookmark_keeps_its_row_as_red(self):
        """Real _probe (no mock): the row must render, not silently vanish."""
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{
                        "name": "Cam", "url": "http://h\ud800ost.lan/p",
                    }],
                    "overrides": {},
                },
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch(
                "socket.create_connection",
                side_effect=AssertionError("a socket must never be opened"),
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["health"], "error")
        self.assertEqual(data["down"], 1)
        encoded = json.dumps(data, ensure_ascii=False, allow_nan=False)
        encoded.encode("utf-8")
        self.assertNotIn("\ud800", encoded)


class InventoryDownStaysAListPins(unittest.TestCase):
    """The vanished-CLI class is deliberately not a 503 on this endpoint."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def test_raising_backend_inventory_still_renders_probed_links(self):
        """utmctl/orbctl/docker all gone raises out of _backend_index in the
        worst case; list_bookmarks contains it and probes the links anyway."""
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{"name": "N", "url": "http://nas.lan"}],
                    "overrides": {},
                },
            ),
            mock.patch.object(
                bookmarks_svc, "_backend_index",
                side_effect=RuntimeError("every inventory CLI vanished"),
            ),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["health"], "ok")
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
