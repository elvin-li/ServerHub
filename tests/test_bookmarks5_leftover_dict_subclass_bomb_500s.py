"""Bookmarks sweep #5: dict-subclass / __bool__ / iterbomb leftovers.

Four prior passes (assistant_bookmarks_modules, bookmarks_digit,
bookmarks_hexid_surrogate_key, bookmarks3, bookmarks4) sealed surrogates,
over-cap ints, numeric YAML ids, torn IPv6, vanished CLIs, and the
``json.loads`` body boundary — but never ran the row-bomb class that
usage5/metrics5/jobs already fixed elsewhere: objects that pass the
``isinstance(x, dict)`` / ``isinstance(x, list)`` gates and then raise from
an overridden ``.get()`` / ``.items()`` / ``__iter__`` / ``__bool__``.
This sweep found **eight live 500s and one silent wipe** on
GET /api/bookmarks, all fixed in ``hub/bookmarks_svc.py``:

* an ``overrides`` mapping whose ``items()`` raises 500'd the
  ``list_bookmarks`` merge loop *and* ``_resolve_backend``'s override scan
  (nothing absorbs a raise on either path), and silently discarded the
  entire backend index out of ``_backend_index`` (absorbed at
  ``f_idx.result()``) — every stopped VM's bookmark probed red instead of
  gray;
* a ``__bool__``-bomb link ``url`` raised out of the bare
  ``not link.get("url")``; a bomb override ``url``/``name`` raised out of
  ``ov.get("url") and …`` / ``or sid``; a bomb link ``id``/``service``
  raised out of ``_compose_result``'s ``or`` chain; a bomb backend
  ``status`` raised out of ``str(backend.get("status") or "")`` at
  probe-decision time;
* a ``quick_links`` list *subclass* whose ``__iter__`` raises 500'd from
  the exception handler itself — ``list(raw_links)`` raised inside the
  try, then again from the identical call in the except fallback;
* a dict-subclass link row whose ``.get`` raises survived the
  ``resolve_value`` all-or-nothing fallback raw (one bomb sibling keeps
  the *whole* list unlaundered) and 500'd every loop that reads it;
* an ``items()`` bomb riding a link field (``name``) reached
  ``_jsonable``'s dict branch, whose bare ``value.items()`` raised at
  encode time; the list branch iterated sequence subclasses the same way.

All pins drive ``create_app()`` + ``TestClient(raise_server_exceptions=
False)``: a raw 500 is a leftover, the coded 200 list with the bomb row
degraded and every healthy sibling kept is the pass.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import bookmarks_svc


class GetBomb(dict):
    """Passes isinstance(x, dict); .get raises. items() still works, so
    resolve_value launders this one — see FullBomb for the raw-path twin."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class FullBomb(dict):
    """.get and items() both raise: items() makes resolve_value's laundering
    raise, so the all-or-nothing fallback keeps this row raw in the list."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")

    def items(self):
        raise RuntimeError("items bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class BoolBomb:
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

    def _get(self, cfg_value: dict):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})


class OverridesItemsBombHttpPins(_HttpPinBase):
    """An overrides mapping whose items() raises: 500'd two separate loops."""

    def test_merge_and_resolve_loops_answer_200_with_the_link_kept(self):
        resp = self._get({"quick_links": [dict(_GOOD)],
                          "overrides": ItemsBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 1)
        self.assertEqual(body["bookmarks"][0]["name"], "good")
        self.assertEqual(body["up"], 1)


class BoolBombValuesHttpPins(_HttpPinBase):
    """__bool__ bombs in link/override values raised out of bare truth tests."""

    def test_bomb_link_url_drops_alone_beside_the_good_sibling(self):
        resp = self._get({
            "quick_links": [{"name": "b", "url": BoolBomb()}, dict(_GOOD)],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual([r["name"] for r in body["bookmarks"]], ["good"])
        self.assertEqual(body["up"], 1)

    def test_bomb_override_url_drops_alone_beside_the_good_sibling(self):
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"o": {"url": BoolBomb(), "name": "O"}},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["name"] for r in resp.json()["bookmarks"]], ["good"])

    def test_bomb_override_name_falls_back_to_the_sid(self):
        resp = self._get({
            "quick_links": [],
            "overrides": {"cam": {"url": "http://cam.lan", "name": BoolBomb()}},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 1)
        self.assertEqual(body["bookmarks"][0]["name"], "cam")

    def test_bomb_link_id_and_service_answer_200(self):
        """_compose_result's ``id or service`` chain, at HTTP level."""
        resp = self._get({
            "quick_links": [{"name": "x", "url": "http://a.lan",
                             "id": BoolBomb(), "service": BoolBomb()},
                            dict(_GOOD)],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 2)
        self.assertIn("good", [r["name"] for r in body["bookmarks"]])


class IterBombQuickLinksHttpPins(_HttpPinBase):
    """list(raw_links) raised in the try *and again* in the except fallback."""

    def test_list_subclass_iter_bomb_answers_an_empty_200(self):
        resp = self._get({"quick_links": IterBombList([dict(_GOOD)]),
                          "overrides": {}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["bookmarks"], [])
        self.assertEqual(body["up"], 0)


class RawBombLinkRowsHttpPins(_HttpPinBase):
    """One bomb sibling keeps the whole list raw past resolve_value."""

    def test_full_bomb_link_row_degrades_and_keeps_the_good_sibling(self):
        resp = self._get({
            "quick_links": [FullBomb(url="http://x.lan"), dict(_GOOD)],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        urls = [r["url"] for r in body["bookmarks"]]
        self.assertIn("http://good.lan", urls)
        # The bomb row's url is a plain str; the plain-dict copy keeps it.
        self.assertIn("http://x.lan", urls)

    def test_full_bomb_link_beside_a_url_override_answers_200(self):
        """The dedupe ``any()`` generator called .get on every raw row."""
        resp = self._get({
            "quick_links": [FullBomb(url="http://x.lan"), dict(_GOOD)],
            "overrides": {"o": {"url": "http://o.lan", "name": "O"}},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        names = [r["name"] for r in resp.json()["bookmarks"]]
        self.assertIn("good", names)
        self.assertIn("O", names)

    def test_get_bomb_row_is_laundered_by_resolve_value(self):
        """items() works on GetBomb, so resolve_value rebuilds it plain."""
        resp = self._get({
            "quick_links": [GetBomb(url="http://x.lan"), dict(_GOOD)],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(len(resp.json()["bookmarks"]), 2)


class JsonableBombFieldsHttpPins(_HttpPinBase):
    """items()/__iter__ bombs riding a rendered link field into _jsonable."""

    def test_items_bomb_name_drops_alone_at_encode_time(self):
        resp = self._get({
            "quick_links": [{"name": ItemsBomb(a=1), "url": "http://a.lan"},
                            dict(_GOOD)],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        by_url = {r["url"]: r for r in body["bookmarks"]}
        self.assertIsNone(by_url["http://a.lan"]["name"])
        self.assertEqual(by_url["http://good.lan"]["name"], "good")

    def test_iter_bomb_name_drops_alone_at_encode_time(self):
        resp = self._get({
            "quick_links": [{"name": IterBombList(["n"]),
                             "url": "http://a.lan"}, dict(_GOOD)],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertIsNone(by_url["http://a.lan"]["name"])


class RealBackendIndexBombHttpPins(_HttpPinBase):
    """The bombs against the real ``_backend_index`` (collectors stubbed)."""

    def _get_real_index(self, cfg_value: dict, vm_rows: list,
                        probe_side_effect):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch("hub.vms_svc.list_utm_vms", return_value=vm_rows),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([], None),
            ),
            mock.patch.object(bookmarks_svc, "_probe",
                              side_effect=probe_side_effect),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})

    def test_items_bomb_overrides_do_not_wipe_the_stopped_vm_gray(self):
        """Pre-fix the raise inside _backend_index discarded the whole index
        (absorbed at f_idx.result()), so the stopped VM's bookmark probed
        red instead of rendering gray — the silent-wipe half of the class."""
        resp = self._get_real_index(
            {"quick_links": [{"name": "Web", "url": "http://web.lan",
                              "id": 8080}],
             "overrides": ItemsBomb()},
            [{"id": "8080", "name": "web", "state": "stopped",
              "status": "stopped", "backend": "utm"}],
            AssertionError("a stopped backend must not be probed"),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["bookmarks"][0]["health"], "stopped")
        self.assertEqual(body["stopped"], 1)

    def test_bool_bomb_backend_status_answers_200_at_decision_time(self):
        """``str(backend.get("status") or "")`` raised after the index had
        already been built — the probe-decision loop, not collection."""
        resp = self._get_real_index(
            {"quick_links": [{"name": "Web", "url": "http://web.lan",
                              "id": 8080}],
             "overrides": {}},
            [{"id": "8080", "name": "web", "state": "up",
              "status": BoolBomb(), "backend": "utm"}],
            _probe_ok,
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["bookmarks"][0]["health"], "ok")
        self.assertEqual(body["up"], 1)


class BackendIndexUnitPins(unittest.TestCase):
    """The wipe, pinned at the unit seam so the HTTP pin cannot mask it."""

    def test_items_bomb_overrides_keep_the_collected_rows(self):
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
                return_value={"quick_links": [], "overrides": ItemsBomb()},
            ),
        ):
            idx = bookmarks_svc._backend_index()
        self.assertIn("vm1", idx)
        self.assertIn("web", idx)


class JsonableUnitPins(unittest.TestCase):
    """The scrub itself: bombs drop alone, siblings stay encodable."""

    def test_items_bomb_mapping_drops_alone(self):
        out = bookmarks_svc._jsonable({"bomb": ItemsBomb(a=1), "ok": 1})
        self.assertEqual(out, {"bomb": None, "ok": 1})
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_iter_bomb_sequence_drops_alone(self):
        out = bookmarks_svc._jsonable({"bomb": IterBombList([1]), "ok": 1})
        self.assertEqual(out, {"bomb": None, "ok": 1})
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
