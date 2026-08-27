"""Bookmarks sweep #7: raw ``==`` / ``in`` compare bombs and index wipes.

Sweep #6 sealed the unbound-base coercions and the raw-kept url set bombs,
but the *comparison* sites still ran raw.  This sweep found four live 500s
and three silent index wipes on GET /api/bookmarks, all fixed in
``hub/bookmarks_svc.py``:

* an ``__eq__``-bomb str subclass riding a backend row's ``state`` 500'd
  the probe-decision loop (``b_state == "stopped"``) and
  ``_compose_result``'s tuple membership (``b_state in ("stopped",
  "down")``) — the subclass side of ``==`` is asked first even opposite
  an exact str;
* the same bomb riding ``status`` (state ``down``, kind ``vm``) 500'd
  ``_compose_result``'s status tuple membership;
* a *non-str* ``__eq__`` bomb riding an override ``url:`` — resolve_value
  launders str values but passes other types through raw — 500'd the
  merge dedupe from the reflected side of
  ``_utf8_text(l.get("url")) == ov_url``;
* a non-str ``__eq__`` bomb riding an override ``expected:`` raised out
  of ``_backend_index``'s compare and wiped the whole collected index
  (absorbed at ``f_idx.result()``), so every stopped VM's bookmark probed
  red instead of gray;
* one bomb inventory row — a dict-subclass ``.get`` bomb, or a
  ``__bool__`` bomb riding the ``or "down"`` state fallback — aborted the
  single try spanning the collection loop and wiped every sibling's
  entry the same way.

All HTTP pins drive ``create_app()`` + ``TestClient(raise_server_
exceptions=False)``: a raw 500 is a leftover; the 200 list with the bomb
degraded and every healthy sibling kept is the pass.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc


class EqBombStr(str):
    """Exact-str compares call the subclass ``__eq__`` first."""

    def __eq__(self, other):
        raise RuntimeError("str eq bomb")

    def __ne__(self, other):
        raise RuntimeError("str ne bomb")

    __hash__ = str.__hash__


class EqBombInt(int):
    """resolve_value passes non-str scalars through raw."""

    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    __hash__ = int.__hash__


class EqBombObj:
    def __eq__(self, other):
        raise RuntimeError("obj eq bomb")

    __hash__ = object.__hash__


class GetBombRow(dict):
    """Passes isinstance(x, dict); ``.get`` raises."""

    def get(self, *a, **k):
        raise RuntimeError("row get bomb")


class BoolBombStr(str):
    """Truthy probes (the ``or "down"`` fallback) raise."""

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


class BackendRowCompareBombHttpPins(_HttpPinBase):
    """__eq__ bombs riding backend-row state / status into the compares."""

    def test_eq_bomb_state_renders_stopped_not_500(self):
        """``b_state == "stopped"`` in the decision loop ran raw."""
        idx = {"svc": {"state": EqBombStr("stopped"), "status": "stopped",
                       "kind": "vm", "name": "svc", "id": "svc"}}
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=idx)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_eq_bomb_status_renders_stopped_not_500(self):
        """_compose_result's status tuple membership ran raw."""
        idx = {"svc": {"state": "down", "status": EqBombStr("exited"),
                       "kind": "vm", "name": "svc", "id": "svc"}}
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=idx)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")

    def test_eq_bomb_kind_answers_200(self):
        """The kind compare shares the same raw ``==`` shape."""
        idx = {"svc": {"state": "down", "status": "exited",
                       "kind": EqBombStr("vm"), "name": "svc", "id": "svc"}}
        resp = self._get({
            "quick_links": [{"name": "a", "url": "http://a.lan",
                             "service": "svc"}, dict(_GOOD)],
            "overrides": {}}, idx=idx)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://a.lan"]["health"], "stopped")
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")


class NonStrOverrideUrlBombHttpPins(_HttpPinBase):
    """Non-str override urls pass resolve_value raw into the merge dedupe."""

    def test_int_eq_bomb_override_url_answers_200(self):
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"o": {"url": EqBombInt(5), "name": "O"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_obj_eq_bomb_override_url_answers_200(self):
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"o": {"url": EqBombObj(), "name": "O"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://good.lan"]["health"], "ok")

    def test_str_override_url_still_merges_and_dedupes(self):
        """The laundered two-sided compare must not cost the merge itself."""
        resp = self._get({
            "quick_links": [dict(_GOOD)],
            "overrides": {"o": {"url": "http://o.lan", "name": "O"},
                          "g": {"url": "http://good.lan", "name": "dupe"}}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = resp.json()["bookmarks"]
        urls = sorted(r["url"] for r in rows)
        self.assertEqual(urls, ["http://good.lan", "http://o.lan"])
        by_url = {r["url"]: r for r in rows}
        self.assertEqual(by_url["http://good.lan"]["name"], "good")
        self.assertEqual(by_url["http://o.lan"]["name"], "O")


class RealIndexBombHttpPins(_HttpPinBase):
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

    def test_eq_bomb_state_vm_row_renders_gray_without_probe(self):
        """End to end: the bomb state keys and compares by its base value,
        so the stopped VM's bookmark stays gray and is never probed."""
        resp = self._get_real_index(
            {"quick_links": [{"name": "Web", "url": "http://web.lan",
                              "id": "8080"}],
             "overrides": {}},
            [{"id": "8080", "name": "web", "state": EqBombStr("stopped"),
              "status": "stopped", "backend": "utm"}],
            AssertionError("a stopped backend must not be probed"),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["bookmarks"][0]["health"], "stopped")
        self.assertEqual(body["stopped"], 1)

    def test_get_bomb_row_does_not_wipe_the_stopped_sibling_gray(self):
        """One bomb row used to abort the whole collection loop."""
        resp = self._get_real_index(
            {"quick_links": [{"name": "Web", "url": "http://web.lan",
                              "id": "8080"}],
             "overrides": {}},
            [GetBombRow(),
             {"id": "8080", "name": "web", "state": "stopped",
              "status": "stopped", "backend": "utm"}],
            AssertionError("a stopped backend must not be probed"),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["bookmarks"][0]["health"], "stopped")

    def test_obj_eq_bomb_expected_does_not_wipe_the_index(self):
        """The raw ``expected == "stopped"`` compare wiped every row."""
        resp = self._get_real_index(
            {"quick_links": [{"name": "Web", "url": "http://web.lan",
                              "id": "8080"}],
             "overrides": {"o": {"expected": EqBombObj(),
                                 "url": "http://b.lan"}}},
            [{"id": "8080", "name": "web", "state": "stopped",
              "status": "stopped", "backend": "utm"}],
            _probe_ok,
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        by_url = {r["url"]: r for r in resp.json()["bookmarks"]}
        self.assertEqual(by_url["http://web.lan"]["health"], "stopped")


class BackendIndexWipeUnitPins(unittest.TestCase):
    """The wipes, pinned at the unit seam so the HTTP pins cannot mask them."""

    def _index(self, vm_rows, container_rows=(), overrides=None):
        with (
            mock.patch("hub.vms_svc.list_utm_vms", return_value=list(vm_rows)),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=(list(container_rows), None),
            ),
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"quick_links": [],
                              "overrides": overrides or {}},
            ),
        ):
            return bookmarks_svc._backend_index()

    def test_get_bomb_vm_row_drops_alone(self):
        idx = self._index([
            GetBombRow(),
            {"id": "vm1", "name": "web", "state": "stopped",
             "status": "stopped", "backend": "utm"}])
        self.assertIn("vm1", idx)
        self.assertIn("web", idx)

    def test_bool_bomb_state_vm_row_drops_alone(self):
        idx = self._index([
            {"id": "vm0", "name": "a", "state": BoolBombStr("x"),
             "status": "stopped", "backend": "utm"},
            {"id": "vm1", "name": "web", "state": "stopped",
             "status": "stopped", "backend": "utm"}])
        self.assertIn("vm1", idx)
        self.assertIn("web", idx)

    def test_get_bomb_container_row_drops_alone(self):
        idx = self._index([], container_rows=[
            GetBombRow(),
            {"id": "c1", "name": "app", "state": "running",
             "detail": "Up 2 hours"}])
        self.assertIn("c1", idx)
        self.assertIn("app", idx)

    def test_obj_eq_bomb_expected_keeps_collected_rows(self):
        idx = self._index(
            [{"id": "vm1", "name": "web", "state": "stopped",
              "status": "stopped", "backend": "utm"}],
            overrides={"o": {"expected": EqBombObj(),
                             "url": "http://b.lan"}})
        self.assertIn("vm1", idx)
        self.assertIn("web", idx)

    def test_plain_expected_stopped_still_marks_override(self):
        idx = self._index([], overrides={
            "o": {"expected": "stopped", "url": "http://b.lan"}})
        self.assertIn("o", idx)
        self.assertEqual(idx["o"]["state"], "stopped")


class ComposeResultUnitPins(unittest.TestCase):
    """_compose_result's compares themselves."""

    def test_eq_bomb_state_down_composes_error_not_raise(self):
        out = bookmarks_svc._compose_result(
            {"name": "a", "url": "http://a.lan"},
            None,
            {"state": EqBombStr("down"), "status": "x", "kind": "vm",
             "name": "n", "id": "i"})
        self.assertEqual(out["health"], "error")

    def test_eq_bomb_state_stopped_composes_stopped(self):
        out = bookmarks_svc._compose_result(
            {"name": "a", "url": "http://a.lan"},
            None,
            {"state": EqBombStr("stopped"), "status": "stopped",
             "kind": "vm", "name": "n", "id": "i"})
        self.assertEqual(out["health"], "stopped")

    def test_eq_bomb_status_down_vm_composes_stopped(self):
        out = bookmarks_svc._compose_result(
            {"name": "a", "url": "http://a.lan"},
            None,
            {"state": "down", "status": EqBombStr("exited"), "kind": "vm",
             "name": "n", "id": "i"})
        self.assertEqual(out["health"], "stopped")


class CmpTextUnitPins(unittest.TestCase):
    """The comparison coercion itself."""

    def test_plain_str_passes_through_exact(self):
        out = bookmarks_svc._cmp_text("stopped")
        self.assertEqual(out, "stopped")
        self.assertIs(type(out), str)

    def test_eq_bomb_str_launders_to_exact(self):
        out = bookmarks_svc._cmp_text(EqBombStr("stopped"))
        self.assertEqual(out, "stopped")
        self.assertIs(type(out), str)

    def test_surrogate_is_scrubbed(self):
        out = bookmarks_svc._cmp_text("a\ud800b")
        self.assertEqual(out, "a?b")
        out.encode("utf-8")

    def test_non_str_answers_empty(self):
        self.assertEqual(bookmarks_svc._cmp_text(None), "")
        self.assertEqual(bookmarks_svc._cmp_text(5), "")
        self.assertEqual(bookmarks_svc._cmp_text(EqBombObj()), "")
        self.assertEqual(bookmarks_svc._cmp_text(EqBombInt(5)), "")


if __name__ == "__main__":
    unittest.main()
