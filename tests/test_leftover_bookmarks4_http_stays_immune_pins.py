"""Bookmarks sweep #4: HTTP-layer stays-immune pins for the uncovered vectors.

This sweep re-ran the leftover classes (UTF-8 surrogates in keys and values,
hex/octal YAML ints past CPython's 4300-digit cap, vanished inventory CLIs,
sibling-row wipes) over the Bookmarks list route and its add/edit path
(``PUT /api/services/{sid}/override`` — an override with a ``url`` is what
synthesises a bookmark row) and found **no live hole**: four prior passes
(test_assistant_bookmarks_modules_leftover_500s, test_leftover_bookmarks_
digit_500s, test_leftover_bookmarks_hexid_surrogate_key_500s,
test_leftover_bookmarks3_stays_immune_pins) already sealed the service layer
and the encoder path.  What was still *unpinned* is the HTTP layer over the
**real** collaborators — the prior real-route pins mock ``_backend_index``
and ``_probe`` wholesale, so a regression inside either would pass them:

* junk ``quick_links`` *containers* (a dict, a str, an over-cap int instead
  of a list; junk rows beside a good row) must answer 200 with the junk
  dropped and the good sibling kept — never a 500, never a sibling wipe;
* poison probe URLs through the **real ``_probe``** (torn IPv6 ``http://[::1``,
  a NUL in the host, a >4300-digit port, a lone-surrogate host, a digit-only
  over-cap https host) must each keep their own red row beside the good
  sibling's row, with no surrogate reaching the wire;
* a numeric YAML ``id: 8080`` resolving a deliberately-stopped backend through
  the **real ``_backend_index``** (collectors stubbed at the inventory
  boundary) must render gray "stopped" over HTTP without opening a probe —
  the str()-probe coercion, end to end;
* vanished inventory CLIs (utmctl / orbctl / docker all FileNotFoundError at
  the collector boundary) must keep GET /api/bookmarks a 200 list — this
  endpoint deliberately never 503s, each collector absorbs its own failure;
* recursive YAML-anchor leftovers (a list that contains itself, a dict that
  contains itself) riding a link must depth-cap, not RecursionError;
* junk override mapping *sids* (bytes, tuple, an object whose ``__str__``
  raises) must not take the synthesised bookmark of a well-formed sibling
  override with them;
* the add/edit boundary: a >4300-digit numeric literal in the override PUT
  body raises **ValueError, not JSONDecodeError**, out of ``json.loads`` —
  FastAPI's body-parse guard must map it (and ``NaN`` / ``Infinity``
  literals) to a 4xx, never a 500.

All pins go through ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` so Starlette's own encoder (ensure_ascii=False, allow_nan=False,
UTF-8 encode) and FastAPI's body parsing are the things under test.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import bookmarks_svc

#: Uncapped constructions: int("9"*5000) itself would trip the digit cap.
_HUGE_INT = 10 ** 5000
_HEX_HUGE = int("f" * 4000, 16)


def _probe_ok(url: str, timeout: float = 3.0) -> dict:
    return {"ok": True, "status": 200, "ms": 1, "error": None}


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


class JunkQuickLinksContainerHttpPins(_HttpPinBase):
    """The container shapes around the links, not the link fields."""

    def _get(self, cfg_value: dict):
        client = self._client()
        with (
            mock.patch.object(bookmarks_svc, "cfg", return_value=cfg_value),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            return client.get("/api/bookmarks", params={"force": "true"})

    def test_quick_links_not_a_list_answers_an_empty_200(self):
        for junk in ({"a": 1}, "http://x", _HUGE_INT, True, None):
            with self.subTest(junk=type(junk).__name__):
                bookmarks_svc.list_bookmarks.invalidate()
                resp = self._get({"quick_links": junk, "overrides": {}})
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                self.assertEqual(body["bookmarks"], [])
                self.assertEqual(body["up"], 0)

    def test_junk_rows_drop_without_wiping_the_good_sibling(self):
        resp = self._get({
            "quick_links": [
                None, 5, "http://not-a-dict", [1], _HUGE_INT,
                {"name": "good", "url": "http://good.lan"},
            ],
            "overrides": {},
        })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 1)
        self.assertEqual(body["bookmarks"][0]["name"], "good")
        self.assertEqual(body["up"], 1)


class PoisonUrlRowsKeepSiblingsHttpPins(_HttpPinBase):
    """Real ``_probe`` (network blocked): every poison URL keeps its own row."""

    _LINKS = [
        {"name": "torn6", "url": "http://[::1"},
        {"name": "nul", "url": "http://a\x00b.lan"},
        {"name": "hugeport", "url": "http://a.lan:" + "9" * 5000},
        {"name": "surr", "url": "http://h\ud800ost.lan/"},
        {"name": "hugehost", "url": "https://" + "9" * 5000 + "/"},
        {"name": "good", "url": "http://good.lan"},
    ]

    def test_each_poison_url_renders_red_beside_the_good_row(self):
        client = self._client()
        blocked = OSError("network disabled in tests")
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"quick_links": self._LINKS, "overrides": {}},
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            # The TestClient itself is in-process ASGI; only the probes would
            # touch the network, and they must fail fast rather than resolve.
            mock.patch("socket.getaddrinfo", side_effect=blocked),
            mock.patch("socket.create_connection", side_effect=blocked),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotIn("\ud800", resp.text)
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), len(self._LINKS))
        by_name = {row["name"]: row for row in body["bookmarks"]}
        for name in ("torn6", "nul", "hugeport", "surr", "hugehost", "good"):
            self.assertIn(name, by_name)
            self.assertEqual(by_name[name]["health"], "error", name)
            self.assertTrue(by_name[name]["error"], name)
        self.assertEqual(body["down"], len(self._LINKS))


class NumericYamlIdStoppedBackendHttpPins(_HttpPinBase):
    """``id: 8080`` (already-int) through the real ``_backend_index``."""

    def test_stopped_backend_reads_gray_without_a_probe(self):
        client = self._client()
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [
                        {"name": "Web", "url": "http://web.lan", "id": 8080},
                    ],
                    "overrides": {},
                },
            ),
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[
                {"id": "8080", "name": "web", "state": "stopped",
                 "status": "stopped", "backend": "utm"},
            ]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([], None),
            ),
            mock.patch.object(
                bookmarks_svc, "_probe",
                side_effect=AssertionError("a stopped backend must not be probed"),
            ),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["bookmarks"][0]["health"], "stopped")
        self.assertEqual(body["stopped"], 1)
        self.assertEqual(body["bookmarks"][0]["backend"]["kind"], "vm")


class VanishedInventoryClisNever503HttpPins(_HttpPinBase):
    """utmctl / orbctl / docker all gone: still a 200 list, never a 503.

    GET /api/bookmarks deliberately has no vanished-CLI 503: each collector
    absorbs its own failure and the links fall back to plain HTTP probes.
    """

    def test_all_collectors_raising_keeps_the_list_a_200(self):
        client = self._client()
        gone = FileNotFoundError("No such file or directory")
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{"name": "N", "url": "http://nas.lan"}],
                    "overrides": {},
                },
            ),
            mock.patch("hub.vms_svc.list_utm_vms", side_effect=gone),
            mock.patch("hub.vms_svc.list_orb_machines", side_effect=gone),
            mock.patch(
                "hub.discovery.containers.discover_containers", side_effect=gone,
            ),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotEqual(resp.status_code, 503)
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 1)
        self.assertEqual(body["bookmarks"][0]["health"], "ok")
        self.assertEqual(body["up"], 1)


class RecursiveAnchorLeftoversHttpPins(_HttpPinBase):
    """YAML anchors can build self-referential nodes; the walk must depth-cap."""

    def test_self_referential_link_fields_answer_200(self):
        recur_list: list = []
        recur_list.append(recur_list)
        recur_dict: dict = {}
        recur_dict["self"] = recur_dict
        client = self._client()
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [
                        {"name": recur_list, "url": "http://a.lan",
                         "extra": recur_dict},
                        {"name": "good", "url": "http://good.lan"},
                    ],
                    "overrides": {},
                },
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(len(body["bookmarks"]), 2)
        names = [row["name"] for row in body["bookmarks"]]
        self.assertIn("good", names)


class JunkOverrideSidKeysHttpPins(_HttpPinBase):
    """Junk mapping *keys* in overrides must not cost the good sibling."""

    def test_junk_sids_drop_and_the_good_override_still_synthesises(self):
        class RaisingStr:
            def __str__(self):
                raise RuntimeError("no str")

        client = self._client()
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [],
                    "overrides": {
                        b"\xff\xfe": {"url": "http://bytes.lan"},
                        (1, 2): {"url": "http://tuple.lan"},
                        RaisingStr(): {"url": "http://raising.lan"},
                        "good": {"url": "http://good.lan", "name": "Good"},
                    },
                },
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            resp = client.get("/api/bookmarks", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        names = [row["name"] for row in body["bookmarks"]]
        self.assertIn("Good", names)
        # The junk-sid overrides still synthesise rows (their urls are fine);
        # what is pinned is that none of them 500s and "good" is never wiped.
        self.assertGreaterEqual(len(body["bookmarks"]), 1)


class OverrideBodyParseBoundaryPins(_HttpPinBase):
    """PUT /api/services/{sid}/override — the bookmarks add/edit boundary.

    ``json.loads`` of a >4300-digit numeric literal raises **ValueError, not
    JSONDecodeError** (the digit cap fires inside int parsing); FastAPI's
    body-parse guard must answer 4xx, never a 500.  ``NaN`` / ``Infinity``
    are accepted by json.loads and must die in validation, not the encoder.
    """

    def _put(self, raw: str):
        client = self._client()
        return client.put(
            "/api/services/testsvc/override",
            content=raw,
            headers={"Content-Type": "application/json"},
        )

    def test_huge_int_literal_in_a_declared_field_is_4xx_not_500(self):
        resp = self._put('{"port": ' + "1" * 5000 + "}")
        self.assertLess(resp.status_code, 500, resp.text[:300])
        self.assertIn(resp.status_code, (400, 422))

    def test_huge_int_literal_in_an_undeclared_field_is_4xx_not_500(self):
        """The parse dies before pydantic ever sees the field names."""
        resp = self._put('{"junk": [' + "9" * 5000 + '], "hide": true}')
        self.assertLess(resp.status_code, 500, resp.text[:300])
        self.assertIn(resp.status_code, (400, 422))

    def test_nan_and_infinity_literals_are_4xx_not_500(self):
        for raw in ('{"port": NaN}', '{"url": Infinity}', '{"port": -Infinity}'):
            with self.subTest(raw=raw):
                resp = self._put(raw)
                self.assertLess(resp.status_code, 500, resp.text[:300])
                self.assertIn(resp.status_code, (400, 422))


if __name__ == "__main__":
    unittest.main()
