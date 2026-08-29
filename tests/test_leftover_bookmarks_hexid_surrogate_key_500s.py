"""Leftover hex-YAML already-int ids and surrogate lookup keys on GET /api/bookmarks.

Prior passes pinned the bookmark list against unhashable YAML keys, leftover
datetime / bytes / inf fields, lone surrogates in *values*, digit-only hosts
and over-cap ports (test_assistant_bookmarks_modules_leftover_500s.py,
test_leftover_bookmarks_digit_500s.py).  A fresh hunt through the mapping-key
lens found three real leftovers:

* ``id: 0xfff…`` — YAML hex/octal (and a binary-plist integer) dodges the
  int(str) digit cap and arrives *already an int*.  ``_index_lookup`` then ran
  ``str(key)`` on it, and str() of a >4300-digit int raises CPython's
  digit-cap ValueError, which 500'd GET /api/bookmarks.  Already-int ids must
  coerce via a str() probe, not a strict isinstance(id, str) gate:
  ``id: 8080`` keys as "8080" either way.
* the same unguarded ``str(key)`` lived in ``_backend_index.put()``, where the
  surrounding try/except-pass silently wiped every backend row *after* the
  poisoned one (and an over-cap override url raised out of the whole builder),
  so a stopped VM's bookmark was probed red instead of reported gray.
* ``_jsonable`` passed an over-cap int through unchanged, and Starlette's
  encoder raises the identical digit-cap ValueError inside json.dumps — a
  second 500 sitting behind the first.
* the inventories publish scrubbed names (``vms_svc._as_text`` encode-replaces
  a lone surrogate away) while the YAML side of the lookup stayed raw
  (``service: "cam\\ud800"`` — PyYAML accepts the escape), so the two sides of
  the backend index keyed by different forms and never matched.  Mapping keys
  must be scrubbed before they become lookup keys.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import bookmarks_svc

#: YAML ``id: 0xfff…`` — hex parsing has no digit cap, so this is an *int*
#: whose decimal form is ~4816 digits, past CPython's 4300-digit str() limit.
_HUGE_INT = int("f" * 4000, 16)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _probe_ok(url: str) -> dict:
    return {"ok": True, "status": 200, "ms": 1, "error": None}


class HexYamlAlreadyIntIdTests(unittest.TestCase):
    """``str()`` of the already-int id is the probe; it used to be the 500."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def test_over_cap_int_id_renders_the_list_not_a_500(self):
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{
                        "name": "Hex", "url": "http://nas.lan:8080", "id": _HUGE_INT,
                    }],
                    "overrides": {},
                },
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch.object(bookmarks_svc, "_probe", side_effect=_probe_ok),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["health"], "ok")
        # The over-cap id is dropped, not str()'d into a 4816-digit key.
        self.assertIsNone(data["bookmarks"][0]["id"])
        _starlette(data)

    def test_index_lookup_over_cap_int_returns_none_not_valueerror(self):
        self.assertIsNone(
            bookmarks_svc._index_lookup({"x": {"state": "ok"}}, _HUGE_INT)
        )

    def test_index_lookup_small_int_still_matches_via_str_probe(self):
        """``id: 8080`` is already-int too; the probe must keep it working."""
        row = {"state": "stopped", "kind": "container", "id": "8080"}
        self.assertEqual(bookmarks_svc._index_lookup({"8080": row}, 8080), row)

    def test_bool_id_is_not_a_key(self):
        """bool-as-int: ``id: true`` must not key as "True" (nor as "1")."""
        self.assertIsNone(
            bookmarks_svc._index_lookup({"True": {"a": 1}, "1": {"a": 1}}, True)
        )

    def test_jsonable_drops_over_cap_int_before_starlette(self):
        out = bookmarks_svc._jsonable({"id": _HUGE_INT, "ms": 12})
        self.assertIsNone(out["id"])
        self.assertEqual(out["ms"], 12)
        _starlette(out)


class BackendIndexPoisonRowTests(unittest.TestCase):
    """One poisoned inventory row must not wipe the rows after it."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def _index(self, vm_rows, overrides=None):
        with (
            mock.patch("hub.vms_svc.list_utm_vms", return_value=vm_rows),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([], None),
            ),
            mock.patch.object(
                bookmarks_svc, "cfg", return_value={"overrides": overrides or {}},
            ),
        ):
            return bookmarks_svc._backend_index()

    def test_over_cap_vm_id_does_not_wipe_the_rows_after_it(self):
        idx = self._index([
            {"id": _HUGE_INT, "name": "poison", "state": "stopped"},
            {"id": "web", "name": "web", "state": "stopped",
             "status": "stopped", "backend": "utm"},
        ])
        self.assertIn("web", idx)
        self.assertEqual(idx["web"]["state"], "stopped")

    def test_non_str_vm_url_does_not_wipe_the_rows_after_it(self):
        # ``url: 0xfff…`` — .rstrip on the already-int url AttributeError'd
        # inside the same absorbed loop, with the same silent loss.
        idx = self._index([
            {"id": "poison", "name": "poison", "state": "ok", "url": _HUGE_INT},
            {"id": "web", "name": "web", "state": "stopped",
             "status": "stopped", "backend": "utm"},
        ])
        self.assertIn("web", idx)

    def test_over_cap_override_url_does_not_raise_out_of_the_builder(self):
        idx = self._index(
            [{"id": "web", "name": "web", "state": "stopped",
              "status": "stopped", "backend": "utm"}],
            overrides={"cam": {"expected": "stopped", "url": _HUGE_INT}},
        )
        self.assertIn("web", idx)
        self.assertIn("cam", idx)

    def test_stopped_vm_bookmark_stays_gray_beside_a_poison_row(self):
        """The user-visible half: gray "stopped", not a red probe failure."""
        with (
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[
                {"id": _HUGE_INT, "name": "poison", "state": "stopped"},
                {"id": "web", "name": "web", "state": "stopped",
                 "status": "stopped", "backend": "utm"},
            ]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([], None),
            ),
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{
                        "name": "Web", "url": "http://web.lan", "service": "web",
                    }],
                    "overrides": {},
                },
            ),
            mock.patch.object(
                bookmarks_svc, "_probe",
                side_effect=AssertionError("a stopped backend must not be probed"),
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        self.assertEqual(data["bookmarks"][0]["health"], "stopped")
        self.assertEqual(data["stopped"], 1)
        _starlette(data)


class SurrogateLookupKeyTests(unittest.TestCase):
    """Inventories publish U+FFFD-scrubbed names; YAML keys arrive raw."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def test_raw_yaml_surrogate_service_matches_scrubbed_inventory_key(self):
        # vms_svc._as_text has already scrubbed the VM's lone surrogate
        # (encode-replace maps it to "?"); the quick_link still carries the
        # raw ``"cam\ud800"``.
        scrubbed = bookmarks_svc._utf8_text("cam\ud800")
        self.assertNotIn("\ud800", scrubbed)
        backend = {"state": "stopped", "kind": "vm", "id": scrubbed}
        row = bookmarks_svc._resolve_backend(
            {"name": "Cam", "url": "http://cam.lan", "service": "cam\ud800"},
            {scrubbed: backend},
        )
        self.assertEqual(row, backend)

    def test_put_scrubs_index_keys_before_they_are_lookup_keys(self):
        # A collector that did not scrub (raw container name) still lands on
        # the same key as the scrubbed lookup — both sides key by one form.
        with (
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([{
                    "id": "cam\ud800", "name": "cam\ud800",
                    "state": "stopped", "detail": "exited",
                }], None),
            ),
            mock.patch.object(bookmarks_svc, "cfg", return_value={"overrides": {}}),
        ):
            idx = bookmarks_svc._backend_index()
        self.assertIn(bookmarks_svc._utf8_text("cam\ud800"), idx)
        self.assertNotIn("cam\ud800", idx)

    def test_surrogate_url_key_matches_the_scrubbed_inventory_url(self):
        scrubbed_url = bookmarks_svc._utf8_text("http://cam.lan/x\ud800")
        backend = {"state": "stopped", "kind": "vm", "id": "cam"}
        row = bookmarks_svc._resolve_backend(
            {"name": "Cam", "url": "http://cam.lan/x\ud800"},
            {f"url:{scrubbed_url}": backend},
        )
        self.assertEqual(row, backend)

    def test_surrogate_service_bookmark_reports_stopped_end_to_end(self):
        with (
            mock.patch("hub.vms_svc.list_utm_vms", return_value=[
                # As published by vms_svc after _as_text scrubbing.
                {"id": "utm:" + bookmarks_svc._utf8_text("cam\ud800"),
                 "name": bookmarks_svc._utf8_text("cam\ud800"),
                 "state": "stopped", "status": "stopped", "backend": "utm"},
            ]),
            mock.patch("hub.vms_svc.list_orb_machines", return_value=[]),
            mock.patch(
                "hub.discovery.containers.discover_containers",
                return_value=([], None),
            ),
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{
                        # Raw YAML: PyYAML accepts the lone-surrogate escape.
                        "name": "Cam", "url": "http://cam.lan",
                        "service": "cam\ud800",
                    }],
                    "overrides": {},
                },
            ),
            mock.patch.object(
                bookmarks_svc, "_probe",
                side_effect=AssertionError("a stopped backend must not be probed"),
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        self.assertEqual(data["bookmarks"][0]["health"], "stopped")
        self.assertEqual(data["stopped"], 1)
        _starlette(data)


if __name__ == "__main__":
    unittest.main()
