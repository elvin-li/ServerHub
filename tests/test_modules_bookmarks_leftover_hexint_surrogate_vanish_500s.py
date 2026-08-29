"""Leftover Modules-page 500s: hex-YAML over-cap ints and surrogate lookup
keys in the bookmark module, and the vanished-nginx CLI that answered the
raw ``sh`` sentinel.

Prior sweeps sealed GET /api/modules itself (junk registry rows, over-cap
ints, surrogates — see test_settings_config_modules_leftover_500s and
test_assistant_bookmarks_modules_leftover_500s) and pinned the bookmark
probes against >4300-digit *string* shapes (test_leftover_bookmarks_digit
_500s).  A fresh hunt over the same modules_api surface found three holes:

* YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
  CPython's 4300-digit conversion limit), so a leftover ``service: 0xFF…``
  in ``quick_links`` arrived *already-int*.  ``_index_lookup`` str()'d it
  bare — the digit-cap ValueError 500'd GET /api/bookmarks — and
  ``bookmarks_svc._jsonable``'s bare ``isinstance(value, int)`` branch let
  the same leftover ride to Starlette's own ``json.dumps`` (a second 500).
  ``_backend_index.put`` had the same bare ``str(key)``: one over-cap
  override sid blew up the whole index build, and ``list_bookmarks``'s
  containment then served ``idx = {}`` — every deliberately-stopped
  VM/container silently probed red instead of reading gray "stopped".
  The fix is a str() probe: a *finite* numeric YAML id (``id: 8080``)
  must keep matching its backend row, not be hidden behind a strict
  ``isinstance(id, str)`` gate;
* link values pass ``resolve_value``, which scrubs lone surrogates to
  U+FFFD — but ``_backend_index`` mapping keys were never scrubbed, so a
  bookmark id carrying a leftover ``\\ud800`` could never resolve the
  backend row listed under the same id: the stopped backend probed over
  the network and rendered red/green instead of gray.  Mapping keys must
  be scrubbed *before* they become lookup keys, on both sides;
* an nginx binary that vanished between the conf check and the spawn made
  POST /api/nginx/test answer the raw ``sh`` sentinel ``"not found"`` and
  made Reload mislabel it "Invalid configuration; not reloaded" — the same
  operator-facing state brew_svc already maps to its coded 503
  ``brew.not_found``.  Classification requires the disk confirm, run only
  on the failure path: a still-present nginx whose spawn failed for
  another reason (a vanished cwd raises the same FileNotFoundError) keeps
  its raw result, and a genuine nginx exit whose stderr merely reads
  "not found" is never reclassified.

os.kill leftovers (the fourth sweep class) do not apply here: nothing in
hub/modules.py, hub/routers/modules_api.py or hub/bookmarks_svc.py
signals a pid.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import bookmarks_svc, nginx_svc

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class HexYamlVectorTest(unittest.TestCase):
    def test_hex_yaml_loads_past_the_digit_cap(self):
        """The vector this file guards: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        import yaml
        loaded = yaml.safe_load("service: 0x" + "f" * 5000)
        self.assertIsInstance(loaded["service"], int)
        with self.assertRaises(ValueError):
            str(loaded["service"])


class BookmarksOverCapIntTests(unittest.TestCase):
    """GET /api/bookmarks must survive already-int over-cap YAML leftovers."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def _list(self, links, overrides=None, idx=None):
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"quick_links": links, "overrides": overrides or {}},
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value=idx or {}),
            mock.patch.object(
                bookmarks_svc, "_probe",
                return_value={"ok": True, "status": 200, "ms": 1, "error": None},
            ),
        ):
            return bookmarks_svc.list_bookmarks(force=True)

    def test_over_cap_service_key_does_not_500_bookmarks(self):
        """``_index_lookup`` str()'d the already-int key bare — ValueError."""
        data = self._list([
            {"name": "N", "url": "http://nas.local", "service": _HUGE_INT},
        ])
        _starlette(data)
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["name"], "N")

    def test_over_cap_link_id_does_not_500_bookmarks(self):
        data = self._list([
            {"name": "N", "url": "http://nas.local", "id": _HUGE_INT},
        ])
        _starlette(data)
        self.assertEqual(len(data["bookmarks"]), 1)
        # json.dumps cannot render the id at all — same drop as inf floats.
        self.assertIsNone(data["bookmarks"][0]["id"])

    def test_over_cap_name_does_not_500_the_encoder(self):
        """``_jsonable``'s bare int branch let the leftover reach Starlette."""
        data = self._list([
            {"name": _HUGE_INT, "url": "http://nas.local", "service": "n"},
        ])
        _starlette(data)
        self.assertIsNone(data["bookmarks"][0]["name"])

    def test_jsonable_drops_over_cap_int(self):
        cleaned = bookmarks_svc._jsonable({"port": _HUGE_INT, "name": "ok"})
        _starlette(cleaned)
        self.assertIsNone(cleaned["port"])
        self.assertEqual(cleaned["name"], "ok")

    def test_index_lookup_over_cap_int_is_a_miss_not_a_raise(self):
        self.assertIsNone(bookmarks_svc._index_lookup({"a": {"x": 1}}, _HUGE_INT))

    def test_finite_numeric_id_still_matches_backend(self):
        """The fix must be a str() probe, not an isinstance(id, str) gate:
        a numeric YAML ``id: 8080`` keeps matching its backend row."""
        data = self._list(
            [{"name": "N", "url": "http://nas.local", "id": 8080}],
            idx={"8080": {"state": "stopped", "kind": "container", "id": "8080"}},
        )
        self.assertEqual(data["bookmarks"][0]["health"], "stopped")
        self.assertEqual(data["stopped"], 1)

    def test_bool_id_stays_a_miss(self):
        """bool is an int subclass; True must not read as backend id "True"."""
        self.assertIsNone(
            bookmarks_svc._index_lookup({"True": {"state": "stopped"}}, True)
        )

    def test_over_cap_override_sid_keeps_sibling_index_rows(self):
        """One over-cap override sid used to blow up the whole backend index;
        every deliberately-stopped backend then silently probed red."""
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"overrides": {
                    _HUGE_INT: {"expected": "stopped", "url": "http://h/huge"},
                    "good": {"expected": "stopped", "url": "http://h/good"},
                }},
            ),
            mock.patch.object(bookmarks_svc, "fan_out", return_value=[[], [], []]),
        ):
            idx = bookmarks_svc._backend_index()
        self.assertIn("good", idx)
        self.assertEqual(idx["good"]["state"], "stopped")

    def test_over_cap_url_does_not_500_resolve(self):
        """``str(link.get("url") or "")`` str()'d the already-int url bare."""
        self.assertIsNone(
            bookmarks_svc._resolve_backend(
                {"name": "N", "url": _HUGE_INT}, {"x": {"state": "ok"}},
            )
        )


class BookmarksSurrogateLookupKeyTests(unittest.TestCase):
    """Link values are scrubbed by resolve_value; index keys must match."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def test_surrogate_id_still_resolves_its_stopped_backend(self):
        """A leftover ``\\ud800`` in the shared id used to miss the index —
        the deliberately-stopped backend probed red instead of gray."""
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [
                        {"name": "VM", "url": "http://h/vm", "id": "web\ud800"},
                    ],
                    "overrides": {
                        "web\ud800": {"expected": "stopped", "hide": True},
                    },
                },
            ),
            mock.patch.object(bookmarks_svc, "fan_out", return_value=[[], [], []]),
            mock.patch.object(
                bookmarks_svc, "_probe",
                side_effect=AssertionError("a stopped backend must not be probed"),
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        _starlette(data)
        self.assertEqual(data["bookmarks"][0]["health"], "stopped")
        self.assertEqual(data["stopped"], 1)
        self.assertNotIn("\ud800", json.dumps(data, ensure_ascii=False))

    def test_surrogate_backend_url_key_still_matches(self):
        """The ``url:`` index keys get the same scrub as the id keys."""
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{"name": "VM", "url": "http://h/vm\ud800"}],
                    "overrides": {
                        "sid": {
                            "expected": "stopped",
                            "hide": True,
                            "url": "http://h/vm\ud800",
                        },
                    },
                },
            ),
            mock.patch.object(bookmarks_svc, "fan_out", return_value=[[], [], []]),
            mock.patch.object(
                bookmarks_svc, "_probe",
                side_effect=AssertionError("a stopped backend must not be probed"),
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        _starlette(data)
        self.assertEqual(data["bookmarks"][0]["health"], "stopped")

    def test_clean_ids_still_match_unchanged(self):
        idx = {}
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={"overrides": {
                    "grafana": {"expected": "stopped", "url": "http://h/g"},
                }},
            ),
            mock.patch.object(bookmarks_svc, "fan_out", return_value=[[], [], []]),
        ):
            idx = bookmarks_svc._backend_index()
        self.assertIn("grafana", idx)
        self.assertIn("url:http://h/g", idx)

    def test_jsonable_scrubs_surrogate_keys_and_values(self):
        """Survivor pin: the payload scrub already covers keys and values."""
        out = bookmarks_svc._jsonable({"k\ud800": 1, "name": "v\ud800"})
        _starlette(out)
        self.assertFalse(any("\ud800" in k for k in out))
        self.assertNotIn("\ud800", out["name"])


class VanishedNginxCliTests(unittest.TestCase):
    """POST /api/nginx/test and /reload: vanished CLI is the coded 503."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)

    def _test_config(self, sh_result, *, on_disk: bool):
        with (
            mock.patch.object(nginx_svc, "sh", return_value=sh_result),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=on_disk, create=True,
            ),
        ):
            return nginx_svc.test_config()

    def test_vanished_cli_answers_coded_503(self):
        """The sentinel + a disk probe confirming the CLI left -> the same
        coded 503 shape brew.not_found uses, instead of the raw two-word
        sentinel the SPA cannot translate."""
        with self.assertRaises(HTTPException) as caught:
            self._test_config((-1, "", "not found"), on_disk=False)
        self.assertEqual(_code(caught.exception), "nginx.not_found")
        self.assertEqual(caught.exception.status_code, 503)

    def test_sentinel_with_cli_on_disk_keeps_raw_result(self):
        """rc -1 with nginx still present (a cwd that vanished raises the
        same FileNotFoundError) must not be blamed on the binary."""
        out = self._test_config((-1, "", "not found"), on_disk=True)
        self.assertEqual(out, {"ok": False, "message": "not found"})

    def test_real_exit_saying_not_found_keeps_raw_result(self):
        """A genuine nginx exit whose stderr reads "not found" is that
        config's own truth, not a vanished CLI."""
        out = self._test_config((1, "", "not found"), on_disk=False)
        self.assertEqual(out, {"ok": False, "message": "not found"})

    def test_reload_vanish_after_test_answers_coded_503(self):
        """nginx vanished between ``-t`` and ``-s reload``: the disk confirm
        runs on the failure path and answers the coded 503 instead of
        kicking launchd at a binary that is gone."""
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "ok", ""), (-1, "", "not found"), (0, "", "")],
            ),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=False, create=True,
            ),
        ):
            with self.assertRaises(HTTPException) as caught:
                nginx_svc.reload_nginx()
        self.assertEqual(_code(caught.exception), "nginx.not_found")
        self.assertEqual(caught.exception.status_code, 503)

    def test_reload_sentinel_with_cli_on_disk_falls_back_to_kickstart(self):
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "ok", ""), (-1, "", "not found"), (0, "", "")],
            ),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True, create=True,
            ),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            out = nginx_svc.reload_nginx()
        self.assertTrue(out["ok"])


if __name__ == "__main__":
    unittest.main()
