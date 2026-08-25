"""Leftover Logs-page 500s/silent losses: hex-YAML already-int ids and
names in ``log_sources``, plus surrogate id/name/path route pins.

The earlier logs sweeps hardened the *values* GET /api/logs emits
(``_stat_size`` float-probes over-cap st_size, ``_utf8_text`` re-encodes
strings).  This sweep covers the config shapes that dodged those guards:

* YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
  CPython's 4300-digit conversion limit), so a hand-edited leftover
  ``log_sources: [{id: 0x2A, …}]`` arrives *already-int*.  The original
  panel accepted numeric ids verbatim (``"id": s["id"]``); the hardening
  sweep's strict ``isinstance(id, str)`` gate then silently HID the whole
  configured source from GET /api/logs — and GET /api/logs/{id} 404'd a
  source that is right there in services.yaml.  A numeric ``name:`` was
  silently replaced by the id the same way.  The fix follows the UPS /
  Dashboard rule: a renderable int coerces through a ``str()`` probe, and
  only an unrenderable >4300-digit leftover (whose ``str()`` — and
  therefore ``json.dumps`` — is the digit-cap ValueError) drops its entry;
* a bool id (``id: true`` passes ``isinstance(int)``) must NOT coerce to
  ``"True"`` — the bool-as-int rule the UPS worker-pid fix pinned;
* leftover ``\\ud800`` in id/name/path stays replace-encoded through the
  actual route (Starlette ``ensure_ascii=False`` then UTF-8 encode).

The two remaining leftover classes from the other domains have no surface
here and are deliberately absent: the Logs backend spawns no CLI (tails
are plain file reads, so there is no vanished-CLI 503 to mis-map) and
holds no pids (no ``os.kill`` probe to OverflowError).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import logs_svc  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hub.routers.logs import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class LogSourcesBase(unittest.TestCase):
    """One real log file, config patched per test."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="logs-hexint-pin-")
        self.addCleanup(tmp.cleanup)
        self.log_path = Path(tmp.name) / "pin.log"
        self.log_path.write_text("first\nsecond\n", encoding="utf-8")

    def _with_sources(self, sources):
        return mock.patch.object(
            logs_svc, "cfg", lambda: {"log_sources": sources},
        )


class HexIntSourceIdTests(LogSourcesBase):
    """GET /api/logs keeps a hex-YAML numeric id; only over-cap drops."""

    def test_hex_yaml_loads_past_the_digit_cap(self):
        """The vector this file guards: PyYAML routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        import yaml
        loaded = yaml.safe_load("id: 0x" + "f" * 5000)
        self.assertIsInstance(loaded["id"], int)
        with self.assertRaises(ValueError):
            str(loaded["id"])

    def test_sane_numeric_id_still_lists_and_tails(self):
        """``id: 0x2A`` loads as int 42.  The original panel accepted it;
        the strict isinstance gate silently hid the configured source."""
        with self._with_sources([
            {"id": 42, "name": "Answer", "path": str(self.log_path)},
        ]):
            listing = _client().get("/api/logs")
            tail = _client().get("/api/logs/42")
        self.assertEqual(listing.status_code, 200)
        rows = listing.json()["sources"]
        self.assertEqual([r["id"] for r in rows], ["42"])
        self.assertTrue(rows[0]["exists"])
        self.assertEqual(tail.status_code, 200)
        self.assertIn("second", tail.json()["log"])
        _starlette(tail.json())

    def test_over_cap_id_drops_only_its_entry(self):
        with self._with_sources([
            {"id": _HUGE_INT, "name": "poisoned", "path": str(self.log_path)},
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([r["id"] for r in resp.json()["sources"]], ["ok"])

    def test_bool_id_does_not_coerce_to_true(self):
        """``id: true`` passes isinstance(int); it must not list as "True"."""
        with self._with_sources([
            {"id": True, "name": "flag", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["sources"], [])

    def test_numeric_name_coerces_instead_of_vanishing(self):
        """``name: 2026`` rendered as 2026 before the isinstance gate
        silently replaced it with the id."""
        with self._with_sources([
            {"id": "ok", "name": 2026, "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["sources"][0]["name"], "2026")

    def test_over_cap_name_falls_back_to_the_id(self):
        with self._with_sources([
            {"id": "ok", "name": _HUGE_INT, "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["sources"][0]["name"], "ok")

    def test_bool_name_falls_back_to_the_id(self):
        with self._with_sources([
            {"id": "ok", "name": True, "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["sources"][0]["name"], "ok")

    def test_over_cap_path_drops_only_its_entry(self):
        """``str(path)`` inside the expanduser try is the digit-cap
        ValueError; the entry must drop without costing the listing."""
        with self._with_sources([
            {"id": "poisoned", "name": "P", "path": _HUGE_INT},
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([r["id"] for r in resp.json()["sources"]], ["ok"])

    def test_renderable_int_path_does_not_500_the_listing(self):
        """``path: 42`` stringifies to a relative name (the original panel
        TypeError'd expanduser on it); whether the odd row survives the
        deny-list depends on the cwd, but the healthy sibling and the
        route must."""
        with self._with_sources([
            {"id": "odd", "name": "Odd", "path": 42},
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        rows = resp.json()["sources"]
        self.assertIn("ok", [r["id"] for r in rows])
        self.assertTrue({r["id"] for r in rows} <= {"odd", "ok"})
        _starlette(rows)


class SurrogateSourceRoutePinTests(LogSourcesBase):
    """Leftover ``\\ud800`` in id/name/path must survive the real route
    (Starlette ensure_ascii=False → UTF-8), not just the service call."""

    def test_surrogate_name_and_path_stay_encodable_through_the_route(self):
        with self._with_sources([
            {"id": "ok", "name": "app\ud800", "path": str(self.log_path)},
        ]):
            listing = _client().get("/api/logs")
            tail = _client().get("/api/logs/ok")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(tail.status_code, 200)
        self.assertNotIn("\ud800", json.dumps(listing.json(), ensure_ascii=False))
        self.assertNotIn("\ud800", json.dumps(tail.json(), ensure_ascii=False))
        _starlette(listing.json())
        _starlette(tail.json())

    def test_surrogate_id_lists_replace_encoded(self):
        with self._with_sources([
            {"id": "app\ud800", "name": "App", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        rows = resp.json()["sources"]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["id"])
        _starlette(rows)

    def test_huge_already_int_lines_still_clamps(self):
        """tail_log's own clamp (callers besides the Query-validated route)
        must not trip on an *already-int* over-cap value: ``int(huge)`` has
        no conversion to fail, and min() never renders it."""
        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            out = logs_svc.tail_log("ok", _HUGE_INT)
        self.assertEqual(out["lines"], 2)
        _starlette(out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
