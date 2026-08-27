"""Host8 leftover sweep: _json_tree/_json_atom raw-500s on the scheduler surfaces.

A hostile re-sweep of the host scheduler/plist surfaces over ``create_app()``
+ ``TestClient(raise_server_exceptions=False)``, after host7 sealed
``_plist_jsonable`` and the launchd plist readers, found the *other* tree
sanitizer — ``system_settings_svc._json_tree`` and its scalar sibling
``_json_atom`` — still detonating on two leftover shapes its tools_svc twin
already survives:

* **The ``isoformat`` probe ran unwrapped.**  ``getattr(value, "isoformat",
  None)`` only swallows AttributeError; a leftover object whose ``isoformat``
  is a *raising property* blew the probe itself and 500'd every route that
  rides ``_json_tree`` — GET /api/scheduler, GET /api/system/scheduler and
  GET /api/settings/scheduler (whose row builder reads labels through
  ``_json_atom``, which carried the same bare probe).  ``_plist_jsonable``
  wrapped this exact getattr in host7; the settings-side twins never did.

* **Every bytes arm coerced through ``bytes(value)``.**  The constructor
  dispatches into a subclass's own ``__bytes__``, so a bytes-subclass value
  whose ``__bytes__`` bombs raised out of ``_utf8_text`` / ``_as_text`` /
  ``_json_atom`` / ``_json_tree`` (both the value arm and the dict-key arm)
  and out of ``get_thresholds``' key laundering — a raw 500 on the scheduler
  trio and GET /api/settings/thresholds, while the same subclass rendered
  fine through ``tools_svc._as_text``'s unbound ``bytes.decode`` read.  The
  unbound base decode survives both the ``__bytes__`` bomb and the bound
  ``.decode`` bomb the old comment worried about, and salvages the real
  C-level bytes instead of dropping them.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import system_settings_svc, tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import unraid_parity


class IsoPropBomb:
    """``getattr(x, "isoformat")`` raises: the probe itself must not 500."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")

    def __str__(self):
        return "IsoPropBomb"


class BytesBomb(bytes):
    """Passes ``isinstance(x, bytes)``; ``bytes(x)`` and bound decode raise."""

    def __bytes__(self):
        raise RuntimeError("bytes bomb")

    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class ByteArrayBomb(bytearray):
    """The bytearray twin: same two bound-dispatch bombs."""

    def __bytes__(self):
        raise RuntimeError("bytes bomb")

    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class _HttpPin(unittest.TestCase):
    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The body Starlette encoded must be re-encodable under the same
        # allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class _SchedulerTrioPin(_HttpPin):
    """Drive all three scheduler views over one leftover timers answer.

    /api/scheduler holds its own import-time reference to launchd_timers,
    so both the tools_svc attribute and the router's copy are patched.
    """

    def _bodies(self, timers) -> dict[str, dict]:
        client = self._client()
        with (
            mock.patch.object(tools_svc, "launchd_timers", return_value=timers),
            mock.patch.object(
                unraid_parity, "launchd_timers", return_value=timers,
            ),
        ):
            return {
                path: self._ok_body(client.get(path))
                for path in (
                    "/api/scheduler",
                    "/api/system/scheduler",
                    "/api/settings/scheduler",
                )
            }


class IsoformatPropertyBombPins(_SchedulerTrioPin):
    """A raising ``isoformat`` property must cost the probe, not the route."""

    def test_iso_prop_bomb_calendar_renders_not_500(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "calendar": IsoPropBomb()},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler"):
            row = bodies[path]["timers"][0]
            # The probe falls through to the text scrub: the value's own
            # readable form survives instead of the whole route dying.
            self.assertEqual(row["calendar"], "IsoPropBomb")
            self.assertEqual(row["label"], "com.example.job")
        slim = bodies["/api/settings/scheduler"]["timers"][0]
        self.assertEqual(slim["calendar"], "IsoPropBomb")

    def test_iso_prop_bomb_label_reads_through_json_atom(self):
        # get_scheduler_summary reads labels via _json_atom, whose probe
        # carried the same bare getattr.
        bodies = self._bodies([
            {"label": IsoPropBomb(), "interval_sec": 60},
        ])
        slim = bodies["/api/settings/scheduler"]["timers"][0]
        self.assertEqual(slim["label"], "IsoPropBomb")


class BytesSubclassBombPins(_SchedulerTrioPin):
    """``__bytes__``/decode bombs salvage their real bytes, never 500."""

    def test_bytes_bomb_value_salvages_the_text(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "program": BytesBomb(b"/bin/echo hi")},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler"):
            row = bodies[path]["timers"][0]
            self.assertEqual(row["program"], "/bin/echo hi")

    def test_bytearray_bomb_value_salvages_the_text(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "program": ByteArrayBomb(b"/bin/echo hi")},
        ])
        row = bodies["/api/system/scheduler"]["timers"][0]
        self.assertEqual(row["program"], "/bin/echo hi")

    def test_bytes_bomb_calendar_key_salvages_the_key(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "calendar": {BytesBomb(b"Minute"): 5}},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler",
                     "/api/settings/scheduler"):
            row = bodies[path]["timers"][0]
            self.assertEqual(row["calendar"], {"Minute": 5})

    def test_non_utf8_bytes_bomb_still_answers_clean_utf8(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "program": BytesBomb(b"\xff\xfehi")},
        ])
        row = bodies["/api/system/scheduler"]["timers"][0]
        self.assertIn("hi", row["program"])


class ThresholdsBytesKeyPin(_HttpPin):
    """GET /api/settings/thresholds launders keys through the same arm."""

    def test_bytes_bomb_threshold_key_salvages_not_500(self):
        client = self._client()
        with mock.patch.object(
            system_settings_svc, "settings_section",
            return_value={BytesBomb(b"cpu_pct"): 50},
        ):
            body = self._ok_body(client.get("/api/settings/thresholds"))
        self.assertEqual(body["cpu_pct"], 50)


class SanitizerUnitPins(unittest.TestCase):
    """Direct pins so the diagnostics/bundle riders of _json_tree hold too."""

    def test_json_tree_iso_prop_bomb_falls_to_text(self):
        self.assertEqual(
            system_settings_svc._json_tree(IsoPropBomb()), "IsoPropBomb",
        )

    def test_json_atom_iso_prop_bomb_falls_to_text(self):
        self.assertEqual(
            system_settings_svc._json_atom(IsoPropBomb()), "IsoPropBomb",
        )

    def test_json_tree_bytes_bomb_base_decodes(self):
        self.assertEqual(system_settings_svc._json_tree(BytesBomb(b"ok")), "ok")
        self.assertEqual(
            system_settings_svc._json_tree({BytesBomb(b"k"): 1}), {"k": 1},
        )

    def test_json_atom_bytes_bomb_base_decodes(self):
        self.assertEqual(system_settings_svc._json_atom(BytesBomb(b"ok")), "ok")

    def test_text_scrubbers_bytes_bomb_base_decode(self):
        self.assertEqual(system_settings_svc._utf8_text(BytesBomb(b"ok")), "ok")
        self.assertEqual(system_settings_svc._as_text(BytesBomb(b"ok")), "ok")
        self.assertEqual(
            system_settings_svc._utf8_text(ByteArrayBomb(b"ok")), "ok",
        )


if __name__ == "__main__":
    unittest.main()
