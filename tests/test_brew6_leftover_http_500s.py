"""Sixth leftover-500s sweep of the Homebrew / brew-services surfaces.

Hunted over ``create_app()`` + TestClient(raise_server_exceptions=False).
Two live leftovers were found and fixed; the rest of the battery pins
neighbouring vectors that were already immune so they cannot regress.

POST /api/apps/autostart (launchd / script kinds, homebrew.mxcl.* included)
* ``plistlib.loads`` accepts any ``<integer>`` — the ``0x…`` spelling parses
  uncapped past CPython's 4300-digit limit — but the dumps writer refuses
  ints outside the 64-bit window with OverflowError.  Toggling RunAtLoad on
  an agent whose plist carries such a value passed the ``bad_plist`` gate,
  parsed cleanly, and then **500'd** at ``_write_plist`` (the files_svc
  /ondemand class, leftover in autostart_svc).
* an unwritable LaunchAgents dir made ``secure_io.replace_bytes`` raise
  OSError out of the same call and **500** the toggle.
  Both are now the coded 409 ``catalog.plist_write_failed`` with the on-disk
  plist intact.

POST /api/brew/services/{name}/action
* the post-spawn tail (the vanished-brew sentinel check, ``ok`` and the
  ``exit {rc}`` render) runs *outside* the spawn try — deliberately, so the
  coded 503 raise cannot be swallowed — which meant a leftover
  numeric-subclass rc whose ``__eq__`` raises, or a bytes-subclass message
  whose bound ``.decode`` raises, **500'd** the action after the run had
  already finished.  ``_plain_rc`` + unbound ``bytes.decode`` /
  ``str.encode`` now degrade them; the disk-confirmed vanished-CLI 503 and
  the no-false-503 behaviour for a still-present brew are pinned unchanged.

Stays-immune pins
* a FIFO occupying a LaunchAgent plist is read O_NONBLOCK-capped: the GET
  renders and the toggle answers the coded 400, never a hang;
* dict-subclass ``.get`` / ``items`` / ``__bool__`` bombs in the live brew
  list or the primed shared snapshot cost at most their own rows on
  GET /api/brew/services and GET /api/apps/autostart, never the request.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import autostart_svc, brew_cache, brew_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_client = None


def client() -> TestClient:
    global _client
    if _client is None:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        # The SPA's failure mode is what is under test, not exception
        # propagation into the test process.
        _client = TestClient(app, raise_server_exceptions=False)
    return _client


def _assert_clean(test: unittest.TestCase, resp) -> None:
    """The body must be strictly renderable UTF-8 with no lone surrogates."""
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")


def _noop_sh(*args, **kwargs):
    return (0, "", "")


_PLIST_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>/opt/homebrew/bin/redis-server</string></array>
<key>RunAtLoad</key><true/>
{extra}
</dict></plist>
"""


class AutostartPlistWriteFailureTests(unittest.TestCase):
    """POST /api/apps/autostart launchd toggles against hostile plist state."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agents = Path(self._tmp.name)
        for patched in (
            mock.patch.object(autostart_svc, "AGENTS_DIR", self.agents),
            mock.patch.object(autostart_svc, "sh", _noop_sh),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        autostart_svc.overview.invalidate()
        self.addCleanup(autostart_svc.overview.invalidate)

    def _plist(self, label: str, extra: str = "") -> Path:
        path = self.agents / f"{label}.plist"
        path.write_text(
            _PLIST_TMPL.format(label=label, extra=extra), encoding="utf-8"
        )
        return path

    def _toggle(self, label: str, enabled: bool = False):
        resp = client().post(
            "/api/apps/autostart",
            json={"id": f"launchd:{label}", "enabled": enabled},
        )
        _assert_clean(self, resp)
        return resp

    def test_out_of_range_plist_integer_is_the_coded_409_file_intact(self):
        # 2^64: loads() parses it, the dumps writer OverflowErrors it.
        path = self._plist(
            "homebrew.mxcl.redis",
            "<key>LegacyTimers</key><integer>18446744073709551616</integer>",
        )
        before = path.read_bytes()
        resp = self._toggle("homebrew.mxcl.redis")
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog.plist_write_failed"
        )
        # Mutate failed: the live agent must not have been half-written.
        self.assertEqual(path.read_bytes(), before)

    def test_hex_over_cap_plist_integer_is_the_coded_409(self):
        # ``0x…`` parses through int(x, 16), uncapped — a real over-cap int
        # exists in the parsed plist and str(OverflowError(it)) is itself the
        # digit-cap ValueError; the coded body must still render clean.
        path = self._plist(
            "homebrew.mxcl.hexy",
            "<key>Nice</key><integer>0x" + "f" * 4400 + "</integer>",
        )
        before = path.read_bytes()
        resp = self._toggle("homebrew.mxcl.hexy", enabled=True)
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog.plist_write_failed"
        )
        self.assertEqual(path.read_bytes(), before)

    def test_unwritable_agents_dir_is_the_coded_409_file_intact(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        path = self._plist("homebrew.mxcl.ok")
        before = path.read_bytes()
        os.chmod(self.agents, 0o555)
        self.addCleanup(os.chmod, self.agents, 0o755)
        resp = self._toggle("homebrew.mxcl.ok")
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog.plist_write_failed"
        )
        self.assertEqual(path.read_bytes(), before)

    def test_clean_plist_toggle_still_writes_and_answers_ok(self):
        path = self._plist("homebrew.mxcl.clean")
        resp = self._toggle("homebrew.mxcl.clean")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])
        import plistlib

        self.assertFalse(plistlib.loads(path.read_bytes())["RunAtLoad"])

    def test_a_fifo_plist_is_the_coded_400_not_a_hang(self):
        # A plain open() of a FIFO parks until a writer appears; the capped
        # reader opens O_NONBLOCK, so this is "unreadable plist", not a hang.
        os.mkfifo(self.agents / "homebrew.mxcl.fifo.plist")
        resp = self._toggle("homebrew.mxcl.fifo")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "autostart.bad_plist")
        listing = client().get("/api/apps/autostart?force=true")
        _assert_clean(self, listing)
        self.assertEqual(listing.status_code, 200, listing.text[:300])


class _EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    __hash__ = int.__hash__


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    def __float__(self):
        raise RuntimeError("float bomb")

    __hash__ = float.__hash__


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _EncodeBombStr(str):
    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class BrewActionSubclassTailTests(unittest.TestCase):
    """POST /api/brew/services/{name}/action: the tail runs outside the try."""

    def _act(self, stub, *, present=True):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=present),
            mock.patch.object(brew_svc, "run_capped", return_value=stub),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "start"}
            )
        _assert_clean(self, resp)
        return resp

    def test_int_subclass_eq_bomb_rc_degrades_not_500s(self):
        resp = self._act((_EqBombInt(2), "no"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "no")

    def test_float_subclass_eq_bomb_rc_degrades_not_500s(self):
        # __float__ is also overridden: _plain_rc's *unbound*
        # float.__float__ call dodges both bombs and keeps the base value.
        resp = self._act((_EqBombFloat(1.5), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit 1.5")

    def test_bytes_subclass_decode_bomb_message_degrades_not_500s(self):
        resp = self._act((0, _DecodeBombBytes(b"started redis")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "started redis")

    def test_str_subclass_encode_bomb_message_with_surrogate_scrubs(self):
        # str.encode's "replace" substitutes "?" for the unencodable half.
        resp = self._act((1, _EncodeBombStr("bad \ud800 tail")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "bad ? tail")

    def test_non_numeric_rc_is_exit_unknown_not_500(self):
        resp = self._act((object(), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit unknown")

    def test_vanished_brew_sentinel_survives_subclass_shapes(self):
        # The coded 503 fires ONLY after the disk re-confirms brew is gone,
        # and must survive an eq-bomb rc and a decode-bomb "not found".
        present = iter([True, False])
        with (
            mock.patch.object(
                brew_svc, "_brew_present", side_effect=lambda: next(present)
            ),
            mock.patch.object(
                brew_svc,
                "run_capped",
                return_value=(_EqBombInt(-1), _DecodeBombBytes(b"not found")),
            ),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "start"}
            )
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "brew.not_found")

    def test_sentinel_with_brew_still_present_keeps_the_raw_result(self):
        # A signal-killed brew is also rc -1: no false "not installed" lie.
        resp = self._act((-1, "not found"), present=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _GetBombDict(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class BrewListSubclassBombStaysImmuneTests(unittest.TestCase):
    """dict-subclass bombs cost at most their rows, never the request."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", disk)
        patched.start()
        self.addCleanup(patched.stop)
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)

    def _get_live(self, rows):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(0, rows, "")),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def _prime(self, rows):
        with brew_cache._lock:
            brew_cache._cache["t"] = float("inf")
            brew_cache._cache["v"] = rows

    def test_live_get_and_bool_bomb_rows_still_render(self):
        resp = self._get_live([
            _GetBombDict(name="a", status="started"),
            _BoolBombDict(name="b", status="stopped"),
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        names = sorted(r["id"] for r in resp.json()["services"])
        self.assertEqual(names, ["a", "b"])

    def test_live_items_bomb_costs_the_rows_never_the_request(self):
        resp = self._get_live([_ItemsBombDict(name="a", status="started")])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_primed_snapshot_bombs_never_500_either_page(self):
        for row in (
            _ItemsBombDict(name="a", status="started"),
            _GetBombDict(name="a", status="started"),
        ):
            self._prime([row])
            with mock.patch.object(brew_svc, "_brew_present", return_value=True):
                resp = client().get("/api/brew/services")
            _assert_clean(self, resp)
            self.assertEqual(resp.status_code, 200, resp.text[:300])

            self._prime([row])
            with (
                mock.patch.object(autostart_svc, "_is_file", return_value=True),
                mock.patch.object(autostart_svc, "sh", _noop_sh),
            ):
                autostart_svc.overview.invalidate()
                listing = client().get("/api/apps/autostart?force=true")
                autostart_svc.overview.invalidate()
            _assert_clean(self, listing)
            self.assertEqual(listing.status_code, 200, listing.text[:300])


if __name__ == "__main__":
    unittest.main()
