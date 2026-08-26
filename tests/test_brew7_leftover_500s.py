"""Seventh leftover-500s sweep: brew listing / autostart JSON responses.

Hunted over ``create_app()`` + TestClient(raise_server_exceptions=False).
The brew6 wave sealed the autostart plist-write 409 and the brew-action
subclass tail; this sweep found four live leftovers in the neighbouring
brew/autostart surfaces and fixed them:

GET /api/brew/services (text fallback, ``brew services list`` without --json)
* the fallback tail runs outside the spawn try, so a leftover
  bytes-subclass ``out`` whose bound ``.decode`` raises **500'd** the list,
  and a numeric-subclass rc whose ``__ne__`` raises did the same at the
  ``rc != 0`` gate.  Both now degrade through unbound base calls
  (``_as_text`` / ``_plain_rc``).

POST /api/apps/autostart (kind ``brew:``)
* the vanished-brew sentinel check and the ``ok`` render run *outside* the
  spawn try (deliberately, so the coded 503 raise cannot be swallowed) —
  a leftover numeric-subclass rc whose ``__eq__`` raises **500'd** the
  toggle after brew had already run.  ``_plain_rc`` now coerces it; the
  disk-confirmed 503 and no-false-503 behaviour are pinned unchanged.
* a bytes-subclass message whose bound ``.decode`` raises used to turn a
  successful rc=0 toggle into ``{ok: false, message: "decode bomb"}``; the
  unbound ``_as_text`` keeps the real message and the real ok.

POST /api/apps/autostart (kind ``launchd:`` / ``script:``)
* ``_as_text(out or err)`` asked the raw launchctl output for truth and then
  encoded it bound: a str-subclass ``__bool__`` / ``.encode`` bomb **500'd**
  the toggle after launchctl had already run;
* an over-cap rc (hex-minted ints dodge CPython's digit cap) ValueError'd
  the bare ``f"bootout rc={rc}"`` render and **500'd** the same way.
  Both now degrade (``_rc_note`` / unbound ``_as_text``), with surrogates
  scrubbed out of the message.

Nested unbound coercions (brew_cache._json_safe, the docker_cli convention)
* a dict-subclass snapshot row whose ``items``/``get``/``__bool__`` raises,
  or a nested int/float/str/bytes-subclass field bomb
  (``__str__``/``__eq__``/``encode``/``decode``), used to raise out of
  ``_copy_items`` and wipe **every** brew row from GET /api/brew/services
  and GET /api/apps/autostart for the whole TTL.  The unbound base reads
  (``dict.items``, ``base.__iter__``, ``int.__index__``, ``float.__float__``,
  ``str.encode``, ``bytes.decode``) now cost at most the poisoned value.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import autostart_svc, brew_cache, brew_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_INT = int("f" * 4400, 16)

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


class _CmpBombInt(int):
    """rc whose comparisons raise — both slots, unlike brew6's eq-only bomb."""

    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    def __ne__(self, other):
        raise RuntimeError("int ne bomb")

    __hash__ = int.__hash__


class _StrBombInt(int):
    def __str__(self):
        # RuntimeError, not ValueError: the bare digit-cap probe missed it.
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __hash__ = float.__hash__


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _EncodeBombStr(str):
    """Self-``__str__``: str() keeps the subclass, so bound encode still bombs."""

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")

    def splitlines(self, *args, **kwargs):
        raise RuntimeError("splitlines bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")

    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class BrewListFallbackTailTests(unittest.TestCase):
    """GET /api/brew/services when the JSON path yields nothing."""

    def _get(self, fallback):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "brew_services_list", return_value=[]),
            mock.patch.object(brew_svc, "sh", return_value=fallback),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        return resp

    def test_decode_bomb_bytes_output_still_renders_its_rows(self):
        resp = self._get((0, _DecodeBombBytes(b"Name Status\nredis started\n"), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = {r["id"]: r for r in resp.json()["services"]}
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")

    def test_ne_bomb_rc_zero_still_renders_not_500s(self):
        resp = self._get((_CmpBombInt(0), "Name Status\nredis started\n", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["id"] for r in resp.json()["services"]], ["redis"]
        )

    def test_ne_bomb_nonzero_rc_reads_as_failure_not_500(self):
        resp = self._get((_CmpBombInt(1), "Name Status\nredis started\n", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_splitlines_bomb_str_output_still_renders(self):
        # _as_text launders the subclass to an exact str before the walk.
        resp = self._get((0, _EncodeBombStr("Name Status\nredis started"), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["id"] for r in resp.json()["services"]], ["redis"]
        )

    def test_surrogate_in_fallback_output_scrubs_not_500s(self):
        resp = self._get((0, "Name Status\nredis\ud800 started\n", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])


class BrewListNestedSubclassBombTests(unittest.TestCase):
    """Live rows with subclass bombs cost at most the poisoned value now."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", disk)
        patched.start()
        self.addCleanup(patched.stop)
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)

    def _rows(self, live_rows) -> dict:
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(0, live_rows, "")),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            resp = client().get("/api/brew/services")
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {r["id"]: r for r in resp.json()["services"]}

    def test_items_get_bool_bomb_rows_keep_their_real_pairs(self):
        rows = self._rows([
            _ItemsBombDict(name="a", status="started"),
            {"name": "b", "status": "stopped"},
        ])
        self.assertEqual(sorted(rows), ["a", "b"])
        self.assertEqual(rows["a"]["status"], "started")

    def test_nested_field_bombs_cost_the_field_never_the_sibling_rows(self):
        rows = self._rows([
            {"name": "a", "status": "started", "exit_code": _StrBombInt(7)},
            {"name": "b", "status": "started", "exit_code": _EqBombFloat(1.5)},
            {"name": "c", "status": "started", "user": _DecodeBombBytes(b"svc")},
            {"name": _EncodeBombStr("d"), "status": "started"},
            {"name": "e", "status": "started", "exit_code": 0},
        ])
        self.assertEqual(sorted(rows), ["a", "b", "c", "d", "e"])
        # __str__ bomb int: the unbound int.__index__ coercion keeps 7.
        self.assertEqual(rows["a"]["exit_code"], 7)
        # __eq__ bomb float: the unbound float.__float__ coercion keeps 1.5.
        self.assertEqual(rows["b"]["exit_code"], 1.5)
        # decode-bomb bytes: the unbound bytes.decode keeps the text.
        self.assertEqual(rows["c"]["user"], "svc")
        self.assertEqual(rows["e"]["exit_code"], 0)

    def test_iter_bomb_list_field_costs_the_field_not_the_row(self):
        rows = self._rows([
            {"name": "a", "status": "started", "user": _IterBombList(["x"])},
        ])
        self.assertIn("a", rows)
        # brew_svc's flat _json_safe drops non-scalar user fields entirely.
        self.assertIsNone(rows["a"]["user"])

    def test_hex_minted_over_cap_exit_code_still_drops_alone(self):
        rows = self._rows([
            {"name": "a", "status": "started", "exit_code": _HUGE_INT},
        ])
        self.assertIn("a", rows)
        self.assertIsNone(rows["a"]["exit_code"])

    def test_primed_bomb_rows_keep_the_autostart_brew_rows(self):
        # The same bombs primed straight into the shared snapshot used to
        # wipe every Homebrew row from GET /api/apps/autostart for the TTL.
        with brew_cache._lock:
            brew_cache._cache["t"] = float("inf")
            brew_cache._cache["v"] = [
                _ItemsBombDict(name="redis", status="started"),
                {"name": "glances", "status": "none",
                 "exit_code": _StrBombInt(3)},
            ]
        with (
            mock.patch.object(autostart_svc, "_is_file", return_value=True),
            mock.patch.object(autostart_svc, "sh", return_value=(0, "", "")),
        ):
            autostart_svc.overview.invalidate()
            resp = client().get("/api/apps/autostart?force=true")
            autostart_svc.overview.invalidate()
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        brew_rows = {
            i["name"]: i for i in resp.json()["items"]
            if i.get("kind") == "brew"
        }
        self.assertEqual(sorted(brew_rows), ["glances", "redis"])
        self.assertTrue(brew_rows["redis"]["running"])


class BrewAutostartToggleTailTests(unittest.TestCase):
    """POST /api/apps/autostart (brew kind): the tail runs outside the try."""

    def _toggle(self, stub, *, present=None, enabled=True):
        if present is None:
            file_patch = mock.patch.object(
                autostart_svc, "_is_file", return_value=True
            )
        else:
            file_patch = mock.patch.object(
                autostart_svc, "_is_file", side_effect=present
            )
        with (
            file_patch,
            mock.patch.object(autostart_svc, "run_capped", return_value=stub),
        ):
            resp = client().post(
                "/api/apps/autostart",
                json={"id": "brew:redis", "enabled": enabled},
            )
        _assert_clean(self, resp)
        return resp

    def test_eq_bomb_rc_zero_still_answers_ok_true(self):
        resp = self._toggle((_CmpBombInt(0), "Started redis"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "Started redis")
        self.assertTrue(payload["autostart"])

    def test_eq_bomb_nonzero_rc_degrades_to_ok_false_not_500(self):
        resp = self._toggle((_CmpBombInt(2), "boom"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertIsNone(payload["autostart"])

    def test_decode_bomb_message_keeps_the_real_ok_and_text(self):
        # The bound-decode raise used to trip the broad except and report a
        # successful start as {ok: false, message: "decode bomb"}.
        resp = self._toggle((0, _DecodeBombBytes(b"Successfully started redis")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "Successfully started redis")

    def test_encode_bomb_surrogate_message_scrubs(self):
        resp = self._toggle((1, _EncodeBombStr("bad \ud800 tail")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["message"], "bad ? tail")

    def test_hex_minted_over_cap_rc_degrades_not_500s(self):
        resp = self._toggle((_HUGE_INT, "noise"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["ok"])

    def test_vanished_brew_sentinel_survives_subclass_shapes(self):
        # The coded 503 fires ONLY after the disk re-confirms brew is gone,
        # and must survive an eq-bomb rc and a decode-bomb "not found".
        resp = self._toggle(
            (_CmpBombInt(-1), _DecodeBombBytes(b"not found")),
            present=[True, False],
        )
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "brew.not_found")

    def test_sentinel_with_brew_still_present_keeps_the_raw_result(self):
        # A signal-killed brew is also rc -1: no false "not installed" lie.
        resp = self._toggle((-1, "not found"), present=[True, True])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")


_PLIST_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>/bin/true</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
"""


class LaunchdToggleLogTailTests(unittest.TestCase):
    """POST /api/apps/autostart (launchd kind): the launchctl log render."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agents = Path(self._tmp.name)
        (self.agents / "com.test.thing.plist").write_text(
            _PLIST_TMPL.format(label="com.test.thing"), encoding="utf-8"
        )
        patched = mock.patch.object(autostart_svc, "AGENTS_DIR", self.agents)
        patched.start()
        self.addCleanup(patched.stop)
        autostart_svc.overview.invalidate()
        self.addCleanup(autostart_svc.overview.invalidate)

    def _toggle(self, sh_result, *, enabled=False):
        with mock.patch.object(
            autostart_svc, "sh", return_value=sh_result
        ):
            resp = client().post(
                "/api/apps/autostart",
                json={"id": "launchd:com.test.thing", "enabled": enabled},
            )
        _assert_clean(self, resp)
        return resp

    def test_bool_and_encode_bomb_launchctl_output_degrades_not_500s(self):
        # ``out or err`` used to ask the subclass for truth, then encode it
        # bound — either bomb 500'd the toggle after launchctl already ran.
        resp = self._toggle(
            (0, _EncodeBombStr("loaded \ud800 ok"), ""), enabled=True
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertIn("loaded ? ok", payload["message"])

    def test_over_cap_rc_renders_rc_unknown_not_500(self):
        resp = self._toggle((_HUGE_INT, "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("bootout rc=unknown", resp.json()["message"])

    def test_cmp_bomb_rc_still_renders_its_base_value(self):
        # _plain_rc's unbound int.__index__ keeps the real 3 past the bombs.
        resp = self._toggle((_CmpBombInt(3), "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("bootout rc=3", resp.json()["message"])

    def test_decode_bomb_stderr_still_reaches_the_message(self):
        resp = self._toggle((1, "", _DecodeBombBytes(b"no such service")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("no such service", resp.json()["message"])

    def test_plain_rc_still_renders_verbatim(self):
        resp = self._toggle((0, "", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("bootout rc=0", resp.json()["message"])


if __name__ == "__main__":
    unittest.main()
