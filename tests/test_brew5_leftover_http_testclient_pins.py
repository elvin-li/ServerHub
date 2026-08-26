"""Fifth leftover-500s sweep of the Brew page, over TestClient this time.

The brew4 battery (tests/test_brew4_leftover_http_stays_immune.py) drives
``create_app()`` through a hand-rolled ASGI cycle.  This sweep re-hunted the
leftover classes (iterbombs, over-cap ints, lone surrogates, vanished-CLI
503s) through Starlette's TestClient — real request building, httpx percent
handling, and the actual response render — and found **no live 500**: the
service/cache hardening in ``hub.brew_svc`` / ``hub.brew_cache`` plus the
sanitizing handlers in ``hub.app_factory`` / ``hub.errors`` already cover
every vector.  What follows pins the vectors brew4 did *not*, so the
immunity cannot silently regress:

GET /api/brew/services
* live `brew services list --json` output arriving as **bytes** still
  renders its rows;
* RFC-valid ``1e999`` / ``-1e999`` exponents (json.loads mints ``inf``
  without the ``Infinity`` literal) and an over-cap *float* digit run cost
  the field, never the row (Starlette encodes with allow_nan=False);
* a deeply-nested live document (the ``safe_json_loads`` RecursionError
  path) keeps the last-good disk journal instead of 500ing or wiping rows;
* a leftover FIFO, directory, multi-MB file, or invalid-UTF-8 bytes at
  data/brew-services.cache.json is "no journal", never a hang (O_NONBLOCK)
  and never a 500;
* ``1e999`` / ``NaN`` inside the journal keep the row, drop the field;
* a primed hostile snapshot (hex-minted over-cap int name, bytes
  name/status, tuple key, NaN nested in ``user``, a 40-deep ``user`` nest —
  the iterbomb class) renders clean through the depth-capped scrub.

POST /api/brew/services/{name}/action
* percent-encoded newline / NUL / lone-surrogate bytes / over-length /
  option-like names are the coded 400 and never reach the spawn;
* an invalid-UTF-8 body, a ``NaN`` / ``1e999`` action (whose value FastAPI
  echoes back in ``detail[].input``), and an over-cap int in *any* body
  field are 4xx with a strictly-UTF-8-renderable body;
* a 5000-char action string is the coded ``brew.bad_action`` 400;
* hostile spawn results (bytes message, NaN rc, wrong-arity stub tuples)
  degrade to ``{ok: false, message}``, never 500.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import brew_cache, brew_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
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
    # Starlette already encoded it once; re-encoding strictly proves it.
    text.encode("utf-8")


class _BrewSandbox(unittest.TestCase):
    """Empty snapshot, private disk journal, and a brew that is 'installed'."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.disk = Path(self._tmp.name) / "brew-services.cache.json"
        patched = mock.patch.object(brew_cache, "_DISK", self.disk)
        patched.start()
        self.addCleanup(patched.stop)
        brew_cache.invalidate_brew_services()
        self.addCleanup(brew_cache.invalidate_brew_services)

    def _get(self, *, live, busy=False, present=True, fallback=(1, "", "")):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=present),
            mock.patch.object(brew_cache, "_brew_busy", return_value=busy),
            mock.patch.object(brew_cache, "sh", return_value=live),
            mock.patch.object(brew_svc, "sh", return_value=fallback),
        ):
            return client().get("/api/brew/services")

    def _get_busy_no_spawn(self):
        """Busy-brew cold start: the journal is the only possible source."""
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=True),
            mock.patch.object(
                brew_cache, "sh",
                side_effect=AssertionError("busy brew must not spawn"),
            ),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            return client().get("/api/brew/services")

    def _rows(self, resp) -> dict:
        _assert_clean(self, resp)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return {r["id"]: r for r in resp.json()["services"]}


class BrewListLiveOutputShapeTests(_BrewSandbox):
    """GET /api/brew/services against live-output shapes brew4 skipped."""

    def test_bytes_live_output_still_renders_its_rows(self):
        resp = self._get(
            live=(0, b'[{"name":"redis","status":"started","exit_code":0}]', b"")
        )
        rows = self._rows(resp)
        self.assertEqual(sorted(rows), ["redis"])
        self.assertEqual(rows["redis"]["status"], "started")

    def test_exponent_infinity_costs_the_field_not_the_row(self):
        # ``1e999`` is RFC-valid JSON that json.loads mints into float inf
        # without the non-standard Infinity literal brew4 pinned.
        resp = self._get(live=(0, (
            '[{"name":"a","status":"started","exit_code":1e999},'
            ' {"name":"b","status":"stopped","exit_code":-1e999}]'
        ), ""))
        rows = self._rows(resp)
        self.assertEqual(sorted(rows), ["a", "b"])
        self.assertIsNone(rows["a"]["exit_code"])
        self.assertIsNone(rows["b"]["exit_code"])

    def test_over_cap_float_digit_run_costs_the_field_not_the_row(self):
        # float() has no digit cap; a 5000-digit decimal parses to inf and
        # must drop like its exponent sibling instead of 500ing the encode.
        resp = self._get(live=(0, (
            '[{"name":"a","status":"started","exit_code":%s.5}]' % _HUGE_DIGITS
        ), ""))
        rows = self._rows(resp)
        self.assertIsNone(rows["a"]["exit_code"])

    def test_deeply_nested_live_output_keeps_the_last_good_journal(self):
        # safe_json_loads raises RecursionError on the nest; the classifier
        # must treat it as "not a successful list" and keep last-good.
        self.disk.write_text(
            '[{"name":"redis","status":"started","exit_code":0}]',
            encoding="utf-8",
        )
        resp = self._get(live=(0, "[" * 4000 + "]" * 4000, ""))
        rows = self._rows(resp)
        self.assertEqual(sorted(rows), ["redis"])

    def test_unrenderable_names_cost_the_row_never_the_request(self):
        # An over-cap int name and an exponent-inf name cannot become an id;
        # the sibling row must survive them.
        resp = self._get(live=(0, (
            '[{"name":%s,"status":"started"},'
            ' {"name":1e999,"status":"started"},'
            ' {"name":"ok","status":"started"}]'
        ) % _HUGE_DIGITS, ""))
        rows = self._rows(resp)
        self.assertEqual(sorted(rows), ["ok"])


class BrewListHostileDiskJournalTests(_BrewSandbox):
    """Leftover junk occupying data/brew-services.cache.json."""

    def test_a_fifo_journal_is_no_journal_not_a_hang(self):
        # A plain open() of a FIFO parks until a writer appears; the capped
        # reader opens O_NONBLOCK and refuses non-regular files.
        os.mkfifo(self.disk)
        rows = self._rows(self._get_busy_no_spawn())
        self.assertEqual(rows, {})

    def test_a_directory_journal_is_no_journal(self):
        self.disk.mkdir()
        rows = self._rows(self._get_busy_no_spawn())
        self.assertEqual(rows, {})

    def test_an_oversized_journal_is_no_journal(self):
        self.disk.write_bytes(
            b'[{"name":"x","status":"started"}]'
            + b" " * (brew_cache._DISK_CAP + 1)
        )
        rows = self._rows(self._get_busy_no_spawn())
        self.assertEqual(rows, {})

    def test_invalid_utf8_journal_bytes_are_no_journal(self):
        # A lone surrogate encoded as raw bytes is a strict-decode
        # UnicodeDecodeError (ValueError), not OSError.
        self.disk.write_bytes(b'[{"name":"\xed\xa0\x80","status":"started"}]')
        rows = self._rows(self._get_busy_no_spawn())
        self.assertEqual(rows, {})

    def test_exponent_infinity_in_the_journal_keeps_the_row(self):
        self.disk.write_text(
            '[{"name":"x","status":"started","exit_code":1e999},'
            ' {"name":"y","status":"stopped","exit_code":NaN}]',
            encoding="utf-8",
        )
        rows = self._rows(self._get_busy_no_spawn())
        self.assertEqual(sorted(rows), ["x", "y"])
        self.assertIsNone(rows["x"]["exit_code"])
        self.assertIsNone(rows["y"]["exit_code"])


class BrewListPrimedHostileSnapshotTests(_BrewSandbox):
    """Already-parsed hostile rows in the shared memory snapshot."""

    def _prime(self, rows):
        with brew_cache._lock:
            brew_cache._cache["t"] = float("inf")
            brew_cache._cache["v"] = rows

    def test_hex_minted_and_bytes_rows_render_clean(self):
        self._prime([
            # str(name) of an over-cap int is the digit-cap ValueError; the
            # row cannot be identified and must drop, not 500.
            {"name": _HUGE_INT, "status": "started"},
            {"name": b"byte\xed", "status": b"star\xff"},
            {("t", "uple"): "key", "name": "tup", "status": "started"},
            {"name": "ok", "status": "started", "user": {"n": float("nan")}},
        ])
        with mock.patch.object(brew_svc, "_brew_present", return_value=True):
            resp = client().get("/api/brew/services")
        rows = self._rows(resp)
        self.assertIn("ok", rows)
        self.assertIn("tup", rows)
        # bytes name decodes with replacement instead of TypeError'ing.
        self.assertIn("byte\ufffd", rows)
        self.assertNotIn(str, [type(k) for k in rows if not isinstance(k, str)])

    def test_a_forty_deep_user_nest_is_depth_capped_not_an_iterbomb(self):
        user: dict = {"leaf": float("inf")}
        for _ in range(40):
            user = {"next": user}
        self._prime([{"name": "deep", "status": "started", "user": user}])
        with mock.patch.object(brew_svc, "_brew_present", return_value=True):
            resp = client().get("/api/brew/services")
        rows = self._rows(resp)
        self.assertIn("deep", rows)
        # brew_svc's flat _json_safe drops non-scalar user fields entirely.
        self.assertIsNone(rows["deep"]["user"])


class BrewActionHostileNameTests(_BrewSandbox):
    """Percent-encoded hostile names must 400 before any spawn."""

    def _act(self, name: str):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped") as spawn,
        ):
            resp = client().post(
                f"/api/brew/services/{name}/action", json={"action": "stop"}
            )
        spawn.assert_not_called()
        _assert_clean(self, resp)
        return resp

    def test_percent_encoded_newline_is_the_coded_400(self):
        resp = self._act("redis%0Astop")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "cli.invalid_value")

    def test_percent_encoded_nul_is_the_coded_400(self):
        resp = self._act("redis%00")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "cli.invalid_value")

    def test_percent_encoded_surrogate_bytes_are_the_coded_400(self):
        # %ED%A0%80 is the raw UTF-8 spelling of a lone surrogate half.
        resp = self._act("%ED%A0%80redis")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "cli.invalid_value")

    def test_over_length_name_is_the_coded_400(self):
        resp = self._act("a" * 300)
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "cli.invalid_value")

    def test_leading_dot_name_is_the_coded_400(self):
        # The positional guard anchors the first character to an alnum.
        resp = self._act(".hidden")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "cli.invalid_value")


class BrewActionHostileBodyTests(_BrewSandbox):
    """Body shapes whose rejected value FastAPI echoes back at the client."""

    def _raw(self, payload: bytes):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped") as spawn,
        ):
            resp = client().post(
                "/api/brew/services/redis/action",
                content=payload,
                headers={"content-type": "application/json"},
            )
        spawn.assert_not_called()
        _assert_clean(self, resp)
        return resp

    def test_invalid_utf8_body_is_4xx_with_a_clean_body(self):
        resp = self._raw(b'\xed\xa0\x80{"action":"stop"}')
        self.assertIn(resp.status_code, (400, 422), resp.text[:300])

    def test_nan_action_echo_renders(self):
        # json.loads accepts NaN; the 422 detail echoes the input, which
        # jsonable_error_detail must keep allow_nan=False-renderable.
        resp = self._raw(b'{"action": NaN}')
        self.assertEqual(resp.status_code, 422, resp.text[:300])
        json.loads(resp.text)

    def test_exponent_infinity_action_echo_renders(self):
        resp = self._raw(b'{"action": 1e999}')
        self.assertEqual(resp.status_code, 422, resp.text[:300])
        json.loads(resp.text)

    def test_over_cap_int_in_any_body_field_is_the_parse_400(self):
        # The digit-cap ValueError (not JSONDecodeError) fires for the whole
        # document regardless of which field carries the literal.
        resp = self._raw(
            b'{"action":"start","noise":' + _HUGE_DIGITS.encode() + b"}"
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])

    def test_a_5000_char_action_is_the_coded_bad_action_400(self):
        resp = self._raw(
            json.dumps({"action": _HUGE_DIGITS}).encode("utf-8")
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "brew.bad_action")


class BrewActionHostileSpawnResultTests(_BrewSandbox):
    """Whatever shape the spawn hands back, the action answers a dict."""

    def _act(self, run):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped", run),
        ):
            resp = client().post(
                "/api/brew/services/redis/action", json={"action": "start"}
            )
        _assert_clean(self, resp)
        return resp

    def test_bytes_message_with_surrogate_bytes_is_scrubbed(self):
        resp = self._act(mock.Mock(return_value=(0, b"ok \xed\xa0\x80")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])

    def test_nan_rc_still_renders_a_message(self):
        resp = self._act(mock.Mock(return_value=(float("nan"), "")))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["message"])

    def test_wrong_arity_stub_results_degrade_to_ok_false(self):
        # A leftover 3-tuple / bare-None stub is a ValueError / TypeError at
        # the unpack, inside service_action's broad except.
        for stub in ((0, "ok", "extra"), None):
            resp = self._act(mock.Mock(return_value=stub))
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            self.assertFalse(resp.json()["ok"])


if __name__ == "__main__":
    unittest.main()
