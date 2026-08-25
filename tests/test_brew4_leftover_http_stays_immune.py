"""Fourth leftover-500s sweep of the Brew page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped hex form that arrives
already-int — huge-number JSON journals, vanished-CLI 503-vs-500) were
re-reproduced against both routes the Brew page mounts:

    GET  /api/brew/services
    POST /api/brew/services/{name}/action

No live leak was found: brew3's service-layer hardening (``_as_text`` /
``_json_safe`` scrubbing, ``_capped_json_int`` decode hooks in
``hub.brew_cache``, the confirmed-vanish 503 in ``service_action``, the
``exit unknown`` render guard) already covers every vector.  But those pins
all drive ``brew_svc`` / ``brew_cache`` directly — none of them exercises
request routing, Pydantic body parsing, app_factory's sanitizing
RequestValidationError handler, the route's audit line, or Starlette's
strict UTF-8 render of the final body.  This battery pins the whole cycle
through ``create_app()`` so the immunity cannot silently regress at the
layer the SPA actually talks to:

* one poisoned ``exit_code`` (>4300 decimal digits) in live
  `brew services list --json` output costs that field, never the row, the
  snapshot, or the request;
* the same literal in the on-disk brew-services journal keeps the last-good
  rows on the busy-brew cold-start path instead of reading as corrupt;
* lone-surrogate keys AND values (live output, disk journal, and the plain
  text fallback parse) are scrubbed before Starlette's strict UTF-8 encode;
* an already-int over-cap leftover (hex-minted, so ``int(x, 16)`` dodges
  the parse-time cap) drops to None through the ``str()`` probe;
* a >4300-digit integer literal in a request body is FastAPI's body-parse
  400 (``json.loads`` raises ValueError, NOT JSONDecodeError), never 500;
* a ``\\ud800`` escape in the plain ``action: str`` field rides into the
  handler and the coded 400 echoes it back in message AND params — both
  scrubbed by ``errors._jsonable_param`` before the strict encode;
* ``--all`` in the name slot stays the coded 400 (option injection);
* a brew that vanished mid-request answers the coded 503 only after the
  filesystem confirms it is gone; the same sentinel while brew is still on
  disk keeps the raw result; an over-cap rc renders as ``exit unknown``;
* the mutating action route still writes its SERVICE_ACTION audit line.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import brew_cache, brew_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import modules_api

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_INT = int("f" * 4400, 16)

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body))


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

    def _get_services(self, *, live_json, busy=False, present=True):
        """GET /api/brew/services with `brew services list --json` stubbed."""
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=present),
            mock.patch.object(brew_cache, "_brew_busy", return_value=busy),
            mock.patch.object(brew_cache, "sh", return_value=(0, live_json, "")),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            return request("GET", "/api/brew/services")


class BrewListHostileLiveOutputHttpTests(_BrewSandbox):
    """GET /api/brew/services with the leftover zoo in live brew output."""

    def test_huge_exit_code_costs_the_field_not_the_request(self):
        status, text = self._get_services(live_json=(
            '[{"name":"syncthing","status":"stopped","exit_code":%s},'
            ' {"name":"redis","status":"started","exit_code":0}]' % _HUGE_DIGITS
        ))
        self.assertEqual(status, 200, text[:300])
        rows = {r["id"]: r for r in json.loads(text)["services"]}
        self.assertEqual(sorted(rows), ["redis", "syncthing"])
        self.assertIsNone(rows["syncthing"]["exit_code"])
        self.assertEqual(rows["redis"]["exit_code"], 0)
        self.assertEqual(rows["syncthing"]["status"], "stopped")

    def test_surrogate_keys_and_values_are_scrubbed_before_the_encode(self):
        # json.loads happily mints lone surrogates from escaped \ud800 in
        # keys AND values; Starlette's strict UTF-8 encode refuses them.
        status, text = self._get_services(live_json=(
            '[{"name":"sync\\ud800thing","status":"star\\udc80ted",'
            ' "user":"me\\ud800","file":"/p\\ud800.plist",'
            ' "\\ud800meta":"\\ud800boom","exit_code":0}]'
        ))
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertNotIn("\udc80", text)
        rows = json.loads(text)["services"]
        self.assertEqual(len(rows), 1)

    def test_nan_and_infinity_literals_drop_to_none(self):
        # json.loads accepts NaN/Infinity; allow_nan=False rendering does not.
        status, text = self._get_services(live_json=(
            '[{"name":"a","status":"started","exit_code":NaN},'
            ' {"name":"b","status":"started","exit_code":Infinity}]'
        ))
        self.assertEqual(status, 200, text[:300])
        rows = {r["id"]: r for r in json.loads(text)["services"]}
        self.assertIsNone(rows["a"]["exit_code"])
        self.assertIsNone(rows["b"]["exit_code"])

    def test_text_fallback_scrubs_a_surrogate_row(self):
        # rc!=0 on the JSON list forces brew_svc's plain-text fallback parse.
        fallback = (
            "Name    Status  User  File\n"
            "syncthing started me\n"
            "bad\ud800name started me\ud800\n"
        )
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=False),
            mock.patch.object(brew_cache, "sh", return_value=(1, "", "boom")),
            mock.patch.object(brew_svc, "sh", return_value=(0, fallback, "")),
        ):
            status, text = request("GET", "/api/brew/services")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        names = [r["name"] for r in json.loads(text)["services"]]
        self.assertIn("syncthing", names)

    def test_no_brew_on_disk_is_the_empty_list_not_an_error(self):
        status, text = self._get_services(live_json="[]", present=False)
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["services"], [])


class BrewListPoisonedDiskJournalHttpTests(_BrewSandbox):
    """Busy-brew cold start: the poisoned on-disk journal stays last-good."""

    def test_huge_int_in_the_journal_keeps_the_rows(self):
        self.disk.write_text(
            '[{"name":"x","status":"started","exit_code":%s},'
            ' {"name":"y","status":"stopped","\\ud800k":"\\ud800v"}]'
            % _HUGE_DIGITS,
            encoding="utf-8",
        )
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_cache, "_brew_busy", return_value=True),
            mock.patch.object(
                brew_cache, "sh",
                side_effect=AssertionError("busy brew must not spawn"),
            ),
            mock.patch.object(brew_svc, "sh", return_value=(1, "", "")),
        ):
            status, text = request("GET", "/api/brew/services")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        rows = {r["id"]: r for r in json.loads(text)["services"]}
        self.assertEqual(sorted(rows), ["x", "y"])
        self.assertIsNone(rows["x"]["exit_code"])


class BrewListHexMintedIntHttpTests(_BrewSandbox):
    """A live over-cap int (already-int, hex-minted) drops via the str() probe."""

    def test_primed_over_cap_int_renders_as_none(self):
        with brew_cache._lock:
            brew_cache._cache["t"] = float("inf")
            brew_cache._cache["v"] = [
                {"name": "syncthing", "status": "started", "exit_code": _HUGE_INT},
                {"name": "redis", "status": "stopped", "exit_code": 0},
            ]
        with mock.patch.object(brew_svc, "_brew_present", return_value=True):
            status, text = request("GET", "/api/brew/services")
        self.assertEqual(status, 200, text[:300])
        rows = {r["id"]: r for r in json.loads(text)["services"]}
        self.assertIsNone(rows["syncthing"]["exit_code"])
        self.assertEqual(rows["redis"]["exit_code"], 0)


class BrewActionBodyGuardHttpTests(_BrewSandbox):
    """Hostile request bodies through the real app's parse + 422 handler."""

    def test_huge_int_literal_in_the_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError (not JSONDecodeError);
        # FastAPI's body-parse guard must map it to 400.
        status, text = request(
            "POST", "/api/brew/services/redis/action",
            raw_body=b'{"action": ' + b"9" * 5000 + b"}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_escape_in_action_is_the_coded_400_with_a_clean_body(self):
        # json.loads mints the lone surrogate and the plain `action: str`
        # field carries it into the handler.  The coded rejection echoes the
        # action back in message AND params, so both must be scrubbed before
        # Starlette's strict UTF-8 encode (errors._jsonable_param) — the raw
        # value used to 500 the error body itself.
        status, text = request(
            "POST", "/api/brew/services/redis/action",
            raw_body=b'{"action": "st\\ud800op"}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertEqual(json.loads(text)["detail"]["code"], "brew.bad_action")

    def test_unknown_action_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/brew/services/redis/action", body={"action": "explode"}
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "brew.bad_action")

    def test_option_injection_in_the_name_stays_the_coded_400(self):
        # `brew services stop --all` stops every service on the host; the
        # positional guard anchors the first character to an alphanumeric.
        with mock.patch.object(brew_svc, "run_capped") as spawn:
            status, text = request(
                "POST", "/api/brew/services/--all/action", body={"action": "stop"}
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "cli.invalid_value")
        spawn.assert_not_called()


class BrewActionVanishedHttpTests(_BrewSandbox):
    """Confirmed-vanished brew is the coded 503; unconfirmed keeps the raw dict."""

    SENTINEL = (-1, "not found")

    def _act(self, *, present, run=None):
        with (
            mock.patch.object(
                brew_svc, "_brew_present",
                mock.Mock(side_effect=present) if isinstance(present, list)
                else mock.Mock(return_value=present),
            ),
            mock.patch.object(
                brew_svc, "run_capped",
                run or mock.Mock(return_value=self.SENTINEL),
            ),
        ):
            return request(
                "POST", "/api/brew/services/redis/action", body={"action": "stop"}
            )

    def test_brew_gone_before_the_spawn_is_503(self):
        status, text = self._act(present=False)
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "brew.not_found")

    def test_vanished_mid_request_is_503_only_after_disk_confirm(self):
        # Gate saw brew, the spawn reported the FileNotFoundError sentinel,
        # and the fresh disk probe on the failure path confirms it is gone.
        status, text = self._act(present=[True, False])
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "brew.not_found")

    def test_sentinel_while_brew_is_still_on_disk_keeps_the_raw_result(self):
        # A signal-killed brew is also rc -1: a brew that is still present
        # must keep its raw result instead of a false "not installed".
        status, text = self._act(present=[True, True])
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")

    def test_a_real_brew_failure_keeps_its_output(self):
        run = mock.Mock(return_value=(1, "Error: redis has no service"))
        status, text = self._act(present=True, run=run)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertIn("no service", payload["message"])


class BrewActionUnrenderableResultHttpTests(_BrewSandbox):
    """The action result itself survives over-cap ints and surrogates."""

    def _act(self, run):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(brew_svc, "run_capped", run),
        ):
            return request(
                "POST", "/api/brew/services/redis/action", body={"action": "start"}
            )

    def test_over_cap_rc_renders_as_exit_unknown(self):
        # f"exit {rc}" of an over-cap int is the digit-cap ValueError.
        status, text = self._act(mock.Mock(return_value=(_HUGE_INT, "")))
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit unknown")

    def test_surrogate_in_the_brew_output_is_scrubbed(self):
        status, text = self._act(
            mock.Mock(return_value=(0, "Successfully started \ud800redis"))
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertTrue(json.loads(text)["ok"])

    def test_surrogate_in_a_raised_message_is_scrubbed(self):
        status, text = self._act(
            mock.Mock(side_effect=RuntimeError("boom \ud800"))
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertFalse(json.loads(text)["ok"])


class BrewActionAuditHttpTests(_BrewSandbox):
    """The mutating route still writes its SERVICE_ACTION audit line."""

    def test_the_action_is_audited_with_the_brew_target(self):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(
                brew_svc, "run_capped", return_value=(0, "Successfully started")
            ),
            mock.patch.object(modules_api.audit, "record") as record,
        ):
            status, text = request(
                "POST", "/api/brew/services/redis/action", body={"action": "start"}
            )
        self.assertEqual(status, 200, text[:300])
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs.get("target"), "brew:redis")
        self.assertEqual(record.call_args.kwargs.get("action"), "start")


if __name__ == "__main__":
    unittest.main()
