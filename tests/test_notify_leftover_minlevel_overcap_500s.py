"""Leftover notify 500s: over-cap ``min_level`` plus stays-immune pins.

Prior sweeps (test_notify_leftover_hexint_id_secrets_wipe) sealed channel
*ids*, the secrets file and the alert-state file against the digit-cap /
surrogate classes.  ``min_level`` was still handled with a bare ``str()``
in two places, and both are live 500 / silent-loss holes:

* ``public_channel`` rendered ``_utf8_text(str(ch.get("min_level")))`` —
  the *inner* ``str()`` on a hand-edited hex-YAML ``min_level: 0xFF…``
  (which loads uncapped: ``int(x, 16)`` is exempt from CPython's
  4300-digit conversion limit) raised the digit-cap ValueError before
  ``_utf8_text`` ever ran, and GET /api/alerts/channels answered 500;
* ``_min_rank`` did ``LEVELS.get(str(...))``: the same row raised out of
  ``_channel_wants`` inside ``dispatch()`` on the alert engine's single
  thread — despite dispatch's never-raises contract — so *every* channel
  (the healthy siblings included) went silent for level-routed alerts.
  The same raise escaped ``effective_settings``; its caller
  ``alerts.notify_settings`` caught it and fell back to the raw legacy
  flags, so an install whose only outlet was an explicit channel had its
  ``enabled`` widening silently dropped: no alert was ever dispatched.

Stays-immune pins for the sibling classes this sweep re-checked and found
already sealed (through the *real* app, so Starlette's ensure_ascii=False
/ allow_nan=False / UTF-8 encode is the thing under test):

* a lone-surrogate ``min_level`` / ``name`` / config value from an escaped
  YAML ``"\\ud800…"`` scrubs in GET /api/alerts/channels;
* a surrogate in a POST body ``config`` value (pydantic ``Any`` passes it
  through) lands, round-trips services.yaml, and never 500s;
* a surrogate in a typed ``str`` field (``name``) is a 422 from the
  sanitized validation handler, never a 500;
* a >4300-digit numeric literal in the request body is FastAPI's coded
  400 body-parse rejection (``json.loads`` raises the digit-cap
  *ValueError*, not JSONDecodeError), never a 500 — and it never wipes
  services.yaml or notify-credentials.json.

The remaining sweep classes are N/A by construction and asserted so:

* vanished-CLI 503: hub/notify_channels.py shells out to nothing — every
  sender is pure stdlib networking and each failure is absorbed into a
  per-channel ``{"ok": False}`` result (pinned: a raising sender keeps
  the sibling channel's send);
* os.kill / bool pids: no ``os.kill`` / ``signal.`` call sites exist in
  the module.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import config, notify_channels  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000
#: What a hand-edited hex-YAML leftover loads as (int(x, 16) is uncapped).
_HEX_HUGE = int("f" * 4000, 16)
#: The raw digit run, for request-body JSON literals.
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + secrets file, so no test touches a real install."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-notify-minlevel-{os.getpid()}-{id(self)}"
        )
        data = root / "data"
        data.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.data = data
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", data),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        secrets = mock.patch.object(
            notify_channels, "SECRETS_FILE", data / "notify-credentials.json"
        )
        secrets.start()
        self.addCleanup(secrets.stop)

    def use_cfg(self, notify_cfg: dict):
        patched = mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: notify_cfg)
        patched.start()
        self.addCleanup(patched.stop)

    def client(self):
        """The real app: the sanitized validation handler and Starlette's
        encoder are part of what these pins assert."""
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)


class OverCapMinLevelTests(_Sandbox):
    """The live holes this sweep found: bare str() on min_level."""

    def test_over_cap_min_level_does_not_500_channels_list(self):
        """public_channel's inner str(min_level) raised the digit-cap
        ValueError and 500'd GET /api/alerts/channels."""
        self.use_cfg({"channels": [
            {"id": "bad", "type": "ntfy", "topic": "t", "min_level": _HEX_HUGE},
            {"id": "fine", "type": "slack"},
        ]})
        r = self.client().get("/api/alerts/channels")
        self.assertEqual(r.status_code, 200, r.text[:300])
        rows = {c["id"]: c for c in r.json()["channels"]}
        self.assertEqual(set(rows), {"bad", "fine"})
        # The unrenderable level degrades to the documented default.
        self.assertEqual(rows["bad"]["min_level"], "warn")

    def test_over_cap_min_level_does_not_raise_dispatch(self):
        """_min_rank raised out of _channel_wants inside dispatch() — on the
        alert engine's single thread — and the healthy sibling went silent."""
        calls: list = []

        def sender(ch, secrets, title, message, **kw):
            calls.append(notify_channels._id_text(ch.get("id")))
            return {"ok": True, "message": "sent"}

        self.use_cfg({"channels": [
            {"id": "bad", "type": "ntfy", "topic": "t", "min_level": _HEX_HUGE},
            {"id": "fine", "type": "slack"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"slack": sender, "ntfy": sender}):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        # The poisoned row falls back to the warn default, so a "down" alert
        # still reaches it — and the sibling always does.
        self.assertEqual(sorted(calls), ["bad", "fine"])
        self.assertTrue(res["ok"], res)

    def test_over_cap_min_level_does_not_lose_effective_settings_widening(self):
        """effective_settings raised; alerts.notify_settings fell back to the
        raw legacy flags and the explicit channel's enabled widening was
        silently dropped — no alert was ever dispatched."""
        raw = {"channels": [
            {"id": "only", "type": "ntfy", "topic": "t", "min_level": _HEX_HUGE},
        ]}
        out = notify_channels.effective_settings(raw)
        self.assertTrue(out.get("enabled"), out)
        self.assertTrue(out.get("include_warn"), out)

    def test_min_rank_probe(self):
        warn = notify_channels.LEVELS["warn"]
        self.assertEqual(notify_channels._min_rank({"min_level": _HEX_HUGE}), warn)
        self.assertEqual(notify_channels._min_rank({"min_level": _HUGE_INT}), warn)
        self.assertEqual(notify_channels._min_rank({"min_level": "down"}),
                         notify_channels.LEVELS["down"])
        self.assertEqual(notify_channels._min_rank({}), warn)


class SurrogateStaysImmunePins(_Sandbox):
    """The surrogate key/value class is already sealed — pin it end to end."""

    def test_surrogate_min_level_and_name_scrub_in_list(self):
        self.use_cfg({"channels": [{
            "id": "s1", "type": "ntfy", "topic": "t",
            "min_level": "\ud800warn", "name": "n\ud800ame",
        }]})
        r = self.client().get("/api/alerts/channels")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertNotIn("\ud800", r.text)

    def test_surrogate_config_value_posts_and_round_trips(self):
        """pydantic's ``Any`` config passes a lone surrogate through; the
        save must land, scrub in the response, and leave services.yaml
        parseable (the silent-loss half of the class)."""
        body = '{"id": "sur1", "type": "ntfy", "config": {"topic": "t\\ud800op"}, "secrets": {}}'
        r = self.client().post(
            "/api/alerts/channels", content=body,
            headers={"content-type": "application/json"},
        )
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertNotIn("\ud800", r.text)
        config.reload_cfg()
        rows = notify_channels.channels()
        self.assertEqual([notify_channels._id_text(c.get("id")) for c in rows], ["sur1"])

    def test_surrogate_typed_str_field_is_422_not_500(self):
        """pydantic rejects a lone surrogate in the typed ``name`` field; the
        stock handler echoed the surrogate back and 500'd under Starlette's
        UTF-8 encode — the app's sanitized handler must answer 422."""
        body = '{"id": "sur2", "type": "ntfy", "name": "n\\ud800ame", "config": {"topic": "t"}, "secrets": {}}'
        r = self.client().post(
            "/api/alerts/channels", content=body,
            headers={"content-type": "application/json"},
        )
        self.assertEqual(r.status_code, 422, r.text[:300])
        self.assertNotIn("\ud800", r.text)


class HugeBodyLiteralStaysImmunePins(_Sandbox):
    """``json.loads`` of a >4300-digit literal is ValueError, not
    JSONDecodeError — the route must answer coded 400, wipe nothing."""

    def test_huge_int_literal_body_is_400_not_500(self):
        (self.data / "notify-credentials.json").write_text(
            '{"keep": {"bot_token": "KEEP"}}', encoding="utf-8",
        )
        body = ('{"id": "x1", "type": "email", "config": {"port": '
                + _HUGE_DIGITS + ', "host": "h", "to": "a@b"}, "secrets": {}}')
        r = self.client().post(
            "/api/alerts/channels", content=body,
            headers={"content-type": "application/json"},
        )
        self.assertEqual(r.status_code, 400, r.text[:300])
        # Neither journal was rewritten from an empty snapshot.
        self.assertEqual(
            notify_channels.channel_secrets("keep"), {"bot_token": "KEEP"},
        )


class SenderFailureContainmentPins(_Sandbox):
    """N-A-by-construction classes, asserted so they stay that way."""

    def test_module_has_no_cli_or_kill_call_sites(self):
        src = (BASE / "hub" / "notify_channels.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", src)
        self.assertNotIn("os.kill", src)
        self.assertNotIn("shutil.which", src)

    def test_raising_sender_keeps_the_sibling_send(self):
        """The vanished-backend shape for this domain: one dead channel is a
        per-channel {"ok": False}, never a 503 and never a sibling loss."""
        calls: list = []

        def good(ch, secrets, title, message, **kw):
            calls.append(ch.get("id"))
            return {"ok": True, "message": "sent"}

        def dead(ch, secrets, title, message, **kw):
            raise FileNotFoundError("endpoint binary gone")

        self.use_cfg({"channels": [
            {"id": "dead", "type": "ntfy", "topic": "t"},
            {"id": "good", "type": "slack"},
        ]})
        with mock.patch.dict(notify_channels._SENDERS, {"ntfy": dead, "slack": good}):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        self.assertEqual(calls, ["good"])
        self.assertEqual(res["sent"], 1)
        self.assertEqual(res["failed"], 1)


if __name__ == "__main__":
    unittest.main()
