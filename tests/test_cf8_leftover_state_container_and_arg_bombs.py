"""Eighth cloudflared leftover sweep — read-modify-write and argument bombs.

The cf7 wave gave ``_jsonable_state`` / ``_as_text`` the modules5 unbound-base
convention, so the *value* scrub is sealed.  What cf7 never reached was the
handful of call sites that still run bound container / string methods on
unscrubbed material.  On the pre-fix tree each of these was a live raise —
a raw 500 on the HTTP routes, an uncoded exception on the direct-caller
seams cf7 already treats as in-scope (the ``_load_state`` seam and the
pydantic-bypassing in-process argument seam):

* ``uninstall_service`` popped ``tunnel_name`` / ``mode`` off the *raw*
  ``_load_state()`` answer, so a dict-subclass ``pop`` bomb 500'd
  POST /uninstall-service after the agent was already stopped and the
  plist/token already removed;
* ``start_with_tunnel`` / ``start_with_token`` ran ``st.update`` on the same
  raw answer, so a dict-subclass ``update`` bomb 500'd POST /start and
  POST /start-token *after the tunnel itself was already up*;
* ``_tunnel_argv``'s non-string arm probed emptiness with
  ``value in (None, "")`` — a leftover ``__eq__`` bomb raised out of the
  probe itself instead of the coded 400;
* ``create_tunnel`` sanitized with ``(name or "").strip()`` — a str-subclass
  ``__bool__`` or ``strip`` bomb raised before the charset gate ran;
* ``route_dns`` did the same to ``hostname``;
* ``start_with_token`` did the same to ``label`` while composing the
  persisted ``tunnel_name``.

Fixes, all in hub/cloudflared_svc.py, all the established conventions: the
read-modify-write paths scrub through ``_jsonable_state`` before ``pop`` /
``update`` (exactly what ``restart`` and ``status`` already do), the argument
sanitizers launder through ``_as_text`` + unbound ``str.strip``, and the
emptiness probe guards its own comparison.

Stays-immune pins ride along: ``route_dns``'s ``.lower()`` was already safe
(strip answers an exact str), an always-equal ``__eq__`` still maps to the
empty-argument code, and ``restart`` / ``status`` keep their existing scrub.
"""
from __future__ import annotations

import contextlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from hub import cloudflared_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _encodable(body) -> None:
    """The exact render Starlette performs: ensure_ascii=False then UTF-8."""
    json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


# ── the hunted leftover bomb classes ─────────────────────────────────────────

class _PopBombDict(dict):
    def pop(self, *a, **k):
        raise RuntimeError("dict pop bomb")


class _UpdateBombDict(dict):
    def update(self, *a, **k):
        raise RuntimeError("dict update bomb")


class _EqBomb:
    """Non-string leftover whose ``__eq__`` raises out of ``in (None, "")``."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __ne__ = __eq__
    __hash__ = object.__hash__


class _EqualsEverything:
    """Stays-immune pin: an always-equal leftover keeps the empty-arg code."""

    def __eq__(self, other):
        return True

    __ne__ = None
    __hash__ = object.__hash__


class _StrStripBomb(str):
    def strip(self, *a, **k):
        raise RuntimeError("str strip bomb")


class _StrLowerBomb(str):
    def lower(self, *a, **k):
        raise RuntimeError("str lower bomb")


class _BoolBombStr(str):
    def __bool__(self):
        raise RuntimeError("str bool bomb")


class _CloudflaredSandbox(unittest.TestCase):
    """Every module-level path constant redirected into a private temp tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cf8-bombs-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.cf_home = root / "cf"
        self.cf_home.mkdir()
        self.state_file = self.state_dir / "serverhub-state.json"
        self.cert = self.cf_home / "cert.pem"
        for name, value in {
            "STATE_DIR": self.state_dir,
            "STATE_FILE": self.state_file,
            "TOKEN_FILE": self.state_dir / "tunnel.token",
            "LOG_FILE": self.state_dir / "tunnel.log",
            "LOGIN_PID": self.state_dir / "login.pid",
            "LOGIN_LOG": self.state_dir / "login.log",
            "LOGIN_URL_FILE": self.state_dir / "login.url",
            "CF_HOME": self.cf_home,
            "CERT": self.cert,
            "CONFIG_YML": self.cf_home / "config.yml",
            "PLIST": root / "local.cloudflared-tunnel.plist",
        }.items():
            patcher = mock.patch.object(cloudflared_svc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        cloudflared_svc.invalidate_tunnels()
        self.addCleanup(cloudflared_svc.invalidate_tunnels)

    def _start_machinery(self) -> contextlib.ExitStack:
        """Mock everything between the route and the read-modify-write."""
        stack = contextlib.ExitStack()
        for patcher in (
            mock.patch.object(cloudflared_svc, "fetch_token", return_value="tok"),
            mock.patch.object(cloudflared_svc, "token_looks_valid", return_value=True),
            mock.patch.object(cloudflared_svc, "_write_token"),
            mock.patch.object(cloudflared_svc, "_write_launchagent_token"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap",
                return_value={"ok": True, "message": "Started"},
            ),
        ):
            stack.enter_context(patcher)
        return stack

    def _persisted(self) -> dict:
        return json.loads(self.state_file.read_text())


class UninstallStatePopBomb(_CloudflaredSandbox):
    def test_pop_bomb_state_still_uninstalls_and_persists_siblings(self):
        """``st.pop`` on the raw journal used to 500 POST /uninstall-service
        after the plist/token were already removed."""
        with mock.patch.object(
            cloudflared_svc, "_load_state",
            return_value=_PopBombDict({
                "tunnel_name": "home", "mode": "token", "keep": 7,
            }),
        ):
            resp = _client().post("/api/cloudflared/uninstall-service")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])
        raw = self._persisted()
        self.assertEqual(raw["keep"], 7)
        # tunnel_name / mode are what uninstall removes on purpose — the
        # scrub must not resurrect them past the pops.
        self.assertNotIn("tunnel_name", raw)
        self.assertNotIn("mode", raw)


class StartStateUpdateBombs(_CloudflaredSandbox):
    def test_update_bomb_state_still_starts_the_tunnel(self):
        """``st.update`` on the raw journal used to 500 POST /start after the
        tunnel itself was already up."""
        with (
            mock.patch.object(
                cloudflared_svc, "_load_state",
                return_value=_UpdateBombDict({"keep": 7}),
            ),
            self._start_machinery(),
        ):
            resp = _client().post("/api/cloudflared/start", json={"tunnel": "home"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["active_tunnel"], "home")
        raw = self._persisted()
        self.assertEqual(raw["keep"], 7)
        self.assertEqual(raw["tunnel_name"], "home")
        self.assertEqual(raw["mode"], "token")

    def test_update_bomb_state_still_starts_with_token(self):
        with (
            mock.patch.object(
                cloudflared_svc, "_load_state",
                return_value=_UpdateBombDict({"keep": 7}),
            ),
            self._start_machinery(),
        ):
            resp = _client().post(
                "/api/cloudflared/start-token", json={"token": "x" * 100},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])
        raw = self._persisted()
        self.assertEqual(raw["keep"], 7)
        self.assertEqual(raw["tunnel_name"], "token")
        self.assertEqual(raw["mode"], "token")


class TunnelArgvEmptinessProbeBombs(unittest.TestCase):
    """Direct in-process callers; the HTTP routes are pydantic-typed."""

    def test_eq_bomb_argument_stays_coded_400(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(_EqBomb())
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")

    def test_always_equal_leftover_keeps_the_empty_code(self):
        """Stays-immune: the guarded probe preserves the old semantics for a
        leftover that compares equal to the empty string."""
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(_EqualsEverything())
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.tunnel_required")

    def test_none_keeps_the_empty_code(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(None)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.tunnel_required")


class CreateTunnelArgBombs(_CloudflaredSandbox):
    """The sanitize must launder the bombs, then answer the coded 400 the
    not-logged-in state has always produced — never an uncoded raise."""

    def test_strip_bomb_name_stays_coded(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.create_tunnel(_StrStripBomb("home"))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.login_required")

    def test_bool_bomb_name_stays_coded(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.create_tunnel(_BoolBombStr("home"))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.login_required")


class RouteDnsArgBombs(_CloudflaredSandbox):
    def test_strip_bomb_hostname_stays_coded(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.route_dns("home", _StrStripBomb(" example.com "))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.login_required")

    def test_bool_bomb_hostname_stays_coded(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.route_dns("home", _BoolBombStr("example.com"))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.login_required")

    def test_lower_bomb_hostname_stays_immune(self):
        """Stays-immune pin: strip answers an exact str, so the bound
        ``lower`` that follows never sees the subclass."""
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc.route_dns("home", _StrLowerBomb("EXAMPLE.COM"))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.login_required")


class StartTokenLabelBombs(_CloudflaredSandbox):
    def test_strip_bomb_label_still_persists_its_text(self):
        with self._start_machinery():
            out = cloudflared_svc.start_with_token(
                "x" * 100, label=_StrStripBomb(" home ")
            )
        _encodable(out)
        self.assertTrue(out["ok"])
        self.assertEqual(self._persisted()["tunnel_name"], "home")

    def test_bool_bomb_label_still_persists_its_text(self):
        with self._start_machinery():
            out = cloudflared_svc.start_with_token(
                "x" * 100, label=_BoolBombStr("home")
            )
        _encodable(out)
        self.assertTrue(out["ok"])
        self.assertEqual(self._persisted()["tunnel_name"], "home")


if __name__ == "__main__":
    unittest.main()
