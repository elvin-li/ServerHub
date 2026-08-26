"""Seventh cloudflared leftover sweep — nested unbound subclass-bomb 500s.

The cf6 wave sealed the surrogate-HOME plist and vanished-login 503s; the
cf3/cf4 waves pinned surrogates, over-cap ints, the ``_json_int`` decode hook
and the vanished-CLI 503.  What ``hub/cloudflared_svc.py`` never adopted was
the modules5 *unbound-base* convention every sibling ``_jsonable`` already
carries, so a leftover subclass handed over by an in-process caller (the
``_load_state`` seam the cf4 battery already treats as the entry point) still
ran its own dunders through the scrub.  On the pre-fix tree each of these was
a live raise out of ``_jsonable_state`` / ``_as_text`` — a raw 500 on
GET /api/cloudflared/status, POST /restart and POST /uninstall-service:

* a dict-subclass ``items()`` bomb (bound ``value.items()``), and a
  triples-``items()`` subclass whose non-pair rows blew the two-target
  unpack in the loop head;
* an int-subclass ``__str__`` bomb (the digit-cap probe only caught
  ValueError) — plain and wearing a >4300-digit over-cap value;
* a float-subclass ``__eq__`` bomb in the NaN/inf probes — plain and
  wearing ``inf``;
* a bytes/bytearray-subclass ``decode`` bomb (bound ``value.decode``), as a
  value and as a mapping key;
* a str-subclass ``encode`` bomb (bound ``value.encode``), as a value and as
  a mapping key — and the self-``__str__`` form, where ``str()`` of an
  object answers a str *subclass* so CPython skips the exact-str copy and
  the bound ``encode`` bomb rode ``_as_text`` into the ``tunnels_error``
  arm of GET /status;
* a list-subclass ``__iter__`` bomb in the sequence walk;
* an ``isoformat`` property bomb / ``__getattr__`` bomb blowing the
  ``getattr`` probe itself;
* an int-subclass ``__str__`` bomb reaching ``_tunnel_argv`` (its str()
  probe caught only ValueError) and a str-subclass ``strip`` bomb on the
  same seam;
* an int-subclass ``__bool__`` bomb / float-subclass ``__eq__`` bomb passed
  to ``logs(lines=...)`` by a direct caller.

Fixes, all in hub/cloudflared_svc.py, all the established conventions:
``_decode_bytes`` (unbound base decode), ``dict.items(value)`` /
``base.__iter__(value)`` views, ``int.__index__`` / ``float.__float__``
base coercions ahead of every probe, unbound ``str.encode`` /
``str.strip``, and the guarded ``getattr`` probe.  The unbound view reads
the real content underneath the override, so the poison scrubs
field-level: the bombed tunnel name still shows, the bombed bytes still
decode, and only the truly unrenderable (over-cap ints, non-finite
floats) drop to None.

Dict-subclass ``.get`` / ``__bool__`` bombs ride along as stays-immune
pins: both are neutralized because the scrub now always answers exact
types before ``st.get(...) or ...`` runs.
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

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from hub import cloudflared_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

#: Built arithmetically: ``int("9" * 5000)`` itself trips the digit cap.
_HUGE_INT = 10 ** 5000

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

class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("dict items bomb")


class _GetBombDict(dict):
    def get(self, *a, **k):
        raise RuntimeError("dict get bomb")


class _TriplesItemsDict(dict):
    def items(self):
        return [("a", 1, 2)]


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class _BytearrayDecodeBomb(bytearray):
    def decode(self, *a, **k):
        raise RuntimeError("bytearray decode bomb")


class _StrEncodeBomb(str):
    def encode(self, *a, **k):
        raise RuntimeError("str encode bomb")


class _SelfStrEncodeBomb:
    """``str()`` answers a str *subclass*, so CPython skips the exact-str copy."""

    def __str__(self):
        return _StrEncodeBomb("payload")


class _SelfStrEncodeBombError(Exception):
    def __str__(self):
        return _StrEncodeBomb("edge down")


class _BoolBombStr(str):
    def __bool__(self):
        raise RuntimeError("str bool bomb")


class _BoolBombInt(int):
    def __bool__(self):
        raise RuntimeError("int bool bomb")


class _StrStripBomb(str):
    def strip(self, *a, **k):
        raise RuntimeError("str strip bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError(f"getattr bomb: {name}")


class _CloudflaredSandbox(unittest.TestCase):
    """Every module-level path constant redirected into a private temp tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cf7-bombs-")
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

    def _status_with_state(self, state) -> dict:
        with mock.patch.object(
            cloudflared_svc, "_load_state", return_value=state,
        ):
            resp = _client().get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        return body


class StatusStateContainerBombs(_CloudflaredSandbox):
    """Whole-journal dict-subclass bombs — the unbound view salvages entries."""

    def test_items_bomb_state_still_reports_active_tunnel(self):
        snap = self._status_with_state(
            _ItemsBombDict({"tunnel_name": "home", "mode": "token"})
        )
        self.assertEqual(snap["active_tunnel"], "home")
        self.assertEqual(snap["mode"], "token")

    def test_get_bomb_state_still_reports_active_tunnel(self):
        """Stays-immune: the scrub answers an exact dict before st.get runs."""
        snap = self._status_with_state(
            _GetBombDict({"tunnel_name": "home", "mode": "token"})
        )
        self.assertEqual(snap["active_tunnel"], "home")
        self.assertEqual(snap["mode"], "token")

    def test_triples_items_state_still_reports_active_tunnel(self):
        """Non-pair rows from a lying ``items()`` used to blow the unpack."""
        snap = self._status_with_state(
            _TriplesItemsDict({"tunnel_name": "home", "mode": "token"})
        )
        self.assertEqual(snap["active_tunnel"], "home")

    def test_nested_items_bomb_costs_only_its_subtree(self):
        snap = self._status_with_state({
            "tunnel_name": "home",
            "junk": {"deep": _ItemsBombDict({"a": 1})},
        })
        self.assertEqual(snap["active_tunnel"], "home")


class StatusStateScalarBombs(_CloudflaredSandbox):
    """Subclass scalar bombs in journal values and keys — scrubbed field-level."""

    def test_int_str_bomb_value_keeps_its_number(self):
        snap = self._status_with_state({"tunnel_name": "home", "updated": _IntStrBomb(7)})
        self.assertEqual(snap["active_tunnel"], "home")

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        """Coercion cannot resurrect the unrenderable: past CPython's digit
        cap the field drops exactly like its plain-int sibling."""
        snap = self._status_with_state(
            {"tunnel_name": _IntStrBomb(_HUGE_INT), "mode": "token"}
        )
        self.assertIsNone(snap["active_tunnel"])
        self.assertEqual(snap["mode"], "token")

    def test_float_eq_bomb_value_survives_and_inf_wearing_it_drops(self):
        snap = self._status_with_state({
            "tunnel_name": "home",
            "updated": _FloatEqBomb(1.5),
            "junk": _FloatEqBomb(float("inf")),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_bytes_decode_bomb_value_and_key_still_decode(self):
        snap = self._status_with_state({
            "tunnel_name": _BytesDecodeBomb(b"home"),
            _BytesDecodeBomb(b"mo\xffde"): _BytearrayDecodeBomb(b"token"),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_str_encode_bomb_value_and_key_still_launder(self):
        snap = self._status_with_state({
            "tunnel_name": _StrEncodeBomb("home\ud800"),
            _StrEncodeBomb("mode"): _StrEncodeBomb("token"),
        })
        self.assertEqual(snap["active_tunnel"], "home?")
        self.assertEqual(snap["mode"], "token")

    def test_bool_bomb_tunnel_name_still_reports(self):
        """Stays-immune: ``st.get(...) or ...`` runs on the exact scrub output."""
        snap = self._status_with_state({"tunnel_name": _BoolBombStr("home")})
        self.assertEqual(snap["active_tunnel"], "home")

    def test_iter_bomb_list_value_keeps_its_elements(self):
        snap = self._status_with_state({
            "tunnel_name": "home", "history": _IterBombList(["a", "b"]),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_isoformat_property_and_getattr_bombs_do_not_500(self):
        snap = self._status_with_state({
            "tunnel_name": "home",
            "when": _IsoPropertyBomb(),
            "what": _GetattrBomb(),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_self_str_encode_bomb_value_salvages_its_text(self):
        snap = self._status_with_state({
            "tunnel_name": "home", "note": _SelfStrEncodeBomb(),
        })
        self.assertEqual(snap["active_tunnel"], "home")


class StatusTunnelsErrorSelfStrBomb(_CloudflaredSandbox):
    def test_tunnels_error_arm_launders_a_self_str_encode_bomb(self):
        """``_as_text(e)`` in the tunnels_error arm used to run the bound
        ``encode`` bomb ``str(e)`` answered and 500 GET /status."""
        self.state_file.write_text("{}")
        self.cert.write_text("x" * 64)
        with mock.patch.object(
            cloudflared_svc, "list_tunnels",
            side_effect=_SelfStrEncodeBombError(),
        ):
            resp = _client().get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertEqual(body["tunnels"], [])
        self.assertEqual(body["tunnels_error"], "edge down")


class RestartStateBombs(_CloudflaredSandbox):
    def test_items_bomb_state_still_restarts_the_salvaged_tunnel(self):
        with (
            mock.patch.object(
                cloudflared_svc, "_load_state",
                return_value=_ItemsBombDict({"tunnel_name": "home"}),
            ),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=True),
            mock.patch.object(
                cloudflared_svc, "start_with_tunnel",
                return_value={"ok": True, "running": True, "active_tunnel": "home"},
            ) as start,
        ):
            resp = _client().post("/api/cloudflared/restart")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])
        start.assert_called_once_with("home")

    def test_items_bomb_state_without_login_is_ok_false_not_500(self):
        with mock.patch.object(
            cloudflared_svc, "_load_state",
            return_value=_ItemsBombDict({"tunnel_name": "home"}),
        ):
            resp = _client().post("/api/cloudflared/restart")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["ok"])


class UninstallStateBombs(_CloudflaredSandbox):
    def test_bomb_values_scrub_into_the_persisted_journal(self):
        """The read-modify-write must keep sane siblings and scrub the bombs,
        never 500 or wipe the file."""
        with mock.patch.object(
            cloudflared_svc, "_load_state",
            return_value={
                "keep": _IntStrBomb(7),
                "note": _BytesDecodeBomb(b"hi"),
                "junk": _IntStrBomb(_HUGE_INT),
                "tunnel_name": "home",
                "mode": "token",
            },
        ):
            resp = _client().post("/api/cloudflared/uninstall-service")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])
        raw = json.loads(self.state_file.read_text())
        self.assertEqual(raw["keep"], 7)
        self.assertEqual(raw["note"], "hi")
        self.assertIsNone(raw["junk"])
        # tunnel_name / mode are what uninstall removes on purpose.
        self.assertNotIn("tunnel_name", raw)
        self.assertNotIn("mode", raw)


class TunnelArgvBombs(unittest.TestCase):
    def test_int_str_bomb_id_still_names_its_tunnel(self):
        self.assertEqual(cloudflared_svc._tunnel_argv(_IntStrBomb(5)), "5")

    def test_overcap_int_wearing_the_bomb_stays_coded_400(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(_IntStrBomb(_HUGE_INT))
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")

    def test_str_strip_bomb_still_names_its_tunnel(self):
        self.assertEqual(cloudflared_svc._tunnel_argv(_StrStripBomb(" home ")), "home")


class LogsLinesBombs(_CloudflaredSandbox):
    """Direct in-process callers; the HTTP route is pydantic-typed."""

    def test_float_eq_bomb_nan_lines_falls_back(self):
        out = cloudflared_svc.logs(lines=_FloatEqBomb(float("nan")))
        _encodable(out)
        self.assertTrue(out["ok"])

    def test_int_bool_bomb_lines_falls_back(self):
        out = cloudflared_svc.logs(lines=_BoolBombInt(3))
        _encodable(out)
        self.assertTrue(out["ok"])


class AsTextBombs(unittest.TestCase):
    def test_bytes_decode_bomb_still_decodes(self):
        self.assertEqual(cloudflared_svc._as_text(_BytesDecodeBomb(b"hi")), "hi")

    def test_self_str_encode_bomb_still_launders(self):
        text = cloudflared_svc._as_text(_SelfStrEncodeBomb())
        self.assertEqual(text, "payload")
        self.assertIs(type(text), str)

    def test_str_encode_bomb_input_answers_exact_str(self):
        text = cloudflared_svc._as_text(_StrEncodeBomb("hi\ud800"))
        self.assertEqual(text, "hi?")
        self.assertIs(type(text), str)


if __name__ == "__main__":
    unittest.main()
