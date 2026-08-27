"""Ninth cloudflared leftover sweep — ``__class__``-property and rc-seam bombs.

The cf7 wave gave ``_jsonable_state`` / ``_as_text`` the unbound-base
convention and cf8 sealed the read-modify-write and argument seams, so every
*dunder* bomb a leftover subclass can wear is laundered.  What none of those
waves reached is the probe that runs before any branch does: ``isinstance``
itself.  When the real type check misses, CPython consults
``value.__class__`` — a raising property propagates out of the probe, and a
*lying* property (one that answers ``dict`` / ``list`` / ``bytes`` for a
non-container) steers the walker into an unbound base call that TypeErrors
on the foreign object.  On the pre-fix tree each of these was a raw 500:

* a leftover whose ``__class__`` is a raising property, as a state value,
  as the whole journal, or as an ``sh()`` stdout, 500'd
  GET /api/cloudflared/status, POST /uninstall-service and POST /create at
  the *first* ``isinstance`` in ``_jsonable_state`` / ``_as_text``;
* a lying ``__class__`` claiming dict / list / bytes (value or mapping key)
  rode past the guard into ``dict.items`` / ``list.__iter__`` /
  ``bytes.decode``, whose unbound descriptors TypeError on a non-instance,
  and 500'd GET /api/cloudflared/status;
* an int-subclass return code whose ``__eq__`` / ``__ne__`` raises — the
  poisoned in-process sh seam — blew the bare ``rc != 0`` / ``rc == 0`` /
  ``rc != -1`` probes and 500'd GET /api/cloudflared/status (the
  ``_launchd_job_info`` compare sits outside its try), POST /create,
  POST /route-dns and POST /start (via ``fetch_token``).

Fixes, all in hub/cloudflared_svc.py, all the established conventions:
``_safe_isinstance`` (a guarded probe, exactly the shape of the guarded
``getattr`` the isoformat arm already uses) everywhere the walker and the
argument sanitizers type a leftover, guarded unbound container views with a
text-salvage fallthrough, a hardened ``_decode_bytes`` whose ``bytes()``
fallback also absorbs a ``__bytes__`` bomb, and ``_rc_int`` — an
``int.__index__`` base coercion for every ``sh()`` return code, with a -255
junk sentinel that is nonzero (a failure) and never -1 (never misread as a
vanished CLI).

Stays-immune pins ride along: a hashable dict-subclass mapping key, a
poisoned tunnels-cache ``__iter__`` bomb (absorbed by the status
``tunnels_error`` arm), an over-cap-int compact-token payload on disk
(``json.loads``'s bare ValueError is already caught), the FIFO-past-the-
``is_file``-gate TOCTOU on serverhub-state.json (``read_text_capped`` opens
O_NONBLOCK and rejects non-regular files), and the vanished-CLI classifier
still confirming on disk before answering 503 even when the rc wears a bomb.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import sys
import tempfile
import threading
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

#: Well-formed connector JWT (three base64url segments, ≥ 80 chars).
_VALID_JWT = "eyJ" + "a" * 40 + "." + "b" * 40 + "." + "c" * 40

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

class _ClassPropertyBomb:
    """``isinstance`` consults ``__class__`` when the type check misses; a
    raising property used to blow the probe itself."""

    @property
    def __class__(self):
        raise RuntimeError("__class__ bomb")


def _lying(cls):
    """An object whose ``__class__`` *claims* another type without being one."""

    class _Liar:
        @property
        def __class__(self):
            return cls

    return _Liar()


class _RcEqBomb(int):
    """Return code from a poisoned sh seam whose comparisons raise."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class _HashableDictKey(dict):
    """A dict subclass that can sit in a mapping as a *key*."""

    __hash__ = object.__hash__


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _BytesDunderBomb:
    """Lying-bytes leftover whose ``__bytes__`` also raises."""

    @property
    def __class__(self):
        return bytes

    def __bytes__(self):
        raise RuntimeError("__bytes__ bomb")


def _overcap_compact_token() -> str:
    """Compact connector token whose payload holds a >4300-digit int.

    ``json.loads`` of such a number raises *bare ValueError* past CPython's
    int→str digit cap; the payload decoder must read that as "not a compact
    token", never let it escape.
    """
    payload = (
        '{"a": ' + "9" * 4400 + ', "s": "' + "x" * 20 + '", "t": "' + "y" * 20 + '"}'
    )
    return base64.urlsafe_b64encode(payload.encode("ascii")).decode().rstrip("=")


class _CloudflaredSandbox(unittest.TestCase):
    """Every module-level path constant redirected into a private temp tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cf9-bombs-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.cf_home = root / "cf"
        self.cf_home.mkdir()
        self.state_file = self.state_dir / "serverhub-state.json"
        self.token_file = self.state_dir / "tunnel.token"
        self.cert = self.cf_home / "cert.pem"
        for name, value in {
            "STATE_DIR": self.state_dir,
            "STATE_FILE": self.state_file,
            "TOKEN_FILE": self.token_file,
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

    def _sign_in(self) -> None:
        self.cert.write_text("x" * 64)


class StatusClassPropertyBombs(_CloudflaredSandbox):
    """Raising ``__class__`` leftovers in the journal — the first isinstance
    in the scrub used to blow before any branch ran."""

    def test_class_bomb_value_keeps_siblings(self):
        snap = self._status_with_state({
            "tunnel_name": "home", "mode": "token", "junk": _ClassPropertyBomb(),
        })
        self.assertEqual(snap["active_tunnel"], "home")
        self.assertEqual(snap["mode"], "token")

    def test_class_bomb_whole_state_still_answers(self):
        snap = self._status_with_state(_ClassPropertyBomb())
        self.assertTrue(snap["ok"])
        self.assertIsNone(snap["active_tunnel"])

    def test_nested_class_bomb_costs_only_its_subtree(self):
        snap = self._status_with_state({
            "tunnel_name": "home",
            "junk": {"deep": [_ClassPropertyBomb()]},
        })
        self.assertEqual(snap["active_tunnel"], "home")


class StatusLyingClassBombs(_CloudflaredSandbox):
    """Lying ``__class__`` properties steering the walker into unbound base
    calls that TypeError on the foreign object."""

    def test_lying_dict_value_keeps_siblings(self):
        snap = self._status_with_state({
            "tunnel_name": "home", "junk": _lying(dict),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_lying_list_value_keeps_siblings(self):
        snap = self._status_with_state({
            "tunnel_name": "home", "junk": _lying(list),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_lying_bytes_value_and_key_keep_siblings(self):
        snap = self._status_with_state({
            "tunnel_name": "home",
            "junk": _lying(bytes),
            _lying(bytes): "poisoned key",
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_lying_bytes_with_bytes_dunder_bomb_keeps_siblings(self):
        """The ``bytes()`` salvage inside ``_decode_bytes`` must absorb a
        ``__bytes__`` bomb too, not trade one raise for another."""
        snap = self._status_with_state({
            "tunnel_name": "home", "junk": _BytesDunderBomb(),
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_lying_bool_value_coerces_instead_of_riding_through(self):
        """A lying-bool leftover used to return *as-is* from the scrub and
        blow the encoder instead of the walker."""
        snap = self._status_with_state({
            "tunnel_name": "home", "junk": _lying(bool),
        })
        self.assertEqual(snap["active_tunnel"], "home")


class UninstallClassPropertyBomb(_CloudflaredSandbox):
    def test_class_bomb_value_still_uninstalls_and_persists_siblings(self):
        """``_save_state``'s except net never caught RuntimeError, so the
        scrub raising on the bomb 500'd POST /uninstall-service after the
        plist/token were already removed."""
        with mock.patch.object(
            cloudflared_svc, "_load_state",
            return_value={
                "keep": 7,
                "note": _ClassPropertyBomb(),
                "tunnel_name": "home",
                "mode": "token",
            },
        ):
            resp = _client().post("/api/cloudflared/uninstall-service")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])
        raw = json.loads(self.state_file.read_text())
        self.assertEqual(raw["keep"], 7)
        # The bomb salvages as text — a str the encoder can always hold.
        self.assertIsInstance(raw["note"], str)
        self.assertNotIn("tunnel_name", raw)
        self.assertNotIn("mode", raw)


class RcSeamBombs(_CloudflaredSandbox):
    """Int-subclass return codes whose comparisons raise — the poisoned
    in-process sh seam.  The base coercion must keep the real value's
    semantics: a bomb wearing 0 still reads as success."""

    def test_create_rc_bomb_wearing_zero_still_succeeds(self):
        self._sign_in()
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/cloudflared"),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(_RcEqBomb(0), "created", ""),
            ),
        ):
            resp = _client().post("/api/cloudflared/create", json={"name": "home"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])

    def test_create_rc_bomb_wearing_one_still_reports_failure(self):
        self._sign_in()
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/cloudflared"),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(_RcEqBomb(1), "", "boom"),
            ),
        ):
            resp = _client().post("/api/cloudflared/create", json={"name": "home"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertFalse(body["ok"])

    def test_route_dns_rc_bomb_still_answers(self):
        self._sign_in()
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/cloudflared"),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(_RcEqBomb(0), "routed", ""),
            ),
        ):
            resp = _client().post(
                "/api/cloudflared/route-dns",
                json={"tunnel": "home", "hostname": "a.example.com"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])

    def test_start_rc_bomb_through_fetch_token_still_starts(self):
        self._sign_in()
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/cloudflared"),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(_RcEqBomb(0), _VALID_JWT, ""),
            ),
            mock.patch.object(cloudflared_svc, "_write_launchagent_token"),
            mock.patch.object(
                cloudflared_svc, "_launchctl_bootstrap",
                return_value={"ok": True, "message": "Started"},
            ),
        ):
            resp = _client().post("/api/cloudflared/start", json={"tunnel": "home"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["active_tunnel"], "home")

    def test_status_rc_bomb_from_launchctl_seam_still_reports_running(self):
        """``_launchd_job_info``'s ``rc != 0`` sits outside its try; the bomb
        used to ride ``_is_running`` into a 500 on GET /status."""
        with (
            mock.patch.object(cloudflared_svc, "_process_running", return_value=False),
            mock.patch.object(
                cloudflared_svc, "sh",
                return_value=(_RcEqBomb(0), "state = running", ""),
            ),
            mock.patch.object(cloudflared_svc, "_load_state", return_value={}),
        ):
            resp = _client().get("/api/cloudflared/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body["running"])

    def test_create_stdout_class_bomb_still_answers(self):
        """``_as_text(out)`` typed the sh stdout with a bare isinstance."""
        self._sign_in()
        with (
            mock.patch.object(cloudflared_svc, "_bin", return_value="/bin/cloudflared"),
            mock.patch.object(
                cloudflared_svc, "sh", return_value=(0, _ClassPropertyBomb(), ""),
            ),
        ):
            resp = _client().post("/api/cloudflared/create", json={"name": "home"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())


class VanishedCliRcBombPins(unittest.TestCase):
    """The vanished-CLI classifier keeps its disk confirm with a bomb rc."""

    def test_rc_bomb_wearing_minus_one_still_confirms_on_disk(self):
        with tempfile.TemporaryDirectory(prefix="cf9-cli-") as tmp:
            missing = Path(tmp) / "cloudflared"
            self.assertTrue(
                cloudflared_svc._cli_vanished(_RcEqBomb(-1), "not found", str(missing))
            )
            present = Path(tmp) / "present"
            present.write_text("#!x\n")
            self.assertFalse(
                cloudflared_svc._cli_vanished(_RcEqBomb(-1), "not found", str(present))
            )

    def test_junk_rc_never_reads_as_vanished(self):
        """Uncoercible junk becomes the -255 sentinel: a failure, never -1."""
        self.assertEqual(cloudflared_svc._rc_int(object()), -255)
        self.assertFalse(
            cloudflared_svc._cli_vanished(object(), "not found", "/nonexistent")
        )

    def test_rc_int_keeps_exact_values(self):
        self.assertEqual(cloudflared_svc._rc_int(0), 0)
        self.assertEqual(cloudflared_svc._rc_int(-1), -1)
        self.assertEqual(cloudflared_svc._rc_int(_RcEqBomb(3)), 3)
        self.assertIs(type(cloudflared_svc._rc_int(_RcEqBomb(3))), int)


class ArgumentSeamClassBombs(_CloudflaredSandbox):
    """Direct in-process callers; the HTTP routes are pydantic-typed."""

    def test_tunnel_argv_class_bomb_stays_coded_400(self):
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv(_ClassPropertyBomb())
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")

    def test_logs_class_bomb_lines_falls_back(self):
        out = cloudflared_svc.logs(lines=_ClassPropertyBomb())
        _encodable(out)
        self.assertTrue(out["ok"])


class JsonableStateClassBombUnits(unittest.TestCase):
    def test_class_bomb_salvages_as_exact_text(self):
        out = cloudflared_svc._jsonable_state(_ClassPropertyBomb())
        self.assertIs(type(out), str)

    def test_lying_bool_answers_exact_bool(self):
        out = cloudflared_svc._jsonable_state(_lying(bool))
        self.assertIs(type(out), bool)

    def test_safe_isinstance_survives_the_bomb(self):
        self.assertFalse(cloudflared_svc._safe_isinstance(_ClassPropertyBomb(), dict))
        self.assertTrue(cloudflared_svc._safe_isinstance({}, dict))


class StaysImmunePins(_CloudflaredSandbox):
    """Vectors that already cannot 500 — pinned so they stay that way."""

    def test_hashable_dict_subclass_mapping_key_keeps_siblings(self):
        snap = self._status_with_state({
            "tunnel_name": "home",
            _HashableDictKey(a=1): "poisoned key",
        })
        self.assertEqual(snap["active_tunnel"], "home")

    def test_poisoned_tunnels_cache_iter_bomb_lands_in_tunnels_error(self):
        """``list(cached)`` raising inside list_tunnels is absorbed by the
        status ``tunnels_error`` arm, never a 500."""
        self._sign_in()
        cloudflared_svc._tunnels_cache.update(
            t=9e18, v=_IterBombList([{"id": "x"}]),
        )
        snap = self._status_with_state({})
        self.assertEqual(snap["tunnels"], [])
        self.assertTrue(snap["tunnels_error"])

    def test_overcap_int_compact_token_on_disk_reads_as_invalid(self):
        """``json.loads`` of a >4300-digit number raises bare ValueError;
        the compact-token decoder already catches it, so GET /status
        answers token_ok=false instead of raising."""
        self.token_file.write_text(_overcap_compact_token() + "\n")
        snap = self._status_with_state({})
        self.assertTrue(snap["has_token"])
        self.assertFalse(snap["token_ok"])

    def test_overcap_int_compact_token_stays_a_coded_400_on_start(self):
        tok = _overcap_compact_token()[:4000]
        resp = _client().post("/api/cloudflared/start-token", json={"token": tok})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "cloudflared.invalid_token")


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
class FifoStateFilePin(_CloudflaredSandbox):
    """A FIFO swapped in at serverhub-state.json past the is_file gate must
    neither hang GET /status nor 500 it — read_text_capped opens O_NONBLOCK
    and rejects non-regular files with the OSError _load_state catches."""

    JOIN_TIMEOUT = 5.0

    def test_status_survives_fifo_state_file_toctou(self):
        os.mkfifo(self.state_file)
        real_is_file = cloudflared_svc._path_is_file

        def lying_is_file(p):
            # The probe saw a regular file; the FIFO landed before the open.
            if Path(p) == self.state_file:
                return True
            return real_is_file(p)

        result: dict = {}

        def worker():
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    cloudflared_svc, "_path_is_file", lying_is_file,
                ))
                result["resp"] = _client().get("/api/cloudflared/status")

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(self.JOIN_TIMEOUT)
        self.assertFalse(
            t.is_alive(), "blocked on the state-file FIFO instead of returning",
        )
        resp = result["resp"]
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertIsNone(body["active_tunnel"])


if __name__ == "__main__":
    unittest.main()
