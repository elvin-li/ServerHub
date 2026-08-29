"""Leftover Gateway-page 500s #7: the one scrubber that never went unbound.

Prior sweeps sealed GET /api/nginx field by field, the pid and conf-path
shapes, the on-disk/vanished-CLI classes, and the runner's raise/arity rank
(test_gateway5_leftover_odd_sh_and_http_pins and its predecessors).  A fresh
hunt over the same mounted routes found that hub/nginx_svc.py was the last
service still reading through *bound* calls — every sibling scrubber
(system, status, scheduler, storage, sensors, ollama, photoshub, …) adopted
the modules5 unbound convention (``int.__index__`` / ``float.__float__`` /
``dict.items(value)`` / ``base.__iter__`` / unbound base decode) and this
module never did.  Confirmed against the mounted routes before fixing —
each of these was an HTTP 500 with a raw traceback:

* GET /api/nginx, a site-row *value* that passes the isinstance gates but
  bombs the bound probe: an int subclass whose ``__str__`` raises
  non-ValueError (the digit-cap probe caught ValueError alone), a float
  subclass whose ``__eq__``/``__ne__`` raises (the NaN/inf probes compare),
  a bytes subclass whose ``__bytes__`` raises (``bytes(value)`` re-enters
  it before the copy), and a str subclass whose ``__str__`` answers *self*
  so the bound ``encode`` bomb stayed live through ``_as_text``'s final
  scrub line;
* GET /api/nginx, the same classes at *key* rank: a bytes-subclass key
  whose ``decode`` raises and a str-subclass key with the self-``__str__``
  + ``encode`` bomb both rode ``_as_text(k)`` to Starlette;
* POST /api/nginx/test, an odd ``sh`` answer (the exact provider rank
  gateway5 fixed for raises and arity) whose *fields* bomb: a
  bytes-subclass stdout/stderr with a ``decode`` bomb, a str-subclass
  stderr with the ``encode`` bomb, and an int-subclass rc whose ``__eq__``
  raises — ``rc == 0`` / ``rc == -1`` rode the comparison to Starlette;
* POST /api/nginx/reload, the same rc ``__eq__`` bomb at the ``-s reload``
  spawn rank (``rc != 0``) and the decode-bomb bytes at the kickstart
  answer rank.

The fix brings the module to the convention: ``_decode_bytes`` (unbound
base decode), exact-int/exact-float base coercion in ``_jsonable`` and
``_pid_text``, the unbound ``dict.items(value)`` / ``base.__iter__`` walk
(a bound ``items()`` / ``__iter__`` bomb no longer costs even the field —
the real entries survive), an unbound ``str.encode`` on ``_as_text``'s
final line, and an exact-int rc coercion inside ``_sh_triple`` (a non-int
rc degrades to the same failure code as a raising runner; the vanished-CLI
classification stays disk-confirmed).

The rest of this battery pins vectors the same hunt found already immune
or merely lossy, held at the HTTP layer so a refactor cannot quietly
reopen them: a decode-bomb bytes *value* (the ``bytes()`` copy already
dodged it), an int-subclass ``__str__``-bomb pid from an odd listing
(guarded before, but it flipped ``running`` to a false "stopped" — the
base coercion now keeps the truthful pid), a str "0" rc from an odd runner
(never a success), and an int-subclass ``__str__``-bomb key (the entry
drops, never the row).

``os.kill`` does not apply here: nothing in hub/nginx_svc.py or its router
signals a pid, and the Gateway backend owns no JSON journal — its only
persistence is the audit trail, whose loader already drops unparseable
lines one at a time (hub/audit.py).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import nginx_svc
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _StrBombInt(int):
    """Passes ``isinstance(x, int)``; raises non-ValueError at str()."""

    def __str__(self):
        raise RuntimeError("int str bomb")


class _EqBombFloat(float):
    """Passes ``isinstance(x, float)``; raises the moment it is compared."""

    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _BytesDunderBomb(bytes):
    """``bytes(value)`` re-enters ``__bytes__`` before the exact copy."""

    def __bytes__(self):
        raise RuntimeError("bytes bomb")


class _DecodeBombBytes(bytes):
    """Passes ``isinstance(x, bytes)``; raises at any bound decode."""

    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class _SelfStr(str):
    """``str()`` of it answers *itself*, keeping the encode bomb live."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _EqBombInt(int):
    """Passes ``isinstance(x, int)``; raises the moment it is compared."""

    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class _OddListing:
    def __init__(self, pid):
        self._pid = pid

    def pid_for(self, label):
        return self._pid


def _get_nginx(sites, listing=None):
    if listing is None:
        listing_patch = mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        )
    else:
        listing_patch = mock.patch(
            "hub.nginx_svc.launchd_listing", return_value=listing
        )
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
        listing_patch,
    ):
        return _client().get("/api/nginx")


class UnboundValueRankRouteTests(unittest.TestCase):
    """Site-row values that bombed the bound probes: each was an HTTP 500."""

    def test_int_subclass_str_bomb_value_survives_as_the_real_int(self):
        # The digit-cap probe caught ValueError alone; a RuntimeError from a
        # subclass __str__ escaped overview() and 500'd the route.  The base
        # coercion (int.__index__) reads the real value through the bomb.
        resp = _get_nginx([
            {"file": "a.conf", "n": _StrBombInt(7)},
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"]["n"], 7)
        self.assertEqual(files["sane.conf"]["listens"], [8080])

    def test_float_subclass_eq_bomb_value_survives_as_the_real_float(self):
        # The NaN/inf probes are comparisons; a subclass __eq__/__ne__ bomb
        # rode them to Starlette.  float.__float__ reads through it.
        resp = _get_nginx([
            {"file": "a.conf", "weight": _EqBombFloat(1.5)},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"]["weight"], 1.5)

    def test_bytes_subclass_dunder_bytes_bomb_value_drops_alone(self):
        # ``bytes(value)`` calls a subclass ``__bytes__`` before copying;
        # the unbound base decode never re-enters the subclass at all.
        resp = _get_nginx([
            {"file": "a.conf", "raw": _BytesDunderBomb(b"x")},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"]["raw"], "x")

    def test_str_subclass_self_str_encode_bomb_value_is_scrubbed(self):
        # str() of it answers itself, so _as_text's final line used to call
        # the *subclass* encode — the unbound str.encode dodges the bomb.
        resp = _get_nginx([
            {"file": "a.conf", "note": _SelfStr("fine")},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"]["note"], "fine")


class UnboundKeyRankRouteTests(unittest.TestCase):
    """The same classes at key rank: each was an HTTP 500."""

    def test_bytes_subclass_decode_bomb_key_reads_through_the_base(self):
        resp = _get_nginx([
            {_DecodeBombBytes(b"k"): "v", "file": "a.conf"},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"]["k"], "v")

    def test_str_subclass_encode_bomb_key_reads_through_the_base(self):
        resp = _get_nginx([
            {_SelfStr("k"): "v", "file": "a.conf"},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"]["k"], "v")

    def test_int_subclass_str_bomb_key_drops_the_entry_not_the_row(self):
        # Key coercion is str(k) under a broad guard already: the bombed
        # entry drops alone, the row and its siblings survive.
        resp = _get_nginx([
            {_StrBombInt(3): "v", "file": "a.conf"},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertIn("sane.conf", files)
        self.assertEqual(files["a.conf"], {"file": "a.conf"})


class _RealConf(unittest.TestCase):
    """A real empty nginx.conf so test_config reaches the spawn."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()


class OddRunnerFieldBombRouteTests(_RealConf):
    """Odd-``sh`` answers whose *fields* bomb: each was an HTTP 500."""

    def _post_test(self, sh_ret):
        with (
            mock.patch.object(nginx_svc, "sh", return_value=sh_ret),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            return self.client.post("/api/nginx/test")

    def test_decode_bomb_stderr_degrades_to_the_base_text(self):
        resp = self._post_test((1, "", _DecodeBombBytes(b"bad conf")))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "bad conf")

    def test_decode_bomb_stdout_degrades_to_the_base_text(self):
        resp = self._post_test((1, _DecodeBombBytes(b"out text"), None))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "out text")

    def test_encode_bomb_str_subclass_stderr_is_scrubbed(self):
        resp = self._post_test((1, "", _SelfStr("bad")))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "bad")

    def test_eq_bomb_rc_on_test_keeps_the_message_and_the_200(self):
        # rc == 0 / rc == -1 used to ride the subclass __eq__ to Starlette;
        # int.__index__ reads the real value through the bomb.
        resp = self._post_test((_EqBombInt(1), "", "err text"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "err text")

    def test_eq_bomb_zero_rc_still_counts_as_success(self):
        # The truthful side of the same coercion: a bombed rc whose real
        # value is 0 must keep reporting ok.
        resp = self._post_test((_EqBombInt(0), "", "syntax is ok"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"])

    def test_string_zero_rc_from_an_odd_runner_is_never_a_success(self):
        # A non-int rc degrades to the failure code: "0" the str is not 0.
        resp = self._post_test(("0", "", "odd"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertFalse(resp.json()["ok"])


class OddRunnerReloadRankRouteTests(_RealConf):
    """The same bombs at reload's two later spawn ranks."""

    def test_eq_bomb_rc_at_the_reload_spawn_reaches_kickstart(self):
        # -t passes, -s reload answers a bombed nonzero rc: rc != 0 must
        # classify without raising and fall through to kickstart.
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "", "ok"), (_EqBombInt(1), "", "stale"),
                             (0, "kick ok", "")],
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertIn("kick ok", body["message"])

    def test_decode_bomb_kickstart_answer_degrades_to_the_base_text(self):
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "", "ok"), (1, "", "boom"),
                             (0, _DecodeBombBytes(b"kicked"), "")],
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "kicked")


class StaysImmuneRoutePinTests(unittest.TestCase):
    """Vectors the hunt found already immune or merely lossy, pinned."""

    def test_decode_bomb_bytes_value_was_already_dodged_by_the_copy(self):
        # A plain decode-bomb bytes value (no __bytes__ override) was
        # already safe — the exact-bytes copy never called the subclass
        # decode.  The unbound base decode keeps that immunity.
        resp = _get_nginx([
            {"file": "a.conf", "raw": _DecodeBombBytes(b"ok")},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertEqual(files["a.conf"]["raw"], "ok")

    def test_str_bomb_pid_from_an_odd_listing_keeps_reporting_running(self):
        # Guarded before (overview()'s try), but the escape flipped
        # ``running`` to a false "stopped" while nginx held a real pid; the
        # base coercion now reads the truthful value through the bomb.
        resp = _get_nginx([], listing=_OddListing(_StrBombInt(743)))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["pid"], "743")
        self.assertTrue(body["running"])

    def test_eq_bomb_pid_from_an_odd_listing_keeps_reporting_running(self):
        resp = _get_nginx([], listing=_OddListing(_EqBombInt(9)))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["pid"], "9")
        self.assertTrue(body["running"])


if __name__ == "__main__":
    unittest.main()
