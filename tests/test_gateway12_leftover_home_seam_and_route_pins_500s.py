"""Twelfth leftover-500s sweep of the Gateway page: the ``user_home`` seam.

gateway11 sealed the config-probe seam and the conf/bin constant bombs on the
mounted nginx routes.  Re-running the hunt with the *provider-seam-call*
shape the sibling backups12 wave surfaced elsewhere — a seam whose call sits
outside every guard — found one live leftover this module never got, plus a
crop of fresh runtime shapes the gateway6-11 guards already answer (pinned
below so a later edit cannot regress them).

The live leftover — ``hub.nginx_svc._default_root``:

* Every runtime read of the derived path constants is laundered
  (``_as_text(NGINX_CONF)`` at render, ``_conf_present`` / ``_conf_arg`` at
  the spawn), but the *derivation* trusted the ``user_home`` provider raw:

      home = user_home()
      return (home / "Services" / "nginx") if home is not None else ...

  ``hub.paths.user_home`` answers ``Path`` or ``None`` today, but the call was
  joined bare — ``home / "Services" / "nginx"`` assumed a Path.  A provider
  that raises outside that helper's caught ``(OSError, RuntimeError,
  ValueError)`` trio (a ``KeyError`` from a ``pwd`` lookup on a uid with no
  passwd entry — the container/sandbox "leftover HOME" this module's own
  docstring already names) escaped, and a leftover that answers text / bytes /
  junk instead of a Path detonated the join with a ``TypeError`` on
  ``str.__truediv__``.  Because the constant is computed at import
  (``NGINX_ROOT = _default_root()``), the raise took the *whole module* down —
  and with it ``hub.routers.modules_api``, which imports it — so
  GET /api/nginx and POST /api/nginx/test|reload answered HTTP 500 (the router
  never mounted) instead of the sentinel root's coded shapes.  Confirmed at
  HEAD: ``_default_root`` raised ``RuntimeError`` / ``KeyError`` for a raising
  provider and ``TypeError`` for a str / bytes / int / object answer.

The fix is the backups12 ``_user_home`` rule, self-contained because it runs
before ``_isinst`` / ``_as_text`` exist: a real Path passes; a textual answer
still names a real directory and is kept as a Path (surrogates via
``surrogateescape``); a raise, junk, or a raising-``__class__`` gate degrades
to ``None`` and the caller takes the ``/var/empty`` sentinel.  The three
routes then answer their coded shapes on a poisoned import instead of 500.

Conflict policy is pinned, not re-claimed: ``_isinst`` stays fail-closed,
``type(x) is bool`` still drops a bool-liar to null, the guarded
``_decode_bytes`` stays, ``_probe_answer`` keeps consent-on-evidence,
``_conf_present`` / ``_conf_arg`` strict-bool and text-launder the conf
constant, and ``_sh3`` / ``_rc_int`` degrade junk to ``-255`` — never the
``-1`` spawn sentinel a poisoned object could use to forge the vanished-CLI
503.  Product version stays 3.9.3.

No exploit code here: every object below is an in-process leftover planted
against our own handlers through the documented provider seams.
"""
from __future__ import annotations

import importlib
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
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _OddListing:
    """A patched launchd listing whose ``pid_for`` answers a planted shape."""

    def __init__(self, pid):
        self._pid = pid

    def pid_for(self, label):
        return self._pid


def _get_nginx(sites, pid="__unset__"):
    if pid == "__unset__":
        lp = mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        )
    else:
        lp = mock.patch(
            "hub.nginx_svc.launchd_listing", return_value=_OddListing(pid)
        )
    with mock.patch.object(nginx_svc, "nginx_sites", return_value=sites), lp:
        return _client().get("/api/nginx")


# --------------------------------------------------------------------------
# Leftover objects planted through the provider seams.
# --------------------------------------------------------------------------
class _RaisingClass:
    """``__class__`` is a raising property (the gateway9 class-bomb shape)."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")

    def __str__(self):
        return "raising-class"


class _BoolLiar:
    """A lying ``__class__`` claiming ``bool`` over no real bool storage."""

    @property
    def __class__(self):
        return bool

    def __str__(self):
        return "bool-liar"


class _DecodeBombBytes(bytes):
    """Real byte storage behind a bound ``.decode`` bomb (guarded-decode pin)."""

    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class _IterBomb:
    """A leftover whose ``__iter__`` raises; it is no known container."""

    def __iter__(self):
        raise RuntimeError("iter bomb")

    def __str__(self):
        return "iter-bomb"


class _CustomIter:
    def __iter__(self):
        return iter([1, 2, 3])

    def __str__(self):
        return "custom-iter"


class _RcImpostor:
    """A lying ``__class__`` claiming ``int`` over no real int storage.

    ``_rc_int`` must degrade it to ``-255`` (junk), never the ``-1`` spawn
    sentinel a poisoned object could use to forge the vanished-CLI 503.
    """

    @property
    def __class__(self):
        return int

    def __str__(self):
        return "rc-impostor"


class _BombedProbeDict(dict):
    """Real ``{"ok": ..., "message": ...}`` storage behind bound read bombs."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")

    def __getitem__(self, key):
        raise RuntimeError("getitem bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _IsFileRaisesConf:
    def is_file(self):
        raise RuntimeError("is_file bomb")

    def __str__(self):
        return "/tmp/gateway12-x.conf"


class _StrBombConf:
    def is_file(self):
        return True

    def __str__(self):
        raise RuntimeError("str bomb")


class HomeSeamDefaultRootTests(unittest.TestCase):
    """``_default_root`` must not 500 the import on a leftover ``user_home``."""

    SENTINEL = Path("/var/empty/serverhub-nginx")

    def _root(self, *, side=None, ret="__unset__"):
        if side is not None:
            patch = mock.patch.object(nginx_svc, "user_home", side_effect=side)
        else:
            patch = mock.patch.object(nginx_svc, "user_home", return_value=ret)
        with patch:
            return nginx_svc._default_root()

    def test_raising_provider_takes_the_sentinel_root(self):
        # A raise outside user_home's caught trio (RuntimeError re-raised, or a
        # KeyError from a pwd lookup) used to escape _default_root and crash
        # the import; it now degrades to the /var/empty sentinel.
        for exc in (RuntimeError("home bomb"), KeyError("uid"), OSError("eio")):
            self.assertEqual(self._root(side=exc), self.SENTINEL)

    def test_text_answer_is_kept_as_a_real_home(self):
        # A textual answer still names a real directory (backups12 rule): kept
        # as a Path rather than discarded.  Pre-fix, str/bytes TypeError'd the
        # ``home / "Services"`` join.
        self.assertEqual(
            self._root(ret="/home/leftover"),
            Path("/home/leftover/Services/nginx"),
        )
        self.assertEqual(
            self._root(ret=b"/home/bytes-home"),
            Path("/home/bytes-home/Services/nginx"),
        )

    def test_surrogate_text_home_is_kept(self):
        # An undecodable on-disk HOME arrives as a str carrying a lone
        # surrogate through surrogateescape: kept as a Path, scrubbed only at
        # render time by _as_text.
        root = self._root(ret="/home/\udcff")
        self.assertEqual(root, Path("/home/\udcff/Services/nginx"))

    def test_non_text_junk_takes_the_sentinel(self):
        # int / object / None / a raising-__class__ / a bool-liar are no
        # usable home: the sentinel holds instead of a TypeError'd join.
        for junk in (12345, object(), None, _RaisingClass(), _BoolLiar()):
            self.assertEqual(self._root(ret=junk), self.SENTINEL)

    def test_real_path_answer_is_used_unchanged(self):
        # Do-not-weaken: a genuine Path still yields the ~/Services/nginx tree.
        self.assertEqual(
            self._root(ret=Path("/tmp/realhome")),
            Path("/tmp/realhome/Services/nginx"),
        )

    def test_user_home_reader_answers_none_for_junk(self):
        with mock.patch.object(
            nginx_svc, "user_home", side_effect=RuntimeError("x")
        ):
            self.assertIsNone(nginx_svc._user_home())
        with mock.patch.object(nginx_svc, "user_home", return_value=object()):
            self.assertIsNone(nginx_svc._user_home())


class HomeSeamReimportRouteTests(unittest.TestCase):
    """A poisoned ``user_home`` at import no longer takes the routes to 500.

    Patch the *source* ``hub.paths.user_home`` so the re-executed
    ``from hub.paths import user_home`` binds the leftover, then reload the
    module in place (the router holds a module reference, so it resolves the
    reloaded functions).  ``tests/__init__`` keeps HOME hermetic, so the
    clean reload in ``tearDown`` restores a sane tree for the rest of the run.
    """

    def tearDown(self):
        importlib.reload(nginx_svc)

    def _reload_with_home(self, **home_patch):
        with mock.patch("hub.paths.user_home", **home_patch):
            importlib.reload(nginx_svc)

    def test_raising_home_provider_keeps_the_routes_answering(self):
        self._reload_with_home(side_effect=RuntimeError("home bomb"))
        self.assertEqual(nginx_svc.NGINX_ROOT, Path("/var/empty/serverhub-nginx"))
        client = _client()
        resp = client.get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())
        self.assertEqual(
            resp.json()["conf"], "/var/empty/serverhub-nginx/nginx.conf"
        )
        # The spawn routes answer their coded missing-conf shape, not a 500.
        test_resp = client.post("/api/nginx/test")
        self.assertEqual(test_resp.status_code, 404, test_resp.text[:200])
        self.assertEqual(
            test_resp.json()["detail"]["code"], "nginx.conf_missing"
        )

    def test_non_path_home_provider_reimports_clean(self):
        # A non-Path answer (int) used to TypeError the import; now the
        # sentinel holds and the module imports.
        self._reload_with_home(return_value=12345)
        self.assertEqual(nginx_svc.NGINX_ROOT, Path("/var/empty/serverhub-nginx"))
        resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())


class RouteImmunityPinTests(unittest.TestCase):
    """Fresh runtime shapes on GET /api/nginx the guards already answer."""

    def test_generator_and_custom_iterable_values_render_as_text(self):
        def gen():
            yield 1
            yield 2

        resp = _get_nginx([
            {"file": "a.conf", "g": gen(), "it": _CustomIter()},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        row = {s["file"]: s for s in body["sites"]}["a.conf"]
        # Neither is a known JSON container: both degrade to their text.
        self.assertIsInstance(row["g"], str)
        self.assertEqual(row["it"], "custom-iter")

    def test_iter_bomb_value_degrades_and_sibling_row_survives(self):
        resp = _get_nginx([
            {"file": "a.conf", "bomb": _IterBomb()},
            {"file": "b.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {s["file"]: s for s in body["sites"]}
        self.assertEqual(rows["a.conf"]["bomb"], "iter-bomb")
        self.assertEqual(rows["b.conf"]["listens"], [8080])

    def test_deeply_nested_and_self_referential_values_never_500(self):
        deep = cur = {}
        for _ in range(60):
            cur["n"] = {}
            cur = cur["n"]
        cur["leaf"] = "\udcff"
        selfref: dict = {}
        selfref["me"] = selfref
        resp = _get_nginx([
            {"file": "a.conf", "deep": deep, "self": selfref},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())

    def test_bool_liar_value_drops_to_null(self):
        # type(x) is bool pin: a lying-__class__ claiming bool falls to the int
        # arm where the unbound coercion drops it to null; a real bool passes.
        resp = _get_nginx([
            {"file": "a.conf", "liar": _BoolLiar(), "real": True},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        row = {s["file"]: s for s in body["sites"]}["a.conf"]
        self.assertIsNone(row["liar"])
        self.assertIs(row["real"], True)

    def test_decode_bomb_bytes_value_renders_its_text(self):
        # guarded-decode pin: unbound bytes.decode dodges the bound bomb.
        resp = _get_nginx([
            {"file": "a.conf", "v": _DecodeBombBytes(b"payload")},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        row = {s["file"]: s for s in body["sites"]}["a.conf"]
        self.assertEqual(row["v"], "payload")

    def test_raising_class_pid_stays_no_pid(self):
        resp = _get_nginx([{"file": "a.conf"}], pid=_RaisingClass())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])
        self.assertEqual(body["site_count"], 1)


class SpawnAndProbePinTests(unittest.TestCase):
    """POST-route conflict-policy pins over a real conf file."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()

    def _post(self, path, sh_answers, present=True):
        with (
            mock.patch.object(nginx_svc, "sh", side_effect=list(sh_answers)),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=present
            ),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            return self.client.post(path)

    def test_rc_impostor_stays_a_plain_failure_not_the_vanished_503(self):
        # _rc_int/_sh3 degrade a lying-int rc impostor to -255 (junk), which is
        # no honest nginx exit and never the -1 spawn sentinel: the coded 503
        # can only be minted by a real, disk-confirmed absence.
        resp = self._post(
            "/api/nginx/test", [(_RcImpostor(), "", "boom")], present=True
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "boom")

    def test_bombed_subclass_probe_keeps_the_honest_fields(self):
        # _probe_answer reads ok/message through unbound dict.get: the honest
        # storage survives the bound __getitem__/get/__bool__ bombs.
        with (
            mock.patch.object(
                nginx_svc, "test_config",
                return_value=_BombedProbeDict(ok=True, message="syntax ok"),
            ),
            mock.patch.object(
                nginx_svc, "sh", side_effect=[(0, "", "")]
            ),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True
            ),
            mock.patch.object(nginx_svc, "invalidate_status"),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "Reloaded\nsyntax ok")


class ConfConstantPinTests(unittest.TestCase):
    """``_conf_present`` / ``_conf_arg`` still launder a leftover conf object."""

    def _post_test(self, conf, sh_answers=((1, "", "err text"),)):
        with (
            mock.patch.object(nginx_svc, "NGINX_CONF", conf),
            mock.patch.object(nginx_svc, "sh", side_effect=list(sh_answers)),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True
            ),
        ):
            return _client().post("/api/nginx/test")

    def test_is_file_bomb_reads_as_the_coded_missing_conf(self):
        resp = self._post_test(_IsFileRaisesConf())
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.conf_missing")

    def test_str_bomb_conf_keeps_the_coded_failure_shape(self):
        resp = self._post_test(_StrBombConf())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "err text")


class HelperUnitPinTests(unittest.TestCase):
    """Direct pins on the conflict-policy helpers (do-not-weaken)."""

    def test_isinst_is_fail_closed(self):
        self.assertFalse(nginx_svc._isinst(_RaisingClass(), int))
        self.assertTrue(nginx_svc._isinst(5, int))

    def test_rc_int_junk_is_minus_255_never_minus_1(self):
        self.assertEqual(nginx_svc._rc_int(_RcImpostor()), -255)
        self.assertEqual(nginx_svc._rc_int("junk"), -255)
        self.assertEqual(nginx_svc._rc_int(object()), -255)
        # Honest exits and the True/False shorthand survive untouched.
        self.assertEqual(nginx_svc._rc_int(0), 0)
        self.assertEqual(nginx_svc._rc_int(-1), -1)
        self.assertEqual(nginx_svc._rc_int(True), 1)
        self.assertEqual(nginx_svc._rc_int(False), 0)

    def test_sh3_junk_degrades_to_minus_255_triple(self):
        self.assertEqual(nginx_svc._sh3(None), (-255, "", ""))
        self.assertEqual(nginx_svc._sh3((1, 2)), (-255, "", ""))
        self.assertEqual(nginx_svc._sh3(_RcImpostor()), (-255, "", ""))
        # An honest triple passes through.
        self.assertEqual(nginx_svc._sh3((0, "o", "e")), (0, "o", "e"))

    def test_probe_answer_junk_never_consents(self):
        self.assertEqual(nginx_svc._probe_answer(None), (False, ""))
        self.assertEqual(nginx_svc._probe_answer("junk"), (False, "junk"))
        ok, _msg = nginx_svc._probe_answer(
            _BombedProbeDict(ok=True, message="m")
        )
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
