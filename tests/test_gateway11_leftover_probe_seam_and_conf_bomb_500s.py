"""Leftover Gateway-page 500s #12: probe-seam junk and conf-constant bombs.

gateway10 sealed the lying-``__class__`` impostors and the rc sentinel
forgery on the ``sh`` seam.  This wave re-ran the hunt against the mounted
routes with the classes the sibling wave-11 hunts sealed elsewhere —
hash-shadowing stored mapping keys, dict-subclass ``get``/``__getitem__``/
``__bool__`` bombs, junk constants at the spawn/classify rank — and found
the POST routes still open at three seams the module reads bare.  Each of
these was confirmed as an HTTP 500 with a raw traceback before fixing:

* POST /api/nginx/reload, the config-probe seam: ``reload_nginx`` reads the
  probe through the module global (tests and tooling patch it) and then ran
  bare ``t["ok"]`` / ``not t["ok"]`` / ``t.get("message")`` reads.  A dict
  *subclass* whose bound ``__getitem__``/``get``/``__bool__`` raise, a
  *hash-shadowing* stored key (a str-subclass key over the ``ok`` or
  ``message`` slot whose ``__eq__`` raises — the C lookup compares the
  *stored* key against the query, so an exact-str probe still detonated
  it), an ``ok`` value whose ``__bool__`` bombs, a non-dict answer
  (None / str), and a junk *raise* from the probe each 500'd the route;
* POST /api/nginx/test and /reload, the conf constant: ``NGINX_CONF``'s
  ``is_file()`` raising outside the historical ``(OSError, ValueError)``
  pair — or answering a ``__bool__``-bombing leftover that blew the bare
  ``not present`` truth-test — and a conf whose ``str()`` bombs inside the
  argv literal (built *before* ``_sh_triple``'s guard could see it);
* POST /api/nginx/test|reload, the vanished-CLI classify: a junk
  ``NGINX_BIN`` whose ``__fspath__`` bombs TypeError'd ``os.path.isfile``
  past ``_nginx_present``'s OSError-only catch;
* POST /api/nginx/reload, the cache seam: a raising ``invalidate_status`` /
  ``invalidate_launchd`` detonated *after* the reload or kickstart had
  already run, so a completed action answered HTTP 500 and the operator
  retried it.

The fix keeps every prior guard and launders the three seams: ``_probe_answer``
reads ok/message through unbound ``dict.get`` with per-field guards (junk
never consents — an unreadable ``ok`` keeps the invalid-config branch — while
honest fields under a bombed subclass wrapper survive the unbound reads);
``_conf_present`` / ``_conf_arg`` strict-bool and text-launder the conf
constant; ``_nginx_present`` answers "present" for a junk probe so an
unreadable disk read can never *confirm* the vanished classification (the
same no-forgery rule ``_rc_int`` applies to the -1 sentinel — OSError keeps
its historical "not present" answer); ``_invalidate_quietly`` keeps a
completed action's answer.

The rest pins ranks the hunt found already immune, at the HTTP layer: a
stateful ``__class__`` row, a hash-shadowed stored LABEL key in an odd
listing, an ExpatError-raising listing, a bound non-pair ``items()`` dict
value, self-``__str__`` encode-bomb keys and values, and — through the
*real* conf.d parser over temp files — torn IPv6 listen lines, over-cap
listen digit runs, and a FIFO occupying a ``*.conf`` (the O_NONBLOCK-guarded
reader family skips it instead of parking the request).

No exploit code here: every object below is an in-process leftover planted
against our own handlers through the documented provider seams.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from xml.parsers.expat import ExpatError

from fastapi.testclient import TestClient

from hub import nginx_svc
from hub.auth import require_auth
from hub.errors import api_error

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


class _EqBombKey(str):
    """Exact-str storage; the stored key's own ``__eq__``/``__ne__`` raise.

    Hash-shadow rank: the C dict lookup compares the *stored* key against
    the query, so probing with a plain ``"ok"`` still runs this bomb.
    """

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")


class _BombedProbeDict(dict):
    """Real mapping storage behind bound read bombs."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")

    def __getitem__(self, key):
        raise RuntimeError("getitem bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")

    def __str__(self):
        return "bool-bomb"


class _SelfStrEncodeBomb(str):
    """``__str__`` answers itself so a bound ``encode`` bomb stays live."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _StatefulClass:
    """``__class__`` answers dict once, then raises (a stateful liar)."""

    def __init__(self):
        self._reads = 0

    @property
    def __class__(self):
        self._reads += 1
        if self._reads > 1:
            raise RuntimeError("class re-read bomb")
        return dict

    def __str__(self):
        return "stateful-class"


class _NonPairItemsDict(dict):
    """Real storage; the bound ``items()`` yields non-pairs."""

    def items(self):
        return ["not-a-pair", 42]


class _FsPathBomb:
    def __fspath__(self):
        raise RuntimeError("fspath bomb")


class _IsFileRaisesPath:
    def is_file(self):
        raise RuntimeError("is_file bomb")

    def __str__(self):
        return "/tmp/gateway11-x.conf"


class _IsFileBoolBombPath:
    def is_file(self):
        return _BoolBomb()

    def __str__(self):
        return "/tmp/gateway11-x.conf"


class _StrBombPath:
    def is_file(self):
        return True

    def __str__(self):
        raise RuntimeError("str bomb")


class _OddListing:
    def __init__(self, jobs=None, pid=None):
        self.jobs = jobs if jobs is not None else {}
        self._pid = pid

    def pid_for(self, label):
        if self._pid is not None:
            return self._pid
        entry = self.jobs.get(label)
        return entry[0] if entry else None


def _get_nginx(sites, listing=None, listing_raises=None):
    if listing_raises is not None:
        lp = mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=listing_raises
        )
    elif listing is None:
        lp = mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        )
    else:
        lp = mock.patch("hub.nginx_svc.launchd_listing", return_value=listing)
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
        lp,
    ):
        return _client().get("/api/nginx")


class _RealConf(unittest.TestCase):
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
            mock.patch.object(nginx_svc, "sh", side_effect=sh_answers),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=present
            ),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            return self.client.post(path)

    def _reload_with_probe(self, probe, sh_answers=((0, "", ""),)):
        if isinstance(probe, BaseException):
            probe_patch = mock.patch.object(
                nginx_svc, "test_config", side_effect=probe
            )
        else:
            probe_patch = mock.patch.object(
                nginx_svc, "test_config", return_value=probe
            )
        with (
            probe_patch,
            mock.patch.object(nginx_svc, "sh", side_effect=list(sh_answers)),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True
            ),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            return self.client.post("/api/nginx/reload")


class ProbeSeamReloadRouteTests(_RealConf):
    """Junk config-probe answers on POST /api/nginx/reload: each was a 500."""

    def test_bombed_subclass_probe_keeps_the_honest_fields(self):
        # Real {"ok": True, "message": "syntax ok"} storage behind bound
        # __getitem__/get/__bool__ bombs: the unbound reads see the honest
        # fields and the reload proceeds — pre-fix the bare t["ok"] 500'd.
        resp = self._reload_with_probe(
            _BombedProbeDict(ok=True, message="syntax ok")
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "Reloaded\nsyntax ok")

    def test_hash_shadow_stored_ok_key_keeps_the_invalid_branch(self):
        # The stored key over the "ok" slot raises from its own __eq__
        # during the C lookup's collision compare: an unreadable ok is not
        # consent to reload, so the invalid branch holds with the sibling
        # message intact.
        resp = self._reload_with_probe(
            {_EqBombKey("ok"): True, "message": "shadowed"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(
            body["message"], "Invalid configuration; not reloaded\nshadowed"
        )

    def test_hash_shadow_stored_message_key_keeps_the_branch_shape(self):
        resp = self._reload_with_probe(
            {"ok": False, _EqBombKey("message"): "gone"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        # The shadowed slot reads empty; the coded branch prefix survives.
        self.assertEqual(
            body["message"], "Invalid configuration; not reloaded\n"
        )

    def test_bool_bomb_ok_value_never_consents_to_reload(self):
        resp = self._reload_with_probe({"ok": _BoolBomb(), "message": "m"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("Invalid configuration; not reloaded", body["message"])

    def test_non_dict_probe_answers_keep_the_invalid_branch(self):
        for probe in [None, "junk", 7, ["ok"]]:
            resp = self._reload_with_probe(probe)
            self.assertEqual(resp.status_code, 200, resp.text[:200])
            body = resp.json()
            _starlette(body)
            self.assertFalse(body["ok"])
            self.assertIn(
                "Invalid configuration; not reloaded", body["message"]
            )

    def test_junk_probe_raise_degrades_to_the_invalid_branch(self):
        resp = self._reload_with_probe(RuntimeError("torn probe"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("torn probe", body["message"])

    def test_coded_probe_raises_keep_their_contract(self):
        # A coded raise is the probe speaking, not junk: conf_missing keeps
        # its 404 and the confirmed-vanished classification keeps its 503.
        for code, status in [
            ("nginx.conf_missing", 404),
            ("nginx.not_found", 503),
        ]:
            resp = self._reload_with_probe(api_error(code))
            self.assertEqual(resp.status_code, status, resp.text[:200])
            self.assertEqual(resp.json()["detail"]["code"], code)

    def test_honest_probe_answers_stay_untouched(self):
        # The laundered path must not change the honest shapes: a real
        # failed probe keeps its message, a real ok reloads.
        resp = self._reload_with_probe({"ok": False, "message": "bad conf"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            resp.json()["message"],
            "Invalid configuration; not reloaded\nbad conf",
        )
        resp = self._post(
            "/api/nginx/reload", [(0, "syntax ok", ""), (0, "", "")]
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "Reloaded\nsyntax ok")

    def test_shadowed_probe_keeps_the_kickstart_fallback_text(self):
        # ok True behind a bombed wrapper, message hash-shadowed: the
        # kickstart fallback reads "kickstart", never a raw 500.
        resp = self._reload_with_probe(
            {"ok": True, _EqBombKey("message"): "gone"},
            sh_answers=[(1, "", ""), (0, "", "")],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "kickstart")


class ConfConstantBombRouteTests(unittest.TestCase):
    """Patched-or-odd conf constants on Test/Reload: each was a 500."""

    def _post_test(self, conf, sh_answers=((1, "", "err text"),)):
        with (
            mock.patch.object(nginx_svc, "NGINX_CONF", conf),
            mock.patch.object(nginx_svc, "sh", side_effect=list(sh_answers)),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True
            ),
        ):
            return _client().post("/api/nginx/test")

    def test_is_file_raising_junk_reads_as_the_coded_missing_conf(self):
        resp = self._post_test(_IsFileRaisesPath())
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "nginx.conf_missing"
        )

    def test_is_file_bool_bomb_answer_reads_as_the_coded_missing_conf(self):
        resp = self._post_test(_IsFileBoolBombPath())
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "nginx.conf_missing"
        )

    def test_conf_str_bomb_keeps_the_coded_failure_shape(self):
        # The argv text launders to "" and the spawn answer stands — the
        # str() bomb used to blow the argv literal before _sh_triple ran.
        resp = self._post_test(_StrBombPath())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "err text")

    def test_reload_with_a_str_bomb_conf_stays_coded_too(self):
        with (
            mock.patch.object(nginx_svc, "NGINX_CONF", _StrBombPath()),
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "syntax ok", ""), (0, "", "")],
            ),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True
            ),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = _client().post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"])


class VanishedForgeryAndClassifyGuardTests(_RealConf):
    """A junk disk probe can never mint the coded 503; honest reads keep it."""

    def test_junk_nginx_bin_never_confirms_the_vanished_503(self):
        # The honest spawn sentinel beside a probe constant whose
        # __fspath__ bombs: pre-fix os.path.isfile TypeError'd past the
        # OSError-only catch — a raw 500 at the classify itself.  An
        # unreadable probe is no confirmation, so the raw failure holds.
        with (
            mock.patch.object(
                nginx_svc, "sh", side_effect=[(-1, "", "not found")]
            ),
            mock.patch.object(nginx_svc, "NGINX_BIN", _FsPathBomb()),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "not found")

    def test_honest_sentinel_with_the_binary_gone_keeps_the_503(self):
        # Do-not-weaken pin: the disk-confirmed classification gateway5
        # established still answers the coded 503 for a real absence.
        missing = str(self.conf.parent / "gateway11-definitely-missing-bin")
        with (
            mock.patch.object(
                nginx_svc, "sh", side_effect=[(-1, "", "not found")]
            ),
            mock.patch.object(nginx_svc, "NGINX_BIN", missing),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.not_found")

    def test_eio_disk_probe_keeps_its_historical_not_present_answer(self):
        # OSError is the disk speaking and stays "not present" (the
        # pre-existing arm, unweakened): the sentinel still classifies.
        with (
            mock.patch.object(
                nginx_svc, "sh", side_effect=[(-1, "", "not found")]
            ),
            mock.patch.object(
                nginx_svc.os.path, "isfile", side_effect=OSError(5, "EIO")
            ),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.not_found")


class InvalidateSeamRouteTests(_RealConf):
    """A raising cache invalidator must not 500 a completed action."""

    def _reload(self, sh_answers, launchd_bomb=False, status_bomb=False):
        launchd_patch = (
            mock.patch.object(
                nginx_svc, "invalidate_launchd",
                side_effect=RuntimeError("cache bomb"),
            )
            if launchd_bomb
            else mock.patch.object(nginx_svc, "invalidate_launchd")
        )
        status_patch = (
            mock.patch.object(
                nginx_svc, "invalidate_status",
                side_effect=RuntimeError("cache bomb"),
            )
            if status_bomb
            else mock.patch.object(nginx_svc, "invalidate_status")
        )
        with (
            mock.patch.object(nginx_svc, "sh", side_effect=sh_answers),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=True
            ),
            launchd_patch,
            status_patch,
        ):
            return self.client.post("/api/nginx/reload")

    def test_status_bomb_on_the_success_path_keeps_the_reloaded_answer(self):
        resp = self._reload(
            [(0, "syntax ok", ""), (0, "", "")], status_bomb=True
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "Reloaded\nsyntax ok")

    def test_both_bombs_on_the_kickstart_path_keep_the_kick_answer(self):
        resp = self._reload(
            [(0, "syntax ok", ""), (1, "", "stale pid"), (0, "kick ok", "")],
            launchd_bomb=True,
            status_bomb=True,
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "kick ok")


class StaysImmunePinTests(unittest.TestCase):
    """Ranks the hunt found already immune, pinned at the HTTP layer."""

    def test_stateful_class_row_drops_alone(self):
        # __class__ answers dict at the row gate, then raises on every
        # re-read inside _jsonable: the row degrades and the sibling holds.
        resp = _get_nginx([
            _StatefulClass(),
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual([s["file"] for s in body["sites"]], ["sane.conf"])

    def test_hash_shadow_stored_label_key_in_an_odd_listing_stays_no_pid(self):
        # The stored key over the LABEL slot raises from its own __eq__
        # inside pid_for's mapping lookup; overview's guard keeps the page.
        listing = _OddListing(
            jobs={_EqBombKey(nginx_svc.LABEL): ("123", "0")}
        )
        resp = _get_nginx([{"file": "sane.conf"}], listing=listing)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])
        self.assertEqual(body["site_count"], 1)

    def test_expat_error_from_the_listing_seam_stays_no_pid(self):
        # A plist-shaped parse failure (ExpatError) riding the listing seam
        # is just another guarded raise: no pid, never a 500.
        resp = _get_nginx(
            [{"file": "sane.conf"}],
            listing_raises=ExpatError("syntax error: line 1, column 0"),
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])

    def test_non_pair_bound_items_dict_value_keeps_real_entries(self):
        # The unbound dict.items read dodges the bound non-pair answer, so
        # the real storage renders.
        resp = _get_nginx([
            {"file": "a.conf", "v": _NonPairItemsDict({"x": 1})},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        row = {s["file"]: s for s in body["sites"]}["a.conf"]
        self.assertEqual(row["v"], {"x": 1})

    def test_self_str_encode_bomb_key_and_value_render_their_text(self):
        resp = _get_nginx([
            {
                "file": "a.conf",
                "v": _SelfStrEncodeBomb("vtext"),
                "d": {_SelfStrEncodeBomb("ktext"): "y"},
            },
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        row = {s["file"]: s for s in body["sites"]}["a.conf"]
        self.assertEqual(row["v"], "vtext")
        self.assertEqual(row["d"], {"ktext": "y"})


class RealParserConfDPinTests(unittest.TestCase):
    """Leftover on-disk conf.d shapes through the *real* parser: never a 500."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gateway11-home-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.conf_d = self.home / "Services" / "nginx" / "conf.d"
        self.conf_d.mkdir(parents=True)
        patched = mock.patch("hub.adaptive.user_home", return_value=self.home)
        patched.start()
        self.addCleanup(patched.stop)

    def _get(self):
        with mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        ):
            return _client().get("/api/nginx")

    def test_torn_ipv6_listen_lines_never_500_and_the_sane_port_parses(self):
        (self.conf_d / "torn.conf").write_text(
            "server {\n"
            "  listen [2001:db8::;\n"        # torn bracket, no port
            "  listen [::]:8443 ssl;\n"      # sane bracketed v6
            "  listen [::1];\n"              # bracketed, portless
            "  listen 9" + "9" * 4400 + ";\n"  # over-cap digit run
            "  server_name example.test;\n"
            "}\n"
        )
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        rows = {s["file"]: s for s in body["sites"]}
        self.assertIn("torn.conf", rows)
        # The sane v6 port parses; the torn/portless/over-cap rows drop
        # silently instead of raising out of the parser.
        self.assertIn(8443, rows["torn.conf"]["listens"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no FIFOs")
    def test_fifo_occupying_a_conf_is_skipped_not_parked_on(self):
        os.mkfifo(self.conf_d / "pipe.conf")
        (self.conf_d / "sane.conf").write_text("listen 8080;\n")
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = [s["file"] for s in body["sites"]]
        # The O_NONBLOCK-guarded reader family never opens the FIFO as a
        # site; the sane sibling renders and the request answers promptly.
        self.assertNotIn("pipe.conf", files)
        self.assertIn("sane.conf", files)
        self.assertEqual(
            {s["file"]: s for s in body["sites"]}["sane.conf"]["listens"],
            [8080],
        )


if __name__ == "__main__":
    unittest.main()
