"""Leftover Gateway-page 500s #6: the spawn itself was the last unguarded rank.

Prior sweeps sealed GET /api/nginx field by field (surrogate keys/values,
already-int over-cap numbers, bytes, non-dict rows, iterbomb list subclasses
and items-bomb rows — test_leftover_gateway_sites_scrub_500s and
test_leftover_gateway_iterbomb_sibling_wipe_500s), the pid and conf-path
shapes (test_leftover_gateway_surrogate_pid_500s), and the vanished-CLI /
poisoned-conf.d classes at the HTTP layer
(test_modules_gateway_leftover_stays_immune_500s).  A fresh hunt over the
same mounted routes found the one provider all of those passes trusted: the
runner.  ``test_config``/``reload_nginx`` do not own ``sh`` — the production
one never raises and always answers ``(rc, out, err)``, but a patched or odd
one (the exact class ``_sh_message`` already guards at *value* rank: bytes,
None, surrogates) can raise outright or answer a wrong-arity tuple / bare
None.  Confirmed against the mounted routes before fixing — each of these
was an HTTP 500 with a raw traceback:

* ``sh`` raising (RecursionError from a leftover ``str(e)`` on a nested
  exception is not ValueError; FileNotFoundError from a stub) rode straight
  to Starlette out of POST /api/nginx/test and both spawn ranks of
  POST /api/nginx/reload;
* a 2-tuple / bare-None answer ValueError'd / TypeError'd the
  ``rc, out, err = sh(...)`` unpack the same way.

The fix is the brew_svc.service_action rule: the unpack moves inside the
guard (``_sh_triple``), a raising or wrong-arity runner degrades to the
failure triple ``(-1, "", text)``, and the vanished-CLI classification stays
with the callers — disk-confirmed, on the failure path only, so a raise
whose text merely reads "not found" becomes the coded 503 only when nginx is
really gone from disk, and keeps its raw ``{ok: false}`` while the binary is
still present.

The rest of this battery pins vectors the same hunt found already immune,
held at the HTTP layer so a refactor cannot quietly reopen them: an
already-int over-cap rc from an odd runner (CPython's 4300-digit int->str
cap; nothing may render it), dict-subclass rows whose ``.get`` / ``.keys`` /
``__bool__`` raise (the sibling ranks of the pinned items-bomb), unhashable
list-subclass values inside ``listens`` and a ``complex`` value, a
huge-number JSON body against the body-less POST (``json.loads`` of those
digits is ValueError, *not* JSONDecodeError, so nothing here may catch
JSONDecodeError alone), a FIFO occupying nginx.conf (must answer the coded
404, never park the request thread on ``open``), and a real on-disk conf.d
holding a torn-IPv6 ``listen [::1;`` / ``proxy_pass http://[::1`` (the
urlsplit ValueError class — the parser never urlsplits, and the raw text
must still encode), a Unicode-digit listen, a 5000-digit listen, an
oversize conf past the 256 KiB cap, invalid-UTF-8 bytes with NULs, and a
FIFO / directory / dangling symlink / self-loop symlink each named
``*.conf`` — all beside one sane site that must keep its row and its port.

``os.kill`` does not apply here: nothing in hub/nginx_svc.py or its router
signals a pid, and the Gateway backend owns no JSON journal — its only
persistence is the audit trail, whose loader already drops unparseable
lines one at a time (hub/audit.py).
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import nginx_svc
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

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


class OddRunnerRouteTests(_RealConf):
    """Raising / wrong-arity sh shapes: the fix.  Each was an HTTP 500."""

    def test_sh_raising_degrades_test_to_ok_false_scrubbed(self):
        # RecursionError carrying a lone surrogate: the raise must not reach
        # Starlette, and the degraded message must reach the SPA scrubbed.
        with mock.patch.object(
            nginx_svc, "sh", side_effect=RecursionError("deep \ud800")
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("deep", body["message"])
        self.assertNotIn("\ud800", body["message"])

    def test_sh_raising_degrades_reload_to_the_invalid_conf_branch(self):
        with mock.patch.object(
            nginx_svc, "sh", side_effect=ValueError("boom")
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("Invalid configuration; not reloaded", body["message"])
        self.assertIn("boom", body["message"])

    def test_wrong_arity_and_bare_none_answers_degrade_to_ok_false(self):
        # A leftover 2-tuple / bare-None stub is a ValueError / TypeError at
        # the unpack — now inside the guard, never a 500.
        for stub in ((0, "only-two"), None):
            with mock.patch.object(nginx_svc, "sh", return_value=stub):
                resp = self.client.post("/api/nginx/test")
            self.assertEqual(resp.status_code, 200, resp.text[:200])
            self.assertFalse(resp.json()["ok"])

    def test_reload_spawn_raising_midway_still_reaches_kickstart(self):
        # -t passes, the -s reload spawn raises, kickstart succeeds: the
        # raise degrades to the rc!=0 branch instead of 500ing, and the
        # kickstart result is what the SPA sees.
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "", "ok"), OSError("torn"), (0, "kick ok", "")],
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

    def test_raise_reading_not_found_is_coded_only_when_nginx_is_gone(self):
        # Disk-confirmed, failure path only: a stub FileNotFoundError whose
        # text is exactly "not found" classifies as the coded 503 only when
        # the binary really left the disk...
        with (
            mock.patch.object(
                nginx_svc, "sh", side_effect=FileNotFoundError("not found")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=False),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.not_found")

    def test_raise_reading_not_found_stays_raw_while_nginx_is_on_disk(self):
        # ...and keeps the raw {ok: false} while nginx is still present —
        # never a false "nginx is not installed".
        with (
            mock.patch.object(
                nginx_svc, "sh", side_effect=FileNotFoundError("not found")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "not found")


class OverCapRcRoutePinTests(_RealConf):
    """An already-int over-cap rc from an odd runner, at the HTTP layer."""

    def test_huge_rc_on_test_keeps_the_message_and_the_200(self):
        # YAML/plist hex loads uncapped (int(x, 16) is exempt from CPython's
        # 4300-digit cap): nothing in the payload may try to render rc.
        with (
            mock.patch.object(
                nginx_svc, "sh", return_value=(_HUGE_INT, "", "boom")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "boom")

    def test_huge_rc_on_reload_is_the_invalid_conf_branch_not_a_500(self):
        with (
            mock.patch.object(
                nginx_svc, "sh", return_value=(_HUGE_INT, "", "boom")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertIn("Invalid configuration; not reloaded", body["message"])


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment .get is read."""

    def get(self, *a, **k):
        raise ValueError("get bomb")


class _KeysBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment keys() is read."""

    def keys(self):
        raise ValueError("keys bomb")


class _BoolBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment it is truth-tested."""

    def __bool__(self):
        raise ValueError("bool bomb")


class _UnhashableList(list):
    __hash__ = None


def _get_nginx(sites):
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
        mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        ),
    ):
        return _client().get("/api/nginx")


class DictSubclassBombSiblingRankRoutePinTests(unittest.TestCase):
    """The .get / .keys / __bool__ ranks beside the pinned items-bomb."""

    def test_get_keys_and_bool_bomb_rows_never_wipe_the_sibling(self):
        # ``overview()``/``_jsonable`` only ever read rows through items();
        # each bomb rank must at worst drop its own row, never 500 the route
        # or take the sane sibling site with it.
        for bomb in (
            _GetBombDict({"file": "poison.conf"}),
            _KeysBombDict({"file": "poison.conf"}),
            _BoolBombDict({"file": "poison.conf"}),
        ):
            resp = _get_nginx([bomb, {"file": "sane.conf", "listens": [8080]}])
            self.assertEqual(resp.status_code, 200, resp.text[:200])
            body = resp.json()
            _starlette(body)
            files = [s["file"] for s in body["sites"]]
            self.assertIn("sane.conf", files)

    def test_unhashable_list_value_and_complex_value_stay_200(self):
        # An unhashable list subclass inside listens must pass through as a
        # list (no set-membership probe may hash it), and a complex value
        # coerces to text instead of TypeError-ing the encoder.
        resp = _get_nginx([
            {
                "file": "sane.conf",
                "listens": [_UnhashableList([8080])],
                "weight": complex(1, 2),
            },
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        site = body["sites"][0]
        self.assertEqual(site["listens"], [[8080]])
        self.assertIsInstance(site["weight"], str)


class BodyAndFifoConfRoutePinTests(unittest.TestCase):
    """Huge-number bodies and a FIFO at nginx.conf answer coded, fast."""

    def test_huge_number_json_body_on_the_bodyless_post_stays_coded(self):
        # json.loads of 6000 digits is ValueError, not JSONDecodeError; the
        # body-less route must never let that shape 500 the parse.
        with mock.patch.object(
            nginx_svc, "NGINX_CONF", Path("/nonexistent/nginx.conf")
        ):
            resp = _client().post(
                "/api/nginx/test",
                content=b'{"noise": ' + b"9" * 6000 + b"}",
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.conf_missing")

    def test_fifo_at_nginx_conf_is_the_coded_404_and_never_hangs(self):
        # ``Path.is_file`` on a FIFO is False without opening it — a plain
        # open would park the request thread until a writer appeared.
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-gateway5-fifo-"))
        fifo = tmp / "nginx.conf"
        try:
            os.mkfifo(fifo)
        except OSError:
            self.skipTest("filesystem refuses FIFOs")
        self.addCleanup(fifo.unlink)
        with mock.patch.object(nginx_svc, "NGINX_CONF", fifo):
            resp = _client().post("/api/nginx/test")
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.conf_missing")


class OnDiskHostileConfDirRoutePinTests(unittest.TestCase):
    """The real parser over a hostile conf.d, through the mounted route."""

    def test_torn_ipv6_digits_oversize_and_special_files_keep_the_sane_site(self):
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-gateway5-confd-"))
        confd = tmp / "Services" / "nginx" / "conf.d"
        confd.mkdir(parents=True)
        (confd / "sane.conf").write_text(
            "listen 8080;\nserver_name nas.local;\n"
            "proxy_pass http://127.0.0.1:3000;\n"
        )
        # The urlsplit ValueError class: a torn IPv6 listen and a torn
        # proxy_pass upstream.  The parser never urlsplits; the raw text
        # must still ride the encode without a raise.
        (confd / "torn6.conf").write_text(
            "listen [::1;\nlisten [::]:443 ssl;\nproxy_pass http://[::1;\n"
        )
        # 5000 digits: int() of the match is CPython's digit-cap ValueError,
        # which must drop the port, never the row or the route.
        (confd / "digits.conf").write_text("listen " + "9" * 5000 + ";\n")
        # \d matches Unicode digits; int() accepts them as 80.
        (confd / "unidigit.conf").write_text("listen \u0668\u0660;\n")
        # Invalid UTF-8 with NULs and a surrogate triple.
        (confd / "binary.conf").write_bytes(
            b"\xff\xfe listen 81;\x00\nserver_name \xed\xa0\x80;\n"
        )
        # Past the 256 KiB read cap: EFBIG drops the file, not the route.
        (confd / "big.conf").write_text("# pad\n" * 60000 + "listen 82;\n")
        (confd / "dir.conf").mkdir()
        (confd / "dangle.conf").symlink_to(confd / "nowhere")
        (confd / "loop.conf").symlink_to(confd / "loop.conf")
        try:
            os.mkfifo(confd / "fifo.conf")
        except OSError:
            pass
        with mock.patch("hub.adaptive.user_home", return_value=tmp):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        self.assertEqual(files["sane.conf"]["listens"], [8080])
        self.assertEqual(files["sane.conf"]["server_names"], ["nas.local"])
        # The torn-IPv6 row survives with the finite port; the torn text is
        # carried verbatim (it is valid UTF-8) without a parse raise.
        self.assertIn(443, files["torn6.conf"]["listens"])
        self.assertIn("http://[::1", files["torn6.conf"]["upstreams"])
        # The over-cap digit run drops the port, keeps the row.
        self.assertEqual(files["digits.conf"]["listens"], [])
        self.assertEqual(files["unidigit.conf"]["listens"], [80])
        # No surrogate may survive into the encoded payload.
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        # Special files never become rows (a FIFO read would have hung).
        for name in ("fifo.conf", "dir.conf", "dangle.conf", "loop.conf",
                     "big.conf"):
            self.assertNotIn(name, files)


if __name__ == "__main__":
    unittest.main()
