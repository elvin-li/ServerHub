"""Leftover Gateway-page 500s #4: the sites list rode ``overview()`` unscrubbed.

Prior sweeps sealed every *other* field of GET /api/nginx's payload — the two
conf paths through ``_as_text``, the pid through ``_pid_text``'s str() probe
(test_leftover_gateway_surrogate_pid_500s), the vanished-CLI sentinel and the
poisoned-conf.d parse at the HTTP layer (test_modules_gateway_leftover_stays_
immune_500s).  A fresh hunt found the one field those passes skipped: the
``sites`` list itself.  ``overview()`` guards its *shape* (an ``Exception``
catch and an ``isinstance(sites, list)`` gate) but trusted the row *content*
verbatim — and, exactly like the pid, ``overview()`` does not own the parser:
the real ``adaptive.nginx_sites`` scrubs its output, but a patched or odd one
(the same class ``_sh_message`` guards for ``sh`` and ``_pid_text`` guards
for the listing) can answer rows the production parser never does.  Confirmed
against the mounted route before fixing — each of these was an HTTP 500:

* a lone surrogate in a site dict *key* or *value* rode raw to Starlette's
  UTF-8 encode (``ensure_ascii=False`` then ``.encode("utf-8")``);
* an *already-int* over-cap number in a value — YAML/plist hex loads
  uncapped (``int(x, 16)`` is exempt from CPython's 4300-digit conversion
  limit) — passed untouched and ValueError'd Starlette's own ``json.dumps``
  at int->str time.  Note ``json.loads`` of the same digits raises ValueError
  too, not JSONDecodeError, so nothing here may catch JSONDecodeError alone;
* the same over-cap int as a dict *key*;
* undecodable ``bytes`` keys/values (TypeError in the encoder);
* a surrogate nested inside ``server_names`` — one level down from the row.

The fix is the same field-level ``_jsonable`` coercer the sibling payloads
carry (bookmarks, status, ollama): keys and values are scrubbed, an over-cap
int drops to None while its finite siblings — including the *numeric* listen
ports the Gateway table renders — pass through as ints via a str() probe,
never an ``isinstance(x, str)`` gate that would silently drop them.  Rows
that are not dicts at all are dropped before ``site_count`` counts them.

The rest of this battery pins shapes the hunt found already immune, so a
refactor cannot quietly reopen them: the surrogate-HOME conf paths at the
route level, a non-list ``nginx_sites`` answer, the kickstart branch's
surrogate/bytes message scrub, and reload's vanished-between-``-t``-and
``-s reload`` coded 503 — both held at the HTTP layer for the first time.

``os.kill`` does not apply here: nothing in hub/nginx_svc.py or its router
signals a pid, and the Gateway backend owns no JSON journal — its only
persistence is the audit trail, whose loader already drops unparseable lines
one at a time (hub/audit.py).
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

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000
#: The plist/YAML vector verbatim: ``int(x, 16)`` is exempt from the cap.
_HUGE_HEX_INT = int("F" * 5000, 16)

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


def _overview_with_sites(sites) -> dict:
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
        mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        ),
    ):
        return nginx_svc.overview()


class PoisonedSiteRowTests(unittest.TestCase):
    """Rows from a parser ``overview()`` does not own must not 500 the encode."""

    def test_surrogate_key_and_value_encode_instead_of_500ing(self):
        ov = _overview_with_sites([
            {"file": "a\ud800.conf", "k\ud800ey": "v\ud800al"},
        ])
        _starlette(ov)
        self.assertNotIn("\ud800", json.dumps(ov, ensure_ascii=False))
        # Field-level scrub, not row loss: the row is still listed.
        self.assertEqual(ov["site_count"], 1)

    def test_over_cap_hex_int_value_drops_field_level_not_the_row(self):
        # The vector is real: the hex parse dodges the str->int cap, so the
        # value arrives already-int and str() of it is the digit-cap
        # ValueError json.dumps raises too.
        with self.assertRaises(ValueError):
            str(_HUGE_HEX_INT)
        ov = _overview_with_sites([
            {"file": "a.conf", "listens": [_HUGE_HEX_INT, 8080]},
        ])
        _starlette(ov)
        site = ov["sites"][0]
        # The finite sibling port survives as an int — a str() probe, never
        # an isinstance(x, str) gate that would silently drop numeric ids.
        self.assertIn(8080, site["listens"])
        self.assertNotIn(_HUGE_HEX_INT, site["listens"])
        self.assertEqual(site["file"], "a.conf")

    def test_over_cap_int_key_drops_the_entry_not_the_row(self):
        ov = _overview_with_sites([
            {"file": "a.conf", _HUGE_INT: "keyed"},
        ])
        _starlette(ov)
        site = ov["sites"][0]
        self.assertEqual(site["file"], "a.conf")
        self.assertNotIn("keyed", site.values())

    def test_bytes_key_and_value_decode_instead_of_500ing(self):
        ov = _overview_with_sites([
            {b"\xff\xfe": b"\xff", "file": "a.conf"},
        ])
        _starlette(ov)
        self.assertEqual(ov["sites"][0]["file"], "a.conf")

    def test_surrogate_nested_in_server_names_is_scrubbed(self):
        ov = _overview_with_sites([
            {"file": "a.conf", "server_names": ["nas\ud800.local"]},
        ])
        _starlette(ov)
        self.assertNotIn("\ud800", json.dumps(ov, ensure_ascii=False))

    def test_non_dict_rows_are_dropped_before_the_count(self):
        ov = _overview_with_sites(["just-a-string", {"file": "b.conf"}])
        _starlette(ov)
        self.assertEqual([s["file"] for s in ov["sites"]], ["b.conf"])
        self.assertEqual(ov["site_count"], 1)

    def test_a_sane_site_row_passes_through_unchanged(self):
        row = {
            "file": "sane.conf",
            "path": "/Users/elvin/Services/nginx/conf.d/sane.conf",
            "listens": [8080, 443],
            "server_names": ["nas.local"],
            "upstreams": ["http://127.0.0.1:8281"],
        }
        ov = _overview_with_sites([dict(row)])
        _starlette(ov)
        self.assertEqual(ov["sites"][0], row)
        self.assertEqual(ov["site_count"], 1)


class PoisonedSiteRowRouteTests(unittest.TestCase):
    """The same contract, held at the HTTP layer GET /api/nginx answers from."""

    def test_poisoned_rows_stay_200_and_the_sane_site_survives(self):
        sites = [
            {"file": "a\ud800.conf", "k\ud800": "v\ud800", b"\xff": b"\xff"},
            {"file": "hex.conf", "listens": [_HUGE_HEX_INT, 8080], _HUGE_INT: "x"},
            "not-a-dict",
            {
                "file": "sane.conf",
                "listens": [8080],
                "server_names": ["nas.local"],
                "upstreams": [],
            },
        ]
        with (
            mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
            mock.patch(
                "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
            ),
        ):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        files = {s.get("file"): s for s in body["sites"]}
        self.assertEqual(files["sane.conf"]["listens"], [8080])
        self.assertIn(8080, files["hex.conf"]["listens"])
        self.assertEqual(body["site_count"], 3)


class StaysImmuneRoutePinTests(unittest.TestCase):
    """Shapes the same hunt found already guarded, pinned at the HTTP layer."""

    def test_surrogate_home_conf_paths_stay_200(self):
        # Function-level pin exists (test_leftover_gateway_surrogate_pid_500s);
        # this holds it through the mounted route.
        root = Path("/Users/elv\udcffin/Services/nginx")
        with (
            mock.patch.object(nginx_svc, "NGINX_CONF", root / "nginx.conf"),
            mock.patch.object(nginx_svc, "CONF_D", root / "conf.d"),
            mock.patch.object(nginx_svc, "nginx_sites", return_value=[]),
            mock.patch(
                "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
            ),
        ):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertNotIn("\udcff", resp.json()["conf"])

    def test_non_list_sites_answer_reads_as_empty(self):
        with (
            mock.patch.object(
                nginx_svc, "nginx_sites", return_value={"not": "a-list"}
            ),
            mock.patch(
                "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
            ),
        ):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["sites"], [])
        self.assertEqual(resp.json()["site_count"], 0)


class KickstartAndReloadVanishRoutePinTests(unittest.TestCase):
    """POST /api/nginx/reload branches the older HTTP pins never reached."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()

    def test_kickstart_branch_scrubs_surrogate_and_bytes_output(self):
        # -t passes, -s reload fails with undecodable bytes stderr, and the
        # kickstart answers a lone surrogate: the message must reach the SPA
        # scrubbed, not 500 at encode time.
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[
                    (0, "syntax ok", ""),
                    (1, "", b"boom \xed\xa0\x80"),
                    (0, "", "kick \ud800 started"),
                ],
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
        self.assertNotIn("\ud800", body["message"])

    def test_vanish_between_test_and_reload_is_the_coded_503(self):
        # Function-level pin exists (test_modules_bookmarks_leftover_hexint_
        # surrogate_vanish_500s); this holds the disk-confirmed failure-path
        # classification through the mounted route.
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "ok", ""), (-1, "", "not found")],
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=False),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.not_found")


if __name__ == "__main__":
    unittest.main()
