"""Leftover Gateway-page 500s #5: rows that refuse *iteration* wiped the list.

Prior sweeps sealed GET /api/nginx's payload field by field — surrogate keys
and values, already-int over-cap numbers, bytes, non-dict rows and a non-list
answer (test_leftover_gateway_sites_scrub_500s), the pid and conf-path shapes
(test_leftover_gateway_surrogate_pid_500s), and the on-disk/vanished-CLI
classes at the HTTP layer (test_modules_gateway_leftover_stays_immune_500s).
A fresh hunt over the same mounted route found the one shape all of those
passes stepped around: values that pass the ``isinstance`` gates but raise
when *iterated*.  ``overview()`` does not own the parser — the real
``adaptive.nginx_sites`` scrubs its output, but a patched or odd one (the
same class ``_sh_message`` guards for ``sh`` and ``_pid_text`` for the
listing) can answer shapes the production parser never does.  Confirmed
against the mounted route before fixing — each of these was an HTTP 500:

* a list *subclass* whose ``__iter__`` raises: it passes the
  ``isinstance(sites, list)`` gate, and the scrub comprehension ran outside
  the ``try`` that guards the ``nginx_sites()`` call itself, so the raise
  rode to Starlette uncaught;
* a dict-subclass *row* whose ``items()`` raises: it passes the
  ``isinstance(row, dict)`` gate and blew up inside ``_jsonable`` — and
  because the whole list was scrubbed in one expression, the poisoned row
  took every sane sibling site down with the 500 (the exact sibling-row
  wipe this sweep hunts).

The fix keeps the blast radius one field wide: ``_jsonable`` materializes
mapping items and sequence iteration under its own guard (an unreadable
mapping or sequence collapses to None, its siblings survive), and
``overview()`` materializes the top-level list under a guard and scrubs
row by row, so a row whose scrub collapses drops alone and ``site_count``
counts only the survivors.

The rest of this battery pins vectors the same hunt found already immune,
held at the HTTP layer for the first time so a refactor cannot quietly
reopen them: NaN/Inf floats against Starlette's ``allow_nan=False`` encoder,
set values (not JSON-serializable natively), >32-deep nesting, a bytes pid
from an odd listing, a ``pid_for`` that raises, the reload route's
"Invalid configuration" and "Reloaded" branches carrying surrogate/bytes
``nginx -t`` output, a NUL/surrogate conf path answering the coded 404, a
garbage JSON body on the body-less POST, and an on-disk conf.d holding a
FIFO named ``*.conf``, a surrogate-named site and a 5000-name server_name
line beside one sane site.

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


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


class _ItemsBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment items() is read."""

    def items(self):
        raise ValueError("items bomb")


class _OddListing:
    """A listing whose pid column skipped Listing's coercion (patched/odd)."""

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


class IterationBombRouteTests(unittest.TestCase):
    """Shapes that pass the isinstance gates but refuse iteration: the fix."""

    def test_list_subclass_iter_bomb_reads_as_empty_not_500(self):
        # Pre-fix: isinstance(sites, list) passed and the scrub comprehension
        # ran outside the try — an HTTP 500 over the mounted route.
        resp = _get_nginx(_IterBombList([{"file": "a.conf"}]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["sites"], [])
        self.assertEqual(body["site_count"], 0)

    def test_items_bomb_row_drops_alone_and_the_sibling_survives(self):
        # Pre-fix: the poisoned row 500'd the route and wiped the sane
        # sibling site with it — the sibling-row wipe this sweep hunts.
        resp = _get_nginx([
            _ItemsBombDict({"file": "poison.conf"}),
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual([s["file"] for s in body["sites"]], ["sane.conf"])
        self.assertEqual(body["sites"][0]["listens"], [8080])
        self.assertEqual(body["site_count"], 1)

    def test_nested_items_bomb_collapses_the_field_not_the_row(self):
        # One rank down: only the unreadable mapping drops to None; the
        # row's readable siblings survive field-level.
        row = nginx_svc._jsonable({
            "file": "a.conf",
            "extras": _ItemsBombDict({"x": 1}),
            "listens": [8080],
        })
        _starlette(row)
        self.assertEqual(row["file"], "a.conf")
        self.assertIsNone(row["extras"])
        self.assertEqual(row["listens"], [8080])

    def test_nested_iter_bomb_sequence_collapses_the_field_not_the_row(self):
        row = nginx_svc._jsonable({
            "file": "a.conf",
            "server_names": _IterBombList(["nas.local"]),
            "listens": [8080],
        })
        _starlette(row)
        self.assertEqual(row["file"], "a.conf")
        self.assertIsNone(row["server_names"])
        self.assertEqual(row["listens"], [8080])


class EncoderHostileValueRoutePinTests(unittest.TestCase):
    """Vectors the hunt found already immune, pinned at the HTTP layer."""

    def test_nan_and_inf_floats_drop_field_level_not_the_route(self):
        # Starlette encodes with allow_nan=False: an unscrubbed NaN/Inf is
        # its ValueError.  The finite sibling port must survive.
        resp = _get_nginx([
            {"file": "a.conf", "weight": float("nan"),
             "listens": [float("inf"), 8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        site = resp.json()["sites"][0]
        self.assertIsNone(site["weight"])
        self.assertEqual([p for p in site["listens"] if p is not None], [8080])

    def test_set_values_become_lists_instead_of_type_erroring(self):
        resp = _get_nginx([{"file": "a.conf", "server_names": {"x", "y"}}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        site = resp.json()["sites"][0]
        self.assertEqual(sorted(site["server_names"]), ["x", "y"])

    def test_past_depth_cap_nesting_stays_200(self):
        deep = leaf = {}
        for _ in range(100):
            leaf["n"] = {}
            leaf = leaf["n"]
        resp = _get_nginx([{"file": "a.conf", "deep": deep}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["sites"][0]["file"], "a.conf")


class OddListingRoutePinTests(unittest.TestCase):
    """Listing shapes beyond the pinned int/bool/str set, at the HTTP layer."""

    def test_bytes_pid_from_an_odd_listing_still_reports_running(self):
        resp = _get_nginx([], listing=_OddListing(b"743"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["pid"], "743")
        self.assertTrue(body["running"])

    def test_pid_for_raising_reads_as_not_running(self):
        class _Raising:
            def pid_for(self, label):
                raise ValueError("digit cap")

        resp = _get_nginx([], listing=_Raising())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])


class ReloadBranchMessageScrubRoutePinTests(unittest.TestCase):
    """The two reload branches older HTTP pins never carried poison through."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()

    def test_invalid_conf_branch_scrubs_surrogate_and_bytes_t_output(self):
        # -t fails with a surrogate stderr and bytes stdout: the "Invalid
        # configuration; not reloaded" prefix concatenation must not
        # TypeError, and the message must reach the SPA scrubbed.
        with (
            mock.patch.object(
                nginx_svc, "sh", return_value=(1, b"du\xed", "bad \ud800 conf")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("Invalid configuration; not reloaded", body["message"])
        self.assertNotIn("\ud800", body["message"])

    def test_reloaded_branch_scrubs_surrogate_t_output(self):
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "", "ok \udcff"), (0, "", "")],
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertIn("Reloaded", body["message"])
        self.assertNotIn("\udcff", body["message"])

    def test_test_route_scrubs_bytes_stderr_and_none_stdout(self):
        with (
            mock.patch.object(
                nginx_svc, "sh", return_value=(1, None, b"\xff\xfe bad")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("bad", body["message"])


class ConfPathAndBodyRoutePinTests(unittest.TestCase):
    """Poisoned conf paths and a garbage body answer coded, never 500."""

    def test_nul_conf_path_is_the_coded_conf_missing(self):
        # Path.is_file on an embedded NUL is ValueError, not OSError.
        with mock.patch.object(
            nginx_svc, "NGINX_CONF", Path("/tmp/x\0y.conf")
        ):
            resp = _client().post("/api/nginx/test")
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.conf_missing")

    def test_surrogate_conf_path_is_the_coded_conf_missing(self):
        with mock.patch.object(
            nginx_svc, "NGINX_CONF", Path("/nonexistent/el\udcffvin/nginx.conf")
        ):
            resp = _client().post("/api/nginx/test")
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.conf_missing")

    def test_garbage_json_body_on_the_bodyless_post_never_500s(self):
        # The route declares no body; undecodable bytes posted as JSON must
        # not trip FastAPI's parse into a 500.
        with mock.patch.object(
            nginx_svc, "NGINX_CONF", Path("/nonexistent/nginx.conf")
        ):
            resp = _client().post(
                "/api/nginx/test",
                content=b"\xff{not json",
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.conf_missing")


class OnDiskOddConfDirRoutePinTests(unittest.TestCase):
    """A hostile real conf.d beside one sane site, over the mounted route."""

    def test_fifo_surrogate_name_and_huge_server_names_keep_the_sane_site(self):
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-gateway-iterbomb-"))
        confd = tmp / "Services" / "nginx" / "conf.d"
        confd.mkdir(parents=True)
        (confd / "sane.conf").write_text(
            "listen 8080;\nserver_name nas.local;\n"
        )
        (confd / "many.conf").write_text(
            "server_name " + " ".join(f"h{i}" for i in range(5000))
            + ";\nlisten 80;\n"
        )
        try:
            # An on-disk name that only surrogateescape can spell.
            (confd / (
                b"s\xff ite".decode("utf-8", "surrogateescape") + ".conf"
            )).write_text("listen 81;\n")
        except OSError:
            pass  # filesystem refuses the name; the other vectors still run
        try:
            os.mkfifo(confd / "fifo.conf")
        except OSError:
            pass
        with mock.patch("hub.adaptive.user_home", return_value=tmp):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\udcff", json.dumps(body, ensure_ascii=False))
        files = {s["file"]: s for s in body["sites"]}
        self.assertEqual(files["sane.conf"]["listens"], [8080])
        self.assertEqual(files["many.conf"]["listens"], [80])
        # The FIFO is not a file and never becomes a row (reading it would
        # have hung the request thread).
        self.assertNotIn("fifo.conf", files)


if __name__ == "__main__":
    unittest.main()
