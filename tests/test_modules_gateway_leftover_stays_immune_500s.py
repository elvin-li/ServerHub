"""Modules-page leftover sweep #3: the domain is already immune — HTTP pins.

A fresh hunt over the Modules page surface (GET /api/modules, GET /api/nginx,
POST /api/nginx/test, POST /api/nginx/reload) reproduced every sweep class
against the *mounted routes* and found no remaining 500 or silent loss:

* lone surrogates in registry keys AND values are scrubbed by
  ``modules._jsonable`` before they reach Starlette's UTF-8 encode
  (values were pinned in test_settings_config_modules_leftover_500s; the
  *key* side and undecodable-bytes keys had no route-level pin);
* YAML-hex over-cap ints (``int(x, 16)`` is exempt from CPython's
  4300-digit cap, so they arrive *already-int*) are dropped by the str()
  probe in ``modules._jsonable`` / ``nginx_svc._pid_text`` — field-level,
  never whole-row: the poisoned row keeps its surviving siblings, and a
  finite numeric pid keeps reporting running (no ``isinstance(x, str)``
  gate);
* a vanished nginx binary answers the coded 503 ``nginx.not_found``
  (disk-confirmed, on the failure path only) while the timeout sentinel
  and a genuine nginx exit keep their original ``{ok, message}`` shape —
  the function-level pins live in
  test_modules_bookmarks_leftover_hexint_surrogate_vanish_500s; these hold
  the same contract at the HTTP layer;
* one poisoned ``conf.d/*.conf`` (a >4300-digit listen directive,
  undecodable bytes) never wipes the Gateway site list: the sane sibling
  site and the sane port survive.

The remaining sweep classes do not apply: nothing in hub/modules.py,
hub/routers/modules_api.py or hub/nginx_svc.py signals a pid (no
``os.kill``), and neither owns a JSON journal — the registry is in-code and
the Gateway's only persistence is the audit trail, whose loader already
drops unparseable lines one at a time (hub/audit.py).

Everything here passed on the tree it was written against; these are
stays-immune pins so a refactor cannot quietly reopen the routes.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import modules, nginx_svc
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000
#: What a leftover ``0xF…`` in hand-edited YAML loads as — already-int.
_HUGE_HEX_YAML = "0x" + "F" * 5000

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


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)
        self.addCleanup(
            lambda: modules.MODULES.__setitem__(slice(None), self._saved)
        )
        self.client = _client()

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class ModulesRouteSurrogateKeyTests(_RegistrySandbox):
    """Surrogates in registry keys AND values never 500 GET /api/modules."""

    def test_surrogate_and_bytes_keys_stay_200_and_encodable(self):
        modules.MODULES.append({
            "id": "evil",
            "name": "ok",
            "description": "d",
            "category": "ops",
            "apis": ["/api/x"],
            "ui_routes": ["/x"],
            "k\ud800ey": "v\ud800al",
            b"\xff\xfe": b"\xff",
        })
        body = self._get_modules()
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        row = next(r for r in body["modules"] if r.get("id") == "evil")
        # Field-level scrub, not whole-row loss: the siblings survive.
        self.assertEqual(row["name"], "ok")
        self.assertEqual(row["apis"], ["/api/x"])
        self.assertIn(
            "evil", [r.get("id") for r in body["by_category"].get("ops", [])]
        )


class ModulesRouteOverCapIntTests(_RegistrySandbox):
    """Already-int YAML-hex leftovers never 500 or wipe GET /api/modules."""

    def test_hex_yaml_row_survives_with_only_the_poison_dropped(self):
        row = yaml.safe_load(
            "{id: plug, name: " + _HUGE_HEX_YAML
            + ", priority: " + _HUGE_HEX_YAML
            + ", category: ops, apis: [/api/x], ui_routes: [/x]}"
        )
        # The vector is real: the hex load bypasses the str->int cap.
        self.assertIsInstance(row["name"], int)
        with self.assertRaises(ValueError):
            str(row["name"])
        modules.MODULES.append(row)
        body = self._get_modules()
        plug = next(r for r in body["modules"] if r.get("id") == "plug")
        self.assertIsNone(plug["name"])
        self.assertIsNone(plug["priority"])
        self.assertEqual(plug["apis"], ["/api/x"])

    def test_over_cap_int_category_regroups_under_other(self):
        modules.MODULES.append({
            "id": "plug",
            "name": "n",
            "category": yaml.safe_load("v: " + _HUGE_HEX_YAML)["v"],
            "apis": [],
            "ui_routes": [],
        })
        body = self._get_modules()
        self.assertIn(
            "plug", [r.get("id") for r in body["by_category"].get("other", [])]
        )

    def test_over_cap_int_key_drops_the_entry_not_the_row(self):
        modules.MODULES.append({
            "id": "plug",
            "name": "n",
            "category": "ops",
            _HUGE_INT: "keyed",
            "apis": [],
            "ui_routes": [],
        })
        body = self._get_modules()
        plug = next(r for r in body["modules"] if r.get("id") == "plug")
        self.assertEqual(plug["name"], "n")
        self.assertNotIn("keyed", plug.values())


class GatewayRoutePoisonedConfTests(unittest.TestCase):
    """One poisoned conf.d file never 500s or wipes GET /api/nginx."""

    def test_huge_listen_digits_and_bad_bytes_keep_the_sane_site(self):
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-gateway-pin-"))
        confd = tmp / "Services" / "nginx" / "conf.d"
        confd.mkdir(parents=True)
        (confd / "poison.conf").write_bytes(
            ("listen " + "9" * 5000 + ";\n").encode()
            + b"server_name \xff\xfe;\nproxy_pass http://\xff;\n"
        )
        (confd / "sane.conf").write_text(
            "listen 8080;\nserver_name nas.local;\n"
        )
        with mock.patch("hub.adaptive.user_home", return_value=tmp):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        files = {s["file"]: s for s in body["sites"]}
        # The sane sibling survives; int() of the >4300-digit run is the
        # digit-cap ValueError and drops only that port.
        self.assertEqual(files["sane.conf"]["listens"], [8080])
        self.assertEqual(files["poison.conf"]["listens"], [])
        self.assertEqual(body["site_count"], 2)


class GatewayRouteVanishedCliTests(unittest.TestCase):
    """The vanished-CLI contract, held at the HTTP layer."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()

    def _post(self, path: str, sh_result, *, on_disk: bool):
        with (
            mock.patch.object(nginx_svc, "sh", return_value=sh_result),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=on_disk),
        ):
            return self.client.post(path)

    def test_vanished_cli_is_the_coded_503_on_both_routes(self):
        for path in ("/api/nginx/test", "/api/nginx/reload"):
            with self.subTest(path=path):
                resp = self._post(path, (-1, "", "not found"), on_disk=False)
                self.assertEqual(resp.status_code, 503, resp.text[:200])
                self.assertEqual(resp.json()["detail"]["code"], "nginx.not_found")

    def test_timeout_keeps_its_original_shape(self):
        resp = self._post("/api/nginx/test", (-1, "", "timeout"), on_disk=False)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json(), {"ok": False, "message": "timeout"})

    def test_real_exit_saying_not_found_keeps_its_original_shape(self):
        resp = self._post("/api/nginx/test", (1, "", "not found"), on_disk=False)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json(), {"ok": False, "message": "not found"})


class _OddListing:
    """A listing whose pid column skipped Listing's coercion (patched/odd)."""

    def __init__(self, pid):
        self._pid = pid

    def pid_for(self, label):
        return self._pid


class GatewayRoutePidShapeTests(unittest.TestCase):
    """The str()-probe pid semantics, held at the HTTP layer."""

    def _overview(self, pid) -> dict:
        with (
            mock.patch.object(nginx_svc, "nginx_sites", return_value=[]),
            mock.patch(
                "hub.nginx_svc.launchd_listing", return_value=_OddListing(pid)
            ),
        ):
            resp = _client().get("/api/nginx")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body

    def test_over_cap_already_int_pid_reads_not_running(self):
        body = self._overview(_HUGE_INT)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])

    def test_bool_pid_reads_not_running(self):
        body = self._overview(True)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])

    def test_finite_numeric_pid_still_reports_running(self):
        body = self._overview(743)
        self.assertEqual(body["pid"], "743")
        self.assertTrue(body["running"])


if __name__ == "__main__":
    unittest.main()
