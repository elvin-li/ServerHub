"""Third leftover-500s sweep of the host / system-overview APIs, over real ASGI.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — vanished-CLI 503-vs-500) were re-reproduced against the mounted
routes.  One live leak was found and is fixed alongside this file:

* ``power_svc._jsonable`` passed ints through without the ``str()`` probe its
  siblings (``system._jsonable``, ``system_settings_svc._json_tree``,
  ``status._jsonable``) all carry, so an over-cap int in a privileged ok
  payload raised the int->str digit-cap ValueError inside Starlette's
  ``json.dumps`` and 500'd POST /api/system/screensharing/enable — the one
  route that feeds a service-layer result dict through that sanitizer — and
  would do the same to any GET /api/system/power field that ever grows an
  int.  The huge-int and NaN pins here fail on the pre-fix tree.

Everything else in the domain was found immune, so the rest of this file pins
the stays-immune corners the existing service-layer suites never cross —
request routing, response rendering and the strict UTF-8 decode of the body:

* GET /api/system/host with a surrogate hostname / CPU brand, >4300-digit
  ``hw.ncpu`` / ``hw.memsize`` sysctl payloads, and a surrogate
  ``SERVERHUB_HOST_IP`` (which flows into the payload *without* a local
  ``_as_text`` — the scrub is host_address's internal guarantee).
* GET /api/identity with surrogate scutil / hostname output, a surrogate
  YAML ``server_comment``, and a surrogate effective host address.
* PUT /api/identity keeps the coded 400 for a JSON-escaped lone-surrogate
  ComputerName (``"\\ud800"`` is legal JSON and decodes to a real lone
  surrogate) and the coded 503 for a scutil whose spawn sentinel is
  confirmed missing on disk — both bodies must themselves stay UTF-8.
* GET /api/system/power with surrogate pmset / ifconfig output and a
  surrogate LAN address.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock
from urllib.parse import quote

import yaml
from fastapi import FastAPI

from hub import identity_svc, power_svc
from hub.routers import power as power_router
from hub.routers import system_extra, unraid_parity

#: Loaded from real YAML text: the 1.1 resolver parses ``0xF…`` through
#: ``int(x, 16)``, which CPython's 4300-digit str->int cap does not bound,
#: so the leftover arrives *already-int* and only fails at render time.
_HUGE_INT = yaml.safe_load("v: 0x" + "F" * 4400)["v"]


async def _asgi_request(method, path, *, body=None):
    """Drive the host-domain routers through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(system_extra.router)
    app.include_router(unraid_parity.router)
    app.include_router(power_router.router)
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": quote(path, safe="/").encode(),
        "query_string": b"", "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 JSON — decode strictly on purpose.
    return status, json.loads(raw.decode("utf-8")) if raw else None


def request(method, path, *, body=None):
    return asyncio.run(_asgi_request(method, path, body=body))


class PowerJsonableDigitCapTests(unittest.TestCase):
    """The sanitizer contract itself — these fail on the pre-fix tree."""

    def test_over_cap_int_is_dropped_like_inf(self):
        self.assertIsNone(power_svc._jsonable(_HUGE_INT))
        cleaned = power_svc._jsonable({"ok": True, "ticks": _HUGE_INT, "port": 5900})
        self.assertIsNone(cleaned["ticks"])
        self.assertEqual(cleaned["port"], 5900)
        self.assertIs(cleaned["ok"], True)
        json.dumps(cleaned, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_over_cap_int_key_still_drops_whole_entry(self):
        cleaned = power_svc._jsonable({_HUGE_INT: "gone", "kept": 1})
        self.assertEqual(cleaned, {"kept": 1})

    def test_bool_and_ordinary_int_are_served_verbatim(self):
        self.assertIs(power_svc._jsonable(True), True)
        self.assertEqual(power_svc._jsonable(10**100), 10**100)


class ScreensharingOkPayloadRenderTests(unittest.TestCase):
    """POST /api/system/screensharing/enable renders the privileged ok
    payload through power_svc._jsonable — the huge-int case 500'd pre-fix."""

    def _enable(self, service_row):
        patches = (
            mock.patch.object(power_router.auth, "browser_authenticated", return_value=True),
            mock.patch.object(power_router.auth, "request_username", return_value="admin"),
            mock.patch.object(power_router.auth, "is_admin", return_value=True),
            mock.patch.object(power_router.auth, "request_client_id", return_value="127.0.0.1"),
            mock.patch.object(power_router.audit, "record", lambda *a, **k: {}),
            mock.patch.object(
                power_router.shares_svc, "set_system_service",
                return_value={"ok": True, "service": service_row},
            ),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            return request("POST", "/api/system/screensharing/enable")

    def test_huge_int_in_ok_payload_stays_http_200(self):
        status, body = self._enable({
            "id": "screen_sharing", "enabled": True,
            "detail": "running\ud800", "since_ticks": _HUGE_INT,
        })
        self.assertEqual(status, 200)
        self.assertIs(body["ok"], True)
        # over-cap int dropped like inf; the surrogate is scrubbed
        self.assertIsNone(body["service"]["since_ticks"])
        self.assertEqual(body["service"]["detail"], "running?")

    def test_nan_and_surrogate_key_in_ok_payload_stay_http_200(self):
        status, body = self._enable({
            "id": "screen_sharing", "enabled": True,
            "load\ud800": "kept", "since": float("nan"),
        })
        self.assertEqual(status, 200)
        self.assertIsNone(body["service"]["since"])
        self.assertEqual(body["service"]["load?"], "kept")


class HostSnapshotAsgiStaysImmunePins(unittest.TestCase):
    """GET /api/system/host — the service-layer suites patch _host_snapshot
    directly; this pins the same leftovers across routing + rendering."""

    def setUp(self):
        system_extra._host_snapshot.invalidate()
        self.addCleanup(system_extra._host_snapshot.invalidate)

    def test_surrogate_and_huge_digit_probes_stay_http_200(self):
        def fake_sh(argv, **kwargs):
            last = argv[-1] if argv else ""
            if argv and argv[0] == "/bin/hostname":
                return 0, "nas\ud800box", ""
            if last == "machdep.cpu.brand_string":
                return 0, "Apple M2\ud800 Pro", ""
            if last in ("hw.ncpu", "hw.memsize"):
                return 0, "9" * 5000, ""
            return 1, "", ""

        with (
            mock.patch.object(system_extra, "sh", side_effect=fake_sh),
            mock.patch.object(system_extra, "is_high", return_value=False),
            mock.patch.object(system_extra, "peek_engine", return_value=False),
            mock.patch.object(system_extra, "default_interface", return_value=""),
            mock.patch.object(system_extra, "interface_address", return_value=""),
            # host_ip() flows into the payload raw — the scrub must hold
            # inside host_address, not in a local _as_text.  \udcff is the
            # surrogateescape form real non-UTF-8 environ bytes decode to
            # (a raw \ud800 cannot even be *stored* in os.environ on Linux).
            mock.patch.dict(
                "os.environ",
                {"SERVERHUB_HOST_IP": "192.0.2.5\udcff", "SERVERHUB_HOST": ""},
            ),
        ):
            status, body = request("GET", "/api/system/host")
        self.assertEqual(status, 200)
        self.assertEqual(body["hostname"], "nas?box")
        self.assertEqual(body["cpu"], "Apple M2? Pro")
        # >4300 digits pass isdigit() but not int(); dropped, not 500
        self.assertIsNone(body["ncpu"])
        self.assertIsNone(body["mem_total_gb"])
        self.assertEqual(body["host_ip"], "192.0.2.5?")
        self.assertEqual(body["lan_ip"], body["host_ip"])
        self.assertEqual(body["interfaces"], [])


class IdentityAsgiStaysImmunePins(unittest.TestCase):
    """GET/PUT /api/identity across real routing and response rendering."""

    def test_surrogate_probes_and_comment_stay_http_200(self):
        def fake_sh(argv, **kwargs):
            if argv and argv[0] == "/bin/hostname":
                return 0, "nas\ud800box", ""
            if "ComputerName" in argv:
                return 0, "NAS \ud800 Box", ""
            if "LocalHostName" in argv:
                return 0, "nas-box", ""
            if "hw.model" in argv:
                return 0, "Mac14,3", ""
            return 1, "", ""

        with (
            mock.patch.object(identity_svc, "sh", side_effect=fake_sh),
            mock.patch.object(
                identity_svc, "effective_host_ip", return_value="192.0.2.7\ud800"
            ),
            mock.patch.object(
                identity_svc, "cfg",
                return_value={"settings": {"server_comment": "rack\ud800 one"}},
            ),
        ):
            status, body = request("GET", "/api/identity")
        self.assertEqual(status, 200)
        self.assertEqual(body["hostname"], "nas?box")
        self.assertEqual(body["computer_name"], "NAS ? Box")
        self.assertEqual(body["comment"], "rack? one")
        self.assertEqual(body["host_ip"], "192.0.2.7?")
        self.assertEqual(body["model"], "Mac14,3")

    def test_json_escaped_surrogate_name_keeps_the_coded_400(self):
        # "\ud800" is legal JSON text and decodes to a real lone surrogate;
        # the error body itself must stay UTF-8 with that name in hand.
        status, body = request(
            "PUT", "/api/identity", body={"computer_name": "bad\ud800name"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "identity.bad_name")

    def test_vanished_scutil_keeps_the_coded_503(self):
        # sh's FileNotFoundError sentinel + the disk confirm (scutil is not
        # a file on this host) → coded 503, never a raw 500.
        with mock.patch.object(
            identity_svc, "sh", return_value=(-1, "", "not found")
        ):
            status, body = request(
                "PUT", "/api/identity", body={"computer_name": "NewName"},
            )
        self.assertEqual(status, 503)
        self.assertEqual(body["detail"]["code"], "identity.scutil_missing")


class PowerOverviewAsgiStaysImmunePins(unittest.TestCase):
    """GET /api/system/power with surrogate pmset/ifconfig and LAN address."""

    def test_surrogate_probe_output_stays_http_200(self):
        def fake_sh(argv, **kwargs):
            if argv and argv[0] == "/usr/bin/pmset":
                return 0, "womp 1\nsleep\ud800 0\n", ""
            if argv and argv[0] == "/sbin/ifconfig":
                return 0, "\tether aa:bb:cc:dd:ee:ff\ud800\n", ""
            return 1, "", ""

        with (
            mock.patch.object(power_svc, "sh", side_effect=fake_sh),
            mock.patch.object(power_svc, "default_interface", return_value="en0"),
            mock.patch.object(power_svc, "port_open", return_value=False),
            mock.patch.object(power_svc, "host_ip", return_value="192.0.2.9\ud800"),
        ):
            status, body = request("GET", "/api/system/power")
        self.assertEqual(status, 200)
        self.assertIs(body["wol"]["enabled"], True)
        self.assertEqual(body["wol"]["iface"], "en0")
        self.assertEqual(body["wol"]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(body["host_ip"], "192.0.2.9?")
        self.assertNotIn("\ud800", body["screen_sharing"]["vnc_url"])


if __name__ == "__main__":
    unittest.main()
