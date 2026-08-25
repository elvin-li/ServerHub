"""WireGuard leftover-500 sweep #4: every vector probed came back immune, so
these pins hold the line at the HTTP layer, through the real app.

What this file adds over the existing WireGuard suites
(``test_wireguard_download_header_leftover_500s`` pins one CJK-name header,
``test_leftover_net_wireguard_digit_500s`` pins the digit-cap validators at
the service layer, ``test_wireguard_hardening`` / ``_peer_ops`` / ``_wstunnel``
cover behaviour):

* **A poisoned stored settings section over mounted routes.**  Leftover YAML
  can hand ``settings()`` surrogate *keys and values*, over-cap hex ints
  (``int(x, 16)`` skips CPython's 4300-digit parse cap, so the poison arrives
  *already-int*), ``.inf`` / ``.nan`` floats, ``!!binary`` bytes and numeric
  ids.  GET /api/wireguard, /settings, /readiness and /next-ip must all
  answer 200 with the defaults filled in — none of these is behind the
  admin guard, so a 500 here takes the page down for every signed-in user.
* **A poisoned peer journal + poisoned ``wg`` dump over mounted routes.**
  ``json.loads`` of a >4300-digit ``created`` raises ValueError — *not*
  JSONDecodeError — which is exactly the trap that used to degrade the whole
  journal to ``{"peers": {}}`` and destroy every retained client key on the
  next write.  The pin asserts the poisoned peer stays *reissuable* through
  GET /api/wireguard and that config / download / export / ping / sync all
  stay coded, with surrogate endpoints and over-cap counters scrubbed.
* **Request bodies through the real app.**  The sanitizing 422 handler is
  registered by ``create_app``; a bare router answers 500 for a ``1e999``
  body.  A >4300-digit int literal is refused at parse time (4xx, and the
  refusal must not wipe anything), and ``\\ud800`` escapes riding in pubkey /
  name / psk / op / target / format answer their coded 400s.
* **The vanished-CLI 503 needs the on-disk confirm.**  The ``sh`` sentinel
  ``(-1, "", "not found")`` plus ``wg`` genuinely gone from disk is the coded
  503; the same sentinel with the binary still present keeps the original
  coded ``wg.keygen_failed`` shape — a slow or broken wg is not a missing
  one, and answering "not installed" next to a version string sends the
  operator at the wrong repair.
* **Failure text is scrubbed, not fatal.**  A failing dump whose stderr
  carries a lone surrogate and a 5000-digit run must reach ``state_error``
  as replaced text, and a failing ``wg-quick up`` must answer the *coded*
  ``admin.failed`` with a renderable JSON body whose detail is capped.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: Arrives already-int: YAML/plist hex loads through ``int(x, 16)``, which the
#: parse cap does not bound.  Built arithmetically so this file can construct it.
_HUGE_INT = 16 ** 5000
_SURR = "\ud800"

PUB = "A" * 42 + "b="
PRIV = "C" * 42 + "d="


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _client():
    from fastapi.testclient import TestClient

    from hub.app_factory import create_app
    from hub.auth import require_auth

    app = create_app()
    app.dependency_overrides[require_auth] = lambda: True
    return app, TestClient(app, raise_server_exceptions=False)


class _MountedRouteTests(unittest.TestCase):
    """Shared harness: real app, auth overridden, admin guard patched."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app, self.client = _client()
        self.addCleanup(app.dependency_overrides.clear)
        from hub.routers import wireguard_api

        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))


#: Every poison class a hand-edited / restored services.yaml has produced:
#: surrogate keys AND values, already-int over-cap hex, non-finite floats,
#: ``!!binary`` bytes, numeric ids, an over-cap listen URL port.
_POISONED_SETTINGS = {
    "interface": _HUGE_INT,
    "subnet": _SURR,
    "listen_port": _HUGE_INT,
    "dns": b"\xff\xfe1a5c",
    "mtu": float("inf"),
    "keepalive": float("nan"),
    "endpoint": _SURR + ":51820",
    "lan_cidr": _HUGE_INT,
    "wan_interface": _SURR,
    "wstunnel_enabled": 2,
    "wstunnel_listen": "ws://0.0.0.0:" + _HUGE_DIGITS,
    "wstunnel_public": _SURR,
    "wstunnel_restrict_to": "127.0.0.1:" + _HUGE_DIGITS,
    _SURR: "surrogate-key-1a5c",
    _HUGE_INT: "hexint-key-1a5c",
}


class PoisonedStoredSettingsHttpTests(_MountedRouteTests):
    """The four unguarded reads answer 200 with defaults over a poisoned store."""

    def setUp(self):
        super().setUp()
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "settings_section",
            lambda name: dict(_POISONED_SETTINGS),
        ))

    def test_settings_read_answers_defaults_not_500(self):
        resp = self.client.get("/api/wireguard/settings")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        merged = body["settings"]
        # Numeric interface / surrogate subnet / over-cap port / inf mtu /
        # nan keepalive / non-bool wstunnel flag all fall back to defaults.
        self.assertEqual(merged["interface"], "wg0")
        self.assertEqual(merged["subnet"], "10.10.0.0/24")
        self.assertEqual(merged["listen_port"], 51820)
        self.assertEqual(merged["mtu"], 1280)
        self.assertEqual(merged["keepalive"], 25)
        self.assertIs(merged["wstunnel_enabled"], False)
        # The surrogate endpoint survives as replaced text ("?" — encode
        # errors="replace" substitutes ASCII), never as a raw \ud800.
        self.assertEqual(merged["endpoint"], "?:51820")

    def test_status_readiness_and_next_ip_stay_200(self):
        for url in (
            "/api/wireguard",
            "/api/wireguard/readiness",
            "/api/wireguard/next-ip",
        ):
            with self.subTest(url=url):
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 200, f"{url}: {resp.text[:300]}")
                _no_surrogates(resp.json())

    def test_next_ip_allocates_from_the_default_subnet(self):
        body = self.client.get("/api/wireguard/next-ip").json()
        self.assertEqual(body["next_ip"], "10.10.0.2/32")
        self.assertEqual(body["subnet"], "10.10.0.0/24")


#: The journal a restored backup / hand edit produces: lone-surrogate escapes
#: in keys AND values, a >4300-digit ``created`` (json.loads int conversion is
#: ValueError, not JSONDecodeError), a huge-float ``1e999`` created, and
#: numeric name / ip fields.
_POISONED_REGISTRY = (
    '{"peers": {'
    f'"{PUB}": {{"name": "\\ud800 phone", "ip": "\\ud800", "mode": "split", '
    f'"created": {_HUGE_DIGITS}, "private_key": "{PRIV}", "\\ud800": "\\ud800"}}, '
    '"\\ud800-key-1a5c": {"name": "surrogate-key-peer", "ip": 5}, '
    '"peer-1a5c": {"name": 1074, "ip": 10, "created": 1e999}'
    "}}"
)

#: ``wg show <dev> dump`` whose peer row carries a surrogate endpoint and
#: over-cap handshake / rx / tx / keepalive columns; the interface row's
#: listen port is over-cap too.
_POISONED_DUMP = (
    f"{PRIV}\t{PUB}\t{_HUGE_DIGITS}\toff\n"
    f"{PUB}\t(none)\t{_SURR}:1\t10.10.0.2/32\t{_HUGE_DIGITS}\t{_HUGE_DIGITS}"
    f"\t{_HUGE_DIGITS}\t{_HUGE_DIGITS}\n"
)


class PoisonedJournalAndDumpHttpTests(_MountedRouteTests):
    """Journal + live-dump poisons stay coded and never cost the journal."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory(prefix="wg4-1a5c-")
        self.addCleanup(tmp.cleanup)
        conf_dir = Path(tmp.name)
        self.conf = conf_dir / "wg0.conf"
        self.conf.write_text(
            "[Interface]\n"
            f"PrivateKey = {PRIV}\n"
            "Address = 10.10.0.1/24\n"
            f"ListenPort = {_HUGE_DIGITS}\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {PUB}\n"
            "AllowedIPs = 10.10.0.2/32\n"
            f"PersistentKeepalive = {_HUGE_DIGITS}\n",
            encoding="utf-8",
        )
        wireguard_svc.REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        wireguard_svc.REGISTRY_PATH.write_text(_POISONED_REGISTRY, encoding="utf-8")
        self.addCleanup(
            lambda: wireguard_svc.REGISTRY_PATH.unlink(missing_ok=True)
        )

        def fake_sh(cmd, timeout=10, **kw):
            if "dump" in cmd:
                return 0, _POISONED_DUMP, ""
            return 0, "", ""

        for target, value in (
            ("conf_path", lambda interface=None: self.conf),
            ("conf_dir", lambda: conf_dir),
            ("public_from_private", lambda private: PUB),
            ("sh", fake_sh),
            ("real_interface", lambda interface=None: "utun9"),
            ("_path_exists", lambda path: True),
        ):
            self.stack.enter_context(
                mock.patch.object(wireguard_svc, target, value)
            )

    def test_status_scrubs_the_poison_and_keeps_the_peer_reissuable(self):
        resp = self.client.get("/api/wireguard")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        # Over-cap dump listen port falls back to the settings default rather
        # than raising CPython's digit-cap ValueError into the encoder.
        self.assertEqual(body["listen_port"], 51820)
        peer = body["peers"][0]
        # Surrogates arrive replaced ("?" — _as_text encodes errors="replace",
        # which substitutes ASCII); over-cap counters degrade to zero.
        self.assertEqual(peer["name"], "? phone")
        self.assertEqual(peer["endpoint"], "?:1")
        self.assertEqual(peer["rx"], 0)
        self.assertEqual(peer["tx"], 0)
        self.assertEqual(peer["last_handshake"], 0)
        # The load-bearing claim: a >4300-digit ``created`` did NOT degrade the
        # journal to {} — the retained private key is still visible, so the
        # next peer write cannot persist an empty view and destroy it.
        self.assertTrue(peer["reissuable"])

    def test_config_download_and_export_stay_200(self):
        query = {"pubkey": PUB}
        resp = self.client.get("/api/wireguard/peers/config", params=query)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertIn(PRIV, payload["content"])
        payload["filename"].encode("latin-1")

        resp = self.client.get("/api/wireguard/peers/download", params=query)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        (resp.headers.get("content-disposition") or "").encode("latin-1")

        for fmt in ("wg", "clash", "clashfull", "sr", "wst"):
            with self.subTest(fmt=fmt):
                resp = self.client.get(
                    "/api/wireguard/export", params={"format": fmt}
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                _no_surrogates(body)
                self.assertEqual(len(body["items"]), 1)

    def test_ping_and_sync_stay_coded(self):
        resp = self.client.post("/api/wireguard/ping")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        result = resp.json()["results"][0]
        self.assertEqual(result["ip"], "10.10.0.2")
        self.assertIsNone(result["latency_ms"])

        resp = self.client.post("/api/wireguard/sync")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["applied"])


class RequestBodyPoisonHttpTests(_MountedRouteTests):
    """Bodies through the real app: parse refusals and coded 400s, never 500."""

    def setUp(self):
        super().setUp()
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation",
            lambda: {"installed": True, "conf_exists": True, "conf_path": "",
                     "conf_dir": "", "wg": "wg", "wg_quick": "wg-quick",
                     "wireguard_go": "", "tools_version": "v1",
                     "userspace_version": "", "probe_failed": False},
        ))

    def _post_raw(self, url: str, body: str, method: str = "POST"):
        return self.client.request(
            method, url, content=body,
            headers={"content-type": "application/json"},
        )

    def test_over_cap_int_body_is_a_parse_time_4xx(self):
        # json.loads raises the digit-cap ValueError before pydantic ever sees
        # the literal; the route must answer 4xx, not a bare 500.
        resp = self._post_raw(
            "/api/wireguard/peers/batch",
            '{"count": ' + _HUGE_DIGITS + ', "prefix": "peer-1a5c"}',
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _no_surrogates(resp.json())

    def test_inf_body_is_a_sanitized_422(self):
        # json.loads turns RFC 1e999 into inf; the stock 422 handler echoed it
        # into detail[].input and 500'd its own error body.
        resp = self._post_raw(
            "/api/wireguard/settings", '{"listen_port": 1e999}', method="PUT"
        )
        self.assertEqual(resp.status_code, 422, resp.text[:300])
        _no_surrogates(resp.json())

    def test_surrogate_escape_bodies_answer_coded_400s(self):
        cases = (
            ("POST", "/api/wireguard/peers/delete",
             '{"pubkey": "\\ud800", "confirm": true}', "wg.bad_key"),
            ("POST", "/api/wireguard/peers",
             '{"name": "\\ud800", "ip": "\\ud800", "mode": "\\ud800"}',
             "wg.bad_name"),
            ("POST", "/api/wireguard/peers/import",
             '{"pubkey": "\\ud800", "ip": "10.10.0.9", "psk": "\\ud800"}',
             "wg.bad_key"),
            ("POST", "/api/wireguard/peers/psk",
             '{"pubkey": "\\ud800", "op": "\\ud800"}', "wg.bad_key"),
            ("POST", "/api/wireguard/remediate",
             '{"target": "\\ud800", "enabled": true}', "wg.bad_action"),
            ("POST", "/api/wireguard/interface",
             '{"action": "\\ud800"}', "wg.bad_action"),
        )
        for method, url, body, code in cases:
            with self.subTest(url=url):
                resp = self._post_raw(url, body, method=method)
                self.assertEqual(resp.status_code, 400, f"{url}: {resp.text[:300]}")
                payload = resp.json()
                _no_surrogates(payload)
                self.assertEqual(payload["detail"]["code"], code)

    def test_over_cap_endpoint_port_is_the_coded_refusal(self):
        resp = self.client.put(
            "/api/wireguard/settings",
            json={"endpoint": "vpn.example.com:" + _HUGE_DIGITS},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.bad_endpoint")

    def test_surrogate_export_format_is_the_coded_refusal(self):
        # %ED%A0%80 is the percent-encoding of a lone surrogate.
        resp = self.client.get("/api/wireguard/export?format=%ED%A0%80")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(payload["detail"]["code"], "wg.bad_format")


class VanishedCliHttpTests(_MountedRouteTests):
    """The 503 claim requires the on-disk confirm; a slow wg keeps its shape."""

    def setUp(self):
        super().setUp()
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation",
            lambda: {"installed": True, "conf_exists": True, "conf_path": "",
                     "conf_dir": "", "wg": "wg", "wg_quick": "wg-quick",
                     "wireguard_go": "", "tools_version": "v1",
                     "userspace_version": "", "probe_failed": False},
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "sh",
            lambda cmd, timeout=10, **kw: (-1, "", "not found"),
        ))

    def test_confirmed_vanished_wg_answers_the_coded_503(self):
        with mock.patch.object(wireguard_svc, "_path_exists", lambda p: False):
            resp = self.client.post(
                "/api/wireguard/peers", json={"name": "phone-1a5c"}
            )
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.not_installed")

    def test_wg_still_on_disk_keeps_the_keygen_failed_shape(self):
        # Same sh sentinel, but the binary is present: the sentinel alone is
        # not proof, and claiming "not installed" beside a version string
        # sends the operator at the wrong repair.
        with mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            resp = self.client.post(
                "/api/wireguard/peers", json={"name": "phone-1a5c"}
            )
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.keygen_failed")


class FailureTextScrubHttpTests(_MountedRouteTests):
    """Failure transcripts with surrogates / huge runs stay renderable."""

    def test_failing_dump_stderr_reaches_state_error_scrubbed(self):
        poison = _SURR + " Unable to access interface " + _HUGE_DIGITS

        def failing_sh(cmd, timeout=10, **kw):
            if "dump" in cmd:
                return 1, "", poison
            if "interfaces" in cmd:
                # A live socket exists, so "not running" is not the answer and
                # the dump failure itself must be reported.
                return 0, "utun9\n", ""
            return 0, "", ""

        with ExitStack() as stack:
            for target, value in (
                ("sh", failing_sh),
                ("sudo_capture", lambda cmd, timeout=10, **kw: (1, "", poison)),
                ("real_interface", lambda interface=None: "utun9"),
            ):
                stack.enter_context(
                    mock.patch.object(wireguard_svc, target, value)
                )
            resp = self.client.get("/api/wireguard")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertFalse(body["running"])
        # The lone surrogate arrives replaced ("?"), the 5000-digit run is
        # head-capped at 200 characters, and the useful words survive the cap.
        self.assertIn("Unable to access interface", body["state_error"])
        self.assertTrue(body["state_error"].startswith("?"))
        self.assertLessEqual(len(body["state_error"]), 200)

    def test_wg_quick_failure_is_the_coded_admin_failed_not_an_encode_crash(self):
        runtime = {
            "interface": "wg0", "name_file": "/var/run/wireguard/wg0.name",
            "name_file_present": False, "sockets": [], "real_interface": "",
            "live": False, "stale": False,
        }
        with ExitStack() as stack:
            for target, value in (
                ("installation",
                 lambda: {"installed": True, "conf_exists": True,
                          "conf_path": "", "conf_dir": "", "wg": "wg",
                          "wg_quick": "wg-quick", "wireguard_go": "",
                          "tools_version": "v1", "userspace_version": "",
                          "probe_failed": False}),
                ("_path_exists", lambda p: True),
                ("runtime_state", lambda interface=None: dict(runtime)),
                ("sh", lambda cmd, timeout=10, **kw: (
                    1, _SURR + " transcript " + _HUGE_DIGITS,
                    "wg-quick: boom " + _HUGE_DIGITS + " " + _SURR + " end-1a5c",
                )),
                ("sudo_refused", lambda err: False),
            ):
                stack.enter_context(
                    mock.patch.object(wireguard_svc, target, value)
                )
            resp = self.client.post(
                "/api/wireguard/interface", json={"action": "up"}
            )
        # The coded shape shared by every privileged failure — a rendered JSON
        # body, not an uncaught exception during its own encode.
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")
        detail = payload["detail"]["params"]["detail"]
        # The reason keeps the tail of the wg-quick: diagnostic (the 5000-digit
        # run is cut to the last 300 chars) with the surrogate replaced.
        self.assertTrue(detail.endswith("? end-1a5c"), detail[-60:])
        self.assertNotIn(_SURR, detail)
        self.assertLessEqual(len(detail), 300)


if __name__ == "__main__":
    unittest.main()
