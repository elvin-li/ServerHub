"""Leftover UTF-8 500s on WireGuard peer re-issue and socket resolution.

Hunt across the remaining WireGuard int()/json.dumps/header paths found the
digit-limit and download-header classes already pinned
(test_leftover_net_wireguard_digit_500s, test_wireguard_download_header_
leftover_500s, test_leftover_wg_cloudflared_500s).  Two UTF-8 leftovers were
still live:

* ``peer_conf`` built the client config with a bare ``str()`` of the
  registry's ``ip``.  ``data/wireguard-peers.json`` is hand-editable and
  restorable from backups, and JSON happily encodes a lone surrogate as
  ``\\ud800`` — whenever the server conf block carried no ``AllowedIPs`` to
  prefer, that surrogate leaked into ``content`` and 500'd
  GET /api/wireguard/peers/config (Starlette's UTF-8 body encode),
  GET /api/wireguard/peers/download (PlainTextResponse encode) and
  GET /api/wireguard/export.  The name and private key already went through
  ``_as_text``; the ip did not.
* ``_sockets`` returned raw ``/var/run/wireguard`` stems.  Filenames come
  back surrogateescape'd, so a leftover socket with undecodable bytes in its
  name flowed through ``runtime_state()`` (``sockets`` / ``real_interface``)
  into GET /api/wireguard/readiness, and — as the single "unclaimed" socket —
  became the ``device`` in POST /api/wireguard/sync's response.

The battery also pins a hunted path that already survives its class: a
registry whose JSON carries a >4300-digit int (CPython's str->int cap raises
ValueError inside ``json.loads``) degrades to an empty registry instead of
500ing every peer read.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import wireguard_svc


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


PUB = "A" * 42 + "b="
PRIV = "C" * 42 + "d="

_SETTINGS = {
    **wireguard_svc.DEFAULTS,
    "endpoint": "vpn.example.com:51820",
    "lan_cidr": "192.168.1.0/24",
}


def _leftover_registry_patches(registry_ip: str):
    """A reissuable peer whose conf block lost AllowedIPs, so the registry
    ip — the leftover — is what ends up in the generated config."""
    meta = {PUB: {
        "name": "phone", "private_key": PRIV, "ip": registry_ip, "mode": "split",
    }}
    record = {
        "public_key": PUB, "ip": "", "preshared_key": "", "name": "phone",
        "mode": "", "created": 0, "reissuable": True, "known": True,
        "keepalive": "",
    }
    return (
        mock.patch.object(wireguard_svc, "_registry_peers", lambda: meta),
        mock.patch.object(wireguard_svc, "peer_records", lambda: [record]),
        mock.patch.object(
            wireguard_svc, "server_identity",
            lambda: {
                "private_key": PRIV, "public_key": PUB,
                "address": "10.10.0.1/24", "listen_port": 51820,
            },
        ),
        mock.patch.object(wireguard_svc, "settings", lambda: dict(_SETTINGS)),
    )


class PeerConfRegistryIpSurrogateTests(unittest.TestCase):
    """GET /api/wireguard/peers/config used to 500 on a leftover ``\\ud800`` ip."""

    def test_surrogate_registry_ip_does_not_500_peer_conf(self):
        p1, p2, p3, p4 = _leftover_registry_patches("10.6.0.2\ud800")
        with p1, p2, p3, p4:
            out = wireguard_svc.peer_conf(PUB, "wg")
        _starlette(out)
        self.assertNotIn("\ud800", out["content"])
        self.assertIn("Address = 10.6.0.2", out["content"])
        # The download twin renders the same content through
        # PlainTextResponse, whose body encode is exactly this.
        out["content"].encode("utf-8")

    def test_surrogate_registry_ip_does_not_500_export(self):
        p1, p2, p3, p4 = _leftover_registry_patches("10.6.0.2\ud800")
        with p1, p2, p3, p4:
            out = wireguard_svc.export_all("wg")
        _starlette(out)
        self.assertEqual(len(out["items"]), 1)
        self.assertNotIn("\ud800", out["items"][0]["content"])

    def test_sane_registry_ip_still_renders(self):
        p1, p2, p3, p4 = _leftover_registry_patches("10.6.0.7")
        with p1, p2, p3, p4:
            out = wireguard_svc.peer_conf(PUB, "wg")
        self.assertIn("Address = 10.6.0.7", out["content"])
        _starlette(out)


class PeerConfigRoutesEndToEndTests(unittest.TestCase):
    """Through the app: the exact requests that used to answer a bare 500."""

    def _client(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _patches(self):
        from hub.routers import wireguard_api

        p1, p2, p3, p4 = _leftover_registry_patches("10.6.0.2\ud800")
        return (
            mock.patch.object(
                wireguard_api, "require_admin_browser", lambda request: "admin"
            ),
            mock.patch.object(
                wireguard_svc, "installation", lambda: {"installed": True}
            ),
            p1, p2, p3, p4,
        )

    def test_config_route_is_200_with_leftover_registry_ip(self):
        client = self._client()
        p1, p2, p3, p4, p5, p6 = self._patches()
        with p1, p2, p3, p4, p5, p6:
            resp = client.get(
                "/api/wireguard/peers/config", params={"pubkey": PUB}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        self.assertIn("Address = 10.6.0.2", payload["content"])
        _starlette(payload)

    def test_download_route_is_200_with_leftover_registry_ip(self):
        client = self._client()
        p1, p2, p3, p4, p5, p6 = self._patches()
        with p1, p2, p3, p4, p5, p6:
            resp = client.get(
                "/api/wireguard/peers/download", params={"pubkey": PUB}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIn("attachment", resp.headers.get("content-disposition") or "")
        self.assertIn("Address = 10.6.0.2", resp.text)

    def test_export_route_is_200_with_leftover_registry_ip(self):
        client = self._client()
        p1, p2, p3, p4, p5, p6 = self._patches()
        with p1, p2, p3, p4, p5, p6:
            resp = client.get("/api/wireguard/export", params={"format": "wg"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        _starlette(resp.json())


class SocketNameSurrogateTests(unittest.TestCase):
    """GET /api/wireguard/readiness used to 500 on an undecodable socket name."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wg-run-"))
        self.addCleanup(
            lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True)
        )
        self._run_dir = mock.patch.object(wireguard_svc, "WG_RUN_DIR", self.tmp)
        self._run_dir.start()
        self.addCleanup(self._run_dir.stop)
        self._settings = mock.patch.object(
            wireguard_svc, "settings", lambda: dict(wireguard_svc.DEFAULTS)
        )
        self._settings.start()
        self.addCleanup(self._settings.stop)

    def test_surrogate_socket_stem_is_dropped_not_500(self):
        (self.tmp / "utun\udcff.sock").write_text("")
        (self.tmp / "utun8.sock").write_text("")
        self.assertEqual(wireguard_svc._sockets(), ["utun8"])
        state = wireguard_svc.runtime_state("wg0")
        _starlette(state)
        self.assertEqual(state["sockets"], ["utun8.sock"])

    def test_lone_surrogate_socket_is_not_our_device(self):
        # The single-unclaimed-socket fallback used to hand the surrogate name
        # back as the device, which POST /api/wireguard/sync then echoed.
        (self.tmp / "utun\udcff.sock").write_text("")
        self.assertEqual(wireguard_svc.real_interface("wg0"), "")
        state = wireguard_svc.runtime_state("wg0")
        _starlette(state)
        self.assertEqual(state["real_interface"], "")

    def test_plain_socket_names_still_resolve(self):
        (self.tmp / "wg0.sock").write_text("")
        self.assertEqual(wireguard_svc.real_interface("wg0"), "wg0")
        (self.tmp / "wg0.sock").unlink()
        (self.tmp / "utun8.sock").write_text("")
        # One socket, no claims: it can only be ours.
        self.assertEqual(wireguard_svc.real_interface("wg0"), "utun8")


class HuntedRegistryDigitPinTests(unittest.TestCase):
    """A >4300-digit int in the registry degrades to empty, not a 500."""

    def test_over_cap_created_degrades_to_empty_registry(self):
        tmp = Path(tempfile.mkdtemp(prefix="wg-reg-"))
        self.addCleanup(
            lambda: __import__("shutil").rmtree(tmp, ignore_errors=True)
        )
        path = tmp / "wireguard-peers.json"
        path.write_text(
            '{"peers": {"%s": {"name": "phone", "created": %s}}}'
            % (PUB, "9" * 5000)
        )
        with mock.patch.object(wireguard_svc, "REGISTRY_PATH", path):
            registry = wireguard_svc._load_registry()
        self.assertEqual(registry, {"peers": {}})
        _starlette(registry)


if __name__ == "__main__":
    unittest.main()
