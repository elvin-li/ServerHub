"""Leftover non-ASCII peer name 500 on GET /api/wireguard/peers/download.

Starlette encodes response header values as latin-1, and ``str.isalnum`` is
true for CJK / Cyrillic / superscripts, so ``filename_for`` kept those
characters in the download filename.  A peer whose registry entry in
``data/wireguard-peers.json`` carried a non-ASCII name (hand-edited, or
restored from a backup written before the ``_NAME_RE`` rule existed) made the
``Content-Disposition`` render raise UnicodeEncodeError: the download route
answered a bare 500 while the JSON ``/peers/config`` twin for the very same
peer answered 200.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from hub import wireguard_export as wgx


def _header_value(value: str) -> bytes:
    """Starlette's own header encode: the value has to survive it."""
    return value.encode("latin-1")


class FilenameForLeftoverTests(unittest.TestCase):
    def test_ascii_names_are_unchanged(self):
        self.assertEqual(wgx.filename_for("wg", "my phone/../x"), "my-phone----x.conf")
        self.assertEqual(wgx.filename_for("clash", "p"), "p-clash.yaml")

    def test_cjk_name_yields_a_latin1_encodable_filename(self):
        """A leftover ``手机`` name used to 500 the download's header render."""
        for fmt in ("wg", "clash", "clashfull", "sr", "wst", "unknown"):
            with self.subTest(fmt=fmt):
                name = wgx.filename_for(fmt, "手机-小米")
                _header_value(name)

    def test_cyrillic_and_superscript_names_are_encodable(self):
        for leftover in ("Телефон", "phone²", "Ёлка ноут"):
            with self.subTest(name=leftover):
                _header_value(wgx.filename_for("wg", leftover))

    def test_fully_non_ascii_name_still_gets_a_real_stem(self):
        """Not ``------.conf``: an all-CJK name falls back to the default."""
        self.assertEqual(wgx.filename_for("wg", "手机"), "peer.conf")

    def test_replacement_char_from_a_cleaned_surrogate_is_encodable(self):
        # peer_conf passes names through _as_text first, which turns a lone
        # surrogate into U+FFFD -- also outside latin-1.
        _header_value(wgx.filename_for("wg", "ok\ufffd"))


class DownloadRouteEndToEndTests(unittest.TestCase):
    """Through the app: the exact request that used to answer a bare 500."""

    PUB = "A" * 42 + "b="
    PRIV = "C" * 42 + "d="

    def _client(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _leftover_registry(self):
        from hub import wireguard_svc
        from hub.routers import wireguard_api

        meta = {self.PUB: {
            "name": "手机-小米", "private_key": self.PRIV,
            "ip": "10.6.0.2", "mode": "split",
        }}
        record = {
            "public_key": self.PUB, "ip": "10.6.0.2", "preshared_key": "",
            "name": "手机-小米", "known": True,
        }
        settings = {
            "interface": "wg0", "subnet": "10.6.0.0/24", "listen_port": 51820,
            "dns": "1.1.1.1", "mtu": 1420, "keepalive": 25,
            "endpoint": "vpn.example.com:51820", "lan_cidr": "192.168.1.0/24",
            "wan_interface": "", "wstunnel_enabled": False,
            "wstunnel_listen": "", "wstunnel_public": "",
            "wstunnel_restrict_to": "",
        }
        return (
            patch.object(wireguard_api, "require_admin_browser", lambda request: "admin"),
            patch.object(wireguard_svc, "installation", lambda: {"installed": True}),
            patch.object(wireguard_svc, "_registry_peers", lambda: meta),
            patch.object(wireguard_svc, "peer_records", lambda: [record]),
            patch.object(
                wireguard_svc, "server_identity",
                lambda: {"private_key": self.PRIV, "public_key": self.PUB},
            ),
            patch.object(wireguard_svc, "settings", lambda: settings),
        )

    def test_download_with_leftover_cjk_name_is_200(self):
        client = self._client()
        p1, p2, p3, p4, p5, p6 = self._leftover_registry()
        with p1, p2, p3, p4, p5, p6:
            resp = client.get(
                "/api/wireguard/peers/download", params={"pubkey": self.PUB}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        disposition = resp.headers.get("content-disposition") or ""
        self.assertIn("attachment", disposition)
        # Starlette's header encode: the filename has to survive latin-1.
        disposition.encode("latin-1")
        self.assertTrue(disposition.isascii(), disposition)

    def test_config_twin_still_answers_json_with_the_original_name(self):
        """The JSON route keeps the display name; only the filename is ASCII."""
        client = self._client()
        p1, p2, p3, p4, p5, p6 = self._leftover_registry()
        with p1, p2, p3, p4, p5, p6:
            resp = client.get(
                "/api/wireguard/peers/config", params={"pubkey": self.PUB}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        self.assertEqual(payload["name"], "手机-小米")
        # Starlette's body encoder settings: the payload has to survive them.
        json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        payload["filename"].encode("latin-1")


if __name__ == "__main__":
    unittest.main()
