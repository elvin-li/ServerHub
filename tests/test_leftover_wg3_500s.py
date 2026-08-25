"""Leftover 500s and silent-loss classes still live in the WireGuard domain.

The prior sweeps pinned the UTF-8 registry ip, the socket-stem surrogates, the
decimal digit-cap parsers and the download header
(test_leftover_wg_utf8_500s, test_leftover_net_wireguard_digit_500s,
test_wireguard_download_header_leftover_500s).  This hunt found four still
live:

* ``wireguard_wstunnel.read_plist`` stringified the LaunchDaemon argv with a
  bare ``str(part)``.  plistlib parses ``<integer>0x…</integer>`` through
  ``int(x, 16)``, which CPython's 4300-digit cap does not bound, so a leftover
  over-cap hex integer survived ``plistlib.loads`` and the ``str()``
  ValueError'd GET /api/wireguard, GET /api/wireguard/settings,
  GET /api/wireguard/readiness and GET /api/system/network.
* ``_load_registry`` wiped the whole journal on one over-cap *decimal* int:
  ``json.loads`` converts integer literals via ``int(str)``, whose ValueError
  is not JSONDecodeError, and the catch-all degraded
  ``data/wireguard-peers.json`` to ``{"peers": {}}``.  Every retained client
  private key read as gone — and the next peer write persisted that empty
  view, destroying them for real.  The number now clamps to 0 and the journal
  survives.
* ``_save_registry`` passed already-int over-cap values straight to
  ``json.dumps``, whose int->str render hits the same cap; the ValueError was
  swallowed and the *whole* journal write silently skipped while the peer
  create reported success.
* ``wg`` uninstalled between the route guard and the spawn answered a 400
  "invalid WireGuard key" (``public_from_private``) or a 500 "could not
  generate a key" (``generate_keypair``'s pubkey step) about a key that is
  fine.  Both now raise the coded 503 ``wg.not_installed`` — only after a
  fresh on-disk probe on the failure path, so a timeout or a real conversion
  failure with the binary still present keeps its original shape.

Stays-immune pins ride along for the neighbours that already survive:
``wireguard_net_svc._daemon_defects`` (same hex-int argv, scrubbed through
``_as_text``) and ``_cli_missing`` (the genkey step's sentinel + probe pair).
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import wireguard_net_svc, wireguard_svc
from hub import wireguard_wstunnel as wst


def _starlette(payload) -> None:
    """Exactly what Starlette's JSON encoder demands of a response body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


PUB = "A" * 42 + "b="
PUB_2 = "B" * 42 + "c="
PRIV = "C" * 42 + "d="

#: An int whose decimal render exceeds CPython's 4300-digit str<->int cap.
_OVER_CAP_DECIMAL = "9" * 5000
#: The same class as an already-parsed int (10**4999 has 5000 digits).
_OVER_CAP_INT = 10 ** 4999

#: A LaunchDaemon plist whose argv smuggles an over-cap int through hex.
_POISONED_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
    ' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    '<plist version="1.0"><dict>'
    "<key>Label</key><string>com.elvin.wstunnel-wg-server</string>"
    "<key>ProgramArguments</key><array>"
    "<string>/opt/homebrew/bin/wstunnel</string><string>server</string>"
    "<string>--restrict-to</string><string>127.0.0.1:51821</string>"
    "<integer>0x" + "F" * 4400 + "</integer>"
    "<string>ws://0.0.0.0:8444</string>"
    "</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>"
    "</dict></plist>"
)


class PlistHexIntegerTests(unittest.TestCase):
    """GET /api/wireguard used to 500 on a hex over-cap LaunchDaemon integer."""

    def setUp(self):
        tmp = Path(tempfile.mkdtemp(prefix="wg-plist-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.plist = tmp / "com.elvin.wstunnel-wg-server.plist"
        self.plist.write_text(_POISONED_PLIST)

    def test_read_plist_hex_over_cap_argv_does_not_raise(self):
        out = wst.read_plist(self.plist)
        _starlette(out)
        # The string parts still parse; only the absurd number degrades.
        self.assertEqual(out["listen"], "ws://0.0.0.0:8444")
        self.assertEqual(out["restrict_to"], "127.0.0.1:51821")

    def test_wstunnel_status_survives_poisoned_plist(self):
        # The exact shape GET /api/wireguard and GET /api/system/network embed.
        with mock.patch.object(wst, "PLIST_PATH", self.plist), mock.patch(
            "hub.proc_cache.ps_pid_commands", lambda: []
        ):
            wst.live.invalidate()
            self.addCleanup(wst.live.invalidate)
            snap = wst.status(dict(wireguard_svc.DEFAULTS))
        _starlette(snap)
        self.assertEqual(snap["desired_listen"], "ws://0.0.0.0:8444")

    def test_daemon_defects_stays_immune_to_hex_over_cap_argv(self):
        # Contrast pin: the boot-job auditor already scrubs argv through
        # _as_text, so the same poison must keep not raising there.
        defects = wireguard_net_svc._daemon_defects(_POISONED_PLIST)
        _starlette(defects)
        self.assertIsInstance(defects, list)


class RegistryJournalTests(unittest.TestCase):
    """One over-cap number must not cost the journal of retained client keys."""

    def setUp(self):
        tmp = Path(tempfile.mkdtemp(prefix="wg-reg-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.path = tmp / "wireguard-peers.json"
        self._patch = mock.patch.object(wireguard_svc, "REGISTRY_PATH", self.path)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _write_poisoned(self):
        self.path.write_text(
            '{"peers": {'
            '"%s": {"name": "phone", "private_key": "%s", "ip": "10.10.0.2/32",'
            ' "mode": "split", "created": %s},'
            ' "%s": {"name": "pad", "ip": "10.10.0.3/32"}}}'
            % (PUB, PRIV, _OVER_CAP_DECIMAL, PUB_2)
        )

    def test_over_cap_created_keeps_every_other_field_and_peer(self):
        self._write_poisoned()
        registry = wireguard_svc._load_registry()
        _starlette(registry)
        self.assertEqual(sorted(registry["peers"]), sorted([PUB, PUB_2]))
        meta = registry["peers"][PUB]
        # The retained private key — the whole point of the journal — survives.
        self.assertEqual(meta["private_key"], PRIV)
        self.assertEqual(meta["created"], 0)

    def test_next_write_does_not_destroy_retained_keys(self):
        # The silent-loss shape: add_peer loads, appends, saves.  With the
        # wiped load this rewrote the journal with only the new peer, and the
        # existing peers' private keys were gone for good.
        self._write_poisoned()
        registry = wireguard_svc._load_registry()
        registry["peers"]["D" * 42 + "e="] = {"name": "new", "created": 1}
        wireguard_svc._save_registry(registry)
        on_disk = json.loads(self.path.read_text())
        self.assertIn(PUB, on_disk["peers"])
        self.assertEqual(on_disk["peers"][PUB]["private_key"], PRIV)
        self.assertIn(PUB_2, on_disk["peers"])
        self.assertIn("D" * 42 + "e=", on_disk["peers"])

    def test_save_registry_clamps_in_memory_over_cap_int(self):
        # Already-int poison: json.dumps' int->str render hits the same cap,
        # and the swallowed ValueError used to skip the whole write.
        wireguard_svc._save_registry(
            {"peers": {PUB: {"name": "phone", "private_key": PRIV,
                             "created": _OVER_CAP_INT}}}
        )
        self.assertTrue(self.path.exists(), "journal write was silently skipped")
        on_disk = json.loads(self.path.read_text())
        self.assertEqual(on_disk["peers"][PUB]["private_key"], PRIV)
        self.assertEqual(on_disk["peers"][PUB]["created"], 0)

    def test_sane_registry_round_trips_unchanged(self):
        wireguard_svc._save_registry(
            {"peers": {PUB: {"name": "phone", "created": 1755000000}}}
        )
        registry = wireguard_svc._load_registry()
        self.assertEqual(registry["peers"][PUB]["created"], 1755000000)


class VanishedCliTests(unittest.TestCase):
    """An uninstall between the route guard and the spawn is the coded 503."""

    def _missing_wg(self):
        return mock.patch.object(
            wireguard_svc, "WG", "/nonexistent/serverhub-test/wg"
        )

    def _present_wg(self):
        tmp = Path(tempfile.mkdtemp(prefix="wg-bin-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        binary = tmp / "wg"
        binary.write_text("#!/bin/sh\n")
        return mock.patch.object(wireguard_svc, "WG", str(binary))

    def test_public_from_private_vanished_wg_is_not_installed(self):
        with self._missing_wg():
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.public_from_private(PRIV)
        self.assertEqual(ctx.exception.code, "wg.not_installed")

    def test_generate_keypair_pubkey_step_vanished_wg_is_not_installed(self):
        # genkey answers (a stub, or a race that lost the binary after it), the
        # pubkey spawn then finds nothing on disk.
        with self._missing_wg(), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (0, PRIV, "")
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.not_installed")

    def test_not_installed_maps_to_http_503(self):
        from hub.errors import error_payload

        status, _body = error_payload("wg.not_installed")
        self.assertEqual(status, 503)

    def test_timeout_with_binary_present_keeps_bad_key_shape(self):
        # A slow wg is not a missing one: empty answer + binary on disk keeps
        # the original mapping.
        with self._present_wg(), mock.patch.object(
            wireguard_svc, "_run_with_input", lambda *a, **k: ""
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.public_from_private(PRIV)
        self.assertEqual(ctx.exception.code, "wg.bad_key")

    def test_timeout_with_binary_present_keeps_keygen_failed_shape(self):
        with self._present_wg(), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (0, PRIV, "")
        ), mock.patch.object(
            wireguard_svc, "_run_with_input", lambda *a, **k: ""
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.keygen_failed")

    def test_genkey_spawn_sentinel_stays_immune(self):
        # The genkey step's own vanished-CLI path predates this sweep; pin it.
        with self._missing_wg(), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (-1, "", "not found")
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.not_installed")


class PeerConfigRouteVanishedCliTests(unittest.TestCase):
    """GET /api/wireguard/peers/config used to answer 400 about a fine key."""

    def _client(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def test_config_route_is_503_when_wg_vanished_mid_request(self):
        from hub.routers import wireguard_api

        settings = {
            **wireguard_svc.DEFAULTS,
            "endpoint": "vpn.example.com:51820",
        }
        record = {
            "public_key": PUB, "ip": "10.6.0.2/32", "preshared_key": "",
            "name": "phone", "mode": "", "created": 0, "reissuable": True,
            "known": True, "keepalive": "",
        }
        meta = {PUB: {
            "name": "phone", "private_key": PRIV, "ip": "10.6.0.2/32",
            "mode": "split",
        }}
        client = self._client()
        with mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ), mock.patch.object(
            # The guard's probe passes; the binary vanishes before the spawn.
            wireguard_svc, "installation", lambda: {"installed": True}
        ), mock.patch.object(
            wireguard_svc, "WG", "/nonexistent/serverhub-test/wg"
        ), mock.patch.object(
            wireguard_svc, "settings", lambda: dict(settings)
        ), mock.patch.object(
            wireguard_svc, "peer_records", lambda: [record]
        ), mock.patch.object(
            wireguard_svc, "_registry_peers", lambda: meta
        ), mock.patch.object(
            wireguard_svc, "read_conf",
            lambda interface=None: {
                "interface": {"PrivateKey": PRIV, "Address": "10.10.0.1/24"},
                "peers": [],
            },
        ):
            resp = client.get(
                "/api/wireguard/peers/config", params={"pubkey": PUB}
            )
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        _starlette(resp.json())


if __name__ == "__main__":
    unittest.main()
