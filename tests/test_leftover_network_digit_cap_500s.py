"""Leftover CPython digit-cap 500s and a vanished-wg misclassification.

YAML hex/octal integers skip CPython's str->int digit cap (bases 16 and 8 are
exempt), so a hand-edited services.yaml value like ``listen_port: 0x<huge>``
survived the settings readers as an over-cap int and then ValueError'd
``json.dumps`` itself — GET /api/system/network (alias config and the wstunnel
snapshot), GET /api/wireguard and GET /api/wireguard/settings all 500'd on a
value the write path would have rejected.

Follow-up on the vanished-CLI convention (docker_cli.looks_cli_vanished):
``(-1, "not found")`` from ``sh`` was treated as "wireguard-tools is not
installed" without confirming the filesystem, so a wg still on disk was
misreported by the 503 while ``installation()`` on the same page showed its
version string.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

import yaml

from hub import network_svc
from hub import wireguard_svc
from hub import wireguard_wstunnel as wt


def _yaml_int(literal: str) -> int:
    """Parse *literal* the way services.yaml does."""
    return yaml.safe_load(f"v: {literal}")["v"]


#: Past the ~4300-digit int->str cap; parses fine because base 16 is exempt.
OVER_CAP_HEX = "0x" + "f" * 4400
#: Same via YAML 1.1 octal (leading zero), base 8 is exempt too.
OVER_CAP_OCT = "0" + "7" * 5000


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


class OverCapIntParsesFromYamlTests(unittest.TestCase):
    def test_hex_and_octal_yaml_ints_skip_the_digit_cap(self):
        """The vector: the parse succeeds, only the render raises."""
        for literal in (OVER_CAP_HEX, OVER_CAP_OCT):
            huge = _yaml_int(literal)
            self.assertIsInstance(huge, int)
            with self.assertRaises(ValueError):
                str(huge)


class NetworkAliasOverCapIntervalTests(unittest.TestCase):
    def test_hex_yaml_interval_does_not_500_alias_settings(self):
        """Over-cap ``ip_aliases.interval`` used to 500 GET /api/system/network."""
        huge = _yaml_int(OVER_CAP_HEX)
        with mock.patch(
            "hub.config.settings_section",
            return_value={"interval": huge, "ips": ["192.0.2.10"]},
        ):
            alias = network_svc._alias_settings()
        _json(alias)
        self.assertEqual(alias["interval"], 60)

    def test_coerce_int_drops_over_cap_to_default(self):
        self.assertEqual(network_svc._coerce_int(_yaml_int(OVER_CAP_OCT), 15), 15)
        # Renderable values keep passing through unchanged.
        self.assertEqual(network_svc._coerce_int("120", 60), 120)


class WireGuardSettingsOverCapTests(unittest.TestCase):
    def test_over_cap_yaml_ints_fall_back_to_defaults(self):
        """Over-cap listen_port/mtu/keepalive used to 500 GET /api/wireguard/settings."""
        huge = _yaml_int(OVER_CAP_HEX)
        with mock.patch.object(
            wireguard_svc, "settings_section",
            return_value={"listen_port": huge, "mtu": huge, "keepalive": huge},
        ):
            cfg = wireguard_svc.settings()
        _json(cfg)
        self.assertEqual(cfg["listen_port"], wireguard_svc.DEFAULTS["listen_port"])
        self.assertEqual(cfg["mtu"], wireguard_svc.DEFAULTS["mtu"])
        self.assertEqual(cfg["keepalive"], wireguard_svc.DEFAULTS["keepalive"])

    def test_out_of_range_ints_fall_back_like_the_write_path(self):
        """The read path now enforces the same ranges save_settings validates."""
        with mock.patch.object(
            wireguard_svc, "settings_section",
            return_value={"listen_port": 0, "mtu": 100, "keepalive": -5},
        ):
            cfg = wireguard_svc.settings()
        self.assertEqual(cfg["listen_port"], wireguard_svc.DEFAULTS["listen_port"])
        self.assertEqual(cfg["mtu"], wireguard_svc.DEFAULTS["mtu"])
        self.assertEqual(cfg["keepalive"], wireguard_svc.DEFAULTS["keepalive"])

    def test_in_range_ints_pass_through(self):
        with mock.patch.object(
            wireguard_svc, "settings_section",
            return_value={"listen_port": 51821, "mtu": 1420, "keepalive": 30},
        ):
            cfg = wireguard_svc.settings()
        self.assertEqual(cfg["listen_port"], 51821)
        self.assertEqual(cfg["mtu"], 1420)
        self.assertEqual(cfg["keepalive"], 30)


class WstunnelStatusOverCapPortTests(unittest.TestCase):
    def test_over_cap_listen_port_does_not_500_status(self):
        """Over-cap ``local_port`` used to 500 GET /api/wireguard and the overview."""
        huge = _yaml_int(OVER_CAP_OCT)
        idle = {
            "listen": "", "restrict_to": "", "pid": 0,
            "running": False, "binary": "", "plist": "",
        }
        with (
            mock.patch.object(wt, "live", return_value=dict(idle)),
            mock.patch.object(wt, "local_ipv4s", return_value=frozenset()),
        ):
            snap = wt.status({"listen_port": huge})
        _json(snap)
        # The garbled value is dropped, so the port falls back to the default
        # listen URL's — the same path an unset listen_port takes.
        self.assertEqual(snap["local_port"], 8444)
        self.assertEqual(snap["local_endpoint"], "127.0.0.1:8444")


class VanishedWgConfirmsFilesystemTests(unittest.TestCase):
    SENTINEL = (-1, "", "not found")

    def test_sentinel_with_wg_on_disk_stays_keygen_failed(self):
        """The 503 must not claim "not installed" about a wg that is on disk."""
        with (
            mock.patch.object(wireguard_svc, "sh", return_value=self.SENTINEL),
            mock.patch.object(wireguard_svc, "_path_exists", return_value=True),
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as caught:
                wireguard_svc.generate_psk()
        self.assertEqual(caught.exception.code, "wg.keygen_failed")

    def test_sentinel_with_wg_gone_raises_the_coded_503(self):
        with (
            mock.patch.object(wireguard_svc, "sh", return_value=self.SENTINEL),
            mock.patch.object(wireguard_svc, "_path_exists", return_value=False),
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as caught:
                wireguard_svc.generate_keypair()
        self.assertEqual(caught.exception.code, "wg.not_installed")

    def test_real_exit_reading_not_found_is_never_the_sentinel(self):
        """A genuine wg exit whose output merely says "not found" keeps its map."""
        with mock.patch.object(wireguard_svc, "_path_exists", return_value=False):
            self.assertFalse(wireguard_svc._cli_missing(1, "not found"))
            self.assertFalse(wireguard_svc._cli_missing(-1, "timeout"))


if __name__ == "__main__":
    unittest.main()
