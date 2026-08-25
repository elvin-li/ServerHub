"""Leftover alias-settings 500s on the Network page, plus stays-immune pins.

Two reproduced classes in ``hub.network_svc``:

* ``ip_aliases.ips`` entries went through a bare ``str(ip)``.  YAML hex/octal
  integers skip CPython's str->int digit cap on the *parse* (bases 16 and 8
  are exempt), so ``ips: [0x<4400 f's>]`` survived services.yaml fine and then
  ValueError'd ``str()`` inside ``_alias_settings`` — 500ing
  GET /api/system/network/alias/auto, POST /api/system/network/alias/auto/run
  and the PUT response, and silently skipping every autobind pass (the loop
  guards swallow the raise, so the thread just never binds anything again).

* ``_valid_ip`` accepts bytes, so a YAML ``!!binary`` netmask rode through
  ``_alias_settings`` *as bytes* and TypeError'd the JSON encoder on the same
  endpoints.

Stays-immune pins for the neighbouring classes this sweep checks:

* ``json.loads`` of a >4300-digit JSON number is ValueError, **not**
  JSONDecodeError — one garbled ``docker network inspect`` must degrade that
  network's row, never wipe the whole listing.
* Escaped ``\\ud800`` inside docker inspect JSON (json.loads emits a real lone
  surrogate even from clean ASCII input) is scrubbed before Starlette encodes.
* A docker CLI that vanishes mid-request maps connect/disconnect to the coded
  503 via the *fresh* forced engine probe; a timeout keeps the plain
  ``ok: false`` shape because the fresh probe still answers "up".
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

import yaml
from fastapi import HTTPException

from hub import docker_cli, network_svc


def _yaml_value(literal: str):
    """Parse *literal* the way services.yaml does."""
    return yaml.safe_load(f"v: {literal}")["v"]


#: Past the ~4300-digit int->str cap; parses fine because base 16 is exempt.
OVER_CAP_HEX = "0x" + "f" * 4400
#: Same via YAML 1.1 octal (leading zero), base 8 is exempt too.
OVER_CAP_OCT = "0" + "7" * 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: dumps then UTF-8 encode."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class AliasIpsOverCapIntTests(unittest.TestCase):
    def test_hex_yaml_ip_entry_does_not_500_alias_settings(self):
        """``ips: [0x<huge>]`` used to ValueError GET /api/system/network/alias/auto."""
        huge = _yaml_value(OVER_CAP_HEX)
        with self.assertRaises(ValueError):
            str(huge)  # the vector: parse fine, render raises
        with mock.patch(
            "hub.config.settings_section",
            return_value={"ips": [huge, "192.0.2.10"]},
        ):
            alias = network_svc._alias_settings()
        _starlette(alias)
        self.assertEqual(alias["ips"], ["192.0.2.10"])

    def test_octal_yaml_ip_entry_does_not_500_alias_auto_status(self):
        huge = _yaml_value(OVER_CAP_OCT)
        with (
            mock.patch(
                "hub.config.settings_section",
                return_value={"ips": [huge, "192.0.2.10"]},
            ),
            mock.patch.object(network_svc, "preferred_active_device", lambda: None),
            mock.patch.object(network_svc, "interface_addresses", lambda: []),
            mock.patch.object(
                network_svc, "_alias_local_route", lambda ip: {"ok": False},
            ),
        ):
            data = network_svc.alias_auto_status()
        _starlette(data)
        self.assertEqual([row["ip"] for row in data["ips"]], ["192.0.2.10"])

    def test_over_cap_ip_does_not_kill_the_autobind_pass(self):
        """The loop's guards swallowed the raise, so binding silently stopped."""
        huge = _yaml_value(OVER_CAP_HEX)
        with (
            mock.patch(
                "hub.config.settings_section",
                return_value={"ips": [huge], "auto_bind": True},
            ),
            mock.patch.object(network_svc, "preferred_active_device", lambda: None),
        ):
            result = network_svc.ensure_aliases_on_preferred(force=True)
        _starlette(result)
        # The garbled entry is dropped, so the pass reports "nothing to manage"
        # rather than dying before it could look at any interface.
        self.assertEqual(result["managed_ips"], [])
        self.assertTrue(result["ok"])

    def test_update_config_over_cap_ip_does_not_500_the_write_path(self):
        huge = _yaml_value(OVER_CAP_OCT)
        saved: dict = {}
        with (
            mock.patch("hub.config.settings_section", return_value={}),
            mock.patch(
                "hub.config.update_settings",
                side_effect=lambda patch: saved.update(patch),
            ),
            mock.patch.object(
                network_svc, "alias_auto_status", return_value={"ok": True},
            ),
        ):
            out = network_svc.update_alias_auto_config(ips=[huge, "192.0.2.10"])
        self.assertEqual(out, {"ok": True})
        self.assertEqual(saved["ip_aliases"]["ips"], ["192.0.2.10"])


class AliasBinaryNetmaskTests(unittest.TestCase):
    def test_yaml_binary_netmask_does_not_500(self):
        """``netmask: !!binary …`` passed ``_valid_ip`` and reached the encoder as bytes."""
        blob = yaml.safe_load("v: !!binary MjU1LjI1NS4yNTUuMA==")["v"]
        self.assertIsInstance(blob, bytes)
        with mock.patch(
            "hub.config.settings_section",
            return_value={"netmask": blob, "ips": ["192.0.2.10"]},
        ):
            alias = network_svc._alias_settings()
        _starlette(alias)
        # The valid dotted quad is kept, decoded — not dropped, not bytes.
        self.assertEqual(alias["netmask"], "255.255.255.0")

    def test_yaml_binary_ip_entry_is_decoded_not_dropped(self):
        blob = yaml.safe_load("v: !!binary MTkyLjAuMi4yMDQ=")["v"]
        self.assertEqual(blob, b"192.0.2.204")
        with mock.patch(
            "hub.config.settings_section", return_value={"ips": [blob]},
        ):
            alias = network_svc._alias_settings()
        _starlette(alias)
        self.assertEqual(alias["ips"], ["192.0.2.204"])

    def test_surrogate_ips_and_netmask_stay_scrubbed(self):
        """Stays-immune: lone surrogates never reach the JSON payload."""
        with mock.patch(
            "hub.config.settings_section",
            return_value={
                "ips": ["192.0.2.10\ud800", "192.0.2.11"],
                "netmask": "255.255.255.0\ud800",
            },
        ):
            alias = network_svc._alias_settings()
        _starlette(alias)
        self.assertEqual(alias["ips"], ["192.0.2.11"])
        self.assertEqual(alias["netmask"], "255.255.255.255")


class DockerNetworkInspectLeftoverPins(unittest.TestCase):
    """Stays-immune: per-network inspect defects degrade one row, never the page."""

    LS = "aaa111\tneta\tbridge\tlocal\nbbb222\tnetb\tbridge\tlocal\n"
    #: >4300-digit decimal in otherwise valid JSON: ``json.loads`` raises plain
    #: ValueError (the int->str/parse cap), not JSONDecodeError.
    HUGE_JSON = '[{"Name": "neta", "IPAM": ' + "1" * 4400 + "}]"
    #: json.loads('"\\ud800"') emits a real lone surrogate from ASCII input.
    SURROGATE_JSON = (
        '[{"Name": "netb", '
        '"IPAM": {"Config": [{"Subnet": "10.9.0.0/24", "Gateway": "10.9.0.1"}]}, '
        '"Containers": {"abcdef123456": '
        '{"Name": "/web\\ud800", "IPv4Address": "10.9.0.2/24"}}}]'
    )

    def _fake_docker(self, *args, timeout=30):
        if args[:2] == ("network", "ls"):
            return 0, self.LS, ""
        if args[:2] == ("network", "inspect"):
            return 0, self.HUGE_JSON if args[2] == "neta" else self.SURROGATE_JSON, ""
        return 1, "", "unexpected"

    def test_huge_json_number_degrades_one_row_not_the_listing(self):
        with (
            mock.patch.object(network_svc, "engine_up", return_value=True),
            mock.patch.object(network_svc, "docker", side_effect=self._fake_docker),
        ):
            rows = network_svc.docker_networks_detail()
        _starlette(rows)
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(set(by_name), {"neta", "netb"})
        # The garbled inspect empties that network's detail only.
        self.assertEqual(by_name["neta"]["subnet"], "")
        self.assertEqual(by_name["netb"]["subnet"], "10.9.0.0/24")

    def test_escaped_surrogate_container_name_is_scrubbed(self):
        with (
            mock.patch.object(network_svc, "engine_up", return_value=True),
            mock.patch.object(network_svc, "docker", side_effect=self._fake_docker),
        ):
            rows = network_svc.docker_networks_detail()
        _starlette(rows)
        netb = next(r for r in rows if r["name"] == "netb")
        self.assertEqual(len(netb["containers"]), 1)
        self.assertNotIn("\ud800", netb["containers"][0]["name"])


class DockerCliVanishedNetworkMutationPins(unittest.TestCase):
    """Stays-immune: vanished CLI is the coded 503; a timeout keeps its shape."""

    SENTINEL = (-1, "", "not found")

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def test_vanished_cli_maps_to_the_coded_503_via_a_fresh_probe(self):
        """Both the mutation and the forced ``docker info`` hit the spawn
        sentinel, so the fresh probe answers "down" — never a raw message."""
        for call in (
            lambda: network_svc.docker_network_connect("mynet", "web-1"),
            lambda: network_svc.docker_network_disconnect("mynet", "web-1"),
        ):
            with (
                mock.patch.object(network_svc, "docker", return_value=self.SENTINEL),
                mock.patch.object(docker_cli, "docker", return_value=self.SENTINEL),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    call()
            self.assertEqual(ctx.exception.status_code, 503)
            self.assertEqual(ctx.exception.detail["code"], "container.engine_down")
            docker_cli.invalidate_engine_state()

    def test_a_timeout_with_the_engine_up_keeps_the_ok_false_shape(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                network_svc, "docker", return_value=(-1, "", "timeout"),
            ),
            mock.patch.object(network_svc, "engine_up", probe),
        ):
            result = network_svc.docker_network_connect("mynet", "web-1")
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["message"], "timeout")
        probe.assert_called_once_with(force=True)


if __name__ == "__main__":
    unittest.main()
