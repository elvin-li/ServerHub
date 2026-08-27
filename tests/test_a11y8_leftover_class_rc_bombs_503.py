"""Eighth a11y leftover sweep: __class__/rc bombs and the services-listing lie.

a11y4–a11y7 sealed the Network+Tools-net vanished-CLI 503s and the nested
``__bool__``/subclass-method bombs, but three NEW vector families still
500'd (or lied through) the very same routes:

* ``__class__``-property bombs.  CPython's ``isinstance`` reads the
  operand's ``__class__`` whenever the real-type fast check misses, so a
  stored value whose ``__class__`` is a raising property blew straight
  through every bare type-gate *before* the earlier hardening could run:
  ``_truthy``'s bool gate (auto_bind / enabled), ``_as_text``'s bytes gate
  (netmask), ``_alias_settings``' str/list ladder (ips) — raw 500s on
  GET /api/system/network/alias/auto, GET/POST failover and POST
  alias/auto/run.  A *lying* ``__class__`` (real type X, claims
  str/bytes/list/bool) passed the gates instead and TypeErrored the
  unbound base calls (``str.replace``, ``list.__iter__``,
  ``bytes.decode``) or rode a non-bool into the JSON encoder — the same
  500s from the other side.  ``sh``-stub stdout bombs took the twin path
  through ``_as_text`` on POST /api/tools/net/ping and GET dns-lookup.

* rc-subclass ``__eq__`` bombs and over-cap exact-int rcs.  ``sh`` is
  stubbed in-process, and a poisoned rc detonated the very first
  ``rc == 0`` / ``_spawn_sentinel`` compare (dhcp/manual/dns/enabled,
  dns-lookup, tools net ping) or blew the ``f"exit {rc}"`` message render
  (CPython's int->str digit cap).  ``_sh`` now launders rc to an exact,
  renderable int; junk degrades to ``-255`` — nonzero (a poisoned rc is
  not consent to claim success) and never ``-1`` (the vanished-spawn
  sentinel stays unforgeable).

* one more vanished-CLI 200 lie: GET /api/system/network/services with a
  vanished networksetup answered 200 ``{"services": []}`` — a Mac with no
  network services, a configuration that does not exist.  Same rule as
  the mutation siblings: disk probe on the empty-listing failure path
  only, coded 503 for the confirmed-absent binary, present-but-empty and
  readable listings keep their honest 200s.

Every fixed case was reproduced live as a raw 500 (or the 200 lie) over
``create_app()`` + ``TestClient`` before fixing.  The tail pins hold the
already-immune neighbours in place: numeric-YAML ips via the str() probe,
interval bombs degrading through ``_coerce_int``, the a11y6/a11y7 spawn
sentinel still recognised through the rc laundering, and the torn-IPv6
lookup refusal.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import cli_args, network_svc, tools_svc
from hub.auth import require_auth

_APP = None

#: A path that exists on every host, standing in for a binary still on disk.
_ON_DISK = sys.executable
_GONE = "/nonexistent/a11y8/tool"

#: Exactly what ``hub.util.sh`` answers for a FileNotFoundError spawn.
_SENTINEL = (-1, "", "not found")

#: An exact int past CPython's 4300-digit int->str render cap (YAML hex
#: leftovers skip the cap on parse, so the value itself constructs fine).
_HUGE_INT = 10 ** 5000


class ClassBomb:
    """Reading ``__class__`` raises — every bare isinstance gate detonates."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class LyingStr:
    """Claims to be str; the unbound base calls refuse it."""

    @property
    def __class__(self):
        return str


class LyingList:
    @property
    def __class__(self):
        return list


class LyingBytes:
    @property
    def __class__(self):
        return bytes


class LyingBool:
    @property
    def __class__(self):
        return bool


class RcEqBomb(int):
    """An rc whose ``==`` raises — the first sentinel compare used to 500."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    __hash__ = int.__hash__


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _strict(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


def _settings(overrides):
    def read(name):
        return overrides.get(name, {})

    return mock.patch("hub.config.settings_section", side_effect=read)


def _no_host_reads():
    """Empty interface/service listings so the status reads spawn nothing."""
    return (
        mock.patch.object(network_svc, "interfaces", return_value=[]),
        mock.patch.object(
            network_svc, "_network_service_order_entries", return_value=[]
        ),
    )


class AliasSettingsClassBombTests(unittest.TestCase):
    """GET /alias/auto: every nested ``__class__`` bomb degrades, never 500s."""

    def _alias_auto(self, section):
        ifaces, order = _no_host_reads()
        with _settings({"ip_aliases": section}), ifaces, order:
            return _client().get("/api/system/network/alias/auto")

    def test_class_bomb_auto_bind_degrades_instead_of_500(self):
        # Fails on the pre-fix tree: isinstance in _truthy read the bomb's
        # __class__ and the RuntimeError 500'd the whole status read.
        resp = self._alias_auto({"auto_bind": ClassBomb(), "ips": []})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertIs(resp.json()["config"]["auto_bind"], True)

    def test_lying_bool_auto_bind_answers_an_exact_json_bool(self):
        # Fails on the pre-fix tree: the liar passed isinstance(…, bool)
        # and rode a non-bool into the JSON encoder.
        resp = self._alias_auto({"auto_bind": LyingBool(), "ips": []})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertIs(resp.json()["config"]["auto_bind"], True)

    def test_class_bomb_netmask_falls_back_to_the_default(self):
        # Fails on the pre-fix tree: _as_text's bytes gate detonated.
        resp = self._alias_auto({"netmask": ClassBomb(), "ips": []})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["netmask"], "255.255.255.255")

    def test_lying_bytes_netmask_falls_back_to_the_default(self):
        # Fails on the pre-fix tree: bytes.decode TypeError'd on the liar.
        resp = self._alias_auto({"netmask": LyingBytes(), "ips": []})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["netmask"], "255.255.255.255")

    def test_class_bomb_ips_reads_as_no_managed_ips(self):
        # Fails on the pre-fix tree: the str/list isinstance ladder raised.
        resp = self._alias_auto({"ips": ClassBomb()})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["ips"], [])

    def test_lying_str_ips_reads_as_no_managed_ips(self):
        # Fails on the pre-fix tree: str.replace TypeError'd on the liar.
        resp = self._alias_auto({"ips": LyingStr()})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["ips"], [])

    def test_lying_list_ips_reads_as_no_managed_ips(self):
        # Fails on the pre-fix tree: list.__iter__ TypeError'd on the liar.
        resp = self._alias_auto({"ips": LyingList()})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["ips"], [])

    def test_alias_auto_run_with_the_bomb_keeps_its_honest_answer(self):
        # The mutation twin of the status read: same settings bombs, same
        # degrade — the no-managed-IPs early return, never a 500.
        ifaces, order = _no_host_reads()
        with (
            _settings({"ip_aliases": {"auto_bind": ClassBomb(), "ips": []}}),
            ifaces,
            order,
        ):
            resp = _client().post("/api/system/network/alias/auto/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertIn("No managed IPs configured", resp.json()["message"])

    def test_stays_immune_interval_bomb_degrades_through_coerce_int(self):
        # Already immune (the a11y-era _pick/_coerce_int guards): pinned so
        # the neighbour cannot regress while its siblings changed.
        resp = self._alias_auto({"interval": ClassBomb(), "ips": []})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["interval"], 60)

    def test_stays_immune_numeric_yaml_ips_drop_through_the_str_probe(self):
        # Already immune (the _as_text str() probe): an over-cap int ip
        # costs its own row only.
        resp = self._alias_auto({"ips": [_HUGE_INT, "192.0.2.44"]})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["config"]["ips"], ["192.0.2.44"])


class FailoverSettingsClassBombTests(unittest.TestCase):
    """GET/POST failover: the ``enabled`` bomb degrades, never 500s."""

    def test_class_bomb_enabled_keeps_the_status_read(self):
        # Fails on the pre-fix tree: _truthy's isinstance gate detonated on
        # GET /api/system/network/failover.
        with _settings({"network_failover": {"enabled": ClassBomb()}}):
            resp = _client().get("/api/system/network/failover")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertIs(resp.json()["config"]["enabled"], True)

    def test_class_bomb_enabled_keeps_the_run_tick_honest(self):
        # Same bomb on the mutation route: the tick still runs (the bomb is
        # truthy) and answers its honest no-wired-adapters 200.
        with (
            _settings({"network_failover": {"enabled": ClassBomb()}}),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            resp = _client().post("/api/system/network/failover/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["enabled"])


class RcBombLaunderingTests(unittest.TestCase):
    """A poisoned rc from a stubbed ``sh`` degrades to an exact int."""

    _SERVICES = [{
        "name": "USB LAN", "hardware_port": "USB 10/100/1000 LAN",
        "device": "en5", "disabled": False,
    }]

    def _dhcp(self, rc):
        with (
            mock.patch.object(
                network_svc, "network_services", return_value=list(self._SERVICES)
            ),
            mock.patch.object(network_svc, "sh", return_value=(rc, "", "")),
        ):
            return _client().post("/api/system/network/services/USB LAN/dhcp")

    def test_rc_eq_bomb_on_dhcp_answers_the_honest_exit(self):
        # Fails on the pre-fix tree: the first rc == 0 compare raised.
        resp = self._dhcp(RcEqBomb(1))
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit 1")

    def test_over_cap_rc_on_dhcp_degrades_instead_of_blowing_the_render(self):
        # Fails on the pre-fix tree: f"exit {rc}" hit the int->str cap.
        resp = self._dhcp(_HUGE_INT)
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit -255")

    def test_rc_eq_bomb_on_tools_net_ping_keeps_the_honest_output(self):
        # Fails on the pre-fix tree: _spawn_sentinel's rc == -1 raised.
        with mock.patch.object(
            tools_svc, "sh", return_value=(RcEqBomb(1), "out", "")
        ):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["output"], "out")

    def test_rc_eq_bomb_on_network_dns_lookup_keeps_the_honest_answer(self):
        with mock.patch.object(
            network_svc, "sh", return_value=(RcEqBomb(1), "out", "")
        ):
            resp = _client().get(
                "/api/system/network/dns-lookup", params={"host": "example.com"}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_stays_immune_spawn_sentinel_survives_the_laundering(self):
        # The a11y7 coded 503 must still fire: the exact-int sentinel rides
        # rc laundering untouched.
        def fake(argv, timeout=10, **kwargs):
            return _SENTINEL

        with (
            mock.patch.object(tools_svc, "sh", side_effect=fake),
            mock.patch.object(tools_svc, "PING", _GONE),
        ):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "tools.ping_missing")

    def test_unusable_rc_junk_never_forges_the_sentinel(self):
        # Junk degrades to -255, not -1: even with the binary off disk and
        # "not found" text, an unusable rc cannot claim the coded 503.
        with (
            mock.patch.object(
                tools_svc, "sh", return_value=(None, "", "not found")
            ),
            mock.patch.object(tools_svc, "PING", _GONE),
        ):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])


class ShOutputClassBombTests(unittest.TestCase):
    """``sh``-stub stdout bombs scrub through ``_as_text``, never 500."""

    def test_class_bomb_stdout_on_tools_net_ping_renders_scrubbed(self):
        # Fails on the pre-fix tree: _as_text's bare bytes gate detonated.
        with mock.patch.object(tools_svc, "sh", return_value=(0, ClassBomb(), "")):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertTrue(resp.json()["ok"])

    def test_class_bomb_stdout_on_network_dns_lookup_renders_scrubbed(self):
        with mock.patch.object(
            network_svc, "sh", return_value=(0, ClassBomb(), "")
        ):
            resp = _client().get(
                "/api/system/network/dns-lookup", params={"host": "example.com"}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])

    def test_lying_bytes_stdout_reads_as_empty_not_500(self):
        # Fails on the pre-fix tree: the liar passed the bytes gate and
        # TypeError'd the unbound base decode.
        with mock.patch.object(
            network_svc, "sh", return_value=(0, LyingBytes(), "")
        ):
            resp = _client().get(
                "/api/system/network/dns-lookup", params={"host": "example.com"}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["answers"], [])


class VanishedNetworksetupServicesListingTests(unittest.TestCase):
    """GET /services: the empty-listing lie becomes the coded 503."""

    def test_confirmed_absent_networksetup_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 {"services": []} — a Mac with no
        # network services, a configuration that does not exist.
        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().get("/api/system/network/services")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_empty_listing_with_the_binary_on_disk_keeps_the_honest_200(self):
        # Present-but-empty must not upgrade to 503 (the a11y4 rule).
        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            resp = _client().get("/api/system/network/services")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["services"], [])

    def test_readable_listing_never_pays_the_probe_and_stays_honest(self):
        # A listing that names services keeps the honest 200 even with the
        # binary off disk — the probe runs on the failure path only.
        rows = [{"name": "Wi-Fi", "hardware_port": "Wi-Fi", "device": "en0",
                 "disabled": False, "order": 1}]
        with (
            mock.patch.object(
                network_svc, "network_services", return_value=list(rows)
            ),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().get("/api/system/network/services")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(
            [s["name"] for s in resp.json()["services"]], ["Wi-Fi"]
        )


class InProcessValidatorBombTests(unittest.TestCase):
    """The shared validators refuse bombs instead of raising (in-process)."""

    def test_is_safe_hostname_refuses_the_class_bomb(self):
        # Fails on the pre-fix tree: _normalise's bare isinstance raised.
        self.assertFalse(cli_args.is_safe_hostname(ClassBomb()))

    def test_is_safe_hostname_refuses_the_lying_str(self):
        # Fails on the pre-fix tree: the unbound str.strip TypeError'd.
        self.assertFalse(cli_args.is_safe_hostname(LyingStr()))

    def test_valid_ip_refuses_the_class_bomb_and_the_liars(self):
        for junk in (ClassBomb(), LyingStr(), LyingBytes()):
            self.assertFalse(network_svc._valid_ip(junk), type(junk).__name__)

    def test_net_dns_lookup_refuses_the_bomb_with_the_coded_soft_fail(self):
        for junk in (ClassBomb(), LyingStr()):
            result = tools_svc.net_dns_lookup(junk)
            self.assertFalse(result["ok"], type(junk).__name__)
            self.assertEqual(result["code"], "tools.empty_name")

    def test_stays_immune_torn_ipv6_lookup_is_the_coded_refusal(self):
        # Already immune (the a11y6 lookup-target guard): a torn IPv6
        # literal is a caller mistake, never a 500.
        resp = _client().get(
            "/api/system/network/dns-lookup", params={"host": "[::1"}
        )
        self.assertEqual(resp.status_code, 400, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.invalid_hostname"
        )


if __name__ == "__main__":
    unittest.main()
