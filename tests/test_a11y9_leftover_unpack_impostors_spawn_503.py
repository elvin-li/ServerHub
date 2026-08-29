"""Ninth a11y leftover sweep: sh-answer unpack impostors and mutation-spawn lies.

a11y8 laundered the *slots* of a stubbed ``sh`` answer (rc through
``_as_rc``, out/err through ``_as_text``), but the laundering lives inside
``_sh`` — *after* the bare ``rc, out, err = sh(...)`` unpack.  Two NEW
vector families still 500'd (or lied through) the same routes:

* whole-answer impostors (the modules9/bookmarks9 class).  The unpack
  dispatches into the answer's own iteration, so a tuple/list *subclass*
  whose bound ``__iter__`` bombs — or a lying ``__class__`` claiming
  tuple/list over no real sequence storage — raised straight out of
  ``_sh`` before any slot laundering ran: raw 500s on POST dhcp/manual/
  dns/enabled/order, wifi/{state}, GET dns-lookup, POST /api/tools/net/
  ping and /net/flush-dns at once.  ``_sh_triple`` now reads the answer
  through the unbound base descriptors: an honest triple in a subclass
  wrapper survives untouched (the vanished-spawn sentinel included), and
  junk degrades to ``(-255, "", "")`` — nonzero (a poisoned answer is not
  consent to claim success) and never ``-1`` (the sentinel stays
  unforgeable).

* vanished-CLI lies on the mutation *spawns*.  a11y4–a11y8 sealed the
  listing side (an empty listing with the binary confirmed absent answers
  the coded 503), but the listings are cached for 6s, so a networksetup /
  ifconfig that vanished *after* the listing validated the name still
  reached the spawn — and POST dhcp/manual/dns/enabled/order, wifi/on and
  alias add/remove answered 200 ``{"ok": false, "message": "not found"}``,
  which reads like the configuration change failed for an unknown reason
  (alias/remove even appended "run manually: sudo ifconfig …" for a binary
  that is not there to run).  Same rule as every sibling: the disk probe
  runs on the spawn-sentinel failure path only, a present-but-failing tool
  keeps its honest answer, and the wifi/alias raises fire *before* the
  sudo fallback so nothing re-spawns over a confirmed-gone binary.

Every fixed case was reproduced live as a raw 500 (or the 200 lie) over
``create_app()`` + ``TestClient`` before fixing.  The tail pins hold the
already-immune neighbours in place: the a11y7 sentinel-503 on tools ping
still fires through the new triple laundering, and the a11y6 vanished
lookup-tools 503 rides it unchanged.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import network_svc, tools_svc
from hub.auth import require_auth

_APP = None

#: A path that exists on every host, standing in for a binary still on disk.
_ON_DISK = sys.executable
_GONE = "/nonexistent/a11y9/tool"

#: Exactly what ``hub.util.sh`` answers for a FileNotFoundError spawn.
_SENTINEL = (-1, "", "not found")


class TupleIterBomb(tuple):
    """A real tuple whose bound ``__iter__`` bombs — the unpack detonated."""

    def __iter__(self):
        raise RuntimeError("tuple iter bomb")


class ListIterBomb(list):
    """The list twin: same unpack detonation, same salvageable storage."""

    def __iter__(self):
        raise RuntimeError("list iter bomb")


class LyingTuple:
    """Claims tuple over no real sequence storage; junk, not an answer."""

    @property
    def __class__(self):
        return tuple


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


_SERVICES = [{
    "name": "USB LAN", "hardware_port": "USB 10/100/1000 LAN",
    "device": "en5", "disabled": False,
}]

_WIFI_PORTS = [{"port": "Wi-Fi", "device": "en0", "mac": ""}]

_IFACES = [{
    "name": "en0", "flags": ["UP"], "up": True, "ipv4": [], "ipv6": [],
    "mac": None, "status": "active", "media": None, "mtu": 1500,
}]


class ShAnswerUnpackImpostorTests(unittest.TestCase):
    """A poisoned whole ``sh`` answer degrades in ``_sh_triple``, never 500s."""

    def _dhcp(self, shret):
        with (
            mock.patch.object(
                network_svc, "network_services", return_value=list(_SERVICES)
            ),
            mock.patch.object(network_svc, "sh", return_value=shret),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            return _client().post("/api/system/network/services/USB LAN/dhcp")

    def test_tuple_iter_bomb_keeps_the_honest_elements_on_dhcp(self):
        # Fails on the pre-fix tree: the rc, out, err unpack dispatched into
        # the subclass __iter__ and the RuntimeError 500'd the route.  The
        # real triple sits readable in the C-level storage and survives.
        resp = self._dhcp(TupleIterBomb((1, "", "")))
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit 1")

    def test_list_iter_bomb_keeps_the_honest_elements_on_dhcp(self):
        resp = self._dhcp(ListIterBomb([0, "Switched", ""]))
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "Switched")

    def test_lying_tuple_degrades_to_the_nonzero_junk_exit(self):
        # Fails on the pre-fix tree: unpacking the non-iterable liar was
        # TypeError.  Junk is not consent to claim success: exit -255.
        resp = self._dhcp(LyingTuple())
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit -255")

    def test_wrong_arity_answer_degrades_instead_of_blowing_the_unpack(self):
        # A 2-slot answer was ValueError at the unpack — junk, same degrade.
        resp = self._dhcp((0, ""))
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["message"], "exit -255")

    def test_tuple_iter_bomb_on_tools_net_ping_keeps_the_honest_output(self):
        # Fails on the pre-fix tree: the same unpack 500'd the Tools twin.
        with (
            mock.patch.object(
                tools_svc, "sh", return_value=TupleIterBomb((0, "pong", ""))
            ),
            mock.patch.object(tools_svc, "PING", _ON_DISK),
        ):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["output"], "pong")

    def test_list_iter_bomb_on_flush_dns_degrades_instead_of_500(self):
        with (
            mock.patch.object(
                tools_svc, "sh", return_value=ListIterBomb([None, "", ""])
            ),
            mock.patch.object(tools_svc, "DSCACHEUTIL", _ON_DISK),
            mock.patch.object(tools_svc, "KILLALL", _ON_DISK),
        ):
            resp = _client().post("/api/tools/net/flush-dns")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_lying_tuple_never_forges_the_sentinel_on_tools_net_ping(self):
        # Junk degrades to -255, not -1: even with the binary off disk, an
        # unusable whole answer cannot claim the coded 503.
        with (
            mock.patch.object(tools_svc, "sh", return_value=LyingTuple()),
            mock.patch.object(tools_svc, "PING", _GONE),
        ):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_stays_immune_sentinel_in_a_subclass_wrapper_keeps_the_503(self):
        # The a11y7 coded 503 must still fire: the honest sentinel triple
        # rides the unbound base reads out of the poisoned wrapper intact.
        with (
            mock.patch.object(
                tools_svc, "sh", return_value=TupleIterBomb(_SENTINEL)
            ),
            mock.patch.object(tools_svc, "PING", _GONE),
        ):
            resp = _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "tools.ping_missing")

    def test_stays_immune_vanished_lookup_tools_503_rides_the_laundering(self):
        # The a11y6 rule is untouched: both resolvers sentinel + both
        # confirmed off disk still answers the coded 503 through _sh_triple.
        with (
            mock.patch.object(network_svc, "sh", return_value=_SENTINEL),
            mock.patch.object(network_svc, "DSCACHEUTIL", _GONE),
            mock.patch.object(network_svc, "DIG", _GONE),
        ):
            resp = _client().get(
                "/api/system/network/dns-lookup", params={"host": "example.com"}
            )
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.lookup_tools_missing"
        )


class VanishedNetworksetupMutationSpawnTests(unittest.TestCase):
    """The mutation spawn's own sentinel becomes the coded 503, not a 200 lie."""

    def _post(self, path, body=None, *, shret=_SENTINEL, ns=_GONE):
        with (
            mock.patch.object(
                network_svc, "network_services", return_value=list(_SERVICES)
            ),
            mock.patch.object(network_svc, "sh", return_value=shret),
            mock.patch.object(network_svc, "NS", ns),
        ):
            if body is None:
                return _client().post(path)
            return _client().post(path, json=body)

    def _assert_coded_503(self, resp):
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_dhcp_spawn_sentinel_with_the_binary_gone_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 {"ok": false, "message": "not
        # found"} — the configuration change blamed for a missing tool.
        self._assert_coded_503(
            self._post("/api/system/network/services/USB LAN/dhcp")
        )

    def test_manual_spawn_sentinel_is_the_coded_503(self):
        self._assert_coded_503(self._post(
            "/api/system/network/services/USB LAN/manual",
            {"ip": "192.0.2.5", "subnet": "255.255.255.0", "router": ""},
        ))

    def test_dns_spawn_sentinel_is_the_coded_503(self):
        self._assert_coded_503(self._post(
            "/api/system/network/services/USB LAN/dns",
            {"servers": ["1.1.1.1"]},
        ))

    def test_enabled_spawn_sentinel_is_the_coded_503(self):
        self._assert_coded_503(self._post(
            "/api/system/network/services/USB LAN/enabled", {"enabled": True},
        ))

    def test_order_spawn_sentinel_is_the_coded_503(self):
        self._assert_coded_503(self._post(
            "/api/system/network/order", {"services": ["USB LAN"]},
        ))

    def test_sentinel_with_the_binary_on_disk_keeps_the_honest_answer(self):
        # A genuine run whose output merely reads "not found" must not
        # upgrade: the disk confirm is what disambiguates.
        resp = self._post(
            "/api/system/network/services/USB LAN/dhcp", ns=_ON_DISK
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")

    def test_real_failure_with_the_binary_gone_never_pays_the_probe(self):
        # The probe runs on the sentinel failure path only: a real nonzero
        # exit keeps its honest answer even with the binary off disk.
        resp = self._post(
            "/api/system/network/services/USB LAN/dhcp",
            shret=(1, "", "eth cable unplugged"),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "eth cable unplugged")


class VanishedWifiAndAliasSpawnTests(unittest.TestCase):
    """wifi/alias spawn sentinels: coded 503, and no sudo re-spawn."""

    def test_wifi_spawn_sentinel_is_the_coded_503_before_the_sudo_retry(self):
        # Fails on the pre-fix tree: 200 {"ok": false, "message": "not
        # found"} after a *second* spawn under sudo over the gone binary.
        calls = []

        def fake(argv, timeout=10, **kwargs):
            calls.append(list(argv))
            return _SENTINEL

        with (
            mock.patch.object(
                network_svc, "hardware_ports", return_value=list(_WIFI_PORTS)
            ),
            mock.patch.object(network_svc, "sh", side_effect=fake),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/wifi/on")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )
        # The raise fires before the sudo fallback: exactly one spawn.
        self.assertEqual(len(calls), 1, calls)

    def test_wifi_sentinel_with_the_binary_on_disk_keeps_the_honest_answer(self):
        with (
            mock.patch.object(
                network_svc, "hardware_ports", return_value=list(_WIFI_PORTS)
            ),
            mock.patch.object(network_svc, "sh", return_value=_SENTINEL),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            resp = _client().post("/api/system/network/wifi/on")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def _alias(self, path, *, shret=_SENTINEL, ifconfig=_GONE, count_calls=None):
        def fake(argv, timeout=10, **kwargs):
            if count_calls is not None:
                count_calls.append(list(argv))
            return shret

        with (
            mock.patch.object(
                network_svc, "interfaces", return_value=list(_IFACES)
            ),
            mock.patch.object(network_svc, "sh", side_effect=fake),
            mock.patch.object(network_svc, "IFCONFIG", ifconfig),
        ):
            return _client().post(
                path, json={"device": "en0", "ip": "192.0.2.44"}
            )

    def test_alias_add_spawn_sentinel_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 ok:false "not found" — reads like
        # the alias add failed for an unknown reason.
        calls = []
        resp = self._alias(
            "/api/system/network/alias/add", count_calls=calls
        )
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.ifconfig_missing"
        )
        self.assertEqual(len(calls), 1, calls)

    def test_alias_remove_spawn_sentinel_is_the_coded_503(self):
        # Fails on the pre-fix tree: the 200 body even said "run manually:
        # sudo ifconfig …" for a binary that is not there to run.
        resp = self._alias("/api/system/network/alias/remove")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.ifconfig_missing"
        )

    def test_alias_sentinel_with_the_binary_on_disk_keeps_the_honest_answer(self):
        resp = self._alias(
            "/api/system/network/alias/add", ifconfig=_ON_DISK
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_alias_real_failure_with_the_binary_gone_stays_honest(self):
        # The probe runs on the sentinel path only: a present-but-failing
        # ifconfig (permission denied, say) keeps the honest escalation.
        resp = self._alias(
            "/api/system/network/alias/add",
            shret=(1, "", "ifconfig: permission denied"),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertIn("permission denied", payload["message"])


if __name__ == "__main__":
    unittest.main()
