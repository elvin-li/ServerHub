"""Eleventh a11y leftover sweep: field-level row bombs and hash-shadow keys.

a11y5–a11y9 sealed the *shape* seams these network/a11y helper routes carry:
the vanished-CLI 503s, the stubbed-``sh`` triple (rc/out/err laundering), the
nested settings-*value* bombs (``__class__`` / lying-type / ``__bool__``).  But
the row *readers* that walk ``interfaces()`` / ``hardware_ports()`` /
``_network_service_order_entries()`` and the settings *mappings* still trusted
individual field reads, so a NEW family of leftovers the zoo never carried blew
straight out of them into raw 500s over ``create_app()`` + ``TestClient``:

* whole-listing impostors — a list *subclass* whose bound ``__iter__`` bombs, or
  a lying ``__class__`` claiming list over no storage — detonated the loop
  header itself (``for iface in interfaces()``).  ``_rows`` reads the C-level
  storage past the override.

* row impostors — a dict *subclass* whose bound ``.get`` bombs, a lying
  ``__class__`` claiming dict over no mapping storage, or a ``__class__``
  property that raises — passed the bare ``isinstance(row, dict)`` gate (or blew
  it) and raised on the first ``row.get(...)``.  ``_isinst`` + ``_mapping_get``
  fail those closed.

* poisoned field values — a stored device/name/ip whose ``__eq__`` bombs (or is
  unhashable, or a *hash-shadowing* key with the same hash as the wanted key and
  a raising ``__eq__``), a ``__bool__``/``__str__`` bomb, a lone surrogate or an
  over-cap int — used to raise out of a ``==`` compare, a set build, a truth
  test or the JSON render.  ``_mapping_get`` (unbound ``dict.get`` in a try) +
  ``_as_text`` + ``_truthy`` degrade each field on its own.

* hash-shadowing settings keys — ``settings_section`` hands back a shallow
  ``dict(raw)`` copy, so a leftover key hashing like ``"ips"``/``"enabled"`` but
  raising ``__eq__`` survived the copy and detonated ``s.get(...)`` in
  ``_alias_settings`` / ``_failover_settings`` and the PUT write path.

Every fixed case was reproduced live as a raw 500 before the fix.  The tail
pins hold the a11y5–a11y9 neighbours in place: the vanished-CLI coded 503s and
the honest answers still ride the new laundering unchanged.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import hub.config as hub_config
from hub import network_svc
from hub.auth import require_auth

_APP = None

_ON_DISK = sys.executable
_GONE = "/nonexistent/a11y11/tool"
_SENTINEL = (-1, "", "not found")
#: An exact int past CPython's 4300-digit int->str render cap.
_HUGE_INT = 10 ** 5000
#: A lone low surrogate: valid to hold in a Python str, fatal to a strict
#: UTF-8 encode, so an un-scrubbed field 500s the Starlette JSON render.
_SURROGATE = "seg\udc80ment"


# ── leftover zoo ────────────────────────────────────────────────────────────

class ClassBomb:
    """Reading ``__class__`` raises — every bare isinstance gate detonates."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class LyingDict:
    """Claims dict over no mapping storage; the unbound ``dict.get`` refuses it."""

    @property
    def __class__(self):
        return dict


class LyingList:
    @property
    def __class__(self):
        return list


class LyingStr:
    @property
    def __class__(self):
        return str


class LyingBool:
    @property
    def __class__(self):
        return bool


class GetBombDict(dict):
    """A real dict whose bound ``.get`` bombs — the unbound builtin survives it."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class IterBombList(list):
    """A real list whose bound ``__iter__`` bombs — the unbound slice survives."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class HashShadowKey(str):
    """Hashes like a plain key but its ``__eq__`` bombs — detonates the lookup."""

    def __new__(cls, shadowed):
        # A distinct stored text so it never *is* the wanted key; only the hash
        # collides, forcing the C lookup into the raising ``__eq__``.
        return str.__new__(cls, shadowed + "\u2063shadow")

    def __init__(self, shadowed):
        self._h = hash(shadowed)

    def __hash__(self):
        return self._h

    def __eq__(self, other):
        raise RuntimeError("hash-shadow eq bomb")


class EqBombStr(str):
    def __eq__(self, other):
        raise RuntimeError("str eq bomb")

    __hash__ = str.__hash__


class BoolBombObj:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class StrBombObj:
    def __str__(self):
        raise RuntimeError("str bomb")


class StripBombStr(str):
    def strip(self, *a):
        raise RuntimeError("strip bomb")


class LowerBombStr(str):
    def lower(self):
        raise RuntimeError("lower bomb")


# ── harness ─────────────────────────────────────────────────────────────────

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


def _iface(**over) -> dict:
    row = {
        "name": "en0", "flags": ["UP"], "up": True,
        "ipv4": [{"ip": "192.0.2.10", "netmask": "255.255.255.0", "broadcast": ""}],
        "ipv6": [], "mac": None, "status": "active", "media": None, "mtu": 1500,
    }
    row.update(over)
    return row


def _order(**over) -> dict:
    row = {"order": 1, "name": "USB LAN", "disabled": False,
           "port": "USB 10/100/1000 LAN", "device": "en0"}
    row.update(over)
    return row


def _hw(**over) -> dict:
    row = {"port": "Wi-Fi", "device": "en1", "mac": ""}
    row.update(over)
    return row


_SERVICES = [{
    "name": "USB LAN", "hardware_port": "USB 10/100/1000 LAN",
    "device": "en0", "disabled": False,
}]


def _settings(overrides):
    def read(name):
        return overrides.get(name, {})

    return mock.patch.object(hub_config, "settings_section", side_effect=read)


def _world(*, ifaces=None, orders=None, hwports=None, settings=None,
           shret=(0, "", "")):
    """Patch every host seam to on-disk tools + the given leftover listings."""
    ifaces = [_iface()] if ifaces is None else ifaces
    orders = [_order()] if orders is None else orders
    hwports = [_hw()] if hwports is None else hwports
    settings = settings or {
        "ip_aliases": {"auto_bind": True, "ips": ["192.0.2.44"],
                       "netmask": "255.255.255.255", "interval": 60},
        "network_failover": {"enabled": True},
    }
    cms = [
        mock.patch.object(network_svc, "interfaces", return_value=ifaces),
        mock.patch.object(network_svc, "_network_service_order_entries",
                          return_value=orders),
        mock.patch.object(network_svc, "hardware_ports", return_value=hwports),
        mock.patch.object(network_svc, "network_services",
                          return_value=list(_SERVICES)),
        mock.patch.object(network_svc, "sh", return_value=shret),
        _settings(settings),
        mock.patch.object(network_svc, "NS", _ON_DISK),
        mock.patch.object(network_svc, "IFCONFIG", _ON_DISK),
        mock.patch.object(network_svc, "ROUTE", _ON_DISK),
        mock.patch.object(network_svc, "PING", _ON_DISK),
        mock.patch.object(network_svc, "DSCACHEUTIL", _ON_DISK),
        mock.patch.object(network_svc, "DIG", _ON_DISK),
    ]
    return cms


class _WorldMixin(unittest.TestCase):
    def _get(self, path, *, params=None, **world):
        from contextlib import ExitStack

        with ExitStack() as stack:
            for cm in _world(**world):
                stack.enter_context(cm)
            return _client().get(path, params=params)

    def _post(self, path, *, json=None, **world):
        from contextlib import ExitStack

        with ExitStack() as stack:
            for cm in _world(**world):
                stack.enter_context(cm)
            return _client().post(path, json=json)

    def _put(self, path, *, json=None, **world):
        from contextlib import ExitStack

        with ExitStack() as stack:
            for cm in _world(**world):
                stack.enter_context(cm)
            return _client().put(path, json=json)

    def _ok_json(self, resp):
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])
        # Body must already be valid UTF-8 JSON.
        return resp.json()


class AliasAutoStatusIfaceRowBombTests(_WorldMixin):
    """GET /alias/auto walks interfaces(); every row leftover degrades to 200."""

    _ROUTE = "/api/system/network/alias/auto"

    def test_class_bomb_whole_row_degrades_instead_of_500(self):
        payload = self._ok_json(self._get(self._ROUTE, ifaces=[ClassBomb()]))
        self.assertIn("config", payload)

    def test_lying_dict_row_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[LyingDict()]))

    def test_get_bomb_dict_row_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[GetBombDict(_iface())]))

    def test_iter_bomb_listing_reads_the_real_rows(self):
        self._ok_json(self._get(self._ROUTE, ifaces=IterBombList([_iface()])))

    def test_lying_list_listing_degrades_to_no_interfaces(self):
        self._ok_json(self._get(self._ROUTE, ifaces=LyingList()))

    def test_unhashable_name_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[_iface(name=[])]))

    def test_hash_shadow_name_degrades_instead_of_500(self):
        self._ok_json(
            self._get(self._ROUTE, ifaces=[_iface(name=HashShadowKey("en0"))])
        )

    def test_eq_bomb_name_degrades_instead_of_500(self):
        self._ok_json(
            self._get(self._ROUTE, ifaces=[_iface(name=EqBombStr("en0"))])
        )

    def test_bool_bomb_up_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[_iface(up=BoolBombObj())]))

    def test_lying_bool_up_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[_iface(up=LyingBool())]))

    def test_bool_bomb_status_degrades_instead_of_500(self):
        self._ok_json(
            self._get(self._ROUTE, ifaces=[_iface(status=BoolBombObj())])
        )

    def test_lying_str_status_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[_iface(status=LyingStr())]))

    def test_lower_bomb_status_degrades_instead_of_500(self):
        self._ok_json(
            self._get(self._ROUTE, ifaces=[_iface(status=LowerBombStr("active"))])
        )

    def test_surrogate_status_renders_valid_utf8(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[_iface(status=_SURROGATE)]))

    def test_iter_bomb_ipv4_degrades_instead_of_500(self):
        self._ok_json(self._get(
            self._ROUTE,
            ifaces=[_iface(ipv4=IterBombList(
                [{"ip": "192.0.2.10", "netmask": "255.255.255.0"}]))],
        ))

    def test_lying_list_ipv4_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, ifaces=[_iface(ipv4=LyingList())]))

    def test_get_bomb_ipv4_entry_degrades_instead_of_500(self):
        self._ok_json(self._get(
            self._ROUTE,
            ifaces=[_iface(ipv4=[GetBombDict(
                {"ip": "192.0.2.10", "netmask": "255.255.255.0"})])],
        ))

    def test_eq_bomb_ipv4_ip_degrades_instead_of_500(self):
        self._ok_json(self._get(
            self._ROUTE,
            ifaces=[_iface(ipv4=[{"ip": EqBombStr("192.0.2.44"),
                                  "netmask": "255.255.255.0"}])],
        ))

    def test_surrogate_ipv4_ip_renders_valid_utf8(self):
        self._ok_json(self._get(
            self._ROUTE,
            ifaces=[_iface(ipv4=[{"ip": _SURROGATE, "netmask": "255.255.255.0"}])],
        ))

    def test_over_cap_ipv4_ip_degrades_instead_of_blowing_the_render(self):
        self._ok_json(self._get(
            self._ROUTE,
            ifaces=[_iface(ipv4=[{"ip": _HUGE_INT, "netmask": "255.255.255.0"}])],
        ))

    def test_str_bomb_netmask_degrades_instead_of_500(self):
        self._ok_json(self._get(
            self._ROUTE,
            ifaces=[_iface(ipv4=[{"ip": "192.0.2.10", "netmask": StrBombObj()}])],
        ))

    def test_run_route_also_degrades_on_the_row_bombs(self):
        # The mutation twin reads the same collector.
        resp = self._post("/api/system/network/alias/auto/run", ifaces=[ClassBomb()])
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])


class AliasAutoStatusOrderRowBombTests(_WorldMixin):
    """GET /alias/auto also walks the service order; the same leftovers degrade."""

    _ROUTE = "/api/system/network/alias/auto"

    def test_class_bomb_order_row_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[ClassBomb()]))

    def test_lying_dict_order_row_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[LyingDict()]))

    def test_get_bomb_order_row_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[GetBombDict(_order())]))

    def test_bool_bomb_disabled_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[_order(disabled=BoolBombObj())]))

    def test_lying_str_device_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[_order(device=LyingStr())]))

    def test_strip_bomb_device_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[_order(device=StripBombStr("en0"))]))

    def test_surrogate_order_name_renders_valid_utf8(self):
        self._ok_json(self._get(self._ROUTE, orders=[_order(name=_SURROGATE)]))

    def test_over_cap_order_name_degrades_instead_of_500(self):
        self._ok_json(self._get(self._ROUTE, orders=[_order(name=_HUGE_INT)]))

    def test_iter_bomb_order_listing_reads_the_real_rows(self):
        self._ok_json(self._get(self._ROUTE, orders=IterBombList([_order()])))


class AliasSettingsHashShadowKeyTests(_WorldMixin):
    """A hash-shadowing settings key can no longer 500 the alias routes."""

    def test_status_read_survives_a_shadow_ips_key(self):
        section = {HashShadowKey("ips"): 1, "auto_bind": True}
        payload = self._ok_json(self._get(
            "/api/system/network/alias/auto",
            settings={"ip_aliases": section, "network_failover": {}},
        ))
        # The shadow key is unreadable, so the config degrades to no managed IPs.
        self.assertEqual(payload["config"]["ips"], [])

    def test_run_route_survives_a_shadow_ips_key(self):
        section = {HashShadowKey("ips"): 1, "auto_bind": True}
        resp = self._post(
            "/api/system/network/alias/auto/run",
            settings={"ip_aliases": section, "network_failover": {}},
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])
        self.assertIn("No managed IPs configured", resp.json()["message"])

    def test_put_write_path_survives_a_shadow_ips_key(self):
        section = {HashShadowKey("ips"): 1, "auto_bind": True,
                   "netmask": "255.255.255.255"}
        with mock.patch.object(hub_config, "update_settings",
                               return_value={}) as saved:
            resp = self._put(
                "/api/system/network/alias/auto",
                json={"interval": 90},
                settings={"ip_aliases": section, "network_failover": {}},
            )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])
        # The patch we tried to write carries only the laundered known keys —
        # never the raising shadow key.
        (patch,), _ = saved.call_args
        for key in patch.get("ip_aliases", {}):
            self.assertIsInstance(key, str)
            self.assertNotIsInstance(key, HashShadowKey)


class FailoverHardwarePortBombTests(_WorldMixin):
    """GET/POST failover walk hardware_ports() + read the failover section."""

    def test_class_bomb_hw_row_keeps_the_run_honest(self):
        resp = self._post("/api/system/network/failover/run", hwports=[ClassBomb()])
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_lying_dict_hw_row_keeps_the_run_honest(self):
        resp = self._post("/api/system/network/failover/run", hwports=[LyingDict()])
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_get_bomb_hw_row_keeps_the_run_honest(self):
        resp = self._post(
            "/api/system/network/failover/run", hwports=[GetBombDict(_hw())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_bool_bomb_hw_port_keeps_the_run_honest(self):
        resp = self._post(
            "/api/system/network/failover/run", hwports=[_hw(port=BoolBombObj())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_str_bomb_hw_port_keeps_the_run_honest(self):
        resp = self._post(
            "/api/system/network/failover/run", hwports=[_hw(port=StrBombObj())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_lying_str_hw_port_keeps_the_run_honest(self):
        resp = self._post(
            "/api/system/network/failover/run", hwports=[_hw(port=LyingStr())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_surrogate_hw_device_renders_valid_utf8(self):
        resp = self._post(
            "/api/system/network/failover/run", hwports=[_hw(device=_SURROGATE)]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_iter_bomb_hw_listing_keeps_the_run_honest(self):
        resp = self._post(
            "/api/system/network/failover/run", hwports=IterBombList([_hw()])
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_status_read_survives_a_shadow_enabled_key(self):
        section = {HashShadowKey("enabled"): 1}
        payload = self._ok_json(self._get(
            "/api/system/network/failover",
            settings={"ip_aliases": {}, "network_failover": section},
        ))
        # Unreadable enabled degrades to disabled default (False).
        self.assertIs(payload["config"]["enabled"], False)


class WifiHardwarePortBombTests(_WorldMixin):
    """POST /wifi/{state} discovers the radio through hardware_ports()."""

    def test_class_bomb_hw_row_degrades_instead_of_500(self):
        resp = self._post("/api/system/network/wifi/on", hwports=[ClassBomb()])
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_get_bomb_hw_row_degrades_instead_of_500(self):
        resp = self._post(
            "/api/system/network/wifi/on", hwports=[GetBombDict(_hw())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_bool_bomb_hw_device_degrades_instead_of_500(self):
        resp = self._post(
            "/api/system/network/wifi/on", hwports=[_hw(device=BoolBombObj())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_lying_str_hw_port_degrades_instead_of_500(self):
        resp = self._post(
            "/api/system/network/wifi/on", hwports=[_hw(port=LyingStr())]
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])

    def test_iter_bomb_hw_listing_degrades_instead_of_500(self):
        resp = self._post(
            "/api/system/network/wifi/on", hwports=IterBombList([_hw()])
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])


class AliasMutationDeviceValidateTests(_WorldMixin):
    """POST alias/add|remove validate the device against interfaces()."""

    _BODY = {"device": "en0", "ip": "192.0.2.44"}

    def _add(self, **world):
        return self._post(
            "/api/system/network/alias/add", json=self._BODY, **world
        )

    def test_class_bomb_row_is_a_clean_4xx_not_a_500(self):
        resp = self._add(ifaces=[ClassBomb()])
        self.assertLess(resp.status_code, 500, _strict(resp)[:400])

    def test_non_dict_row_is_a_clean_4xx_not_a_500(self):
        resp = self._add(ifaces=[42])
        self.assertLess(resp.status_code, 500, _strict(resp)[:400])

    def test_row_missing_name_is_a_clean_4xx_not_a_500(self):
        resp = self._add(ifaces=[{"up": True}])
        self.assertLess(resp.status_code, 500, _strict(resp)[:400])

    def test_unhashable_name_is_a_clean_4xx_not_a_500(self):
        resp = self._add(ifaces=[_iface(name=[])])
        self.assertLess(resp.status_code, 500, _strict(resp)[:400])

    def test_hash_shadow_name_is_a_clean_4xx_not_a_500(self):
        resp = self._add(ifaces=[_iface(name=HashShadowKey("en0"))])
        self.assertLess(resp.status_code, 500, _strict(resp)[:400])

    def test_iter_bomb_listing_is_a_clean_4xx_not_a_500(self):
        resp = self._add(ifaces=IterBombList([_iface()]))
        self.assertLess(resp.status_code, 500, _strict(resp)[:400])

    def test_honest_listing_still_adds_the_alias(self):
        # The device really is present, so the mutation runs and answers 200.
        resp = self._add()
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])


class StaysImmuneTests(_WorldMixin):
    """The a11y5–a11y9 neighbours ride the new laundering unchanged."""

    def test_vanished_ifconfig_alias_add_is_still_the_coded_503(self):
        with (
            mock.patch.object(network_svc, "interfaces", return_value=[_iface()]),
            mock.patch.object(network_svc, "sh", return_value=_SENTINEL),
            mock.patch.object(network_svc, "IFCONFIG", _GONE),
        ):
            resp = _client().post(
                "/api/system/network/alias/add",
                json={"device": "en0", "ip": "192.0.2.44"},
            )
        self.assertEqual(resp.status_code, 503, _strict(resp)[:400])
        self.assertEqual(resp.json()["detail"]["code"], "network.ifconfig_missing")

    def test_vanished_networksetup_wifi_is_still_the_coded_503(self):
        with (
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/wifi/on")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:400])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_vanished_lookup_tools_dns_lookup_is_still_the_coded_503(self):
        with (
            mock.patch.object(network_svc, "sh", return_value=_SENTINEL),
            mock.patch.object(network_svc, "DSCACHEUTIL", _GONE),
            mock.patch.object(network_svc, "DIG", _GONE),
        ):
            resp = _client().get(
                "/api/system/network/dns-lookup", params={"host": "example.com"}
            )
        self.assertEqual(resp.status_code, 503, _strict(resp)[:400])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.lookup_tools_missing"
        )

    def test_honest_wifi_answer_still_rides_through(self):
        with (
            mock.patch.object(
                network_svc, "hardware_ports",
                return_value=[{"port": "Wi-Fi", "device": "en1", "mac": ""}],
            ),
            mock.patch.object(network_svc, "sh", return_value=(0, "", "")),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            resp = _client().post("/api/system/network/wifi/on")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:400])


if __name__ == "__main__":
    unittest.main()
