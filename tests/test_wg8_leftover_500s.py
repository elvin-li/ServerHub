"""WireGuard leftover-500 sweep #8: shape bombs on the listing/settings seams.

All reproduced over ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` before the fixes; each answered ``500 Internal Server Error`` with a
traceback, never a coded JSON body.  Wave wg7 sealed the ``_as_text`` /
``_plain_int`` value bombs; these are the *container*-shape leftovers on the
same routes.

The live leftovers
==================
* **The parsed conf's blocks were trusted to be exact.**  :func:`status`,
  :func:`used_addresses`, :func:`server_identity` and :func:`_identify` ran
  bound ``.get`` / bare iteration on ``read_conf()``'s ``interface`` block
  and ``peers`` list.  A dict-subclass block with a bombing ``.get``, a
  list-subclass ``peers`` whose ``__iter__`` raises, or a dict-subclass row
  was a raw 500 out of GET /api/wireguard, GET /api/wireguard/readiness and
  GET /api/wireguard/next-ip.  Now laundered through ``_conf_interface`` /
  ``_conf_peers`` (unbound ``dict.get`` / ``list.__iter__``, ``dict(...)``
  copies), so junk costs only the value it sits in.
* **``status()`` indexed peer rows bare.**  ``record["keepalive"]`` on a
  partial row from a patched provider KeyError'd the poll, and the
  ``stats.get(...) or record[...]`` chains reflected into a stored value's
  ``__bool__``.  The walk now guards the provider (the ``_ping_targets``
  rule), launders rows, and probes truthiness through ``_truthy``.
* **``peer_origin_conflict`` iterated the listing bound.**  The old
  comprehension detonated a list-subclass ``__iter__`` bomb and a row's
  bound ``.get`` — one junk row 500'd the whole readiness page.
* **``settings()`` called the section's bound ``.items``.**  A dict-subclass
  section with a bombing ``.items`` 500'd every WireGuard read at once.
* **``wstunnel.status()`` trusted the ``live()`` snapshot.**  A dict-subclass
  snapshot's bound ``.get`` raised out of GET /api/wireguard, /settings and
  /readiness; and ``_int_or_zero`` reflected into ``value or 0`` (a
  ``__bool__`` bomb) while passing a >4300-digit already-int ``pid`` straight
  to Starlette's ``json.dumps``, whose int->str digit cap ValueError'd one
  layer later.
* **``_conf_int`` probed the raw value first.**  ``raw not in (None, "")``
  ran a *reflected* ``__eq__`` and the bare ``int(...)`` dispatched into a
  numeric subclass — either bomb raised past the arithmetic-trio except.

What stays pinned besides the fixes
===================================
* ``listener_row`` keeps refusing a torn-IPv6 listen URL (``ValueError`` out
  of urlsplit) instead of raising, and launders a dict-subclass snapshot.
* No new error codes: everything degrades to defaults, so no locale keys.
* health8's ping surfaces (``ping_peers`` / ``_ping_deadline`` /
  ``_ping_targets`` and the ``wg.ping_missing`` 503) are untouched.
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_net_svc, wireguard_svc, wireguard_wstunnel  # noqa: E402

PUB = "A" * 42 + "b="

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class GetBombDict(dict):
    """Bound ``.get`` raises; ``dict(...)`` still copies the real storage."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class EqBomb:
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = None


class IntBomb(int):
    def __int__(self):
        raise RuntimeError("int bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class ConfIntUnitTests(unittest.TestCase):
    def test_reflected_eq_bomb_keeps_the_fallback(self):
        # The old ``raw not in (None, "")`` blank probe invoked the stored
        # value's reflected __eq__ before any coercion ran.
        self.assertEqual(wireguard_svc._conf_int(EqBomb(), 51820), 51820)

    def test_over_cap_already_int_keeps_the_fallback(self):
        # int->str is capped at 4300 digits; json.dumps enforces the same cap,
        # so the huge value must never survive to the response body.
        self.assertEqual(wireguard_svc._conf_int(10 ** 5000, 25), 25)

    def test_plain_values_still_convert(self):
        self.assertEqual(wireguard_svc._conf_int("51820", 0), 51820)
        self.assertEqual(wireguard_svc._conf_int("", 25), 25)
        self.assertEqual(wireguard_svc._conf_int(None, 25), 25)
        self.assertEqual(wireguard_svc._conf_int(0, 25), 0)


class IntOrZeroUnitTests(unittest.TestCase):
    def test_bool_bomb_answers_zero(self):
        # ``int(value or 0)`` reflected into the leftover's own __bool__.
        self.assertEqual(wireguard_wstunnel._int_or_zero(BoolBomb()), 0)

    def test_int_bomb_subclass_recovers_the_exact_value(self):
        self.assertEqual(wireguard_wstunnel._int_or_zero(IntBomb(8444)), 8444)

    def test_over_cap_already_int_answers_zero(self):
        self.assertEqual(wireguard_wstunnel._int_or_zero(10 ** 5000), 0)

    def test_plain_values_still_convert(self):
        self.assertEqual(wireguard_wstunnel._int_or_zero("8444"), 8444)
        self.assertEqual(wireguard_wstunnel._int_or_zero(None), 0)
        self.assertEqual(wireguard_wstunnel._int_or_zero(1.0), 1)


class ListenerRowUnitTests(unittest.TestCase):
    def test_torn_ipv6_listen_url_answers_none_not_raise(self):
        # urlsplit raises ValueError("Invalid IPv6 URL") on the unbalanced
        # bracket; the row builder must absorb it.
        row = wireguard_wstunnel.listener_row({"listen": "ws://[::1:8444", "pid": 1})
        self.assertIsNone(row)

    def test_getbomb_snapshot_still_builds_the_row(self):
        row = wireguard_wstunnel.listener_row(
            GetBombDict({"listen": "ws://0.0.0.0:8444", "pid": 12})
        )
        self.assertEqual(row["port"], "8444")
        self.assertEqual(row["pid"], 12)

    def test_over_cap_pid_reads_as_absent(self):
        row = wireguard_wstunnel.listener_row(
            {"listen": "ws://0.0.0.0:8444", "pid": 10 ** 5000}
        )
        self.assertEqual(row["pid"], "")
        _no_surrogates(row)


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    READS = (
        "/api/wireguard",
        "/api/wireguard/settings",
        "/api/wireguard/readiness",
        "/api/wireguard/next-ip",
    )

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth
        from hub.routers import wireguard_api

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation", lambda: dict(INSTALL)
        ))

    def get_ok(self, path):
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        return body


class ParsedConfShapeBombTests(_MountedRouteTests):
    """A junk parsed-conf shape costs only its value, never the page."""

    def _with_conf(self, parsed):
        return mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: parsed
        )

    def test_getbomb_interface_block_keeps_every_read_200(self):
        # The live leftover: status/used_addresses ran the block's bound
        # ``.get`` — a raw 500 on GET /api/wireguard, /readiness, /next-ip.
        with self._with_conf({"interface": GetBombDict({"Address": "10.9.0.1/24"}),
                              "peers": []}):
            for path in self.READS:
                self.get_ok(path)

    def test_bool_bomb_address_keeps_every_read_200(self):
        # ``iface.get("Address") or ""`` reflected into the stored value's
        # own __bool__ before _as_text ever saw it.
        with self._with_conf({"interface": {"Address": BoolBomb()}, "peers": []}):
            for path in self.READS:
                self.get_ok(path)

    def test_eq_bomb_mtu_keeps_status_200_with_the_default(self):
        # _conf_int's old blank probe ran the reflected __eq__.  The stored
        # section is pinned empty so the expected fallback is the default
        # regardless of what earlier tests left in services.yaml.
        with self._with_conf({"interface": {"MTU": EqBomb()}, "peers": []}), \
                mock.patch.object(wireguard_svc, "settings_section", lambda name: {}):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["mtu"], wireguard_svc.DEFAULTS["mtu"])

    def test_iterbomb_peers_list_keeps_every_read_200(self):
        with self._with_conf({"interface": {}, "peers": IterBombList()}):
            for path in self.READS:
                self.get_ok(path)

    def test_getbomb_peer_row_keeps_every_read_200(self):
        with self._with_conf({"interface": {},
                              "peers": [GetBombDict({"PublicKey": PUB})]}):
            for path in self.READS:
                self.get_ok(path)

    def test_plain_conf_still_reads_through_the_launder(self):
        # The laundering must not cost real values: the address, the peer and
        # its AllowedIPs all survive.
        with self._with_conf({
            "interface": {"Address": "10.9.0.1/24", "ListenPort": "51825"},
            "peers": [{"PublicKey": PUB, "AllowedIPs": "10.9.0.2/32"}],
        }):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["address"], "10.9.0.1/24")
        self.assertEqual(body["listen_port"], 51825)
        self.assertEqual(body["peer_count"], 1)
        self.assertEqual(body["peers"][0]["allowed_ips"], "10.9.0.2/32")


class PeerListingBombTests(_MountedRouteTests):
    """The status walk and readiness probe do not own ``peer_records``."""

    def _with_records(self, records):
        return mock.patch.object(wireguard_svc, "peer_records", lambda: records)

    def test_iterbomb_listing_keeps_status_and_readiness_200(self):
        with self._with_records(IterBombList()):
            self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/readiness")

    def test_getbomb_partial_row_keeps_status_and_readiness_200(self):
        # Bound ``.get`` bombs *and* the bare ``record["keepalive"]`` KeyError
        # on a partial row both used to 500 the poll.
        row = GetBombDict({"public_key": PUB, "ip": "10.9.0.2/32"})
        with self._with_records([row]):
            body = self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/readiness")
        self.assertEqual(body["peer_count"], 1)
        self.assertEqual(body["peers"][0]["pubkey"], PUB)

    def test_bool_bomb_row_values_keep_status_200(self):
        row = {
            "public_key": PUB, "ip": "10.9.0.2/32", "preshared_key": BoolBomb(),
            "keepalive": BoolBomb(), "name": "n", "mode": "split",
            "created": 0, "reissuable": BoolBomb(), "known": BoolBomb(),
        }
        with self._with_records([row]):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peers"][0]["psk"], False)
        self.assertEqual(body["peers"][0]["keepalive"], "off")

    def test_raising_listing_keeps_readiness_200(self):
        def boom():
            raise RuntimeError("listing bomb")

        with mock.patch.object(wireguard_svc, "peer_records", boom):
            self.get_ok("/api/wireguard")
            body = self.get_ok("/api/wireguard/readiness")
        self.assertEqual(body["peer_origin"]["reason"], "no_peers")

    def test_real_foreign_rows_still_flag_the_conflict(self):
        # The laundering must not blunt the copied-from-another-server check.
        rows = [{
            "public_key": PUB, "ip": "10.9.0.2/32", "preshared_key": "",
            "keepalive": "", "name": "", "mode": "", "created": 0,
            "reissuable": False, "known": False,
        }]
        with self._with_records(rows):
            body = self.get_ok("/api/wireguard/readiness")
        self.assertTrue(body["peer_origin"]["conflict"])
        self.assertEqual(body["peer_origin"]["foreign"], 1)


class StoredSectionShapeBombTests(_MountedRouteTests):
    def test_items_bomb_section_keeps_every_read_200(self):
        # settings() ran the section's *bound* .items; one subclass leftover
        # 500'd all four WireGuard reads at once.
        section = ItemsBombDict({"listen_port": 51825})
        with mock.patch.object(
            wireguard_svc, "settings_section", lambda name: section
        ):
            for path in self.READS:
                self.get_ok(path)
            body = self.get_ok("/api/wireguard/settings")
        # dict.items reads the C-level storage, so the real value survives.
        self.assertEqual(body["settings"]["listen_port"], 51825)


class WstunnelSnapshotBombTests(_MountedRouteTests):
    def _with_live(self, snapshot):
        return mock.patch.object(
            wireguard_wstunnel, "live", lambda ps_text=None: snapshot
        )

    def test_getbomb_snapshot_keeps_status_and_settings_200(self):
        snap = GetBombDict({
            "listen": "ws://0.0.0.0:8444", "restrict_to": "127.0.0.1:51820",
            "pid": 12, "running": True, "binary": "", "plist": "",
        })
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/settings")
            self.get_ok("/api/wireguard/readiness")
        # dict(...) copies the storage: the live listen survives the launder.
        self.assertEqual(body["wstunnel"]["listen"], "ws://0.0.0.0:8444")
        self.assertEqual(body["wstunnel"]["pid"], 12)

    def test_over_cap_pid_keeps_status_200_and_reads_zero(self):
        # A >4300-digit already-int pid used to ValueError json.dumps itself.
        snap = {"listen": "", "restrict_to": "", "pid": 10 ** 5000,
                "running": True, "binary": "", "plist": ""}
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/settings")
        self.assertEqual(body["wstunnel"]["pid"], 0)

    def test_raising_live_keeps_status_200(self):
        def boom(ps_text=None):
            raise RuntimeError("live bomb")

        with self._with_live(None), mock.patch.object(
            wireguard_wstunnel, "live", boom
        ):
            self.get_ok("/api/wireguard")


if __name__ == "__main__":
    unittest.main()
