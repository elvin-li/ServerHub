"""WireGuard leftover-500 sweep #10: lying ``__class__`` impostors, rc bombs.

wg9 sealed the raising-``__class__``-*property* zoo (the gate itself
detonates) and health10 taught ``wireguard_svc._as_text`` / ``_ping_targets``
to survive the sibling class: a *lying* impostor whose ``__class__`` property
*returns* a claimed builtin type (bool/str/bytes/dict/list/tuple) while the
real object is a plain object.  Such a liar passes every ``_isa`` /
``isinstance`` gate and then detonates the unbound base descriptor the gate
was guarding (``bytes.decode`` / ``str.encode`` / ``dict.get`` /
``dict.items`` / ``tuple.__iter__`` / bare ``int()``), because the C-level
call checks the real type and refuses the impostor with TypeError.

Re-running the brew10/json9 zoo over the WireGuard surfaces (real
``create_app()`` + ``TestClient(raise_server_exceptions=False)``) surfaced
these as raw 500s before the fixes:

* **The stored-section merge.**  ``settings()``'s ``dict.items(stored)`` ran
  bare after the ``_isa`` gate, so a dict-liar section 500'd GET
  /api/wireguard and GET /api/wireguard/settings.  A *bool-liar* value rode
  the old ``_isa(value, bool)`` gate into ``merged`` as itself and 500'd
  Starlette's encoder; a bool-liar ``listen_port`` detonated
  ``_plain_int``'s bare ``int(value)`` bool arm.  Bool gates are identity
  now (bool cannot be subclassed, so a real flag is one of the two
  singletons); the section walk and ``_plain_int`` degrade liars.
* **The parsed-conf launders.**  ``_conf_interface`` / ``_conf_peers`` ran
  ``dict.get(parsed, ...)`` bare after ``_isa``, so a dict-liar out of a
  patched ``read_conf`` 500'd GET /api/wireguard; ``_plain_rows`` ran
  ``tuple.__iter__`` bare, so a tuple-liar peers value 500'd GET
  /api/wireguard/next-ip and /export.  Liars now fall through to the
  generic guarded ``iter()`` probe (the health10 rule).
* **The ping row walk.**  ``_ping_targets`` gated rows with ``_isa`` but
  then ran ``dict.get(record, "ip")`` bare — a dict-liar row 500'd POST
  /api/wireguard/ping where every other junk row drops alone.  Rows are
  laundered to exact dicts, so ``ping_peers``'s result build is safe too.
* **The wstunnel scalar launder.**  ``wireguard_wstunnel._as_text`` ran the
  unbound ``bytes.decode`` / ``str.encode`` bare (the pre-health10 shape),
  so one bytes- or str-liar snapshot value 500'd GET /api/wireguard and GET
  /api/wireguard/settings out of the very launder that exists to absorb
  junk.  ``status()``'s bare ``dict(settings)`` copy, the stored-side
  ``cfg.get(...) or default`` ``__bool__`` probes and ``listener_row``'s
  bare ``dict.get`` had the same shape.
* **The mutation rc probes.**  The read path laundered exits through
  ``_ping_rc`` (wg9), but ``generate_keypair`` / ``generate_psk`` /
  ``_cli_missing`` / ``apply_live`` / ``interface_action`` still compared
  bare — an rc-subclass ``__eq__`` bomb from a patched/odd ``sh`` 500'd
  POST /api/wireguard/peers, /sync and /interface.  ``int.__index__``
  salvages a bombed honest 0, so a healthy sync still answers applied.
* **The PUT seam.**  ``save_settings`` probed the config root with bare
  ``isinstance`` + ``dict.get``, so a liar root 500'd PUT
  /api/wireguard/settings after validation had already passed.

Conflict pins kept from earlier sweeps: the ``wg.ping_missing`` disk-confirmed
503 fires through the union of guards; a liar *listing* on the peers walk
already degraded (health10) and stays row-level; the wstunnel dict-liar
snapshot already read as empty (wg8's guarded ``dict(found)``).  No new error
codes: everything degrades to defaults, so no locale keys.
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

from hub import wireguard_svc, wireguard_wstunnel  # noqa: E402

PUB = "A" * 42 + "b="
PRIV = "B" * 42 + "c="

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}

#: sh()'s exact FileNotFoundError sentinel for a vanished binary.
_VANISHED = (-1, "", "not found")


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _liar(claimed):
    """A lying impostor: ``isinstance`` answers *claimed*, the object is not one."""

    class _Liar:
        @property
        def __class__(self):
            return claimed

    return _Liar()


class EqBombInt(int):
    """An rc whose comparison raises — ``rc == 0`` / ``rc != 0`` detonate."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class LaunderUnitTests(unittest.TestCase):
    """The scalar/shape launders survive the liar members themselves."""

    def test_svc_as_text_liars_stay_absorbed(self):
        # Pin (health10): the unbound decode/encode already ran inside a try.
        for claim in (bytes, bytearray, str):
            self.assertIsInstance(wireguard_svc._as_text(_liar(claim)), str)

    def test_wstunnel_as_text_liars_answer_a_str(self):
        # The live leftover: the unbound descriptors ran bare here.
        for claim in (bytes, bytearray, str):
            self.assertIsInstance(wireguard_wstunnel._as_text(_liar(claim)), str)

    def test_plain_int_bool_liar_answers_none_real_bools_stay_exact(self):
        self.assertIsNone(wireguard_svc._plain_int(_liar(bool)))
        self.assertEqual(wireguard_svc._plain_int(True), 1)
        self.assertEqual(wireguard_svc._plain_int(False), 0)

    def test_plain_rows_tuple_liar_answers_empty(self):
        self.assertEqual(wireguard_svc._plain_rows(_liar(tuple)), [])
        self.assertEqual(wireguard_svc._plain_rows(_liar(list)), [])

    def test_plain_rows_dict_liar_row_drops_alone(self):
        rows = wireguard_svc._plain_rows([_liar(dict), {"PublicKey": PUB}])
        self.assertEqual(rows, [{"PublicKey": PUB}])

    def test_plain_mapping_get_liar_answers_none(self):
        self.assertIsNone(wireguard_svc._plain_mapping_get(_liar(dict), "k"))
        self.assertEqual(wireguard_svc._plain_mapping_get({"k": 1}, "k"), 1)

    def test_conf_interface_and_peers_dict_liar_answer_empty(self):
        self.assertEqual(wireguard_svc._conf_interface(_liar(dict)), {})
        self.assertEqual(wireguard_svc._conf_peers(_liar(dict)), [])

    def test_cli_missing_rc_bomb_reads_as_not_the_sentinel(self):
        # A bomb that cannot answer must keep the keygen_failed shape, never
        # upgrade to the tool-absent 503.
        self.assertFalse(wireguard_svc._cli_missing(_liar(int), "not found"))

    def test_cli_missing_bombed_honest_sentinel_still_confirms_on_disk(self):
        # int.__index__ salvages the honest -1; the disk probe still gates.
        with mock.patch.object(wireguard_svc, "_path_exists", lambda p: False):
            self.assertTrue(wireguard_svc._cli_missing(EqBombInt(-1), "not found"))
        with mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            self.assertFalse(wireguard_svc._cli_missing(EqBombInt(-1), "not found"))

    def test_generate_keypair_rc_bomb_raises_the_typed_error(self):
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(2), "", "")
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.keygen_failed")

    def test_generate_keypair_bombed_rc_zero_is_salvaged(self):
        # A bombed honest 0 must not degrade a working keygen into a failure.
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(0), PRIV, "")
        ), mock.patch.object(
            wireguard_svc, "_run_with_input", lambda argv, data, **k: PUB
        ):
            self.assertEqual(wireguard_svc.generate_keypair(), (PRIV, PUB))

    def test_generate_psk_rc_bomb_raises_the_typed_error(self):
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(1), "", "")
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_psk()
        self.assertEqual(ctx.exception.code, "wg.keygen_failed")


class WstunnelLiarUnitTests(unittest.TestCase):
    def test_status_dict_liar_settings_answers_defaults(self):
        # The bare ``dict(settings)`` copy raised TypeError on the liar.
        snapshot = wireguard_wstunnel.status(_liar(dict))
        self.assertFalse(snapshot["enabled"])
        self.assertEqual(snapshot["desired_listen"], wireguard_wstunnel.DEFAULT_LISTEN)
        _no_surrogates(snapshot)

    def test_status_bool_bomb_stored_values_stay_absorbed(self):
        # The stored-side ``cfg.get(...) or default`` probes ran the value's
        # own __bool__ before the launder could absorb it.
        snapshot = wireguard_wstunnel.status({
            "listen_port": BoolBomb(),
            "wstunnel_listen": BoolBomb(),
            "wstunnel_restrict_to": BoolBomb(),
            "wstunnel_public": BoolBomb(),
            "endpoint": BoolBomb(),
        })
        self.assertIsInstance(snapshot, dict)
        _no_surrogates(snapshot)

    def test_listener_row_dict_liar_answers_none(self):
        self.assertIsNone(wireguard_wstunnel.listener_row(_liar(dict)))

    def test_listener_row_plain_snapshot_still_builds_the_row(self):
        row = wireguard_wstunnel.listener_row(
            {"listen": "ws://0.0.0.0:8444", "port": 8444, "pid": 12}
        )
        self.assertEqual(row["port"], "8444")
        self.assertEqual(row["pid"], 12)


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    READS = ("/api/wireguard", "/api/wireguard/settings")

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


class StoredSectionLiarTests(_MountedRouteTests):
    """settings() survives a section (or value) that lies about its type."""

    def _with_section(self, section):
        return mock.patch.object(
            wireguard_svc, "settings_section", lambda name: section
        )

    def test_dict_liar_section_keeps_every_read_200_with_defaults(self):
        # The live leftover: dict.items(liar) raised TypeError past the gate.
        with self._with_section(_liar(dict)):
            for path in self.READS:
                self.get_ok(path)
            body = self.get_ok("/api/wireguard/settings")
        self.assertEqual(
            body["settings"]["listen_port"], wireguard_svc.DEFAULTS["listen_port"]
        )

    def test_bool_liar_flag_value_keeps_the_default_not_the_object(self):
        # The liar rode the old _isa(value, bool) gate into the payload and
        # 500'd Starlette's encoder.
        with self._with_section({"wstunnel_enabled": _liar(bool), "mtu": 1400}):
            body = self.get_ok("/api/wireguard/settings")
        self.assertIs(body["settings"]["wstunnel_enabled"], False)
        self.assertEqual(body["settings"]["mtu"], 1400)

    def test_real_stored_false_still_survives_the_identity_gate(self):
        # False is a real stored value for wstunnel_enabled; the tighter
        # gate must not blunt it (and True must stay True).
        with self._with_section({"wstunnel_enabled": False}):
            self.assertIs(
                self.get_ok("/api/wireguard/settings")["settings"]["wstunnel_enabled"],
                False,
            )
        with self._with_section({"wstunnel_enabled": True}):
            self.assertIs(
                self.get_ok("/api/wireguard/settings")["settings"]["wstunnel_enabled"],
                True,
            )

    def test_bool_liar_listen_port_keeps_the_default(self):
        # _plain_int's bare int(value) bool arm dispatched into the liar.
        with self._with_section({"listen_port": _liar(bool), "mtu": 1400}):
            body = self.get_ok("/api/wireguard/settings")
            self.get_ok("/api/wireguard")
        self.assertEqual(
            body["settings"]["listen_port"], wireguard_svc.DEFAULTS["listen_port"]
        )
        self.assertEqual(body["settings"]["mtu"], 1400)


class ParsedConfLiarTests(_MountedRouteTests):
    def _with_conf(self, parsed):
        return mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: parsed
        )

    def test_dict_liar_parsed_conf_keeps_status_200(self):
        # _conf_interface's bare dict.get(liar) raised TypeError.
        with self._with_conf(_liar(dict)):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peer_count"], 0)

    def test_tuple_liar_peers_keeps_next_ip_and_export_200(self):
        # _plain_rows' bare tuple.__iter__ detonated outside status()'s
        # provider try — used_addresses and export_all walk the conf bare.
        conf = {"interface": {}, "peers": _liar(tuple)}
        with self._with_conf(conf):
            body = self.get_ok("/api/wireguard/next-ip")
            export = self.get_ok("/api/wireguard/export")
        self.assertEqual(body["used"], 0)
        self.assertEqual(export["items"], [])

    def test_list_liar_peers_stays_immune(self):
        # Pin: the list arm already ran inside a try; the restructure must
        # keep the liar degrading to an empty listing.
        with self._with_conf({"interface": {}, "peers": _liar(list)}):
            body = self.get_ok("/api/wireguard/next-ip")
        self.assertEqual(body["used"], 0)


class PingRowLiarTests(_MountedRouteTests):
    def _ping(self, records, sh_answer=(0, "", "")):
        with mock.patch.object(
            wireguard_svc, "peer_records", lambda: records
        ), mock.patch.object(wireguard_svc, "sh", lambda *a, **k: sh_answer):
            return self.client.post("/api/wireguard/ping")

    CLEAN = {"public_key": PUB, "ip": "10.9.0.2/32", "name": "phone"}

    def test_dict_liar_row_drops_alone(self):
        # _ping_targets' bare dict.get(record, "ip") raised TypeError.
        resp = self._ping([_liar(dict), dict(self.CLEAN)])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["results"][0]["pubkey"], PUB)

    def test_vanished_cli_503_still_fires_through_the_liar_guard(self):
        # Pin: the disk-confirmed wg.ping_missing 503 must survive the union
        # of guards — a liar row must not swallow the tool-absent signal.
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: True):
            resp = self._ping([_liar(dict), dict(self.CLEAN)], _VANISHED)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_without_disk_confirm_keeps_honest_rows(self):
        # Pin: the fresh disk probe still gates the 503.
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: False):
            resp = self._ping([dict(self.CLEAN)], _VANISHED)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])


class WstunnelSnapshotLiarTests(_MountedRouteTests):
    def _with_live(self, snapshot):
        return mock.patch.object(
            wireguard_wstunnel, "live", lambda ps_text=None: snapshot
        )

    SNAP = {"listen": "", "restrict_to": "", "pid": 12, "running": False,
            "binary": "", "plist": ""}

    def test_bytes_liar_listen_value_keeps_both_reads_200(self):
        # wireguard_wstunnel._as_text's bare unbound bytes.decode detonated.
        snap = dict(self.SNAP, listen=_liar(bytes))
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/settings")
        self.assertEqual(body["wstunnel"]["pid"], 12)

    def test_str_liar_restrict_value_keeps_status_200(self):
        # The str arm rode the liar into the bare unbound str.encode.
        snap = dict(self.SNAP, restrict_to=_liar(str), running=True)
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
        _no_surrogates(body)
        self.assertTrue(body["wstunnel"]["running"])

    def test_dict_liar_snapshot_stays_immune(self):
        # Pin (wg8): the guarded dict(found) copy already refused the liar.
        with self._with_live(_liar(dict)):
            for path in self.READS:
                self.get_ok(path)

    def test_plain_snapshot_still_reads_through_the_launder(self):
        snap = {"listen": "ws://0.0.0.0:8444", "restrict_to": "127.0.0.1:51820",
                "pid": 12, "running": True, "binary": "", "plist": ""}
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["wstunnel"]["listen"], "ws://0.0.0.0:8444")
        self.assertTrue(body["wstunnel"]["running"])


class MutationRcBombTests(_MountedRouteTests):
    """The mutation spawns' bare rc probes detonated past the coded errors."""

    def test_keygen_rc_bomb_answers_the_coded_body_not_a_raw_500(self):
        # Before the fix this was a raw RuntimeError 500 with no JSON body.
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(2), "", "")
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
            resp = self.client.post("/api/wireguard/peers", json={"name": "phone"})
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.keygen_failed")

    def test_sync_bombed_rc_zero_still_applies(self):
        # int.__index__ salvages the honest 0: a healthy sync must not
        # degrade into wg.sync_failed (and must never 500).
        staged = Path(tempfile.mkdtemp(prefix="wg10-conf-")) / "wg0.conf"
        staged.write_text("[Interface]\nListenPort = 51820\n")
        with mock.patch.object(
            wireguard_svc, "live_interface", lambda interface: ("utun8", [], "")
        ), mock.patch.object(
            wireguard_svc, "conf_path", lambda interface=None: staged
        ), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(0), "", "")
        ):
            resp = self.client.post("/api/wireguard/sync")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["applied"])

    def test_interface_action_bombed_rc_zero_still_succeeds(self):
        state = {"stale": False, "live": False, "name_file": "/tmp/wg0.name",
                 "interface": "wg0", "name_file_present": False,
                 "sockets": [], "real_interface": ""}
        with mock.patch.object(
            wireguard_svc, "_path_exists", lambda p: True
        ), mock.patch.object(
            wireguard_svc, "runtime_state", lambda iface=None: dict(state)
        ), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(0), "", "")
        ):
            resp = self.client.post(
                "/api/wireguard/interface", json={"action": "down"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])


class SaveSettingsLiarTests(_MountedRouteTests):
    def test_dict_liar_cfg_root_keeps_put_200_and_persists_the_patch(self):
        # save_settings' bare isinstance + dict.get probes detonated on the
        # liar root after validation had already passed.
        saved = {}
        with mock.patch.object(
            wireguard_svc, "cfg", lambda: _liar(dict)
        ), mock.patch.object(
            wireguard_svc, "update_settings", lambda patch: saved.update(patch)
        ):
            resp = self.client.put("/api/wireguard/settings", json={"mtu": 1400})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(saved["wireguard"]["mtu"], 1400)

    def test_plain_cfg_root_still_merges_the_stored_section(self):
        # The liar guard must not blunt a real read-modify-write: existing
        # keys survive alongside the patch.
        saved = {}
        with mock.patch.object(
            wireguard_svc, "cfg",
            lambda: {"settings": {"wireguard": {"endpoint": "vpn.example.com"}}},
        ), mock.patch.object(
            wireguard_svc, "update_settings", lambda patch: saved.update(patch)
        ):
            resp = self.client.put("/api/wireguard/settings", json={"mtu": 1400})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(saved["wireguard"]["mtu"], 1400)
        self.assertEqual(saved["wireguard"]["endpoint"], "vpn.example.com")


if __name__ == "__main__":
    unittest.main()
