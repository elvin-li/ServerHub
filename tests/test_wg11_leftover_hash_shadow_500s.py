"""WireGuard leftover-500 sweep #11: hash-shadow keys, ``sh`` answer shapes.

wg10 sealed the lying-``__class__`` impostors and the mutation rc bombs.
Re-running the brew11-style batteries over the WireGuard surfaces (real
``create_app()`` + ``TestClient(raise_server_exceptions=False)``) surfaced
two NEW leftover families that still 500'd JSON routes:

* **Hash-shadow mapping keys.**  Every row/block launder copies through an
  exact ``dict(...)``, which preserves poisoned *keys* without re-hashing.
  A stored str-subclass key whose ``__hash__`` collides with a real field
  name ("ip", "PublicKey", "Address", "known", …) and whose ``__eq__``
  raises then detonates the C-level probe loop inside the very next
  ``row.get(...)`` / ``dict.get(row, ...)`` — a raw 500 on POST
  /api/wireguard/ping (``_ping_targets`` / ``ping_peers``'s result build),
  GET /api/wireguard (``status``'s record and iface pulls,
  ``peer_records``), GET /api/wireguard/next-ip (``used_addresses``), GET
  /api/wireguard/export (bare ``record["public_key"]``), GET
  /api/wireguard/readiness (``peer_origin_conflict``'s bound ``.get``),
  GET /api/wireguard/peers/config (``meta.get`` + the reflected
  ``or ""`` ``__bool__`` probes) and PUT /api/wireguard/settings
  (``dict(stored)`` fast-copied the shadow, the patch insert detonated).
  :func:`hub.wireguard_svc._mapping_get` launders every such pull now: a
  shadowed lookup reads as absent, costing only the field it shadows.
* **``sh()`` answer shapes.**  None of the spawn seams own their runner
  (tests and tooling patch ``sh`` / ``sudo_capture``), and the bare
  ``rc, out, err = sh(...)`` unpack detonated on any answer that is not a
  3-sequence — None, a bare string, a 2- or 4-tuple, or a runner that
  raises.  A raw 500 on GET /api/wireguard (``_binary_version`` through
  ``installation``'s fan_out, ``_dump_all``, ``live_interface``), POST
  /api/wireguard/peers (``generate_keypair``), POST /api/wireguard/sync
  (``apply_live``) and POST /api/wireguard/interface.
  :func:`hub.wireguard_svc._sh_answer` reads junk as ``(-255, "", "")`` —
  ``-255`` is no honest exit and never ``sh``'s ``-1`` FileNotFoundError
  sentinel, so a mangled answer can neither pass an ``== 0`` success probe
  nor fake the vanished-CLI shape.

Conflict pins kept from earlier sweeps: the ``wg.ping_missing`` 503 stays
disk-confirmed and fires through the union of guards; the honest
``(-1, "", "not found")`` sentinel still upgrades ``generate_keypair`` to
the coded ``wg.not_installed`` 503 *only* after the on-disk probe;
``_plain_mapping_get`` keeps its None-defaulted shape; ``type``-identity
bool gates and the guarded-decode ``_as_text`` stay as wg10 pinned them.
No new error codes: everything degrades to absent fields or the already
coded errors, so no locale keys.
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

from hub import wireguard_net_svc, wireguard_svc  # noqa: E402

PUB = "A" * 42 + "b="
PUB2 = "C" * 42 + "d="
PRIV = "B" * 42 + "c="

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}

#: sh()'s exact FileNotFoundError sentinel for a vanished binary.
_VANISHED = (-1, "", "not found")

#: Answers no honest ``sh`` ever gives: not a 3-sequence at all.
_JUNK_ANSWERS = (None, "junk", (0, ""), (0, "", "", ""), object(), 7)


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ShadowKey(str):
    """A stored key that hash-collides with *target* and bombs the probe loop.

    Built disarmed so the poisoned dict can be constructed at all (insertion
    runs the same ``__eq__``), then armed: from that point any dict lookup
    that probes this slot — i.e. any ``.get(target)`` when the honest key is
    absent — raises out of the C-level comparison.
    """

    armed = False

    def __new__(cls, target):
        self = str.__new__(cls, "\x00shadow:" + target)
        self._target_hash = hash(target)
        return self

    def __hash__(self):
        return self._target_hash

    def __eq__(self, other):
        if _ShadowKey.armed:
            raise RuntimeError("hash-shadow eq bomb")
        return str.__eq__(self, other)

    def __ne__(self, other):
        if _ShadowKey.armed:
            raise RuntimeError("hash-shadow ne bomb")
        return str.__ne__(self, other)


def _shadowed(base: dict, *targets: str) -> dict:
    """*base* plus one shadow key per absent *target*, armed on return."""
    _ShadowKey.armed = False
    out = dict(base)
    for target in targets:
        out[_ShadowKey(target)] = "shadow-junk"
    _ShadowKey.armed = True
    return out


class _EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class MappingGetUnitTests(unittest.TestCase):
    def test_shadowed_key_reads_as_absent(self):
        row = _shadowed({"name": "phone"}, "ip")
        # The live leftover: both spellings detonated on the shadow slot.
        with self.assertRaises(RuntimeError):
            row.get("ip")
        with self.assertRaises(RuntimeError):
            dict.get(row, "ip")
        self.assertIsNone(wireguard_svc._mapping_get(row, "ip"))
        self.assertEqual(wireguard_svc._mapping_get(row, "ip", ""), "")

    def test_honest_fields_still_answer_through_the_launder(self):
        row = _shadowed({"name": "phone", "ip": "10.9.0.2/32"}, "mode")
        self.assertEqual(wireguard_svc._mapping_get(row, "ip"), "10.9.0.2/32")
        self.assertEqual(wireguard_svc._mapping_get(row, "name"), "phone")

    def test_junk_shapes_answer_the_default(self):
        self.assertEqual(wireguard_svc._mapping_get(None, "k", 5), 5)
        self.assertEqual(wireguard_svc._mapping_get([("k", 1)], "k", 5), 5)

    def test_plain_mapping_get_keeps_its_pinned_shape(self):
        # Pin (wg10): the historical helper answers None, never a default arg.
        self.assertIsNone(wireguard_svc._plain_mapping_get({"a": 1}, "b"))
        self.assertEqual(wireguard_svc._plain_mapping_get({"a": 1}, "a"), 1)
        self.assertIsNone(
            wireguard_svc._plain_mapping_get(_shadowed({}, "a"), "a")
        )


class ShAnswerUnitTests(unittest.TestCase):
    def _run(self, answer):
        return wireguard_svc._sh_answer(lambda argv, timeout: answer, [], timeout=1)

    def test_junk_shapes_read_as_the_failure_triple(self):
        for junk in _JUNK_ANSWERS:
            self.assertEqual(self._run(junk), (-255, "", ""))

    def test_a_raising_runner_reads_as_the_failure_triple(self):
        def bomb(argv, timeout):
            raise RuntimeError("spawn bomb")

        self.assertEqual(
            wireguard_svc._sh_answer(bomb, [], timeout=1), (-255, "", "")
        )

    def test_honest_answers_pass_through_untouched(self):
        self.assertEqual(self._run((0, "out", "err")), (0, "out", "err"))
        self.assertEqual(self._run([2, "o", "e"]), (2, "o", "e"))
        rc = _EqBombInt(0)
        answered = self._run((rc, "", ""))
        self.assertIs(answered[0], rc)

    def test_the_vanished_sentinel_survives_the_launder(self):
        # Pin: the disk-confirmed 503s depend on the honest sentinel arriving.
        self.assertEqual(self._run(_VANISHED), _VANISHED)

    def test_junk_never_reads_as_the_vanished_sentinel(self):
        for junk in _JUNK_ANSWERS:
            rc, out, err = self._run(junk)
            self.assertFalse(wireguard_svc._ping_spawn_sentinel(rc, out, err))
            with mock.patch.object(wireguard_svc, "_path_exists", lambda p: False):
                self.assertFalse(wireguard_svc._cli_missing(rc, err))


class ServiceShadowUnitTests(unittest.TestCase):
    def test_ping_targets_shadow_ip_row_drops_alone(self):
        rows = [
            _shadowed({"public_key": PUB, "name": "junk"}, "ip"),
            {"public_key": PUB2, "ip": "10.9.0.3/32", "name": "ok"},
        ]
        with mock.patch.object(wireguard_svc, "peer_records", lambda: rows):
            targets = wireguard_svc._ping_targets()
        self.assertEqual([host for _r, host in targets], ["10.9.0.3"])

    def test_peer_records_shadow_allowed_ips_keeps_the_row(self):
        peer = _shadowed({"PublicKey": PUB}, "AllowedIPs")
        conf = {"interface": {}, "peers": [peer]}
        with mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: conf
        ):
            records = wireguard_svc.peer_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["public_key"], PUB)
        self.assertEqual(records[0]["ip"], "")
        _no_surrogates(records)

    def test_used_addresses_shadow_address_reads_as_no_claims(self):
        conf = {
            "interface": _shadowed({"ListenPort": "51820"}, "Address"),
            "peers": [_shadowed({"PublicKey": PUB}, "AllowedIPs")],
        }
        with mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: conf
        ):
            self.assertEqual(wireguard_svc.used_addresses(), set())

    def test_peer_origin_conflict_shadow_rows_stay_counted(self):
        rows = [
            _shadowed({"public_key": PUB}, "known", "reissuable"),
            {"public_key": PUB2, "known": True, "reissuable": True},
        ]
        with mock.patch.object(wireguard_svc, "peer_records", lambda: rows):
            verdict = wireguard_net_svc.peer_origin_conflict()
        self.assertFalse(verdict["conflict"])
        self.assertEqual(verdict["foreign"], 1)
        self.assertEqual(verdict["total"], 2)
        _no_surrogates(verdict)


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

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


class PingShadowRouteTests(_MountedRouteTests):
    CLEAN = {"public_key": PUB2, "ip": "10.9.0.3/32", "name": "ok"}

    def _ping(self, records, sh_answer=(0, "", "")):
        with mock.patch.object(
            wireguard_svc, "peer_records", lambda: records
        ), mock.patch.object(wireguard_svc, "sh", lambda *a, **k: sh_answer):
            return self.client.post("/api/wireguard/ping")

    def test_shadow_ip_row_drops_alone(self):
        rows = [_shadowed({"public_key": PUB, "name": "junk"}, "ip"),
                dict(self.CLEAN)]
        resp = self._ping(rows)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["results"][0]["pubkey"], PUB2)

    def test_shadow_pubkey_row_keeps_the_probe_answering(self):
        # The result build's dict.get(record, "public_key") detonated after
        # every probe had already run.
        rows = [_shadowed({"ip": "10.9.0.2/32", "name": "x"}, "public_key")]
        resp = self._ping(rows)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["results"][0]["pubkey"], "")

    def test_vanished_cli_503_still_fires_through_shadow_rows(self):
        # Pin: the disk-confirmed wg.ping_missing must survive the union of
        # guards — a shadow row must not swallow the tool-absent signal.
        rows = [_shadowed({"public_key": PUB, "name": "junk"}, "ip"),
                dict(self.CLEAN)]
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: True):
            resp = self._ping(rows, _VANISHED)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_without_disk_confirm_keeps_honest_rows(self):
        # Pin: the fresh disk probe still gates the 503.
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: False):
            resp = self._ping([dict(self.CLEAN)], _VANISHED)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])


class StatusShadowRouteTests(_MountedRouteTests):
    def _with_conf(self, parsed):
        return mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: parsed
        )

    def test_shadow_peer_fields_keep_status_next_ip_and_export_200(self):
        peer = _shadowed({"PublicKey": PUB}, "AllowedIPs", "PresharedKey")
        with self._with_conf({"interface": {}, "peers": [peer]}):
            body = self.get_ok("/api/wireguard")
            self.assertEqual(body["peer_count"], 1)
            self.assertEqual(self.get_ok("/api/wireguard/next-ip")["used"], 0)
            export = self.get_ok("/api/wireguard/export")
        # Not reissuable (no retained key), so the peer lands in skipped.
        self.assertEqual(export["items"], [])
        self.assertEqual(len(export["skipped"]), 1)

    def test_shadow_interface_fields_keep_status_200_with_defaults(self):
        iface = _shadowed(
            {}, "Address", "ListenPort", "PrivateKey", "MTU", "DNS"
        )
        with self._with_conf({"interface": iface, "peers": []}):
            body = self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/next-ip")
        self.assertEqual(body["address"], "")
        self.assertEqual(
            body["listen_port"], wireguard_svc.DEFAULTS["listen_port"]
        )

    def test_shadow_registry_meta_costs_only_the_metadata(self):
        conf = {
            "interface": {},
            "peers": [{"PublicKey": PUB, "AllowedIPs": "10.9.0.2/32"}],
        }
        meta = _shadowed({"mode": "split"}, "name", "private_key", "created")
        with self._with_conf(conf), mock.patch.object(
            wireguard_svc, "_registry_peers", lambda: {PUB: meta}
        ):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peers"][0]["name"], "")
        self.assertEqual(body["peers"][0]["mode"], "split")
        self.assertFalse(body["peers"][0]["reissuable"])

    def test_readiness_shadow_rows_keep_200(self):
        rows = [_shadowed({"public_key": PUB}, "known", "reissuable")]
        with mock.patch.object(wireguard_svc, "peer_records", lambda: rows):
            self.get_ok("/api/wireguard/readiness")


class PeerConfShadowRouteTests(_MountedRouteTests):
    SERVER = {
        "private_key": PRIV, "public_key": PUB2,
        "address": "10.10.0.1/24", "listen_port": 51820,
    }

    def _get_conf(self, meta):
        conf = {
            "interface": {},
            "peers": [{"PublicKey": PUB, "AllowedIPs": "10.9.0.2/32"}],
        }
        with mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: conf
        ), mock.patch.object(
            wireguard_svc, "_registry_peers", lambda: {PUB: meta}
        ), mock.patch.object(
            wireguard_svc, "server_identity", lambda: dict(self.SERVER)
        ):
            return self.client.get(
                "/api/wireguard/peers/config", params={"pubkey": PUB}
            )

    def test_shadow_private_key_answers_the_coded_error_not_a_raw_500(self):
        # The old ``meta.get("private_key") or ""`` detonated on the shadow.
        resp = self._get_conf(_shadowed({"name": "phone"}, "private_key"))
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "wg.peer_not_reissuable"
        )

    def test_shadow_name_and_mode_still_render_the_config(self):
        meta = _shadowed({"private_key": PRIV}, "name", "mode")
        resp = self._get_conf(meta)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["name"], "peer")
        self.assertIn("10.9.0.2/32", body["content"])


class SaveSettingsShadowRouteTests(_MountedRouteTests):
    def test_shadow_stored_key_keeps_put_200_and_merges_honest_keys(self):
        # dict(stored) fast-copied the shadow; current["mtu"] = 1400 then
        # detonated the probe loop after validation had already passed.
        stored = _shadowed({"endpoint": "vpn.example.com"}, "mtu")
        saved = {}
        with mock.patch.object(
            wireguard_svc, "cfg",
            lambda: {"settings": {"wireguard": stored}},
        ), mock.patch.object(
            wireguard_svc, "update_settings", lambda patch: saved.update(patch)
        ):
            resp = self.client.put("/api/wireguard/settings", json={"mtu": 1400})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(saved["wireguard"]["mtu"], 1400)
        self.assertEqual(saved["wireguard"]["endpoint"], "vpn.example.com")
        # The junk key is dropped, not persisted back into services.yaml.
        self.assertEqual(
            [type(k) for k in saved["wireguard"]], [str, str]
        )


class AnswerShapeRouteTests(_MountedRouteTests):
    def test_junk_sh_answers_keep_every_read_200(self):
        for junk in _JUNK_ANSWERS:
            with mock.patch.object(
                wireguard_svc, "sh", lambda *a, **k: junk
            ), mock.patch.object(
                wireguard_svc, "sudo_capture", lambda *a, **k: junk
            ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: True):
                self.get_ok("/api/wireguard")
                self.get_ok("/api/wireguard/settings")

    def test_junk_sh_answer_keeps_the_coded_keygen_error(self):
        # Before the fix: TypeError out of the bare unpack, a raw 500 with
        # no JSON body.  The disk-confirm pin rides along: junk must never
        # fake the vanished sentinel, so even with wg gone from disk this
        # stays keygen_failed, not the not_installed 503.
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: None
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: False):
            resp = self.client.post("/api/wireguard/peers", json={"name": "phone"})
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.keygen_failed")

    def test_honest_sentinel_still_upgrades_to_the_disk_confirmed_503(self):
        # Pin: _sh_answer must pass the real sentinel through so the
        # confirmed-vanished wg keeps its coded 503.
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: _VANISHED
        ), mock.patch.object(wireguard_svc, "_path_exists", lambda p: False):
            resp = self.client.post("/api/wireguard/peers", json={"name": "phone"})
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.not_installed")

    def test_junk_sh_answer_keeps_the_coded_sync_error(self):
        staged = Path(tempfile.mkdtemp(prefix="wg11-conf-")) / "wg0.conf"
        staged.write_text("[Interface]\nListenPort = 51820\n")
        with mock.patch.object(
            wireguard_svc, "live_interface", lambda interface: ("utun8", [], "")
        ), mock.patch.object(
            wireguard_svc, "conf_path", lambda interface=None: staged
        ), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: None
        ), mock.patch.object(
            wireguard_svc, "run_admin", lambda *a, **k: {"ok": False}
        ):
            resp = self.client.post("/api/wireguard/sync")
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.sync_failed")

    def test_junk_sh_answer_keeps_the_interface_route_coded(self):
        state = {"stale": False, "live": False, "name_file": "/tmp/wg0.name",
                 "interface": "wg0", "name_file_present": False,
                 "sockets": [], "real_interface": ""}
        with mock.patch.object(
            wireguard_svc, "_path_exists", lambda p: True
        ), mock.patch.object(
            wireguard_svc, "runtime_state", lambda iface=None: dict(state)
        ), mock.patch.object(wireguard_svc, "sh", lambda *a, **k: "junk"):
            resp = self.client.post(
                "/api/wireguard/interface", json={"action": "down"}
            )
        # Coded failure body, never a raw unpack TypeError 500.
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        self.assertIn("code", resp.json()["detail"])

    def test_honest_sh_answer_still_succeeds_end_to_end(self):
        # The launder must not blunt a healthy spawn: a real 3-tuple exit 0
        # keeps POST /api/wireguard/interface answering ok.
        state = {"stale": False, "live": False, "name_file": "/tmp/wg0.name",
                 "interface": "wg0", "name_file_present": False,
                 "sockets": [], "real_interface": ""}
        with mock.patch.object(
            wireguard_svc, "_path_exists", lambda p: True
        ), mock.patch.object(
            wireguard_svc, "runtime_state", lambda iface=None: dict(state)
        ), mock.patch.object(wireguard_svc, "sh", lambda *a, **k: (0, "", "")):
            resp = self.client.post(
                "/api/wireguard/interface", json={"action": "down"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["ok"])


if __name__ == "__main__":
    unittest.main()
