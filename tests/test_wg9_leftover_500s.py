"""WireGuard leftover-500 sweep #9: __class__-property, key and rc bombs.

All reproduced over ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` before the fixes; each answered ``500 Internal Server Error`` with a
traceback, never a coded JSON body.  wg8 sealed the *container*-shape bombs
(dict-subclass ``.get``/``.items``, list-subclass ``__iter__``); health9 added
``_isa``/``_ping_rc`` to the ping gates.  Re-running the zoo with the
raising-``__class__``-property, poisoned-mapping-key and rc-``__eq__`` members
surfaced these live leftovers on GET /api/wireguard, GET
/api/wireguard/settings and POST /api/wireguard/ping:

* **The type gates themselves detonated.**  ``isinstance`` consults
  ``value.__class__`` when the exact-type check misses, so a leftover whose
  ``__class__`` is a *raising property* blew up the very launders that exist
  to absorb junk: ``_as_text``'s bytes/str gates (reached from every conf
  value, peer-record value and ``sh`` stream, including POST /ping's output
  parse), ``_plain_int``/``_conf_int``/``_nonfinite``'s numeric gates,
  ``settings()``'s section- and value-shape gates, ``_conf_interface`` /
  ``_conf_peers`` / ``_plain_rows``'s container gates, and ``status()``'s
  keepalive scalar gate.  All now go through ``_isa`` (the health9 rule).
* **A poisoned stored-section key 500'd every settings read.**  Dict lookup
  runs the probe key's *reflected* ``__eq__`` first when it is a str
  subclass, so ``key not in merged`` / ``DEFAULTS[key]`` detonated on one
  leftover key.  The merge loop now guards per item: a bomb key costs only
  its own entry, sibling keys keep merging.
* **rc-subclass ``__eq__``/``__ne__`` bombs from a patched/odd ``sh`` blew
  the read path's bare exit probes** — ``_binary_version`` (through
  ``installation()``'s fan_out on both GET reads), ``_dump_all`` and
  ``live_interface``'s three spawns (GET /api/wireguard), and
  ``wireguard_wstunnel.local_ipv4s``.  All now launder through
  ``_ping_rc`` / ``_rc_int``; ``int.__index__`` salvages the honest exit, so
  a bombed rc 0 still reads as success rather than a false alarm.
* **The wstunnel snapshot's values reflected into their own ``__bool__``.**
  wg8 laundered the snapshot's *shape*; the ``found.get(...) or ""`` blank
  probes, ``bool(found.get("running"))`` and the ``configured`` truthiness
  chain still ran a leftover value's own ``__bool__``, and a
  raising-``__class__`` snapshot detonated the shape gate itself — raw 500s
  on GET /api/wireguard and GET /api/wireguard/settings.

Already-immune vectors are pinned rather than re-claimed: the FIFO-occupied
wg0.conf (read_text_capped opens O_NONBLOCK and refuses non-regular files),
the over-cap JSON integer in the peer registry (``_journal_int`` absorbs the
``json.loads`` ValueError), the isoformat-property date leftover in the
stored section (the type gate drops it before any encoder sees it), the torn
IPv6 wstunnel listen URL (regex parse, no urlsplit), the whole-listing
``__class__`` bomb on POST /ping (health9's ``_ping_targets`` gates), and the
``wg.ping_missing`` 503 (disk-confirm only) surviving the union of guards.

No new error codes: everything degrades to defaults, so no locale keys.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import date
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_svc, wireguard_wstunnel  # noqa: E402

PUB = "A" * 42 + "b="

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


class ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class EqBombKey(str):
    """A stored mapping key whose reflected ``__eq__`` raises on dict lookup."""

    def __eq__(self, other):
        raise RuntimeError("key eq bomb")

    __hash__ = str.__hash__


class EqBombInt(int):
    """An rc whose comparison raises — ``rc == 0`` / ``rc != 0`` detonate."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class IsoBombDate(date):
    """YAML-shaped date leftover whose encoder hook raises."""

    def isoformat(self):
        raise RuntimeError("isoformat bomb")


class LaunderUnitTests(unittest.TestCase):
    """The scalar launders survive the raising-__class__ member themselves."""

    def test_as_text_class_bomb_answers_a_str(self):
        text = wireguard_svc._as_text(ClassBomb())
        self.assertIsInstance(text, str)

    def test_plain_int_class_bomb_answers_none(self):
        self.assertIsNone(wireguard_svc._plain_int(ClassBomb()))

    def test_conf_int_class_bomb_keeps_the_fallback(self):
        self.assertEqual(wireguard_svc._conf_int(ClassBomb(), 25), 25)

    def test_nonfinite_class_bomb_answers_false(self):
        self.assertFalse(wireguard_svc._nonfinite(ClassBomb()))

    def test_plain_rows_class_bomb_row_drops_alone(self):
        rows = wireguard_svc._plain_rows([ClassBomb(), {"PublicKey": PUB}])
        self.assertEqual(rows, [{"PublicKey": PUB}])

    def test_conf_interface_class_bomb_parsed_answers_empty(self):
        self.assertEqual(wireguard_svc._conf_interface(ClassBomb()), {})
        self.assertEqual(wireguard_svc._conf_peers(ClassBomb()), [])


class BinaryVersionRcTests(unittest.TestCase):
    """installation()'s version probes do not own ``sh``."""

    def _version(self, answer):
        with mock.patch.object(wireguard_svc, "_path_exists", lambda p: True), \
                mock.patch.object(wireguard_svc, "sh", lambda *a, **k: answer):
            return wireguard_svc._binary_version("/opt/homebrew/bin/wg")

    def test_rc_eq_bomb_reads_as_no_answer_not_a_raise(self):
        self.assertEqual(self._version((EqBombInt(2), "v1", "")), "")

    def test_rc_eq_bomb_zero_is_salvaged_not_defaulted(self):
        # int.__index__ keeps the honest exit: a bombed rc 0 still reports
        # the version rather than degrading to "probe failed".
        self.assertEqual(
            self._version((EqBombInt(0), "wireguard-tools v1.0.20210914", "")),
            "wireguard-tools v1.0.20210914",
        )


class WstunnelRcUnitTests(unittest.TestCase):
    def test_local_ipv4s_rc_bomb_answers_empty(self):
        wireguard_wstunnel.local_ipv4s.cache_clear()
        self.addCleanup(wireguard_wstunnel.local_ipv4s.cache_clear)
        with mock.patch.object(
            wireguard_wstunnel, "sh", lambda *a, **k: (EqBombInt(1), "", "")
        ):
            self.assertEqual(wireguard_wstunnel.local_ipv4s(), frozenset())


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


class StoredSectionClassBombTests(_MountedRouteTests):
    """settings() survives a section (or value, or key) that lies about itself."""

    def _with_section(self, section):
        return mock.patch.object(
            wireguard_svc, "settings_section", lambda name: section
        )

    def test_class_bomb_section_keeps_every_read_200_with_defaults(self):
        # The live leftover: the shape gate itself ran the bomb's __class__.
        with self._with_section(ClassBomb()):
            for path in self.READS:
                self.get_ok(path)
            body = self.get_ok("/api/wireguard/settings")
        self.assertEqual(
            body["settings"]["listen_port"], wireguard_svc.DEFAULTS["listen_port"]
        )

    def test_class_bomb_section_keeps_ping_200(self):
        # Pin: _ping_targets' provider guard already absorbed this; the
        # settings() fix must not regress it.
        with self._with_section(ClassBomb()), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (0, "", "")
        ):
            resp = self.client.post("/api/wireguard/ping")
        self.assertEqual(resp.status_code, 200, resp.text[:300])

    def test_class_bomb_value_costs_only_its_key(self):
        # A bombed numeric and a bombed string value each keep the default;
        # the plain sibling in the same section survives.
        section = {"listen_port": ClassBomb(), "endpoint": ClassBomb(), "mtu": 1400}
        with self._with_section(section):
            body = self.get_ok("/api/wireguard/settings")
        self.assertEqual(
            body["settings"]["listen_port"], wireguard_svc.DEFAULTS["listen_port"]
        )
        self.assertEqual(body["settings"]["endpoint"], wireguard_svc.DEFAULTS["endpoint"])
        self.assertEqual(body["settings"]["mtu"], 1400)

    def test_eq_bomb_mapping_key_costs_only_its_entry(self):
        # Dict lookup calls the probe key's reflected __eq__ first, so the
        # old bare ``key not in merged`` was a raw 500 on every settings read.
        section = {EqBombKey("endpoint"): "vpn.example.com", "mtu": 1400}
        with self._with_section(section):
            body = self.get_ok("/api/wireguard/settings")
            self.get_ok("/api/wireguard")
        self.assertEqual(body["settings"]["endpoint"], wireguard_svc.DEFAULTS["endpoint"])
        self.assertEqual(body["settings"]["mtu"], 1400)

    def test_isoformat_bomb_date_stays_immune(self):
        # Pin: the per-key type gate drops the YAML date before any encoder
        # could run its isoformat.
        with self._with_section({"endpoint": IsoBombDate(2026, 8, 19)}):
            body = self.get_ok("/api/wireguard/settings")
        self.assertEqual(body["settings"]["endpoint"], wireguard_svc.DEFAULTS["endpoint"])

    def test_plain_section_still_merges_through_the_guard(self):
        # The per-item guard must not blunt real reads.
        section = {"listen_port": 51825, "endpoint": "vpn.example.com"}
        with self._with_section(section):
            body = self.get_ok("/api/wireguard/settings")
        self.assertEqual(body["settings"]["listen_port"], 51825)
        self.assertEqual(body["settings"]["endpoint"], "vpn.example.com")


class ParsedConfClassBombTests(_MountedRouteTests):
    def _with_conf(self, parsed):
        return mock.patch.object(
            wireguard_svc, "read_conf", lambda interface=None: parsed
        )

    def test_class_bomb_parsed_conf_keeps_status_200(self):
        with self._with_conf(ClassBomb()):
            self.get_ok("/api/wireguard")

    def test_class_bomb_address_value_keeps_status_200(self):
        # _as_text's own type gates ran the value's __class__.
        with self._with_conf({"interface": {"Address": ClassBomb()}, "peers": []}):
            body = self.get_ok("/api/wireguard")
        _no_surrogates(body)

    def test_class_bomb_peers_container_stays_immune(self):
        # Pin: the status walk's provider guard already absorbed this; the
        # _plain_rows _isa gates keep it row-level now.
        with self._with_conf({"interface": {}, "peers": ClassBomb()}):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peer_count"], 0)


class PeerRecordClassBombTests(_MountedRouteTests):
    def _with_records(self, records):
        return mock.patch.object(wireguard_svc, "peer_records", lambda: records)

    CLEAN = {
        "public_key": PUB, "ip": "10.9.0.2/32", "preshared_key": "",
        "keepalive": "25", "name": "phone", "mode": "split", "created": 0,
        "reissuable": False, "known": True,
    }

    def test_class_bomb_keepalive_value_keeps_status_200(self):
        # status()'s scalar gate itself ran the value's __class__.
        row = dict(self.CLEAN, keepalive=ClassBomb())
        with self._with_records([row]):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peer_count"], 1)
        self.assertEqual(body["peers"][0]["keepalive"], "off")

    def test_class_bomb_row_value_keeps_the_clean_sibling(self):
        rows = [dict(self.CLEAN, public_key=ClassBomb()), dict(self.CLEAN)]
        with self._with_records(rows):
            body = self.get_ok("/api/wireguard")
        _no_surrogates(body)
        self.assertEqual(body["peer_count"], 2)
        self.assertIn(PUB, [p["pubkey"] for p in body["peers"]])


class ShRcBombRouteTests(_MountedRouteTests):
    def test_rc_eq_bomb_sh_keeps_status_200(self):
        # _dump_all / live_interface's bare ``rc != 0`` probes detonated.
        with mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(3), "", "boom")
        ), mock.patch.object(
            wireguard_svc, "sudo_capture", lambda *a, **k: (EqBombInt(3), "", "boom")
        ):
            body = self.get_ok("/api/wireguard")
        self.assertFalse(body["running"])

    def test_rc_eq_bomb_zero_still_reads_the_dump(self):
        # The salvage keeps an honest tunnel visible: a bombed rc 0 must not
        # degrade a healthy dump into "not running".
        dump = "\t".join(["srv-priv", PUB, "51820", "off"])
        with mock.patch.object(
            wireguard_svc, "real_interface", lambda interface=None: "utun8"
        ), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: (EqBombInt(0), dump, "")
        ):
            body = self.get_ok("/api/wireguard")
        self.assertTrue(body["running"])
        self.assertEqual(body["public_key"], PUB)


class PingClassBombStreamTests(_MountedRouteTests):
    def _ping_with(self, sh_answer):
        with mock.patch.object(
            wireguard_svc, "peer_records",
            lambda: [{"public_key": PUB, "ip": "10.9.0.2/32", "name": "phone"}],
        ), mock.patch.object(
            wireguard_svc, "sh", lambda *a, **k: sh_answer
        ):
            return self.client.post("/api/wireguard/ping")

    def test_class_bomb_stdout_keeps_ping_200(self):
        # _as_text's gates ran the stream's __class__ inside _ping_once —
        # past its spawn try, re-raised through fan_out.
        resp = self._ping_with((0, ClassBomb(), ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        # rc is the authority: reachable, latency unknown.
        self.assertTrue(body["results"][0]["reachable"])
        self.assertIsNone(body["results"][0]["latency_ms"])

    def test_class_bomb_stderr_keeps_ping_200(self):
        resp = self._ping_with((1, "", ClassBomb()))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])

    def test_vanished_cli_503_still_fires_after_disk_confirm(self):
        # Pin: the health8 coded 503 survives the union of guards.
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: True):
            resp = self._ping_with(_VANISHED)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_without_disk_confirm_keeps_honest_rows(self):
        # Pin: the disk probe still gates the 503.
        with mock.patch.object(wireguard_svc, "_ping_cli_gone", lambda: False):
            resp = self._ping_with(_VANISHED)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])


class WstunnelSnapshotValueBombTests(_MountedRouteTests):
    def _with_live(self, snapshot):
        return mock.patch.object(
            wireguard_wstunnel, "live", lambda ps_text=None: snapshot
        )

    SNAP = {"listen": "", "restrict_to": "", "pid": 12, "running": False,
            "binary": "", "plist": ""}

    def test_class_bomb_snapshot_keeps_status_and_settings_200(self):
        with self._with_live(ClassBomb()):
            for path in self.READS:
                self.get_ok(path)

    def test_bool_bomb_listen_value_keeps_status_200(self):
        # ``found.get("listen") or ""`` reflected into the value's __bool__.
        snap = dict(self.SNAP, listen=BoolBomb(), running=True)
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["wstunnel"]["pid"], 12)

    def test_bool_bomb_running_value_keeps_status_200(self):
        snap = dict(self.SNAP, running=BoolBomb())
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
        self.assertFalse(body["wstunnel"]["running"])

    def test_bool_bomb_binary_and_plist_values_keep_status_200(self):
        snap = dict(self.SNAP, binary=BoolBomb(), plist=BoolBomb())
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
            self.get_ok("/api/wireguard/settings")
        _no_surrogates(body)

    def test_plain_snapshot_still_reads_through_the_launder(self):
        snap = {"listen": "ws://0.0.0.0:8444", "restrict_to": "127.0.0.1:51820",
                "pid": 12, "running": True, "binary": "", "plist": ""}
        with self._with_live(snap):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["wstunnel"]["listen"], "ws://0.0.0.0:8444")
        self.assertTrue(body["wstunnel"]["running"])
        self.assertTrue(body["wstunnel"]["configured"])

    def test_torn_ipv6_stored_listen_stays_immune(self):
        # Pin: the listen URL is parsed by regex, never urlsplit, so the
        # unbalanced bracket cannot raise out of the status read.
        with mock.patch.object(
            wireguard_svc, "settings_section",
            lambda name: {"wstunnel_listen": "ws://[::1:8444"},
        ):
            for path in self.READS:
                self.get_ok(path)


class LeftoverNodePinTests(_MountedRouteTests):
    """Filesystem leftovers that are already absorbed stay absorbed."""

    def test_fifo_occupied_conf_stays_immune(self):
        # Pin: read_text_capped opens O_NONBLOCK and refuses non-regular
        # files with OSError, which read_conf already degrades to a skeleton.
        confdir = Path(tempfile.mkdtemp(prefix="wg9-fifo-"))
        os.mkfifo(confdir / "wg0.conf")
        with mock.patch.object(wireguard_svc, "conf_dir", lambda: confdir):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peer_count"], 0)

    def test_over_cap_registry_int_stays_immune(self):
        # Pin: json.loads converts integer literals via int(str), which
        # CPython caps at 4300 digits — ValueError, not JSONDecodeError.
        # _journal_int absorbs it to 0 so the journal (and the peer) survive.
        wireguard_svc.REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        wireguard_svc.REGISTRY_PATH.write_text(
            '{"peers": {"%s": {"name": "phone", "created": %s}}}'
            % (PUB, "9" * 5000)
        )
        self.addCleanup(
            lambda: wireguard_svc.REGISTRY_PATH.unlink(missing_ok=True)
        )
        with mock.patch.object(
            wireguard_svc, "read_conf",
            lambda interface=None: {
                "interface": {},
                "peers": [{"PublicKey": PUB, "AllowedIPs": "10.9.0.2/32"}],
            },
        ):
            body = self.get_ok("/api/wireguard")
        self.assertEqual(body["peer_count"], 1)
        self.assertEqual(body["peers"][0]["name"], "phone")
        self.assertEqual(body["peers"][0]["last_handshake"], 0)


if __name__ == "__main__":
    unittest.main()
