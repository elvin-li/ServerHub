"""Sixth leftover-500s sweep of the Network surfaces, over the mounted app.

The hunted zoo (recursive YAML anchors, the CPython 4300-digit int cap in
JSON *request bodies*, hostile on-disk YAML types, torn / oversize /
whole-document-paste services.yaml, a FIFO squatting the config path,
surrogates in body keys and values, dict-subclass bombs at the cfg()
boundary) was re-driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` against the alias / failover
routes — this time over the REAL on-disk services.yaml rather than a mocked
``settings_section``, which is the boundary net5 never crossed.

One live leftover was found and fixed:

* ``ip_aliases: &a {self: *a}`` — a recursive YAML anchor — survives
  ``yaml.safe_load`` and ``settings_section``, so
  PUT /api/system/network/alias/auto copied the stored section, patched it,
  and handed :func:`hub.config.deep_merge` a patch that contained itself.
  ``copy.deepcopy`` is memo'd against cycles but the merge walk was not:
  the recursion never terminated and the PUT answered a RecursionError 500
  instead of saving.  The walk is now cycle-guarded by identity along the
  current merge path (per-path, so a non-cyclic alias reused by sibling
  keys still merges into both); the save lands, the sibling settings keys
  survive, and the rewritten file stays loadable.

Everything else answered 2xx/4xx/503 with strictly-decodable UTF-8 bodies;
those pins hold the line:

* torn non-UTF-8 / oversize / whole-document-paste services.yaml answers
  the coded 503 ``settings.config_unreadable`` on the mutating PUT with the
  on-disk bytes intact, while the GET readers keep rendering defaults;
* a FIFO squatting services.yaml neither hangs the readers nor the PUT
  (``read_text_capped`` opens O_NONBLOCK; the mutate treats a non-regular
  node as holding nothing to lose and replaces it);
* a >4300-digit int in a JSON request body is FastAPI's coded 400 — the
  digit-cap ValueError out of ``json.loads`` is not a JSONDecodeError, but
  the body-parse guard catches broader than that;
* deeply-nested-YAML depth windows answer coded 503s (``save_failed`` /
  ``config_unreadable``), never a raw RecursionError 500;
* the hostile on-disk YAML type zoo (``!!set`` ips, ``!!binary`` netmask
  and booleans, hex ints past the render cap, ``.inf``/``.nan``, dates,
  ``!!omap`` tuples, int/null/date section keys) degrades to defaults on
  every alias/failover surface;
* surrogate-escaped keys and values in PUT bodies are laundered, and a
  cfg() root that is a dict subclass with bombing ``get``/``keys``/
  ``items``/``__bool__`` never reaches the section readers.
"""
from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, docker_cli, host_address, network_svc

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


_SANE_IFCONFIG = (
    "en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n"
    "\tether aa:bb:cc:dd:ee:ff\n"
    "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
    "\tstatus: active\n"
)
_SANE_ORDER = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    "(1) Wi-Fi\n"
    "(Hardware Port: Wi-Fi, Device: en0)\n"
    "(2) USB LAN\n"
    "(Hardware Port: USB 10/100/1000 LAN, Device: en5)\n"
)
_SANE_HW = (
    "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
    "\n"
    "Hardware Port: USB 10/100/1000 LAN\nDevice: en5\n"
    "Ethernet Address: ff:ee:dd:cc:bb:aa\n"
)


def _fake_network_sh(argv, timeout=10, **kwargs):
    prog = argv[0]
    if prog == "/sbin/ifconfig":
        if len(argv) > 2 and argv[1].startswith("en"):
            return 0, "", ""  # alias add/remove mutations succeed
        return 0, _SANE_IFCONFIG, ""
    if prog == "/usr/sbin/networksetup":
        return {
            "-listnetworkserviceorder": (0, _SANE_ORDER, ""),
            "-listallhardwareports": (0, _SANE_HW, ""),
            "-getinfo": (
                0,
                "DHCP Configuration\nIP Address: 192.0.2.10\nRouter: 192.0.2.1\n",
                "",
            ),
            "-getdnsservers": (0, "1.1.1.1\n", ""),
            "-getsearchdomains": (0, "lan\n", ""),
            "-getairportpower": (0, "Wi-Fi Power (en0): On\n", ""),
            "-listallnetworkservices": (0, "An asterisk\nWi-Fi\nUSB LAN\n", ""),
        }.get(argv[1], (0, "", ""))
    if prog == "/sbin/route":
        return 0, "  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL>\n", ""
    if prog == "/usr/sbin/lsof":
        return 0, (
            "COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME\n"
            "app 2 me 1u IPv4 0 0t0 TCP 127.0.0.1:9090 (LISTEN)\n"
        ), ""
    if prog == "/usr/sbin/netstat":
        return 0, "default 192.0.2.1 UGSc en0\n", ""
    if prog == "/sbin/ping":
        return 0, "1 packets\n", ""
    if prog in ("/usr/bin/dscacheutil", "/usr/bin/dig"):
        return 0, "1.2.3.4\n", ""
    if prog == "/usr/bin/sudo":
        return 1, "", "sudo: a password is required"
    return 1, "", "not run"


def _fake_docker_sh(argv, timeout=30, **kwargs):
    return 1, "", "Cannot connect to the Docker daemon"


class _DiskConfigSandbox(unittest.TestCase):
    """Sane subprocess stubs; the REAL services.yaml is the hostile boundary.

    The suite shares one state directory, so the file is snapshotted and
    restored byte-exactly around every test, caches busted both ways.
    """

    def setUp(self):
        for patched in (
            mock.patch.object(network_svc, "sh", side_effect=_fake_network_sh),
            mock.patch.object(host_address, "sh", side_effect=_fake_network_sh),
            mock.patch.object(docker_cli, "sh", side_effect=_fake_docker_sh),
            mock.patch.object(network_svc, "_wstunnel_snapshot", return_value=None),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        try:
            self._saved_yaml = config.YAML_PATH.read_bytes()
        except OSError:
            self._saved_yaml = None
        self.addCleanup(self._restore_yaml)
        self._reset_caches()
        self.addCleanup(self._reset_caches)

    def _restore_yaml(self):
        self._clear_yaml_node()
        if self._saved_yaml is not None:
            config.YAML_PATH.write_bytes(self._saved_yaml)
        config.reload_cfg()

    @staticmethod
    def _clear_yaml_node():
        """Remove whatever occupies the config path (file or planted FIFO)."""
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass

    @staticmethod
    def _reset_caches():
        network_svc._bust()
        host_address.invalidate_routing()
        docker_cli.invalidate_engine_state()

    def write_yaml(self, text: str):
        self._clear_yaml_node()
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(text, encoding="utf-8")
        config.reload_cfg()
        self._reset_caches()

    def request_ok(self, method, path, body=None, want=200, raw=None):
        if raw is not None:
            resp = _client().request(
                method, path, content=raw,
                headers={"content-type": "application/json"},
            )
        else:
            resp = _client().request(method, path, json=body)
        # The body must already be valid UTF-8 — decode strictly on purpose.
        text = resp.content.decode("utf-8")
        self.assertEqual(resp.status_code, want, f"{path}: {text[:300]}")
        self.assertNotIn("\ud800", text, path)
        return json.loads(text)


class RecursiveAnchorCycleTests(_DiskConfigSandbox):
    """The live leftover: a recursive anchor cycled deep_merge into a 500."""

    _DIRECT_CYCLE = (
        "settings:\n"
        "  other_key: keepme\n"
        "  ip_aliases: &a\n"
        "    self: *a\n"
        "    auto_bind: true\n"
        "    ips: ['192.0.2.44']\n"
    )

    def test_direct_cycle_put_saves_instead_of_recursing(self):
        self.write_yaml(self._DIRECT_CYCLE)
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": False}
        )
        self.assertIs(payload["config"]["auto_bind"], False)
        # The rewritten file must stay loadable, keep the change, and keep
        # the sibling settings key the cycle used to take down with it.
        reloaded = config.reload_cfg()
        settings = reloaded.get("settings") or {}
        self.assertEqual(settings.get("other_key"), "keepme")
        section = settings.get("ip_aliases")
        self.assertIsInstance(section, dict)
        self.assertIs(section.get("auto_bind"), False)
        self.assertEqual(section.get("ips"), ["192.0.2.44"])

    def test_indirect_two_hop_cycle_put_saves(self):
        self.write_yaml(
            "settings:\n"
            "  other_key: keepme\n"
            "  ip_aliases: &a\n"
            "    auto_bind: true\n"
            "    hop:\n"
            "      back: *a\n"
        )
        self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": False}
        )
        settings = config.reload_cfg().get("settings") or {}
        self.assertEqual(settings.get("other_key"), "keepme")
        self.assertIs((settings.get("ip_aliases") or {}).get("auto_bind"), False)

    def test_settings_root_cycle_put_saves(self):
        self.write_yaml(
            "settings: &s\n"
            "  other_key: keepme\n"
            "  loop: *s\n"
            "  ip_aliases:\n"
            "    auto_bind: true\n"
        )
        self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": False}
        )
        settings = config.reload_cfg().get("settings") or {}
        self.assertEqual(settings.get("other_key"), "keepme")
        self.assertIs((settings.get("ip_aliases") or {}).get("auto_bind"), False)

    def test_cyclic_config_reads_stay_200(self):
        """The GET / run halves were already immune — pinned so they stay."""
        self.write_yaml(self._DIRECT_CYCLE)
        status = self.request_ok("GET", "/api/system/network/alias/auto")
        self.assertEqual(status["config"]["ips"], ["192.0.2.44"])
        run = self.request_ok("POST", "/api/system/network/alias/auto/run")
        self.assertEqual(run["managed_ips"], ["192.0.2.44"])

    def test_sibling_alias_reuse_still_merges_into_both(self):
        """The cycle guard is per-path: a non-cyclic dict reused by two
        sibling keys is NOT a cycle and must keep merging into both."""
        shared = {"k": 2, "n": 3}
        merged = config.deep_merge(
            {"a": {"k": 1, "keep": True}, "b": {"k": 1}},
            {"a": shared, "b": shared},
        )
        self.assertEqual(merged["a"], {"k": 2, "keep": True, "n": 3})
        self.assertEqual(merged["b"], {"k": 2, "n": 3})


class ConfigDiskStateTests(_DiskConfigSandbox):
    """Unreadable-but-present services.yaml: coded 503, file intact."""

    def test_torn_bytes_put_is_the_coded_503_and_bytes_stay_intact(self):
        torn = b"settings:\n  ip_aliases:\n    ips\xff\xfe: ["
        self._clear_yaml_node()
        config.YAML_PATH.write_bytes(torn)
        config.reload_cfg()
        self._reset_caches()
        # Readers degrade to defaults rather than 500ing the page...
        status = self.request_ok("GET", "/api/system/network/alias/auto")
        self.assertEqual(status["config"]["ips"], [])
        # ...while the mutating PUT refuses rather than wiping the file.
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": False},
            want=503,
        )
        self.assertEqual(
            payload["detail"]["code"], "settings.config_unreadable"
        )
        self.assertEqual(config.YAML_PATH.read_bytes(), torn)

    def test_oversize_put_is_the_coded_503_and_the_file_survives(self):
        self.write_yaml("keep: me\n")
        big = "# pad\nk: " + "a" * 2_000_000 + "\n"
        config.YAML_PATH.write_text(big, encoding="utf-8")
        config.reload_cfg()
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": False},
            want=503,
        )
        self.assertEqual(
            payload["detail"]["code"], "settings.config_unreadable"
        )
        self.assertEqual(
            config.YAML_PATH.read_text(encoding="utf-8"), big
        )

    def test_whole_document_paste_put_is_the_coded_503(self):
        self.write_yaml("- a\n- b\n")
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": False},
            want=503,
        )
        self.assertEqual(
            payload["detail"]["code"], "settings.config_unreadable"
        )
        self.assertEqual(
            config.YAML_PATH.read_text(encoding="utf-8"), "- a\n- b\n"
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_fifo_squatting_the_config_neither_hangs_nor_500s(self):
        """A FIFO at services.yaml holds no YAML to lose: the readers answer
        defaults immediately (O_NONBLOCK open, never a parked read) and the
        PUT clears the node and saves a fresh regular file."""
        self._clear_yaml_node()
        os.mkfifo(config.YAML_PATH)
        config.reload_cfg()
        self._reset_caches()
        status = self.request_ok("GET", "/api/system/network/alias/auto")
        self.assertEqual(status["config"]["ips"], [])
        self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": True}
        )
        self.assertTrue(config.YAML_PATH.is_file())
        section = (config.reload_cfg().get("settings") or {}).get("ip_aliases")
        self.assertIsInstance(section, dict)


class HostileJsonBodyTests(_DiskConfigSandbox):
    """Request-body poison answers 4xx — never the digit-cap / parse 500."""

    def setUp(self):
        super().setUp()
        self.write_yaml("settings: {}\n")

    def test_over_cap_int_body_is_a_400(self):
        # json.loads of a >4300-digit number raises ValueError, NOT
        # JSONDecodeError; the body-parse guard must catch it anyway.
        self.request_ok(
            "PUT", "/api/system/network/alias/auto",
            raw=('{"interval": ' + _HUGE_DIGITS + "}").encode(),
            want=400,
        )

    def test_infinity_and_nan_bodies_are_422(self):
        for raw in (b'{"interval": Infinity}', b'{"interval": NaN}'):
            self.request_ok(
                "PUT", "/api/system/network/alias/auto", raw=raw, want=422
            )

    def test_deeply_nested_body_is_a_400(self):
        self.request_ok(
            "PUT", "/api/system/network/alias/auto",
            raw=(b"[" * 20000) + (b"]" * 20000),
            want=400,
        )

    def test_surrogate_escaped_key_and_values_are_laundered(self):
        # json.loads happily produces lone-surrogate keys and values from
        # \\ud800 escapes; the PUT must scrub them, drop the junk ip, and
        # answer a strictly-decodable 200.
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto",
            raw=b'{"auto_bind": true, "\\ud800": 1,'
                b' "ips": ["\\ud800192.0.2.5", "192.0.2.44"],'
                b' "netmask": "\\ud800"}',
        )
        self.assertEqual(payload["config"]["ips"], ["192.0.2.44"])
        section = (config.reload_cfg().get("settings") or {}).get("ip_aliases")
        self.assertEqual(section.get("ips"), ["192.0.2.44"])

    def test_over_cap_int_bodies_on_sibling_mutations_are_400(self):
        for path in (
            "/api/system/network/order",
            "/api/system/network/docker/connect",
        ):
            self.request_ok(
                "POST", path,
                raw=('{"x": ' + _HUGE_DIGITS + "}").encode(),
                want=400,
            )


class OnDiskYamlTypeZooTests(_DiskConfigSandbox):
    """Hostile YAML types through the REAL file (net5 mocked this boundary)."""

    _ZOO = (
        "settings:\n"
        "  ip_aliases:\n"
        "    auto_bind: 2026-08-19\n"
        "    ips: !!set {'192.0.2.44': null, 8080: null}\n"
        "    netmask: !!binary |\n"
        "      MjU1LjI1NS4yNTUuMA==\n"
        "    interval: 0x" + "f" * 4400 + "\n"
        "    prefer_wired: .nan\n"
        "  network_failover:\n"
        "    enabled: true\n"
        "    interval: .inf\n"
        "    fail_threshold: " + _HUGE_DIGITS + "\n"
        "    probe_timeout_ms: 2026-08-19\n"
        "    power_save_wifi: !!binary |\n"
        "      AA==\n"
    )

    def test_the_zoo_degrades_to_defaults_on_every_surface(self):
        self.write_yaml(self._ZOO)
        status = self.request_ok("GET", "/api/system/network/alias/auto")
        # !!set iterates fine but no member is a valid ip once scrubbed to
        # text; the !!binary netmask decodes instead of becoming b'…' junk.
        self.assertEqual(status["config"]["netmask"], "255.255.255.0")
        # The already-int over-cap hex interval degrades to the default
        # instead of ValueError-ing json.dumps at render time.
        self.assertEqual(status["config"]["interval"], 60)
        self.request_ok("POST", "/api/system/network/alias/auto/run")
        failover = self.request_ok("GET", "/api/system/network/failover")
        # .inf interval clamps; the >4300-digit threshold coerces then clamps.
        self.assertEqual(failover["config"]["interval"], 15)
        self.assertEqual(failover["config"]["fail_threshold"], 2)
        self.assertEqual(failover["config"]["probe_timeout_ms"], 1200)
        run = self.request_ok("POST", "/api/system/network/failover/run")
        self.assertTrue(run["enabled"])
        overview = self.request_ok("GET", "/api/system/network")
        self.assertIn("alias_auto", overview)

    def test_partial_put_over_the_zoo_still_saves(self):
        self.write_yaml(self._ZOO)
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"auto_bind": True}
        )
        self.assertIs(payload["config"]["auto_bind"], True)
        # The write-back must leave a loadable file with the over-cap hex
        # int dropped by the dump retry, so later saves are not wedged.
        written = config.YAML_PATH.read_text(encoding="utf-8")
        self.assertNotIn("f" * 100, written)
        section = (config.reload_cfg().get("settings") or {}).get("ip_aliases")
        self.assertIsInstance(section, dict)
        self.assertIs(section.get("auto_bind"), True)

    def test_omap_tuples_and_junk_section_keys_stay_200(self):
        self.write_yaml(
            "settings:\n"
            "  ip_aliases:\n"
            "    auto_bind: true\n"
            "    ips: !!omap\n"
            "      - '192.0.2.44': 1\n"
            "    1: intkey\n"
            "    ~: nullkey\n"
            "    2026-08-19: datekey\n"
            "    netmask: [255, 255, 255, 0]\n"
        )
        status = self.request_ok("GET", "/api/system/network/alias/auto")
        # omap loads as (key, value) tuples — not valid ips, dropped.
        self.assertEqual(status["config"]["ips"], [])
        self.assertEqual(status["config"]["netmask"], "255.255.255.255")
        self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"interval": 90}
        )
        section = (config.reload_cfg().get("settings") or {}).get("ip_aliases")
        self.assertEqual(section.get("interval"), 90)


class CfgSubclassBombStaysImmuneTests(_DiskConfigSandbox):
    """A cfg() root wearing a bombing dict subclass never reaches the readers."""

    def test_bombing_cfg_root_keeps_alias_status_200(self):
        class Bomb(dict):
            def get(self, *args, **kwargs):
                raise RuntimeError("get bomb")

            def keys(self):
                raise RuntimeError("keys bomb")

            def items(self):
                raise RuntimeError("items bomb")

            def __bool__(self):
                raise RuntimeError("bool bomb")

        root = Bomb(
            settings=Bomb(
                ip_aliases=Bomb(auto_bind=True, ips=["192.0.2.44"]),
                network_failover=Bomb(enabled=False),
            )
        )
        with mock.patch("hub.config.cfg", return_value=root):
            status = self.request_ok("GET", "/api/system/network/alias/auto")
            self.assertEqual(status["config"]["ips"], ["192.0.2.44"])
            failover = self.request_ok("GET", "/api/system/network/failover")
            self.assertIs(failover["config"]["enabled"], False)


if __name__ == "__main__":
    unittest.main()
