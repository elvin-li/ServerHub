"""A pf.conf edit that pf refuses is worse than no edit at all.

pf groups rules into classes and rejects a file that presents them out of order:
options, normalization, queueing, translation, filtering.  ``nat-anchor`` is
translation and ``anchor`` is filtering, so appending both to the end of Apple's
default ``/etc/pf.conf`` -- which already ends with filter anchors and loads --
puts a translation rule after a filter rule.  pfctl then rejects **the whole
file**, so the failure is not "NAT was not added" but "no pf rule on this machine
can be loaded any more".

Found on the real host, from a file the panel itself had written:

    /etc/pf.conf:12: Rules must be in order: options, normalization, queueing,
    translation, filtering

with the anchor wired in twice -- once correctly by an earlier build, once
appended out of order by a later one -- while the panel reported NAT as installed,
because it only ever checked that the anchor file and a reference to it existed.

``pfctl -n -f`` parses without loading and needs no privileges whatsoever, so
these are all checkable before anything goes near /etc.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import wireguard_net_svc as net  # noqa: E402

#: Apple's stock file, which is what this has to stay compatible with.
APPLE_PF_CONF = """scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
"""

TRANSLATION = re.compile(r"^\s*(?:nat|rdr|binat)(?:-anchor)?\b")
FILTER = re.compile(r"^\s*(?:anchor|pass|block|match|antispoof)\b")


def _classes(text: str) -> list[str]:
    """Sequence of rule classes in *text*, ignoring loads and comments."""
    out = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.strip().startswith("load "):
            continue
        if TRANSLATION.match(line):
            out.append("translation")
        elif FILTER.match(line):
            out.append("filter")
        elif line.strip().startswith("scrub"):
            out.append("normalization")
    return out


class OrderingTests(unittest.TestCase):
    def test_translation_never_follows_filtering(self):
        """The invariant pf enforces, asserted directly on the generated text."""
        rendered = net.render_pf_conf(APPLE_PF_CONF)
        classes = _classes(rendered)
        first_filter = classes.index("filter")
        self.assertNotIn(
            "translation",
            classes[first_filter:],
            f"a translation rule follows a filter rule; pf will reject the file:\n{rendered}",
        )

    def test_the_nat_anchor_is_not_appended_at_the_end(self):
        """The specific mistake: correct content, fatal placement."""
        rendered = net.render_pf_conf(APPLE_PF_CONF)
        lines = [line for line in rendered.splitlines() if line.strip()]
        nat_line = next(i for i, line in enumerate(lines) if line.startswith("nat-anchor \"serverhub"))
        apple_filter = next(i for i, line in enumerate(lines) if line.startswith("anchor \"com.apple"))
        self.assertLess(nat_line, apple_filter)

    def test_all_three_directives_are_present(self):
        rendered = net.render_pf_conf(APPLE_PF_CONF)
        self.assertIn(f'nat-anchor "{net.ANCHOR_NAME}"', rendered)
        self.assertIn(f'anchor "{net.ANCHOR_NAME}"', rendered)
        self.assertIn(f'load anchor "{net.ANCHOR_NAME}" from', rendered)

    def test_a_file_with_no_translation_rules_still_orders_correctly(self):
        """The nat-anchor has to go *before* the first filter rule, not after the last."""
        rendered = net.render_pf_conf('anchor "com.apple/*"\n')
        classes = _classes(rendered)
        self.assertEqual(classes.index("translation"), 0)
        self.assertNotIn("translation", classes[classes.index("filter"):])

    def test_an_empty_file_is_handled(self):
        rendered = net.render_pf_conf("")
        self.assertIn(f'nat-anchor "{net.ANCHOR_NAME}"', rendered)


class IdempotenceTests(unittest.TestCase):
    def test_installing_twice_does_not_duplicate_the_anchor(self):
        once = net.render_pf_conf(APPLE_PF_CONF)
        twice = net.render_pf_conf(once)
        self.assertEqual(once, twice)
        self.assertEqual(twice.count(f'nat-anchor "{net.ANCHOR_NAME}"'), 1)

    def test_a_pre_existing_unmarked_reference_is_absorbed_not_duplicated(self):
        """Exactly the state the real host was in: wired in twice, one copy bad.

        The earlier references carry no marker of this panel's, so removing only
        marked lines would have left them in place and added a third copy.
        """
        messy = (
            'scrub-anchor "com.apple/*"\n'
            'nat-anchor "com.apple/*"\n'
            f'nat-anchor "{net.ANCHOR_NAME}"\n'
            'rdr-anchor "com.apple/*"\n'
            'anchor "com.apple/*"\n'
            f'anchor "{net.ANCHOR_NAME}"\n'
            'load anchor "com.apple" from "/etc/pf.anchors/com.apple"\n'
            f'load anchor "{net.ANCHOR_NAME}" from "{net.PF_ANCHOR_PATH}"\n'
            "\n"
            f"{net.PF_MARKER}\n"
            f'nat-anchor "{net.ANCHOR_NAME}"\n'
            f'anchor "{net.ANCHOR_NAME}"\n'
            f'load anchor "{net.ANCHOR_NAME}" from "{net.PF_ANCHOR_PATH}"\n'
        )
        rendered = net.render_pf_conf(messy)
        # Counted per line, not by substring: `load anchor "x"` contains
        # `anchor "x"`, so a substring count cannot tell the three directives apart.
        starts = [line.strip() for line in rendered.splitlines()]
        for directive in (
            f'nat-anchor "{net.ANCHOR_NAME}"',
            f'anchor "{net.ANCHOR_NAME}"',
            f'load anchor "{net.ANCHOR_NAME}"',
        ):
            self.assertEqual(
                sum(1 for line in starts if line.startswith(directive)),
                1,
                f"{directive} appears more than once:\n{rendered}",
            )
        classes = _classes(rendered)
        self.assertNotIn("translation", classes[classes.index("filter"):])

    def test_apples_own_anchors_survive_untouched(self):
        rendered = net.render_pf_conf(APPLE_PF_CONF)
        for line in APPLE_PF_CONF.splitlines():
            self.assertIn(line, rendered)

    def test_removal_takes_every_reference_including_unmarked_ones(self):
        rendered = net.render_pf_conf(APPLE_PF_CONF)
        stripped = "\n".join(net._without_our_lines(rendered))
        self.assertNotIn(net.ANCHOR_NAME, stripped)
        self.assertIn('anchor "com.apple/*"', stripped)


@unittest.skipUnless(
    Path("/sbin/pfctl").exists(), "pfctl only exists on macOS"
)
class ParserTests(unittest.TestCase):
    """The generator is checked against pf's actual parser, not just our model of it.

    ``pfctl -n`` parses without loading and without privileges, which is why there
    was never an excuse for shipping an unvalidated edit.
    """

    def _parse(self, body: str) -> tuple[int, str]:
        with TemporaryDirectory() as tmp:
            anchor = Path(tmp) / "anchor"
            anchor.write_text("nat on en0 inet from 10.10.0.0/24 to any -> (en0)\n")
            conf = Path(tmp) / "pf.conf"
            conf.write_text(body.replace(f'from "{net.PF_ANCHOR_PATH}"', f'from "{anchor}"'))
            proc = subprocess.run(
                ["/sbin/pfctl", "-n", "-f", str(conf)],
                capture_output=True, text=True, timeout=20,
            )
            return proc.returncode, (proc.stderr or "") + (proc.stdout or "")

    def test_the_generated_file_parses(self):
        rc, output = self._parse(net.render_pf_conf(APPLE_PF_CONF))
        self.assertEqual(rc, 0, output)

    def test_the_old_appending_behaviour_really_did_not_parse(self):
        """Guards the regression rather than merely describing it."""
        broken = APPLE_PF_CONF + (
            f"\n{net.PF_MARKER}\n"
            f'nat-anchor "{net.ANCHOR_NAME}"\n'
            f'anchor "{net.ANCHOR_NAME}"\n'
            f'load anchor "{net.ANCHOR_NAME}" from "{net.PF_ANCHOR_PATH}"\n'
        )
        rc, output = self._parse(broken)
        self.assertNotEqual(rc, 0)
        self.assertIn("Rules must be in order", output)


class SupersededCheckTests(unittest.TestCase):
    """A readiness list must not report both ends of a cause-and-effect pair.

    Several gates sit downstream of one another: NAT cannot be loaded out of a
    pf.conf that pf refuses to parse, and an endpoint cannot resolve to the right
    address when none is configured.  Listing both produced two rows carrying the
    same text -- and for pf, the same button -- which reads as the panel repeating
    itself and leaves the operator guessing which one to act on.
    """

    def _readiness(self, **overrides):
        nat = {
            "anchor_path": "/etc/pf.anchors/serverhub-wireguard",
            "anchor_exists": True,
            "referenced": True,
            "complete": False,
            "on_disk": True,
            "wiring_ok": True,
            "conf_parses": False,
            "conf_error": "/etc/pf.conf:12: Rules must be in order",
            "loaded": None,
            "anchor_body": "",
        }
        nat.update(overrides.get("nat") or {})
        daemon = {
            "label": "com.wireguard.wg0",
            "plist_path": "/Library/LaunchDaemons/com.wireguard.wg0.plist",
            "installed": True,
            "loaded": True,
            "managed": True,
            "respawn_loop": False,
        }
        settings = {
            "interface": "wg0", "subnet": "10.10.0.0/24", "listen_port": 51820,
            "dns": "", "mtu": 1280, "keepalive": 25,
            "endpoint": overrides.get("endpoint", ""), "lan_cidr": "",
            "wan_interface": "en0",
        }
        with (
            patch.object(net, "nat_installed", return_value=nat),
            patch.object(net, "daemon_state", return_value=daemon),
            patch.object(net, "forwarding_enabled", return_value=True),
            patch.object(net, "pf_enabled", return_value=False),
            patch.object(net, "wan_interface", return_value="en0"),
            patch.object(
                net, "peer_origin_conflict",
                return_value={"conflict": False, "reason": "", "foreign": 0, "total": 1},
            ),
            patch.object(
                net, "endpoint_resolution",
                return_value=overrides.get("resolution") or {
                    "endpoint": "", "resolved": [], "unreachable": [], "suggest": [],
                    "ok": False, "reason": "not_set",
                },
            ),
            patch.object(net.wireguard_svc, "settings", return_value=settings),
            patch.object(
                net.wireguard_svc, "installation",
                return_value={
                    "installed": True, "conf_exists": True, "tools_version": "v1",
                    "conf_path": "/x/wg0.conf",
                },
            ),
            patch.object(
                net.wireguard_svc, "status",
                return_value={"running": True, "state_error": ""},
            ),
            patch.object(
                net.wireguard_svc, "runtime_state",
                return_value={
                    "stale": False, "name_file": "", "real_interface": "utun8",
                    "live": True,
                },
            ),
        ):
            return net.readiness()

    def test_nat_is_not_reported_alongside_the_parse_failure_it_causes(self):
        result = self._readiness()
        ids = [c["id"] for c in result["checks"]]
        self.assertIn("pf_conf", ids)
        self.assertNotIn("nat", ids)
        self.assertEqual(result["blocking"].count("pf_conf"), 1)

    def test_pf_enabled_is_not_reported_either(self):
        """pf cannot be switched on out of a file it will not parse."""
        self.assertNotIn("pf", [c["id"] for c in self._readiness()["checks"]])

    def test_the_root_cause_is_listed_before_its_symptom(self):
        """Order carries meaning: the actionable row has to come first."""
        result = self._readiness(nat={"conf_parses": True, "complete": False})
        ids = [c["id"] for c in result["checks"]]
        self.assertLess(ids.index("pf_conf"), ids.index("nat"))

    def test_nat_reappears_once_the_file_parses(self):
        result = self._readiness(nat={"conf_parses": True, "complete": False})
        self.assertIn("nat", result["blocking"])

    def test_endpoint_resolution_is_not_reported_while_no_endpoint_is_set(self):
        result = self._readiness()
        self.assertIn("endpoint", result["blocking"])
        self.assertNotIn("endpoint_resolves", [c["id"] for c in result["checks"]])

    def test_endpoint_resolution_is_reported_once_one_is_set(self):
        result = self._readiness(
            endpoint="vpn.example",
            resolution={
                "endpoint": "vpn.example", "resolved": ["2001:4860::1"],
                "unreachable": ["2001:4860::1"], "ok": False,
                "reason": "not_this_host", "suggest": [],
            },
        )
        self.assertNotIn("endpoint", result["blocking"])
        self.assertIn("endpoint_resolves", result["blocking"])

    def test_no_check_id_appears_twice(self):
        for kwargs in ({}, {"nat": {"conf_parses": True}}):
            ids = [c["id"] for c in self._readiness(**kwargs)["checks"]]
            self.assertEqual(len(ids), len(set(ids)), ids)

    def test_the_internal_supersede_marker_is_not_exposed(self):
        for check in self._readiness()["checks"]:
            self.assertNotIn("superseded_by", check)


class DaemonPlistTests(unittest.TestCase):
    """`wg-quick up` is not a daemon, so KeepAlive turns it into a respawn loop."""

    def _body(self) -> str:
        return net.render_daemon_plist(
            "com.wireguard.wg0",
            "/opt/homebrew/etc/wireguard/wg0.conf",
            "/opt/homebrew/bin/bash",
            "/opt/homebrew/bin/wg-quick",
        )

    def test_keepalive_is_absent(self):
        """Homebrew's template pairs KeepAlive with `wg-quick up`.

        `wg-quick up` exits as soon as the interface is configured, so launchd
        restarts it, the next run finds the interface it just created and dies with
        "`wg0' already exists as `utun8'", forever.  The real host's
        /var/log/wireguard-wg0.log was a wall of exactly that.
        """
        self.assertNotIn("KeepAlive", self._body())

    def test_it_runs_at_load(self):
        self.assertIn("<key>RunAtLoad</key>", self._body())

    def test_wg_quick_is_launched_through_a_modern_bash(self):
        # Its `#!/usr/bin/env bash` shebang finds Apple's bash 3.2 under a
        # scrubbed PATH, which wg-quick refuses to run under.
        body = self._body()
        self.assertIn("<string>/opt/homebrew/bin/bash</string>", body)
        self.assertLess(
            body.index("/opt/homebrew/bin/bash"), body.index("/opt/homebrew/bin/wg-quick")
        )

    def test_it_is_valid_plist_xml(self):
        import plistlib

        parsed = plistlib.loads(self._body().encode())
        self.assertEqual(parsed["Label"], "com.wireguard.wg0")
        self.assertEqual(parsed["UserName"], "root")
        self.assertTrue(parsed["RunAtLoad"])
        self.assertNotIn("KeepAlive", parsed)

    def test_a_respawning_plist_is_reported_rather_than_accepted(self):
        homebrew_style = self._body().replace(
            "<key>RunAtLoad</key>\n    <true/>",
            "<key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>",
        )
        with (
            patch.object(net, "sh", return_value=(1, "", "")),
            patch.object(net, "sudo_capture", return_value=(1, "", "")),
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "read_text", return_value=homebrew_style),
            patch.object(net.wireguard_svc, "settings", return_value={"interface": "wg0"}),
        ):
            state = net.daemon_state()
        self.assertTrue(state["respawn_loop"])
        self.assertFalse(state["managed"])


class EndpointResolutionTests(unittest.TestCase):
    """The endpoint clients are told to dial has to lead back to this host.

    On the real host everything server-side was correct and no client could
    connect: the endpoint's AAAA record pointed into a different /64 than the one
    this machine holds, and clients follow RFC 6724 and prefer IPv6, so essentially
    every phone dialled an address that was not this server.  "endpoint is set" was
    the whole of the old check, so nothing in the panel could say so.
    """

    def _resolve(self, endpoint: str, resolved: list[str], local: set[str]) -> dict:
        infos = [(None, None, None, None, (address, 0)) for address in resolved]
        with (
            patch.object(net.wireguard_svc, "settings", return_value={"endpoint": endpoint}),
            patch.object(net.socket, "getaddrinfo", return_value=infos),
            patch.object(net, "_local_addresses", return_value=local),
        ):
            return net.endpoint_resolution()

    def test_a_v6_endpoint_outside_every_local_prefix_is_rejected(self):
        # The real values from the host this was written for.
        result = self._resolve(
            "vpn.example",
            ["2408:8248:1e84:400a::1"],
            {"2408:8248:1e43:8080::215"},
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "not_this_host")
        self.assertEqual(result["unreachable"], ["2408:8248:1e84:400a::1"])

    def test_a_v6_endpoint_that_is_a_local_address_is_accepted(self):
        result = self._resolve(
            "vpn.example",
            ["2408:8248:1e43:8080::215"],
            {"2408:8248:1e43:8080::215"},
        )
        self.assertTrue(result["ok"])

    def test_a_public_v4_endpoint_is_not_failed(self):
        """A NAT'd server cannot see its own public IPv4, so this is unknowable.

        Reporting it as broken would put a permanent false error in front of every
        correctly configured installation.
        """
        # A genuinely globally routable address: Python's `is_private` also covers
        # the documentation ranges (192.0.2.0/24, 203.0.113.0/24, 2001:db8::/32),
        # so those cannot stand in for "public" here.
        result = self._resolve("vpn.example", ["93.184.216.34"], {"192.168.1.206"})
        self.assertTrue(result["ok"])

    def test_a_private_endpoint_is_rejected(self):
        result = self._resolve("vpn.example", ["192.168.1.206"], {"192.168.1.206"})
        self.assertFalse(result["ok"])

    def test_a_v6_mismatch_is_ignored_when_the_host_has_no_global_v6(self):
        """Without a local address to compare against there is nothing to conclude."""
        result = self._resolve(
            "vpn.example", ["2606:4700:4700::1111"], {"192.168.1.206"}
        )
        self.assertTrue(result["ok"])

    def test_a_name_that_does_not_resolve_is_reported(self):
        with (
            patch.object(
                net.wireguard_svc, "settings", return_value={"endpoint": "nope.invalid"}
            ),
            patch.object(net.socket, "getaddrinfo", side_effect=OSError),
            patch.object(net, "_local_addresses", return_value=set()),
        ):
            result = net.endpoint_resolution()
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "dns_failed")

    def test_a_port_suffix_is_stripped_before_resolving(self):
        result = self._resolve("vpn.example:51821", ["203.0.113.7"], set())
        self.assertEqual(result["endpoint"], "vpn.example")


if __name__ == "__main__":
    unittest.main()


class DaemonDetailTests(unittest.TestCase):
    """"A boot job is installed" and "it is the job we manage" are different facts.

    The variant found on the real host wrapped the command in
    ``bash -c '... && exec sleep infinity'``.  It does bring the tunnel up at boot,
    so it is not a failure -- but the lingering process is what launchd counts as
    the job running, so stopping the tunnel from the panel leaves launchd reporting
    a running job against a stopped tunnel and makes ``kickstart`` a no-op.
    Reporting only the plist path gave the operator no way to tell that apart from
    the job the panel would have written.
    """

    def _daemon(self, **overrides) -> dict:
        base = {
            "label": "com.wireguard.wg0",
            "plist_path": "/Library/LaunchDaemons/com.wireguard.wg0.plist",
            "installed": True,
            "loaded": True,
            "managed": True,
            "respawn_loop": False,
        }
        base.update(overrides)
        return base

    def test_the_managed_job_reports_just_its_path(self):
        self.assertEqual(
            net._daemon_detail(self._daemon()),
            "/Library/LaunchDaemons/com.wireguard.wg0.plist",
        )

    def test_a_foreign_job_is_named_as_such(self):
        detail = net._daemon_detail(self._daemon(managed=False))
        self.assertIn("not the job this panel manages", detail)

    def test_a_respawn_loop_outranks_the_managed_notice(self):
        """The loop is the actionable fault; say that, not "not ours"."""
        detail = net._daemon_detail(self._daemon(managed=False, respawn_loop=True))
        self.assertIn("loop", detail)
        self.assertNotIn("not the job", detail)

    def test_an_absent_job_reports_where_it_would_go(self):
        detail = net._daemon_detail(self._daemon(installed=False, managed=False))
        self.assertEqual(detail, "/Library/LaunchDaemons/com.wireguard.wg0.plist")

    def test_a_foreign_job_is_not_treated_as_a_failure(self):
        """It does start the tunnel at boot, so `ok` must stay true."""
        with (
            patch.object(net, "daemon_state", return_value=self._daemon(managed=False)),
            patch.object(net, "nat_installed", return_value={
                "anchor_path": "/x", "anchor_exists": True, "referenced": True,
                "complete": True, "on_disk": True, "wiring_ok": True,
                "conf_parses": True, "conf_error": "", "loaded": True,
                "anchor_body": "",
            }),
            patch.object(net, "forwarding_enabled", return_value=True),
            patch.object(net, "pf_enabled", return_value=True),
            patch.object(net, "wan_interface", return_value="en0"),
            patch.object(net, "peer_origin_conflict", return_value={
                "conflict": False, "reason": "", "foreign": 0, "total": 1,
            }),
            patch.object(net, "endpoint_resolution", return_value={
                "endpoint": "vpn.example", "resolved": ["93.184.216.34"],
                "unreachable": [], "ok": True, "reason": "",
            }),
            patch.object(net.wireguard_svc, "settings", return_value={
                "interface": "wg0", "subnet": "10.10.0.0/24", "listen_port": 51820,
                "dns": "", "mtu": 1280, "keepalive": 25, "endpoint": "vpn.example",
                "lan_cidr": "", "wan_interface": "en0",
            }),
            patch.object(net.wireguard_svc, "installation", return_value={
                "installed": True, "conf_exists": True, "tools_version": "v1",
                "conf_path": "/x/wg0.conf",
            }),
            patch.object(net.wireguard_svc, "status", return_value={
                "running": True, "state_error": "",
            }),
            patch.object(net.wireguard_svc, "runtime_state", return_value={
                "stale": False, "name_file": "", "real_interface": "utun8",
                "live": True,
            }),
        ):
            result = net.readiness()
        boot = next(c for c in result["checks"] if c["id"] == "boot")
        self.assertTrue(boot["ok"])
        self.assertIn("not the job this panel manages", boot["detail"])
        self.assertTrue(result["ready"], result["blocking"])


class EndpointSuggestionTests(unittest.TestCase):
    """Naming the address the record should point at, not just that it is wrong.

    "not this host" leaves the operator to find the right address, and the obvious
    way to do that -- read ifconfig, pick a global v6 -- picks a *temporary privacy
    address* most of the time, because macOS holds several in the same /64 at once
    and rotates them within a day or two.  A record pointing at one works this
    afternoon and fails tomorrow, which is a worse outcome than no suggestion.
    """

    #: Real output shape from the host this was written for.
    IFCONFIG = """en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.206 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 fe80::53:2cad:c272:7ad2%en7 prefixlen 64 secured scopeid 0x13
	inet6 2408:8248:1e43:8080:40c:dda6:c436:609b prefixlen 64 autoconf secured
	inet6 2408:8248:1e43:8080:61ef:809b:162c:dfec prefixlen 64 deprecated autoconf temporary
	inet6 2408:8248:1e43:8080::215 prefixlen 64 dynamic
	inet6 2408:8248:1e43:8080:145e:4e16:a93c:6b23 prefixlen 64 autoconf temporary
	inet6 fd07:b51a:cc66:0:a617:db5e:ab7:e9f1 prefixlen 64 dynamic
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet6 ::1 prefixlen 128
	inet 127.0.0.1 netmask 0xff000000
"""

    def _suggestions(self, output: str = "") -> list[str]:
        with patch.object(net, "sh", return_value=(0, output or self.IFCONFIG, "")):
            return net.stable_local_addresses()

    def test_the_dhcp_or_manual_address_is_recommended_first(self):
        """`dynamic` outlives the prefix churn that rotates the others."""
        self.assertEqual(self._suggestions()[0], "2408:8248:1e43:8080::215")

    def test_a_secured_autoconf_address_is_the_second_choice(self):
        self.assertEqual(
            self._suggestions()[1], "2408:8248:1e43:8080:40c:dda6:c436:609b"
        )

    def test_temporary_and_deprecated_addresses_are_never_recommended(self):
        for address in self._suggestions():
            self.assertNotIn("61ef", address)   # deprecated temporary
            self.assertNotIn("145e", address)   # live temporary

    def test_a_unique_local_address_is_never_recommended(self):
        """fc00::/7 is bound to the interface and unreachable from outside.

        It is `dynamic`, so a rank-only ordering would put it near the top -- and
        suggesting it is worse than suggesting nothing, because it looks like an
        answer.
        """
        for address in self._suggestions():
            self.assertFalse(
                ipaddress.ip_address(address).is_private, f"{address} is not routable"
            )

    def test_loopback_and_link_local_are_excluded(self):
        joined = " ".join(self._suggestions())
        self.assertNotIn("::1", joined)
        self.assertNotIn("fe80", joined)

    def test_ipv4_is_not_offered_as_a_v6_record_value(self):
        for address in self._suggestions():
            self.assertIn(":", address)

    def test_a_host_with_no_global_v6_suggests_nothing(self):
        only_v4 = "en0: flags=8863 mtu 1500\n\tinet 192.168.1.5 netmask 0xffffff00\n"
        self.assertEqual(self._suggestions(only_v4), [])

    def test_the_detail_names_the_address_to_use(self):
        resolution = {
            "endpoint": "vpn.example",
            "resolved": ["2408:8248:1e84:400a::1"],
            "unreachable": ["2408:8248:1e84:400a::1"],
            "ok": False,
            "reason": "not_this_host",
            "suggest": ["2408:8248:1e43:8080::215"],
        }
        detail = net._resolution_detail(resolution)
        self.assertIn("not this host", detail)
        self.assertIn("2408:8248:1e43:8080::215", detail)

    def test_no_suggestion_leaves_the_detail_unchanged(self):
        resolution = {
            "endpoint": "vpn.example",
            "resolved": ["192.168.1.5"],
            "unreachable": ["192.168.1.5"],
            "ok": False,
            "reason": "not_this_host",
            "suggest": [],
        }
        self.assertNotIn("this host is", net._resolution_detail(resolution))

    def test_a_v4_only_mismatch_does_not_suggest_a_v6_address(self):
        """The record that is wrong is the A record; a AAAA is not the fix."""
        infos = [(None, None, None, None, ("192.168.1.9", 0))]
        with (
            patch.object(
                net.wireguard_svc, "settings", return_value={"endpoint": "vpn.example"}
            ),
            patch.object(net.socket, "getaddrinfo", return_value=infos),
            patch.object(net, "_local_addresses", return_value={"192.168.1.206"}),
        ):
            result = net.endpoint_resolution()
        self.assertFalse(result["ok"])
        self.assertEqual(result["suggest"], [])
