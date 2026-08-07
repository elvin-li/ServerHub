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
                    "endpoint": "", "resolved": [], "unreachable": [],
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
                "reason": "not_this_host",
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
