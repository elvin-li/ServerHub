"""The sudoers template must not hardcode an account, and must cover what we run.

The copy installed on this machine granted its rules to a user named "serverhub"
while the panel ran as a different account, so every narrowed rule silently missed.
The features that needed them fell back to either an interactive password prompt --
impossible to answer from a web request -- or to a separate, far broader grant
(`NOPASSWD: /opt/homebrew/bin/smartctl`, unrestricted) that made the narrowing
pointless: smartctl's -s, -t and -X verbs write to the device.

Two invariants are pinned here. The template stays account-agnostic, and every
command the code actually runs under `sudo -n` has a matching rule -- because a
missing rule does not fail loudly, it just makes a feature quietly stop working.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

TEMPLATE = BASE / "deploy" / "sudoers.d" / "serverhub"
INSTALLER = BASE / "deploy" / "install-sudoers.sh"


def template_text() -> str:
    return TEMPLATE.read_text()


class TemplateIsAccountAgnosticTests(unittest.TestCase):
    def test_the_user_line_is_a_placeholder(self):
        text = template_text()
        self.assertIn("__SERVERHUB_USER__ ALL=(root) NOPASSWD:", text)

    def test_no_hardcoded_home_directory(self):
        """A path under /Users/<name> is the same bug in another shape."""
        offenders = [
            line for line in template_text().splitlines()
            if re.search(r"/Users/(?!__SERVERHUB)[A-Za-z0-9_.-]+", line)
            and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            offenders, [], "hardcoded home path in a rule:\n" + "\n".join(offenders)
        )

    def test_no_bare_account_name_grants(self):
        grants = [
            line for line in template_text().splitlines()
            if re.match(r"^[A-Za-z0-9_.-]+\s+ALL=", line)
        ]
        for line in grants:
            self.assertTrue(
                line.startswith("__SERVERHUB_USER__"),
                f"grant is bound to a literal account: {line}",
            )

    def test_installer_substitutes_both_placeholders(self):
        script = INSTALLER.read_text()
        for placeholder in ("__SERVERHUB_USER__", "__SERVERHUB_STATE__"):
            self.assertIn(placeholder, script, f"installer never substitutes {placeholder}")
        self.assertIn("visudo -cf", script, "installer must validate before installing")

    def test_installer_refuses_to_ship_an_unsubstituted_file(self):
        self.assertRegex(
            INSTALLER.read_text(),
            r'grep -q "__SERVERHUB_"',
            "installer does not check for leftover placeholders",
        )


class RulesCoverWhatWeRunTests(unittest.TestCase):
    """Every `sudo -n` command in hub/ needs a rule, or the feature dies silently."""

    def setUp(self):
        self.text = template_text()

    def assertGranted(self, needle: str, why: str):
        self.assertIn(needle, self.text, f"no sudoers rule for {needle!r} -- {why}")

    def test_smart_health_reads(self):
        for verb in ("-a ^/dev/", "-H ^/dev/", "-n standby ^/dev/"):
            self.assertGranted(f"smartctl {verb}", "storage health page")

    def test_smart_self_test_control(self):
        # `smartctl -t` and -X write to the device, so these are the rules that
        # replace the old blanket smartctl grant rather than adding to it.
        for verb in ("-t short ^/dev/", "-t long ^/dev/", "-X ^/dev/"):
            self.assertGranted(f"smartctl {verb}", "SMART self-tests")

    def test_smart_transport_flag_variants_are_enumerated(self):
        """An anchored device regex matches one argv element, so `-d nvme` needs its own rule."""
        for verb in ("-t short -d nvme ^/dev/", "-X -d nvme ^/dev/", "-c -d nvme ^/dev/"):
            self.assertGranted(f"smartctl {verb}", "NVMe transport flag")

    def test_smart_device_argument_is_anchored(self):
        """A trailing `/dev/*` is a suffix wildcard, not a one-token placeholder.

        Verified on macOS sudo 1.9.17p2: `smartctl -a /dev/*` also matches
        `smartctl -a /dev/disk0 -V`, so any verb can be smuggled behind a
        read-only one.  The anchored regex matches exactly one argv element and
        sits in the last (only legal) regex position.
        """
        offenders = [
            stripped
            for line in self.text.splitlines()
            if (stripped := line.strip().rstrip(", \\").rstrip()).startswith(
                "/opt/homebrew/bin/smartctl"
            )
            and not stripped.endswith("-V")
            and not stripped.endswith("$")
        ]
        self.assertEqual(
            offenders,
            [],
            "smartctl rules whose device argument is not an anchored regex:\n"
            + "\n".join(offenders),
        )

    def test_smart_version_probe(self):
        # passwordless_available() runs this to decide whether scheduled tests can
        # run headless; without a rule it reports "no" and silently disables them.
        # Note: no trailing "" here -- see test_no_trailing_empty_string_argument.
        self.assertGranted("smartctl -V,", "passwordless capability probe")

    def test_wireguard_state_read(self):
        # Without this the WireGuard page can only ever report "not running".
        self.assertGranted("wg show wg0 dump,", "WireGuard peer state")

    def test_no_trailing_wildcard_argument(self):
        """A rule ending in `*` is a prefix grant, not a pinned one.

        sudo treats a trailing wildcard as a suffix match over ALL remaining
        argv elements (verified on macOS sudo 1.9.17p2): `networksetup
        -getairportpower *` also matches `-getairportpower en0 evil2 evil3`.
        Every rule must therefore end in a literal token or an anchored regex.
        A `*` is only tolerated mid-rule, where it matches exactly one element,
        and only when a fixed tail argument follows it.
        """
        offenders = []
        for line in self.text.splitlines():
            stripped = line.strip().rstrip(", \\").rstrip()
            if stripped.startswith("/") and stripped.endswith("*"):
                offenders.append(stripped)
        self.assertEqual(
            offenders,
            [],
            "rules ending in a wildcard grant every extra argument:\n"
            + "\n".join(offenders),
        )

    def test_no_trailing_empty_string_argument(self):
        """A \"\" after real arguments is a phantom argv element that never matches.

        sudoers only defines \"\" as \"no arguments allowed\" when it is the sole
        argument of a rule.  macOS sudo 1.9.17p2 refuses to match rules that
        append it after real arguments at runtime, while `sudo -l` still lists
        them -- exactly the bug that made the WireGuard page show "not running"
        despite a live tunnel.  An explicit argument list already rejects extra
        arguments, so the "" bought no security, only breakage.
        """
        offenders = []
        for line in self.text.splitlines():
            stripped = line.strip().rstrip(", \\").rstrip()
            if stripped.startswith("/") and stripped.endswith('""'):
                offenders.append(stripped)
        self.assertEqual(
            offenders,
            [],
            'rules ending in "" after other arguments never match at runtime:'
            "\n" + "\n".join(offenders),
        )

    def test_wireguard_config_apply_is_path_pinned(self):
        self.assertGranted("wg syncconf wg0 __SERVERHUB_STATE__/data/wg0.sync.conf", "peer reload")
        self.assertNotIn(
            "wg syncconf wg0 *", self.text,
            "a wildcard path would let any file be loaded as an interface config",
        )

    def test_wg_quick_is_path_pinned(self):
        # wg-quick executes PostUp/PostDown from its config file as root, so a
        # wildcard here would be arbitrary code execution as root.
        self.assertGranted("wg-quick up /opt/homebrew/etc/wireguard/wg0.conf", "tunnel up")
        for bad in ("wg-quick up *", "wg-quick down *"):
            self.assertNotIn(bad, self.text, f"{bad} is arbitrary root code execution")

    def test_wg_quick_rule_matches_how_the_code_invokes_it(self):
        """sudo matches the whole argv, so an interpreter prefix must agree.

        The service launches wg-quick through a modern bash by absolute path,
        because under sudo's scrubbed PATH its `#!/usr/bin/env bash` shebang finds
        Apple's bash 3.2 and wg-quick refuses to run.  A rule written without that
        prefix would never match the real invocation, and the tunnel controls would
        fail with a password prompt no web request can answer.
        """
        service = (BASE / "hub" / "wireguard_svc.py").read_text()
        uses_bash_prefix = bool(re.search(r"\[\s*BASH\s*,\s*WG_QUICK\s*,", service))
        rule_has_bash_prefix = bool(
            re.search(r"/bin/bash /opt/homebrew/bin/wg-quick (?:up|down) ", self.text)
        )
        self.assertEqual(
            uses_bash_prefix,
            rule_has_bash_prefix,
            "hub/wireguard_svc.py and the sudoers rule disagree on whether "
            "wg-quick is launched through an explicit bash; sudo matches the full "
            "argv, so one of them will never match",
        )

    def test_ip_forwarding_is_enumerated_not_wildcarded(self):
        for value in ("net.inet.ip.forwarding=1", "net.inet.ip.forwarding=0"):
            self.assertGranted(f"sysctl -w {value}", "WireGuard routing")
        self.assertNotIn(
            "sysctl -w *", self.text,
            "a wildcard would expose every kernel tunable on the machine",
        )

    def test_no_unrestricted_binary_grants(self):
        """A rule naming a binary with no arguments is a blanket grant."""
        offenders = []
        for line in self.text.splitlines():
            stripped = line.strip().rstrip(", \\")
            if not stripped.startswith("/"):
                continue
            # A pinned rule always constrains arguments with an explicit
            # argument list; sudo only matches an identical argv.  (A trailing
            # "" must not be used for that -- see
            # test_no_trailing_empty_string_argument.)
            if re.fullmatch(r"/[\w/.@-]+", stripped):
                offenders.append(stripped)
        self.assertEqual(
            offenders,
            [],
            "these rules grant a binary with any arguments:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
