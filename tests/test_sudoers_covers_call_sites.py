"""Every `sudo -n` in hub/ needs a sudoers rule that actually matches.

A missing or malformed rule raises nothing.  sudo simply asks for a password, and
a web request has no one to type it, so the feature stops working with no error
that points at the cause.  Two variants of this have already shipped:

* `wg show wg0 dump` had no rule at all, so the WireGuard page could only ever
  report "not running";
* 21 smartctl rules, 8 pmset rules and 3 network rules were written as
  `smartctl -a ^/dev/[A-Za-z0-9]+$`, which sudo never matches -- SMART reads
  silently needed a password for as long as those rules were installed.

The second one is why this file models sudo's matching semantics explicitly
rather than approximately.  Per sudoers(5): "If the arguments in a Cmnd begin
with the '^' character, they will be interpreted as a regular expression."  The
regex therefore has to start at the FIRST argument and describe the WHOLE
argument string; a `^` anywhere else leaves the rule in glob mode, where `^`,
`+` and `$` are literal characters that no real argv contains.

Glob mode is modelled the same way sudo behaves (verified on macOS sudo
1.9.17p2): the pattern is matched against the arguments joined by spaces, so `*`
spans argument boundaries -- `-setairportpower * on` also matches
`-setairportpower en0 evil on`.
"""
from __future__ import annotations

import ast
import getpass
import itertools
import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import paths as _paths  # noqa: E402
from hub import power_svc as _power_svc  # noqa: E402
from hub import wireguard_svc as _wireguard_svc  # noqa: E402
from hub.sudoers_policy import (  # noqa: E402  (needs sys.path above)
    FORBIDDEN,
    PINNED_BIN_DIR,
    REQUIRED,
    UNPINNED_EQUIVALENTS,
    authorised,
    dead_regex_rules,
    executed_paths,
    parse_template,
    split_rule,
    unpinned_rules,
)

HUB = BASE / "hub"
TEMPLATE = BASE / "deploy" / "sudoers.d" / "serverhub"

#: Module-level constants that appear inside argv lists, so a call site can be
#: compared against a rule as a concrete path.
CONSTANTS = {
    # Policy analysis uses the pinned paths the sudoers template grants.  The
    # runtime constants fall back to Homebrew when /usr/local/libexec/serverhub
    # is absent (Linux CI, a Mac that has not run install-sudoers.sh).  Using
    # those fallbacks here would report a host-layout gap as a policy hole.
    # Runtime drift is checked separately in
    # test_the_binaries_the_code_resolves_are_the_ones_granted.
    "SMARTCTL": f"{PINNED_BIN_DIR}/smartctl",
    "WG": f"{PINNED_BIN_DIR}/wg",
    "WG_QUICK": _wireguard_svc.WG_QUICK,
    "BASH": "/opt/homebrew/bin/bash",
    "RM": "/bin/rm",
    "PFCTL": "/sbin/pfctl",
    "SYSCTL": "/usr/sbin/sysctl",
    "LAUNCHCTL": "/bin/launchctl",
    "NS": "/usr/sbin/networksetup",
    "NFSD": "/sbin/nfsd",
    # System path, not a Homebrew-pinned one: the runtime constant is the
    # same path the sudoers template grants.
    "PMSET": _power_svc.PMSET,
    "DISKUTIL": "/usr/sbin/diskutil",
    "TMUTIL": "/usr/bin/tmutil",
    "MDUTIL": "/usr/bin/mdutil",
    "CP": "/bin/cp",
    "CHOWN": "/usr/sbin/chown",
    "CHMOD": "/bin/chmod",
}

#: Placeholder for an argv element this analysis cannot resolve statically (an
#: f-string, a call, a subscript).
UNKNOWN = "\x00"

#: Placeholder for `*expansion`, which stands for an unknown NUMBER of arguments.
#: Substituting a single token for it would be wrong in both directions, so call
#: sites containing one are not analysed here -- the concrete argv is assembled
#: at the caller, where it has its own call site.
VARIADIC = "\x01"

#: Stand-ins tried for an unresolved argv element.  A call site counts as covered
#: if *any* combination of these matches a rule, so the test reports definite
#: gaps rather than guesses.  Every entry is a value the code actually passes.
SUBSTITUTIONS = (
    # device nodes and transport flags
    "/dev/disk0",
    "-d nvme",
    # interface names
    "en0",
    "utun4",
    "wg0",
    # smartctl verbs and operands
    "short",
    "long",
    "conveyance",
    "offline",
    "standby,now",
    "standby,off",
    # power prefs: keys then values
    "disksleep",
    "displaysleep",
    "womp",
    "powernap",
    "lowpowermode",
    "10",
    "0",
    "1",
    # shutdown flags
    "-h",
    "-r",
    # network
    "192.168.1.204",
    "255.255.255.255",
    "on",
    "off",
    "net.inet.ip.forwarding=1",
    "net.inet.ip.forwarding=0",
    # paths and service labels
    "/var/run/wireguard/wg0.name",
    "system/com.wireguard.wg0",
    f"{BASE}/data/wg0.sync.conf",
    "/opt/homebrew/etc/wireguard/wg0.conf",
)


def _literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return CONSTANTS.get(node.id, UNKNOWN)
    if isinstance(node, ast.Attribute):
        return CONSTANTS.get(node.attr, UNKNOWN)
    if isinstance(node, ast.Starred):
        return VARIADIC
    return UNKNOWN


def call_sites() -> list[tuple[str, int, list[str]]]:
    found = []
    for path in sorted(HUB.rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.List) or len(node.elts) < 3:
                continue
            first = _literal(node.elts[0])
            if first not in ("sudo", "/usr/bin/sudo") or _literal(node.elts[1]) != "-n":
                continue
            argv = [_literal(e) for e in node.elts[2:]]
            found.append((path.relative_to(BASE).as_posix(), node.lineno, argv))
    return found


def rules() -> list[str]:
    """Rule bodies from the template, with install-time placeholders resolved.

    Resolving them is what lets rules that pin a path under the state directory
    (`wg syncconf <state>/data/wg0.sync.conf`) be compared against call sites.
    """
    return parse_template(
        TEMPLATE.read_text(), state_root=str(BASE), user=getpass.getuser()
    )


def authorised_argv(argv: list[str], all_rules: list[str]) -> str | None:
    """As above, but for a call site whose elements may be unresolved."""
    if not argv:
        return None
    slots = [i for i, a in enumerate(argv) if a == UNKNOWN]
    if not slots:
        return authorised(argv[0], " ".join(argv[1:]), all_rules)
    # Keep the search bounded: 3 slots over the substitution table is ~30k
    # candidates, which is fast; beyond that the site is too dynamic to judge.
    if len(slots) > 3:
        return "<too dynamic to analyse>"
    for combo in itertools.product(SUBSTITUTIONS, repeat=len(slots)):
        filled = list(argv)
        for slot, value in zip(slots, combo):
            filled[slot] = value
        hit = authorised(filled[0], " ".join(filled[1:]), all_rules)
        if hit:
            return hit
    return None


class SudoersCoverageTests(unittest.TestCase):
    def setUp(self):
        self.rules = rules()
        self.sites = call_sites()

    def test_the_analysis_finds_the_call_sites(self):
        # Guards the walker: if it silently matched nothing, every assertion
        # below would pass without checking anything.
        self.assertGreater(len(self.sites), 15, "the AST walk found almost nothing")
        self.assertGreater(len(self.rules), 20, "no rules parsed from the template")

    def test_every_sudo_call_site_has_a_rule(self):
        gaps = []
        for path, line, argv in self.sites:
            # `sudo -n *command` stands for an unknown NUMBER of arguments, so
            # there is nothing here to compare against a rule.  The commands it
            # expands to are covered by their own call sites.
            if VARIADIC in argv or all(a == UNKNOWN for a in argv):
                continue
            if authorised_argv(argv, self.rules) is None:
                rendered = " ".join("<dynamic>" if a == UNKNOWN else a for a in argv)
                gaps.append(f"{path}:{line}  sudo -n {rendered}")
        self.assertEqual(
            gaps,
            [],
            "these privileged calls have no sudoers rule that matches, so they "
            "will prompt for a password no web request can answer:\n" + "\n".join(gaps),
        )

    # ── rule form ────────────────────────────────────────────────────────────

    def test_regex_must_start_the_argument_list(self):
        """The bug that silently disabled 32 rules.

        `smartctl -a ^/dev/[A-Za-z0-9]+$` looks anchored but is glob-matched,
        because the argument list starts with `-a` rather than `^`.  No real argv
        contains a literal `^`, so such a rule can never match anything.
        """
        broken = dead_regex_rules(self.rules)
        self.assertEqual(
            broken,
            [],
            "these rules put '^' after the first argument, so sudo treats the "
            "whole argument list as a glob and the rule can never match:\n"
            + "\n".join(broken),
        )

    def test_the_detector_catches_the_historical_bug(self):
        """The previous version of this file modelled regexes per-argument.

        That mirrored the same wrong assumption the policy was written under, so
        it passed against 32 rules that sudo never matched.  These are the exact
        rules that shipped broken; the detector has to reject all of them, and
        has to accept the corrected forms.
        """
        shipped_broken = [
            "/opt/homebrew/bin/smartctl -a ^/dev/[A-Za-z0-9]+$",
            "/opt/homebrew/bin/smartctl -t short -d nvme ^/dev/[A-Za-z0-9]+$",
            "/usr/bin/pmset -a disksleep ^[0-9]+$",
            "/sbin/ifconfig * alias * netmask ^[0-9.]+$",
            "/usr/sbin/networksetup -getairportpower ^[A-Za-z0-9]+$",
        ]
        self.assertEqual(
            dead_regex_rules(shipped_broken),
            shipped_broken,
            "the detector no longer recognises the bug it exists to catch",
        )

        corrected = [
            "/opt/homebrew/bin/smartctl ^-a /dev/[A-Za-z0-9]+$",
            "/usr/bin/pmset ^-a disksleep [0-9]+$",
            "/opt/homebrew/bin/smartctl -V",
            "/usr/sbin/sysctl -w net.inet.ip.forwarding=1",
        ]
        self.assertEqual(
            dead_regex_rules(corrected), [], "the detector flags correct rules"
        )

        # And the corrected forms must actually match the argv they exist for,
        # while the broken forms match nothing -- which is the whole point.
        self.assertIsNotNone(
            authorised("/opt/homebrew/bin/smartctl", "-a /dev/disk0", corrected)
        )
        self.assertIsNone(
            authorised("/opt/homebrew/bin/smartctl", "-a /dev/disk0", shipped_broken)
        )

    def test_regex_rules_do_not_also_use_globs(self):
        """Regex mode replaces glob mode; a `*` in a regex rule is a quantifier."""
        for rule in self.rules:
            _, args = split_rule(rule)
            if not args.startswith("^"):
                continue
            # A quantifier follows a token; a glob `*` stands alone or ends a path.
            for token in args.split():
                self.assertNotEqual(
                    token, "*", f"glob '*' inside a regex rule: {rule}"
                )

    def test_regex_rules_are_anchored_at_both_ends(self):
        """Without a trailing `$` extra arguments could be appended."""
        for rule in self.rules:
            _, args = split_rule(rule)
            if args.startswith("^"):
                self.assertTrue(
                    args.endswith("$"),
                    f"regex rule is not anchored at the end, so arguments can be "
                    f"appended: {rule}",
                )

    def test_regex_rules_compile(self):
        for rule in self.rules:
            _, args = split_rule(rule)
            if args.startswith("^"):
                try:
                    re.compile(args[1:-1] if args.endswith("$") else args[1:])
                except re.error as exc:
                    self.fail(f"invalid regex in {rule}: {exc}")

    def test_no_phantom_empty_argument(self):
        """`""` is only meaningful as a rule's sole argument.

        Appended after real arguments it becomes an empty argv element that no
        real command carries, and sudo lists the rule but never matches it. This
        is what made the WireGuard page report "not running" forever.
        """
        for rule in self.rules:
            _, args = split_rule(rule)
            tokens = args.split()
            if len(tokens) > 1:
                self.assertNotIn(
                    '""',
                    tokens,
                    f'"" appended after real arguments never matches: {rule}',
                )

    def test_no_whole_binary_grants(self):
        """A rule with no argument list permits every argument the binary takes."""
        unpinned = unpinned_rules(self.rules)
        self.assertEqual(
            unpinned,
            [],
            "these rules pin only the executable, not its arguments:\n"
            + "\n".join(unpinned),
        )

    # ── what the policy must and must not authorise ──────────────────────────

    def test_real_call_shapes_are_authorised(self):
        """Shapes taken from the call sites, including both `-d nvme` orderings.

        hub/smart_test_svc._smartctl puts the transport flag between verb and
        device; device_type()'s probe puts it first.  Both have to match.
        """
        missing = [
            f"{binary} {argstr}"
            for binary, argstr in REQUIRED
            if authorised(binary, argstr, self.rules) is None
        ]
        self.assertEqual(
            missing, [], "the policy does not authorise these real calls:\n" + "\n".join(missing)
        )

    def test_dangerous_shapes_are_not_authorised(self):
        """Nothing may smuggle a second verb, a wider key, or another target."""
        leaks = [
            f"{binary} {argstr}   <- via: {authorised(binary, argstr, self.rules)}"
            for binary, argstr in FORBIDDEN
            if authorised(binary, argstr, self.rules) is not None
        ]
        self.assertEqual(
            leaks, [], "the policy authorises shapes it must refuse:\n" + "\n".join(leaks)
        )

    def test_the_binaries_the_code_resolves_are_the_ones_granted(self):
        """A PATH-resolved binary can drift away from the path sudoers pins.

        `hub.paths.SMARTCTL` is `shutil.which("smartctl") or "/opt/homebrew/..."`,
        so what the code executes depends on the PATH of whatever launched the
        panel.  Today both resolve to the granted path and there is only one
        smartctl installed -- but a second copy earlier in PATH (a /usr/local/bin
        install, say) would silently move every privileged SMART call to a binary
        no rule covers, and SMART reads would go back to asking for a password
        with nothing to show why.
        """
        # executed_paths, not just the rule's binary: a script reached as an
        # argument to a pinned interpreter is executed by the rule without ever
        # being that rule's binary.
        if not Path(f"{PINNED_BIN_DIR}/smartctl").is_file():
            self.skipTest(
                "pinned /usr/local/libexec/serverhub copies are not installed "
                "on this host"
            )
        granted = {p for rule in self.rules for p in executed_paths(rule)}
        # WG_QUICK is intentionally absent from the policy -- see
        # test_wg_quick_is_deliberately_not_granted.
        resolved = {
            "hub.paths.SMARTCTL": _paths.SMARTCTL,
            "hub.wireguard_svc.WG": _wireguard_svc.WG,
        }
        drifted = [
            f"{name} = {value} (no rule names this path)"
            for name, value in resolved.items()
            if value not in granted
        ]
        self.assertEqual(
            drifted,
            [],
            "the code would run a binary the policy does not authorise, so the "
            "call prompts for a password no web request can answer. If the paths "
            "below are under /opt/homebrew the pinned copies are missing -- run "
            "deploy/install-sudoers.sh:\n" + "\n".join(drifted),
        )

    def test_the_pinned_copies_are_what_gets_granted(self):
        """The policy must name the root-owned copies, never the Homebrew ones.

        Homebrew chowns its prefix to the installing account, so a rule naming
        /opt/homebrew/bin/smartctl can be satisfied by any program that account
        cares to put there: the argument regexes become decorative and the grant
        is plain passwordless root.  Reverting the path looks like a cosmetic
        change, which is exactly why it is asserted.
        """
        granted = {p for rule in self.rules for p in executed_paths(rule)}
        self.assertIn(PINNED_BIN_DIR + "/smartctl", granted)
        self.assertIn(PINNED_BIN_DIR + "/wg", granted)
        reopened = sorted(set(UNPINNED_EQUIVALENTS) & granted)
        self.assertEqual(
            reopened,
            [],
            "these paths live in a directory the granted account owns, so "
            "granting them reopens passwordless root:\n" + "\n".join(reopened),
        )

    def test_wg_quick_is_deliberately_not_granted(self):
        """Its absence is a decision, not an oversight.

        wg-quick executes the PostUp/PostDown lines of the config it is handed, as
        root, and the panel has to be able to write that config because it
        generates it.  No argument pinning fixes that, so tunnel up/down goes
        through hub/macos_admin instead and asks for the operator's password once.
        The read-only `wg show` rules stay passwordless, so the page still renders.
        """
        granted = {p for rule in self.rules for p in executed_paths(rule)}
        self.assertNotIn("/opt/homebrew/bin/wg-quick", granted)
        service = (BASE / "hub" / "wireguard_svc.py").read_text()
        self.assertIn(
            "run_admin_sequence",
            service,
            "with no passwordless rule, tunnel up/down has to have a password "
            "path or the WireGuard page cannot start the tunnel at all",
        )

    def test_device_patterns_cannot_escape_dev(self):
        """`/dev/*` would also match `/dev/../etc/shadow`; the regexes must not."""
        for rule in self.rules:
            _, args = split_rule(rule)
            if not args.startswith("^") or "/dev/" not in args:
                continue
            pattern = args[1:-1] if args.endswith("$") else args[1:]
            self.assertNotIn(
                "/dev/*",
                pattern,
                f"rule falls back to a glob for the device node: {rule}",
            )


if __name__ == "__main__":
    unittest.main()
