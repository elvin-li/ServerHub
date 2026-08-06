"""Every `sudo -n` in hub/ needs a sudoers rule, or the feature dies silently.

A missing rule raises nothing. sudo simply asks for a password, and a web request
has no one to type it, so the call fails and the feature stops working with no
error that points at the cause. The WireGuard page sat unable to read peer state
for exactly this reason: `wg show wg0 dump` had no rule, so the panel could only
ever report "not running".

This walks the AST for `["sudo", "-n", ...]` argv lists, resolves the module
constants used in them, and requires each to be authorised by the template. It
understands the regex argument patterns the template uses (sudo 1.9.10+), which
are deliberately tighter than globs: sudoers' `*` matches `/` as well, so `/dev/*`
would also accept `/dev/../etc/shadow`.
"""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

HUB = BASE / "hub"
TEMPLATE = BASE / "deploy" / "sudoers.d" / "serverhub"

#: Module-level constants that appear inside argv lists, so a call site can be
#: compared against a rule as a concrete path.
CONSTANTS = {
    "SMARTCTL": "/opt/homebrew/bin/smartctl",
    "WG": "/opt/homebrew/bin/wg",
    "WG_QUICK": "/opt/homebrew/bin/wg-quick",
    "BASH": "/opt/homebrew/bin/bash",
    "RM": "/bin/rm",
    "PFCTL": "/sbin/pfctl",
    "SYSCTL": "/usr/sbin/sysctl",
    "LAUNCHCTL": "/bin/launchctl",
    "NS": "/usr/sbin/networksetup",
    "NFSD": "/sbin/nfsd",
    "DISKUTIL": "/usr/sbin/diskutil",
    "TMUTIL": "/usr/bin/tmutil",
    "MDUTIL": "/usr/bin/mdutil",
    "CP": "/bin/cp",
    "CHOWN": "/usr/sbin/chown",
    "CHMOD": "/bin/chmod",
}

#: Placeholder for an argv element this analysis cannot resolve statically (an
#: f-string, a call, a starred expansion). Treated as "could be anything", so the
#: test reports only definite gaps rather than guesses.
UNKNOWN = "\x00"


def _literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return CONSTANTS.get(node.id, UNKNOWN)
    if isinstance(node, ast.Attribute):
        return CONSTANTS.get(node.attr, UNKNOWN)
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
            if _literal(node.elts[0]) != "sudo" or _literal(node.elts[1]) != "-n":
                continue
            argv = [_literal(e) for e in node.elts[2:]]
            found.append((path.relative_to(BASE).as_posix(), node.lineno, argv))
    return found


def rules() -> list[str]:
    return [
        line.strip().rstrip(", \\")
        for line in TEMPLATE.read_text().splitlines()
        if line.strip().startswith("/")
    ]


def authorised_by(argv: list[str], all_rules: list[str]) -> str | None:
    for rule in all_rules:
        parts = rule.split()
        # A lone trailing "" means "and no further arguments are permitted".
        exact = bool(parts) and parts[-1] == '""'
        if exact:
            parts = parts[:-1]
        if len(parts) > len(argv) or (exact and len(parts) != len(argv)):
            continue
        for want, got in zip(parts, argv):
            if want == "*" or got == UNKNOWN:
                continue
            if want.startswith("^") and want.endswith("$"):
                if re.fullmatch(want[1:-1], got):
                    continue
                break
            if want.endswith("*") and got.startswith(want[:-1]):
                continue
            if want.replace("\\,", ",") != got:
                break
        else:
            return rule
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
            # `sudo -n *command` builds its argv elsewhere, so there is nothing
            # here to compare against a rule. Reporting it as a gap would be a
            # false alarm; the commands it expands to are covered by their own
            # call sites and by test_wireguard_stale_runtime.
            if all(a == UNKNOWN for a in argv):
                continue
            if authorised_by(argv, self.rules) is None:
                rendered = " ".join("<dynamic>" if a == UNKNOWN else a for a in argv)
                gaps.append(f"{path}:{line}  sudo -n {rendered}")
        self.assertEqual(
            gaps,
            [],
            "these privileged calls have no sudoers rule, so they will prompt for "
            "a password no web request can answer:\n" + "\n".join(gaps),
        )

    def test_regex_patterns_are_anchored(self):
        """An unanchored regex would match far more than intended."""
        for rule in self.rules:
            for part in rule.split():
                if part.startswith("^") != part.endswith("$") and (
                    part.startswith("^") or part.endswith("$")
                ):
                    self.fail(f"half-anchored pattern in rule: {rule}")

    def test_regex_patterns_compile(self):
        for rule in self.rules:
            for part in rule.split():
                if part.startswith("^") and part.endswith("$"):
                    try:
                        re.compile(part[1:-1])
                    except re.error as exc:
                        self.fail(f"invalid regex {part!r} in {rule}: {exc}")

    def test_device_patterns_cannot_escape_dev(self):
        """`/dev/*` would also match `/dev/../etc/shadow`; the regex must not."""
        for rule in self.rules:
            for part in rule.split():
                if part.startswith("^/dev/"):
                    pattern = part[1:-1]
                    self.assertIsNone(
                        re.fullmatch(pattern, "/dev/../etc/shadow"),
                        f"pattern {part} escapes /dev",
                    )
                    self.assertIsNotNone(
                        re.fullmatch(pattern, "/dev/disk0"),
                        f"pattern {part} rejects a real device",
                    )


if __name__ == "__main__":
    unittest.main()
