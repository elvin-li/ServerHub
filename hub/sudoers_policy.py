"""How sudo matches a command against a sudoers rule.

There is one implementation of these semantics on purpose.  ServerHub shipped 32
sudoers rules that sudo silently never matched, and the test that was supposed to
catch it modelled matching a second, different way -- the same wrong way the
policy had been written.  Two models that agree with each other and disagree with
sudo catch nothing, so the test suite and the operational verifier now share this
module.

The rules, from sudoers(5) on macOS sudo 1.9.17p2:

* A rule is a fully-qualified binary, optionally followed by an argument list.
  With no argument list, ANY arguments are permitted.
* If the argument list is exactly ``""``, only an empty argument list matches.
* If the argument list BEGINS with ``^``, the whole list is a POSIX extended
  regular expression matched against the arguments joined by single spaces.
  A ``^`` anywhere else does not enable regex mode -- the rule stays in glob
  mode, where ``^``, ``+`` and ``$`` are literal characters that no real argv
  carries, so such a rule can never match.  That is the bug above.
* Otherwise the list is a shell-style glob, also matched against the joined
  argument string.  ``*`` therefore spans argument boundaries: ``-setairportpower
  * on`` also matches ``-setairportpower en0 evil on``.
* Outside regex mode, ``,`` ``:`` ``=`` and ``\\`` are backslash-escaped in the
  file and unescaped before matching.
"""
from __future__ import annotations

import re
from pathlib import Path

__all__ = [
    "split_rule",
    "rule_matches",
    "authorised",
    "dead_regex_rules",
    "unpinned_rules",
    "parse_template",
    "parse_installed",
    "normalise_rule",
    "executed_paths",
    "path_arguments",
    "user_writable",
    "swappable_rules",
    "writable_argument_rules",
    "REQUIRED",
    "FORBIDDEN",
]

SMARTCTL = "/opt/homebrew/bin/smartctl"
WG = "/opt/homebrew/bin/wg"

#: Invocations the panel makes that MUST be passwordless, as (binary, arguments).
#:
#: Shapes are taken from the call sites, including both placements of the `-d
#: nvme` transport flag: hub/smart_test_svc._smartctl puts it between the verb and
#: the device, while device_type()'s probe puts it first.  Both reach sudo.
REQUIRED: tuple[tuple[str, str], ...] = (
    (SMARTCTL, "-a /dev/disk0"),
    (SMARTCTL, "-H /dev/disk0"),
    (SMARTCTL, "-i /dev/disk0"),
    (SMARTCTL, "-i -d nvme /dev/disk0"),
    (SMARTCTL, "-d nvme -i /dev/disk0"),
    (SMARTCTL, "-c -d nvme /dev/disk0"),
    (SMARTCTL, "-l selftest -d nvme /dev/disk0"),
    (SMARTCTL, "-n standby /dev/disk4"),
    (SMARTCTL, "-s standby,now /dev/disk4"),
    (SMARTCTL, "-s standby,off /dev/disk4"),
    (SMARTCTL, "-t short -d nvme /dev/disk0"),
    (SMARTCTL, "-t conveyance /dev/disk4"),
    (SMARTCTL, "-X -d nvme /dev/disk0"),
    ("/usr/bin/pmset", "-a disksleep 10"),
    ("/usr/bin/pmset", "-a womp 1"),
    ("/usr/bin/pmset", "-a lowpowermode 0"),
    ("/sbin/ifconfig", "en0 alias 192.168.1.204 netmask 255.255.255.255"),
    ("/sbin/ifconfig", "en0 -alias 192.168.1.204"),
    ("/usr/sbin/networksetup", "-getairportpower en0"),
    ("/usr/sbin/networksetup", "-setairportpower en0 on"),
    ("/usr/sbin/networksetup", "-setairportpower en0 off"),
    ("/usr/sbin/sysctl", "-w net.inet.ip.forwarding=1"),
    ("/usr/sbin/sysctl", "-w net.inet.ip.forwarding=0"),
    (WG, "show interfaces"),
    (WG, "show all dump"),
    (WG, "show wg0 dump"),
    ("/bin/rm", "-f /var/run/wireguard/wg0.name"),
)

#: Invocations that must NOT be passwordless.  Each is a shape a narrowed rule
#: could accidentally readmit: a write verb smuggled behind a read-only one, a
#: path escaping the device tree, a wider preference key, another target.
FORBIDDEN: tuple[tuple[str, str], ...] = (
    (SMARTCTL, "-a /dev/disk0 -X"),
    (SMARTCTL, "-H /dev/disk0 -t long"),
    (SMARTCTL, "-a /dev/../etc/shadow"),
    (SMARTCTL, "-a /etc/passwd"),
    (SMARTCTL, "-t destroy /dev/disk0"),
    ("/usr/bin/pmset", "-a destroyfvkeyonstandby 1"),
    ("/usr/bin/pmset", "-a disksleep 10 -a womp 1"),
    ("/usr/bin/pmset", "-a disksleep abc"),
    ("/sbin/ifconfig", "en0 down"),
    ("/sbin/ifconfig", "en0 alias 10.0.0.1 netmask 255.255.255.0 mtu 100"),
    ("/usr/sbin/networksetup", "-setairportpower en0 evil on"),
    ("/usr/sbin/networksetup", "-setairportpower en0 on extra"),
    ("/usr/sbin/networksetup", "-setcomputername pwned"),
    ("/usr/sbin/sysctl", "-w kern.securelevel=0"),
    (WG, "show eth0 dump"),
    (WG, "syncconf wg0 /tmp/evil.conf"),
    ("/bin/rm", "-rf /"),
    ("/bin/rm", "-f /etc/sudoers"),
    ("/bin/chmod", "777 /etc/sudoers"),
)


def split_rule(rule: str) -> tuple[str, str]:
    """A rule into ``(binary, argument_string)``; the argument string may be ""."""
    binary, _, args = rule.partition(" ")
    return binary, args.strip()


def normalise_rule(rule: str) -> str:
    """A rule in a form comparable between the template and ``sudo -l`` output.

    sudo renders the sudoers-level escapes its own way: a template rule written
    ``sysctl -w net.inet.ip.forwarding=1`` comes back from ``sudo -l`` as
    ``...forwarding\\=1``.  Only those four escapes are touched, so a regex's
    ``\\.`` survives -- it means "a literal dot" to the regex engine, not to the
    sudoers parser.
    """
    return re.sub(r"\\([,:=\\])", r"\1", rule)


def _glob_to_regex(pattern: str) -> str:
    literal = re.sub(r"\\([,:=\\])", r"\1", pattern)
    return re.escape(literal).replace(r"\*", ".*").replace(r"\?", ".")


def _regex_body(args: str) -> str:
    return args[1:-1] if args.endswith("$") else args[1:]


def rule_matches(rule: str, binary: str, argstr: str) -> bool:
    """Whether *rule* authorises *binary* run with *argstr* (arguments joined)."""
    rbin, rargs = split_rule(rule)
    if rbin != binary:
        return False
    if not rargs:
        return True
    if rargs == '""':
        return argstr == ""
    if rargs.startswith("^"):
        try:
            return re.fullmatch(_regex_body(rargs), argstr) is not None
        except re.error:
            return False
    return re.fullmatch(_glob_to_regex(rargs), argstr) is not None


def authorised(binary: str, argstr: str, rules: list[str]) -> str | None:
    """The first rule authorising this invocation, or None."""
    for rule in rules:
        if rule_matches(rule, binary, argstr):
            return rule
    return None


def dead_regex_rules(rules: list[str]) -> list[str]:
    """Rules whose ``^`` is not the first character of the argument list.

    These are listed by ``sudo -l`` and never match anything, so the feature
    depending on them asks for a password forever.
    """
    dead = []
    for rule in rules:
        _, args = split_rule(rule)
        if "^" in args and not args.startswith("^"):
            dead.append(rule)
    return dead


def unpinned_rules(rules: list[str]) -> list[str]:
    """Rules that pin only the executable, permitting any arguments."""
    return [r for r in rules if not split_rule(r)[1]]


def parse_template(body: str, *, state_root: str = "", user: str = "") -> list[str]:
    """Rule bodies from a sudoers template, one per line.

    Install-time placeholders are resolved so template rules can be compared
    against real call sites.
    """
    if state_root:
        body = body.replace("__SERVERHUB_STATE__", state_root)
    if user:
        body = body.replace("__SERVERHUB_USER__", user)
    return [
        line.strip().rstrip("\\").strip().rstrip(",")
        for line in body.splitlines()
        if line.strip().startswith("/")
    ]


def parse_installed(sudo_l_output: str) -> list[str]:
    """Passwordless rules as ``sudo -l`` reports them for the current user.

    Only NOPASSWD entries are collected: for a member of the admin group every
    command is permitted *with* a password, so anything else says nothing about
    whether the panel can run it unattended.
    """
    rules: list[str] = []
    for chunk in re.split(r"\n\s*", sudo_l_output):
        if "NOPASSWD:" not in chunk:
            continue
        _, _, rhs = chunk.partition("NOPASSWD:")
        for part in rhs.split(", "):
            part = part.strip().rstrip(",")
            if part.startswith("/"):
                rules.append(part)
            elif rules and part:
                # a comma that belonged inside a regex, not a list separator
                rules[-1] += ", " + part
    return rules


# ---------------------------------------------------------------------------
# Is the pinned binary actually pinned?
# ---------------------------------------------------------------------------
# Narrowing a rule's arguments is only worth anything if the program those
# arguments are handed to cannot be replaced.  A NOPASSWD rule naming a binary
# the granting account can rewrite is passwordless root no matter how precisely
# the argument list is spelled: overwrite the file, run the rule, and the
# argument regex authorises your own code.
#
# On Apple Silicon this is the default state of anything under /opt/homebrew.
# `brew` chowns its whole prefix to the installing user, so /opt/homebrew/bin is
# user-writable and every binary in it is a user-owned symlink.  Rules naming
# smartctl, wg, wg-quick or bash therefore look pinned and are not.
#
# `visudo -cf` checks grammar and verify-sudoers checks whether a rule can match.
# Neither can see this, which is why it lives here.

#: Programs that execute a path handed to them, so that argument carries exactly
#: the same authority as the interpreter and belongs in the executed set.
_INTERPRETERS = frozenset({
    "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh",
    "/usr/bin/env", "/usr/bin/perl", "/usr/bin/python3", "/usr/bin/ruby",
    "/opt/homebrew/bin/bash", "/usr/local/bin/bash",
    "/opt/homebrew/bin/zsh", "/usr/local/bin/zsh",
})


def executed_paths(rule: str) -> list[str]:
    """Absolute paths a rule causes to be EXECUTED as root.

    Usually just the binary.  When the binary is an interpreter its script
    argument runs with the same authority, so
    ``/opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick up ...`` executes two
    replaceable files, not one.
    """
    binary, args = split_rule(rule)
    if not binary.startswith("/"):
        return []
    executed = [binary]
    if binary in _INTERPRETERS and not args.startswith("^"):
        for token in args.split():
            if token.startswith("/"):
                executed.append(token)
                break
    return executed


def path_arguments(rule: str) -> list[str]:
    """Absolute paths a rule passes as data rather than as code.

    Reported separately because the consequence depends on the program: a
    writable path here is only dangerous if the tool acts on the file's contents
    with root authority.  ``wg-quick`` is the case that matters -- it executes the
    ``PostUp``/``PostDown`` lines of the config it is given -- so a writable
    config file is a root code path even when every binary is immutable.

    Regex-mode argument lists are skipped: they are patterns, not literal paths.
    """
    binary, args = split_rule(rule)
    if not args or args.startswith("^") or args == '""':
        return []
    executed = set(executed_paths(rule))
    return [t for t in args.split() if t.startswith("/") and t not in executed]


def user_writable(path: str) -> bool:
    """Whether the calling user could substitute what ``path`` resolves to.

    Three ways, all equivalent in effect:

    * the file itself is writable;
    * it is a symlink and its target is writable (the usual Homebrew shape);
    * a directory on the way to it is writable, which allows unlinking the entry
      and putting a different file there -- so a read-only file in a writable
      directory is still not pinned.
    """
    import os

    p = Path(path)
    if p.is_symlink():
        try:
            target = p.resolve()
        except OSError:
            target = None
        if target is not None and target.exists() and os.access(target, os.W_OK):
            return True
    if p.exists() and os.access(p, os.W_OK):
        return True
    # The nearest existing ancestor: writable means the leaf can be replaced.
    parent = p.parent
    while True:
        if parent.exists():
            return os.access(parent, os.W_OK)
        if parent.parent == parent:
            return False
        parent = parent.parent


def swappable_rules(
    rules: list[str], writable=user_writable
) -> list[tuple[str, list[str]]]:
    """Rules that execute something the grantee can replace.

    Each entry is ``(rule, [writable paths])``.  A non-empty result means those
    rules are equivalent to passwordless root regardless of their argument
    pinning, so it should be treated as a policy failure rather than a warning.
    """
    found = []
    for rule in rules:
        hits = [p for p in executed_paths(rule) if writable(p)]
        if hits:
            found.append((rule, hits))
    return found


def writable_argument_rules(
    rules: list[str], writable=user_writable
) -> list[tuple[str, list[str]]]:
    """Rules passing a grantee-writable file as an argument to a root command."""
    found = []
    for rule in rules:
        hits = [p for p in path_arguments(rule) if writable(p)]
        if hits:
            found.append((rule, hits))
    return found
