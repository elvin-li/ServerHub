#!/usr/bin/env python3
"""Check the policy sudo has actually LOADED, not the template on disk.

The test suite validates the template.  That is not the same thing: the machine
runs whatever is in /etc/sudoers.d, which can be older than the repo, generated
for a different account, or shadowed by another file in the same directory.  This
asks sudo itself what it will allow without a password, and holds the answer
against the contract in hub/sudoers_policy.

Why not `sudo -n -l <command>`: for a member of the admin group that exits 0 for
every command, `rm -rf /` included, because it answers "is this permitted at all"
(with a password) rather than "is this permitted unattended".  Only the NOPASSWD
entry list is meaningful, so that is what gets parsed.

    deploy/verify-sudoers.py          # audit the installed policy
    deploy/verify-sudoers.py --quiet  # exit status only

Exit status: 0 clean, 1 a required call is missing or a forbidden one is allowed.
"""
from __future__ import annotations

import getpass
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.sudoers_policy import (  # noqa: E402
    FORBIDDEN,
    PINNED_BIN_DIR,
    REQUIRED,
    authorised,
    dead_regex_rules,
    normalise_rule,
    parse_installed,
    parse_template,
    swappable_rules,
    unpinned_rules,
    writable_argument_rules,
)

quiet = "--quiet" in sys.argv


def say(*args: object) -> None:
    if not quiet:
        print(*args)


proc = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True)
if proc.returncode != 0 and not proc.stdout.strip():
    print("cannot list the sudo policy without a password prompt.", file=sys.stderr)
    print("run `sudo -v` first, or install the policy with", file=sys.stderr)
    print("  deploy/install-sudoers.sh", file=sys.stderr)
    sys.exit(1)

rules = parse_installed(proc.stdout)
say(f"loaded passwordless rules: {len(rules)}")

problems: list[str] = []

# Drift: the template can be edited without reinstalling, and then the tests pass
# against a policy the machine is not running. Compare rule sets, not file bytes,
# so a comment-only edit is not reported as drift.
template = BASE / "deploy" / "sudoers.d" / "serverhub"
if template.is_file():
    expected = {
        normalise_rule(r)
        for r in parse_template(
            template.read_text(), state_root=str(BASE), user=getpass.getuser()
        )
    }
    loaded = {normalise_rule(r) for r in rules}
    only_template = sorted(expected - loaded)
    only_loaded = sorted(loaded - expected)
    if only_template or only_loaded:
        problems.append("installed policy differs from the template")
        say("\nthe template and the loaded policy disagree; reinstall with")
        say("  deploy/install-sudoers.sh")
        for rule in only_template:
            say(f"    in template, not loaded:  {rule}")
        for rule in only_loaded:
            say(f"    loaded, not in template:  {rule}")
    else:
        say(f"in sync with {template.relative_to(BASE)}")

dead = dead_regex_rules(rules)
if dead:
    problems.append(f"{len(dead)} rule(s) can never match")
    say("\nrules whose '^' does not start the argument list (sudo lists them,")
    say("but they are glob-matched and never match a real argv):")
    for rule in dead:
        say("   ", rule)

unpinned = unpinned_rules(rules)
if unpinned:
    problems.append(f"{len(unpinned)} rule(s) pin only the executable")
    say("\nrules granting a whole binary, i.e. any arguments it accepts:")
    for rule in unpinned:
        say("   ", rule)

missing = [(b, a) for b, a in REQUIRED if authorised(b, a, rules) is None]
if missing:
    problems.append(f"{len(missing)} required call(s) need a password")
    say("\nthe panel makes these calls, and they will prompt for a password")
    say("that no web request can answer:")
    for binary, argstr in missing:
        say(f"    {binary} {argstr}")

leaks = [(b, a, authorised(b, a, rules)) for b, a in FORBIDDEN]
leaks = [(b, a, r) for b, a, r in leaks if r is not None]
if leaks:
    problems.append(f"{len(leaks)} forbidden call(s) are passwordless")
    say("\nthese must NOT be passwordless:")
    for binary, argstr, rule in leaks:
        say(f"    {binary} {argstr}")
        say(f"        allowed by: {rule}")

# Pinning arguments is only worth something if the program cannot be replaced.
# Homebrew chowns its whole prefix to the installing user, so a rule naming
# /opt/homebrew/bin/<x> is passwordless root: overwrite the file and the argument
# regex authorises your own code. Neither visudo nor the match checks above can
# see this, so it is checked last and counts as a failure, not a warning.
swappable = swappable_rules(rules)
if swappable:
    problems.append(f"{len(swappable)} rule(s) execute a replaceable file")
    say("\nthese rules run a file this account can rewrite, which makes them")
    say("equivalent to passwordless root however precisely the arguments are")
    say("pinned -- overwrite the file, run the rule:")
    for rule, hits in swappable:
        say("   ", rule)
        for path in hits:
            say(f"        writable: {path}")

# A warning, not a failure, and the distinction is the point. The only rule left
# in this category is `wg syncconf <state>/data/wg0.sync.conf`, whose config the
# panel has to be able to write because it generates it -- and `wg syncconf`
# applies peers, it does not execute anything from the file the way wg-quick
# executes PostUp. Counting it as a failure would leave --verify permanently red,
# and a check that always fails is a check people learn to ignore.
writable_args = writable_argument_rules(rules)
if writable_args:
    say("\nnote: these rules hand a file this account can rewrite to a root")
    say("command. That is by design where the panel generates the file, but it")
    say("is only safe while the program does not execute its contents -- wg-quick")
    say("does (PostUp/PostDown), which is why it is not granted at all:")
    for rule, hits in writable_args:
        say("   ", rule)
        for path in hits:
            say(f"        writable: {path}")

# The template promises that --verify notices a stale copy, so it has to. A
# pinned binary is a snapshot: `brew upgrade` moves the original and leaves the
# copy behind at the old version. That still works -- it is simply older -- so it
# is a warning, but an unreported one would quietly become years old.
stale: list[str] = []
for tool in ("smartctl", "wg"):
    pinned = Path(PINNED_BIN_DIR) / tool
    if not pinned.exists():
        problems.append(f"pinned {tool} is missing")
        say(f"\n{pinned} does not exist, so every rule naming it can never")
        say("match and the feature will ask for a password. Reinstall with")
        say("  deploy/install-sudoers.sh")
        continue
    current = shutil.which(tool)
    if not current:
        continue
    try:
        if Path(current).read_bytes() != pinned.read_bytes():
            stale.append(f"{tool}: {pinned} differs from {current}")
    except OSError:
        pass
if stale:
    say("\nnote: a pinned copy is out of date with the installed build")
    say("(it still works, it is just an older version). Refresh with")
    say("  deploy/install-sudoers.sh")
    for line in stale:
        say("   ", line)

if not problems:
    say(
        f"\nOK: all {len(REQUIRED)} required calls are passwordless, "
        f"all {len(FORBIDDEN)} forbidden shapes are refused"
    )
    sys.exit(0)

print("\n" + "; ".join(problems), file=sys.stderr)
sys.exit(1)
