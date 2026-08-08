#!/usr/bin/env python3
"""Check that every Homebrew package the app store offers actually exists.

A catalog entry naming a package Homebrew does not have fails in two directions at
once, and neither is obvious from the panel:

  * installing it always errors, with Homebrew's "No Cask with this name exists"
    surfaced as the failure;
  * its install check never matches either, so the store keeps offering it as
    not-installed even on a host where the underlying tool is present and working.

Both shipped.  `native-wireguard` named a cask `wireguard` (Homebrew only has the
`wireguard-tools` and `wireguard-go` formulae; the GUI client is a Mac App Store
app), and `native-duplicacy` named a formula `duplicacy` (it is the cask
`duplicacy-cli`).  The WireGuard entry was the more confusing of the two, because
the panel's WireGuard page worked the whole time.

This is a script rather than a unit test on purpose: it shells out to `brew` once
per package, needs the tap metadata, and would make the offline test suite depend
on the network.  tests/test_native_catalog_shape.py covers what can be checked
without brew.

    deploy/verify-catalog.py            # every entry
    deploy/verify-catalog.py --quiet    # only the problems

Exit status: 0 when every package resolves, 1 otherwise.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub.native_catalog import NATIVE_APPS  # noqa: E402
from hub.paths import BREW  # noqa: E402

quiet = "--quiet" in sys.argv

#: Artifact kinds whose installation runs the macOS installer through sudo.  The
#: panel cannot elevate those: Homebrew refuses to run as root at all, so the
#: operator has to run the install on the machine itself.
ROOT_ARTIFACTS = {"pkg", "installer", "prefpane", "qlplugin", "kext"}


def say(*args: object) -> None:
    if not quiet:
        print(*args)


def package_tokens(app: dict) -> list[tuple[str, str]]:
    """(kind, token) pairs an entry claims Homebrew can install."""
    method = app.get("method") or ""
    if method == "brew_cask" and app.get("package"):
        return [("cask", str(app["package"]))]
    if method in ("brew_formula", "brew_service") and app.get("package"):
        return [("formula", str(app["package"]))]
    if method == "brew_multi":
        return [("formula", str(p)) for p in (app.get("packages") or [])]
    return []


if not Path(BREW).is_file():
    print(f"brew not found at {BREW}; cannot verify the catalog", file=sys.stderr)
    sys.exit(1)

missing: list[tuple[str, str, str, str]] = []
needs_root: list[tuple[str, str]] = []
checked = 0

for app in NATIVE_APPS:
    for kind, token in package_tokens(app):
        checked += 1
        flag = "--cask" if kind == "cask" else "--formula"
        proc = subprocess.run(
            [BREW, "info", flag, "--json=v2", token],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            reason = (proc.stderr or proc.stdout or "").strip().splitlines()[:1]
            missing.append(
                (str(app["id"]), kind, token, reason[0][:80] if reason else "unknown")
            )
            say(f"  MISSING  {app['id']:<26} {kind:<8} {token}")
            continue

        say(f"  ok       {app['id']:<26} {kind:<8} {token}")
        if kind != "cask":
            continue
        cask = (json.loads(proc.stdout).get("casks") or [{}])[0]
        kinds: set[str] = set()
        for artifact in cask.get("artifacts") or []:
            if isinstance(artifact, dict):
                kinds.update(artifact.keys())
        if kinds & ROOT_ARTIFACTS:
            needs_root.append((str(app["id"]), token))

say()
say(f"checked {checked} package token(s)")

if needs_root:
    say()
    say("these need root, so the panel cannot install them -- Homebrew refuses to")
    say("run as root, and what needs root is the installer it calls internally:")
    for app_id, token in needs_root:
        say(f"    {app_id:<26} {token}")
    say("the panel reports this and prints the command to run on the Mac.")

if missing:
    print(file=sys.stderr)
    print(f"{len(missing)} package(s) the catalog names do not exist:", file=sys.stderr)
    for app_id, kind, token, reason in missing:
        print(f"    {app_id} -> {kind} {token}: {reason}", file=sys.stderr)
    sys.exit(1)

say()
say("every package the catalog names exists in Homebrew")
