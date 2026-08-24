"""Files that hold key material must be unstageable, not merely uncommitted.

``test_secret_file_modes.py`` proves a secret is private to other *local* users.
This file proves the other half: that the same secret cannot leave the machine.
The distinction matters because the two failures look nothing alike -- a 0644
token is a local privilege problem, while a committed token is published to
everyone who can clone the repository and stays in the history after deletion.

The property is checked with ``git check-ignore`` rather than by reading
``.gitignore`` as text, because a rule's *presence* does not imply it *matches*:
a later negation, a directory-scoped pattern, or a rule that lacks the leading
``data/`` can all leave a path stageable while the grep still succeeds. Asking
git resolves precedence the same way ``git add`` will.

Paths are asserted whether or not they exist right now. A rule that only works
once the feature has run is a rule that fails on a fresh clone, which is exactly
when a first commit is most likely to sweep the file in.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

# Each entry is (relative path, why it must never be committed).  The reason is
# carried into the assertion message so a failure explains the stakes instead of
# just naming a path.
SECRET_PATHS = [
    (
        "data/wireguard-peers.json",
        "holds the client private keys the WireGuard panel issued -- a server "
        "conf only stores peers' public halves, so this file is the one place "
        "the private halves exist",
    ),
    (
        "data/pf.conf.staged",
        "a verbatim copy of the machine's live /etc/pf.conf, including its real "
        "rules and interface names",
    ),
    (
        "data/pf-anchor-wireguard",
        "renders the host's real egress interface and tunnel subnet",
    ),
    (
        "data/wg0.sync.conf",
        "the config handed to `wg syncconf`, containing peer key material",
    ),
    (
        "data/.session-secret",
        "signs session cookies; leaking it forges any administrator's session",
    ),
    ("data/.local-client-token", "authenticates the menu-bar client to the API"),
    ("data/.setup-token", "authorises first-run setup"),
    ("data/service-credentials.json", "the per-service credential index"),
    ("services.yaml", "the live inventory: real host addresses and secrets"),
    ("services.yaml.bak.1", "a backup of the live inventory (services.yaml.bak.*)"),
    (
        "services.yaml.bak-20260807-182329",
        "a backup of the live inventory with a dash before the timestamp -- the "
        "form the panel actually writes at the repository root.  The `.bak.*` "
        "rule matched only the dotted form, and this table only listed the "
        "dotted form, so a verbatim copy of services.yaml sat stageable in the "
        "working tree while both the rule and this test looked correct",
    ),
    (
        "services.yaml.precredrestore.20260807-111549",
        "an inventory snapshot before a credential restore, at the repository "
        "root rather than under data/",
    ),
    ("data/services.yaml.bak.1", "a backup of the live inventory under data/"),
    (".env", "conventional home for deployment secrets"),
    ("data/tunnel.key", "any private key (*.key)"),
    ("data/cert.pem", "any certificate or key bundle (*.pem)"),
    (
        "data/auth-audit.jsonl",
        "every sign-in attempt with the administrator's username and the "
        "client's real address",
    ),
    (
        "data/auth-audit.jsonl.bak-20260805-112015",
        "a rotated copy of the auth trail; the live-log rule does not cover "
        "the timestamped backups the rotator leaves beside it, and the "
        "records carry the same username and client fields",
    ),
    (
        "data/terminal-audit.jsonl.1",
        "a rotated terminal audit log: recorded commands and their arguments",
    ),
    (
        "data/services.yaml.precredrestore.20260807-111549",
        "an inventory snapshot taken before a credential restore; the "
        "`.bak.*` rule matched only one of the several suffixes the panel "
        "writes, and this one carries the same hosts and secrets as "
        "services.yaml itself",
    ),
    (
        "data/pf.conf.check",
        "a copy of the machine's live firewall ruleset, which names its real "
        "egress interface and internal addresses",
    ),
    (
        "data/.services.yaml.lock",
        "the inventory write mutex: pure runtime state that is meaningless in "
        "a clone, and a tracked lock file would be checked out held",
    ),
    (
        "data/uninstalled-agents/com.example.worker.20260816-000000.plist",
        "an archived LaunchAgent plist from uninstall: real program paths and "
        "working directories on this machine",
    ),
    (
        "data/com.elvin.wstunnel-wg-server.plist",
        "the staged root wstunnel LaunchDaemon: host listen address and the "
        "WireGuard restrict-to target, written 0600 under data/ before sudo cp",
    ),
    (
        "data/twofa.json",
        "TOTP secret and recovery hashes; leaking it disables two-factor "
        "for every enrolled account",
    ),
    (
        "data/twofa.json.lock",
        "the 2FA write mutex; runtime state that must not travel with a clone",
    ),
    (
        "data/api-keys.json",
        "the bearer API key store: a sha256 per key plus its role and label.  "
        "It is written 0600 through secure_io exactly like data/twofa.json, "
        "which was listed here, while this one was not -- the rules named the "
        "files a reviewer remembered rather than the directory they all live in",
    ),
    (
        "data/exports.staged",
        "the /etc/exports the NFS panel is about to install, copied verbatim: "
        "the real export paths and the client addresses allowed to mount them.  "
        "Same class as data/pf.conf.staged, which was covered",
    ),
    (
        "data/smart-tests.json",
        "SMART self-test history keyed by this machine's device nodes",
    ),
    (
        "data/docker-update-status.json",
        "the image-update scan result: every image and tag this host runs",
    ),
    (
        "data/ups-policy-state.json",
        "UPS shutdown-policy state; per-machine runtime state",
    ),
    (
        "data/anything-a-future-feature-writes.json",
        "the point of the data/ rule: this directory is per-machine runtime "
        "state end to end, so a store added by a later feature must be "
        "unstageable before anyone thinks to name it here.  Four files had "
        "already escaped the per-name rules by the time this was written",
    ),
]


def git_ignores(rel: str) -> tuple[bool, str]:
    """Return (ignored, matching rule) for *rel* according to git itself.

    The exit status alone is not the answer.  Under ``-v``, ``git check-ignore``
    exits 0 whenever *any* pattern matched -- including a negation -- and prints
    that pattern with a leading ``!``.  So a whitelisted path such as
    ``services.yaml.example`` comes back as rc=0 with
    ``.gitignore:33:!services.yaml.example``, which reads as "ignored" if only the
    status is consulted.  Without ``-v`` the same path exits 1, i.e. the two
    invocations disagree on the very question being asked.

    The negation is therefore resolved from the pattern text.  ``-v`` is kept
    because the rule is worth reporting in a failure message, and because a
    negation matching a *secret* path is precisely the precedence bug this file
    exists to catch -- silently coercing rc=0 to "ignored" would hide it.
    """
    proc = subprocess.run(
        ["git", "check-ignore", "-v", "--no-index", "--", rel],
        cwd=BASE,
        capture_output=True,
        text=True,
    )
    # 0 = some pattern matched (stdout names it), 1 = none did, >1 = git error.
    if proc.returncode == 1:
        return False, ""
    if proc.returncode != 0:
        raise AssertionError(f"git check-ignore failed for {rel}: {proc.stderr.strip()}")
    rule = proc.stdout.strip()
    # Format: `<source>:<lineno>:<pattern>\t<pathname>`.  Split the pattern off
    # by field position rather than searching for "!", which would also fire on
    # a path or pattern that merely contains one.
    head = rule.split("\t")[0]
    parts = head.split(":", 2)
    pattern = parts[2] if len(parts) == 3 else ""
    return not pattern.startswith("!"), rule


class GitIgnoreCoversSecretsTests(unittest.TestCase):
    def test_git_is_available(self):
        # Without this the whole file would pass vacuously in a source tarball.
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=BASE,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            "these tests assert a git property and need a real work tree",
        )

    def test_every_secret_path_is_ignored(self):
        missing = []
        for rel, why in SECRET_PATHS:
            ignored, rule = git_ignores(rel)
            if not ignored:
                missing.append(f"  {rel} -- {why}")
            else:
                self.assertTrue(rule, f"{rel}: ignored but no rule reported")
        self.assertEqual(
            missing,
            [],
            "these paths can be staged by `git add` even though they hold "
            "secrets:\n" + "\n".join(missing),
        )

    def test_no_secret_path_is_already_tracked(self):
        """A rule cannot save a file git is already tracking."""
        proc = subprocess.run(
            ["git", "ls-files", "--"] + [rel for rel, _ in SECRET_PATHS],
            cwd=BASE,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            proc.stdout.strip(),
            "",
            "a secret-bearing path is tracked; .gitignore does not apply to "
            "tracked files, so this needs `git rm --cached` and a history review",
        )

    def test_the_committed_example_inventory_stays_committable(self):
        """The template must not be swept up by the services.yaml rules."""
        ignored, rule = git_ignores("services.yaml.example")
        self.assertFalse(
            ignored,
            f"services.yaml.example is the committed template but is ignored by {rule}",
        )


if __name__ == "__main__":
    unittest.main()
