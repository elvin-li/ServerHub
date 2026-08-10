"""Uninstall a LaunchAgent-managed service from the Services page.

Scope is deliberately narrow.  "Uninstall" here means *stop supervising this
service*, not "delete the software":

    1. ``launchctl bootout``  — stop it and remove it from the user domain
    2. move its ``.plist`` into a timestamped backup directory

Program binaries, configuration files, databases and logs are never touched, so
the action is reversible: the operator can copy the plist back and bootstrap it.
Anything that is not a plain user LaunchAgent (containers, VMs, brew formulae,
scripts) is refused rather than half-handled, and ServerHub itself is protected
so the panel cannot uninstall the process serving the request.
"""
from __future__ import annotations

import plistlib
import re
import shutil
import time
from pathlib import Path
from typing import Any

from hub.errors import api_error
from hub.launchd_cache import invalidate_launchd
from hub.paths import AGENTS_DIR, DATA_DIR, UID
from hub.util import sh

#: Backups live in private mutable state so a removed plist is recoverable.
BACKUP_DIR = DATA_DIR / "uninstalled-agents"

#: Labels the panel must never bootout.  Removing the panel or menu bar kills the
#: request in flight and leaves no supervised process to restore it; removing the
#: tunnel silently cuts the remote access path an operator may be using *right
#: now* to click the button, with no way back in.  Restoring any of these means
#: local shell access, so they are refused here rather than merely confirmed.
#: Several spellings reach this guard because the panel agent has been installed
#: under different labels over time: ``install.sh`` writes the dotted names, the
#: native ServerHub.app writes the hyphenated ones, and distribution builds use a
#: ``com.elvin`` prefix.  All of them point at the very same supervised job, so
#: every spelling must be refused -- protecting only one would let the others
#: through and unload the panel serving the request.
PROTECTED_LABELS = frozenset({
    # install.sh / source installs
    "local.serverhub.panel",
    "local.serverhub.menubar",
    "local.serverhub.launcher",
    # ServerHubLauncher.swift / native app installs
    "local.serverhub",
    "local.serverhub-launcher",
    "local.serverhub-menubar",
    # distribution installs
    "com.elvin.serverhub",
    "com.elvin.serverhub-launcher",
    "com.elvin.serverhub-menubar",
    "local.cloudflared-tunnel",
})

#: launchd labels are reverse-DNS-ish.  Restricting the character set keeps the
#: value safe to use as a launchctl argument and as a filename.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _plist_path(label: str) -> Path:
    """Resolve *label* to a plist inside AGENTS_DIR, or refuse.

    The path is resolved and re-checked against the agents directory so a label
    can never traverse out of it, even if the regex is later loosened.
    """
    agents = Path(AGENTS_DIR).resolve()
    candidate = (agents / f"{label}.plist").resolve()
    if candidate.parent != agents:
        raise api_error("services.uninstall_not_supported", id=label)
    return candidate


def preview(label: str) -> dict[str, Any]:
    """Describe exactly what an uninstall would do, without changing anything."""
    label = (label or "").strip()
    if not _LABEL_RE.match(label):
        raise api_error("services.uninstall_not_supported", id=label or "?")
    # Compared case-insensitively: launchd labels are case-sensitive, but the
    # LaunchAgents directory lives on a case-insensitive volume by default, so
    # "Local.Serverhub.Panel" resolves to the real panel plist. Matching exactly
    # would let a differently-cased spelling slip past this guard and archive a
    # protected agent's plist.
    if label.lower() in PROTECTED_LABELS:
        raise api_error("services.uninstall_protected", id=label)

    path = _plist_path(label)
    if not path.is_file():
        # Distinct from "not supported": the caller named a plausible agent that
        # simply is not installed here, which the UI reports differently.
        raise api_error("services.uninstall_unknown", id=label)

    program = ""
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
        args = data.get("ProgramArguments") or []
        program = str(args[0]) if args else str(data.get("Program") or "")
    except Exception:
        # An unreadable plist can still be booted out and archived; the preview
        # simply has less to show.
        program = ""

    return {
        "label": label,
        "plist": str(path),
        "program": program,
        # Spelled out so the confirmation dialog can state the blast radius
        # instead of a vague "are you sure".
        "removes": ["launchd registration", "plist file (backed up)"],
        "keeps": ["program files", "configuration", "data", "logs"],
        "reversible": True,
    }


def uninstall(label: str) -> dict[str, Any]:
    """Bootout *label* and archive its plist. Idempotent for a missing agent."""
    info = preview(label)
    path = Path(info["plist"])

    # bootout is best-effort: an agent that is already unloaded returns non-zero
    # but the uninstall should still complete and archive the plist.
    rc, out, err = sh(["/bin/launchctl", "bootout", f"gui/{UID}/{label}"], timeout=20)
    # The services page refetches right after an uninstall and reads the shared
    # listing (hub/launchd_cache.py); without this it would still show the agent.
    invalidate_launchd()
    booted_out = rc == 0

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        BACKUP_DIR.chmod(0o700)
    except OSError:
        pass

    backup = BACKUP_DIR / f"{label}.{time.strftime('%Y%m%d-%H%M%S')}.plist"
    try:
        shutil.move(str(path), str(backup))
    except OSError as exc:
        raise api_error("services.uninstall_failed", id=label, error=str(exc))
    try:
        backup.chmod(0o600)
    except OSError:
        pass

    try:
        from hub.status import invalidate_status
        invalidate_status()
    except Exception:
        pass

    return {
        "ok": True,
        "label": label,
        "booted_out": booted_out,
        "backup": str(backup),
        "detail": (out or err or "").strip(),
        "restore_hint": f"cp {backup} {path} && launchctl bootstrap gui/{UID} {path}",
    }
