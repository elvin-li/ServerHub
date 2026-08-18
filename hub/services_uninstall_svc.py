"""Uninstall a LaunchAgent-managed service from the Services page.

Scope is deliberately narrow.  The default action is *stop supervising this
service*, not "delete the software":

    1. ``launchctl bootout``  — stop it and remove it from the user domain
    2. move its ``.plist`` into a timestamped backup directory
    3. drop the ``services.yaml`` override so the row does not linger

Program binaries stay on disk unless the caller sets ``remove_data=True``, and
even then the tree is removed only when it sits strictly inside ``~/Services``.
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

#: Program trees may be deleted only when they sit strictly inside this root.
#: The live Kiro-Go agent (and other self-hosted LaunchAgents) keep their
#: binary and config under ~/Services/<name>; nothing outside that tree is
#: ever removed by this path.
SERVICES_ROOT = Path.home() / "Services"

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


def _forget_override(label: str) -> None:
    """Drop the services.yaml override so the row does not stay as a ghost."""
    try:
        from hub.config import drop_override
        drop_override(label)
    except Exception:
        pass


def _tree_under_services(path: Path | None) -> Path | None:
    """Return *path* if it is a directory strictly inside ~/Services."""
    if path is None:
        return None
    try:
        resolved = path.expanduser().resolve()
        root = Path(SERVICES_ROOT).expanduser().resolve()
    except OSError:
        return None
    if resolved == root or root not in resolved.parents:
        return None
    return resolved


def _removable_tree(program: str, workdir: str) -> Path | None:
    """Working directory, or the program's parent, when either is under Services."""
    for raw in (workdir, str(Path(program).parent) if program else ""):
        if not raw:
            continue
        tree = _tree_under_services(Path(raw))
        if tree is not None:
            return tree
    return None


def _agent_paths(path: Path) -> tuple[str, str, str]:
    """``(label, program, workdir)`` from one plist, tolerating a broken file."""
    try:
        data = plistlib.loads(path.read_bytes())
    except Exception:
        return path.stem, "", ""
    args = data.get("ProgramArguments") or []
    program = str(args[0]) if args else str(data.get("Program") or "")
    return (
        str(data.get("Label") or path.stem),
        program,
        str(data.get("WorkingDirectory") or ""),
    )


def _other_agents_in(tree: Path, label: str) -> list[str]:
    """Other installed agents whose program or workdir lives inside *tree*.

    ``WorkingDirectory`` (and a program's parent) is routinely a *shared*
    deployment directory rather than one agent's private files: on a typical
    host ``local.immich-logrotate`` -- a log rotation helper -- names
    ``~/Services/immich``, which is the entire Immich deployment including the
    compose file, ``.env`` and its sibling agents' programs.  Deleting the tree
    on the strength of one agent naming it takes the other agents with it, so
    ``remove_data`` is only offered when nothing else lives there.
    """
    agents = Path(AGENTS_DIR)
    if not agents.is_dir():
        return []
    users: list[str] = []
    for path in sorted(agents.glob("*.plist")):
        if path.stem.lower() == label.lower():
            continue
        other, program, workdir = _agent_paths(path)
        if other.lower() == label.lower():
            continue
        for raw in (workdir, str(Path(program).parent) if program else ""):
            if not raw:
                continue
            try:
                resolved = Path(raw).expanduser().resolve()
            except OSError:
                continue
            if resolved == tree or tree in resolved.parents:
                users.append(other)
                break
    return sorted(set(users))


def _plist_path(label: str) -> Path:
    """Resolve *label* to a plist inside AGENTS_DIR, or refuse.

    The path is resolved and re-checked against the agents directory so a label
    can never traverse out of it, even if the regex is later loosened.

    launchd registers the job under the plist's ``Label``, which can differ
    from the filename.  Matching only ``<label>.plist`` made uninstall report
    "unknown" for a job the services page had just shown.
    """
    agents = Path(AGENTS_DIR).resolve()
    candidate = (agents / f"{label}.plist").resolve()
    if candidate.parent != agents:
        raise api_error("services.uninstall_not_supported", id=label)
    if candidate.is_file():
        declared, _, _ = _agent_paths(candidate)
        if declared == label or declared.lower() == label.lower():
            return candidate
    try:
        for path in sorted(agents.glob("*.plist")):
            resolved = path.resolve()
            if resolved.parent != agents:
                continue
            declared, _, _ = _agent_paths(resolved)
            if declared == label or declared.lower() == label.lower():
                return resolved
    except OSError:
        pass
    # A leftover ``<label>.plist`` whose Label is some other job must not
    # be archived under this name.
    if candidate.is_file():
        raise api_error("services.uninstall_unknown", id=label)
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
    workdir = ""
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
        args = data.get("ProgramArguments") or []
        program = str(args[0]) if args else str(data.get("Program") or "")
        workdir = str(data.get("WorkingDirectory") or "")
    except Exception:
        # An unreadable plist can still be booted out and archived; the preview
        # simply has less to show.
        program = ""
        workdir = ""

    tree = _removable_tree(program, workdir)
    shared_with = _other_agents_in(tree, label) if tree is not None else []
    removes = ["launchd registration", "plist file (backed up)", "panel override"]
    # Default uninstall keeps the program tree.  ``can_remove_data`` is the
    # signal that those files *may* be deleted; the confirmation UI decides.
    keeps = ["program files", "configuration", "data", "logs"]

    return {
        "label": label,
        "plist": str(path),
        "program": program,
        "workdir": workdir,
        "can_remove_data": bool(
            tree is not None and tree.exists() and not shared_with
        ),
        "remove_data_path": str(tree) if tree is not None else "",
        #: Why ``can_remove_data`` is false despite a tree being present.
        "remove_data_shared_with": shared_with,
        # Spelled out so the confirmation dialog can state the blast radius
        # instead of a vague "are you sure".
        "removes": removes,
        "keeps": keeps,
        "reversible": True,
    }


def uninstall(label: str, *, remove_data: bool = False) -> dict[str, Any]:
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

    removed_tree = ""
    # Re-derived from preview()'s own verdict rather than from remove_data_path:
    # the path is present even when the tree is shared, and deleting it then
    # would take the sibling agents' programs with it.
    if remove_data and info.get("can_remove_data"):
        tree = _tree_under_services(Path(info.get("remove_data_path") or ""))
        if tree is not None and tree.is_dir():
            try:
                shutil.rmtree(tree)
                removed_tree = str(tree)
            except OSError as exc:
                raise api_error("services.uninstall_failed", id=label, error=str(exc))

    _forget_override(label)

    try:
        from hub.status import invalidate_status
        invalidate_status()
    except Exception:
        pass
    try:
        from hub.apps_manage_svc import invalidate_inventory
        invalidate_inventory()
    except Exception:
        pass

    return {
        "ok": True,
        "label": label,
        "booted_out": booted_out,
        "backup": str(backup),
        "removed_tree": removed_tree,
        "detail": (out or err or "").strip(),
        "restore_hint": f"cp {backup} {path} && launchctl bootstrap gui/{UID} {path}",
    }
