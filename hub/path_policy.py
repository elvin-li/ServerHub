"""Shared sensitive-path policy for browse, SMB, and NFS surfaces.

The file browser denylist (:mod:`hub.files_svc`) is the source of truth for
basenames and leaf trees.  SMB and NFS also need *directory roots* that must
not be published (and whose parents must not be shared, or nested secrets leak).
Keep that root list here so the three surfaces cannot drift apart.
"""
from __future__ import annotations

from pathlib import Path

from hub.paths import BASE, STATE_ROOT


def sensitive_export_roots() -> tuple[Path, ...]:
    """Resolved trees that must not be shared/exported (nor have a parent shared)."""
    home = Path.home()
    return (
        BASE.resolve(),
        STATE_ROOT.resolve(),
        (home / ".ssh").resolve(),
        (home / ".aws").resolve(),
        (home / ".gnupg").resolve(),
        (home / ".kube").resolve(),
        (home / "Library" / "Keychains").resolve(),
        (home / "Services" / "backups").resolve(),
        (home / "Services" / "filebrowser").resolve(),
        (home / "Services" / "cloudflared").resolve(),
        (home / "Services" / "private_integration").resolve(),
        (home / ".cloudflared").resolve(),
    )


def path_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def touches_sensitive_export(path: Path) -> bool:
    """True when *path* is inside a sensitive tree or is an ancestor of one."""
    real = path.resolve()
    return any(
        path_inside(real, root) or path_inside(root, real)
        for root in sensitive_export_roots()
    )
