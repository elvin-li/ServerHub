"""Create secret-bearing files without a world-readable window.

``Path.write_text()`` followed by ``chmod(0o600)`` is the pattern this module
replaces.  Under the default umask of 022 the file is born 0644, so between the
write and the chmod every local user on the machine can read it.  The payloads
this affects are real credentials: Cloudflare tunnel tokens, generated database
and admin passwords inside compose files, and the template variable dumps that
carry those same passwords.

``hub/auth.py`` already got this right with
``os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)``.  The helpers here generalise
that so the rest of the codebase has one obvious way to do it, including the
atomic replace-an-existing-file case that O_EXCL alone cannot express.
"""
from __future__ import annotations

import os
from pathlib import Path

SECRET_MODE = 0o600
SECRET_DIR_MODE = 0o700


def _ensure_private_parents(path: Path) -> None:
    """Create every missing ancestor of ``path`` as an owner-only directory.

    ``mkdir(mode=...)`` is masked by the umask and, with ``parents=True``, does
    not apply the mode to the intermediate levels at all, so each newly created
    level is chmod'ed explicitly.  Directories that already exist are left
    alone: tightening a pre-existing shared directory is not this helper's
    call to make.
    """
    missing = []
    cur = path.parent
    while not cur.is_dir():
        missing.append(cur)
        if cur.parent == cur:
            break
        cur = cur.parent

    for d in reversed(missing):
        d.mkdir(exist_ok=True)
        os.chmod(d, SECRET_DIR_MODE)


def write_secret_text(path: Path | str, content: str, *, encoding: str = "utf-8") -> Path:
    """Write ``content`` to ``path``, never leaving it readable by other users.

    The file is created (or truncated) through a file descriptor opened with the
    restrictive mode, so it is 0600 from the moment it first exists.  An
    already-existing file has its mode tightened before the new bytes land,
    because O_TRUNC on a 0644 file would otherwise publish the new secret.
    """
    p = Path(path)
    _ensure_private_parents(p)
    if p.exists():
        # Tighten first: truncating a 0644 file and then writing would expose
        # the new content for the duration of the write.
        os.chmod(p, SECRET_MODE)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECRET_MODE)
    # fdopen takes ownership of fd, so its context manager closes it on both the
    # success and the exception path.
    with os.fdopen(fd, "w", encoding=encoding) as fh:
        fh.write(content)
    # A pre-existing file keeps its original mode through O_CREAT, so enforce it.
    os.chmod(p, SECRET_MODE)
    return p


def replace_secret_text(
    path: Path | str, content: str, *, encoding: str = "utf-8"
) -> Path:
    """Atomically install ``content`` at ``path`` via a 0600 temp file.

    Use this where a partially written file would be worse than no update, e.g.
    a credential index another process reads concurrently.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    write_secret_text(tmp, content, encoding=encoding)
    os.replace(tmp, p)
    os.chmod(p, SECRET_MODE)
    return p


def make_secret_dir(path: Path | str) -> Path:
    """Create ``path`` (and parents) owner-only."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, SECRET_DIR_MODE)
    return p
