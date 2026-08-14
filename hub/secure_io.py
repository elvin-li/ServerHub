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

import errno
import os
from pathlib import Path

SECRET_MODE = 0o600
SECRET_DIR_MODE = 0o700


def _open_flags(*base: int) -> int:
    """Combine open flags and add O_NOFOLLOW when the platform supports it."""
    flags = 0
    for flag in base:
        flags |= flag
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise OSError(errno.ELOOP, "Refusing to write through a symlink", str(path))


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
    # A planted symlink at the secret path must not become write-through to a
    # file the attacker chooses.  O_NOFOLLOW covers the open; the lexists check
    # gives a clear error before chmod would follow the link on some platforms.
    _refuse_symlink(p)
    if p.exists():
        # Tighten first: truncating a 0644 file and then writing would expose
        # the new content for the duration of the write.
        os.chmod(p, SECRET_MODE)
    fd = os.open(p, _open_flags(os.O_WRONLY, os.O_CREAT, os.O_TRUNC), SECRET_MODE)
    # fdopen takes ownership of fd, so its context manager closes it on both the
    # success and the exception path.
    with os.fdopen(fd, "w", encoding=encoding) as fh:
        fh.write(content)
    # A pre-existing file keeps its original mode through O_CREAT, so enforce it.
    os.chmod(p, SECRET_MODE)
    return p


def create_secret_text(path: Path | str, content: str, *, encoding: str = "utf-8") -> bool:
    """Create ``path`` with ``content`` only if it does not exist yet.

    Returns True if the file was created, False if it was already there.

    This exists because "write the defaults if the config is missing" must not be
    expressed as ``if not path.exists(): write_secret_text(...)``.  That reads the
    filesystem twice and trusts the first answer: when ``exists()`` returned a
    false negative, the second step truncated a fully populated services.yaml
    down to defaults and took the admin account, every app and every bookmark
    with it.  O_EXCL asks the kernel to make the decision and the write in one
    step, so a wrong answer means "nothing happened" rather than "data gone".
    """
    p = Path(path)
    _ensure_private_parents(p)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SECRET_MODE)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding=encoding) as fh:
        fh.write(content)
    os.chmod(p, SECRET_MODE)
    return True


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


def copy_secret_file(src: Path | str, dst: Path | str) -> Path:
    """Copy ``src`` to ``dst`` without ever publishing the copy.

    ``shutil.copy2`` is wrong for secrets in two distinct ways.  It creates the
    destination at the umask and only *then* copies the source's mode, so the
    bytes are world-readable for the duration of the copy; and when the source
    itself is world-readable (a repo-shipped ``.example``) it faithfully
    reproduces that mode.  Reading the source and re-writing it through
    ``write_secret_text`` gets both right: the destination is 0600 from its
    first byte regardless of what the source was.

    Bytes rather than text so this stays usable for non-UTF-8 payloads.
    """
    s, d = Path(src), Path(dst)
    data = s.read_bytes()
    _ensure_private_parents(d)
    _refuse_symlink(d)
    if d.exists():
        os.chmod(d, SECRET_MODE)
    fd = os.open(d, _open_flags(os.O_WRONLY, os.O_CREAT, os.O_TRUNC), SECRET_MODE)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(d, SECRET_MODE)
    return d


def make_secret_dir(path: Path | str) -> Path:
    """Create ``path`` (and parents) owner-only."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, SECRET_DIR_MODE)
    except PermissionError:
        pass
    return p
