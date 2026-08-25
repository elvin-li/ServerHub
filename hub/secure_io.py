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
import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path

from hub.util import read_bytes_capped

SECRET_MODE = 0o600
SECRET_DIR_MODE = 0o700
#: Leftover multi-MB source used to OOM ``copy_secret_file`` (settings backup).
SECRET_COPY_CAP = 1024 * 1024


def drop_leftover_nonfile(path: Path | str) -> None:
    """Unlink a leftover directory/socket occupying a file the panel writes.

    ``os.replace`` onto a leftover directory is ``IsADirectoryError`` and used
    to 500 the request that persisted credentials, peer registry, PhotosHub
    config, or alert state.
    """
    p = Path(path)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return
    except OSError:
        return
    if stat.S_ISREG(st.st_mode):
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            os.rmdir(p)
        else:
            os.unlink(p)
    except OSError:
        pass


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
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        st = None
    if st is not None:
        if stat.S_ISLNK(st.st_mode):
            raise OSError(errno.ELOOP, "refusing to follow symlink", str(p))
        # Tighten first: truncating a 0644 file and then writing would expose
        # the new content for the duration of the write.
        os.chmod(p, SECRET_MODE)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, SECRET_MODE)
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
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, SECRET_MODE)
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
    # Per-writer temp: a fixed "name.tmp" collides when two panel processes
    # save secrets concurrently (config save + credentials apply).
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    try:
        # O_EXCL so a pre-created guessable tmp cannot be truncated and
        # filled with the secret, then os.replace'd onto the live file.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, SECRET_MODE)
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(content)
        os.replace(tmp, p)
        os.chmod(p, SECRET_MODE)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return p


def replace_bytes(path: Path | str, data: bytes, *, mode: int = 0o644) -> Path:
    """Atomically install *data* at *path* (plists, caches — not secrets).

    ``open(path, \"wb\")`` + dump tears the file if the process dies mid-write;
    launchd then refuses to load the agent.  Same tmp+replace as
    :func:`replace_secret_text`, but the default mode is 0644.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, p)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return p


def copy_secret_file(
    src: Path | str, dst: Path | str, *, max_bytes: int = SECRET_COPY_CAP
) -> Path:
    """Copy ``src`` to ``dst`` without ever publishing the copy.

    ``shutil.copy2`` is wrong for secrets in two distinct ways.  It creates the
    destination at the umask and only *then* copies the source's mode, so the
    bytes are world-readable for the duration of the copy; and when the source
    itself is world-readable (a repo-shipped ``.example``) it faithfully
    reproduces that mode.  Reading the source and re-writing it through
    ``write_secret_text`` gets both right: the destination is 0600 from its
    first byte regardless of what the source was.

    Bytes rather than text so this stays usable for non-UTF-8 payloads.
    Unbounded reads of leftover multi-MB services.yaml used to OOM
    PUT /api/settings during the pre-save backup.
    """
    s, d = Path(src), Path(dst)
    data = read_bytes_capped(s, max_bytes)
    _ensure_private_parents(d)
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        st = None
    if st is not None:
        if stat.S_ISLNK(st.st_mode):
            raise OSError(errno.ELOOP, "refusing to follow symlink", str(d))
        os.chmod(d, SECRET_MODE)
    fd = os.open(d, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, SECRET_MODE)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(d, SECRET_MODE)
    return d


def append_text(
    path: Path | str, content: str, *, encoding: str = "utf-8", mode: int = 0o644
) -> Path:
    """Append *content* to *path* without following a last-component symlink.

    ``open(path, "a")`` follows a replacement symlink and writes wherever it
    points.  Audit, metrics and alerts journals live under a writable data
    directory; a planted symlink would redirect the next line onto another
    file the panel user can write.

    ``O_NONBLOCK`` + the regular-file check: a leftover FIFO occupying a
    journal used to park this open until a reader appeared — the metrics
    sampler wedged holding its buffer lock, and GET /api/metrics hung behind
    it.  A FIFO now raises OSError (ENXIO from the open, or EINVAL from the
    check when a reader exists), the same failure class a leftover directory
    already produced.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        p,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0),
        mode,
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(p))
    except Exception:
        os.close(fd)
        raise
    with os.fdopen(fd, "a", encoding=encoding) as fh:
        fh.write(content)
    return p


def _lock_fd(lock_path: Path) -> int | None:
    """flock fd, or None when a leftover node / EIO blocks creating it."""
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            st = os.lstat(lock_path)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            try:
                if stat.S_ISDIR(st.st_mode):
                    os.rmdir(lock_path)
                else:
                    os.unlink(lock_path)
            except OSError:
                return None
        return os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None


@contextmanager
def file_lock(path: Path | str):
    """Exclusive cross-process flock for read-modify-write of *path*.

    The same arrangement config, twofa_svc and api_keys each grew by hand: a
    sibling ``<name>.lock`` file rather than the target itself, because the
    atomic tmp+replace writers in this module swap the target's inode and a
    lock held on the old inode silently stops excluding anybody.

    A leftover directory named ``<name>.lock``, or EIO creating it, must not
    break the caller — the context simply runs unlocked in that case, which is
    exactly the in-process-lock-only behaviour callers had before.

    The same fallback covers ``flock`` itself.  ENOLCK/EIO from the lock call
    (data/ on NFS with lockd down is the classic) used to raise out of the
    context manager; audit.record()'s logging-never-breaks-the-request except
    then swallowed it and the sign-in line was silently lost even though the
    trail was perfectly writable.  Unlock failures after the body are eaten
    for the same reason: the write already happened, and ``os.close`` releases
    the lock regardless.
    """
    p = Path(path)
    fd = _lock_fd(p.with_name(p.name + ".lock"))
    if fd is None:
        yield
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            yield
            return
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(fd)


def make_secret_dir(path: Path | str) -> Path:
    """Create ``path`` (and parents) owner-only."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, SECRET_DIR_MODE)
    except PermissionError:
        pass
    return p
