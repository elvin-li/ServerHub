"""Paths and binary locations (OrbStack / UTM / smartctl)."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from hub import secure_io


def _expand_root(raw) -> Path:
    """Best-effort ``Path.expanduser().resolve()``.

    ``SERVERHUB_RUNTIME_DIR=~/…`` leftover used to RuntimeError import of
    every route when HOME was unset; leftover NUL is ValueError.
    """
    try:
        return Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        try:
            return Path(raw).resolve()
        except (OSError, RuntimeError, ValueError):
            return Path(str(raw) or ".")


RUNTIME_ROOT = _expand_root(
    os.environ.get("SERVERHUB_RUNTIME_DIR") or Path(__file__).resolve().parent.parent
)
# BASE remains the compatibility name for the immutable application/runtime
# tree. Packaged builds keep mutable state outside the signed app bundle.
BASE = RUNTIME_ROOT
_STATE_OVERRIDE = os.environ.get("SERVERHUB_STATE_DIR", "").strip()
STATE_ROOT = (
    _expand_root(_STATE_OVERRIDE)
    if _STATE_OVERRIDE
    else RUNTIME_ROOT
)
DATA_DIR = STATE_ROOT / "data"
CONFIG_FILE = STATE_ROOT / "services.yaml"


def ensure_state_dirs() -> None:
    """Create private writable state directories for packaged installations."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    # DATA_DIR holds the session secret, the setup token, the local client
    # token, the service-credential index and the timestamped services.yaml
    # backups -- secrets on every install, not just packaged ones.  Tightening
    # it only when SERVERHUB_STATE_DIR was set left source installs at the
    # umask default (0755), so every local user could list those filenames and
    # watch tokens appear.  The files themselves are 0600, so this closes a
    # metadata leak rather than a content leak, but the directory has no reason
    # to be traversable by anyone else.
    secure_io.make_secret_dir(DATA_DIR)
    if _STATE_OVERRIDE:
        # Only tighten the root when it is a dedicated state directory.  On a
        # source install STATE_ROOT *is* the checkout, and clamping the whole
        # project tree to 0700 is not this function's call to make.
        STATE_ROOT.chmod(0o700)


def user_home() -> Path | None:
    """Best-effort ``Path.home()``.

    RuntimeError when HOME cannot be resolved, ValueError on a leftover NUL
    in HOME: either used to 500 GET /api/logs, GET /api/stacks, GET /api/catalog,
    GET /api/apps, compose create/validate, and launcher login.
    """
    try:
        return Path.home()
    except (OSError, RuntimeError, ValueError):
        return None


def _bin_exists(path: str, *, as_file: bool = False) -> bool:
    """``Path.exists`` / ``is_file`` leftover EIO used to 500 import of hub.paths."""
    if not path:
        return False
    try:
        p = Path(path)
        return p.is_file() if as_file else p.exists()
    except (OSError, ValueError):
        return False


#: Root-owned copies of the few binaries that are granted passwordless sudo.
#:
#: Narrowing a sudoers rule's arguments is only worth something if the program
#: itself cannot be replaced, and Homebrew's binaries can be: `brew` chowns its
#: whole prefix to the installing account, so /opt/homebrew/bin and everything in
#: it is writable by the very user the rule is granted to.  A NOPASSWD rule on
#: /opt/homebrew/bin/smartctl is therefore passwordless root -- overwrite the
#: file, run the rule.
#:
#: /usr/local is root:wheel on macOS and Homebrew does not touch it on Apple
#: Silicon, so copies placed here cannot be swapped by the panel user.
#: deploy/install-sudoers.sh creates them; the sudoers template grants only
#: these paths.
PINNED_BIN_DIR = Path("/usr/local/libexec/serverhub")


def _is_root_owned(path: Path) -> bool:
    """True when *path* cannot be modified by anyone but root.

    Checked rather than assumed: using a "pinned" copy that turned out to be
    writable would be worse than not pinning at all, because the sudoers rule
    names it.
    """
    try:
        st = path.stat()
    except OSError:
        return False
    # uid 0, and not writable by group or other.
    return st.st_uid == 0 and not (st.st_mode & 0o022)


def pinned_or(name: str, fallback: str) -> str:
    """The root-owned copy of *name* if it is usable, else *fallback*.

    Falling back is deliberate: on a machine where the copies were never
    installed the panel still works, it just has to ask for the administrator
    password for the operations that need root.  That is the safe direction --
    the alternative is silently executing a binary the sudoers rule does not
    actually cover.
    """
    candidate = PINNED_BIN_DIR / name
    if _is_root_owned(candidate) and os.access(candidate, os.X_OK):
        return str(candidate)
    return fallback


DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
_orb_candidates = [
    shutil.which("orb") or "",
    "/opt/homebrew/bin/orb",
    "/usr/local/bin/orb",
]
ORB = next((p for p in _orb_candidates if _bin_exists(p, as_file=True)), "/usr/local/bin/orb")
# Current OrbStack exposes management subcommands through ``orb`` even when a
# separate orbctl binary is absent.  Keep the old name for callers/API shape.
ORBCTL = shutil.which("orbctl") or ORB


def _utmctl_candidates() -> list[str]:
    """User Applications fallback.  ``Path.home()`` leftover must not 500 import."""
    home = user_home()
    extra = (
        [] if home is None else [str(home / "Applications/UTM.app/Contents/MacOS/utmctl")]
    )
    return [
        shutil.which("utmctl") or "",
        "/Applications/UTM.app/Contents/MacOS/utmctl",
        *extra,
    ]


UTMCTL = next(
    (p for p in _utmctl_candidates() if _bin_exists(p)),
    "/Applications/UTM.app/Contents/MacOS/utmctl",
)
SMARTCTL = pinned_or("smartctl", shutil.which("smartctl") or "/opt/homebrew/bin/smartctl")
# Homebrew prefix differs between Apple Silicon (/opt/homebrew) and Intel
# (/usr/local).  Several modules had their own copy of this fallback; hub.brew_cache
# imports it from here so there is one definition.  which() first so a PATH-provided
# brew wins, matching how DOCKER/ORB above resolve.
_brew_candidates = [
    shutil.which("brew") or "",
    "/opt/homebrew/bin/brew",
    "/usr/local/bin/brew",
]
BREW = next((p for p in _brew_candidates if _bin_exists(p, as_file=True)), "/opt/homebrew/bin/brew")
# Known prefixes first: nginx -t / -s reload must not pick a PATH hijack.
# which() is last so Intel Homebrew (/usr/local) and a custom prefix still work.
_nginx_candidates = [
    "/opt/homebrew/bin/nginx",
    "/usr/local/bin/nginx",
    shutil.which("nginx") or "",
]
NGINX = next(
    (p for p in _nginx_candidates if _bin_exists(p, as_file=True)),
    "/opt/homebrew/bin/nginx",
)
UID = os.getuid()


def _default_agents_dir() -> Path:
    """User LaunchAgents. ``expanduser`` leftover must not 500 import."""
    home = user_home()
    return (
        home / "Library" / "LaunchAgents"
        if home is not None
        else Path("/var/empty/serverhub-launchagents")
    )


#: A Path, not a str: every consumer immediately wrapped it in Path() anyway, and
#: two modules kept their own `Path.home() / "Library" / "LaunchAgents"` because of
#: the type mismatch -- a second definition that could drift from this one.
#: Existing `Path(AGENTS_DIR)` and f-string uses keep working unchanged.
AGENTS_DIR = _default_agents_dir()
STATIC_DIR = BASE / "static"
LEGACY_INDEX = BASE / "index.html"
