"""Paths and binary locations (OrbStack / UTM / smartctl)."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from hub import secure_io

RUNTIME_ROOT = Path(
    os.environ.get("SERVERHUB_RUNTIME_DIR") or Path(__file__).resolve().parent.parent
).expanduser().resolve()
# BASE remains the compatibility name for the immutable application/runtime
# tree. Packaged builds keep mutable state outside the signed app bundle.
BASE = RUNTIME_ROOT
_STATE_OVERRIDE = os.environ.get("SERVERHUB_STATE_DIR", "").strip()
STATE_ROOT = (
    Path(_STATE_OVERRIDE).expanduser().resolve()
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
ORB = next((p for p in _orb_candidates if p and Path(p).is_file()), "/usr/local/bin/orb")
# Current OrbStack exposes management subcommands through ``orb`` even when a
# separate orbctl binary is absent.  Keep the old name for callers/API shape.
ORBCTL = shutil.which("orbctl") or ORB
_utm_candidates = [
    shutil.which("utmctl") or "",
    "/Applications/UTM.app/Contents/MacOS/utmctl",
    str(Path.home() / "Applications/UTM.app/Contents/MacOS/utmctl"),
]
UTMCTL = next((p for p in _utm_candidates if p and Path(p).exists()), "/Applications/UTM.app/Contents/MacOS/utmctl")
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
BREW = next((p for p in _brew_candidates if p and Path(p).is_file()), "/opt/homebrew/bin/brew")
UID = os.getuid()
#: A Path, not a str: every consumer immediately wrapped it in Path() anyway, and
#: two modules kept their own `Path.home() / "Library" / "LaunchAgents"` because of
#: the type mismatch -- a second definition that could drift from this one.
#: Existing `Path(AGENTS_DIR)` and f-string uses keep working unchanged.
AGENTS_DIR = Path(os.path.expanduser("~/Library/LaunchAgents"))
STATIC_DIR = BASE / "static"
LEGACY_INDEX = BASE / "index.html"
