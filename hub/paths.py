"""Paths and binary locations (OrbStack / UTM / smartctl)."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

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
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if _STATE_OVERRIDE:
        STATE_ROOT.chmod(0o700)
        DATA_DIR.chmod(0o700)


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
SMARTCTL = shutil.which("smartctl") or "/opt/homebrew/bin/smartctl"
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
AGENTS_DIR = os.path.expanduser("~/Library/LaunchAgents")
STATIC_DIR = BASE / "static"
LEGACY_INDEX = BASE / "index.html"
