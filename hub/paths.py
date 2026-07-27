"""Paths and binary locations (OrbStack / UTM / smartctl)."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
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
