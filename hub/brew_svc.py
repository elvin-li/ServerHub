"""Homebrew services management — macOS-native module."""
from __future__ import annotations

import os

from fastapi import HTTPException

from hub import cli_args
from hub.brew_cache import brew_services_list
from hub.status import invalidate_status
from hub.util import sh

BREW = "/opt/homebrew/bin/brew"
if not os.path.isfile(BREW):
    BREW = "/usr/local/bin/brew"


def _brew_env() -> dict:
    env = dict(os.environ)
    path = env.get("PATH", "")
    for p in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"):
        if p not in path:
            path = p + ":" + path
    env["PATH"] = path
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    return env


# nginx is run only via local.onedrive-nginx (custom conf); hide idle brew formula
_HIDE_BREW = {"nginx"}


def list_services() -> list:
    if not os.path.isfile(BREW):
        return []
    # Shared TTL cache: `brew services list --json` costs ~1.3s and four
    # modules ask for it while rendering one page.
    items = []
    data = brew_services_list()
    if data:
        try:
            for s in data:
                name = s.get("name") or ""
                if name in _HIDE_BREW:
                    continue
                status = (s.get("status") or "").lower()
                # started|stopped|error|none
                state = "ok" if status in ("started", "running") else (
                    "warn" if status in ("error",) else "down"
                )
                items.append({
                    "id": name,
                    "name": name,
                    "status": status or "unknown",
                    "state": state,
                    "user": s.get("user"),
                    "file": s.get("file"),
                    "exit_code": s.get("exit_code"),
                    "actions": ["restart", "stop"] if state == "ok" else ["start"],
                })
            return items
        except Exception:
            pass
    # fallback text parse
    rc, out, err = sh([BREW, "services", "list"], timeout=20)
    if rc != 0:
        return []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        name, status = parts[0], parts[1].lower()
        if name in _HIDE_BREW:
            continue
        state = "ok" if status == "started" else "down"
        items.append({
            "id": name,
            "name": name,
            "status": status,
            "state": state,
            "user": parts[2] if len(parts) > 2 else None,
            "file": None,
            "actions": ["restart", "stop"] if state == "ok" else ["start"],
        })
    return items


def service_action(name: str, action: str) -> dict:
    if action not in ("start", "stop", "restart"):
        raise HTTPException(400, f"bad action {action}")
    # `^[\w@.+-]+$` matched `--all`, so `brew services stop --all` stopped every
    # service on the host instead of one.  The shared guard anchors the first
    # character to an alphanumeric.
    name = cli_args.require_positional(name, label="service name")
    if not os.path.isfile(BREW):
        raise HTTPException(503, "brew not found")
    import subprocess
    try:
        p = subprocess.run(
            [BREW, "services", action, name],
            capture_output=True, text=True, timeout=120,
            env=_brew_env(),
        )
        invalidate_status()
        return {
            "ok": p.returncode == 0,
            "message": (p.stdout or p.stderr or "").strip() or f"exit {p.returncode}",
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}
