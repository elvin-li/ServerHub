"""Boot / login autostart management for Docker, Homebrew services, LaunchAgents.

- Docker: HostConfig.RestartPolicy (unless-stopped / always / no / on-failure)
- Brew: brew services start/stop (loads/unloads LaunchAgent with RunAtLoad)
- LaunchAgents: RunAtLoad / KeepAlive / Disabled in plist + launchctl load/unload
"""
from __future__ import annotations

import os
import plistlib
import re
import time
from pathlib import Path

from fastapi import HTTPException

from hub import cli_args
from hub.docker_cli import engine_up
from hub.util import cached_snapshot, fan_out, sh
from hub.brew_cache import brew_services_list, invalidate_brew_services

from hub.paths import AGENTS_DIR  # noqa: E402
# Imported rather than redefined: hub.paths tries `which brew` before the two
# standard prefixes, so a Homebrew installed anywhere else is still found. The
# local copy this replaces only knew /opt/homebrew and /usr/local, which meant
# autostart quietly reported "brew missing" on a host where other pages using
# hub.paths.BREW worked fine.
from hub.paths import BREW  # noqa: E402

_TTL = 12.0


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


def _uid_domain() -> str:
    return f"gui/{os.getuid()}"


def _read_plist(path: Path) -> dict:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f) or {}
    except Exception:
        return {}


def _write_plist(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        plistlib.dump(data, f)


def _loaded_labels() -> str:
    """One `launchctl list` covering every loaded job in this session.

    This used to be called once *per label* from inside the plist loop, which is
    what made /api/apps/autostart cost 63 subprocesses on a 29-agent host:
    `launchctl list` already reports every job, so asking it again for each agent
    was N-1 invocations of one command answering one question.
    """
    rc, out, _ = sh(["/bin/launchctl", "list"], timeout=8)
    return out or "" if rc == 0 else ""


def _launchctl_loaded(label: str, loaded_snapshot: str | None = None) -> bool:
    """Whether *label* is loaded, cheapest signal first.

    Both probes mean the same thing and the answer is their OR, so the order is
    free to change: consult the shared `launchctl list` snapshot when the caller has
    one, and pay for a per-label `launchctl print` only when the snapshot does not
    already say yes. For a loaded agent that is zero extra subprocesses.
    """
    if loaded_snapshot is not None and label in loaded_snapshot:
        return True
    rc, out, _ = sh(["/bin/launchctl", "print", f"{_uid_domain()}/{label}"], timeout=5)
    if rc == 0 and out:
        return True
    if loaded_snapshot is not None:
        # Already checked above; re-running `list` would ask the same question twice.
        return False
    rc2, out2, _ = sh(["/bin/launchctl", "list"], timeout=8)
    return rc2 == 0 and label in (out2 or "")


# ─── Docker ──────────────────────────────────────────────────────────────────

def _docker_autostart_items() -> list[dict]:
    if not engine_up():
        return []
    from hub import containers_svc
    info = containers_svc.list_containers(with_stats=False)
    items = []
    for c in info.get("containers") or []:
        name = c.get("id") or c.get("name")
        if not name:
            continue
        policy = c.get("restart_policy") or "no"
        auto = bool(c.get("autostart")) or policy in ("always", "unless-stopped", "on-failure")
        items.append({
            "id": f"docker-ctr:{name}",
            "kind": "docker",
            "name": c.get("name") or name,
            "label": name,
            "autostart": auto,
            "policy": policy,
            "running": c.get("raw_state") == "running" or c.get("state") == "ok",
            "state": c.get("state"),
            "detail": f"restart={policy}",
            "project": c.get("project"),
            "actions": ["enable", "disable", "set_policy"],
            "group": "Docker 容器",
        })
    return items


def set_docker_autostart(name: str, enabled: bool, policy: str | None = None) -> dict:
    from hub import containers_svc
    if enabled:
        pol = policy if policy in ("always", "unless-stopped", "on-failure") else "unless-stopped"
    else:
        pol = "no"
    return containers_svc.set_restart_policy(name, pol)


# ─── Brew services ───────────────────────────────────────────────────────────

def _brew_service_items() -> list[dict]:
    if not Path(BREW).is_file():
        return []
    items = []
    # Shared TTL cache: this list was being fetched once per caller, and
    # `brew services list --json` costs ~1.3s each time.
    data = brew_services_list()
    for s in data:
        name = s.get("name") or ""
        if not name or name == "nginx":  # managed separately via custom conf often
            # still show nginx but mark custom
            pass
        status = (s.get("status") or "").lower()
        file_path = s.get("file") or ""
        pl = {}
        if file_path and Path(file_path).exists():
            pl = _read_plist(Path(file_path))
        # brew services "started" means loaded; RunAtLoad typically true when managed by brew
        run_at = pl.get("RunAtLoad", True) if pl else (status in ("started", "running", "error"))
        # autostart ≈ will start at login: brew has registered the agent (file exists + RunAtLoad)
        auto = bool(file_path) and bool(run_at) and status != "none"
        # status none = not started as service; may still have plist from previous start
        if status == "none" and not file_path:
            auto = False
        items.append({
            "id": f"brew:{name}",
            "kind": "brew",
            "name": name,
            "label": pl.get("Label") or f"homebrew.mxcl.{name}",
            "autostart": auto,
            "running": status in ("started", "running"),
            "status": status or "unknown",
            "plist": file_path or None,
            "run_at_load": bool(run_at) if pl else None,
            "keep_alive": bool(pl.get("KeepAlive")) if pl else None,
            "detail": f"brew services · {status or '—'}",
            "actions": ["enable", "disable"],
            "group": "Homebrew 服务",
        })
    return items


def set_brew_autostart(name: str, enabled: bool) -> dict:
    # Same hyphen-permissive class as brew_svc had: `{"id": "brew:--all"}`
    # reached `brew services stop --all`.
    name = cli_args.require_positional(name, label="brew service name")
    if not Path(BREW).is_file():
        raise HTTPException(503, "brew not found")
    import subprocess
    action = "start" if enabled else "stop"
    try:
        p = subprocess.run(
            [BREW, "services", action, name],
            capture_output=True, text=True, timeout=120, env=_brew_env(),
        )
        msg = ((p.stdout or "") + (p.stderr or "")).strip()
        # `brew services start/stop` is exactly what the shared snapshot
        # reports on, so the cached copy is stale the moment this returns.
        invalidate_brew_services()
        # stop unloads agent → no login start; start loads with RunAtLoad
        return {
            "ok": p.returncode == 0,
            "message": msg or f"brew services {action} {name}",
            "autostart": enabled if p.returncode == 0 else None,
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ─── LaunchAgents (user) ─────────────────────────────────────────────────────

def _launchd_items(loaded_snapshot: str | None = None) -> list[dict]:
    items = []
    if not AGENTS_DIR.is_dir():
        return items

    # Parse and filter the plists first — pure filesystem work — so the subprocess
    # probes below are paid only for agents that survive the filter.
    parsed = []
    for path in sorted(AGENTS_DIR.glob("*.plist")):
        pl = _read_plist(path)
        label = pl.get("Label") or path.stem
        # skip brew-managed (shown under brew) to reduce dupes — still include non-mxcl
        if label.startswith("homebrew.mxcl."):
            continue  # covered by brew list
        parsed.append((path, pl, label))
    if not parsed:
        return items

    if loaded_snapshot is None:
        loaded_snapshot = _loaded_labels()

    # Whatever the snapshot cannot answer needs its own `launchctl print`. Those are
    # independent of one another, so probe them together instead of walking the list.
    # `_launchctl_loaded` cannot raise, which is what fan_out requires.
    unknown = [label for _, _, label in parsed if label not in loaded_snapshot]
    probed = dict(zip(
        unknown,
        fan_out(lambda lb: _launchctl_loaded(lb, loaded_snapshot), unknown),
    ))

    for path, pl, label in parsed:
        run_at = bool(pl.get("RunAtLoad"))
        keep = pl.get("KeepAlive")
        disabled = bool(pl.get("Disabled"))
        loaded = True if label in loaded_snapshot else probed.get(label, False)
        auto = run_at and not disabled
        items.append({
            "id": f"launchd:{label}",
            "kind": "launchd",
            "name": label,
            "label": label,
            "autostart": auto,
            "running": loaded,
            "run_at_load": run_at,
            "keep_alive": bool(keep) if not isinstance(keep, dict) else True,
            "disabled": disabled,
            "plist": str(path),
            "detail": f"RunAtLoad={run_at} KeepAlive={bool(keep)} loaded={loaded}",
            "program": " ".join(pl.get("ProgramArguments") or [])[:100],
            "actions": ["enable", "disable"],
            "group": "LaunchAgents",
        })
    return items


def set_launchd_autostart(label: str, enabled: bool) -> dict:
    # The hyphen is inside the class with no anchor on the first character, so
    # "--foo" matches.  It is not exploitable at the sinks below, because the
    # label is always interpolated behind a "gui/<uid>/" prefix and so can never
    # be argv-initial -- but that is an accident of the current call sites, and a
    # launchd label does not start with a hyphen in the first place.
    if not re.match(r"^[\w.@+-]+$", label or "") or label.startswith("-"):
        raise HTTPException(400, "invalid label")
    path = AGENTS_DIR / f"{label}.plist"
    # find by Label field if filename differs
    if not path.exists():
        for p in AGENTS_DIR.glob("*.plist"):
            pl = _read_plist(p)
            if pl.get("Label") == label:
                path = p
                break
    if not path.exists():
        raise HTTPException(404, f"plist not found for {label}")

    pl = _read_plist(path)
    pl["RunAtLoad"] = bool(enabled)
    if enabled:
        pl["Disabled"] = False
    else:
        # keep KeepAlive as-is but RunAtLoad false; unload if loaded
        pass
    _write_plist(path, pl)

    dom = _uid_domain()
    logs = []
    if enabled:
        # bootout then bootstrap to pick up RunAtLoad
        sh(["/bin/launchctl", "bootout", f"{dom}/{label}"], timeout=8)
        rc, out, err = sh(["/bin/launchctl", "bootstrap", dom, str(path)], timeout=10)
        logs.append(out or err or f"bootstrap rc={rc}")
        sh(["/bin/launchctl", "enable", f"{dom}/{label}"], timeout=5)
        sh(["/bin/launchctl", "kickstart", "-k", f"{dom}/{label}"], timeout=10)
    else:
        rc, out, err = sh(["/bin/launchctl", "bootout", f"{dom}/{label}"], timeout=10)
        logs.append(out or err or f"bootout rc={rc}")
        # disable for session
        sh(["/bin/launchctl", "disable", f"{dom}/{label}"], timeout=5)

    return {
        "ok": True,
        "message": f"RunAtLoad={enabled} · " + " · ".join(logs)[:400],
        "autostart": enabled,
        "plist": str(path),
    }


# ─── Global login autostart script ───────────────────────────────────────────

def _script_status(loaded_snapshot: str | None = None) -> dict:
    plist = AGENTS_DIR / "local.serverhub.autostart.plist"
    script = Path.home() / "Services" / "autostart.sh"
    pl = _read_plist(plist) if plist.exists() else {}
    return {
        "id": "script:local.serverhub.autostart",
        "kind": "script",
        "name": "登录自启脚本 (autostart.sh)",
        "label": "local.serverhub.autostart",
        "autostart": bool(pl.get("RunAtLoad")) and plist.exists(),
        "running": (
            _launchctl_loaded("local.serverhub.autostart", loaded_snapshot)
            if plist.exists()
            else False
        ),
        "plist": str(plist) if plist.exists() else None,
        "script": str(script) if script.exists() else None,
        "detail": "登录后启动已配置的本地服务",
        "actions": ["enable", "disable", "run_now"] if plist.exists() else [],
        "group": "登录脚本",
    }


def set_script_autostart(enabled: bool) -> dict:
    return set_launchd_autostart("local.serverhub.autostart", enabled)


def run_autostart_now() -> dict:
    script = Path.home() / "Services" / "autostart.sh"
    if not script.exists():
        raise HTTPException(404, "autostart.sh not found")
    import subprocess
    try:
        p = subprocess.Popen(
            ["/bin/bash", str(script)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=_brew_env(),
        )
        return {"ok": True, "message": f"已后台执行 autostart.sh (pid {p.pid})"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ─── Overview ────────────────────────────────────────────────────────────────

@cached_snapshot(_TTL)
def overview(force: bool = False) -> dict:

    # Four independent inventories — docker inspect, the shared brew snapshot, the
    # LaunchAgents directory and the login script — plus one `launchctl list` that
    # the last two both read. Taking the snapshot first means it is fetched once
    # rather than once per collector, and the collectors then overlap.
    loaded_snapshot = _loaded_labels()
    docker_items, brew_items, launchd_items, script = fan_out(
        lambda fn: fn(),
        [
            _docker_autostart_items,
            _brew_service_items,
            lambda: _launchd_items(loaded_snapshot),
            lambda: _script_status(loaded_snapshot),
        ],
        max_workers=4,
    )

    items = [script] + brew_items + launchd_items + docker_items
    counts = {
        "total": len(items),
        "autostart_on": sum(1 for i in items if i.get("autostart")),
        "autostart_off": sum(1 for i in items if not i.get("autostart")),
        "docker": len(docker_items),
        "brew": len(brew_items),
        "launchd": len(launchd_items),
        "running": sum(1 for i in items if i.get("running")),
    }
    v = {
        "ts": time.strftime("%H:%M:%S"),
        "items": items,
        "counts": counts,
        "groups": ["登录脚本", "Homebrew 服务", "LaunchAgents", "Docker 容器"],
        "hint": "Docker 用 restart 策略；brew/LaunchAgent 用登录加载。关闭 brew 服务会取消登录自启。",
    }
    return v


def set_autostart(item_id: str, enabled: bool, policy: str | None = None) -> dict:
    """Toggle autostart. id: docker-ctr:name | brew:name | launchd:label | script:..."""
    overview.invalidate()
    if ":" not in item_id:
        raise HTTPException(400, "id 格式: kind:name")
    kind, _, name = item_id.partition(":")
    if kind == "docker-ctr" or kind == "docker":
        # allow docker:name alias
        return set_docker_autostart(name, enabled, policy=policy)
    if kind == "brew":
        return set_brew_autostart(name, enabled)
    if kind == "launchd":
        return set_launchd_autostart(name, enabled)
    if kind == "script":
        return set_script_autostart(enabled)
    raise HTTPException(400, f"unknown kind: {kind}")


def set_docker_policy(name: str, policy: str) -> dict:
    overview.invalidate()
    from hub import containers_svc
    return containers_svc.set_restart_policy(name, policy)
