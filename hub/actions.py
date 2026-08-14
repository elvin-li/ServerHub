"""Start / stop / restart targets."""
from __future__ import annotations

import glob
import subprocess
import threading
import time
from pathlib import Path

from fastapi import HTTPException

from hub import cli_args
from hub.config import cfg
from hub.launchd_cache import invalidate_launchd
from hub.paths import AGENTS_DIR, BREW, DOCKER, ORB, UID, UTMCTL
from hub.util import sh


def _launchctl(args: list[str]):
    """Run a state-changing `launchctl` subcommand and drop the shared listing.

    Invalidated *after* the command rather than before it: clearing first leaves a
    window in which a concurrent reader refills the cache from the pre-change
    session, and that entry would then be served for the rest of its TTL.
    """
    try:
        return sh(["launchctl", *args])
    finally:
        invalidate_launchd()


def registry():
    reg = {}
    for a in cfg().get("apps") or []:
        if a.get("container_engine") or a.get("docker_engine"):
            reg[a["id"]] = ("app-engine", a)
        else:
            reg[a["id"]] = ("app", a)
    for s in cfg().get("scripts") or []:
        reg[s["id"]] = ("script", s)
    for path in glob.glob(f"{AGENTS_DIR}/*.plist"):
        reg.setdefault(Path(path).stem, ("launchd", {"label": Path(path).stem, "path": path}))
    rc, out, _ = sh([DOCKER, "ps", "-a", "--format", "{{.Names}}"], timeout=8)
    if rc == 0:
        for n in out.splitlines():
            reg.setdefault(n, ("container", {}))
    rc, out, _ = sh([UTMCTL, "list"], timeout=6)
    if rc == 0:
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) == 3:
                reg.setdefault(parts[2], ("vm", {"backend": "utm"}))
                reg.setdefault(parts[0], ("vm", {"backend": "utm", "name": parts[2]}))
    # OrbStack Linux machines
    try:
        from hub import vms_svc
        for m in vms_svc.list_orb_machines():
            reg.setdefault(m["id"], ("vm", {"backend": "orb", "name": m.get("orb_name")}))
            if m.get("orb_name"):
                reg.setdefault(m["orb_name"], ("vm", {"backend": "orb", "name": m["orb_name"]}))
    except Exception:
        pass
    return reg


def vm_restart_async(name):
    def job():
        subprocess.run([UTMCTL, "stop", name, "--force"], timeout=120)
        for _ in range(40):
            r = subprocess.run([UTMCTL, "status", name], capture_output=True, text=True)
            if r.stdout.strip() == "stopped":
                break
            time.sleep(3)
        subprocess.run([UTMCTL, "start", name], timeout=60)
    threading.Thread(target=job, daemon=True).start()
    return 0, "重启已开始（约 1-2 分钟）", ""


def run_action(target, action):
    reg = registry()
    if target not in reg:
        # allow orb:name / direct vm action via vms_svc
        if target.startswith("orb:") or action in ("start", "stop", "restart", "suspend", "delete"):
            try:
                from hub import vms_svc
                r = vms_svc.vm_action(target, action)
                return (0 if r.get("ok") else 1, r.get("message") or "", "")
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(404, f"unknown target: {target} ({e})")
        raise HTTPException(404, f"unknown target: {target}")
    kind, meta = reg[target]
    if kind == "launchd":
        label, dom = meta["label"], f"gui/{UID}"
        # Each branch changes what `launchctl list` reports, and the panel refetches
        # the services page straight after an action.  `_launchctl` drops the shared
        # listing (hub/launchd_cache.py) once the command has actually run, so that
        # refetch cannot be served a snapshot taken before it.
        if action == "restart":
            return _launchctl(["kickstart", "-k", f"{dom}/{label}"])
        if action == "run":
            return _launchctl(["kickstart", f"{dom}/{label}"])
        if action == "stop":
            return _launchctl(["bootout", f"{dom}/{label}"])
        if action == "start":
            rc, o, e = _launchctl(["bootstrap", dom, meta["path"]])
            if rc not in (0, 17) and "already" not in e.lower():
                return rc, o, e
            return _launchctl(["kickstart", f"{dom}/{label}"])
    if kind == "container" and action in ("start", "stop", "restart", "pause", "unpause", "remove", "kill"):
        # Registry keys are container names. An option-shaped name (or a
        # caller-supplied target that somehow landed here) must not become
        # ``docker stop --all``.
        name = cli_args.require_positional(target, label="container name")
        if action == "remove":
            return sh([DOCKER, "rm", "-f", "--", name], timeout=90)
        return sh([DOCKER, action, "--", name], timeout=90)
    # brew formula services (when not registered as local LaunchAgent)
    if action in ("start", "stop", "restart", "run") and str(target).startswith("homebrew.mxcl."):
        pkg = cli_args.require_positional(
            str(target).replace("homebrew.mxcl.", "", 1),
            label="brew service name",
        )
        # hub.paths.BREW rather than a local `which(...) or "/opt/homebrew/..."`:
        # that form has no /usr/local fallback, so on an Intel host with brew off
        # PATH this branch found nothing and the service silently never started.
        brew = BREW
        if Path(brew).exists():
            act = "restart" if action == "run" else action
            return sh([brew, "services", act, pkg], timeout=90)
    if kind == "vm":
        try:
            from hub import vms_svc
            vid = target
            if meta.get("backend") == "orb" and not str(target).startswith("orb:"):
                vid = f"orb:{meta.get('name') or target}"
            elif meta.get("name") and meta.get("backend") == "utm":
                vid = meta.get("name") or target
            r = vms_svc.vm_action(vid, action)
            return (0 if r.get("ok") else 1, r.get("message") or "", "")
        except HTTPException:
            raise
        except Exception:
            if action == "start":
                return sh([UTMCTL, "start", target], timeout=60)
            if action == "stop":
                return sh([UTMCTL, "stop", target, "--force"], timeout=120)
            if action == "restart":
                return vm_restart_async(target)
    if kind == "app":
        if action in ("stop", "restart"):
            sh(["osascript", "-e", f'quit app "{meta["process"]}"'], timeout=15)
            time.sleep(2)
        if action in ("start", "restart"):
            return sh(["open", "-ga", meta["process"]])
        return 0, "stopped", ""
    if kind == "app-engine":
        if action == "start":
            rc, o, e = sh([ORB, "start"], timeout=60)
            if rc == 0:
                return rc, o or "OrbStack 已启动", e
            return sh(["open", "-ga", "OrbStack"])
        if action == "stop":
            rc, o, e = sh([ORB, "stop"], timeout=60)
            if rc == 0:
                return rc, o or "OrbStack 已停止", e
            return sh(["osascript", "-e", 'quit app "OrbStack"'], timeout=20)
    if kind == "script":
        if action in ("stop", "restart") and meta.get("stop"):
            sh(meta["stop"], timeout=30, shell=True)
            time.sleep(1)
        if action in ("start", "restart") and meta.get("start"):
            return sh(f"nohup {meta['start']} >/dev/null 2>&1 &", timeout=20, shell=True)
        return 0, "stopped", ""
    raise HTTPException(400, f"bad action {action} for {kind}")
