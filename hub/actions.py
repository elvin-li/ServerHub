"""Start / stop / restart targets."""
from __future__ import annotations

import glob
import plistlib
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path

from fastapi import HTTPException

from hub import cli_args
from hub.config import cfg
from hub.errors import api_error
from hub.launchd_cache import invalidate_launchd
from hub.paths import AGENTS_DIR, BREW, DOCKER, ORB, UID, UTMCTL
from hub.util import read_bytes_capped, sh, utf8_env

_PROCESS_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
#: Leftover multi-MB LaunchAgent plist used to OOM start/stop and GET registry.
_PLIST_CAP = 256 * 1024


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 action JSON."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _path_is_file(path) -> bool:
    try:
        return Path(path).is_file()
    except OSError:
        return False


def _app_process_name(name: str) -> str:
    """Refuse osascript interpolation of an option-shaped or quoted process name."""
    value = str(name or "").strip()
    if not _PROCESS_NAME_RE.fullmatch(value):
        raise api_error("actions.bad_process_name")
    return value


def _script_argv(command) -> list[str]:
    if isinstance(command, (list, tuple)):
        # ``str()`` not ``_as_text``: leftover ``!!binary`` ``b'--all'`` must
        # stay ``"b'--all'"``, not decode into a real ``--all`` option.
        argv = [str(part) for part in command]
    else:
        try:
            argv = shlex.split(str(command))
        except ValueError:
            # Unmatched quotes (and other shlex parse errors) used to 500
            # start/stop of a script target instead of a 400.
            raise api_error("actions.empty_script")
    if not argv:
        raise api_error("actions.empty_script")
    # Leftover ``\ud800`` used to UnicodeEncodeError ``Popen`` on start.
    checked = cli_args.as_argv([_as_text(part) for part in argv])
    if checked is None:
        raise api_error("actions.empty_script")
    return checked


def _launchctl(args: list[str]):
    """Run a state-changing `launchctl` subcommand and drop the shared listing.

    Invalidated *after* the command rather than before it: clearing first leaves a
    window in which a concurrent reader refills the cache from the pre-change
    session, and that entry would then be served for the rest of its TTL.
    """
    try:
        return sh(["/bin/launchctl", *args])
    finally:
        invalidate_launchd()


#: `launchctl bootstrap` of a job that is already in the session is not a
#: failure of Start.  Older macOS reports that as 17 (EEXIST); current macOS
#: reports it as 5 (EIO) with the wording "Bootstrap failed: 5: Input/output
#: error".  Either way the job is loaded — kickstart is the start we wanted.
_BOOTSTRAP_ALREADY = {0, 5, 17}


def _bootstrap_ok_to_kickstart(rc: int, out: str = "", err: str = "") -> bool:
    """True when bootstrap succeeded, or the job was already in the session."""
    if rc in _BOOTSTRAP_ALREADY:
        return True
    return "already" in f"{err} {out}".lower()


def _job_pid_and_status(label: str) -> tuple[str, str] | None:
    """``(pid, last_exit)`` from the shared listing, or None if not loaded."""
    try:
        from hub.launchd_cache import listing
        entry = listing(force=True).jobs.get(label)
    except Exception:
        return None
    if entry is None:
        return None
    return entry[0], entry[1]


def _confirm_launchd_alive(label: str, rc: int, out: str, err: str,
                           *, attempts: int = 6, delay: float = 0.25):
    """After kickstart, treat a KeepAlive crash loop as a failed start.

    ``launchctl kickstart`` returns 0 even when the process exits immediately.
    The Services page then toasted success while the job sat at
    ``state = spawn scheduled`` / last exit 255 — the same UX as Cloudflare
    with an invalid token.
    """
    if rc != 0:
        return rc, out, err
    last = None
    for i in range(max(1, attempts)):
        last = _job_pid_and_status(label)
        if last is None:
            time.sleep(delay)
            continue
        pid, status = last
        if str(pid).isdigit():
            return 0, out, err
        if status not in ("", "-", "0") and i >= 1:
            raise api_error(
                "actions.crash_loop",
                label=_as_text(label),
                exit=_as_text(status),
            )
        time.sleep(delay)
    if last is None:
        return 1, "", "Start command issued but the job is not loaded; check the log"
    pid, status = last
    if str(pid).isdigit():
        return 0, out, err
    if status not in ("", "-", "0"):
        raise api_error(
            "actions.crash_loop",
            label=_as_text(label),
            exit=_as_text(status),
        )
    return 0, out, err


def _plist_dict(path) -> dict | None:
    try:
        data = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _plist_disabled(path: str) -> bool:
    pl = _plist_dict(path)
    return bool(pl and pl.get("Disabled"))


def _set_plist_disabled(path: str, disabled: bool) -> None:
    """Persist the Disabled key so the services page matches launchctl."""
    pl = _plist_dict(path)
    if pl is None:
        return
    if bool(pl.get("Disabled")) == bool(disabled):
        return
    pl["Disabled"] = bool(disabled)
    from hub import secure_io
    secure_io.replace_bytes(path, plistlib.dumps(pl))


def registry():
    reg = {}
    for a in cfg().get("apps") or []:
        if not isinstance(a, dict):
            continue
        sid = a.get("id")
        if not isinstance(sid, str) or not sid:
            continue
        sid = _as_text(sid).strip()
        if not sid:
            continue
        if a.get("container_engine") or a.get("docker_engine"):
            reg[sid] = ("app-engine", a)
        else:
            reg[sid] = ("app", a)
    for s in cfg().get("scripts") or []:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        if not isinstance(sid, str) or not sid:
            continue
        sid = _as_text(sid).strip()
        if not sid:
            continue
        reg[sid] = ("script", s)
    try:
        plist_paths = glob.glob(f"{AGENTS_DIR}/*.plist")
    except OSError:
        plist_paths = []
    for path in plist_paths:
        stem = Path(path).stem
        label = stem
        pl = _plist_dict(path)
        if pl and pl.get("Label"):
            label = _as_text(pl["Label"]).strip() or stem
        meta = ("launchd", {"label": label, "path": path})
        reg.setdefault(label, meta)
        if stem != label:
            reg.setdefault(stem, meta)
    rc, out, _ = sh([DOCKER, "ps", "-a", "--format", "{{.Names}}"], timeout=8)
    if rc == 0:
        for n in _as_text(out).splitlines():
            if n:
                reg.setdefault(n, ("container", {}))
    rc, out, _ = sh([UTMCTL, "list"], timeout=6)
    if rc == 0:
        for line in _as_text(out).splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) == 3:
                reg.setdefault(parts[2], ("vm", {"backend": "utm"}))
                reg.setdefault(parts[0], ("vm", {"backend": "utm", "name": parts[2]}))
    # OrbStack Linux machines
    try:
        from hub import vms_svc
        for m in vms_svc.list_orb_machines():
            if not isinstance(m, dict):
                continue
            oid = _as_text(m.get("id")).strip()
            oname = _as_text(m.get("orb_name")).strip()
            if oid:
                reg.setdefault(oid, ("vm", {"backend": "orb", "name": oname or oid}))
            if oname:
                reg.setdefault(oname, ("vm", {"backend": "orb", "name": oname}))
    except Exception:
        pass
    return reg


def vm_restart_async(name):
    def job():
        # sh(), not bare subprocess.run: the status probe had no timeout (a
        # wedged utmctl parked this thread forever), and a TimeoutExpired
        # from stop/start escaped the thread — leaving the VM stopped with
        # the restart silently abandoned halfway.  sh() bounds every call
        # and reports failure as a return code instead of raising.
        sh([UTMCTL, "stop", name, "--force"], timeout=120)
        for _ in range(40):
            _, out, _ = sh([UTMCTL, "status", name], timeout=10)
            if out == "stopped":
                break
            time.sleep(3)
        sh([UTMCTL, "start", name], timeout=60)
    threading.Thread(target=job, daemon=True).start()
    return 0, "Restart started (takes about 1-2 minutes)", ""


def run_action(target, action):
    # YAML leftover ``.inf`` / ``\\ud800`` used to AttributeError
    # ``startswith`` or UnicodeEncodeError the action JSON.
    target = _as_text(target)
    action = _as_text(action)
    reg = registry()
    if target not in reg:
        # allow orb:name / direct vm action via vms_svc
        if target.startswith("orb:") or action in ("start", "stop", "restart", "suspend", "delete"):
            raw = target[4:] if target.startswith("orb:") else target
            try:
                cli_args.require_positional(raw, label="vm")
            except HTTPException:
                raise api_error("actions.unknown_target", target=target)
            try:
                from hub import vms_svc
                r = vms_svc.vm_action(target, action)
                return (0 if r.get("ok") else 1, _as_text(r.get("message") or ""), "")
            except HTTPException:
                raise
            except Exception:
                raise api_error("actions.unknown_target", target=target)
        raise api_error("actions.unknown_target", target=target)
    kind, meta = reg[target]
    if kind == "launchd":
        label, dom = meta["label"], f"gui/{UID}"
        # Each branch changes what `launchctl list` reports, and the panel refetches
        # the services page straight after an action.  `_launchctl` drops the shared
        # listing (hub/launchd_cache.py) once the command has actually run, so that
        # refetch cannot be served a snapshot taken before it.
        if action == "restart":
            rc, o, e = _launchctl(["kickstart", "-k", f"{dom}/{label}"])
            return _confirm_launchd_alive(label, rc, o, e)
        if action == "run":
            return _launchctl(["kickstart", f"{dom}/{label}"])
        if action == "stop":
            return _launchctl(["bootout", f"{dom}/{label}"])
        if action == "start":
            if _plist_disabled(meta["path"]):
                _launchctl(["enable", f"{dom}/{label}"])
                try:
                    _set_plist_disabled(meta["path"], False)
                except Exception:
                    pass
            rc, o, e = _launchctl(["bootstrap", dom, meta["path"]])
            if not _bootstrap_ok_to_kickstart(rc, o, e):
                return rc, o, e
            rc, o, e = _launchctl(["kickstart", f"{dom}/{label}"])
            return _confirm_launchd_alive(label, rc, o, e)
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
        if _path_is_file(brew):
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
            return (0 if r.get("ok") else 1, _as_text(r.get("message") or ""), "")
        except HTTPException:
            raise
        except Exception:
            name = cli_args.require_positional(target, label="vm")
            if action == "start":
                return sh([UTMCTL, "start", name], timeout=60)
            if action == "stop":
                return sh([UTMCTL, "stop", name, "--force"], timeout=120)
            if action == "restart":
                return vm_restart_async(name)
    if kind == "app":
        process = _app_process_name(meta.get("process") or "")
        if action in ("stop", "restart"):
            sh(["/usr/bin/osascript", "-e", f'quit app "{process}"'], timeout=15)
            time.sleep(2)
        if action in ("start", "restart"):
            return sh(["/usr/bin/open", "-ga", process])
        return 0, "stopped", ""
    if kind == "app-engine":
        if action == "start":
            rc, o, e = sh([ORB, "start"], timeout=60)
            if rc == 0:
                return rc, o or "OrbStack started", e
            return sh(["/usr/bin/open", "-ga", "OrbStack"])
        if action == "stop":
            rc, o, e = sh([ORB, "stop"], timeout=60)
            if rc == 0:
                return rc, o or "OrbStack stopped", e
            return sh(["/usr/bin/osascript", "-e", 'quit app "OrbStack"'], timeout=20)
    if kind == "script":
        if action in ("stop", "restart") and meta.get("stop"):
            sh(_script_argv(meta["stop"]), timeout=30)
            time.sleep(1)
        if action in ("start", "restart") and meta.get("start"):
            argv = _script_argv(meta["start"])
            try:
                subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                    env=utf8_env(),
                )
            except (OSError, ValueError, TypeError) as exc:
                # Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError.
                return 1, "", _as_text(exc)
            return 0, "started", ""
        return 0, "stopped", ""
    raise api_error("actions.bad_action", action=action, kind=kind)
