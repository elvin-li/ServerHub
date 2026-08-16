"""VM management: UTM (utmctl) + OrbStack Linux machines (orbctl)."""
from __future__ import annotations

import re
import threading
import time
from typing import Any

from hub import vm_console
from hub.config import override
from hub.errors import api_error
from hub.paths import ORBCTL, UTMCTL
from hub.util import cached_snapshot, fan_out, port_open, sh


# Short TTL shared by status feed, bookmarks, and /api/vms (dedupe utmctl/orbctl).
# Must stay LONGER than hub.status._STATUS_TTL (35s): the status feed is polled
# on that cadence, so a shorter TTL here guaranteed a miss on every refresh and
# paid ~390ms for utmctl+orbctl every single time.  Correctness after a VM
# start/stop comes from invalidate_vm_lists(), not from the TTL lapsing.
_LIST_TTL = 45.0



def invalidate_vm_lists():
    """Bust UTM/Orb list caches only (no status re-entry)."""
    _utm_snapshot.invalidate()
    _orb_snapshot.invalidate()


def _invalidate():
    invalidate_vm_lists()
    try:
        from hub.status import invalidate_status
        invalidate_status()
    except Exception:
        pass

# Common OrbStack distros for create UI
ORB_DISTROS = [
    "ubuntu", "debian", "fedora", "arch", "alpine", "centos",
    "rocky", "alma", "opensuse", "kali", "nixos",
]


def _utm_available() -> bool:
    return bool(UTMCTL) and __import__("pathlib").Path(UTMCTL).exists()


def _orb_available() -> bool:
    return bool(ORBCTL) and __import__("pathlib").Path(ORBCTL).exists()


def _probe_port(port) -> bool | None:
    """Port reachability that never raises, so one VM cannot cost the listing.

    ``fan_out`` re-raises on iteration, which would turn a single unreachable
    host into an empty VM list rather than one row reading "warn".
    """
    try:
        return port_open(port)
    except Exception:
        return False


def _list_utm_vms_uncached() -> list[dict]:
    if not _utm_available():
        return []
    rc, out, err = sh([UTMCTL, "list"], timeout=10)
    if rc != 0:
        return []
    # Parsed first, probed second, assembled third.  The per-VM work in the old
    # single loop was a TCP connect against the VM's configured port, which costs
    # the full 0.6s timeout whenever the guest is not listening yet -- so a host
    # with several port-mapped VMs paid that serially on every refresh.  Parsing
    # and override lookups stay on this thread; only the socket waits fan out.
    rows = []
    for line in out.splitlines()[1:]:
        # UUID Status Name (name may have spaces)
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        uuid, status, name = parts[0], parts[1], parts[2]
        ov = override(name) or override(uuid) or {}
        if ov.get("hide"):
            continue
        rows.append({"uuid": uuid, "status": status, "name": name, "ov": ov})

    # None where no port is configured, matching the previous conditional.
    probes = fan_out(
        lambda port: _probe_port(port) if port else None,
        [row["ov"].get("port") for row in rows],
    )

    items = []
    for row, p in zip(rows, probes):
        uuid, status, name, ov = row["uuid"], row["status"], row["name"], row["ov"]
        started = status in ("started", "running")
        suspended = status in ("paused", "suspended")
        stopped = status in ("stopped", "stop", "shutdown")
        # ok=运行 / warn=挂起或端口异常 / stopped=主动停止(灰) / down=意外异常(红)
        if started and p is False:
            state = "warn"
        elif started:
            state = "ok"
        elif suspended:
            state = "warn"
        elif stopped:
            state = "stopped"
        else:
            state = "down"
        actions = []
        if started:
            actions = ["stop", "restart", "suspend", "ip", "rename"]
        elif suspended:
            actions = ["start", "stop", "delete", "rename"]
        else:
            actions = ["start", "clone", "delete", "rename"]
        items.append({
            "id": name,
            "uuid": uuid,
            # Console authorisation is keyed by UUID, never by the display name:
            # renaming a VM must not move an allowlist entry to another machine.
            "console_id": vm_console.console_id_for_utm(uuid),
            "console": vm_console.capability(backend="utm", vm_uuid=uuid, running=started),
            "name": ov.get("name") or name,
            "backend": "utm",
            "status": status,
            "state": state,
            "detail": f"UTM · {status}",
            "url": ov.get("url"),
            "group": ov.get("group") or "UTM",
            "actions": actions,
            "ips": [],
        })
    return items


@cached_snapshot(_LIST_TTL)
def _utm_snapshot() -> list[dict]:
    return _list_utm_vms_uncached()


def list_utm_vms(force: bool = False) -> list[dict]:
    """UTM inventory, cached for _LIST_TTL with one in-flight refresh.

    The copy is deliberate and predates the shared helper: callers concatenate and
    sort these lists, and handing out the cached object would let one of them mutate
    what every later reader sees.

    The lock used to be released before `_list_utm_vms_uncached()` ran, so
    overlapping callers all missed and each spawned its own `utmctl list` plus a port
    probe per VM.
    """
    return list(_utm_snapshot(force))


def _list_orb_machines_uncached() -> list[dict]:
    if not _orb_available():
        return []
    # orbctl list -f json if available, else text
    rc, out, err = sh([ORBCTL, "list", "-f", "json"], timeout=15)
    items: list[dict] = []
    if rc == 0 and out.strip().startswith(("[", "{")):
        import json
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = data.get("machines") or data.get("items") or []
            for m in data or []:
                name = m.get("name") or m.get("Name") or m.get("id") or ""
                if not name:
                    continue
                status = (m.get("state") or m.get("status") or m.get("Status") or "").lower()
                item = _orb_item(name, status, m)
                if item:
                    items.append(item)
            if items:
                return items
        except Exception:
            pass
    rc, out, err = sh([ORBCTL, "list"], timeout=15)
    if rc != 0:
        return []
    # parse table: NAME  STATE  ...
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if not lines:
        return []
    # skip header if present
    start = 1 if re.search(r"name|state|status", lines[0], re.I) else 0
    for line in lines[start:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        name, status = parts[0], parts[1].lower()
        if name.lower() in ("name", "id"):
            continue
        item = _orb_item(name, status, {})
        if item:
            items.append(item)
    return items


@cached_snapshot(_LIST_TTL)
def _orb_snapshot() -> list[dict]:
    return _list_orb_machines_uncached()


def list_orb_machines(force: bool = False) -> list[dict]:
    """OrbStack inventory. Copied and single-flight for the same reasons as above."""
    return list(_orb_snapshot(force))


def _orb_item(name: str, status: str, raw: dict) -> dict | None:
    ov = override(f"orb-{name}") or override(name) or {}
    if ov.get("hide"):
        return None
    running = status in ("running", "started", "up")
    stopped = status in ("stopped", "stop", "exited", "created", "shutdown")
    if running:
        state = "ok"
    elif stopped or not status:
        state = "stopped"
    else:
        state = "down"
    if running:
        actions = ["stop", "restart", "shell", "delete", "rename"]
    else:
        actions = ["start", "delete", "clone", "rename"]
    return {
        "id": f"orb:{name}",
        "uuid": raw.get("id") or name,
        "name": ov.get("name") or name,
        "orb_name": name,
        "backend": "orb",
        "status": status or "unknown",
        "state": state,
        "detail": f"OrbStack · {status or 'unknown'}",
        "url": ov.get("url"),
        "group": ov.get("group") or "OrbStack Linux",
        "actions": actions,
        "distro": raw.get("distro") or raw.get("image") or "",
        "ips": [],
        # OrbStack Linux machines are headless by design.  Reporting the reason
        # (rather than omitting the key) lets the UI explain why there is no
        # console button instead of rendering one that could never connect.
        "console_id": None,
        "console": vm_console.capability(backend="orb", vm_uuid=str(raw.get("id") or name), running=running),
    }


def list_all_vms() -> dict:
    """Both hypervisors' inventories.

    UTM and OrbStack are separate binaries that know nothing about each other, so
    one listing does not inform the other. `fan_out` keeps them in order, which is
    what puts UTM's rows ahead of OrbStack's in the combined list.
    """
    utm, orb = fan_out(
        lambda probe: probe(), [list_utm_vms, list_orb_machines], max_workers=2
    )
    return {
        "vms": utm + orb,
        "utm_count": len(utm),
        "orb_count": len(orb),
        "utm_available": _utm_available(),
        "orb_available": _orb_available(),
        "utmctl": UTMCTL,
        "orbctl": ORBCTL,
        "orb_distros": ORB_DISTROS,
    }


def discover_vms() -> list:
    """Status feed format for services dashboard."""
    items = []
    for v in list_utm_vms() + list_orb_machines():
        actions = []
        if v["state"] == "ok":
            actions = ["restart", "stop"]
        else:
            actions = ["start"]
        items.append({
            "id": v["id"],
            "kind": "vm",
            "name": v["name"],
            "state": v["state"],  # ok | warn | stopped | down
            "detail": v["detail"],
            "url": v.get("url"),
            "group": v.get("group") or "Virtual Machines",
            "actions": actions,
            "backend": v.get("backend"),
        })
    return items


def rename_vm_display(vm_id: str, new_name: str) -> dict:
    """Rename display name via services.yaml overrides (utmctl has no rename)."""
    from hub.config import set_override

    new_name = (new_name or "").strip()
    if not new_name:
        raise api_error("vms.name_required")
    backend, name = _parse_id(vm_id)
    # key used by list_* for overrides
    if backend == "orb":
        key = name  # override(name) or override(orb-name)
        # prefer existing key
        from hub.config import override as _ov
        if _ov(f"orb-{name}"):
            key = f"orb-{name}"
        elif _ov(name):
            key = name
        else:
            key = name
    else:
        key = name
    set_override(key, {"name": new_name})
    _invalidate()
    return {"ok": True, "action": "rename", "id": vm_id, "name": new_name, "message": f"Display name changed to {new_name}"}


def _parse_id(vm_id: str) -> tuple[str, str]:
    """Return (backend, name)."""
    if vm_id.startswith("orb:"):
        return "orb", vm_id[4:]
    # uuid style → utm
    if re.match(r"^[0-9A-Fa-f-]{36}$", vm_id):
        return "utm", vm_id
    # check orb first by listing
    for m in list_orb_machines():
        if m.get("orb_name") == vm_id or m["id"] == vm_id:
            return "orb", m.get("orb_name") or vm_id
    return "utm", vm_id


def vm_action(vm_id: str, action: str, **kwargs) -> dict[str, Any]:
    backend, name = _parse_id(vm_id)
    action = (action or "").strip().lower()

    if backend == "utm":
        return _utm_action(name, action, **kwargs)
    if backend == "orb":
        return _orb_action(name, action, **kwargs)
    raise api_error("vms.unknown_backend", vm=vm_id)


def _utm_action(name: str, action: str, **kwargs) -> dict:
    if not _utm_available():
        raise api_error("vms.utm_unavailable")
    if action == "start":
        rc, out, err = sh([UTMCTL, "start", name], timeout=90)
    elif action == "stop":
        force = kwargs.get("force", True)
        args = [UTMCTL, "stop", name]
        if force:
            args.append("--force")
        else:
            args.append("--request")
        rc, out, err = sh(args, timeout=180)
    elif action == "kill":
        rc, out, err = sh([UTMCTL, "stop", name, "--kill"], timeout=60)
    elif action == "suspend":
        rc, out, err = sh([UTMCTL, "suspend", name], timeout=120)
    elif action == "restart":
        return _utm_restart_async(name)
    elif action == "delete":
        # must be stopped
        st = _utm_status(name)
        if st in ("started", "running"):
            sh([UTMCTL, "stop", name, "--force"], timeout=120)
            time.sleep(2)
        rc, out, err = sh([UTMCTL, "delete", name], timeout=60)
    elif action == "clone":
        new_name = (kwargs.get("name") or "").strip()
        args = [UTMCTL, "clone", name]
        if new_name:
            args += ["--name", new_name]
        rc, out, err = sh(args, timeout=300)
    elif action == "ip":
        rc, out, err = sh([UTMCTL, "ip-address", name], timeout=15)
        ips = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        _invalidate()
        return {"ok": rc == 0, "action": action, "id": name, "ips": ips, "message": out or err}
    elif action == "rename":
        return rename_vm_display(name, kwargs.get("name") or "")
    elif action == "status":
        st = _utm_status(name)
        return {"ok": True, "action": action, "id": name, "status": st}
    else:
        raise api_error("vms.utm_unsupported_action", action=action)
    _invalidate()
    return {"ok": rc == 0, "action": action, "id": name, "message": out if rc == 0 else (err or out)}


def _utm_status(name: str) -> str:
    rc, out, _ = sh([UTMCTL, "status", name], timeout=10)
    return (out or "").strip() if rc == 0 else "unknown"


def utm_vm_running(vm_uuid: str) -> bool:
    """True when the UTM VM with *vm_uuid* is currently started.

    Looked up by UUID and re-queried live rather than trusting a cached list or
    a display name: console authorisation must not follow a renamed VM, and a
    machine that stopped since the page loaded must not accept a bridge.
    """
    uuid = str(vm_uuid or "").strip().lower()
    if not uuid or not _utm_available():
        return False
    for vm in list_utm_vms(force=True):
        if str(vm.get("uuid") or "").strip().lower() != uuid:
            continue
        return _utm_status(str(vm.get("id") or "")) in ("started", "running")
    return False


def _utm_restart_async(name: str) -> dict:
    def job():
        # sh(), not bare subprocess.run: a TimeoutExpired from stop/start
        # escaped this worker thread, abandoning the restart halfway with
        # the VM left stopped.  sh() bounds every call and reports failure
        # as a return code instead of raising.
        sh([UTMCTL, "stop", name, "--force"], timeout=180)
        for _ in range(40):
            _, out, _ = sh([UTMCTL, "status", name], timeout=10)
            if out == "stopped":
                break
            time.sleep(2)
        sh([UTMCTL, "start", name], timeout=90)
        _invalidate()

    threading.Thread(target=job, daemon=True).start()
    return {"ok": True, "action": "restart", "id": name, "message": "Restart started (takes about 1–2 minutes)"}


def _orb_action(name: str, action: str, **kwargs) -> dict:
    if not _orb_available():
        raise api_error("vms.orb_unavailable")
    if action == "start":
        rc, out, err = sh([ORBCTL, "start", name], timeout=120)
    elif action == "stop":
        rc, out, err = sh([ORBCTL, "stop", name], timeout=120)
    elif action == "restart":
        rc, out, err = sh([ORBCTL, "restart", name], timeout=180)
    elif action == "delete":
        # orbctl delete NAME -y if exists
        rc, out, err = sh([ORBCTL, "delete", name, "-f"], timeout=180)
        if rc != 0:
            rc, out, err = sh([ORBCTL, "delete", name], timeout=180)
    elif action == "clone":
        new_name = (kwargs.get("name") or f"{name}-clone").strip()
        rc, out, err = sh([ORBCTL, "clone", name, new_name], timeout=600)
    elif action == "shell":
        # return SSH hint
        rc, out, err = sh([ORBCTL, "ssh", name], timeout=10)
        return {
            "ok": True,
            "action": "shell",
            "id": name,
            "message": out or f"Run in a terminal: orb -m {name}",
            "command": f"orb -m {name}",
        }
    elif action == "info":
        rc, out, err = sh([ORBCTL, "info", name], timeout=15)
        return {"ok": rc == 0, "action": "info", "id": name, "message": out or err}
    elif action == "rename":
        return rename_vm_display(f"orb:{name}", kwargs.get("name") or "")
    else:
        raise api_error("vms.orb_unsupported_action", action=action)
    _invalidate()
    return {"ok": rc == 0, "action": action, "id": name, "message": out if rc == 0 else (err or out)}


def create_orb_machine(distro: str, name: str | None = None, arch: str | None = None) -> dict:
    """orbctl create DISTRO[:VERSION] [NAME]"""
    if not _orb_available():
        raise api_error("vms.orb_unavailable")
    distro = (distro or "").strip()
    if not distro:
        raise api_error("vms.distro_required")
    # sanitize
    if not re.match(r"^[a-zA-Z0-9._:-]+$", distro):
        raise api_error("vms.bad_distro")
    args = [ORBCTL, "create", distro]
    if name:
        name = name.strip()
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$", name):
            raise api_error("vms.bad_machine_name")
        args.append(name)
    if arch in ("arm64", "amd64"):
        args += ["--arch", arch]
    rc, out, err = sh(args, timeout=600)
    _invalidate()
    return {
        "ok": rc == 0,
        "action": "create",
        "distro": distro,
        "name": name,
        "message": out if rc == 0 else (err or out),
    }
