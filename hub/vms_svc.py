"""VM management: UTM (utmctl) + OrbStack Linux machines (orbctl)."""
from __future__ import annotations

import re
import threading
import time
from typing import Any

from hub import cli_args, vm_console
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


def _bin_present(path) -> bool:
    if not path:
        return False
    try:
        return __import__("pathlib").Path(path).exists()
    except (OSError, TypeError, ValueError):
        # Dying FUSE/SMB mounts raise EIO; a NUL leftover raises ValueError.
        return False


def _utm_available() -> bool:
    return _bin_present(UTMCTL)


def _orb_available() -> bool:
    return _bin_present(ORBCTL)


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` so GET /api/vms cannot UTF-8 500."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _display_text(value, fallback: str = "") -> str:
    """JSON-safe display string for a leftover YAML/JSON field.

    ``name: .inf``, ``group: 2026-08-19``, ``!!binary`` and a ``!!set`` each
    used to leak into GET /api/vms and fail Starlette's allow_nan=False encoder.
    """
    if value is None or isinstance(value, bool):
        return fallback
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return fallback
        return str(value)
    if isinstance(value, int):
        try:
            float(value)
        except OverflowError:
            return fallback
        return str(value)
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        return fallback
    try:
        text = str(value)
    except Exception:
        return fallback
    return _as_text(text) if text else fallback


def _optional_text(value) -> str | None:
    text = _display_text(value, "")
    return text or None


def _id_text(value, fallback: str) -> str:
    """Machine id/uuid from leftover orbctl JSON: Infinity/objects are not ids."""
    if isinstance(value, str) and value:
        return _as_text(value)
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            float(value)
        except OverflowError:
            return fallback
        return str(value)
    return fallback


def _jsonable(value, depth: int = 0):
    """Drop leftover inf/bytes/huge ints/``\\ud800`` so Starlette cannot 500 GET /api/vms."""
    if depth > 32:
        return None
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            try:
                key = k if isinstance(k, (str, bytes, bytearray)) else str(k)
            except Exception:
                continue
            key = _as_text(key)
            out[key] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        try:
            float(value)
        except OverflowError:
            return None
        return value
    if isinstance(value, str):
        return _as_text(value)
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/vms.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    return None


def _listing_rows(probe) -> list:
    """One hypervisor's inventory, or [] if that listing is leftover/broken.

    ``fan_out`` re-raises, so a single ``utmctl`` blow-up used to 500 GET /api/vms
    (including the OrbStack rows that had already succeeded).
    """
    try:
        rows = probe()
    except Exception:
        return []
    return list(rows) if isinstance(rows, (list, tuple)) else []


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
    out = _as_text(out)
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
        uuid, status, name = _as_text(parts[0]), _as_text(parts[1]), _as_text(parts[2])
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
            "name": _display_text(ov.get("name"), name) or name,
            "backend": "utm",
            "status": status,
            "state": state,
            "detail": f"UTM · {status}",
            "url": _optional_text(ov.get("url")),
            "group": _display_text(ov.get("group"), "UTM") or "UTM",
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
    out = _as_text(out)
    if rc == 0 and out.strip().startswith(("[", "{")):
        import json
        try:
            data = json.loads(out)
        except (TypeError, ValueError, RecursionError):
            # RecursionError: leftover deeply-nested ``orbctl list -f json``
            # is not ValueError; GET /api/vms used to 500.
            data = None
        try:
            if data is not None:
                if isinstance(data, dict):
                    data = data.get("machines") or data.get("items") or []
                if not isinstance(data, list):
                    data = []
                for m in data:
                    if not isinstance(m, dict):
                        continue
                    # orbctl JSON names must be strings. Coercing ``name: 1``
                    # used to invent a machine called "1" on GET /api/vms.
                    raw_name = m.get("name")
                    if raw_name is None:
                        raw_name = m.get("Name")
                    if raw_name is None:
                        raw_name = m.get("id")
                    if not isinstance(raw_name, str):
                        continue
                    name = _as_text(raw_name).strip()
                    if not name:
                        continue
                    raw_status = m.get("state") or m.get("status") or m.get("Status") or ""
                    if not isinstance(raw_status, str):
                        raw_status = str(raw_status) if raw_status is not None else ""
                    status = _as_text(raw_status).lower()
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
    lines = [ln for ln in _as_text(out).splitlines() if ln.strip()]
    if not lines:
        return []
    # skip header if present
    start = 1 if re.search(r"name|state|status", lines[0], re.I) else 0
    for line in lines[start:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        name, status = _as_text(parts[0]), _as_text(parts[1]).lower()
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
    name, status = _as_text(name), _as_text(status)
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
    uuid = _id_text(raw.get("id"), name)
    distro = raw.get("distro") or raw.get("image") or ""
    return {
        "id": f"orb:{name}",
        "uuid": uuid,
        "name": _display_text(ov.get("name"), name) or name,
        "orb_name": name,
        "backend": "orb",
        "status": status or "unknown",
        "state": state,
        "detail": f"OrbStack · {status or 'unknown'}",
        "url": _optional_text(ov.get("url")),
        "group": _display_text(ov.get("group"), "OrbStack Linux") or "OrbStack Linux",
        "actions": actions,
        "distro": _display_text(distro, ""),
        "ips": [],
        # OrbStack Linux machines are headless by design.  Reporting the reason
        # (rather than omitting the key) lets the UI explain why there is no
        # console button instead of rendering one that could never connect.
        "console_id": None,
        "console": vm_console.capability(backend="orb", vm_uuid=uuid, running=running),
    }


def list_all_vms() -> dict:
    """Both hypervisors' inventories.

    UTM and OrbStack are separate binaries that know nothing about each other, so
    one listing does not inform the other. `fan_out` keeps them in order, which is
    what puts UTM's rows ahead of OrbStack's in the combined list.
    """
    utm, orb = fan_out(
        _listing_rows, [list_utm_vms, list_orb_machines], max_workers=2
    )
    return _jsonable({
        "vms": utm + orb,
        "utm_count": len(utm),
        "orb_count": len(orb),
        "utm_available": _utm_available(),
        "orb_available": _orb_available(),
        "utmctl": UTMCTL,
        "orbctl": ORBCTL,
        "orb_distros": ORB_DISTROS,
    })


def discover_vms() -> list:
    """Status feed format for services dashboard."""
    items = []
    for v in _listing_rows(list_utm_vms) + _listing_rows(list_orb_machines):
        if not isinstance(v, dict):
            continue
        actions = []
        if v.get("state") == "ok":
            actions = ["restart", "stop"]
        else:
            actions = ["start"]
        items.append({
            "id": v.get("id"),
            "kind": "vm",
            "name": v.get("name"),
            "state": v.get("state"),  # ok | warn | stopped | down
            "detail": v.get("detail"),
            "url": v.get("url"),
            "group": v.get("group") or "Virtual Machines",
            "actions": actions,
            "backend": v.get("backend"),
        })
    return _jsonable(items) or []


def rename_vm_display(vm_id: str, new_name: str) -> dict:
    """Rename display name via services.yaml overrides (utmctl has no rename)."""
    from hub.config import set_override

    if not isinstance(new_name, str) or not new_name.strip():
        raise api_error("vms.name_required")
    new_name = new_name.strip()
    backend, name = _parse_id(vm_id)
    name = (name or "").strip()
    if not name:
        raise api_error("vms.name_required")
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


def _argv_name(value: str, *, code: str = "vms.bad_id") -> str:
    """A VM name that cannot be read as a utmctl/orbctl option.

    UTM display names may contain spaces (``Windows 11``), so this is not
    :func:`cli_args.require_positional`.  A leading hyphen is enough to turn
    ``utmctl start --help`` / ``orbctl clone src --all``.
    """
    text = str(value or "").strip()
    if (
        not text
        or text.startswith("-")
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)
    ):
        raise api_error(code)
    return text


def _parse_id(vm_id: str) -> tuple[str, str]:
    """Return (backend, name)."""
    raw = str(vm_id or "").strip()
    if not raw or any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        raise api_error("vms.bad_id")
    if raw.startswith("orb:"):
        return "orb", _argv_name(raw[4:])
    # uuid style → utm
    if re.match(r"^[0-9A-Fa-f-]{36}$", raw):
        return "utm", raw
    # Refuse before ``orbctl list``: ``--help`` is not a machine name.
    if raw.startswith("-"):
        raise api_error("vms.bad_id")
    # check orb first by listing
    try:
        machines = list_orb_machines()
    except Exception:
        machines = []
    for m in machines if isinstance(machines, list) else []:
        if not isinstance(m, dict):
            continue
        if m.get("orb_name") == raw or m.get("id") == raw:
            return "orb", _argv_name(m.get("orb_name") or raw)
    return "utm", _argv_name(raw)


def vm_action(vm_id: str, action: str, **kwargs) -> dict[str, Any]:
    backend, ident = _parse_id(vm_id)
    action = (action or "").strip().lower()

    if backend == "utm":
        return _utm_action(ident, action, **kwargs)
    if backend == "orb":
        return _orb_action(ident, action, **kwargs)
    raise api_error("vms.unknown_backend", vm=vm_id)


def _utm_action(ident: str, action: str, **kwargs) -> dict:
    if not _utm_available():
        raise api_error("vms.utm_unavailable")
    if action == "start":
        rc, out, err = sh([UTMCTL, "start", ident], timeout=90)
    elif action == "stop":
        force = kwargs.get("force", True)
        args = [UTMCTL, "stop", ident]
        if force:
            args.append("--force")
        else:
            args.append("--request")
        rc, out, err = sh(args, timeout=180)
    elif action == "kill":
        rc, out, err = sh([UTMCTL, "stop", ident, "--kill"], timeout=60)
    elif action == "suspend":
        rc, out, err = sh([UTMCTL, "suspend", ident], timeout=120)
    elif action == "restart":
        return _utm_restart_async(ident)
    elif action == "delete":
        # must be stopped
        st = _utm_status(ident)
        if st in ("started", "running"):
            sh([UTMCTL, "stop", ident, "--force"], timeout=120)
            time.sleep(2)
        rc, out, err = sh([UTMCTL, "delete", ident], timeout=60)
    elif action == "clone":
        new_name = kwargs.get("name")
        args = [UTMCTL, "clone", ident]
        if new_name is not None and new_name != "":
            if not isinstance(new_name, str):
                raise api_error("vms.bad_machine_name")
            args += ["--name", _argv_name(new_name, code="vms.bad_machine_name")]
        rc, out, err = sh(args, timeout=300)
    elif action == "ip":
        rc, out, err = sh([UTMCTL, "ip-address", ident], timeout=15)
        text = _as_text(out)
        ips = [ln.strip() for ln in text.splitlines() if ln.strip()]
        _invalidate()
        return {
            "ok": rc == 0, "action": action, "id": ident, "ips": ips,
            "message": text or _as_text(err),
        }
    elif action == "rename":
        return rename_vm_display(ident, kwargs.get("name") or "")
    elif action == "status":
        st = _utm_status(ident)
        return {"ok": True, "action": action, "id": ident, "status": st}
    else:
        raise api_error("vms.utm_unsupported_action", action=action)
    _invalidate()
    return {
        "ok": rc == 0, "action": action, "id": ident,
        "message": _as_text(out) if rc == 0 else (_as_text(err) or _as_text(out)),
    }


def _utm_status(name: str) -> str:
    rc, out, _ = sh([UTMCTL, "status", name], timeout=10)
    return _as_text(out).strip() if rc == 0 else "unknown"


def utm_vm_running(vm_uuid: str) -> bool:
    """True when the UTM VM with *vm_uuid* is currently started.

    Looked up by UUID and re-queried live rather than trusting a cached list or
    a display name: console authorisation must not follow a renamed VM, and a
    machine that stopped since the page loaded must not accept a bridge.
    """
    uuid = str(vm_uuid or "").strip().lower()
    if not uuid or not _utm_available():
        return False
    try:
        vms = list_utm_vms(force=True)
    except Exception:
        return False
    for vm in vms if isinstance(vms, list) else []:
        if not isinstance(vm, dict):
            continue
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
            if _as_text(out).strip() == "stopped":
                break
            time.sleep(2)
        sh([UTMCTL, "start", name], timeout=90)
        _invalidate()

    threading.Thread(target=job, daemon=True).start()
    return {"ok": True, "action": "restart", "id": name, "message": "Restart started (takes about 1–2 minutes)"}


def _orb_action(ident: str, action: str, **kwargs) -> dict:
    if not _orb_available():
        raise api_error("vms.orb_unavailable")
    if action == "start":
        rc, out, err = sh([ORBCTL, "start", ident], timeout=120)
    elif action == "stop":
        rc, out, err = sh([ORBCTL, "stop", ident], timeout=120)
    elif action == "restart":
        rc, out, err = sh([ORBCTL, "restart", ident], timeout=180)
    elif action == "delete":
        # orbctl delete NAME -y if exists
        rc, out, err = sh([ORBCTL, "delete", ident, "-f"], timeout=180)
        if rc != 0:
            rc, out, err = sh([ORBCTL, "delete", ident], timeout=180)
    elif action == "clone":
        new_name = kwargs.get("name")
        if new_name is None or new_name == "":
            new_name = f"{ident}-clone"
        elif not isinstance(new_name, str):
            raise api_error("vms.bad_machine_name")
        new_name = _argv_name(new_name, code="vms.bad_machine_name")
        rc, out, err = sh([ORBCTL, "clone", ident, new_name], timeout=600)
    elif action == "shell":
        # Hint only.  ``orbctl ssh`` is an interactive session and used to sit
        # on the request thread until the 10s sh() timeout.
        return {
            "ok": True,
            "action": "shell",
            "id": ident,
            "message": f"Run in a terminal: orb -m {ident}",
            "command": f"orb -m {ident}",
        }
    elif action == "info":
        rc, out, err = sh([ORBCTL, "info", ident], timeout=15)
        return {
            "ok": rc == 0, "action": "info", "id": ident,
            "message": _as_text(out) or _as_text(err),
        }
    elif action == "rename":
        return rename_vm_display(f"orb:{ident}", kwargs.get("name") or "")
    else:
        raise api_error("vms.orb_unsupported_action", action=action)
    _invalidate()
    return {
        "ok": rc == 0, "action": action, "id": ident,
        "message": _as_text(out) if rc == 0 else (_as_text(err) or _as_text(out)),
    }


def create_orb_machine(distro: str, name: str | None = None, arch: str | None = None) -> dict:
    """orbctl create DISTRO[:VERSION] [NAME]"""
    if not _orb_available():
        raise api_error("vms.orb_unavailable")
    distro = (distro or "").strip()
    if not distro:
        raise api_error("vms.distro_required")
    # ``^[a-zA-Z0-9._:-]+$`` matched ``--help`` because ``-`` is in the class
    # with no first-character anchor — ``orbctl create --help``.
    if not cli_args.is_safe_positional(distro):
        raise api_error("vms.bad_distro")
    args = [ORBCTL, "create", distro]
    if name:
        if not isinstance(name, str):
            raise api_error("vms.bad_machine_name")
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
        "message": _as_text(out) if rc == 0 else (_as_text(err) or _as_text(out)),
    }
