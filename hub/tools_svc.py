"""Tools / diagnostics — Unraid Tools parity for macOS home server.

Useful Unraid Tools mapped here:
  System Information, Diagnostics, Syslog, Processes, Hardware Profile,
  About, Docker (df/prune), Scheduler, Update check, Network helpers.

Inspired by Cockpit (logs/services), OMV (SMART/updates), CasaOS (simple tiles).
"""
from __future__ import annotations

import glob
import math
import os
import platform
import re
import shlex
import shutil
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from hub import __version__, metrics
from hub import cli_args
from hub.errors import api_error, soft_fail
from hub.host_address import host_ip
from hub.service_signatures import unescape_proc_name
from hub.docker_cli import (
    cli_on_disk,
    docker,
    engine_up,
    looks_cli_vanished,
    looks_engine_down,
    parse_int_capped,
)
from hub.paths import BASE, BREW, DOCKER, ORB
from hub.proc_cache import ps_lines
from hub.util import LazyPool, fan_out, read_bytes_capped, safe_json_loads, sh, strftime_now, tail_file_lines, ttl_memo
from hub.brew_cache import _brew_busy

_pool = LazyPool(2, "hub-tools")
#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/tools launchd views.
_PLIST_CAP = 256 * 1024


def shutdown_executor() -> None:
    _pool.shutdown()


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so an ``sh``-stub leftover whose
    ``__class__`` is a raising property blew straight through the bare
    bytes gate below before the scrub could run — a raw 500 on
    POST /api/tools/net/ping and every other ``_sh`` consumer (the
    bookmarks8/modules8 rule).
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 Tools JSON."""
    if _isinst(value, (bytes, bytearray)):
        try:
            # Unbound base decode: a subclass ``.decode`` bomb riding a
            # cross-module row (a disk power_state, say) used to raise here
            # and 500 GET /api/tools/hardware.  The try is for a *lying*
            # ``__class__`` (claims bytes, is not): the unbound call
            # TypeErrors and junk answers "" like any unreadable leftover.
            base = bytes if _isinst(value, bytes) else bytearray
            value = base.decode(value, "utf-8", "replace")
        except Exception:
            return ""
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
    try:
        # Unbound base encode (the storage7 rule): a ``__str__`` override may
        # *return* a str subclass whose bound ``encode`` bombs, and the old
        # ``value.encode(...)`` dispatched into it — degrading a readable
        # cross-module answer (a DNS ip, a ps row) to "".  ``str.encode``
        # reads the real char storage, so the text survives the bomb.
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _as_rc(value) -> int:
    """Exact int exit status from a possibly-poisoned ``rc``.

    The network_svc ``_as_rc`` rule: a real spawn always answers an exact
    int, but ``sh`` is stubbed in-process and an rc *subclass* whose
    ``__eq__`` bombs detonated the very first ``rc == 0`` /
    ``_spawn_sentinel`` compare — a raw 500 on POST /api/tools/net/ping.
    Junk degrades to ``-255``: nonzero (a poisoned rc is not consent to
    claim success) and never ``-1`` (the vanished-spawn sentinel must stay
    unforgeable).
    """
    if type(value) is not int:
        try:
            value = int(value)
        except Exception:
            return -255
        if type(value) is not int:
            return -255
    try:
        str(value)
    except ValueError:
        # Over-cap exact int (a YAML hex leftover skips CPython's digit
        # cap): it blows any ``rc={rc}`` message render the same way.
        return -255
    return value


def _sh(cmd, timeout=10, **kwargs):
    # Tests stub ``sh`` with leftover None/bytes/int; parsers below assume text.
    rc, out, err = sh(cmd, timeout=timeout, **kwargs)
    return _as_rc(rc), _as_text(out), _as_text(err)


def _docker(*args, **kwargs):
    rc, out, err = docker(*args, **kwargs)
    return rc, _as_text(out), _as_text(err)


# ─── Catalog (Unraid Tools home tiles) ───────────────────────────────────────

def tools_catalog() -> dict:
    """Tile map like Unraid /Tools — labels localized via label_key on the frontend."""
    tiles = [
        {"id": "sysinfo", "label_key": "tools.tile_sysinfo", "desc_key": "tools.tile_sysinfo_desc", "tab": "diag", "icon": "info"},
        {"id": "diagnostics", "label_key": "tools.tile_diagnostics", "desc_key": "tools.tile_diagnostics_desc", "tab": "diag", "action": "download_diag", "icon": "zip"},
        {"id": "syslog", "label_key": "tools.tile_syslog", "desc_key": "tools.tile_syslog_desc", "tab": "syslog", "icon": "log"},
        {"id": "processes", "label_key": "tools.tile_proc", "desc_key": "tools.tile_proc_desc", "tab": "proc", "icon": "cpu"},
        {"id": "hardware", "label_key": "tools.tile_hw", "desc_key": "tools.tile_hw_desc", "tab": "hw", "icon": "chip"},
        {"id": "docker", "label_key": "tools.tile_docker", "desc_key": "tools.tile_docker_desc", "tab": "docker", "icon": "docker"},
        {"id": "scheduler", "label_key": "tools.tile_sched", "desc_key": "tools.tile_sched_desc", "tab": "sched", "icon": "clock"},
        {"id": "updates", "label_key": "tools.tile_updates", "desc_key": "tools.tile_updates_desc", "tab": "updates", "icon": "update"},
        {"id": "network", "label_key": "tools.tile_net", "desc_key": "tools.tile_net_desc", "tab": "net", "icon": "net"},
        {"id": "fcp", "label_key": "tools.tile_health", "desc_key": "tools.tile_health_desc", "href": "/health", "icon": "shield"},
        {"id": "userscripts", "label_key": "tools.tile_maint", "desc_key": "tools.tile_maint_desc", "href": "/maintenance", "icon": "script"},
        {"id": "appstore", "label_key": "tools.tile_apps", "desc_key": "tools.tile_apps_desc", "href": "/apps", "icon": "apps"},
        {"id": "logs", "label_key": "tools.tile_logs", "desc_key": "tools.tile_logs_desc", "href": "/logs", "icon": "file"},
        {"id": "backups", "label_key": "tools.tile_backups", "desc_key": "tools.tile_backups_desc", "href": "/backups", "icon": "backup"},
        {"id": "alerts", "label_key": "tools.tile_alerts", "desc_key": "tools.tile_alerts_desc", "href": "/alerts", "icon": "bell"},
        {"id": "about", "label_key": "tools.tile_about", "desc_key": "tools.tile_about_desc", "tab": "about", "icon": "about"},
    ]
    return {
        "tiles": tiles,
        "hint_key": "tools.catalog_hint",
    }


# ─── Processes ───────────────────────────────────────────────────────────────

_proc_cache: dict = {"t": 0.0, "v": None, "limit": 0}
_PROC_TTL = 5.0


def _clamp_int(raw, default: int, lo: int, hi: int) -> int:
    # JSON ``1e309`` is inf; ``int(inf)`` OverflowError.  Bool is an int.
    # ``raw is True/False``, not ``isinstance(raw, bool)``, and ``_isinst``
    # below: a ``__class__``-property bomb raised out of the bare gates
    # before the try could catch anything — the same in-process
    # POST /api/tools/net/ping 500 the base coercions were added for.
    if raw is True or raw is False or raw is None:
        value = default
    else:
        try:
            # Base coercions before ``int()`` (the smart_test_svc.history
            # rule): the routes hand over Pydantic-exact ints, but these
            # services are also called in-process, and an int-subclass
            # ``__int__`` bomb raised RuntimeError past the old arithmetic
            # trio — a raw 500 on POST /api/tools/net/ping for those callers.
            if _isinst(raw, int):
                raw = int.__index__(raw)
            elif _isinst(raw, float):
                raw = float.__float__(raw)
            value = int(raw)
        except Exception:
            value = default
    return max(lo, min(value, hi))


def top_processes(limit: int = 25) -> list:
    now = time.time()
    limit = _clamp_int(limit, 25, 5, 100)
    if (
        _proc_cache["v"] is not None
        and _proc_cache["limit"] >= limit
        and now - _proc_cache["t"] < _PROC_TTL
    ):
        return _proc_cache["v"][:limit]
    # One shared `ps aux` (hub/proc_cache.py).  The row cache above stays: it holds
    # the *parsed and sorted* rows, which the shared table deliberately does not.
    lines = ps_lines()
    if isinstance(lines, list):
        # Exact-list copy through the unbound base read: a leftover
        # list-subclass table whose bound ``__len__`` / ``__getitem__``
        # raises passes the isinstance gate, and the bomb used to blow
        # ``len(lines)`` / ``lines[1:]`` below and 500
        # GET /api/system/processes.  (An ``__iter__`` bomb was already
        # neutralized by the slice; these two were not.)
        lines = list.__getitem__(lines, slice(None))
    else:
        try:
            lines = list(lines)
        except Exception:
            return []
    if len(lines) < 2:
        return []
    rows = []
    for line in lines[1:]:
        line = _as_text(line)
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            cpu = float(parts[2])
            mem = float(parts[3])
        except (TypeError, ValueError, OverflowError):
            continue
        if not (math.isfinite(cpu) and math.isfinite(mem)):
            continue
        rows.append({
            "user": parts[0],
            "pid": parts[1],
            "cpu": cpu,
            "mem": mem,
            "vsz": parts[4],
            "rss": parts[5],
            "stat": parts[7],
            "time": parts[9],
            "command": parts[10][:160],
        })
    rows.sort(key=lambda r: (r["cpu"], r["mem"]), reverse=True)
    out = rows[:limit]
    _proc_cache.update(t=time.time(), v=out, limit=limit)
    return out


# ─── Docker ──────────────────────────────────────────────────────────────────

#: `docker system df` makes the daemon walk every image, container, volume and
#: build-cache entry to total their sizes, and it was the one heavy Docker read in
#: this module with no cache: the Tools page asked for it directly, `diagnostics()`
#: asked again in the same payload, and `docker_prune()` asks a third time.  Sizes
#: move when images are pulled or pruned, not between two polls seconds apart, so a
#: short window collapses the duplicates without showing stale figures.  Pruning
#: invalidates explicitly, since that is the one caller that just changed them.
_DOCKER_DF_TTL = 30.0


def _docker_gone(rc: int, out: str, err: str) -> bool:
    """Whether a failed docker spawn should be classified as engine-down.

    Two shapes, one operator-facing state: the daemon-socket complaint, and
    ``sh``'s FileNotFoundError sentinel when the CLI itself vanished inside
    ``engine_up()``'s 5s memo (OrbStack uninstalled mid-request, a dying
    mount).  The sentinel alone is not proof — a cwd that vanished raises the
    same FileNotFoundError — so it requires the fresh disk confirm, run only
    on this failure path (the docker_cli ``looks_cli_vanished`` contract:
    pattern-match, then confirm).  Either way the forced ``engine_up`` probe
    stays the final arbiter, so a genuine CLI exit whose output merely reads
    "not found" while the engine answers "up" keeps its raw result.
    """
    if rc == 0:
        return False
    text = err or out
    suspicious = looks_engine_down(text) or (
        looks_cli_vanished(text) and not cli_on_disk()
    )
    # _safe_flag: the forced probe is a cross-module read, and a leftover
    # ``__bool__`` bomb riding its answer used to raise here — a raw 500 on
    # GET /api/docker/df and POST /api/tools/docker/prune instead of the
    # engine-down classification.  An unanswerable probe counts as down.
    return suspicious and not _safe_flag(engine_up(force=True))


@ttl_memo(_DOCKER_DF_TTL)
def docker_disk_usage() -> dict:
    # _safe_flag: ``engine_up()`` is a cross-module read and these three
    # docker views trusted its bool contract wholesale — a leftover
    # ``__bool__`` bomb answer used to raise out of the bare ``if not`` and
    # 500 GET /api/docker/df, GET /api/docker/sizes and
    # POST /api/tools/docker/prune (diagnostics' probe_docker was already
    # guarded).  An unanswerable flag degrades to engine-down.
    if not _safe_flag(engine_up()):
        return {"engine_up": False, "raw": "", "lines": []}
    rc, out, err = _docker("system", "df", timeout=30)
    if _docker_gone(rc, out, err):
        # The gate above trusts a 5s memo, so an engine that dies inside the
        # TTL still reached `docker system df` — and the payload then claimed
        # engine_up: True with the raw daemon stderr as `raw`.  A CLI that
        # vanished inside the same window claimed engine_up: True with the
        # two-word spawn sentinel as `raw`.  The probe is forced (same
        # convention as containers_svc._raise_if_engine_down); a failure
        # while the engine answers "up" keeps the raw message.
        return {"engine_up": False, "raw": "", "lines": []}
    lines = []
    for line in out.splitlines():
        if not line.strip() or line.startswith("TYPE"):
            continue
        m = re.match(
            r"^(.+?)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$",
            line.strip(),
        )
        if m:
            lines.append({
                "type": m.group(1).strip(),
                "total": m.group(2),
                "active": m.group(3),
                "size": m.group(4),
                "reclaimable": m.group(5).strip(),
            })
    return {"engine_up": True, "raw": out or err, "lines": lines}


def container_sizes() -> list:
    # _safe_flag: same cross-module ``__bool__``-bomb guard as
    # docker_disk_usage above.
    if not _safe_flag(engine_up()):
        return []
    # -s/--size is what populates {{.Size}}.  OrbStack happens to fill it in
    # anyway, but stock Docker Engine leaves the column empty without it, so the
    # size table would render blank on any other host.  It costs nothing here
    # (measured: same 0.06s with and without on 4 containers).
    rc, out, _ = _docker(
        "ps", "-a", "-s",
        "--format", "{{.Names}}\t{{.Size}}\t{{.Image}}\t{{.Status}}",
        timeout=60,
    )
    items = []
    if rc == 0:
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) >= 2:
                items.append({
                    "name": p[0],
                    "size": p[1],
                    "image": p[2] if len(p) > 2 else "",
                    "status": p[3] if len(p) > 3 else "",
                })
    return items


def docker_prune(what: str = "dangling", confirm: bool = False) -> dict:
    """Safe-ish Docker cleanup. what: dangling | build | volumes | all_unused.

    Never force-removes running containers. Requires confirm=True.
    """
    if not confirm:
        return soft_fail("tools.confirm_required")
    # _safe_flag: same cross-module ``__bool__``-bomb guard as
    # docker_disk_usage above — the bomb becomes the coded engine-down
    # soft-fail, never a raw 500.
    if not _safe_flag(engine_up()):
        return soft_fail("container.engine_down")
    cmds = {
        "dangling": ["image", "prune", "-f"],
        "build": ["builder", "prune", "-f"],
        "volumes": ["volume", "prune", "-f"],
        "all_unused": ["system", "prune", "-f"],  # unused images/networks/stopped containers
    }
    if not isinstance(what, str):
        out = soft_fail("tools.bad_prune", what="")
        out["allowed"] = list(cmds.keys())
        return out
    what = (what or "dangling").strip().lower()
    if what not in cmds:
        out = soft_fail("tools.bad_prune", what=what)
        out["allowed"] = list(cmds.keys())
        return out
    rc, out, err = _docker(*cmds[what], timeout=180)
    # A prune is exactly the event the cached totals describe, so the cached copy is
    # wrong the moment this returns.  Drop it before reporting the new figures.
    docker_disk_usage.invalidate()
    if _docker_gone(rc, out, err):
        # The engine_up() gate at entry trusts a 5s memo; an engine that died
        # inside the TTL used to surface as an uncoded ok:false carrying the
        # raw untranslated daemon stderr — and a CLI that vanished inside it
        # as an uncoded ok:false carrying the raw two-word spawn sentinel.
        # Coded soft-fail (dict contract, like tools ping/dns) with the
        # fields Tools.vue already renders.
        fail = soft_fail("container.engine_down")
        fail["what"] = what
        fail["df"] = None
        return fail
    return {
        "ok": rc == 0,
        "what": what,
        "message": (out or err or "").strip()[:2000] or ("done" if rc == 0 else "failed"),
        "df": docker_disk_usage() if rc == 0 else None,
    }


# ─── Diagnostics / system info ───────────────────────────────────────────────

def diagnostics() -> dict:
    # Six unrelated questions -- the hostname, three sysctls, the boot time, and the
    # Docker engine's disk totals -- and not one of them reads another's answer.  Run
    # top to bottom this was the whole payload's latency added up, and `docker system
    # df` alone is most of it, so the four cheap sysctls sat waiting behind it for no
    # reason.  Each probe absorbs its own failure and returns the same fallback the
    # serial version used, which is what `fan_out` requires.
    def probe_hostname() -> str:
        rc, out, _ = _sh(["/bin/hostname"], timeout=3)
        return out if rc == 0 else _as_text(platform.node())

    def probe_cpu() -> str:
        rc, out, _ = _sh(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], timeout=3)
        return out if rc == 0 else ""

    def probe_ncpu() -> int | None:
        rc, out, _ = _sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=3)
        if rc != 0 or not out.isdigit():
            return None
        try:
            # ``isdigit()`` does not bound length: ``int()`` of a >4300-digit
            # leftover is ValueError (CPython's str->int cap), which used to
            # 500 GET /api/system/diagnostics through fan_out.
            return int(out)
        except (TypeError, ValueError, OverflowError):
            return None

    def probe_mem_gb() -> float | None:
        rc, out, _ = _sh(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=3)
        if rc != 0 or not out.isdigit():
            return None
        # A leftover 400-digit ``hw.memsize`` OverflowError'd GET
        # /api/diagnostics; a >4300-digit one ValueError'd ``int()`` itself.
        try:
            gb = round(int(out) / 2**30, 1)
        except (TypeError, ValueError, OverflowError):
            return None
        return gb if math.isfinite(gb) else None

    def probe_uptime() -> int | None:
        try:
            rc, boot, _ = _sh(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
            if rc == 0 and "sec =" in boot:
                m = re.search(r"sec\s*=\s*(\d+)", boot)
                if m:
                    try:
                        return int(time.time()) - int(m.group(1))
                    except (TypeError, ValueError, OverflowError):
                        # Leftover ``time.time() = inf`` OverflowError'd GET /api/diagnostics.
                        return None
        except Exception:
            pass
        return None

    def probe_docker() -> tuple[bool, dict]:
        # Kept as one unit so the `if eng` guard is preserved exactly; `engine_up`
        # is itself cached and single-flighted, so asking here costs nothing.
        try:
            eng = engine_up()
            return eng, (docker_disk_usage() if eng else {})
        except Exception:
            return False, {}

    def probe_platform() -> str:
        # identity_svc's memo, not a bare platform.platform(): on macOS that shells
        # out twice (`uname -p`, then `file -b` on the interpreter via
        # architecture()), and the settings bundle and the diagnostics header want
        # the same string.  Same substitution _diag_host already makes.
        try:
            from hub.identity_svc import platform_string
            return platform_string()
        except Exception:
            return _as_text(platform.platform())

    def probe_host_ip() -> str:
        try:
            return host_ip()
        except Exception:
            return ""

    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = 0.0
    load1, load5, load15 = _finite_load(load1), _finite_load(load5), _finite_load(load15)
    # The last two used to be inlined in the return dict below, so they ran *after*
    # this wave rather than in it -- `platform.platform()` two spawns deep and
    # `host_ip()` another two, four spawns of pure tail on an endpoint whose whole
    # point is to answer quickly when something is wrong.  Neither reads anything
    # else here, and neither is read by anything here.
    (
        hostname, model, ncpu, mem_gb, uptime_s, (eng, df), plat, ip,
    ) = fan_out(
        lambda probe: probe(),
        [
            probe_hostname, probe_cpu, probe_ncpu, probe_mem_gb, probe_uptime,
            probe_docker, probe_platform, probe_host_ip,
        ],
    )

    try:
        du = shutil.disk_usage("/")
        total = du.total or 0
        root_disk_pct = round(du.used / total * 100, 1) if total else 0.0
        root_disk_free_gb = round(du.free / 2**30, 1)
    except (OSError, OverflowError, ValueError, TypeError):
        root_disk_pct = 0.0
        root_disk_free_gb = 0.0
    if not math.isfinite(root_disk_pct):
        root_disk_pct = 0.0
    if not math.isfinite(root_disk_free_gb):
        root_disk_free_gb = 0.0
    try:
        metrics_points = len(metrics.history(60))
    except Exception:
        # A leftover history table that refuses ``len()`` (a list-subclass
        # ``__len__`` bomb, an unsized answer) used to raise here — the one
        # unguarded cross-module read left in this collector — and 500
        # GET /api/system/diagnostics after every probe had answered.
        metrics_points = 0
    return {
        "hostname": _as_text(hostname),
        "platform": _as_text(plat),
        "arch": _as_text(platform.machine()),
        "cpu": model,
        "ncpu": ncpu,
        "mem_gb": mem_gb,
        "load": [load1, load5, load15],
        "uptime_sec": uptime_s,
        "uptime_human": _fmt_uptime(uptime_s) if uptime_s else None,
        "root_disk_pct": root_disk_pct,
        "root_disk_free_gb": root_disk_free_gb,
        "orbstack": eng,
        # shutil.which resolves these at import from a surrogateescape-decoded
        # PATH; a leftover lone surrogate served raw 500'd the UTF-8 encode of
        # GET /api/system/diagnostics (the _host_snapshot fix, one module over).
        "docker_cli": _as_text(DOCKER),
        "orb_cli": _as_text(ORB),
        "python": _as_text(platform.python_version()),
        # host_ip() sanitizes its own answer today, but this boundary echoed
        # it raw while every sibling field goes through _as_text — a leftover
        # lone-surrogate address 500'd the UTF-8 encode and a >4300-digit int
        # ValueError'd Starlette's json.dumps on GET /api/system/diagnostics.
        "host_ip": _as_text(ip),
        "docker_df": df,
        "metrics_points": metrics_points,
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "version": __version__,
    }


def _finite_load(value) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return round(number, 2) if math.isfinite(number) else 0.0


def _fmt_uptime(sec: int | None) -> str:
    if isinstance(sec, bool) or sec is None:
        return "—"
    try:
        value = int(sec)
    except (TypeError, ValueError, OverflowError):
        return "—"
    if value <= 0:
        return "—"
    d, r = divmod(value, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# ─── Syslog (Unraid Syslog) ──────────────────────────────────────────────────

#: `log show` scans the unified log archive and measured 10-13s on this host --
#: on *every* request, warm or cold, because this was the one heavy reader in this
#: module without a cache (hardware_profile and updates below both have one).
#: Revisiting the Logs page or leaving it polling therefore paid the full scan
#: each time.  Keyed by the query, since a different window or level is a
#: different scan.  The TTL is short enough that the page still reads as live and
#: long enough that flipping between levels and back is instant.
_syslog_cache: dict[tuple[int, int, str], tuple[float, dict]] = {}
_SYSLOG_TTL = 45.0
#: One lock, deliberately: a second viewer arriving mid-scan waits and then finds
#: the fresh result rather than starting a second 10s scan of its own.
_syslog_refresh_lock = threading.Lock()


def syslog_tail(
    minutes: int = 60,
    limit: int = 80,
    level: str = "error",
    force: bool = False,
) -> dict:
    """Recent unified log entries (macOS log show).

    level: error | fault | default (broader) | all
    """
    minutes = _clamp_int(minutes, 60, 5, 24 * 60)
    limit = _clamp_int(limit, 80, 10, 300)
    level = (str(level or "error")).lower()

    key = (minutes, limit, level)
    if not force:
        hit = _syslog_cache.get(key)
        if hit and time.time() - hit[0] < _SYSLOG_TTL:
            return {**hit[1], "cached": True}

    with _syslog_refresh_lock:
        # Re-check: another request may have completed the same scan while this
        # one waited, which is what turns the lock into a single-flight.
        hit = _syslog_cache.get(key)
        if not force and hit and time.time() - hit[0] < _SYSLOG_TTL:
            return {**hit[1], "cached": True}
        result = _syslog_tail_uncached(minutes, limit, level)
        if result.get("ok"):
            _syslog_cache[key] = (time.time(), result)
            # Bounded: minutes x limit x level is a small space, but a caller
            # sweeping it would otherwise grow this without limit.
            if len(_syslog_cache) > 24:
                oldest = min(_syslog_cache, key=lambda k: _syslog_cache[k][0])
                _syslog_cache.pop(oldest, None)
        return {**result, "cached": False}


def _syslog_tail_uncached(minutes: int, limit: int, level: str) -> dict:
    # Prefer lightweight predicates
    if level == "error":
        predicate = 'eventType == "logEvent" AND messageType == "error"'
    elif level == "fault":
        predicate = 'eventType == "logEvent" AND messageType IN {"error","fault"}'
    elif level == "default":
        predicate = 'eventType == "logEvent" AND messageType IN {"error","fault","default"}'
    else:
        predicate = 'eventType == "logEvent"'

    # log show can be slow; keep last short and timeout tight
    cmd = [
        "/usr/bin/log", "show",
        "--last", f"{minutes}m",
        "--predicate", predicate,
        "--style", "compact",
    ]
    if level == "all":
        cmd.append("--info")
    rc, out, err = _sh(cmd, timeout=25)

    lines = []
    if rc == 0 and out:
        raw_lines = [ln for ln in out.splitlines() if ln.strip()]
        raw_lines = [ln for ln in raw_lines if not ln.startswith("Timestamp")]
        lines = raw_lines[-limit:]
    elif rc != 0:
        syslog_path = Path("/var/log/system.log")
        try:
            fallback = syslog_path.exists()
        except OSError:
            fallback = False
        if fallback:
            try:
                lines = tail_file_lines(syslog_path, limit)
                err = "fallback:/var/log/system.log"
                rc = 0
            except OSError as e:
                err = _as_text(e)

    return {
        "ok": rc == 0,
        "minutes": minutes,
        "level": level,
        "count": len(lines),
        "lines": lines,
        "message": (err or "")[:300] if rc != 0 else "",
        "hint": "macOS unified log",
    }


# ─── Hardware Profile ────────────────────────────────────────────────────────

_hw_cache: dict = {"t": 0.0, "v": None}
_HW_TTL = 300.0  # system_profiler is heavy
_updates_cache: dict = {"t": 0.0, "v": None}
_UPDATES_TTL = 600.0  # softwareupdate is very expensive

#: Held only across a refresh, never across a cache read.  Separate locks so a
#: slow `softwareupdate -l` cannot block a hardware-profile request.
_hw_refresh_lock = threading.Lock()
_updates_refresh_lock = threading.Lock()


def _hw_fresh() -> dict | None:
    v = _hw_cache["v"]
    if v is not None and time.time() - _hw_cache["t"] < _HW_TTL:
        return v
    return None


def hardware_profile(force: bool = False) -> dict:
    """Unraid Hardware Profile — system_profiler subsets (cached 5 min).

    Single-flight: four ``system_profiler`` subsets at up to 12s each is far too
    expensive to run once per concurrent caller.  Waiters re-check the cache
    after acquiring the lock, so the second arrival returns the first one's
    result instead of paying again.  ``force`` skips the fast path but still
    joins the refresh, so a page full of parallel widgets cannot stampede.
    """
    if not force:
        hit = _hw_fresh()
        if hit is not None:
            return hit
    with _hw_refresh_lock:
        hit = _hw_fresh()
        if hit is not None:
            return hit
        return _hardware_profile_uncached()


def _profiler_report(entry) -> tuple[int, str]:
    """``(rc, truncated text)`` for one system_profiler data type.  Never raises.

    Truncation happens here rather than at the call site so the 4000-character
    cap is applied to each report independently, exactly as the serial version
    did, and so an exploding report yields its message instead of costing the
    other three.
    """
    _, data_type = entry
    try:
        rc, out, err = _sh(
            ["/usr/sbin/system_profiler", data_type, "-detailLevel", "mini"],
            timeout=12,
        )
    except Exception as exc:  # noqa: BLE001 - one report must not lose the rest
        # leftover ``str(exc)`` RecursionError / ``\\ud800`` used to 500 GET /api/tools.
        return 1, _as_text(exc)[:4000]
    text = (out or err or "").strip()
    if len(text) > 4000:
        text = text[:4000] + "\n…(truncated)"
    return rc, text


def _renderable_number(value):
    """*value* as a number Starlette's allow_nan=False encoder can emit, or None.

    Bool is an int; inf/nan are refused by the encoder; an over-cap int (YAML/
    plist hex loads uncapped through ``int(x, 16)``) makes ``json.dumps`` itself
    raise the int->str digit-cap ValueError, so probe with ``str()``.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # used to blow the digit-cap probe below (only ValueError was
                # caught) and 500 GET /api/tools/hardware.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            return None
        return value
    if isinstance(value, float):
        if type(value) is not float:
            try:
                value = float.__float__(value)
            except Exception:
                return None
        return value if math.isfinite(value) else None
    return None


def _safe_flag(value, *, tri: bool = False):
    """``bool(value)`` that a leftover ``__bool__`` bomb cannot raise through."""
    if tri and value is None:
        return None
    try:
        return bool(value)
    except Exception:
        return None if tri else False


def _power_disk_row(d) -> dict | None:
    """The hardware tab's subset of one disk-power row.  Never raises.

    ``list_power_disks`` sanitizes its own fields today, but this boundary
    trusted that cross-module contract wholesale: text fields go through
    ``_as_text`` (numeric ids coerce via its str() probe; unrenderable ones
    degrade to ""), ``size_gb`` through the renderable-number probe, and the
    two flags through ``bool``, so a poisoned row costs itself one field
    rather than the whole cached payload.

    Reads are unbound (``dict.get``): a dict-subclass row whose bound
    ``get()`` raises still passes the isinstance gate, and the bomb used to
    escape into ``fan_out`` — which re-raises on iteration — and 500
    GET /api/tools/hardware.  Same for ``__bool__`` bombs on the two flags.
    """
    if not isinstance(d, dict):
        return None
    ssd = dict.get(d, "ssd")
    return {
        "id": _as_text(dict.get(d, "id")),
        "name": _as_text(dict.get(d, "name")),
        "size_gb": _renderable_number(dict.get(d, "size_gb")),
        "ssd": _safe_flag(ssd, tri=True),
        "power_state": _as_text(dict.get(d, "power_state")),
        "system": _safe_flag(dict.get(d, "system")),
    }


def _hardware_profile_uncached() -> dict:
    sections = {}
    # Keep only quick types — skip network/displays by default (slow & rarely needed)
    types = [
        ("hardware", "SPHardwareDataType"),
        ("memory", "SPMemoryDataType"),
        ("storage", "SPStorageDataType"),
        ("power", "SPPowerDataType"),
    ]
    # Four independent `system_profiler` reports, each with a 12s timeout, ran one
    # after another -- so the hardware page's latency was their sum even though no
    # report depends on another.  `fan_out` keeps them in the declared order,
    # which is the order the sections are rendered in.
    def profiler_sections() -> dict:
        out: dict = {}
        for (key, dt), (rc, text) in zip(types, fan_out(_profiler_report, types)):
            out[key] = {
                "ok": rc == 0,
                "data_type": dt,
                "text": text,
            }
        return out

    def power_disks() -> list:
        try:
            from hub import disk_power_svc
            rows = disk_power_svc.list_power_disks()[:12]
        except Exception:
            return []
        # Field-by-field, not pass-through: this boundary used to copy the six
        # fields raw, so one leftover ``\ud800`` name / inf size_gb / bytes
        # power_state in a single row 500'd GET /api/tools/hardware at
        # Starlette's encode — outside the try above — and the poisoned
        # payload then sat in _hw_cache, re-serving that 500 for the full
        # 5-minute TTL with the four profiler sections wiped alongside.
        out = []
        for d in rows:
            try:
                row = _power_disk_row(d)
            except Exception:
                # Last-ditch: a bomb the field scrubs miss costs its own row,
                # never the batch (fan_out re-raises on iteration, which
                # would wipe the profiler sections alongside).
                row = None
            if row is not None:
                out.append(row)
        return out

    # The disk listing is its own multi-level chain (which disks exist, what `/` sits
    # on, then one `diskutil info` per disk), and it waited for all four profiler
    # reports first even though neither half reads the other.  Nested rather than
    # flattened: the inner batch keeps the section order the page renders, and both
    # levels are bounded, so this cannot outgrow the per-call pools.
    section_rows, disks = fan_out(
        lambda collect: collect(), [profiler_sections, power_disks], max_workers=2
    )
    sections.update(section_rows)
    v = {
        "sections": sections,
        "disks": disks,
        "ts": strftime_now("%H:%M:%S"),
        "hint": "Hardware info is cached for 5 minutes",
        "cached": True,
    }
    _hw_cache.update(t=time.time(), v=v)
    return v


# ─── Updates ─────────────────────────────────────────────────────────────────

def _updates_fresh() -> dict | None:
    v = _updates_cache["v"]
    if v is not None and time.time() - _updates_cache["t"] < _UPDATES_TTL:
        return v
    return None


_updates_warmer_stop: threading.Event | None = None
_updates_warmer_thread: threading.Thread | None = None


def start_updates_warmer(initial_delay: float = 25.0) -> None:
    """Keep the update cache populated so no request ever pays for the probe.

    ``brew outdated`` plus ``softwareupdate -l`` measured 11.5s cold here, and the
    existing cache only helps *after* someone has already waited for it.  Whoever
    opened the Tools page first absorbed the whole cost.

    The refresh runs at two thirds of the TTL so the entry is replaced before it
    expires and the window where a request finds nothing cached never opens.  The
    initial delay keeps this off the startup path: the panel should be answering
    requests long before it spends ten seconds asking Homebrew about updates.
    """
    global _updates_warmer_stop, _updates_warmer_thread
    if _updates_warmer_thread and _updates_warmer_thread.is_alive():
        return
    stop = threading.Event()
    interval = max(60.0, _UPDATES_TTL * 2 / 3)

    def loop():
        if stop.wait(initial_delay):
            return
        while True:
            try:
                check_updates(force=True)
            except Exception:
                # A warmer must never take the panel down; the next pass retries.
                pass
            if stop.wait(interval):
                return

    _updates_warmer_stop = stop
    _updates_warmer_thread = threading.Thread(
        target=loop, daemon=True, name="updates-warmer"
    )
    _updates_warmer_thread.start()


def stop_updates_warmer() -> None:
    global _updates_warmer_stop, _updates_warmer_thread
    if _updates_warmer_stop is not None:
        _updates_warmer_stop.set()
    _updates_warmer_stop = None
    _updates_warmer_thread = None


def check_updates(force: bool = False) -> dict:
    """Lightweight update overview (cached 10 min — softwareupdate is expensive).

    Single-flight, same reasoning as ``hardware_profile``: ``brew outdated`` plus
    ``softwareupdate -l`` is up to 90s of subprocess time, and the Tools page can
    ask for it from several widgets at once.  GitHub is a short HTTPS GET for
    the panel's own latest release and rides the same snapshot.
    """
    if not force:
        hit = _updates_fresh()
        if hit is not None:
            return hit
    with _updates_refresh_lock:
        if not force:
            hit = _updates_fresh()
            if hit is not None:
                return hit
        return _check_updates_uncached(force=force)


#: `brew outdated` hung past 45s for hours on this host (mirror / lock).
#: The updates warmer calls it every ~7 min with force=True; without a
#: cooldown that is a 45s blocked thread plus a timeout line each pass.
_BREW_FAIL_COOLDOWN = 1800.0
_brew_retry_at = 0.0


def _brew_env() -> dict:
    env = dict(os.environ)
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    return env


def _brew_outdated() -> dict:
    """`brew outdated`, as the updates card wants it.  Never raises."""
    # hub.paths.BREW, not a local which()-or-default: the local form omits the
    # /usr/local prefix, so on Intel with brew off PATH the updates card reported
    # "no brew" while the rest of the panel used brew happily.
    global _brew_retry_at
    brew = BREW
    try:
        present = Path(brew).exists()
    except OSError:
        present = False
    if not present:
        return {"ok": False, "outdated": [], "count": 0, "raw": ""}
    now = time.time()
    busy = _brew_busy()
    if busy or now < _brew_retry_at:
        hit = _updates_fresh()
        previous = hit.get("brew") if isinstance(hit, dict) else None
        if isinstance(previous, dict):
            return previous
        return {"ok": False, "outdated": [], "count": 0, "raw": "busy" if busy else "timeout"}
    try:
        rc, out, err = _sh(
            [brew, "outdated", "--verbose"], timeout=45, env=_brew_env(),
        )
    except Exception as exc:  # noqa: BLE001 - reported in the card
        return {"ok": False, "outdated": [], "count": 0, "raw": _as_text(exc)[:200]}
    if rc == -1 and err == "timeout":
        _brew_retry_at = now + _BREW_FAIL_COOLDOWN
    elif rc == 0:
        _brew_retry_at = 0.0
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    return {
        "ok": rc == 0,
        "outdated": lines[:40],
        "count": len(lines),
        "raw": (err or "")[:200] if rc != 0 else "",
    }


def _macos_updates() -> dict:
    """`softwareupdate -l`, filtered.  Never raises."""
    try:
        # slow by nature; a tight timeout and a partial answer beat blocking
        rc, out, err = _sh(["/usr/sbin/softwareupdate", "-l"], timeout=45)
    except Exception as exc:  # noqa: BLE001 - reported in the card
        return {"ok": False, "lines": [], "raw": _as_text(exc)[:1500], "has_updates": False}
    raw = (out or err or "").strip()
    interesting = [
        ln for ln in raw.splitlines()
        if ln.strip() and not ln.startswith("Software Update Tool")
    ]
    return {
        "ok": rc == 0,
        "lines": interesting[:30],
        "raw": raw[:1500],
        "has_updates": any(
            "Label:" in ln or "recommended" in ln.lower() or "*" in ln
            for ln in interesting
        ),
    }


#: Pinned GitHub API host.  The panel checks its own releases here; a
#: settings override may change owner/name, never the host.
_GITHUB_HOST = "api.github.com"
_GITHUB_REPO_DEFAULT = "elvin-li/ServerHub"
_GITHUB_TIMEOUT = 8.0
_GITHUB_BODY_CAP = 256 * 1024
_GITHUB_TTL = 1800.0
_github_cache: dict = {"t": 0.0, "v": None}
_github_lock = threading.Lock()
_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_TAG_RE = re.compile(r"\Av?[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _github_repo() -> str:
    try:
        from hub.config import settings_section
        raw = _as_text((settings_section("updates") or {}).get("github_repo")).strip()
    except Exception:
        raw = ""
    if _REPO_RE.fullmatch(raw):
        return raw
    return _GITHUB_REPO_DEFAULT


def parse_version(value) -> tuple:
    """Numeric version tuple from ``v3.9.1`` / ``3.9.1-4-gdeadbeef``.

    Non-numeric leftovers become ``(0,)`` so a compare never OverflowError's
    or TypeError's GET /api/tools/updates.  Git describe's ``-N-gSHA`` suffix
    is ignored so ``v3.9.1-4-gdead`` still compares as 3.9.1.
    """
    text = _as_text(value).strip()
    m = re.match(r"v?(\d+(?:\.\d+){0,5})", text, re.I)
    if not m:
        return (0,)
    parts: list[int] = []
    for chunk in m.group(1).split("."):
        try:
            parts.append(int(chunk))
        except (TypeError, ValueError, OverflowError):
            break
    return tuple(parts) or (0,)


def _github_empty(*, error: str = "", repo: str | None = None) -> dict:
    return {
        "ok": False,
        "current": _as_text(__version__),
        "latest": None,
        "tag": None,
        "html_url": "",
        "published_at": "",
        "notes": "",
        "update_available": False,
        "error": _as_text(error)[:300],
        "repo": repo or _github_repo(),
        "source": "",
    }


def _github_get_json(path: str):
    """GET ``https://api.github.com`` *path*.  Returns parsed JSON or raises."""
    if not isinstance(path, str) or not path.startswith("/repos/"):
        raise ValueError("github path")
    url = f"https://{_GITHUB_HOST}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"ServerHub/{_as_text(__version__) or 'panel'}",
            "Accept": "application/vnd.github+json",
        },
        method="GET",
    )
    from hub.http_guard import no_redirect_opener
    opener = no_redirect_opener()
    try:
        resp = opener.open(req, timeout=_GITHUB_TIMEOUT)
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(_GITHUB_BODY_CAP)
        except Exception:
            body = b""
        raise RuntimeError(_as_text(body[:200]) or f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError) as exc:
        raise RuntimeError(_as_text(exc)[:200] or "unreachable") from exc
    try:
        raw = resp.read(_GITHUB_BODY_CAP)
    finally:
        try:
            resp.close()
        except Exception:
            pass
    try:
        # parse_int_capped: a leftover >4300-digit numeric literal makes
        # ``json.loads`` itself raise ValueError (not JSONDecodeError) at
        # CPython's str->int digit cap, so one unrenderable number (a release
        # ``id``, say) used to wipe the whole updates card to
        # "invalid github json" — and the tags fallback with it, since both
        # routes share this reader.  The hook loads the huge literal as None
        # and the tag/notes fields the card actually renders survive.
        parsed = safe_json_loads(
            raw.decode("utf-8", "replace") or "null", parse_int=parse_int_capped,
        )
    except (ValueError, TypeError, RecursionError):
        raise RuntimeError("invalid github json")
    return parsed


def _release_from_payload(payload, *, repo: str, source: str) -> dict | None:
    if not isinstance(payload, dict):
        return None
    tag = _as_text(payload.get("tag_name") or payload.get("name")).strip()
    if not tag or not _TAG_RE.fullmatch(tag):
        return None
    html = _as_text(payload.get("html_url")).strip()
    if html and not html.startswith("https://github.com/"):
        html = f"https://github.com/{repo}/releases/tag/{tag}"
    if not html:
        html = f"https://github.com/{repo}/releases/tag/{tag}"
    notes = _as_text(payload.get("body"))[:1500]
    current = _as_text(__version__)
    latest = tag.lstrip("vV") or tag
    newer = parse_version(latest) > parse_version(current)
    return {
        "ok": True,
        "current": current,
        "latest": latest,
        "tag": tag,
        "html_url": html,
        "published_at": _as_text(payload.get("published_at") or payload.get("created_at"))[:40],
        "notes": notes,
        "update_available": newer,
        "error": "",
        "repo": repo,
        "source": source,
    }


def _github_latest_uncached() -> dict:
    repo = _github_repo()
    try:
        payload = _github_get_json(f"/repos/{repo}/releases/latest")
        found = _release_from_payload(payload, repo=repo, source="release")
        if found:
            return found
    except RuntimeError as exc:
        err = _as_text(exc)
        low = err.lower()
        # 404 = no releases published; fall through to tags.
        if "404" not in low and "not found" not in low:
            return _github_empty(error=err, repo=repo)
    try:
        tags = _github_get_json(f"/repos/{repo}/tags?per_page=5")
    except RuntimeError as exc:
        return _github_empty(error=_as_text(exc), repo=repo)
    if not isinstance(tags, list) or not tags:
        return _github_empty(error="no github releases or tags", repo=repo)
    first = tags[0] if isinstance(tags[0], dict) else {}
    fake = {
        "tag_name": first.get("name"),
        "html_url": f"https://github.com/{repo}/releases/tag/{_as_text(first.get('name')).strip()}",
        "body": "",
    }
    found = _release_from_payload(fake, repo=repo, source="tag")
    return found or _github_empty(error="unreadable github tag", repo=repo)


def _github_latest(*, force: bool = False) -> dict:
    """Latest GitHub release/tag for this panel.  Never raises."""
    now = time.time()
    if not force:
        hit = _github_cache["v"]
        if hit is not None and now - _github_cache["t"] < _GITHUB_TTL:
            return hit
    with _github_lock:
        if not force:
            hit = _github_cache["v"]
            if hit is not None and time.time() - _github_cache["t"] < _GITHUB_TTL:
                return hit
        try:
            result = _github_latest_uncached()
        except Exception as exc:
            result = _github_empty(error=_as_text(exc)[:200])
        _github_cache.update(t=time.time(), v=result)
        return result


def github_update_status(*, fetch: bool = True, force: bool = False,
                         checkout: bool = True) -> dict:
    """Cached GitHub snapshot plus optional local checkout state.  Never raises.

    ``fetch=False`` never opens a socket (dashboard / About / status poll).
    ``checkout=False`` skips ``git status`` so a hot poll cannot stall.
    """
    if not fetch:
        hit = _github_cache["v"]
        gh = hit if isinstance(hit, dict) else _github_empty(error="")
    else:
        gh = _github_latest(force=force)
    if not checkout:
        return gh if isinstance(gh, dict) else _github_empty()
    return _with_checkout_state(gh)


def _checkout_is_git() -> bool:
    try:
        return (Path(BASE) / ".git").is_dir()
    except OSError:
        return False


def _with_checkout_state(gh: dict) -> dict:
    out = dict(gh) if isinstance(gh, dict) else _github_empty()
    git = _checkout_is_git()
    dirty = _git_dirty() if git else False
    out["git"] = git
    out["dirty"] = dirty
    out["can_apply"] = bool(out.get("ok") and out.get("update_available") and git)
    return out


def _git_dirty() -> bool:
    rc, out, err = _sh(
        ["/usr/bin/git", "-C", str(BASE), "status", "--porcelain"],
        timeout=8,
    )
    if rc != 0:
        return True
    return bool((out or err or "").strip())


def apply_github_update(*, confirm: bool = False, stash: bool = False) -> dict:
    """Fetch the GitHub tag and run ``install.sh`` as a maintenance job.

    Local uncommitted work blocks the merge unless *stash* is true.  The stash
    is kept (named ``serverhub-pre-update``) because ``install.sh`` restarts
    the panel before a ``stash pop`` would run.
    """
    if not confirm:
        raise api_error("tools.confirm_required")
    if not _checkout_is_git():
        raise api_error("tools.not_a_git_checkout")
    snap = _github_latest(force=True)
    if not snap.get("ok"):
        raise api_error("tools.github_unreachable", error=_as_text(snap.get("error"))[:200] or "github")
    if not snap.get("update_available"):
        raise api_error("tools.no_update")
    tag = _as_text(snap.get("tag")).strip()
    if not _TAG_RE.fullmatch(tag):
        raise api_error("tools.no_update")
    dirty = _git_dirty()
    if dirty and not stash:
        raise api_error("tools.dirty_tree")
    from hub import jobs
    root = shlex.quote(str(BASE))
    safe_tag = shlex.quote(tag)
    stash_line = (
        '/usr/bin/git stash push -u -m serverhub-pre-update; '
        if dirty and stash else ""
    )
    command = (
        f"set -euo pipefail; cd {root}; "
        f"{stash_line}"
        f"/usr/bin/git fetch --tags origin; "
        f"/usr/bin/git merge --ff-only {safe_tag}; "
        f"./install.sh"
    )
    jobs.start_job({
        "id": "panel-update",
        "command": command,
        "timeout": 900,
    })
    return {
        "ok": True,
        "job_id": "panel-update",
        "tag": tag,
        "latest": snap.get("latest"),
        "stashed": bool(dirty and stash),
    }


def apply_brew_upgrade(*, confirm: bool = False) -> dict:
    """Upgrade outdated Homebrew formulae as a maintenance job."""
    if not confirm:
        raise api_error("tools.confirm_required")
    if _brew_busy():
        raise api_error("tools.brew_busy")
    brew = BREW
    try:
        present = Path(brew).is_file()
    except OSError:
        present = False
    if not present:
        raise api_error("tools.brew_busy")
    from hub import jobs
    jobs.start_job({
        "id": "brew-upgrade",
        "command": f"{shlex.quote(str(brew))} upgrade --quiet",
        "timeout": 1800,
    })
    return {"ok": True, "job_id": "brew-upgrade"}


def _check_updates_uncached(*, force: bool = False) -> dict:
    # Two unrelated package managers asked two unrelated questions, each with a 45s
    # timeout -- so in series the worst case was the 90s the docstring warns about,
    # and the ordinary case was the sum of two slow commands for no reason.  They
    # share nothing and neither needs elevation, so they run together and the cost
    # becomes the slower of the two.  GitHub is a short GET; run it on this
    # thread while those two occupy the pool.
    brew_future = _pool.submit(_brew_outdated)
    macos_future = _pool.submit(_macos_updates)
    github_result = github_update_status(fetch=True, force=force)

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    brew_result = _result(brew_future, {"ok": False, "outdated": [], "count": 0, "raw": ""})
    macos_result = _result(
        macos_future,
        {"ok": False, "lines": [], "raw": "", "has_updates": False},
    )

    result = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "github": github_result,
        "brew": brew_result,
        "macos": macos_result,
        "hint": "GitHub is the panel itself · Homebrew / macOS are check-only",
        "cached_ttl": _UPDATES_TTL,
    }
    _updates_cache.update(t=time.time(), v=result)
    return result


# ─── Network helpers ─────────────────────────────────────────────────────────

#: Module-level so the vanished-CLI probes re-check the exact path the spawn
#: used (the network_svc ROUTE/PING/DSCACHEUTIL convention).
PING = "/sbin/ping"
DSCACHEUTIL = "/usr/bin/dscacheutil"
KILLALL = "/usr/bin/killall"


def _cli_gone(path: str) -> bool:
    """Fresh disk probe: True only for a confirmed-absent binary at *path*.

    Run on a failure path only (the network_svc ``_cli_gone`` / docker
    ``cli_on_disk`` rule — a successful spawn never pays the stat).  An
    unreadable parent directory (EIO/ESTALE on a dying mount) must not
    upgrade the failure to the coded 503, so a stat that raises reads as
    "still present".
    """
    try:
        return not Path(path).is_file()
    except (OSError, ValueError):
        return False


def _spawn_sentinel(rc, out: str, err: str) -> bool:
    """True when ``(rc, out, err)`` is ``sh``'s FileNotFoundError sentinel.

    ``run_capped``/``sh`` collapse every failed spawn of a missing binary
    into exactly ``(-1, "", "not found")`` — never a real CLI exit.  A
    genuine run whose output merely reads "not found" is disambiguated by
    the :func:`_cli_gone` disk confirm every caller pairs with this check.
    """
    return rc == -1 and (err or out or "").strip() == "not found"


def net_ping(host: str, count: int = 3) -> dict:
    # The old blocklist enumerated shell metacharacters and never considered a
    # leading hyphen, so `-f` / `--flood` landed in ping's option position.
    if not cli_args.is_safe_hostname(host):
        return soft_fail("tools.bad_host")
    # Unbound ``str.strip`` (the health_svc encode-bomb rule at strip rank):
    # the route hands over a Pydantic-exact str, but a str-subclass host
    # whose bound ``.strip`` raises passed the guard above and 500'd the
    # in-process call where every junk host earns the coded refusal.  The
    # unbound base method also answers an exact str, so the subclass's other
    # overrides cannot ride into the argv below.
    host = str.strip(host)
    count = _clamp_int(count, 3, 1, 10)
    rc, out, err = _sh(
        [PING, "-c", str(count), "-W", "2000", host],
        timeout=count * 3 + 5,
    )
    if _spawn_sentinel(rc, out, err) and _cli_gone(PING):
        # A vanished /sbin/ping answered 200 ok:false output "not found",
        # which reads like the *host* does not respond — the same lie the
        # Network tab's failover/dns-lookup routes already upgraded to a
        # coded 503.  Disk-confirmed on the spawn-sentinel failure path
        # only; a present-but-failing ping keeps its honest output below.
        raise api_error("tools.ping_missing")
    return {
        "ok": rc == 0,
        "host": host,
        "count": count,
        "output": (out or err or "").strip()[:3000],
    }


def net_dns_lookup(name: str) -> dict:
    # _isinst + unbound strip in a try: a __class__-bomb name from an
    # in-process caller raised out of the bare gate, and a lying
    # ``__class__`` (claims str, is not) TypeErrors the base call — both
    # earn the coded refusal every other junk name gets.
    if not _isinst(name, str):
        return soft_fail("tools.empty_name")
    try:
        stripped = str.strip(name)
    except Exception:
        return soft_fail("tools.empty_name")
    if not stripped:
        return soft_fail("tools.empty_name")
    # `dig -f /etc/passwd` treats the file as a query list, and this endpoint
    # returns command output -- an arbitrary-file-read primitive from one
    # unanchored blocklist.  Require an alphanumeric first character instead.
    if not cli_args.is_safe_hostname(name):
        return soft_fail("tools.bad_host")
    name = stripped
    results = []
    try:
        infos = socket.getaddrinfo(name, None)
        seen = set()
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            # Raw membership first so an unhashable leftover stays the coded
            # failure below (TypeError lands in the except like any other
            # resolver fault) instead of being coerced into a junk answer.
            if ip in seen:
                continue
            seen.add(ip)
            # getaddrinfo answers are str, but this boundary echoed
            # ``sockaddr[0]`` raw: a leftover >4300-digit int (int->str digit
            # cap ValueError), lone-surrogate str (UnicodeEncodeError) or
            # non-finite float (allow_nan=False) used to 500 the Starlette
            # render of POST /api/tools/net/dns.  Scrub; an unrenderable ip
            # costs its own row, never the lookup.
            ip_text = _as_text(ip)[:64]
            if not ip_text:
                continue
            results.append({
                "ip": ip_text,
                "family": "IPv6" if fam == socket.AF_INET6 else "IPv4",
            })
    except Exception as e:
        return {"ok": False, "name": name, "message": _as_text(e), "results": []}
    # also dig if available for NS/info
    # System dig first. which("dig") used to win, so a PATH hijack could
    # replace the resolver this endpoint echoes back to the browser.
    try:
        system_dig = Path("/usr/bin/dig").is_file()
    except OSError:
        system_dig = False
    if system_dig:
        dig = "/usr/bin/dig"
    else:
        try:
            dig = shutil.which("dig") or ""
        except (OSError, ValueError):
            dig = ""
    dig_out = ""
    try:
        # Path("").exists() is True (cwd); an empty which() used to spawn [""].
        have_dig = bool(dig) and Path(dig).is_file()
    except OSError:
        have_dig = False
    if have_dig:
        rc, out, _ = _sh([dig, "+short", name], timeout=8)
        if rc == 0:
            dig_out = (out or "").strip()[:500]
    return {
        "ok": True,
        "name": name,
        "results": results,
        "dig": dig_out,
    }


def parse_lsof_listen_line(line: str) -> dict | None:
    """Parse one `lsof -nP -iTCP -sTCP:LISTEN` row.

    Layout is COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)].
    The NAME column is the last field once the trailing "(LISTEN)" state token
    is dropped; DEVICE/SIZE-OFF widths vary, so counting from the right is the
    only reliable way. NAME looks like "*:8086", "127.0.0.1:8086" or
    "[::1]:8086" — IPv6 literals contain colons, so split on the LAST one.
    """
    if isinstance(line, (bytes, bytearray)):
        line = line.decode("utf-8", "replace")
    elif not isinstance(line, str):
        return None
    parts = line.split()
    if len(parts) < 9:
        return None
    # Drop trailing state token(s) such as "(LISTEN)" to expose NAME.
    while len(parts) > 9 and parts[-1].startswith("(") and parts[-1].endswith(")"):
        parts.pop()
    name = parts[-1]
    if ":" not in name:
        return None
    address, _, port_s = name.rpartition(":")
    if not address or not port_s.isdigit():
        return None
    try:
        port = int(port_s)
    except (TypeError, ValueError):
        return None
    command = unescape_proc_name(parts[0])[:40]
    return {
        # existing keys the Tools view already renders
        "command": command,
        "pid": parts[1],
        "user": parts[2],
        "name": name[:80],
        # added: structured fields for the port-conflict pre-check
        "process": command,
        "address": address[:64],
        "port": port,
    }


def listening_ports(limit: int = 40) -> dict:
    """Quick lsof listen summary (Unraid-ish net tools)."""
    rc, out, err = _sh(
        ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
        timeout=12,
    )
    rows = []
    if rc == 0:
        for line in out.splitlines()[1:]:
            row = parse_lsof_listen_line(line)
            if row:
                rows.append(row)
    rows = rows[: _clamp_int(limit, 40, 5, 100)]
    return {
        "ok": rc == 0,
        "count": len(rows),
        "ports": rows,
        "message": (err or "")[:200] if rc != 0 else "",
    }


def flush_dns() -> dict:
    """Flush macOS DNS caches (common admin tool)."""
    msgs = []
    ok_any = False
    all_vanished = True
    for cmd in [
        [DSCACHEUTIL, "-flushcache"],
        [KILLALL, "-HUP", "mDNSResponder"],
    ]:
        rc, out, err = _sh(cmd, timeout=8)
        msgs.append(f"{' '.join(cmd)} → rc={rc} {(out or err).strip()[:80]}")
        if rc == 0:
            ok_any = True
        if not _spawn_sentinel(rc, out, err):
            all_vanished = False
    if not ok_any:
        if all_vanished and _cli_gone(DSCACHEUTIL) and _cli_gone(KILLALL):
            # Both spawns answered ``sh``'s vanished sentinel and both
            # binaries are confirmed off disk: "partially failed (may need
            # administrator privileges)" blamed sudo rights for missing
            # host tools.  The raise fires *before* the sudo fallback, so
            # nothing re-spawns over the confirmed-gone killall.  Either
            # tool still on disk — including present-but-failing (a real
            # permission problem) — keeps the honest escalation below.
            raise api_error("tools.dns_flush_tools_missing")
        # may need sudo for killall
        rc, out, err = _sh(
            ["/usr/bin/sudo", "-n", KILLALL, "-HUP", "mDNSResponder"],
            timeout=8,
        )
        msgs.append(f"sudo killall mDNSResponder → rc={rc}")
        ok_any = rc == 0
    return {
        "ok": ok_any,
        "message": "DNS cache flushed" if ok_any else "partially failed (may need administrator privileges)",
        "detail": msgs,
    }


# ─── LaunchAgents (broader than timers) ──────────────────────────────────────

def _truthy(value) -> bool:
    """Guarded ``bool(...)``: a leftover ``__bool__``/``__len__`` bomb in a
    parsed plist value must degrade to False, never raise out of the
    launchd readers into a raw 500."""
    if isinstance(value, bool):
        return value
    try:
        return bool(value)
    except Exception:
        return False


def _plist_map(pl) -> dict | None:
    """Plain-dict copy of a parsed plist, or None.

    ``dict(subclass)`` copies through CPython's C-level storage, bypassing
    a leftover's overridden ``.get``/``items``/``keys`` (the host6 _as_map
    rule): a parser answer that is a dict *subclass* with a bombing bound
    ``.get`` passed the old ``isinstance(pl, dict)`` gate and raised out of
    the field reads — a raw 500 on GET /api/system/scheduler and
    GET /api/tools/agents.
    """
    if not isinstance(pl, dict):
        return None
    try:
        return dict(pl)
    except Exception:
        return None


def _args_text(args, cap: int) -> str:
    """ProgramArguments joined for display.  Never raises.

    Exact-list copy through the unbound base read (the top_processes rule):
    a leftover ProgramArguments that is a list *subclass* whose bound
    ``__iter__`` bombs passed the isinstance gate and blew the join —
    a raw 500 on both launchd views; the real elements sit readable in the
    C-level storage and survive.
    """
    if not isinstance(args, list):
        return ""
    try:
        items = list.__getitem__(args, slice(None))
    except Exception:
        return ""
    return " ".join(_as_text(a) for a in items)[:cap]


def _plist_int(raw):
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        try:
            # Base coercion to an exact int first: an int *subclass* whose
            # ``__int__``/``__index__`` bombs used to raise past the
            # enumerated catch below and 500 the launchd views.
            value = int.__index__(raw)
        except Exception:
            return None
    else:
        try:
            value = int(raw)
        except Exception:
            return None
    try:
        # ``int()`` of an int is not length-capped: XML plists load
        # ``<integer>0x…</integer>`` through ``int(raw, 16)``, which CPython's
        # 4300-digit conversion limit exempts, so an over-cap StartInterval
        # arrived here *already-int* and Starlette's json.dumps raised the
        # int->str digit-cap ValueError — 500ing GET /api/system/scheduler
        # and GET /api/tools/agents.  Probe with str(): unrenderable is
        # unusable.
        str(value)
    except ValueError:
        return None
    return value


def _plist_jsonable(value, depth: int = 0):
    """Drop inf/nan/``\\ud800`` so Starlette's allow_nan=False encoder cannot 500.

    Coercions run on the *base* types (the storage7 unbound rule): every
    bound dispatch here — ``value.items()``, iteration, ``value.decode``,
    the bare ``str()`` digit-cap probe — reflected into a leftover
    subclass's own override, and a calendar carrying an items()-bomb dict,
    an ``__iter__``-bomb list, a decode()-bomb bytes or an
    ``__index__``/``__str__``-bomb int answered a raw 500 on
    GET /api/system/scheduler where its plain-typed siblings rendered fine.
    """
    if depth > 8:
        return None
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # used to raise a non-ValueError past the digit-cap probe.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render the
            # number at all — a hex-plist calendar minute dodges the parse-time
            # cap (``int(raw, 16)``) and used to ValueError Starlette's own
            # json.dumps.  Same drop as its inf float sibling below.
            return None
        return value
    if isinstance(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float, matching the int arm.
                value = float.__float__(value)
            except Exception:
                return None
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, dict):
        # Unbound base view: ``dict.items`` reads the real C-level storage,
        # so the salvageable keys of an items()-bomb subclass survive.
        try:
            items = list(dict.items(value))
        except Exception:
            return None
        out = {}
        for k, v in items:
            out[_as_text(k)] = _plist_jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        if isinstance(value, list):
            base = list
        elif isinstance(value, tuple):
            base = tuple
        elif isinstance(value, set):
            base = set
        else:
            base = frozenset
        try:
            # Unbound base iteration (the ``dict.items`` rule at sequence
            # rank): a subclass whose bound ``__iter__`` raises drops to
            # None only when even the base storage refuses.
            items = list(base.__iter__(value))
        except Exception:
            return None
        return [_plist_jsonable(v, depth + 1) for v in items]
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a bytes subclass whose bound ``.decode``
        # bombs must not raise out of the sanitizer.
        base = bytes if isinstance(value, bytes) else bytearray
        return base.decode(value, "utf-8", "replace")[:200]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # A raising ``isoformat`` property used to blow the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/tools launchd.
            return _plist_jsonable(iso(), depth + 1)
        except Exception:
            return None
    return _as_text(value)[:200]


def launchd_timers() -> list:
    """List StartInterval / calendar agents for Scheduler-like view."""
    import plistlib

    try:
        agents = os.path.expanduser("~/Library/LaunchAgents")
    except (OSError, RuntimeError, ValueError, TypeError):
        # RuntimeError: leftover HOME unset; ValueError: leftover NUL in HOME.
        # GET /api/tools launchd timers used to 500.
        return []
    try:
        paths = sorted(glob.glob(f"{agents}/*.plist"))
    except OSError:
        return []
    items = []
    for path in paths:
        try:
            pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
        except Exception:
            continue
        # Laundered plain-dict copy, then plain reads: a dict-*subclass*
        # parser answer with a bombing bound ``.get`` used to raise out of
        # the field reads below and 500 GET /api/system/scheduler.
        pl = _plist_map(pl)
        if pl is None:
            continue
        label = pl.get("Label")
        # No bare ``or`` fallback: it dispatched into a leftover Label's own
        # ``__bool__``, and the bomb 500'd both launchd views.
        if not isinstance(label, str) or not label:
            label = Path(path).stem
        label = _as_text(label)
        interval = _plist_int(pl.get("StartInterval"))
        calendar = pl.get("StartCalendarInterval")
        if not interval and not _truthy(calendar):
            continue
        items.append({
            "label": label,
            "path": _as_text(path),
            "interval_sec": interval,
            "calendar": _plist_jsonable(calendar),
            "program": _args_text(pl.get("ProgramArguments"), 120),
        })
    return items


def launchd_agents_summary() -> dict:
    import plistlib

    try:
        agents_dir = Path(os.path.expanduser("~/Library/LaunchAgents"))
    except (OSError, RuntimeError, ValueError, TypeError):
        # RuntimeError: leftover HOME unset on GET /api/tools launchd agents.
        return {
            "count": 0,
            "agents": [],
            "dir": "",
            "hint": "User-level LaunchAgents · see the Scheduler page for timers",
        }
    items = []
    try:
        paths = sorted(agents_dir.glob("*.plist"))
    except OSError:
        paths = []
    for path in paths:
        try:
            pl = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
        except Exception:
            items.append({
                "label": _as_text(path.stem), "path": _as_text(path), "error": "parse",
            })
            continue
        # Laundered plain-dict copy + guarded bools: a dict-subclass parser
        # answer with a bombing ``.get``, or a ``__bool__``-bomb
        # RunAtLoad/KeepAlive/Disabled/calendar value, used to raise out of
        # these reads and 500 GET /api/tools/agents.
        pl = _plist_map(pl)
        if pl is None:
            items.append({
                "label": _as_text(path.stem), "path": _as_text(path), "error": "parse",
            })
            continue
        label = pl.get("Label")
        if not isinstance(label, str) or not label:
            label = path.stem
        run_at = _truthy(pl.get("RunAtLoad"))
        keep = pl.get("KeepAlive")
        interval = _plist_int(pl.get("StartInterval"))
        calendar = pl.get("StartCalendarInterval")
        disabled = _truthy(pl.get("Disabled"))
        items.append({
            "label": _as_text(label),
            "path": _as_text(path),
            "run_at_load": run_at,
            "keep_alive": _truthy(keep) if not isinstance(keep, dict) else True,
            "interval_sec": interval,
            "calendar": _truthy(calendar),
            "disabled": disabled,
            "program": _args_text(pl.get("ProgramArguments"), 100),
        })
    return {
        "count": len(items),
        "agents": items,
        "dir": _as_text(agents_dir),
        "hint": "User-level LaunchAgents · see the Scheduler page for timers",
    }


# ─── About ───────────────────────────────────────────────────────────────────

def about_info() -> dict:
    # The same tail as `diagnostics()` had, for the same two reads: `host_ip()` is a
    # route lookup then an `ipconfig`, and `platform.platform()` shells out twice more
    # on macOS.  Four spawns, three deep, to fill two fields of a static page.
    def probe_host_ip() -> str:
        try:
            return host_ip()
        except Exception:
            return ""

    def probe_platform() -> str:
        try:
            from hub.identity_svc import platform_string
            return platform_string()
        except Exception:
            return _as_text(platform.platform())

    ip, plat = fan_out(lambda probe: probe(), [probe_host_ip, probe_platform])
    return {
        "name": "ServerHub",
        "version": __version__,
        "tagline_key": "tools.about_tagline",
        # Scrubbed for the same reason as diagnostics(): the raw echo used
        # to 500 GET /api/tools/about on a leftover surrogate / over-cap int.
        "host_ip": _as_text(ip),
        "platform": _as_text(plat),
        "python": _as_text(platform.python_version()),
        # BASE derives from __file__; a checkout path with a leftover non-UTF-8
        # byte surfaces as a lone surrogate and 500'd GET /api/tools/about.
        "base": _as_text(BASE),
        "credit_keys": [
            "tools.credit_stack",
            "tools.credit_services",
        ],
        "links": [
            {"label_key": "nav.settings", "href": "/settings"},
            {"label_key": "nav.health", "href": "/health"},
            {"label_key": "nav.modules", "href": "/modules"},
            {"label_key": "nav.maintenance", "href": "/maintenance"},
        ],
        "github": github_update_status(fetch=False, checkout=True),
    }
