"""Fix Common Problems style health checks (Unraid plugin inspiration)."""
from __future__ import annotations

import os
import shutil
import threading
import time

from hub.docker_cli import engine_up
from hub.launchd_cache import running_labels as launchd_running_labels
from hub.nginx_svc import overview as nginx_overview, test_config as nginx_test
from hub.paths import SMARTCTL
from hub.util import fan_out, port_open, sh
from hub.brew_cache import brew_services_list
from pathlib import Path

_cache = {"t": 0.0, "v": None}
_TTL = 45.0
#: One lock, not per-key: there is a single snapshot, so a reader arriving mid-collection
#: should wait for that result rather than starting a second seven-way fan-out.
_refresh_lock = threading.Lock()


def _check(id_: str, name: str, level: str, ok: bool, detail: str, fix: str = "") -> dict:
    return {
        "id": id_,
        "name": name,
        "level": level if not ok else "ok",  # ok | warn | error
        "ok": ok,
        "detail": detail,
        "fix": fix,
    }


def _probe_port(port) -> bool | None:
    """Port reachability that never raises, for use inside the pool."""
    try:
        return port_open(port)
    except Exception:
        return False


#: Ports whose reachability is reported, in the order the page renders them.
_KEY_PORTS = (
    (8086, "ServerHub panel :8086", "launchctl kickstart local.serverhub.panel"),
    (8123, "Home Assistant :8123", "Check com.homeassistant.core"),
    (8281, "Nginx HTTPS :8281", "Check system Nginx / certificates"),
)


def _engine_up() -> bool:
    try:
        return bool(engine_up())
    except Exception:
        return False


def _nginx_pair() -> list[dict]:
    """Both nginx checks -- or the single combined failure the page has always shown.

    One try/except spanning both calls is deliberate rather than sloppy: when nginx
    is not installed at all, `nginx_overview()` raises and the page shows one
    "System Nginx" error instead of that plus a second, redundant config-syntax
    failure. Returning the checks as a list preserves that all-or-one behaviour now
    that the pair runs inside a worker, where an escaping exception would cost the
    entire batch.
    """
    try:
        ngx = nginx_overview()
        ok = bool(ngx.get("running"))
        pair = [_check(
            "nginx", "System Nginx gateway",
            "error", ok,
            f"running pid={ngx.get('pid')} · sites {ngx.get('site_count')}" if ok else "not running",
            "launchctl kickstart -k gui/$(id -u)/local.system-nginx" if not ok else "",
        )]
        t = nginx_test()
        pair.append(_check(
            "nginx_conf", "Nginx config syntax",
            "error", t.get("ok"),
            (t.get("message") or "")[:160],
            "Check ~/Services/nginx/conf.d/" if not t.get("ok") else "",
        ))
        return pair
    except Exception as e:
        return [_check(
            "nginx", "System Nginx", "error", False, str(e),
            "Check LaunchAgent local.system-nginx",
        )]


def _port_checks() -> list[dict]:
    """Reachability for every key port, probed together.

    Each connect waits out its full timeout when nothing is listening, so three
    dead ports charged the health page that wait three times in a row.
    """
    return [
        _check(
            f"port_{port}", name,
            "warn", up,
            "port reachable" if up else "port not responding",
            fix if not up else "",
        )
        for (port, name, fix), up in zip(
            _KEY_PORTS, fan_out(_probe_port, [port for port, _, _ in _KEY_PORTS])
        )
    ]


def _running_labels() -> frozenset[str]:
    """Labels with a live PID, from one `launchctl list` for the whole function.

    This replaced per-service `launchctl` probes in the brew loop below: a label with
    a PID in column one is running, which is exactly what those probes asked.

    The listing now comes from :mod:`hub.launchd_cache`, shared with the Immich
    checks in the same fan-out and with nginx's own probe.  All three ran their own
    -- two of them spelled ``launchctl`` and one ``/bin/launchctl``, which is why
    grouping spawns by argv only ever showed one of the two duplicates -- so this
    endpoint read the same session listing three times.

    The local parse also had a bug worth recording: it accepted any first column
    that was not ``-`` or empty, and the header row's first column is ``PID``, so
    the literal string ``Label`` was reported as a running job.  Harmless only
    because nothing is called that.
    """
    return launchd_running_labels()


def _brew_snapshot() -> list:
    """brew service states, or an empty list.

    Failure is swallowed here rather than propagated because this now runs in a
    worker, where a raise would discard every other probe in the batch instead of
    just this one; the page then renders without the brew rows.
    """
    try:
        return brew_services_list() or []
    except Exception:
        return []


def _smart_checks() -> list[dict]:
    """System-disk SMART health, empty when smartctl is unavailable.

    SMARTCTL, not a literal /opt/homebrew path: the sudoers policy grants the
    root-owned copy under /usr/local/libexec/serverhub (Homebrew's prefix is
    writable by the panel's own account, so granting it would be passwordless
    root).  A hardcoded Homebrew path here matches no rule, so this probe would
    ask for a password nobody can type and the health card would go blank.
    """
    rc, out, _ = sh(["sudo", "-n", SMARTCTL, "-H", "/dev/disk0"], timeout=10)
    if rc in (0, 4) and out:
        ok = "PASSED" in out.upper() or "OK" in out.upper()
        return [_check(
            "smart_disk0", "System disk SMART",
            "error", ok,
            out.strip().splitlines()[-1][:120] if out.strip() else "unknown",
            "Back up your data and check the disk" if not ok else "",
        )]
    return []


def _immich_checks() -> list[dict]:
    """Immich hybrid stack (containers + native worker + native ML + PG18).

    Kept in its own module because `docker ps` says nothing about the native
    halves: the worker and ML service run outside Docker, and a green
    immich_server tells you the web UI is up while thumbnails, transcode and
    face recognition are all silently dead.
    """
    try:
        from hub import immich_svc

        return list(immich_svc.run_checks().get("checks") or [])
    except Exception as e:
        return [_check(
            "immich", "Immich hybrid stack check", "warn", False, f"check failed: {e}"[:160],
            "See hub/immich_svc.py",
        )]


def _time_machine_checks() -> list[dict]:
    """A Time Machine share is only a backup target while smbd is running.

    The share-point flag survives File Sharing being switched off, and client
    Macs then fail their backups silently — the panel row still looks
    configured.  Nothing is reported when no share carries the flag: this is a
    prerequisite check, not a feature advertisement.
    """
    try:
        from hub import shares_svc

        flagged = [
            name
            for name, info in shares_svc.time_machine_records().items()
            if info.get("time_machine")
        ]
        if not flagged:
            return []
        up = shares_svc.smb_service_running()
        return [_check(
            "tm_share_smb", "Time Machine share reachable",
            "warn", up,
            f"{len(flagged)} Time Machine share(s); SMB "
            + ("listening on :445" if up else "service not running"),
            "Turn on File Sharing in System Settings so client Macs can reach "
            "the backup share" if not up else "",
        )]
    except Exception as e:
        return [_check(
            "tm_share_smb", "Time Machine share check", "warn", False,
            f"check failed: {e}"[:160], "See hub/shares_svc.py",
        )]


def _wireguard_checks() -> list[dict]:
    """WireGuard tunnel liveness + boot daemon integrity.

    wg-quick is not a daemon: once it has configured the interface, nothing is
    left running, so a wireguard-go crash (or a reboot with a defective boot
    job) kills the tunnel silently.  That exact failure went unnoticed here for
    two days because no check watched it — remote clients just stopped
    connecting while every other light stayed green.

    Both probes are passwordless: `wg show` goes through the pinned sudoers
    rule, and daemon_state() only reads the plist and `launchctl print`.
    """
    try:
        from hub import wireguard_net_svc, wireguard_svc

        if not wireguard_svc.installation().get("installed"):
            return []  # wireguard-tools absent — feature unused on this host
        interface = wireguard_svc.settings().get("interface") or "wg0"
        if not wireguard_svc.conf_path(interface).exists():
            return []  # no tunnel configured — nothing to watch
        checks = []

        device, _rows, error = wireguard_svc.live_interface(interface)
        up = bool(device) and not error
        checks.append(_check(
            "wg_tunnel", "WireGuard tunnel",
            "error", up,
            f"running on {device}" if up else (error or "not running"),
            "Start it from the WireGuard page — and fix the boot daemon below "
            "or it will die again" if not up else "",
        ))

        daemon = wireguard_net_svc.daemon_state()
        healthy = bool(daemon.get("healthy"))
        defects = ", ".join(daemon.get("defects") or [])
        checks.append(_check(
            "wg_daemon", "WireGuard boot daemon",
            "warn", healthy,
            "supervised (KeepAlive) and managed" if healthy
            else (f"defective: {defects}" if defects else "not installed"),
            "Use the fix action on the WireGuard page (admin password), or run "
            "deploy/repair-wireguard.sh" if not healthy else "",
        ))
        return checks
    except Exception as e:
        return [_check(
            "wg_check", "WireGuard check", "warn", False,
            f"check failed: {e}"[:160], "See hub/wireguard_net_svc.py",
        )]


def _worker_checks() -> list[dict]:
    """Liveness of the long-lived worker threads (hub/worker_health.py).

    A dead sampler/alerter/scheduler thread is otherwise invisible: the panel
    keeps serving requests while alerts stop firing and metrics stop
    recording, which is precisely the failure an operator opens this page to
    rule out.  Pure in-memory read — no subprocess, no lock held while slow —
    so it runs outside the fan-out and can never be the slow row.  No row is
    emitted before any worker has registered (unit-test apps built without
    the lifespan), so existing payload consumers see no change there.
    """
    try:
        from hub import worker_health

        registered = worker_health.snapshot()
        if not registered:
            return []
        dead = worker_health.problems()
        return [_check(
            "workers", "Panel background workers",
            "error", not dead,
            f"{len(registered)} worker threads ticking" if not dead
            else "; ".join(dead)[:160],
            "Restart the ServerHub panel LaunchAgent (launchctl kickstart)"
            if dead else "",
        )]
    except Exception:
        return []


def run_checks(force: bool = False) -> dict:
    """Cached health snapshot, collected once however many readers ask at once.

    The TTL alone was not enough.  This check reads the cache, and the collection
    below is a seven-way fan-out that shells out to `sudo smartctl`, `launchctl`,
    brew and the Immich stack -- so every reader that arrived during a cold window
    ran the whole thing.  The health card, the dashboard and the diagnostics bundle
    all want this, and the panel and menu-bar client both poll: measured with four
    concurrent cold readers, four `launchctl list` and four `sudo -n smartctl` where
    one of each would have served all of them.

    Same double-checked shape as brew_cache and docker_cli, rather than `ttl_memo`,
    because `_cache` is inspected directly by tests that predate this.
    """
    if not force and _cache["v"] and time.time() - _cache["t"] < _TTL:
        return _cache["v"]
    with _refresh_lock:
        # Re-check under the lock: another reader may have finished the same
        # collection while this one waited, which is what makes this single-flight.
        if not force and _cache["v"] and time.time() - _cache["t"] < _TTL:
            return _cache["v"]
        return _collect_checks()


def _collect_checks() -> dict:
    checks = []

    # Disk space root
    du = shutil.disk_usage("/")
    pct = du.used / du.total * 100
    checks.append(_check(
        "disk_root", "System disk space",
        "error" if pct >= 95 else "warn",
        pct < 90,
        f"used {pct:.0f}% ({du.used//2**30}/{du.total//2**30} GB)",
        "Clean up large files / Docker images, or expand storage" if pct >= 90 else "",
    ))

    # Every remaining probe in one wave.
    #
    # These ask unrelated questions of unrelated subsystems -- the container engine,
    # nginx, three TCP ports, launchd, brew, smartctl and the Immich stack -- and none
    # of them reads another's answer, yet the page used to wait out their sum. The
    # slow ones are also the ones most likely to be slow together on a sick host,
    # which is exactly when this page gets opened.
    #
    # Order is restored below, not taken from completion: `fan_out` returns results in
    # submission order, and each probe returns its checks already assembled, so the
    # rendered sequence is identical to when this ran top to bottom.
    eng, nginx_checks, port_checks, running_labels, brew_states, smart, immich, wg, tm = fan_out(
        lambda probe: probe(),
        [
            _engine_up,
            _nginx_pair,
            _port_checks,
            _running_labels,
            _brew_snapshot,
            _smart_checks,
            _immich_checks,
            _wireguard_checks,
            _time_machine_checks,
        ],
        max_workers=9,
    )

    # OrbStack / docker
    checks.append(_check(
        "orbstack", "OrbStack / Docker engine",
        "error", eng,
        "engine running" if eng else "engine not running",
        "Start OrbStack from the Services page, or open -a OrbStack" if not eng else "",
    ))

    # nginx system
    checks.extend(nginx_checks)

    # key ports
    checks.extend(port_checks)

    # brew critical
    if brew_states:
        try:
            for s in brew_states:
                n = s.get("name") or ""
                # postgresql@18 is a *separate* cluster (:5433) holding the
                # Immich database; @17 (:5432) holds TeslaMate.  Checking only
                # @17 reports "database fine" while Immich's DB is down.
                if n not in ("postgresql@17", "postgresql@18", "mosquitto", "grafana"):
                    continue
                st = (s.get("status") or "").lower()
                ok = st in ("started", "running")
                if not ok and st in ("none", ""):
                    # 未经 brew services 纳管但由 LaunchAgent 直接加载时 brew 显示 none，
                    # 需回查 launchctl 实际运行状态，避免误报。用上面那份全量列表，
                    # 不再为每个服务单独开一个子进程。
                    if f"homebrew.mxcl.{n}" in running_labels:
                        ok, st = True, "running (launchd)"
                checks.append(_check(
                    f"brew_{n}", f"Homebrew {n}",
                    "error" if n.startswith("postgres") else "warn",
                    ok,
                    st or "unknown",
                    f"brew services start {n}" if not ok else "",
                ))
        except Exception:
            pass

    # LaunchAgents with KeepAlive that are not running.
    # running_labels was built once at the top of this function.
    import glob, plistlib
    agents = Path.home() / "Library/LaunchAgents"
    for path in glob.glob(str(agents / "*.plist")):
        try:
            with open(path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        label = pl.get("Label") or Path(path).stem
        if not pl.get("KeepAlive"):
            continue
        if pl.get("StartInterval") or pl.get("StartCalendarInterval"):
            continue
        ok = label in running_labels
        if not ok:
            checks.append(_check(
                f"la_{label}", f"KeepAlive not running: {label}",
                "warn", False,
                "LaunchAgent has KeepAlive configured but is not running",
                f"launchctl kickstart -k gui/$(id -u)/{label}",
            ))

    # SMART quick (cached style) — probed in the wave above.
    checks.extend(smart)

    # Time Machine / backup dir writable
    bdir = Path.home() / "Services" / "backups"
    try:
        bdir.mkdir(parents=True, exist_ok=True)
        ok = os.access(bdir, os.W_OK)
    except Exception:
        ok = False
    checks.append(_check(
        "backup_dir", "Backup directory writable",
        "warn", ok,
        str(bdir),
        "Check ~/Services/backups permissions" if not ok else "",
    ))

    # Immich hybrid stack — probed in the wave above.
    checks.extend(immich)

    # WireGuard tunnel + boot daemon — probed in the wave above.
    checks.extend(wg)

    # Time Machine share prerequisites — probed in the wave above.
    checks.extend(tm)

    # Worker-thread liveness — in-memory, deliberately outside the fan-out.
    checks.extend(_worker_checks())

    errors = sum(1 for c in checks if not c["ok"] and c["level"] == "error")
    warns = sum(1 for c in checks if not c["ok"] and c["level"] == "warn")
    oks = sum(1 for c in checks if c["ok"])
    v = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"ok": oks, "warn": warns, "error": errors, "total": len(checks)},
        "checks": checks,
        "healthy": errors == 0,
    }
    _cache.update(t=time.time(), v=v)
    return v
