"""Cloudflare Tunnel (cloudflared) management for ServerHub web panel.

Allows login / create / start / stop / logs without Remote Desktop.
Uses a dedicated LaunchAgent (local.cloudflared-tunnel) with token file so the
broken bare `brew services cloudflared` (no args / no config) is avoided.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

from hub.errors import api_error
from hub.paths import AGENTS_DIR, BREW
from hub import secure_io
from hub.launchd_cache import invalidate_launchd
from hub.proc_cache import invalidate_processes, ps_lines
from hub.util import fan_out, sh

CF_BIN = "/opt/homebrew/bin/cloudflared"
if not Path(CF_BIN).is_file():
    CF_BIN = "/usr/local/bin/cloudflared"

CF_HOME = Path.home() / ".cloudflared"
CERT = CF_HOME / "cert.pem"
STATE_DIR = Path.home() / "Services" / "cloudflared"
STATE_FILE = STATE_DIR / "serverhub-state.json"
TOKEN_FILE = STATE_DIR / "tunnel.token"
LOG_FILE = STATE_DIR / "tunnel.log"
CONFIG_YML = CF_HOME / "config.yml"
LABEL = "local.cloudflared-tunnel"
PLIST = Path(AGENTS_DIR) / f"{LABEL}.plist"
LOGIN_PID = STATE_DIR / "login.pid"
LOGIN_LOG = STATE_DIR / "login.log"
LOGIN_URL_FILE = STATE_DIR / "login.url"


#: Cloudflare's documented tunnel edge range (198.41.192.0/20).  A subset is
#: pinned when DNS is untrustworthy — see _edge_workaround_args().
EDGE_NETWORK = "198.41.192.0/20"
FALLBACK_EDGE_IPS = (
    "198.41.192.7",
    "198.41.192.27",
    "198.41.200.13",
    "198.41.200.43",
)
EDGE_PORT = 7844


def _ip_in_edge_range(ip: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(EDGE_NETWORK)
    except ValueError:
        return False


def resolve_edge_ips() -> list[str]:
    """IPs the system resolver returns for the tunnel edge hostnames."""
    import socket

    out: list[str] = []
    for host in ("region1.v2.argotunnel.com", "region2.v2.argotunnel.com"):
        try:
            for info in socket.getaddrinfo(host, EDGE_PORT, socket.AF_INET,
                                           socket.SOCK_STREAM):
                addr = info[4][0]
                if addr not in out:
                    out.append(addr)
        except OSError:
            continue
    return out


def dns_diagnosis() -> dict:
    """Detect the DNS-hijack failure mode behind 'TLS handshake with edge: EOF'.

    A transparent proxy / fake-ip resolver (Clash, mihomo, some routers) answers
    ``*.argotunnel.com`` with an address outside Cloudflare's range.  TCP to that
    address connects — the proxy accepts it — but the proxy will not carry
    cloudflared's non-HTTP protocol, so the TLS handshake dies with EOF and the
    tunnel retries forever.  The symptom looks like a cloudflared bug; it is not.
    """
    resolved = resolve_edge_ips()
    bogus = [ip for ip in resolved if not _ip_in_edge_range(ip)]
    return {
        "resolved": resolved,
        "bogus": bogus,
        "hijacked": bool(resolved) and not any(_ip_in_edge_range(i) for i in resolved),
        "edge_network": EDGE_NETWORK,
    }


def _edge_workaround_args() -> list[str]:
    """Extra `tunnel run` args needed when DNS for the edge is hijacked.

    Two flags, both required, verified against a hijacked network:
      * ``--edge`` pins real edge addresses, bypassing the poisoned lookup.
        Without it cloudflared dials the fake IP and gets a TLS EOF.
      * ``--protocol http2`` moves off QUIC.  The same proxy also drops
        UDP/7844, so with ``--edge`` alone the handshake succeeds but every
        connection times out with "no recent network activity".
    On a healthy network this returns nothing, so normal installs keep
    Cloudflare's own edge selection and QUIC.
    """
    diag = dns_diagnosis()
    if not diag["hijacked"]:
        return []
    args: list[str] = []
    for ip in FALLBACK_EDGE_IPS:
        args += ["--edge", f"{ip}:{EDGE_PORT}"]
    args += ["--protocol", "http2"]
    return args


def _ensure_dirs() -> None:
    CF_HOME.mkdir(parents=True, exist_ok=True)
    try:
        CF_HOME.chmod(0o700)
    except OSError:
        pass
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        STATE_DIR.chmod(0o700)
    except OSError:
        pass


def _bin() -> str:
    if Path(CF_BIN).is_file():
        return CF_BIN
    w = sh(["/usr/bin/which", "cloudflared"], timeout=5)[1].strip()
    if w and Path(w).is_file():
        return w
    raise api_error("cloudflared.not_installed")


def _load_state() -> dict:
    _ensure_dirs()
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text() or "{}")
        except Exception:
            return {}
    return {}


def _save_state(data: dict) -> None:
    _ensure_dirs()
    # Created 0600 through the open() mode: write-then-chmod left the state
    # readable by every local user for the duration of the write.
    secure_io.write_secret_text(
        STATE_FILE, json.dumps(data, ensure_ascii=False, indent=2)
    )


def _logged_in() -> bool:
    return CERT.is_file() and CERT.stat().st_size > 20


def _read_login_pid() -> int | None:
    """Return the recorded login PID, discarding malformed/stale metadata."""
    if not LOGIN_PID.is_file():
        return None
    try:
        pid = int(LOGIN_PID.read_text().strip())
        if pid <= 1:
            raise ValueError("unsafe pid")
        return pid
    except (OSError, ValueError):
        LOGIN_PID.unlink(missing_ok=True)
        return None


def _wait_login_pid(pid: int, timeout: float) -> bool:
    """Wait up to *timeout* for a login process and reap it when it is ours.

    A PID file can survive a panel restart.  In that case the process is no
    longer our child and ``waitpid`` raises ``ChildProcessError``; poll it with
    signal 0 instead.  Direct children are always reaped here, which is the
    distinction between a stopped process and a zombie.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                return True
        except ChildProcessError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                return False

        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _login_process_pending() -> bool:
    """Whether the recorded login waiter is alive, reaping it if it exited."""
    pid = _read_login_pid()
    if pid is None:
        return False
    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            LOGIN_PID.unlink(missing_ok=True)
            return False
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        LOGIN_PID.unlink(missing_ok=True)
        return False


def _terminate_login_process(*, term_timeout: float = 2.0,
                             kill_timeout: float = 1.0) -> bool:
    """Stop and reap the login waiter recorded in ``LOGIN_PID``.

    ``cloudflared tunnel login`` is spawned directly by this panel, so sending
    a signal without ``waitpid`` leaves a zombie until ServerHub exits.  Give it
    a short graceful window, escalate to SIGKILL, and remove the PID file only
    after the process is confirmed gone.  No disk, tunnel, or certificate data
    is modified.
    """
    pid = _read_login_pid()
    if pid is None:
        return True

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        # It may already be an exited, waitable child.
        pass
    except (PermissionError, OSError):
        return False

    stopped = _wait_login_pid(pid, term_timeout)
    if not stopped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except (PermissionError, OSError):
            return False
        stopped = _wait_login_pid(pid, kill_timeout)

    if stopped:
        LOGIN_PID.unlink(missing_ok=True)
    return stopped


def _process_running() -> bool:
    # The shared table (hub/proc_cache.py), not this module's own `ps aux`: the Apps
    # page walks the native catalog -- which scans the same table for every app that
    # has no launchd label -- and then lands here for the tunnel, so one request read
    # the process table twice.  The match below stays local because it is not a plain
    # substring test; it distinguishes a real `tunnel run` from any stray cloudflared.
    for line in ps_lines():
        low = line.lower()
        if "cloudflared" not in low:
            continue
        if "tunnel run" in low or "tunnel --config" in low:
            return True
        # token-mode service often shows just cloudflared with token-file
        if "cloudflared" in low and ("token" in low or "config" in low) and "grep" not in low:
            return True
    return False


def _launchd_running() -> bool:
    uid = os.getuid()
    rc, out, _ = sh(["/bin/launchctl", "print", f"gui/{uid}/{LABEL}"], timeout=5)
    if rc == 0 and "state = running" in (out or ""):
        return True
    # brew agent (usually useless without config)
    rc2, out2, _ = sh(
        ["/bin/launchctl", "print", f"gui/{uid}/homebrew.mxcl.cloudflared"],
        timeout=5,
    )
    if rc2 == 0 and "state = running" in (out2 or ""):
        return True
    return False


def _is_running() -> bool:
    return _process_running() or _launchd_running()


#: Cached tunnel list.
#:
#: `cloudflared tunnel list` is a round trip to Cloudflare's API, and it was the
#: single most expensive thing in the Apps page payload at ~1.6s of its ~4.5s.
#: It had no cache at all, while the inventory around it caches for only 8s, so a
#: browser sitting on that page re-queried a remote service every few seconds --
#: and the 30s timeout meant an unreachable Cloudflare could hang the page for
#: half a minute.
#:
#: The account's tunnel list changes when an operator creates or deletes a tunnel,
#: which is minutes-to-days apart, not seconds. Five minutes is generous for
#: freshness and removes the remote dependency from the page path entirely; the
#: mutating paths below invalidate it so a newly created tunnel appears at once.
_TUNNELS_TTL = 300.0
_tunnels_cache: dict = {"t": 0.0, "v": None}
#: One lock, so a second reader arriving mid-request waits for that answer rather
#: than opening its own connection to Cloudflare.
_tunnels_lock = threading.Lock()


def invalidate_tunnels() -> None:
    """Drop the cached tunnel list after creating or deleting a tunnel."""
    with _tunnels_lock:
        _tunnels_cache.update(t=0.0, v=None)


def list_tunnels(force: bool = False) -> list[dict]:
    """Return tunnels from account (requires cert.pem)."""
    if not force:
        cached = _tunnels_cache["v"]
        if cached is not None and time.time() - _tunnels_cache["t"] < _TUNNELS_TTL:
            return list(cached)

    with _tunnels_lock:
        cached = _tunnels_cache["v"]
        if not force and cached is not None and time.time() - _tunnels_cache["t"] < _TUNNELS_TTL:
            return list(cached)
        result = _list_tunnels_uncached()
        if result is None:
            # Could not reach Cloudflare. Serve the previous answer if there is
            # one -- a stale tunnel list beats an empty page -- and do not cache
            # the failure. Treating "empty" as failure here was the first attempt
            # and it meant an account with no tunnels never cached at all, so the
            # remote call ran on every single poll.
            return list(cached) if cached is not None else []
        _tunnels_cache.update(t=time.time(), v=list(result))
        return result


def _list_tunnels_uncached() -> list[dict] | None:
    """Tunnels for the account, or None when the answer is unknown.

    The distinction matters for caching. "This account has no tunnels" is a real,
    cacheable answer; "cloudflared could not reach Cloudflare" is not, and caching
    it would hide every tunnel for the whole TTL.
    """
    if not _logged_in():
        # Not an error and not transient: without a cert there is nothing to list.
        return []
    # 10s, not 30: this sits on a page load, and a Cloudflare that has not
    # answered in ten seconds is not going to make the page useful.
    rc, out, err = sh([_bin(), "tunnel", "list"], timeout=10)
    if rc != 0:
        return None
    text = (out or "") + "\n" + (err or "")
    tunnels: list[dict] = []
    # ID NAME CREATED CONNECTIONS
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("You can") or line.startswith("ID "):
            continue
        # uuid name date... connections
        m = re.match(
            r"^([0-9a-f-]{36})\s+(\S+)\s+(\S+)\s*(.*)$",
            line,
            re.I,
        )
        if not m:
            continue
        rest = (m.group(4) or "").strip()
        tunnels.append({
            "id": m.group(1),
            "name": m.group(2),
            "created": m.group(3),
            "connections": rest,
            "active": bool(rest and rest not in ("", "-")),
        })
    return tunnels


def fetch_token(tunnel: str) -> str:
    """Fetch run token for named tunnel (requires cert.pem)."""
    tunnel = (tunnel or "").strip()
    if not tunnel:
        raise api_error("cloudflared.tunnel_required")
    if not _logged_in():
        raise api_error("cloudflared.not_logged_in")
    rc, out, err = sh([_bin(), "tunnel", "token", tunnel], timeout=45)
    token = (out or "").strip().splitlines()
    token = (token[-1] if token else "").strip()
    if rc != 0 or not token or len(token) < 40:
        raise api_error(
            "cloudflared.token_fetch_failed",
            error=(err or out or "unknown")[-500:],
        )
    return token


def _write_token(token: str) -> Path:
    _ensure_dirs()
    token = (token or "").strip()
    if len(token) < 40:
        raise api_error("cloudflared.invalid_token")
    # The tunnel token grants ingress to this LAN, so it must never exist with
    # default permissions, not even for the moment before a chmod.
    secure_io.write_secret_text(TOKEN_FILE, token + "\n")
    return TOKEN_FILE


def _write_launchagent_token() -> Path:
    """LaunchAgent: cloudflared tunnel run --token-file ..."""
    _ensure_dirs()
    if not TOKEN_FILE.is_file():
        raise api_error("cloudflared.no_token")
    bin_path = _bin()
    # Rendered one <string> per argv element, so the workaround flags land as
    # real separate arguments (launchd does no word splitting).
    #
    # Position matters: --edge / --protocol belong to the `tunnel` command, so
    # they must appear BEFORE the `run` subcommand.  Placed after it, cloudflared
    # exits immediately with "flag provided but not defined: -edge" and dumps its
    # help text into the log, which under KeepAlive becomes a silent respawn loop.
    extra = _edge_workaround_args()
    # Serialised with plistlib rather than an f-string template.  Hand-built XML
    # has to escape every interpolated value itself, and none of these were
    # escaped: a path or flag containing &, < or " produced either a corrupt
    # plist that launchd silently refuses, or -- given a value that ever becomes
    # attacker-influenced -- injected extra <string> elements into
    # ProgramArguments, which is arbitrary command execution at login.  plistlib
    # escapes correctly by construction, and it is already what every other
    # plist writer in this codebase uses (native_catalog, launcher_svc).
    payload = {
        "Label": LABEL,
        # Position matters: --edge / --protocol belong to the `tunnel` command, so
        # they must appear BEFORE the `run` subcommand.  Placed after it,
        # cloudflared exits immediately with "flag provided but not defined:
        # -edge" and dumps its help text into the log, which under KeepAlive
        # becomes a silent respawn loop.  One list element per argv element, so
        # launchd never word-splits them.
        "ProgramArguments": [
            str(bin_path),
            "tunnel",
            "--no-autoupdate",
            *[str(a) for a in extra],
            "run",
            "--token-file",
            str(TOKEN_FILE),
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(LOG_FILE),
        "StandardErrorPath": str(LOG_FILE),
        "WorkingDirectory": str(STATE_DIR),
        "EnvironmentVariables": {
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(Path.home()),
        },
    }
    PLIST.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False))
    return PLIST


def _forget_host_state() -> None:
    """Drop the shared launchd listing and process table after changing either.

    Both are cached briefly so that concurrent page readers share one spawn.  Every
    caller here mutates the state and then immediately reads it back to report what
    happened, which is exactly the case a TTL answers wrongly.
    """
    invalidate_launchd()
    invalidate_processes()


def _launchctl_bootout() -> None:
    uid = os.getuid()
    sh(["/bin/launchctl", "bootout", f"gui/{uid}/{LABEL}"], timeout=15)
    # also stop bare brew agent so it doesn't fight us
    sh(["/bin/launchctl", "bootout", f"gui/{uid}/homebrew.mxcl.cloudflared"], timeout=10)
    # BREW, not a literal: hub.paths resolves it through `which` and both standard
    # prefixes, so this still stops the agent on a host where Homebrew is not in
    # /opt/homebrew. With the literal the call just failed silently and the brew
    # agent kept competing with ours for the tunnel.
    sh([BREW, "services", "stop", "cloudflared"], timeout=30)
    _forget_host_state()


def _launchctl_bootstrap() -> dict:
    uid = os.getuid()
    _launchctl_bootout()
    time.sleep(0.4)
    if not PLIST.is_file():
        return {"ok": False, "message": f"Missing {PLIST}"}
    rc, out, err = sh(
        ["/bin/launchctl", "bootstrap", f"gui/{uid}", str(PLIST)],
        timeout=20,
    )
    # enable for future logins
    sh(["/bin/launchctl", "enable", f"gui/{uid}/{LABEL}"], timeout=10)
    sh(["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"], timeout=15)
    _forget_host_state()
    ok = rc == 0 or _is_running()
    msg = (out or "") + (err or "")
    running = False
    if ok:
        # wait briefly for process
        for _ in range(8):
            # The point of this loop is to observe a change, so each pass needs its
            # own reading.  The process table and the launchd listing are both cached
            # for a few seconds to collapse concurrent page readers, and a cached
            # answer here would mean polling the same pre-start snapshot eight times
            # and reporting a successful start as "check the log".
            _forget_host_state()
            running = _is_running()
            if running:
                break
            time.sleep(0.4)
    # One reading decides both fields.  They used to be two separate `_is_running()`
    # calls -- each a full process-table scan -- which could disagree with each other
    # and report ok=True alongside "start command issued, check the log".
    return {
        "ok": ok or running,
        "message": msg.strip() or ("Started" if running else "Start command issued; check the log"),
    }


def status() -> dict:
    """Panel snapshot for Cloudflared."""
    _ensure_dirs()
    st = _load_state()

    def _tunnels() -> tuple[list, str | None]:
        """The tunnel list, or the reason it could not be fetched.

        Absorbs its own failure so it can share a wave with the liveness check.
        """
        if not _logged_in():
            return [], None
        try:
            return list_tunnels(), None
        except Exception as e:
            return [], str(e)

    # The liveness check is local and the tunnel list is a round-trip to
    # Cloudflare; neither reads the other's answer, and this endpoint is polled, so
    # the page used to wait for a remote API call before it could say whether the
    # daemon is even up. `_logged_in` is a file check, so gating the fetch costs
    # nothing inside the worker.
    #
    # `_is_running` is left as it is: it short-circuits on `ps` before touching
    # launchctl, and `_launchd_running` tries its second label only when the first
    # misses. Fanning those out would add a spawn to the healthy path to save one on
    # the broken path.
    running, (tunnels, tunnels_err) = fan_out(
        lambda probe: probe(), [_is_running, _tunnels], max_workers=2
    )

    login_url = None
    if LOGIN_URL_FILE.is_file():
        try:
            login_url = LOGIN_URL_FILE.read_text().strip() or None
        except Exception:
            login_url = None
    # Reap a login child that exited between polls instead of retaining a zombie.
    login_pending = _login_process_pending()

    bin_path = None
    try:
        bin_path = _bin()
    except Exception:
        bin_path = None
    return {
        "ok": True,
        "installed": bool(bin_path and Path(bin_path).is_file()),
        "bin": bin_path,
        "logged_in": _logged_in(),
        "cert_path": str(CERT) if CERT.is_file() else None,
        "running": running,
        "state": "ok" if running else "down",
        "status_text": "Running" if running else "Stopped",
        "active_tunnel": st.get("tunnel_name") or st.get("tunnel_id"),
        "mode": st.get("mode") or ("token" if TOKEN_FILE.is_file() else None),
        "has_token": TOKEN_FILE.is_file(),
        "tunnels": tunnels,
        "tunnels_error": tunnels_err,
        "login_url": login_url if login_pending or not _logged_in() else None,
        "login_pending": login_pending,
        "plist": str(PLIST) if PLIST.is_file() else None,
        "log_path": str(LOG_FILE),
        "config_path": str(CONFIG_YML) if CONFIG_YML.is_file() else None,
        "notes": (
            "Pick an existing tunnel or paste a Zero Trust token to start/stop. "
            "Configure routes/subdomains in the Cloudflare Zero Trust dashboard "
            "(recommended); no Remote Desktop needed."
        ),
    }


def login_start() -> dict:
    """Start `cloudflared tunnel login` and return the browser URL for the user."""
    if _logged_in():
        return {
            "ok": True,
            "already": True,
            "message": f"Already logged in ({CERT})",
            "logged_in": True,
        }
    _ensure_dirs()
    # Stop and reap the previous direct child before replacing its PID file.
    if not _terminate_login_process():
        return {
            "ok": False,
            "message": "Could not stop the previous login process; try again later",
            "logged_in": False,
            "login_pending": True,
        }
    LOGIN_URL_FILE.unlink(missing_ok=True)
    LOGIN_LOG.write_text("")
    # Run login; cloudflared prints a URL then waits for callback
    proc = subprocess.Popen(
        [_bin(), "tunnel", "login"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(CF_HOME),
        env={**os.environ, "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "HOME": str(Path.home())},
    )
    LOGIN_PID.write_text(str(proc.pid))
    url = None
    # read up to ~8s for URL line
    deadline = time.time() + 12
    buf = ""
    assert proc.stdout is not None
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.15)
            continue
        buf += line
        LOGIN_LOG.write_text(buf[-8000:])
        m = re.search(r"https://[^\s]+", line)
        if m:
            url = m.group(0).rstrip(").,]")
            LOGIN_URL_FILE.write_text(url)
            break
    if not url and buf:
        m2 = re.search(r"https://[^\s]+", buf)
        if m2:
            url = m2.group(0).rstrip(").,]")
            LOGIN_URL_FILE.write_text(url)
    if not url:
        # still running? keep process
        if proc.poll() is None:
            return {
                "ok": False,
                "message": "Login process started but no URL was found; check the login log or run cloudflared tunnel login in a local browser session",
                "login_pending": True,
                "log": buf[-1500:],
            }
        return {"ok": False, "message": "Login failed\n" + buf[-1500:]}
    return {
        "ok": True,
        "message": "Open the link below in a browser and authorize with your Cloudflare account (a phone or another computer works too)",
        "login_url": url,
        "login_pending": True,
        "logged_in": False,
    }


def login_poll() -> dict:
    """Check if cert.pem appeared after login_start."""
    if _logged_in():
        # A successful callback leaves the directly-spawned login waiter alive;
        # stop and reap it rather than only sending a signal and leaking a zombie.
        stopped = _terminate_login_process()
        LOGIN_URL_FILE.unlink(missing_ok=True)
        return {
            "ok": stopped,
            "logged_in": True,
            "message": "Login successful" if stopped else "Login successful, but cleaning up the login process failed; try again later",
        }
    url = LOGIN_URL_FILE.read_text().strip() if LOGIN_URL_FILE.is_file() else None
    return {
        "ok": True,
        "logged_in": False,
        "login_pending": _login_process_pending(),
        "login_url": url,
        "message": "Waiting for the browser to finish authorization…",
    }


def create_tunnel(name: str) -> dict:
    name = re.sub(r"[^a-zA-Z0-9._-]", "", (name or "").strip())
    if not name:
        raise api_error("cloudflared.invalid_name")
    if not _logged_in():
        raise api_error("cloudflared.login_required")
    rc, out, err = sh([_bin(), "tunnel", "create", name], timeout=60)
    # The account list just changed; do not let the page show the old one.
    invalidate_tunnels()
    ok = rc == 0
    msg = ((out or "") + "\n" + (err or "")).strip()
    tunnels = list_tunnels() if ok or _logged_in() else []
    return {"ok": ok, "message": msg[-2000:], "tunnels": tunnels}


def start_with_tunnel(tunnel: str) -> dict:
    """Fetch token for tunnel name/uuid and start LaunchAgent."""
    tunnel = (tunnel or "").strip()
    token = fetch_token(tunnel)
    _write_token(token)
    _write_launchagent_token()
    r = _launchctl_bootstrap()
    st = _load_state()
    st.update({"mode": "token", "tunnel_name": tunnel, "updated": time.time()})
    _save_state(st)
    return {
        "ok": r.get("ok") or _is_running(),
        "message": f"Tunnel \"{tunnel}\" configured and started\n" + (r.get("message") or ""),
        "running": _is_running(),
        "active_tunnel": tunnel,
    }


def start_with_token(token: str, label: str | None = None) -> dict:
    """Start using a pasted Zero Trust token."""
    _write_token(token)
    _write_launchagent_token()
    r = _launchctl_bootstrap()
    st = _load_state()
    st.update({
        "mode": "token",
        "tunnel_name": (label or "").strip() or "token",
        "updated": time.time(),
    })
    _save_state(st)
    return {
        "ok": r.get("ok") or _is_running(),
        "message": "Tunnel started with the token\n" + (r.get("message") or ""),
        "running": _is_running(),
    }


def stop() -> dict:
    _launchctl_bootout()
    # kill leftover tunnel processes (not ddns scripts)
    rc, out, _ = sh(["/bin/ps", "axo", "pid=,command="], timeout=5)
    if rc == 0 and out:
        for line in out.splitlines():
            low = line.lower()
            if "cloudflared" in low and ("tunnel" in low or "token" in low):
                try:
                    pid = int(line.strip().split(None, 1)[0])
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
    time.sleep(0.5)
    return {
        "ok": not _is_running(),
        "message": "Stopped" if not _is_running() else "Stop signal sent; the process may still be exiting",
        "running": _is_running(),
    }


def restart() -> dict:
    st = _load_state()
    name = st.get("tunnel_name")
    if TOKEN_FILE.is_file():
        _write_launchagent_token()
        r = _launchctl_bootstrap()
        return {
            "ok": r.get("ok") or _is_running(),
            "message": "Restarted\n" + (r.get("message") or ""),
            "running": _is_running(),
            "active_tunnel": name,
        }
    if name and _logged_in():
        return start_with_tunnel(name)
    return {"ok": False, "message": "Nothing to restart: pick a tunnel or paste a token and start it first"}


def route_dns(tunnel: str, hostname: str) -> dict:
    """cloudflared tunnel route dns <tunnel> <hostname>"""
    tunnel = (tunnel or "").strip()
    hostname = (hostname or "").strip().lower()
    if not tunnel or not hostname:
        raise api_error("cloudflared.route_args_required")
    if not _logged_in():
        raise api_error("cloudflared.login_required")
    rc, out, err = sh(
        [_bin(), "tunnel", "route", "dns", tunnel, hostname],
        timeout=60,
    )
    msg = ((out or "") + "\n" + (err or "")).strip()
    return {"ok": rc == 0, "message": msg[-2000:]}


def logs(lines: int = 120) -> dict:
    lines = max(20, min(int(lines or 120), 500))
    chunks: list[str] = []
    for p in (LOG_FILE, Path("/opt/homebrew/var/log/cloudflared.log"), LOGIN_LOG):
        if p.is_file():
            try:
                text = p.read_text(errors="replace")
                tail = "\n".join(text.splitlines()[-lines:])
                chunks.append(f"===== {p} =====\n{tail}")
            except Exception as e:
                chunks.append(f"===== {p} =====\n(read error: {e})")
    if not chunks:
        return {"ok": True, "log": "No logs yet (the tunnel writes to ~/Services/cloudflared/tunnel.log once started)"}
    return {"ok": True, "log": "\n\n".join(chunks), "source": "cloudflared"}


def uninstall_service() -> dict:
    """Stop agent and remove ServerHub-managed plist/token (keep cert & brew)."""
    stop()
    login_stopped = _terminate_login_process()
    removed = []
    for p in (PLIST, TOKEN_FILE, LOGIN_URL_FILE):
        try:
            if p.is_file():
                p.unlink()
                removed.append(str(p))
        except Exception:
            pass
    st = _load_state()
    st.pop("tunnel_name", None)
    st.pop("mode", None)
    _save_state(st)
    message = "Stopped and removed the panel-managed tunnel service\n" + "\n".join(removed)
    if not login_stopped:
        message += "\nLogin process cleanup failed; the PID record was kept for a later retry"
    return {"ok": login_stopped, "message": message}
