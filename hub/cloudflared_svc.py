"""Cloudflare Tunnel (cloudflared) management for ServerHub web panel.

Allows login / create / start / stop / logs without Remote Desktop.
Uses a dedicated LaunchAgent (local.cloudflared-tunnel) with token file so the
broken bare `brew services cloudflared` (no args / no config) is avoided.
"""
from __future__ import annotations

import base64
import json
import os
import plistlib
import re
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path

from hub import cli_args, secure_io
from hub.errors import api_error
from hub.paths import AGENTS_DIR, BREW, user_home
from hub.launchd_cache import invalidate_launchd
from hub.proc_cache import invalidate_processes, ps_lines, ps_pid_commands
from hub.util import fan_out, read_text_capped, safe_json_loads, sh, tail_file_lines, utf8_env

def _probe_cf_bin() -> str:
    """First cloudflared path that is readable.  ``is_file`` EIO used to 500 import."""
    preferred = "/opt/homebrew/bin/cloudflared"
    try:
        if Path(preferred).is_file():
            return preferred
    except (OSError, ValueError, TypeError):
        pass
    return "/usr/local/bin/cloudflared"


def _home_dir() -> Path:
    """Best-effort HOME.  ``Path.home()`` leftover used to 500 import."""
    return user_home() or Path("/var/empty/serverhub-cloudflared")


CF_BIN = _probe_cf_bin()
_HOME = _home_dir()
CF_HOME = _HOME / ".cloudflared"
CERT = CF_HOME / "cert.pem"
STATE_DIR = _HOME / "Services" / "cloudflared"
STATE_FILE = STATE_DIR / "serverhub-state.json"
#: Leftover multi-MB serverhub-state.json used to OOM GET /api/cloudflared/status.
_STATE_CAP = 256 * 1024
#: Leftover huge ``tunnel login`` stdout line used to RSS-bomb POST /login.
_LOGIN_LINE_CAP = 4096
TOKEN_FILE = STATE_DIR / "tunnel.token"
LOG_FILE = STATE_DIR / "tunnel.log"
CONFIG_YML = CF_HOME / "config.yml"
LABEL = "local.cloudflared-tunnel"
PLIST = Path(AGENTS_DIR) / f"{LABEL}.plist"
LOGIN_PID = STATE_DIR / "login.pid"
LOGIN_LOG = STATE_DIR / "login.log"
LOGIN_URL_FILE = STATE_DIR / "login.url"
#: Held so login_start can close the text pipes.  Discarding the Popen
#: after reading the URL left an unclosed TextIOWrapper (ResourceWarning
#: in the suite, leaked fd in the panel until GC).
_login_proc: subprocess.Popen | None = None


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` so cloudflared JSON cannot UTF-8 500."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
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


#: Cloudflare connector tokens always start with ``eyJ`` (base64 of ``{"``).
#: The Zero Trust dashboard pastes a three-segment JWT; ``cloudflared tunnel
#: token`` returns a single-segment JSON blob ``{"a","s","t"}``.  A 40-character
#: placeholder still passed the old ``len < 40`` gate; KeepAlive then respawned
#: forever on "Provided Tunnel token is not valid."
_TOKEN_MIN = 80
_TOKEN_FILE_CAP = 8192
_TOKEN_B64_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_TOKEN_JWT_RE = re.compile(
    r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)


def _normalize_token(token) -> str:
    return _as_text(token).strip().strip("\"'")


def _compact_token_payload(text: str) -> dict | None:
    """Decode a one-segment ``{"a","s","t"}`` connector token, or None."""
    if not text.startswith("eyJ") or not _TOKEN_B64_RE.fullmatch(text):
        return None
    try:
        raw = text + "=" * (-len(text) % 4)
        data = base64.urlsafe_b64decode(raw.encode("ascii"))
        obj = safe_json_loads(data)
    except (ValueError, TypeError, RecursionError, OverflowError):
        return None
    if not isinstance(obj, dict):
        return None
    account, tunnel = obj.get("a"), obj.get("t")
    if not isinstance(account, str) or not isinstance(tunnel, str):
        return None
    if len(account) < 8 or len(tunnel) < 8:
        return None
    return obj


def token_looks_valid(token) -> bool:
    """True when *token* is a Cloudflare connector JWT or compact token."""
    text = _normalize_token(token)
    if len(text) < _TOKEN_MIN:
        return False
    if _TOKEN_JWT_RE.fullmatch(text):
        return True
    return _compact_token_payload(text) is not None


def _read_saved_token() -> str:
    if not _path_is_file(TOKEN_FILE):
        return ""
    try:
        return _normalize_token(read_text_capped(TOKEN_FILE, _TOKEN_FILE_CAP))
    except (OSError, ValueError, TypeError):
        return ""


def _path_is_file(path: Path) -> bool:
    """``Path.is_file()`` raises on EACCES/EIO; a dying mount used to 500 status/logs."""
    try:
        return path.is_file()
    except (OSError, ValueError, TypeError):
        return False


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except (OSError, ValueError, TypeError):
        return False


#: login.url holds one short https URL; anything longer is junk.
_LOGIN_URL_CAP = 4096


def _read_login_url() -> str | None:
    """Login URL from ``LOGIN_URL_FILE`` without ever blocking the request.

    ``open()`` of a FIFO planted at login.url parks the caller until a writer
    appears, and ``read()`` parks it while the writer stays silent, so a swap
    between the ``is_file`` check and the open hung GET /api/cloudflared/status
    (and login poll) forever.  ``O_NONBLOCK`` makes the FIFO open return at
    once, ``fstat`` rejects anything that is not a regular file, ``O_NOFOLLOW``
    refuses a planted symlink, and the read itself is capped.
    """
    if not _path_is_file(LOGIN_URL_FILE):
        return None
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(LOGIN_URL_FILE), flags)
    except (OSError, ValueError, TypeError):
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, _LOGIN_URL_CAP)
    except OSError:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return data.decode("utf-8", "replace").strip() or None


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
        except (OSError, UnicodeError, ValueError):
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
    for path in (CF_HOME, STATE_DIR):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            # A file occupying ~/.cloudflared used to FileExistsError and
            # 500 GET /api/cloudflared/status on every poll.
            continue
        try:
            path.chmod(0o700)
        except OSError:
            pass


def _bin() -> str:
    if _path_is_file(Path(CF_BIN)):
        return CF_BIN
    w = _as_text(sh(["/usr/bin/which", "cloudflared"], timeout=5)[1]).strip()
    if w and _path_is_file(Path(w)):
        return w
    raise api_error("cloudflared.not_installed")


def _cli_vanished(rc, err, binary) -> bool:
    """Whether an ``sh()`` result means cloudflared itself vanished mid-request.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` — a
    sentinel, never a real cloudflared exit.  ``_bin()`` probes before the
    spawn, so an uninstall in between used to answer POST /token as a 400
    blaming the pasted token and POST /create / /route-dns as an uncoded
    ``{ok: false, message: "not found"}`` the SPA cannot map, instead of the
    same coded 503 the up-front probe raises.  A timeout keeps its own
    sentinel and is deliberately not classified: a slow CLI is not a missing
    one.  rc -1 is also what a signal-killed run reports, so the disk
    re-check confirms the binary is actually gone before classifying — a
    *still-present* cloudflared that printed exactly ``not found`` and died
    keeps its raw result.  The re-check runs only on this failure path.
    """
    if rc != -1 or _as_text(err).strip() != "not found":
        return False
    return not _path_is_file(Path(_as_text(binary)))


def _jsonable_state(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Infinity in serverhub-state.json was already dropped; leftover
    ``name: 2026-08-19`` / ``!!binary`` / ``!!set`` still leaked
    ``datetime.date`` / bytes / set into GET /api/cloudflared/status
    (``active_tunnel`` / ``mode``) because this walker returned them as-is.
    """
    if depth > 16:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Over the int→str digit cap (sys.get_int_max_str_digits):
            # json.dumps of such a leftover ValueError'd, which silently
            # dropped the whole _save_state write and would 500 any
            # encoder the value reached.  Drop it like non-finite floats.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, (bytes, bytearray)):
                k = k.decode("utf-8", "replace")
            elif not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            # Leftover ``\\ud800`` keys used to 500 GET /api/cloudflared/status.
            k = k.encode("utf-8", "replace").decode("utf-8")
            out[k] = _jsonable_state(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable_state(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/cloudflared/status.
            return _jsonable_state(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _as_text(value)
    except Exception:
        return None


def _json_int(digits: str) -> int | None:
    """``json.loads`` int hook: null the one number the encoder cannot hold.

    Past CPython's ~4300-digit int<->str cap the decoder's own ``int()``
    conversion raises *bare ValueError* — not JSONDecodeError — and the
    except-ValueError fallback in :func:`_load_state` read that as a corrupt
    document.  One over-cap counter written by an operator script silently
    wiped the whole serverhub-state.json to ``{}``: GET /api/cloudflared/status
    (and the Apps page) lost ``active_tunnel`` / ``mode``, restart reported
    "Nothing to restart", and the next read-modify-write (start / uninstall)
    persisted the wipe to disk.  A ``str()``-probe-style guard, not an
    isinstance gate: every renderable numeric id still parses as an int.
    """
    try:
        return int(digits)
    except ValueError:
        return None


def _load_state() -> dict:
    _ensure_dirs()
    if _path_is_file(STATE_FILE):
        try:
            data = safe_json_loads(
                read_text_capped(STATE_FILE, _STATE_CAP) or "{}",
                parse_int=_json_int,
            )
        except (OSError, ValueError, RecursionError):
            # RecursionError: leftover deeply-nested tunnel state is not ValueError.
            return {}
        data = _jsonable_state(data)
        return data if isinstance(data, dict) else {}
    return {}


def _save_state(data: dict) -> None:
    _ensure_dirs()
    # Created 0600 through the open() mode: write-then-chmod left the state
    # readable by every local user for the duration of the write.
    try:
        secure_io.replace_secret_text(
            STATE_FILE,
            json.dumps(
                _jsonable_state(data), ensure_ascii=False, indent=2, allow_nan=False,
            ),
        )
    except (OSError, ValueError, TypeError, RecursionError):
        # A file occupying STATE_DIR or a directory occupying STATE_FILE
        # used to 500 POST /start after the tunnel itself was already up.
        # RecursionError: leftover nested tunnel state after _jsonable_state
        # is not ValueError.
        pass


def _logged_in() -> bool:
    try:
        # is_file then stat raced: a vanished cert raised FileNotFoundError
        # and 500'd every cloudflared status/action that gates on login.
        return _path_is_file(CERT) and CERT.stat().st_size > 20
    except (OSError, ValueError):
        return False


def _forget_login_pid() -> None:
    try:
        LOGIN_PID.unlink(missing_ok=True)
    except OSError:
        pass


def _read_login_pid() -> int | None:
    """Return the recorded login PID, discarding malformed/stale metadata."""
    if not _path_is_file(LOGIN_PID):
        return None
    try:
        with open(LOGIN_PID, encoding="utf-8", errors="replace") as fh:
            raw = fh.read(32)
        pid = int(raw.strip())
        # pid_t is signed 32-bit; os.kill/waitpid OverflowError above that
        # and 500'd every cloudflared status poll.
        if pid <= 1 or pid > 2**31 - 1:
            raise ValueError("unsafe pid")
        return pid
    except (OSError, ValueError, OverflowError):
        _forget_login_pid()
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
        except OverflowError:
            return True
        except ChildProcessError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except (PermissionError, OverflowError):
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
            _forget_login_pid()
            return False
    except OverflowError:
        _forget_login_pid()
        return False
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OverflowError):
        _forget_login_pid()
        return False


def _close_login_proc() -> None:
    """Drop the Popen held by :func:`login_start` and close its pipes."""
    global _login_proc
    proc = _login_proc
    _login_proc = None
    if proc is None:
        return
    for stream in (proc.stdout, proc.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass


def _signal_login(pid: int, sig: int) -> None:
    """Signal the login waiter, and its group only when we own the group.

    ``login_start`` uses ``start_new_session``, so the child is a group
    leader (pgid == pid) and ``killpg`` takes browser helpers with it.
    A leftover PID from an older panel (or a test child) often shares
    *this* process group; ``killpg`` there would take the panel down.
    """
    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError, OverflowError):
        pgid = None
    try:
        if pgid is not None and pgid == pid and pgid != os.getpgrp():
            os.killpg(pgid, sig)
            return
        os.kill(pid, sig)
    except OverflowError as exc:
        raise ProcessLookupError from exc


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
        _close_login_proc()
        return True

    try:
        _signal_login(pid, signal.SIGTERM)
    except ProcessLookupError:
        # It may already be an exited, waitable child.
        pass
    except (PermissionError, OSError):
        return False

    stopped = _wait_login_pid(pid, term_timeout)
    if not stopped:
        try:
            _signal_login(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except (PermissionError, OSError):
            return False
        stopped = _wait_login_pid(pid, kill_timeout)

    if stopped:
        _forget_login_pid()
        _close_login_proc()
    return stopped


def _process_running() -> bool:
    # The shared table (hub/proc_cache.py), not this module's own `ps aux`: the Apps
    # page walks the native catalog -- which scans the same table for every app that
    # has no launchd label -- and then lands here for the tunnel, so one request read
    # the process table twice.  The match below stays local because it is not a plain
    # substring test; it distinguishes a real `tunnel run` from any stray cloudflared.
    for line in ps_lines():
        low = _as_text(line).lower()
        if "cloudflared" not in low:
            continue
        if "tunnel run" in low or "tunnel --config" in low:
            return True
        # token-mode service often shows just cloudflared with token-file
        if "cloudflared" in low and ("token" in low or "config" in low) and "grep" not in low:
            return True
    return False


def _parse_launchctl_print(out) -> dict:
    """Pull state / runs / last exit from ``launchctl print`` text."""
    text = _as_text(out)
    state = ""
    m = re.search(r"(?m)^\s*state\s*=\s*(.+?)\s*$", text)
    if m:
        state = m.group(1).strip()
    runs = None
    m = re.search(r"runs\s*=\s*(\d+)", text)
    if m:
        try:
            runs = int(m.group(1))
        except (TypeError, ValueError, OverflowError):
            runs = None
    last_exit = None
    m = re.search(r"last exit code\s*=\s*(-?\d+)", text)
    if m:
        try:
            last_exit = int(m.group(1))
        except (TypeError, ValueError, OverflowError):
            last_exit = None
    return {"state": state, "runs": runs, "last_exit": last_exit}


def _launchd_job_info(label: str = LABEL) -> dict:
    empty = {
        "loaded": False,
        "running": False,
        "state": "",
        "runs": None,
        "last_exit": None,
    }
    try:
        uid = os.getuid()
        rc, out, _ = sh(["/bin/launchctl", "print", f"gui/{uid}/{label}"], timeout=5)
    except Exception:
        return empty
    if rc != 0:
        return empty
    parsed = _parse_launchctl_print(out)
    parsed["loaded"] = True
    parsed["running"] = parsed.get("state") == "running"
    return parsed


def _launchd_running() -> bool:
    if _launchd_job_info().get("running"):
        return True
    # brew agent (usually useless without config)
    brew = _launchd_job_info("homebrew.mxcl.cloudflared")
    return bool(brew.get("running"))


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
    text = _as_text(out) + "\n" + _as_text(err)
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


def _tunnel_argv(value: str, *, empty_code: str = "cloudflared.tunnel_required") -> str:
    """Tunnel name/UUID that cannot be read as a cloudflared option."""
    # Nested non-strings in serverhub-state.json used to raise ``.strip``.
    if isinstance(value, int) and not isinstance(value, bool):
        # ``tunnel_name: 123`` written unquoted by an operator script parses
        # as an int; the plain isinstance gate below silently refused to
        # restart tunnel "123".  str() probe, so an over-cap leftover stays a
        # coded 400 (ValueError under the digit cap) instead of a 500.
        try:
            value = str(value)
        except ValueError:
            raise api_error("cloudflared.invalid_name")
    if not isinstance(value, str):
        if value in (None, ""):
            raise api_error(empty_code)
        raise api_error("cloudflared.invalid_name")
    text = value.strip()
    if not text:
        raise api_error(empty_code)
    if not cli_args.is_safe_positional(text):
        raise api_error("cloudflared.invalid_name")
    return text


def fetch_token(tunnel: str) -> str:
    """Fetch run token for named tunnel (requires cert.pem)."""
    tunnel = _tunnel_argv(tunnel)
    if not _logged_in():
        raise api_error("cloudflared.not_logged_in")
    bin_path = _bin()
    rc, out, err = sh([bin_path, "tunnel", "token", tunnel], timeout=45)
    if _cli_vanished(rc, err, bin_path):
        raise api_error("cloudflared.not_installed")
    token = _as_text(out).strip().splitlines()
    token = _normalize_token(token[-1] if token else "")
    if rc != 0 or not token_looks_valid(token):
        raise api_error(
            "cloudflared.token_fetch_failed",
            error=(_as_text(err) or _as_text(out) or "unknown")[-500:],
        )
    return token


def _write_token(token: str) -> Path:
    _ensure_dirs()
    token = _normalize_token(token)
    if not token_looks_valid(token):
        raise api_error("cloudflared.invalid_token")
    # The tunnel token grants ingress to this LAN, so it must never exist with
    # default permissions, not even for the moment before a chmod.
    try:
        secure_io.replace_secret_text(TOKEN_FILE, token + "\n")
    except OSError:
        # A directory occupying tunnel.token, or a file occupying STATE_DIR,
        # used to 500 POST /start-token.
        raise api_error("cloudflared.no_token")
    return TOKEN_FILE


def _launch_env() -> dict[str, str]:
    """Launchd/login env.  ``Path.home()`` RuntimeError used to 500 POST /start."""
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"}
    home = user_home()
    if home is not None:
        env["HOME"] = str(home)
    return env


def _write_launchagent_token() -> Path:
    """LaunchAgent: cloudflared tunnel run --token-file ..."""
    _ensure_dirs()
    saved = _read_saved_token()
    if not saved:
        raise api_error("cloudflared.no_token")
    if not token_looks_valid(saved):
        raise api_error("cloudflared.invalid_token")
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
        "EnvironmentVariables": _launch_env(),
    }
    # A leftover directory occupying the plist path made os.replace raise
    # IsADirectoryError out of replace_bytes and 500 POST /start,
    # /start-token and /restart (and the Apps autostart toggle).  Drop an
    # empty leftover so the start self-heals; anything the drop cannot
    # remove (a non-empty directory) stays a coded 503.
    secure_io.drop_leftover_nonfile(PLIST)
    try:
        secure_io.replace_bytes(
            PLIST, plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False)
        )
    except OSError as e:
        raise api_error(
            "cloudflared.plist_write_failed", error=_as_text(e) or "error"
        )
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


def _recent_tunnel_error() -> str:
    """Human reason from the last log lines, or empty when nothing matches."""
    try:
        lines = tail_file_lines(LOG_FILE, 40)
    except Exception:
        return ""
    text = _as_text("\n".join(lines)).lower()
    if "token is not valid" in text:
        return (
            "Provided tunnel token is not valid. "
            "Paste a Zero Trust tunnel token (it starts with eyJ)."
        )
    if "flag provided but not defined" in text:
        return (
            "cloudflared rejected a LaunchAgent flag "
            "(often --edge placed after the `run` subcommand)."
        )
    if "tls handshake with edge: eof" in text:
        return (
            "TLS handshake with the Cloudflare edge failed "
            "(DNS hijack or a local proxy intercepting the tunnel)."
        )
    return ""


def _start_failure_reason(info: dict | None = None) -> str:
    hint = _recent_tunnel_error()
    if hint:
        return hint
    info = info if isinstance(info, dict) else {}
    last_exit = info.get("last_exit")
    state = _as_text(info.get("state") or "") or "not running"
    if last_exit not in (None, 0):
        return (
            f"cloudflared exited with code {last_exit} ({state}). "
            f"Check {LOG_FILE}."
        )
    return f"Start command issued but cloudflared is not running. Check {LOG_FILE}."


def _raise_if_start_failed(result: dict) -> None:
    if result.get("ok"):
        return
    msg = _as_text(result.get("message") or "")
    low = msg.lower()
    if "token is not valid" in low or "starts with eyj" in low:
        raise api_error("cloudflared.invalid_token")
    raise api_error("cloudflared.start_failed", error=msg[-500:] or "not running")


def _launchctl_bootstrap() -> dict:
    uid = os.getuid()
    _launchctl_bootout()
    time.sleep(0.4)
    if not _path_is_file(PLIST):
        return {"ok": False, "message": f"Missing {PLIST}"}
    rc, out, err = sh(
        ["/bin/launchctl", "bootstrap", f"gui/{uid}", str(PLIST)],
        timeout=20,
    )
    # enable for future logins
    sh(["/bin/launchctl", "enable", f"gui/{uid}/{LABEL}"], timeout=10)
    sh(["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"], timeout=15)
    _forget_host_state()
    msg = (_as_text(out) + _as_text(err)).strip()
    running = False
    info: dict = {}
    # The point of this loop is to observe a change, so each pass needs its
    # own reading.  The process table and the launchd listing are both cached
    # for a few seconds to collapse concurrent page readers, and a cached
    # answer here would mean polling the same pre-start snapshot eight times
    # and reporting a successful start as "check the log".
    for i in range(8):
        _forget_host_state()
        running = _is_running()
        if running:
            break
        info = _launchd_job_info()
        # Invalid token (and similar) exits in milliseconds.  Do not wait the
        # full poll window, and do not leave KeepAlive loaded — that is the
        # silent crash loop the Services page then reports as "won't start".
        if i >= 1 and info.get("last_exit") not in (None, 0) and not info.get("running"):
            break
        time.sleep(0.4)
    if running:
        return {"ok": True, "message": msg or "Started"}
    reason = _start_failure_reason(info)
    _launchctl_bootout()
    return {"ok": False, "message": reason}


def status() -> dict:
    """Panel snapshot for Cloudflared."""
    _ensure_dirs()
    st = _jsonable_state(_load_state())
    if not isinstance(st, dict):
        st = {}

    def _tunnels() -> tuple[list, str | None]:
        """The tunnel list, or the reason it could not be fetched.

        Absorbs its own failure so it can share a wave with the liveness check.
        """
        if not _logged_in():
            return [], None
        try:
            return list_tunnels(), None
        except Exception as e:
            return [], _as_text(e)

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

    # Never a plain open()+read(): a FIFO planted at login.url used to park
    # this poll endpoint forever (see _read_login_url).
    login_url = _read_login_url()
    # Reap a login child that exited between polls instead of retaining a zombie.
    login_pending = _login_process_pending()

    bin_path = None
    try:
        bin_path = _bin()
    except Exception:
        bin_path = None
    has_token = _path_is_file(TOKEN_FILE)
    token_ok = token_looks_valid(_read_saved_token()) if has_token else False
    crash_loop = False
    last_exit = None
    status_text = "Running" if running else "Stopped"
    if not running and _path_is_file(PLIST):
        info = _launchd_job_info()
        last_exit = info.get("last_exit")
        if info.get("loaded") and last_exit not in (None, 0):
            crash_loop = True
            status_text = _recent_tunnel_error() or (
                f"Crash-looping · last exit {last_exit}"
            )
        elif has_token and not token_ok:
            status_text = "Saved token is not a valid Cloudflare connector token"
    return _jsonable_state({
        "ok": True,
        "installed": bool(bin_path and _path_is_file(Path(bin_path))),
        "bin": bin_path,
        "logged_in": _logged_in(),
        "cert_path": str(CERT) if _path_is_file(CERT) else None,
        "running": running,
        "state": "ok" if running else "down",
        "status_text": status_text,
        "crash_loop": crash_loop,
        "last_exit": last_exit,
        "token_ok": token_ok,
        "active_tunnel": st.get("tunnel_name") or st.get("tunnel_id"),
        "mode": st.get("mode") or ("token" if has_token else None),
        "has_token": has_token,
        "tunnels": tunnels,
        "tunnels_error": tunnels_err,
        "login_url": login_url if login_pending or not _logged_in() else None,
        "login_pending": login_pending,
        "plist": str(PLIST) if _path_is_file(PLIST) else None,
        "log_path": str(LOG_FILE),
        "config_path": str(CONFIG_YML) if _path_is_file(CONFIG_YML) else None,
        "notes": (
            "Pick an existing tunnel or paste a Zero Trust token to start/stop. "
            "Configure routes/subdomains in the Cloudflare Zero Trust dashboard "
            "(recommended); no Remote Desktop needed."
        ),
    })


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
    try:
        LOGIN_URL_FILE.unlink(missing_ok=True)
    except OSError:
        # A directory occupying login.url used to 500 POST /login.
        pass
    try:
        # write_text follows a planted symlink and O_TRUNCs the target.
        # LOGIN_URL already uses replace_secret_text (O_EXCL|O_NOFOLLOW tmp).
        secure_io.replace_secret_text(LOGIN_LOG, "")
    except OSError:
        pass
    # Run login; cloudflared prints a URL then waits for callback.
    # cwd must be a directory: a file occupying ~/.cloudflared used to
    # NotADirectoryError after _ensure_dirs started swallowing that collision.
    cwd = str(CF_HOME) if _path_is_dir(CF_HOME) else None
    global _login_proc
    _close_login_proc()
    try:
        proc = subprocess.Popen(
            [_bin(), "tunnel", "login"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            cwd=cwd,
            env=utf8_env({**os.environ, **_launch_env()}),
            start_new_session=True,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, ValueError, TypeError, RecursionError) as e:
        return {
            "ok": False,
            "message": "Could not start cloudflared login: " + (_as_text(e) or "error"),
            "logged_in": False,
        }
    _login_proc = proc
    try:
        secure_io.replace_secret_text(LOGIN_PID, str(proc.pid))
    except OSError:
        pass
    url = None
    # Read up to 12s for the URL line.  monotonic, not time.time(), for the
    # same reason _wait_login_pid uses it: this loop runs on a request
    # thread, and the wall clock can step under it -- NTP corrects it, and
    # the panel's own date & time settings set it outright.  A backwards
    # step would park the request here for the length of the correction.
    deadline = time.monotonic() + 12
    buf = ""
    if proc.stdout is None:
        return {
            "ok": False,
            "message": "Login process started but no output was captured",
            "login_pending": True,
        }
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            line = proc.stdout.readline(_LOGIN_LINE_CAP)
        except (OSError, UnicodeDecodeError, ValueError, TypeError):
            break
        if not line:
            time.sleep(0.15)
            continue
        if len(line) >= _LOGIN_LINE_CAP and not line.endswith("\n"):
            try:
                while True:
                    rest = proc.stdout.readline(_LOGIN_LINE_CAP)
                    if rest == "" or rest.endswith("\n"):
                        break
            except (OSError, UnicodeDecodeError, ValueError, TypeError):
                break
        buf += line
        if len(buf) > 16_000:
            buf = buf[-8000:]
        try:
            secure_io.replace_secret_text(LOGIN_LOG, buf[-8000:])
        except OSError:
            pass
        m = re.search(r"https://[^\s]+", line)
        if m:
            url = m.group(0).rstrip(").,]")
            try:
                secure_io.replace_secret_text(LOGIN_URL_FILE, url)
            except OSError:
                pass
            break
    if not url and buf:
        m2 = re.search(r"https://[^\s]+", buf)
        if m2:
            url = m2.group(0).rstrip(").,]")
            try:
                secure_io.replace_secret_text(LOGIN_URL_FILE, url)
            except OSError:
                pass
    if not url:
        # still running? keep process
        if proc.poll() is None:
            return {
                "ok": False,
                "message": "Login process started but no URL was found; check the login log or run cloudflared tunnel login in a local browser session",
                "login_pending": True,
                "log": buf[-1500:],
            }
        _close_login_proc()
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
        try:
            LOGIN_URL_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        return {
            "ok": stopped,
            "logged_in": True,
            "message": "Login successful" if stopped else "Login successful, but cleaning up the login process failed; try again later",
        }
    # Never a plain open()+read(): a FIFO planted at login.url used to park
    # this poll endpoint forever (see _read_login_url).
    url = _read_login_url()
    return {
        "ok": True,
        "logged_in": False,
        "login_pending": _login_process_pending(),
        "login_url": url,
        "message": "Waiting for the browser to finish authorization…",
    }


def create_tunnel(name: str) -> dict:
    name = re.sub(r"[^a-zA-Z0-9._-]", "", (name or "").strip())
    # The charset class includes ``-``, so ``--help`` survived the strip and
    # became ``cloudflared tunnel create --help``.
    if not name or not cli_args.is_safe_positional(name):
        raise api_error("cloudflared.invalid_name")
    if not _logged_in():
        raise api_error("cloudflared.login_required")
    bin_path = _bin()
    rc, out, err = sh([bin_path, "tunnel", "create", name], timeout=60)
    if _cli_vanished(rc, err, bin_path):
        raise api_error("cloudflared.not_installed")
    # The account list just changed; do not let the page show the old one.
    invalidate_tunnels()
    ok = rc == 0
    msg = (_as_text(out) + "\n" + _as_text(err)).strip()
    tunnels = list_tunnels() if ok or _logged_in() else []
    return {"ok": ok, "message": msg[-2000:], "tunnels": tunnels}


def start_with_tunnel(tunnel: str) -> dict:
    """Fetch token for tunnel name/uuid and start LaunchAgent."""
    tunnel = _tunnel_argv(tunnel)
    token = fetch_token(tunnel)
    _write_token(token)
    _write_launchagent_token()
    r = _launchctl_bootstrap()
    _raise_if_start_failed(r)
    st = _load_state()
    st.update({"mode": "token", "tunnel_name": tunnel, "updated": time.time()})
    _save_state(st)
    return {
        "ok": True,
        "message": f"Tunnel \"{tunnel}\" configured and started\n" + (r.get("message") or ""),
        "running": True,
        "active_tunnel": tunnel,
    }


def start_with_token(token: str, label: str | None = None) -> dict:
    """Start using a pasted Zero Trust token."""
    token = _normalize_token(token)
    if not token_looks_valid(token):
        raise api_error("cloudflared.invalid_token")
    _write_token(token)
    _write_launchagent_token()
    r = _launchctl_bootstrap()
    _raise_if_start_failed(r)
    st = _load_state()
    st.update({
        "mode": "token",
        "tunnel_name": (label or "").strip() or "token",
        "updated": time.time(),
    })
    _save_state(st)
    return {
        "ok": True,
        "message": "Tunnel started with the token\n" + (r.get("message") or ""),
        "running": True,
    }


def stop() -> dict:
    _launchctl_bootout()
    # kill leftover tunnel processes (not ddns scripts)
    for pid, cmd in ps_pid_commands(force=True):
        low = cmd.lower()
        if "cloudflared" in low and ("tunnel" in low or "token" in low):
            try:
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
    st = _jsonable_state(_load_state())
    if not isinstance(st, dict):
        st = {}
    name = st.get("tunnel_name")
    if _path_is_file(TOKEN_FILE):
        if not token_looks_valid(_read_saved_token()):
            _launchctl_bootout()
            raise api_error("cloudflared.invalid_token")
        _write_launchagent_token()
        r = _launchctl_bootstrap()
        _raise_if_start_failed(r)
        return _jsonable_state({
            "ok": True,
            "message": "Restarted\n" + (r.get("message") or ""),
            "running": True,
            "active_tunnel": name,
        })
    if name and _logged_in():
        return start_with_tunnel(name)
    return {"ok": False, "message": "Nothing to restart: pick a tunnel or paste a token and start it first"}


def route_dns(tunnel: str, hostname: str) -> dict:
    """cloudflared tunnel route dns <tunnel> <hostname>"""
    tunnel = _tunnel_argv(tunnel, empty_code="cloudflared.route_args_required")
    hostname = (hostname or "").strip().lower()
    if not hostname or not cli_args.is_safe_hostname(hostname):
        raise api_error("cloudflared.route_args_required")
    if not _logged_in():
        raise api_error("cloudflared.login_required")
    bin_path = _bin()
    rc, out, err = sh(
        [bin_path, "tunnel", "route", "dns", tunnel, hostname],
        timeout=60,
    )
    if _cli_vanished(rc, err, bin_path):
        raise api_error("cloudflared.not_installed")
    msg = (_as_text(out) + "\n" + _as_text(err)).strip()
    return {"ok": rc == 0, "message": msg[-2000:]}


def logs(lines: int = 120) -> dict:
    try:
        n = int(lines or 120)
    except (TypeError, ValueError, OverflowError):
        n = 120
    if isinstance(lines, float) and (
        lines != lines or lines in (float("inf"), float("-inf"))
    ):
        n = 120
    lines = max(20, min(n, 500))
    chunks: list[str] = []
    for p in (LOG_FILE, Path("/opt/homebrew/var/log/cloudflared.log"), LOGIN_LOG):
        # is_file() on the brew log path used to PermissionError and 500
        # GET /api/cloudflared/logs even when our own tunnel.log was fine.
        try:
            present = p.is_file()
        except (OSError, ValueError):
            continue
        if not present:
            continue
        try:
            tail = "\n".join(tail_file_lines(p, lines))
            chunks.append(f"===== {p} =====\n{tail}")
        except Exception as e:
            chunks.append(
                f"===== {p} =====\n(read error: {_as_text(e) or 'error'})"
            )
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
            if _path_is_file(p):
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
