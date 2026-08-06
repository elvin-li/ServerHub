"""WireGuard server management for macOS — peers, keys, config and live state.

ServerHub drives the Homebrew ``wireguard-tools`` + ``wireguard-go`` pair, which is
how a Mac runs a WireGuard *server* (Apple's App Store client cannot act as one).
The feature set mirrors the reference router panel this page is modelled on: server
status, a peer table with live traffic, peer creation with full/split tunnel modes
and optional preshared keys, batch creation, import, and multi-format export.

Two deliberate differences from that reference, both about not losing information:

* **Client keys are retained.** A server config only stores each peer's *public*
  key, so a panel that generates a keypair and forgets the private half can never
  re-issue that peer's config or QR code — the operator's only recourse is to
  delete the peer and enrol the device again.  Peers are therefore journalled to
  ``data/wireguard-peers.json`` at mode 0600.  This is a real tradeoff: it puts
  client private keys on the server.  It is opt-out per peer (``keep_key=False``
  generates the key, hands it over once, and stores only the public half), and the
  UI states which peers are re-issuable.
* **``wg-quick strip`` is reimplemented here.** On macOS that subcommand refuses to
  run as anyone but root — it re-executes itself under ``sudo`` and prompts on a
  tty — so calling it from a web request either hangs or fails.  Stripping is a
  pure text transform, so it is done in-process instead: no subprocess, no
  elevation, and testable without a WireGuard installation.

Privilege model: reading and writing ``wg0.conf`` needs no elevation (Homebrew's
``etc`` directory is owned by the installing user).  Bringing the interface up or
down, and reading live peer state from the kernel/userspace socket, do.  Those go
through ``sudo -n`` when the packaged sudoers rule is installed, falling back to
the native macOS authorization sheet, and never to an interactive tty prompt.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
from pathlib import Path

from hub import wireguard_export
from hub.config import cfg, update_settings
from hub.macos_admin import run_admin, run_admin_sequence, sudo_capture
from hub.paths import DATA_DIR
from hub.secure_io import write_secret_text
from hub.util import port_open, sh

WG = "/opt/homebrew/bin/wg"
WG_QUICK = "/opt/homebrew/bin/wg-quick"
RM = "/bin/rm"
WIREGUARD_GO = "/opt/homebrew/bin/wireguard-go"

#: wg-quick is a bash script with a `#!/usr/bin/env bash` shebang and refuses to
#: run under bash 3.  Under sudo the environment is scrubbed to a minimal PATH,
#: so `env bash` resolves to Apple's ancient /bin/bash 3.2 and wg-quick dies
#: with "Version mismatch: bash 3 detected".  Launch it through a modern bash
#: by absolute path instead — deterministic under sudo and matches the
#: sudoers rules, which pin this exact argv.
def _modern_bash() -> str:
    for candidate in ("/opt/homebrew/bin/bash", "/usr/local/bin/bash"):
        if Path(candidate).exists():
            return candidate
    return "/bin/bash"


BASH = _modern_bash()

#: Homebrew's prefix differs between Apple silicon and Intel; probe both.
_CONF_DIRS = ("/opt/homebrew/etc/wireguard", "/usr/local/etc/wireguard")

REGISTRY_PATH = DATA_DIR / "wireguard-peers.json"

#: Interface names WireGuard accepts and we are willing to manage.
_IFACE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,14}$")

#: Base64 Curve25519 key: 43 characters plus '='.
_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=$")

#: Peer display names.  Deliberately conservative: the value ends up in a
#: filename, a QR label and a config comment.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$")

#: Keys wg-quick handles itself and ``wg setconf`` rejects.
_WG_QUICK_ONLY = {
    "address", "dns", "mtu", "table", "preup", "postup", "predown",
    "postdown", "saveconfig",
}

#: A peer is "active" if it handshook within this many seconds.  WireGuard
#: rekeys about every two minutes, so a healthy peer is always inside this.
ACTIVE_WINDOW = 180
#: Handshook once, but not recently — connected earlier and went away.
STALE_WINDOW = 900

DEFAULTS = {
    "interface": "wg0",
    "subnet": "10.10.0.0/24",
    "listen_port": 51820,
    "dns": "1.1.1.1, 8.8.8.8",
    "mtu": wireguard_export.DEFAULT_MTU,
    "keepalive": 25,
    "endpoint": "",
    "lan_cidr": "",
    "wan_interface": "",
}


class WireGuardError(ValueError):
    """Carries a stable ``code`` the router maps to a translated API error."""

    def __init__(self, code: str, **params):
        super().__init__(code)
        self.code = code
        self.params = params


# ── settings ─────────────────────────────────────────────────────────────────

def settings() -> dict:
    """Effective WireGuard settings, defaults filled in."""
    stored = (cfg().get("settings") or {}).get("wireguard") or {}
    merged = dict(DEFAULTS)
    for key, value in stored.items():
        if key in merged and value not in (None, ""):
            merged[key] = value
    iface = str(merged["interface"])
    if not _IFACE_RE.match(iface):
        merged["interface"] = DEFAULTS["interface"]
    try:
        ipaddress.ip_network(str(merged["subnet"]), strict=False)
    except ValueError:
        merged["subnet"] = DEFAULTS["subnet"]
    try:
        merged["listen_port"] = int(merged["listen_port"])
    except (TypeError, ValueError):
        merged["listen_port"] = DEFAULTS["listen_port"]
    try:
        merged["mtu"] = int(merged["mtu"])
    except (TypeError, ValueError):
        merged["mtu"] = DEFAULTS["mtu"]
    try:
        merged["keepalive"] = int(merged["keepalive"])
    except (TypeError, ValueError):
        merged["keepalive"] = DEFAULTS["keepalive"]
    return merged


def save_settings(patch: dict) -> dict:
    """Persist a subset of the WireGuard settings after validating each field."""
    current = dict((cfg().get("settings") or {}).get("wireguard") or {})
    for key, value in (patch or {}).items():
        if key not in DEFAULTS:
            continue
        if value is None:
            current.pop(key, None)
            continue
        if key == "interface":
            if not _IFACE_RE.match(str(value)):
                raise WireGuardError("wg.bad_interface", interface=str(value)[:20])
        elif key == "subnet":
            try:
                ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                raise WireGuardError("wg.bad_subnet", subnet=str(value)[:40])
        elif key in ("listen_port", "mtu", "keepalive"):
            try:
                number = int(value)
            except (TypeError, ValueError):
                raise WireGuardError("wg.bad_number", field=key)
            if key == "listen_port" and not (1 <= number <= 65535):
                raise WireGuardError("wg.bad_number", field=key)
            if key == "mtu" and not (576 <= number <= 1500):
                raise WireGuardError("wg.bad_number", field=key)
            if key == "keepalive" and not (0 <= number <= 3600):
                raise WireGuardError("wg.bad_number", field=key)
            value = number
        elif key == "lan_cidr" and value:
            try:
                ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                raise WireGuardError("wg.bad_subnet", subnet=str(value)[:40])
        elif key == "endpoint" and value:
            if not re.match(r"^[A-Za-z0-9._-]{1,253}(?::\d{1,5})?$", str(value)):
                raise WireGuardError("wg.bad_endpoint", endpoint=str(value)[:60])
        elif key == "wan_interface" and value:
            if not re.match(r"^[a-z][a-z0-9]{0,14}$", str(value)):
                raise WireGuardError("wg.bad_interface", interface=str(value)[:20])
        current[key] = value
    update_settings({"wireguard": current})
    return settings()


# ── installation & paths ─────────────────────────────────────────────────────

def conf_dir() -> Path:
    for candidate in _CONF_DIRS:
        path = Path(candidate)
        if path.is_dir():
            return path
    return Path(_CONF_DIRS[0])


def conf_path(interface: str | None = None) -> Path:
    return conf_dir() / f"{interface or settings()['interface']}.conf"


def installation() -> dict:
    """Which WireGuard pieces are present, and their versions."""
    def version(binary: str, args: list[str]) -> str:
        if not Path(binary).exists():
            return ""
        rc, out, err = sh([binary, *args], timeout=8)
        text = (out or err or "").strip().splitlines()
        return text[0][:120] if text and rc == 0 else ""

    tools = version(WG, ["--version"])
    userspace = version(WIREGUARD_GO, ["--version"])
    # Presence is decided by the binaries being on disk, not by a subprocess
    # succeeding.  Deriving it from `wg --version` meant any transient failure of
    # that probe -- a timeout under load, a stray non-zero exit -- reported
    # "wireguard-tools is not installed" and refused every operation, which is a
    # wildly misleading answer on a host where it is plainly installed.  The
    # version strings stay best-effort and are only used for display.
    present = Path(WG).exists() and Path(WG_QUICK).exists()
    return {
        "wg": WG if Path(WG).exists() else "",
        "wg_quick": WG_QUICK if Path(WG_QUICK).exists() else "",
        "wireguard_go": WIREGUARD_GO if Path(WIREGUARD_GO).exists() else "",
        "tools_version": tools,
        "userspace_version": userspace,
        "installed": present,
        #: True when the binaries are there but would not answer a version probe;
        #: the page can distinguish "missing" from "installed but misbehaving".
        "probe_failed": present and not tools,
        "conf_dir": str(conf_dir()),
        "conf_path": str(conf_path()),
        "conf_exists": conf_path().exists(),
    }


# ── key material ─────────────────────────────────────────────────────────────

def _run_with_input(argv: list[str], data: str, *, timeout: int = 8) -> str:
    """Run *argv* feeding *data* on stdin, returning trimmed stdout.

    :func:`hub.util.sh` has no stdin channel, and widening its signature for the
    single caller that needs one would change a helper used across the codebase.
    """
    try:
        proc = subprocess.run(
            argv, input=data, capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def generate_keypair() -> tuple[str, str]:
    """A fresh (private, public) Curve25519 pair from ``wg genkey`` / ``wg pubkey``."""
    rc, private, _ = sh([WG, "genkey"], timeout=8)
    private = private.strip()
    if rc != 0 or not _KEY_RE.match(private):
        raise WireGuardError("wg.keygen_failed")
    public = _run_with_input([WG, "pubkey"], private + "\n")
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.keygen_failed")
    return private, public


def generate_psk() -> str:
    rc, psk, _ = sh([WG, "genpsk"], timeout=8)
    psk = psk.strip()
    if rc != 0 or not _KEY_RE.match(psk):
        raise WireGuardError("wg.keygen_failed")
    return psk


def public_from_private(private: str) -> str:
    if not _KEY_RE.match(str(private or "")):
        raise WireGuardError("wg.bad_key")
    public = _run_with_input([WG, "pubkey"], str(private).strip() + "\n")
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.bad_key")
    return public


# ── server config ────────────────────────────────────────────────────────────

def read_conf(interface: str | None = None) -> dict:
    """Parse the server config, or an empty skeleton when absent."""
    path = conf_path(interface)
    try:
        text = path.read_text()
    except OSError:
        return {"interface": {}, "peers": []}
    return wireguard_export.parse_conf(text)


def strip_conf(text: str) -> str:
    """Drop wg-quick-only directives, leaving what ``wg setconf`` accepts.

    Replaces ``wg-quick strip``, which on macOS insists on running as root.
    """
    out: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.lower() in ("[interface]", "[peer]"):
            out.append(line)
            continue
        key, sep, _ = line.partition("=")
        if not sep:
            continue
        if key.strip().lower() in _WG_QUICK_ONLY:
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def render_conf(server: dict, peers: list[dict]) -> str:
    """Build the full ``wg0.conf`` body from the server block and peer records."""
    cfg_ = settings()
    lines = [
        "# Managed by ServerHub. Peer blocks are regenerated on every change.",
        f"# Last written: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "[Interface]",
        f"PrivateKey = {server['private_key']}",
        f"Address = {server['address']}",
        f"ListenPort = {server['listen_port']}",
    ]
    if cfg_["dns"]:
        lines.append(f"DNS = {cfg_['dns']}")
    if cfg_["mtu"]:
        lines.append(f"MTU = {cfg_['mtu']}")

    for peer in peers:
        lines += ["", "[Peer]"]
        if peer.get("name"):
            lines.append(f"# {peer['name']}")
        lines.append(f"PublicKey = {peer['public_key']}")
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        lines.append(f"AllowedIPs = {peer['ip']}")
        keepalive = int(peer.get("keepalive") or cfg_["keepalive"] or 0)
        if keepalive:
            lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def server_identity() -> dict:
    """The server's own keys and address, creating them on first use."""
    parsed = read_conf()
    iface = parsed["interface"]
    cfg_ = settings()
    network = ipaddress.ip_network(cfg_["subnet"], strict=False)
    default_address = f"{network.network_address + 1}/{network.prefixlen}"

    private = str(iface.get("PrivateKey") or "").strip()
    if not _KEY_RE.match(private):
        directory = conf_dir()
        key_file = directory / "privatekey"
        try:
            candidate = key_file.read_text().strip()
        except OSError:
            candidate = ""
        private = candidate if _KEY_RE.match(candidate) else ""
    if not private:
        private, _ = generate_keypair()

    return {
        "private_key": private,
        "public_key": public_from_private(private),
        "address": str(iface.get("Address") or default_address).strip(),
        "listen_port": int(str(iface.get("ListenPort") or cfg_["listen_port"]).strip() or cfg_["listen_port"]),
    }


# ── peer registry ────────────────────────────────────────────────────────────

def _load_registry() -> dict:
    try:
        data = json.loads(REGISTRY_PATH.read_text())
    except (OSError, ValueError):
        return {"peers": {}}
    if not isinstance(data, dict) or not isinstance(data.get("peers"), dict):
        return {"peers": {}}
    return data


def _save_registry(data: dict) -> None:
    write_secret_text(REGISTRY_PATH, json.dumps(data, indent=2, ensure_ascii=False))


def _registry_peers() -> dict:
    return _load_registry().get("peers") or {}


def peer_records() -> list[dict]:
    """Peers as configured, enriched with registry metadata.

    The config file is the source of truth for *membership* — an operator may have
    edited it by hand, and a peer that is in the file must appear in the UI even if
    the panel never created it.  The registry only adds name, mode and retained
    key material.
    """
    parsed = read_conf()
    registry = _registry_peers()
    records = []
    for peer in parsed["peers"]:
        public = str(peer.get("PublicKey") or "").strip()
        if not public:
            continue
        meta = registry.get(public) or {}
        records.append({
            "public_key": public,
            "ip": str(peer.get("AllowedIPs") or "").strip(),
            "preshared_key": str(peer.get("PresharedKey") or "").strip(),
            "keepalive": str(peer.get("PersistentKeepalive") or "").strip(),
            "name": str(meta.get("name") or ""),
            "mode": str(meta.get("mode") or ""),
            "created": meta.get("created") or 0,
            # Whether this peer's config/QR can be produced again.
            "reissuable": bool(meta.get("private_key")),
            "known": bool(meta),
        })
    return records


# ── live state ───────────────────────────────────────────────────────────────

def _dump(interface: str) -> tuple[bool, list[list[str]], str]:
    """Parse ``wg show <iface> dump`` into rows.

    The dump format is tab-separated and stable across versions, unlike the
    human-readable output: first row is the interface
    (private key, public key, listen port, fwmark), each later row is a peer
    (public key, preshared key, endpoint, allowed ips, latest handshake,
    rx bytes, tx bytes, persistent keepalive).
    """
    rc, out, err = sh([WG, "show", interface, "dump"], timeout=10)
    if rc != 0:
        # The UAPI socket is root-owned: retry with root.  sudo_capture uses
        # the web-entered password when this request carries one (management
        # from another device), else the packaged passwordless sudoers rules.
        rc, out, err = sudo_capture([WG, "show", interface, "dump"], timeout=10)
    if rc != 0:
        return False, [], (err or out or "").strip()[:200]
    rows = [line.split("\t") for line in out.splitlines() if line.strip()]
    return True, rows, ""


def _human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "K", "M", "G", "T"):
        if size < 1024 or unit == "T":
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}T"


def status(force: bool = False) -> dict:
    """Server state plus the peer table, shaped for the page.

    Mirrors the reference panel's payload so the two UIs stay comparable:
    ``running``, ``listen_port``, ``public_key``, ``mtu``, ``peer_count``,
    ``active_count``, ``stale_count``, ``keepalive_missing`` and ``peers[]``.
    """
    del force  # state is cheap; the poll interval is the throttle
    cfg_ = settings()
    interface = cfg_["interface"]
    install = installation()
    records = peer_records()

    up, rows, error = _dump(interface)
    live: dict[str, dict] = {}
    listen_port = 0
    server_public = ""
    if up and rows:
        head = rows[0]
        if len(head) >= 3:
            server_public = head[1].strip()
            try:
                listen_port = int(head[2])
            except ValueError:
                listen_port = 0
        for row in rows[1:]:
            if len(row) < 8:
                continue
            public = row[0].strip()
            try:
                handshake = int(row[4])
            except ValueError:
                handshake = 0
            try:
                rx, tx = int(row[5]), int(row[6])
            except ValueError:
                rx, tx = 0, 0
            live[public] = {
                "endpoint": row[2].strip(),
                "allowed_ips": row[3].strip(),
                "last_handshake": handshake,
                "rx": rx,
                "tx": tx,
                "keepalive": row[7].strip(),
                "preshared": row[1].strip() not in ("", "(none)"),
            }

    now = int(time.time())
    peers = []
    active = stale = keepalive_missing = 0
    for record in records:
        stats = live.get(record["public_key"]) or {}
        handshake = int(stats.get("last_handshake") or 0)
        age = (now - handshake) if handshake else 0
        is_active = bool(handshake) and age <= ACTIVE_WINDOW
        is_stale = bool(handshake) and ACTIVE_WINDOW < age <= STALE_WINDOW
        active += 1 if is_active else 0
        stale += 1 if is_stale else 0
        keepalive = stats.get("keepalive") or record["keepalive"] or "off"
        if str(keepalive) in ("", "0", "off"):
            keepalive_missing += 1
        peers.append({
            "pubkey": record["public_key"],
            "name": record["name"],
            "mode": record["mode"],
            "allowed_ips": stats.get("allowed_ips") or record["ip"],
            "endpoint": stats.get("endpoint") or "",
            "last_handshake": handshake,
            "handshake_age": age,
            "active": is_active,
            "stale": is_stale,
            "keepalive": str(keepalive),
            "psk": bool(stats.get("preshared") or record["preshared_key"]),
            "rx": int(stats.get("rx") or 0),
            "tx": int(stats.get("tx") or 0),
            "rx_human": _human_bytes(int(stats.get("rx") or 0)),
            "tx_human": _human_bytes(int(stats.get("tx") or 0)),
            "reissuable": record["reissuable"],
            "known": record["known"],
        })

    parsed = read_conf()
    address = str(parsed["interface"].get("Address") or "").strip()
    try:
        conf_public = public_from_private(str(parsed["interface"].get("PrivateKey") or ""))
    except WireGuardError:
        conf_public = ""

    return {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "installed": install["installed"],
        "install": install,
        "interface": interface,
        "running": up,
        "state_error": error,
        "listen_port": listen_port or int(parsed["interface"].get("ListenPort") or cfg_["listen_port"]),
        "public_key": server_public or conf_public,
        "address": address,
        "subnet": cfg_["subnet"],
        "mtu": int(parsed["interface"].get("MTU") or cfg_["mtu"]),
        "dns": str(parsed["interface"].get("DNS") or cfg_["dns"]),
        "endpoint": cfg_["endpoint"],
        "peers": peers,
        "peer_count": len(peers),
        "active_count": active,
        "stale_count": stale,
        "keepalive_missing": keepalive_missing,
        "unknown_count": sum(1 for p in peers if not p["known"]),
        "reissuable_count": sum(1 for p in peers if p["reissuable"]),
    }


# ── address allocation ───────────────────────────────────────────────────────

def used_addresses() -> set[str]:
    """Every host address already claimed, including the server's own."""
    used: set[str] = set()
    parsed = read_conf()
    address = str(parsed["interface"].get("Address") or "")
    for part in address.split(","):
        host = part.strip().split("/")[0].strip()
        if host:
            used.add(host)
    for peer in parsed["peers"]:
        for part in str(peer.get("AllowedIPs") or "").split(","):
            host = part.strip().split("/")[0].strip()
            if host:
                used.add(host)
    return used


def next_ip() -> dict:
    """The lowest free host address in the configured subnet."""
    cfg_ = settings()
    network = ipaddress.ip_network(cfg_["subnet"], strict=False)
    used = used_addresses()
    server = str(network.network_address + 1)
    for host in network.hosts():
        candidate = str(host)
        if candidate == server:
            continue
        if candidate not in used:
            return {"next_ip": f"{candidate}/32", "used": len(used), "subnet": cfg_["subnet"]}
    raise WireGuardError("wg.subnet_full", subnet=cfg_["subnet"])


def _validate_ip(value: str) -> str:
    """Normalize a peer address to ``a.b.c.d/32`` inside the configured subnet."""
    raw = str(value or "").strip()
    if not raw:
        raise WireGuardError("wg.bad_ip", ip="")
    host_part = raw.split("/")[0].strip()
    try:
        address = ipaddress.ip_address(host_part)
    except ValueError:
        raise WireGuardError("wg.bad_ip", ip=raw[:40])
    network = ipaddress.ip_network(settings()["subnet"], strict=False)
    if address not in network:
        raise WireGuardError("wg.ip_outside_subnet", ip=str(address), subnet=str(network))
    return f"{address}/32"


# ── writing the config ───────────────────────────────────────────────────────

def _write_conf(peers: list[dict]) -> Path:
    """Persist the server config from *peers*, keeping a one-generation backup.

    Mode 0600 from the first byte: the file holds the server private key, and a
    default-umask write would leave it world-readable until a later chmod.
    """
    server = server_identity()
    body = render_conf(server, peers)
    path = conf_path()
    if path.exists():
        try:
            backup = path.with_suffix(".conf.bak")
            write_secret_text(backup, path.read_text())
        except OSError:
            # A missing backup must not block a legitimate change.
            pass
    write_secret_text(path, body)
    return path


def _peers_for_write() -> list[dict]:
    """Current peers in the shape :func:`render_conf` expects."""
    return [
        {
            "public_key": record["public_key"],
            "ip": record["ip"],
            "preshared_key": record["preshared_key"],
            "name": record["name"],
            "keepalive": record["keepalive"],
        }
        for record in peer_records()
    ]


def client_allowed_ips(mode: str) -> str:
    """What the *client* routes over the tunnel for a given mode.

    ``full`` sends everything, which is what "get me a home IP address" means.
    ``split`` sends only the home subnets, so the device keeps its local internet
    path and battery life — the right default for a phone.
    """
    cfg_ = settings()
    if (mode or "").lower() == "full":
        return "0.0.0.0/0, ::/0"
    parts = [cfg_["subnet"]]
    if cfg_["lan_cidr"]:
        parts.append(cfg_["lan_cidr"])
    return ", ".join(parts)


def _endpoint_for_clients() -> str:
    """``host:port`` clients dial.  Empty when the operator has not set a host."""
    cfg_ = settings()
    endpoint = str(cfg_["endpoint"] or "").strip()
    port = server_identity()["listen_port"]
    if not endpoint:
        return ""
    if ":" in endpoint:
        return endpoint
    return f"{endpoint}:{port}"


def build_client_conf(
    *,
    private_key: str,
    ip: str,
    mode: str,
    preshared_key: str = "",
) -> str:
    """Assemble the peer-side config for a client."""
    cfg_ = settings()
    server = server_identity()
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {ip}",
    ]
    if cfg_["dns"]:
        lines.append(f"DNS = {cfg_['dns']}")
    if cfg_["mtu"]:
        lines.append(f"MTU = {cfg_['mtu']}")
    lines += ["", "[Peer]", f"PublicKey = {server['public_key']}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"AllowedIPs = {client_allowed_ips(mode)}")
    endpoint = _endpoint_for_clients()
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    else:
        lines.append("# Endpoint = your-host:51820   <- set the public endpoint in settings")
    if cfg_["keepalive"]:
        lines.append(f"PersistentKeepalive = {cfg_['keepalive']}")
    return "\n".join(lines) + "\n"


# ── peer operations ──────────────────────────────────────────────────────────

def add_peer(
    *,
    name: str,
    ip: str = "",
    mode: str = "split",
    psk: bool = False,
    keep_key: bool = True,
) -> dict:
    """Create a peer, returning its ready-to-use client config."""
    label = str(name or "").strip()
    if not _NAME_RE.match(label):
        raise WireGuardError("wg.bad_name")
    if (mode or "").lower() not in ("full", "split"):
        raise WireGuardError("wg.bad_mode", mode=str(mode)[:20])
    mode = mode.lower()

    address = _validate_ip(ip) if ip else next_ip()["next_ip"]
    if address.split("/")[0] in used_addresses():
        raise WireGuardError("wg.ip_in_use", ip=address)

    private, public = generate_keypair()
    preshared = generate_psk() if psk else ""

    peers = _peers_for_write()
    peers.append({
        "public_key": public,
        "ip": address,
        "preshared_key": preshared,
        "name": label,
        "keepalive": settings()["keepalive"],
    })
    _write_conf(peers)

    registry = _load_registry()
    registry["peers"][public] = {
        "name": label,
        "ip": address,
        "mode": mode,
        "created": int(time.time()),
        # Retaining the private key is what makes re-issue possible; opting out
        # keeps only the public half, so the config below is the single copy.
        **({"private_key": private} if keep_key else {}),
        **({"preshared_key": preshared} if preshared else {}),
    }
    _save_registry(registry)

    conf = build_client_conf(
        private_key=private, ip=address, mode=mode, preshared_key=preshared
    )
    apply_result = apply_live()
    return {
        "ok": True,
        "name": label,
        "ip": address,
        "pub": public,
        "mode": mode,
        "psk": preshared,
        "client_conf": conf,
        "reissuable": bool(keep_key),
        "applied": apply_result.get("ok", False),
        "endpoint_configured": bool(_endpoint_for_clients()),
    }


def batch_add(
    *,
    count: int,
    prefix: str = "peer",
    mode: str = "split",
    psk: bool = False,
    keep_key: bool = True,
) -> dict:
    """Create several peers in one pass, numbering them from the prefix."""
    try:
        total = int(count)
    except (TypeError, ValueError):
        raise WireGuardError("wg.bad_count")
    if not 1 <= total <= 50:
        raise WireGuardError("wg.bad_count")
    base = str(prefix or "peer").strip() or "peer"
    if not _NAME_RE.match(base):
        raise WireGuardError("wg.bad_name")

    created = []
    for index in range(total):
        # Names must stay unique and within the name pattern; the registry is
        # keyed by public key, so a collision here is only cosmetic.
        label = f"{base}-{index + 1}"[:32]
        created.append(add_peer(name=label, mode=mode, psk=psk, keep_key=keep_key))
    return {"ok": True, "created": len(created), "peers": created}


def del_peer(pubkey: str) -> dict:
    """Remove a peer from the server config and forget its stored key."""
    public = str(pubkey or "").strip()
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.bad_key")
    remaining = [p for p in _peers_for_write() if p["public_key"] != public]
    if len(remaining) == len(_peers_for_write()):
        raise WireGuardError("wg.peer_not_found", pubkey=public[:16])
    _write_conf(remaining)

    registry = _load_registry()
    registry["peers"].pop(public, None)
    _save_registry(registry)

    apply_live()
    return {"ok": True, "pubkey": public, "remaining": len(remaining)}


def import_peer(*, pubkey: str, ip: str, name: str = "", psk: str = "") -> dict:
    """Adopt a peer whose keypair was generated elsewhere.

    Only the public key is known, so the peer is recorded as not re-issuable: the
    panel can route to it but can never regenerate its config.
    """
    public = str(pubkey or "").strip()
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.bad_key")
    if public in {p["public_key"] for p in _peers_for_write()}:
        raise WireGuardError("wg.peer_exists", pubkey=public[:16])
    address = _validate_ip(ip)
    if address.split("/")[0] in used_addresses():
        raise WireGuardError("wg.ip_in_use", ip=address)
    label = str(name or "").strip()
    if label and not _NAME_RE.match(label):
        raise WireGuardError("wg.bad_name")
    preshared = str(psk or "").strip()
    if preshared and not _KEY_RE.match(preshared):
        raise WireGuardError("wg.bad_key")

    peers = _peers_for_write()
    peers.append({
        "public_key": public,
        "ip": address,
        "preshared_key": preshared,
        "name": label,
        "keepalive": settings()["keepalive"],
    })
    _write_conf(peers)

    registry = _load_registry()
    registry["peers"][public] = {
        "name": label,
        "ip": address,
        "mode": "imported",
        "created": int(time.time()),
        **({"preshared_key": preshared} if preshared else {}),
    }
    _save_registry(registry)
    apply_live()
    return {"ok": True, "pubkey": public, "ip": address, "name": label}


def toggle_psk(*, pubkey: str, op: str) -> dict:
    """Add or remove a peer's preshared key.

    Adding one is a breaking change for that client until its config is updated,
    so the new key is returned for the operator to distribute.
    """
    public = str(pubkey or "").strip()
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.bad_key")
    action = (op or "").strip().lower()
    if action not in ("add", "remove"):
        raise WireGuardError("wg.bad_action", action=action[:20])

    peers = _peers_for_write()
    target = next((p for p in peers if p["public_key"] == public), None)
    if target is None:
        raise WireGuardError("wg.peer_not_found", pubkey=public[:16])

    preshared = generate_psk() if action == "add" else ""
    target["preshared_key"] = preshared
    _write_conf(peers)

    registry = _load_registry()
    entry = registry["peers"].setdefault(public, {})
    if preshared:
        entry["preshared_key"] = preshared
    else:
        entry.pop("preshared_key", None)
    _save_registry(registry)

    apply_live()
    return {"ok": True, "pubkey": public, "psk": preshared, "op": action}


def peer_conf(pubkey: str, fmt: str = "wg") -> dict:
    """Re-issue a stored peer's config in *fmt*.

    Only possible for peers whose private key was retained; anything else would
    require the client to be re-enrolled, and saying so is better than emitting a
    config with a placeholder key that silently never connects.
    """
    public = str(pubkey or "").strip()
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.bad_key")
    meta = _registry_peers().get(public)
    if not meta:
        raise WireGuardError("wg.peer_unknown", pubkey=public[:16])
    private = str(meta.get("private_key") or "")
    if not private:
        raise WireGuardError("wg.peer_not_reissuable", pubkey=public[:16])

    conf = build_client_conf(
        private_key=private,
        ip=str(meta.get("ip") or ""),
        mode=str(meta.get("mode") or "split"),
        preshared_key=str(meta.get("preshared_key") or ""),
    )
    cfg_ = settings()
    name = str(meta.get("name") or "peer")
    rendered = wireguard_export.render(
        fmt, conf, name, lan_cidr=cfg_["lan_cidr"], wg_cidr=cfg_["subnet"]
    )
    return {
        "ok": True,
        "name": name,
        "format": (fmt or "wg").lower(),
        "filename": wireguard_export.filename_for(fmt, name),
        "content": rendered,
    }


def export_all(fmt: str = "wg") -> dict:
    """Every re-issuable peer rendered in *fmt*, for a bulk hand-out."""
    items = []
    skipped = []
    for record in peer_records():
        try:
            items.append(peer_conf(record["public_key"], fmt))
        except WireGuardError:
            skipped.append({
                "pubkey": record["public_key"],
                "name": record["name"],
                "reason": "not_reissuable",
            })
    return {"ok": True, "format": (fmt or "wg").lower(), "items": items, "skipped": skipped}


# ── interface control ────────────────────────────────────────────────────────

def apply_live() -> dict:
    """Push the on-disk config into a running interface without dropping it.

    ``wg syncconf`` reconciles peers in place, so existing tunnels survive a peer
    being added elsewhere in the file.  A full ``wg-quick`` restart would tear down
    every session, which is a poor trade for adding one phone.  When the interface
    is not running there is nothing to sync and this is a no-op.
    """
    cfg_ = settings()
    interface = cfg_["interface"]
    up, _, _ = _dump(interface)
    if not up:
        return {"ok": True, "applied": False, "reason": "not_running"}

    try:
        stripped = strip_conf(conf_path().read_text())
    except OSError:
        return {"ok": False, "error": "conf_unreadable"}
    staged = DATA_DIR / f"{interface}.sync.conf"
    write_secret_text(staged, stripped)

    rc, _, err = sh(["sudo", "-n", WG, "syncconf", interface, str(staged)], timeout=30)
    if rc == 0:
        return {"ok": True, "applied": True}
    result = run_admin([WG, "syncconf", interface, str(staged)], timeout=120)
    if result.get("ok"):
        return {"ok": True, "applied": True}
    return {"ok": False, "error": result.get("error") or "sync_failed", "detail": err[:200]}


#: Where wg-quick records which utun device it assigned to an interface.
WG_RUN_DIR = Path("/var/run/wireguard")


def runtime_state(interface: str | None = None) -> dict:
    """What wg-quick believes about *interface*, read without elevation.

    wg-quick stores the utun it picked in ``<iface>.name`` and the userspace
    driver opens ``<utun>.sock`` alongside it.  A name file with no socket means a
    previous run died between creating the device and finishing setup -- wg-quick
    does not clean up after itself, and from then on every ``up`` aborts with
    ``` `wg0' already exists as `utun8' ``` while ``down`` cannot find the
    interface either.  That combination leaves the tunnel permanently unstartable
    with a message that points at the wrong thing.

    The name file is mode 0400 root, so its contents are unreadable here; presence
    plus the absence of any socket is the signal, and both are visible from a stat.
    """
    iface = interface or settings()["interface"]
    name_file = WG_RUN_DIR / f"{iface}.name"
    try:
        sockets = sorted(p.name for p in WG_RUN_DIR.glob("*.sock"))
    except OSError:
        sockets = []
    recorded = name_file.exists()
    return {
        "interface": iface,
        "name_file": str(name_file),
        "name_file_present": recorded,
        "sockets": sockets,
        # Claimed by a previous run, but nothing is actually serving it.
        "stale": recorded and not sockets,
    }


def interface_action(action: str) -> dict:
    """Bring the tunnel up, down, or cycle it."""
    verb = (action or "").strip().lower()
    if verb not in ("up", "down", "restart"):
        raise WireGuardError("wg.bad_action", action=verb[:20])
    path = str(conf_path())
    if not Path(path).exists():
        raise WireGuardError("wg.no_conf", path=path)

    if verb == "restart":
        commands = [[BASH, WG_QUICK, "down", path], [BASH, WG_QUICK, "up", path]]
    else:
        commands = [[BASH, WG_QUICK, verb, path]]

    # Clear a claim left behind by a run that died mid-setup.  Without this the
    # operator is stuck for good: `up` refuses because wg-quick still thinks the
    # interface exists, and `down` cannot remove the record because the device it
    # names is gone.  Only done when nothing is actually serving the interface, so
    # a live tunnel is never orphaned by this.
    stale = runtime_state(cfg_interface := settings()["interface"])
    if verb in ("up", "restart") and stale["stale"]:
        commands.insert(0, [RM, "-f", stale["name_file"]])
    del cfg_interface

    # sudo -n first so an operator with the packaged sudoers rule is not
    # prompted on every restart; without a rule the sequence falls through to
    # run_admin_sequence, which either uses the web-entered administrator
    # password or reports "password_required" so the SPA can ask for it.
    for command in commands:
        rc, _, _ = sh(["sudo", "-n", *command], timeout=60)
        if rc != 0:
            return run_admin_sequence(commands, timeout=180)
    return {"ok": True, "action": verb}


def view_conf(reveal: bool = False) -> dict:
    """The server config as text, private key redacted unless explicitly revealed."""
    try:
        text = conf_path().read_text()
    except OSError:
        raise WireGuardError("wg.no_conf", path=str(conf_path()))
    if reveal:
        return {"ok": True, "conf": text, "redacted": False}
    redacted = re.sub(
        r"(?im)^(PrivateKey\s*=\s*).*$", r"\1[redacted]", text
    )
    return {"ok": True, "conf": redacted, "redacted": True}


def ping_peers(timeout_ms: int = 800) -> dict:
    """ICMP-probe each peer's tunnel address.

    Reachability here is a stronger signal than a recent handshake: a handshake
    only proves the peer's WireGuard is alive, not that traffic crosses the tunnel
    (a missing route or NAT rule breaks the second without touching the first).
    """
    results = []
    deadline = max(200, min(int(timeout_ms or 800), 5000))
    for record in peer_records():
        host = record["ip"].split("/")[0].split(",")[0].strip()
        if not host:
            continue
        rc, out, _ = sh(
            ["/sbin/ping", "-c", "1", "-W", str(deadline), "-n", host], timeout=8
        )
        match = re.search(r"time=([\d.]+)\s*ms", out or "")
        results.append({
            "pubkey": record["public_key"],
            "name": record["name"],
            "ip": host,
            "reachable": rc == 0,
            "latency_ms": float(match.group(1)) if match else None,
        })
    reachable = sum(1 for r in results if r["reachable"])
    return {
        "ok": True,
        "results": results,
        "reachable": reachable,
        "total": len(results),
    }




def port_reachable() -> bool | None:
    """Whether the configured listen port answers locally."""
    return port_open(server_identity()["listen_port"], host="127.0.0.1", timeout=0.5)
