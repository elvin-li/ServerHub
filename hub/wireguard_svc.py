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

import fcntl
import ipaddress
import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from hub import wireguard_export
from hub.config import cfg, update_settings
from hub.macos_admin import (
    run_admin,
    run_admin_sequence,
    sudo_capture,
    sudo_refused,
)
from hub.paths import DATA_DIR, pinned_or
from hub.secure_io import write_secret_text
from hub.util import sh

WG = pinned_or("wg", "/opt/homebrew/bin/wg")
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

#: Where wg-quick records which utun device it assigned to an interface.
WG_RUN_DIR = Path("/var/run/wireguard")

#: Kernel-assigned tunnel devices wireguard-go can land on.
_UTUN_RE = re.compile(r"^utun\d{1,3}$")

#: wg-quick treats a ``<iface>.name`` record as describing a live socket only
#: when the two were created within this many seconds of each other.  Mirrored
#: from its own ``get_real_interface`` so both agree on what counts as live.
_NAME_SOCKET_SKEW = 2

REGISTRY_PATH = DATA_DIR / "wireguard-peers.json"

#: Serialises read-modify-write of the server config *across processes*.
_LOCK_PATH = DATA_DIR / "wireguard.lock"


@contextmanager
def conf_lock() -> Iterator[None]:
    """Hold an exclusive lock over the server config and the peer registry.

    Every peer operation is a read-modify-write of two files: it reads the current
    peer list, appends or removes one, and writes both back.  Without a lock two
    of those interleaving lose a peer outright -- the second writer's snapshot
    predates the first writer's change, so writing it back silently deletes it.
    Address allocation has the same shape and would hand the same IP to two peers.

    An in-process lock is not sufficient here.  A packaged ``ServerHub.app`` and a
    source checkout can both be running against the same state directory -- that
    configuration exists on the machine this was written for, and it is already
    documented as having cost the stored admin credentials the same way.  So this
    is an ``flock``, which the kernel arbitrates between processes.

    The slow part -- pushing the result into the running interface -- is
    deliberately left outside: it re-reads the whole config from disk, so running
    it after another writer's change still applies a consistent file.
    """
    fd = os.open(_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

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


#: A DNS name, deliberately narrow: this value is written verbatim into client
#: config files and into a ``wireguard://`` URL.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


def split_endpoint(value: str) -> tuple[str, str]:
    """``(host, port)`` from an endpoint, port empty when absent.

    An IPv6 literal is full of colons, so "contains a colon" cannot mean "has a
    port".  Both the bracketed form (``[2408:...::1]:51821``) and the bare one
    (``2408:...::1``) have to be understood: the bare form is what an operator
    naturally types, the bracketed form is what has to be written into a config.
    """
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("["):
        host, _, rest = raw.partition("]")
        return host[1:].strip(), rest.lstrip(":").strip()
    if raw.count(":") > 1:
        # More than one colon and no brackets: an unbracketed IPv6 address, which
        # has no room left to express a port.
        return raw, ""
    host, _, port = raw.partition(":")
    return host.strip(), port.strip()


def format_endpoint(host: str, port: int | str) -> str:
    """``host:port``, bracketing *host* when it is an IPv6 literal."""
    text = str(host or "").strip()
    if not text:
        return ""
    if ":" in text:
        text = f"[{text}]"
    return f"{text}:{port}"


def _valid_endpoint(value: str) -> bool:
    """Whether *value* is a dialable ``host`` or ``host:port``.

    Accepts a hostname, an IPv4 literal or an IPv6 literal, bracketed or bare.
    """
    host, port = split_endpoint(value)
    if not host:
        return False
    if port and not (port.isdigit() and 1 <= int(port) <= 65535):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


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
            # A hostname, an IPv4 literal, or an IPv6 literal -- each optionally
            # with a port.  The previous pattern allowed no colons except before a
            # port, which silently made an IPv6 endpoint unconfigurable: on a
            # connection where IPv4 is behind carrier NAT and IPv6 is the only
            # publicly reachable path, that ruled out the only address that works.
            if not _valid_endpoint(str(value)):
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


# ── which device is this interface, really ───────────────────────────────────
#
# On Linux "wg0" is both the wg-quick interface name and the kernel device, so
# `wg show wg0` works and none of this is needed.  macOS has no kernel WireGuard
# driver: wg-quick starts wireguard-go on a *kernel-assigned* utun, records the
# mapping in /var/run/wireguard/wg0.name, and from then on every `wg` subcommand
# must be given the utun.  `wg` itself does no such translation -- it derives the
# UAPI socket path straight from the name it was handed -- so `wg show wg0 dump`
# looks for a wg0.sock that by construction never exists and fails with
# "Unable to access interface: No such file or directory" on a perfectly healthy
# tunnel.  Passing the friendly name here is therefore not a corner case: it made
# the page report "not running" forever, left the peer table without a single
# handshake or byte count, and made `wg syncconf` fail on every peer change, so
# adding or revoking a peer edited the file and never reached the live tunnel.

def _sockets() -> list[str]:
    """Device names of the WireGuard UAPI sockets currently present."""
    try:
        return sorted(p.stem for p in WG_RUN_DIR.glob("*.sock"))
    except OSError:
        return []


def _recorded_device(name_file: Path) -> str:
    """The utun *name_file* names, resolved without elevation.

    The record is mode 0400 root, so reading it usually fails from the panel's
    account.  wg-quick's own fallback works on timestamps -- it accepts a record
    only when the socket it names was created within a couple of seconds of it --
    and that same pairing identifies the device from the outside: the socket whose
    creation is contemporaneous with the record is the one this record describes.
    Using wg-quick's rule rather than inventing one keeps both ends agreeing about
    which tunnels are live.
    """
    try:
        recorded = name_file.read_text(errors="replace").strip()
    except OSError:
        recorded = ""
    if _UTUN_RE.match(recorded) or _IFACE_RE.match(recorded):
        return recorded

    try:
        anchor = name_file.stat().st_mtime
    except OSError:
        return ""
    paired = []
    for device in _sockets():
        try:
            skew = abs((WG_RUN_DIR / f"{device}.sock").stat().st_mtime - anchor)
        except OSError:
            continue
        if skew <= _NAME_SOCKET_SKEW:
            paired.append((skew, device))
    # Two tunnels started in the same second are indistinguishable this way, and
    # guessing between them would point `wg syncconf` at someone else's
    # interface.  Reporting "unknown" is recoverable; that is not.
    if len(paired) == 1:
        return paired[0][1]
    return ""


def real_interface(interface: str | None = None) -> str:
    """The device name ``wg`` answers to for *interface*, or ``""`` if unknown.

    Cheapest and most certain first:

    1. A socket already carries this name -- the interface *is* the device (Linux,
       or an operator who configured a utun outright).
    2. wg-quick left a ``<iface>.name`` record; resolve through it.
    3. Exactly one WireGuard socket exists on the machine, and no record claims
       another name, so it can only be ours.

    Deliberately unprivileged: status is polled every 20 seconds and resolution
    must not cost a sudo round-trip.  When it comes back empty :func:`_dump` falls
    back to identifying the interface by its public key, which does need root.
    """
    iface = interface or settings()["interface"]
    sockets = _sockets()
    if iface in sockets:
        return iface

    name_file = WG_RUN_DIR / f"{iface}.name"
    if name_file.exists():
        return _recorded_device(name_file)

    try:
        others = [p for p in WG_RUN_DIR.glob("*.name") if p.stem != iface]
    except OSError:
        others = []
    claimed = {_recorded_device(p) for p in others}
    unclaimed = [d for d in sockets if d not in claimed]
    if len(unclaimed) == 1:
        return unclaimed[0]
    return ""


# ── live state ───────────────────────────────────────────────────────────────

#: Field counts in `wg show ... dump` output: 5 for the interface row
#: (private key, public key, listen port, fwmark) and 9 for a peer row.  Under
#: `wg show all dump` every row carries the device name in front, which is how a
#: prefixed row is recognised without depending on the caller's arguments.
_DUMP_INTERFACE_FIELDS = 4
_DUMP_PEER_FIELDS = 8


def _redact_keys(text: str) -> str:
    """Blank out anything shaped like a WireGuard key.

    Defence in depth for strings that end up in an API response or a log. The
    callers below already avoid the streams that carry key material; this makes a
    future caller that forgets harmless rather than a disclosure.
    """
    return re.sub(r"[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=", "[redacted]", str(text or ""))


def _tool_error(stderr: str, fallback: str) -> str:
    """A reportable failure reason for a ``wg`` command.

    Deliberately stderr-only.  The obvious-looking ``stderr or stdout`` fallback is
    a disclosure here: the first field of every ``wg show ... dump`` line is the
    interface's *private key*, and this string is returned by the status endpoint
    (which any signed-in session can read) and rendered into the readiness table.
    A partial dump on a non-zero exit would have published the server's private key
    into the page.
    """
    text = _redact_keys(stderr).strip()
    return (text or fallback)[:200]


def _dump_value(field: str) -> str:
    """A dump field, with ``wg``'s placeholder for "no value" turned into empty."""
    text = str(field or "").strip()
    return "" if text in ("(none)", "off") else text


def _dump_rows(text: str, device: str = "") -> list[list[str]]:
    """Tab-separated dump rows, with ``wg show all``'s device column removed.

    The dump format is stable across versions, unlike the human-readable output:
    the first row is the interface (private key, public key, listen port, fwmark)
    and each later row is a peer (public key, preshared key, endpoint, allowed
    ips, latest handshake, rx bytes, tx bytes, persistent keepalive).
    """
    rows = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) in (_DUMP_INTERFACE_FIELDS + 1, _DUMP_PEER_FIELDS + 1):
            # Prefixed by `wg show all dump`; keep only the requested device.
            if device and fields[0] != device:
                continue
            fields = fields[1:]
        rows.append(fields)
    return rows


def _dump_all() -> tuple[dict[str, list[list[str]]], str]:
    """Every WireGuard interface's dump, keyed by device name.

    ``wg show all dump`` is one privileged call for the whole machine, which is
    what makes it usable as a fallback: when the utun cannot be worked out from
    the filesystem, the interface can still be recognised by its own public key.
    """
    rc, out, err = sh([WG, "show", "all", "dump"], timeout=10)
    if rc != 0:
        rc, out, err = sudo_capture([WG, "show", "all", "dump"], timeout=10)
    if rc != 0:
        del out  # carries key material; never reported
        return {}, _tool_error(err, "could not read interface state")
    grouped: dict[str, list[list[str]]] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        grouped.setdefault(fields[0], []).append(fields[1:])
    return grouped, ""


def _identify(grouped: dict[str, list[list[str]]]) -> str:
    """Pick the device serving *our* config out of every running interface.

    The server's public key is the identity: it is derived from the private key in
    wg0.conf and appears in the interface row of the dump, so a match is proof
    rather than a guess.  The listen port is the second-best signal, for the
    window after an operator changed the key on disk without restarting.

    The expected values come from the config file directly rather than from
    :func:`server_identity`, which mints a keypair when the file has none -- a
    write-shaped side effect that has no business firing on a status poll.
    """
    iface_block = read_conf()["interface"]
    try:
        expected_key = public_from_private(str(iface_block.get("PrivateKey") or ""))
    except WireGuardError:
        expected_key = ""
    expected_port = str(iface_block.get("ListenPort") or "").strip()

    by_port = ""
    for device, rows in grouped.items():
        head = rows[0] if rows else []
        if len(head) < 3:
            continue
        if expected_key and head[1].strip() == expected_key:
            return device
        if expected_port and head[2].strip() == expected_port:
            by_port = by_port or device
    if by_port:
        return by_port
    return next(iter(grouped)) if len(grouped) == 1 else ""


def live_interface(interface: str) -> tuple[str, list[list[str]], str]:
    """``(device, dump rows, error)`` for whatever is currently serving *interface*.

    *interface* is the wg-quick name the operator configured; the UAPI socket may
    live under a different, kernel-assigned name.  Resolution is tried from the
    filesystem first because it needs no elevation, then from the dump of every
    interface, which recognises ours by public key.  The device is returned
    alongside the rows because callers that go on to *change* the interface
    (``wg syncconf``) need the same name, and resolving twice means two privileged
    round-trips for one operation.
    """
    device = real_interface(interface)
    first_error = ""
    if device:
        rc, out, err = sh([WG, "show", device, "dump"], timeout=10)
        if rc != 0:
            # The UAPI socket is root-owned: retry with root.  sudo_capture uses
            # the web-entered password when this request carries one (management
            # from another device), else the packaged passwordless sudoers rules.
            rc, out, err = sudo_capture([WG, "show", device, "dump"], timeout=10)
        if rc == 0:
            return device, _dump_rows(out, device), ""
        first_error = _tool_error(err, "")

    grouped, error = _dump_all()
    if not grouped:
        # `wg show interfaces` needs no elevation, so it separates "the tunnel is
        # down" from "the dump could not be read".  Those call for opposite
        # responses -- start the interface, or fix the sudoers rule -- and the old
        # code reported the kernel's "No such file or directory" for both.
        rc, out, _ = sh([WG, "show", "interfaces"], timeout=8)
        if rc == 0 and not out.strip():
            return "", [], "not running"
        return "", [], first_error or error or "interface not found"
    device = _identify(grouped)
    if not device:
        return "", [], first_error or "could not tell which interface is ours"
    return device, grouped[device], ""


def _dump(interface: str) -> tuple[bool, list[list[str]], str]:
    """``(running, rows, error)``, the shape :func:`status` consumes."""
    device, rows, error = live_interface(interface)
    return bool(device), rows, error


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
        # Canonical column order, guaranteed by :func:`_dump_rows`: an interface
        # row is (private key, public key, listen port, fwmark) and a peer row is
        # (public key, preshared key, endpoint, allowed ips, latest handshake,
        # rx, tx, keepalive).  `wg show all dump` prefixes every row with the
        # device name; that column is removed at the point the output is parsed,
        # so nothing downstream has to know which command produced it.
        #
        # Compensating for the prefix *here* instead was tried and is why the page
        # showed the listen port where the server key belongs and reported every
        # peer as never having handshaked: with the column already gone, the
        # shifted indices read one field to the left and the 9-field guard
        # rejected every (8-field) peer row.
        head = rows[0]
        if len(head) >= _DUMP_INTERFACE_FIELDS:
            server_public = head[1].strip()
            try:
                listen_port = int(head[2])
            except ValueError:
                listen_port = 0
        for row in rows[1:]:
            if len(row) < _DUMP_PEER_FIELDS:
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
                # `wg` writes the literal "(none)" for a field it has no value
                # for.  Passed through, that reached the page as a peer whose
                # remote endpoint was the word "(none)"; it means "not connected"
                # and has to read as empty.
                "endpoint": _dump_value(row[2]),
                "allowed_ips": _dump_value(row[3]),
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


def allocate_ip(taken: set[str]) -> str:
    """The lowest address in the subnet that is not in *taken*.

    Takes the claimed set as an argument rather than reading it, so a batch can
    allocate several addresses before any of them is written to disk.  Deriving it
    from the config each time only works if every peer is persisted immediately,
    which is what forced batch creation to rewrite the config once per peer.
    """
    cfg_ = settings()
    network = ipaddress.ip_network(cfg_["subnet"], strict=False)
    server = str(network.network_address + 1)
    for host in network.hosts():
        candidate = str(host)
        if candidate == server or candidate in taken:
            continue
        return f"{candidate}/32"
    raise WireGuardError("wg.subnet_full", subnet=cfg_["subnet"])


def next_ip() -> dict:
    """The lowest free host address in the configured subnet."""
    cfg_ = settings()
    used = used_addresses()
    return {
        "next_ip": allocate_ip(used),
        "used": len(used),
        "subnet": cfg_["subnet"],
    }


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
    host, port = split_endpoint(settings()["endpoint"])
    if not host:
        return ""
    return format_endpoint(host, port or server_identity()["listen_port"])


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

    with conf_lock():
        # Allocation reads the claimed set and the write commits it; both have to
        # be inside one lock or two concurrent additions get the same address.
        entry, meta, result = _mint_peer(
            label=label, ip=ip, mode=mode, psk=psk, keep_key=keep_key,
            taken=used_addresses(),
        )
        peers = _peers_for_write()
        peers.append(entry)
        _write_conf(peers)

        registry = _load_registry()
        registry["peers"][entry["public_key"]] = meta
        _save_registry(registry)

    apply_result = apply_live()
    result["applied"] = apply_result.get("ok", False)
    return result


def _mint_peer(
    *,
    label: str,
    ip: str,
    mode: str,
    psk: bool,
    keep_key: bool,
    taken: set[str],
) -> tuple[dict, dict, dict]:
    """Generate one peer's keys and records without writing anything.

    Split out so a batch can mint every peer first and persist once.  *taken* is
    the set of addresses already claimed, and the caller extends it between calls;
    that is what lets several peers be allocated before any of them is on disk.
    """
    address = _validate_ip(ip) if ip else allocate_ip(taken)
    if address.split("/")[0] in taken:
        raise WireGuardError("wg.ip_in_use", ip=address)

    private, public = generate_keypair()
    preshared = generate_psk() if psk else ""

    entry = {
        "public_key": public,
        "ip": address,
        "preshared_key": preshared,
        "name": label,
        "keepalive": settings()["keepalive"],
    }
    meta = {
        "name": label,
        "ip": address,
        "mode": mode,
        "created": int(time.time()),
        # Retaining the private key is what makes re-issue possible; opting out
        # keeps only the public half, so the config handed back is the single copy.
        **({"private_key": private} if keep_key else {}),
        **({"preshared_key": preshared} if preshared else {}),
    }
    result = {
        "ok": True,
        "name": label,
        "ip": address,
        "pub": public,
        "mode": mode,
        "psk": preshared,
        "client_conf": build_client_conf(
            private_key=private, ip=address, mode=mode, preshared_key=preshared
        ),
        "reissuable": bool(keep_key),
        "applied": False,
        "endpoint_configured": bool(_endpoint_for_clients()),
    }
    return entry, meta, result


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

    if (mode or "").lower() not in ("full", "split"):
        raise WireGuardError("wg.bad_mode", mode=str(mode)[:20])
    mode = mode.lower()

    # Every peer is minted first and the config is written once.  Calling add_peer
    # in a loop rewrote wg0.conf, took a backup and ran a privileged `wg syncconf`
    # for each one -- fifty of each for a batch of fifty, which is slow enough to
    # outrun the request timeout and leaves a partially-created batch behind when
    # it does.
    created = []
    with conf_lock():
        peers = _peers_for_write()
        taken = used_addresses()
        registry = _load_registry()
        for index in range(total):
            # Names must stay unique and within the name pattern; the registry is
            # keyed by public key, so a collision here is only cosmetic.
            label = f"{base}-{index + 1}"[:32]
            entry, meta, result = _mint_peer(
                label=label, ip="", mode=mode, psk=psk, keep_key=keep_key, taken=taken
            )
            peers.append(entry)
            registry["peers"][entry["public_key"]] = meta
            taken.add(entry["ip"].split("/")[0])
            created.append(result)

        _write_conf(peers)
        _save_registry(registry)
    applied = apply_live().get("ok", False)
    for result in created:
        result["applied"] = applied
    return {"ok": True, "created": len(created), "peers": created}


def del_peer(pubkey: str) -> dict:
    """Remove a peer from the server config and forget its stored key."""
    public = str(pubkey or "").strip()
    if not _KEY_RE.match(public):
        raise WireGuardError("wg.bad_key")
    with conf_lock():
        # One read, not two.  Comparing against a second, independent read of the
        # config meant a peer added between them made the counts match and the
        # deletion report "no such peer" -- while the first read, which no longer
        # contained that new peer, was what got written back, silently dropping it.
        peers = _peers_for_write()
        remaining = [p for p in peers if p["public_key"] != public]
        if len(remaining) == len(peers):
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
    address = _validate_ip(ip)
    label = str(name or "").strip()
    if label and not _NAME_RE.match(label):
        raise WireGuardError("wg.bad_name")
    preshared = str(psk or "").strip()
    if preshared and not _KEY_RE.match(preshared):
        raise WireGuardError("wg.bad_key")

    with conf_lock():
        if address.split("/")[0] in used_addresses():
            raise WireGuardError("wg.ip_in_use", ip=address)
        peers = _peers_for_write()
        if public in {p["public_key"] for p in peers}:
            raise WireGuardError("wg.peer_exists", pubkey=public[:16])
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

    with conf_lock():
        peers = _peers_for_write()
        target = next((p for p in peers if p["public_key"] == public), None)
        if target is None:
            raise WireGuardError("wg.peer_not_found", pubkey=public[:16])

        preshared = generate_psk() if action == "add" else ""
        target["preshared_key"] = preshared
        _write_conf(peers)

        # Only update a registry entry that already exists.  `setdefault` used to
        # create one for peers this panel never issued, which is how toggling a PSK
        # on an imported peer quietly reclassified it: `peer_records` reads "has a
        # registry entry" as `known`, so the peer stopped counting as foreign and
        # the copied-from-another-server detection lost sight of it.  The stored
        # copy is only ever used to re-issue a config, which needs a private key
        # this peer does not have, so fabricating the entry bought nothing either.
        registry = _load_registry()
        entry = registry["peers"].get(public)
        if entry is not None:
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

    The two sources are used for what each is authoritative about.  The server
    config decides what the tunnel will *accept* -- the peer's address and its
    preshared key -- so those are read from there.  The registry supplies only what
    a server config cannot hold: the client's private key, its name, and its tunnel
    mode.

    Taking the address and the preshared key from the registry as well was wrong in
    a way that is invisible until a client tries to connect: the two files are
    written in sequence and can be restored from backups independently, and this
    host has already had that happen more than once.  Once they disagree, the panel
    hands out a config the server is guaranteed to reject, and the operator sees a
    client that will not connect with nothing anywhere explaining why.
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

    configured = next(
        (r for r in peer_records() if r["public_key"] == public), None
    )
    if configured is None:
        # In the registry but not in the config: the peer was removed from the
        # server, so a config for it could only ever fail to connect.
        raise WireGuardError("wg.peer_not_found", pubkey=public[:16])

    conf = build_client_conf(
        private_key=private,
        ip=configured["ip"] or str(meta.get("ip") or ""),
        mode=str(meta.get("mode") or "split"),
        preshared_key=configured["preshared_key"],
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
    # `wg` addresses the kernel-assigned device, not the wg-quick name.  Passing
    # the friendly name made every sync fail, so a peer added through the panel
    # landed in the file and never in the running tunnel until a full restart.
    device, _, _ = live_interface(interface)
    if not device:
        return {"ok": True, "applied": False, "reason": "not_running"}

    try:
        stripped = strip_conf(conf_path().read_text())
    except OSError:
        return {"ok": False, "error": "conf_unreadable"}
    staged = DATA_DIR / f"{interface}.sync.conf"
    write_secret_text(staged, stripped)

    rc, _, err = sh(["sudo", "-n", WG, "syncconf", device, str(staged)], timeout=30)
    if rc == 0:
        return {"ok": True, "applied": True, "device": device}
    result = run_admin([WG, "syncconf", device, str(staged)], timeout=120)
    if result.get("ok"):
        return {"ok": True, "applied": True, "device": device}
    return {"ok": False, "error": result.get("error") or "sync_failed", "detail": err[:200]}


def runtime_state(interface: str | None = None) -> dict:
    """What wg-quick believes about *interface*, read without elevation.

    wg-quick stores the utun it picked in ``<iface>.name`` and the userspace
    driver opens ``<utun>.sock`` alongside it.  A record with no live socket means
    a previous run died between creating the device and finishing setup -- wg-quick
    does not clean up after itself, and from then on every ``up`` aborts with
    ``` `wg0' already exists as `utun8' ``` while ``down`` cannot find the
    interface either.  That combination leaves the tunnel permanently unstartable
    with a message that points at the wrong thing.

    Staleness is judged against *the socket this record names*, resolved through
    :func:`real_interface`.  Judging it against "any socket at all" was wrong on
    any machine running a second userspace tunnel: that tunnel's socket made a
    genuinely stale record look healthy, the automatic cleanup never fired, and
    the interface stayed unstartable with no indication why.
    """
    iface = interface or settings()["interface"]
    name_file = WG_RUN_DIR / f"{iface}.name"
    recorded = name_file.exists()
    device = real_interface(iface)
    live = bool(device) and (WG_RUN_DIR / f"{device}.sock").exists()
    return {
        "interface": iface,
        "name_file": str(name_file),
        "name_file_present": recorded,
        "sockets": [f"{name}.sock" for name in _sockets()],
        "real_interface": device,
        "live": live,
        # Claimed by a previous run, but nothing is actually serving it.
        "stale": recorded and not live,
    }


#: `wg-quick down` on macOS walks every network service with `networksetup` to
#: restore DNS and deletes one route per peer, all serially.  The old 60s budget
#: expired part-way through on a host with several services and a handful of
#: peers, and the timeout kills sudo mid-teardown: the socket is already gone but
#: `<iface>.name` has not been removed yet, which is precisely the wedged state
#: the stale-claim cleanup exists to undo.  Better not to create it.
_WG_QUICK_TIMEOUT = 180


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
    state = runtime_state(settings()["interface"])
    if verb in ("up", "restart") and state["stale"]:
        commands.insert(0, [RM, "-f", state["name_file"]])

    # Asking for `up` on a tunnel that is already serving traffic is not a
    # failure, and it must not be treated as one: the previous code answered
    # wg-quick's "already exists" by tearing the interface down and bringing it
    # back, dropping every live session to reach a state that already held.
    if verb == "up" and state["live"]:
        return {"ok": True, "action": verb, "already_running": True}

    # sudo -n first so an operator with the packaged sudoers rule is not
    # prompted on every restart.  A *refusal* from sudo means no rule covers this
    # and the sequence is retried through run_admin_sequence, which either uses
    # the web-entered administrator password or reports "password_required" so
    # the SPA can ask for it.  A failure from wg-quick itself is reported as
    # itself -- no password can fix a bad config, and saying "password required"
    # sent operators looking in the wrong place entirely.
    for command in commands:
        rc, out, err = sh(["sudo", "-n", *command], timeout=_WG_QUICK_TIMEOUT)
        if rc == 0:
            continue
        if sudo_refused(err):
            return run_admin_sequence(commands, timeout=_WG_QUICK_TIMEOUT + 60)
        combined = ((err or "") + "\n" + (out or "")).strip()
        # A zombie claim can appear between the check above and this call (or the
        # record can name a device that has since gone).  One repair attempt,
        # only when nothing is serving the interface.
        if verb in ("up", "restart") and "already exists" in combined:
            fresh = runtime_state(settings()["interface"])
            if fresh["live"]:
                return {"ok": True, "action": verb, "already_running": True}
            sh(["sudo", "-n", RM, "-f", fresh["name_file"]], timeout=20)
            rc, out, err = sh(["sudo", "-n", *command], timeout=_WG_QUICK_TIMEOUT)
            if rc == 0:
                continue
            combined = ((err or "") + "\n" + (out or "")).strip()
        return {
            "ok": False,
            "error": "failed",
            "message": _wg_quick_reason(combined),
        }
    return {"ok": True, "action": verb}


def _wg_quick_reason(output: str) -> str:
    """The line of wg-quick output that says what went wrong.

    wg-quick echoes every command it runs with a ``[#]`` prefix, so its stderr is
    mostly a transcript.  Surfacing the tail of that verbatim buries the one line
    that matters under `route`/`networksetup` noise; its own diagnostics are the
    ones prefixed ``wg-quick:``.
    """
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    diagnostics = [line for line in lines if line.lower().startswith("wg-quick:")]
    chosen = diagnostics or [line for line in lines if not line.startswith("[")] or lines
    # wg-quick's transcript should not contain key material -- it feeds the config
    # through a file descriptor rather than an argument -- but this string is
    # returned to the browser, so it is redacted rather than trusted to stay clean.
    return _redact_keys(" ".join(chosen))[-300:]


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
