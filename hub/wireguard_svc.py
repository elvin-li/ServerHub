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
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from hub import wireguard_export, wireguard_wstunnel
from hub.config import cfg, settings_section, update_settings
from hub.macos_admin import (
    run_admin,
    run_admin_sequence,
    sudo_capture,
    sudo_refused,
)
from hub.paths import DATA_DIR, pinned_or
from hub.secure_io import drop_leftover_nonfile, replace_secret_text
from hub.util import fan_out, read_text_capped, safe_json_loads, sh, strftime_now, utf8_env

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
        try:
            if Path(candidate).exists():
                return candidate
        except (OSError, ValueError, TypeError):
            # Dying-mount ``exists`` EIO used to 500 import of this module.
            continue
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

#: Leftover multi-MB junk in these small files used to OOM GET /api/wireguard.
_CONF_CAP = 256 * 1024
_KEY_CAP = 256
_NAME_CAP = 64
_REGISTRY_CAP = 256 * 1024

#: Serialises read-modify-write of the server config *across processes*.
_LOCK_PATH = DATA_DIR / "wireguard.lock"

#: In-process fallback when the flock file cannot be opened at all; weaker
#: than the flock (it does not see the other process) but strictly better
#: than refusing every peer change outright.
_LOCK_FALLBACK = threading.Lock()


def _lock_fd() -> int | None:
    """flock fd for :data:`_LOCK_PATH`, or None when a leftover node blocks it.

    A leftover directory occupying ``data/wireguard.lock`` made the bare
    ``os.open`` raise EISDIR — a raw 500 out of every peer mutation (create,
    batch, delete, import, PSK toggle) before any validation ran, exactly the
    class :func:`hub.config._file_lock` already degrades for services.yaml.
    An *empty* leftover (directory or FIFO) is cleared so the cross-process
    lock self-heals; anything that still cannot be opened (a non-empty
    directory, EIO on a dying mount) reports None and the caller falls back.
    """
    drop_leftover_nonfile(_LOCK_PATH)
    try:
        _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        return os.open(_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None


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

    A leftover node at the lock path, or EIO out of ``os.open``/``flock`` on a
    dying mount, degrades to the in-process fallback lock rather than a raw
    500: the peer change is still serialised within this process, and refusing
    it entirely would not protect anything the broken lock file was guarding.
    """
    fd = _lock_fd()
    if fd is None:
        with _LOCK_FALLBACK:
            yield
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            with _LOCK_FALLBACK:
                yield
            return
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
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

def _as_text(value) -> str:
    """``wg`` leftovers used to leak ``bytes``/None/``\\ud800`` into JSON.

    Unbound through the base types (the brew_svc/docker_cli convention): a
    leftover bytes-subclass whose bound ``.decode`` raises, or a str-subclass
    whose ``__str__`` returns itself and whose bound ``.encode`` raises, used
    to detonate this launderer instead of costing only the poisoned value —
    a raw 500 out of GET /api/wireguard, /readiness and POST /ping.

    :func:`_isa` gates, not bare ``isinstance``: this launderer is the first
    thing every leftover value hits, and a value whose ``__class__`` is a
    *raising property* detonated the type gates themselves (isinstance
    consults ``__class__`` when the exact-type check misses) — a raw 500 on
    GET /api/wireguard, GET /api/wireguard/settings and POST
    /api/wireguard/ping for a value this function exists to absorb.

    The unbound base calls run inside a ``try``: a *lying*-``__class__``
    impostor (the docker10/json9 shape — ``isinstance`` answers bytes / str,
    the real object is neither) passes the ``_isa`` gate but makes the
    unbound ``bytes.decode`` / ``str.encode`` descriptor itself raise
    ``TypeError`` — the exact raw 500 on POST /api/wireguard/ping that a
    bytes-liar peer ``ip`` / ``name`` / ``public_key`` reproduced.  A liar
    falls through to the generic ``str()`` probe like any other leftover.
    """
    text = None
    if _isa(value, bytes):
        try:
            text = bytes.decode(value, "utf-8", "replace")
        except Exception:
            text = None
    elif _isa(value, bytearray):
        try:
            text = bytearray.decode(value, "utf-8", "replace")
        except Exception:
            text = None
    elif _isa(value, str):
        text = value
    elif value is None:
        return ""
    if text is None:
        # A bytes/bytearray impostor whose unbound decode just raised, or a
        # value that is not text at all: coerce through a guarded ``str()``.
        try:
            text = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except Exception:
        # A str-liar rode the ``_isa(value, str)`` branch as *text* itself,
        # and unbound ``str.encode`` cannot apply to it — one last guarded
        # ``str()`` renders its honest ``__str__`` instead of 500ing.
        try:
            return str.encode(str(value), "utf-8", "replace").decode("utf-8")
        except Exception:
            try:
                return type(value).__name__
            except Exception:
                return ""


def _path_exists(path) -> bool:
    """``Path.exists()`` raises EIO/ESTALE; leftover dying mounts 500'd GET /api/wireguard."""
    try:
        return Path(path).exists()
    except (OSError, ValueError, TypeError):
        return False


def _path_is_dir(path) -> bool:
    """``Path.is_dir()`` re-raises EIO/ESTALE; that used to 500 GET /api/wireguard."""
    try:
        return Path(path).is_dir()
    except (OSError, ValueError, TypeError):
        return False


def _now() -> int:
    """Finite unix timestamp. Leftover ``time.time() = inf`` OverflowError'd GET /api/wireguard."""
    try:
        return int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0


def _conf_int(raw, fallback) -> int:
    """Parse a conf field that operators sometimes write as ``51820/udp``.

    The old blank probe ``raw not in (None, "")`` ran a *reflected*
    ``__eq__`` on the stored value, and the bare ``int(...)`` dispatched
    into a numeric subclass's ``__int__`` — either bomb raised past the
    arithmetic-trio except and 500'd GET /api/wireguard on a conf/registry
    value the coercion below degrades anyway.  Identity/isinstance gates
    first, then everything through :func:`_plain_int`, which never raises.
    """
    blank = raw is None or (
        _isa(raw, (str, bytes, bytearray)) and not _as_text(raw).strip()
    )
    number = _plain_int(fallback if blank else raw)
    if number is None:
        number = _plain_int(fallback)
    return 0 if number is None else number


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__``/``__len__`` bomb."""
    try:
        return bool(value)
    except Exception:
        return False


def _plain_mapping_get(mapping, key):
    """Unbound ``dict.get`` behind the liar-proof shape gate, or None.

    The read side of every ``dict.get(x, k) if isinstance(x, dict)`` seam:
    ``_isa`` absorbs a raising-``__class__`` property, and the ``try``
    absorbs a *lying*-``__class__`` impostor (the brew10/json9 shape —
    ``isinstance`` answers dict, the real object is a plain object) that
    passes the gate and makes the descriptor itself raise TypeError.
    """
    if not _isa(mapping, dict):
        return None
    try:
        return dict.get(mapping, key)
    except Exception:
        return None


def _nonfinite(value) -> bool:
    # _isa: a raising-``__class__``-property leftover detonated the bare gate.
    if not _isa(value, float):
        return False
    try:
        # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
        # bomb used to raise out of the NaN/inf probes below and 500 the
        # caller instead of costing only the poisoned value.
        value = float.__float__(value)
    except Exception:
        return True
    return value != value or value in (float("inf"), float("-inf"))


def _plain_int(value):
    """Exact int, or None when *value* cannot safely become one.

    Base-type coercions throughout (``int.__index__``, ``float.__float__``,
    text via :func:`_as_text`): a stored numeric-subclass whose ``__int__`` /
    ``__index__`` / ``__eq__`` raises used to blow the bare ``int(...)`` in
    :func:`settings` — a raw 500 on GET /api/wireguard, GET
    /api/wireguard/settings and /readiness, on a value the range check below
    would have rejected anyway.  Over-cap digit runs (CPython's 4300-digit
    str->int cap) degrade to None the same way.  :func:`_isa` gates
    throughout: a raising-``__class__``-property leftover detonated the bare
    ``isinstance`` checks themselves.
    """
    # Identity, not _isa: bool cannot be subclassed, so a real bool is only
    # ever the two singletons.  A *lying*-``__class__`` impostor (the
    # brew10/json9 shape — ``isinstance`` answers bool, the real object is a
    # plain object) passed the old ``_isa(value, bool)`` gate and detonated
    # the bare ``int(value)`` with TypeError — a raw 500 on GET
    # /api/wireguard and GET /api/wireguard/settings for a stored
    # ``listen_port`` this function exists to range-check.  The liar now
    # falls through to the guarded int branch and degrades to None.
    if value is True or value is False:
        return int(value)
    if _isa(value, int):
        try:
            value = int.__index__(value)
            # str() probe (the _save_registry rule): an over-cap already-int
            # (YAML hex/octal, a poisoned registry merge) renders through
            # int->str, which CPython caps at 4300 digits — json.dumps
            # ValueErrors past it, one layer after the range checks passed.
            str(value)
            return value
        except Exception:
            return None
    if _isa(value, float):
        try:
            value = float.__float__(value)
        except Exception:
            return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return int(value)
    if _isa(value, (str, bytes, bytearray)):
        try:
            return int(_as_text(value).strip())
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _usable_network(value):
    """An IP network that still has room for the server address (network + 1).

    ``255.255.255.255/32`` parses, then ``network_address + 1`` raises
    AddressValueError and 500'd next-ip / peer-create / conf writes.
    """
    try:
        network = ipaddress.ip_network(str(value), strict=False)
        network.network_address + 1
        return network
    except (TypeError, ValueError, OverflowError):
        return None


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
    "wstunnel_enabled": False,
    "wstunnel_listen": wireguard_wstunnel.DEFAULT_LISTEN,
    "wstunnel_public": "",
    "wstunnel_restrict_to": "",
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
    if port:
        try:
            if not (port.isdigit() and 1 <= int(port) <= 65535):
                return False
        except ValueError:
            # isdigit() bounds neither length (CPython caps str->int at 4300
            # digits) nor the digit class (``²`` passes isdigit but not int);
            # the ValueError used to 500 PUT /api/wireguard/settings.
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
    # Unbound ``dict.items`` behind a provider guard (the save_settings
    # ``dict.get`` rule): this read does not own ``settings_section`` — tests
    # and tooling patch it — and a section that raises, or arrives as a dict
    # *subclass* whose bound ``.items`` bombs, used to 500 every WireGuard
    # read (GET /api/wireguard, /settings, /readiness, /next-ip).
    try:
        stored = settings_section("wireguard")
    except Exception:
        stored = {}
    merged = dict(DEFAULTS)
    # _isa, not bare isinstance: a patched section whose ``__class__`` is a
    # raising property detonated the shape gate itself — a raw 500 on GET
    # /api/wireguard and GET /api/wireguard/settings before any value ran.
    # The unbound ``dict.items`` runs inside a ``try``: a *lying*-``__class__``
    # impostor (the brew10/json9 shape — ``isinstance`` answers dict, the
    # real object is a plain object) passed the ``_isa`` gate and made the
    # descriptor itself raise TypeError — the same raw 500 on both reads the
    # gate exists to stop.  A liar section reads as empty and every key
    # keeps its default.
    items = ()
    if _isa(stored, dict):
        try:
            items = dict.items(stored)
        except Exception:
            items = ()
    for key, value in items:
        # Per-item try (the mapping-key lesson): ``key not in merged`` and
        # ``DEFAULTS[key]`` both run the stored *key*'s own hash/__eq__ —
        # dict lookup calls the probe key's reflected ``__eq__`` first when
        # it is a str subclass — so one poisoned key used to 500 every
        # settings read.  A bomb key now costs only its own entry; sibling
        # keys keep merging.
        try:
            if key not in merged or value is None:
                continue
            # YAML leftover ``endpoint: 2026-08-19`` / ``!!binary`` / ``!!set``
            # used to leak into GET /api/wireguard and GET /api/wireguard/settings
            # under Starlette's encoder (this payload never went through _jsonable).
            #
            # Type-gated per key, and *before* any probe that calls into the
            # value: the old ``value in (None, "")`` blank test invoked a stored
            # subclass's ``__eq__``, and the bytes launder called its bound
            # ``.decode`` — either bomb was a raw 500 out of every settings read.
            expected = DEFAULTS[key]
            if isinstance(expected, bool):
                # Identity, not _isa: bool cannot be subclassed, so a real
                # stored flag is only ever the two singletons (False is a
                # real value for wstunnel_enabled; keep it).  The old
                # ``_isa(value, bool)`` gate let a lying-``__class__``
                # impostor ride into ``merged`` as itself, and Starlette's
                # ``json.dumps`` refused the object — a raw 500 on GET
                # /api/wireguard/settings for a value the gate exists to
                # keep out.  A liar now keeps the default.
                if value is True or value is False:
                    merged[key] = value
                continue
            if isinstance(expected, str):
                if _isa(value, (str, bytes, bytearray)):
                    # _as_text launders surrogates, bytes, and subclass
                    # encode/decode bombs into an exact str; blanks keep the
                    # default, as before.
                    text = _as_text(value)
                    if text:
                        merged[key] = text
                continue
            # Numeric keys: kept raw here, coerced and range-checked below.
            merged[key] = value
        except Exception:
            continue
    iface = str(merged["interface"])
    if not _IFACE_RE.match(iface):
        merged["interface"] = DEFAULTS["interface"]
    if _usable_network(merged["subnet"]) is None:
        merged["subnet"] = DEFAULTS["subnet"]
    # Same ranges save_settings enforces.  services.yaml is hand-editable and
    # a YAML hex/octal int skips CPython's str->int digit cap (base 16/8 are
    # exempt), so ``listen_port: 0x<4300+ digits>`` parsed here as an over-cap
    # int and then ValueError'd ``json.dumps`` itself — GET /api/wireguard,
    # GET /api/wireguard/settings and the Network overview's wstunnel snapshot
    # all 500'd on a value the write path would have rejected.  _plain_int
    # rather than a bare int(): a numeric-subclass ``__int__``/``__index__``
    # bomb raised past the old (TypeError, ValueError, OverflowError) tuple.
    for key, low, high in (
        ("listen_port", 1, 65535),
        ("mtu", 576, 1500),
        ("keepalive", 0, 3600),
    ):
        number = _plain_int(merged[key])
        if number is None or not (low <= number <= high):
            number = DEFAULTS[key]
        merged[key] = number
    for key, value in merged.items():
        if isinstance(value, str):
            merged[key] = _as_text(value)
    return merged


def save_settings(patch: dict) -> dict:
    """Persist a subset of the WireGuard settings after validating each field."""
    # Unbound ``dict.get``, the settings_section lesson: a leftover config
    # root (or ``settings`` map) that is a dict *subclass* with a bombing
    # ``.get`` raised straight out of the bare method calls here and 500'd
    # PUT /api/wireguard/settings — plus POST /api/wireguard/remediate for
    # the wstunnel targets, whose uninstall/stabilize paths save settings.
    #
    # _isa gates plus a ``try`` around each unbound call (the brew10/json9
    # liar rule): a root whose ``__class__`` is a raising property
    # detonated the bare ``isinstance`` itself, and a *lying*-``__class__``
    # impostor passed the gate and made ``dict.get`` / ``dict(...)`` raise
    # TypeError — the same raw 500 on PUT /api/wireguard/settings this
    # shape-degrade exists to stop.  A liar reads as an empty section; the
    # validated patch below still persists.
    data = cfg()
    raw = _plain_mapping_get(data, "settings")
    stored = _plain_mapping_get(raw, "wireguard")
    current = {}
    if _isa(stored, dict):
        try:
            current = dict(stored)
        except Exception:
            current = {}
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
            if _usable_network(value) is None:
                raise WireGuardError("wg.bad_subnet", subnet=str(value)[:40])
        elif key in ("listen_port", "mtu", "keepalive"):
            try:
                number = int(value)
            except (TypeError, ValueError, OverflowError):
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
        elif key == "wstunnel_enabled":
            if isinstance(value, str):
                value = value.strip().lower() in ("1", "true", "yes", "on")
            else:
                value = bool(value)
        elif key in ("wstunnel_listen", "wstunnel_public") and value:
            if not wireguard_wstunnel.valid_listen_url(str(value)):
                raise WireGuardError("wg.bad_wstunnel_url", url=str(value)[:80])
            value = str(value).strip()
        elif key == "wstunnel_restrict_to" and value:
            if not wireguard_wstunnel.valid_restrict_to(str(value)):
                raise WireGuardError("wg.bad_wstunnel_target", target=str(value)[:60])
            value = str(value).strip()
        current[key] = value
    update_settings({"wireguard": current})
    return settings()


# ── installation & paths ─────────────────────────────────────────────────────

def conf_dir() -> Path:
    for candidate in _CONF_DIRS:
        path = Path(candidate)
        if _path_is_dir(path):
            return path
    return Path(_CONF_DIRS[0])


def conf_path(interface: str | None = None) -> Path:
    return conf_dir() / f"{interface or settings()['interface']}.conf"


def _binary_version(binary: str) -> str:
    """First line of ``<binary> --version``, or "" when it would not answer.

    Deliberately *not* memoised, though it looks like an obvious candidate: the
    string is static and :func:`installation` runs as a route guard on every
    ``/api/wireguard/*`` request as well as inside
    :func:`wireguard_net_svc.readiness`, so a cache would save two spawns per
    readiness read.

    It would also make a transient failure sticky.  ``installation`` reports
    ``probe_failed`` from this result, and the whole point of that field -- see the
    comment below -- is that a one-off timeout must not be treated as authoritative.
    Caching "" for a TTL turns a blip into a minute of the panel insisting the tools
    are degraded, and caching a success does the same in reverse. Two spawns is not
    worth that, so the duplication is left in place and only the two probes overlap.
    """
    if not _path_exists(binary):
        return ""
    rc, out, err = sh([binary, "--version"], timeout=8)
    # _ping_rc before the comparison (the health9 rc rule): this probe does
    # not own ``sh`` — tests and tooling patch it — and an rc-subclass whose
    # ``__eq__`` raises used to detonate ``rc == 0`` through installation()'s
    # fan_out, a raw 500 on GET /api/wireguard and GET /api/wireguard/settings.
    text = (_as_text(out) or _as_text(err)).strip().splitlines()
    return text[0][:120] if text and _ping_rc(rc) == 0 else ""


def installation() -> dict:
    """Which WireGuard pieces are present, and their versions."""
    # Two unrelated binaries; on a cold cache they answer in one wave instead of two.
    tools, userspace = fan_out(_binary_version, [WG, WIREGUARD_GO], max_workers=2)
    # Presence is decided by the binaries being on disk, not by a subprocess
    # succeeding.  Deriving it from `wg --version` meant any transient failure of
    # that probe -- a timeout under load, a stray non-zero exit -- reported
    # "wireguard-tools is not installed" and refused every operation, which is a
    # wildly misleading answer on a host where it is plainly installed.  The
    # version strings stay best-effort and are only used for display.
    present = _path_exists(WG) and _path_exists(WG_QUICK)
    return {
        "wg": WG if _path_exists(WG) else "",
        "wg_quick": WG_QUICK if _path_exists(WG_QUICK) else "",
        "wireguard_go": WIREGUARD_GO if _path_exists(WIREGUARD_GO) else "",
        "tools_version": tools,
        "userspace_version": userspace,
        "installed": present,
        #: True when the binaries are there but would not answer a version probe;
        #: the page can distinguish "missing" from "installed but misbehaving".
        "probe_failed": present and not tools,
        "conf_dir": str(conf_dir()),
        "conf_path": str(conf_path()),
        "conf_exists": _path_exists(conf_path()),
    }


# ── key material ─────────────────────────────────────────────────────────────

def _cli_missing(rc, err) -> bool:
    """Whether an ``sh()`` result means the ``wg`` binary itself is gone.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` — a
    sentinel, never a real ``wg`` exit.  The route guard checks the binary is
    on disk before the request runs, so an uninstall in between used to turn
    peer create / batch / PSK toggle into a 500 ``wg.keygen_failed`` when the
    truthful answer is the same coded 503 the guard raises.  A timeout keeps
    its own sentinel and stays ``keygen_failed``: a slow wg is not a missing
    one.

    The sentinel alone is not proof (the docker_cli.looks_cli_vanished
    convention: pattern-match, then confirm).  A spawn can FileNotFoundError
    for reasons other than the binary — and answering "wireguard-tools is not
    installed" while ``installation()`` on the same page shows a version
    string sends the operator at the wrong repair.  Confirm on the filesystem
    before claiming the 503; a wg that is still on disk keeps the original
    ``keygen_failed`` mapping.
    """
    # _ping_rc before the comparison (the health9 rc rule): an rc-subclass
    # whose ``__ne__`` raises used to detonate the bare ``rc != -1`` — a raw
    # 500 out of every keygen failure path instead of the coded error.  A
    # bombed honest ``-1`` is salvaged through ``int.__index__`` and still
    # reads as the sentinel; a bomb that cannot answer reads as "not the
    # sentinel" and keeps the original ``keygen_failed`` shape.
    if _ping_rc(rc) != -1 or _as_text(err).strip() != "not found":
        return False
    return not _path_exists(WG)


def _run_with_input(argv: list[str], data: str, *, timeout: int = 8) -> str:
    """Run *argv* feeding *data* on stdin, returning trimmed stdout.

    :func:`hub.util.sh` has no stdin channel, and widening its signature for the
    single caller that needs one would change a helper used across the codebase.
    ``capture_output=True`` used to keep the whole pipe in RAM; ``wg pubkey``
    is tiny, but a wedged child on the peer-create request still could not.
    """
    payload = data.encode("utf-8") if isinstance(data, str) else (data or b"")
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.run(
                    argv,
                    input=payload,
                    stdout=out,
                    stderr=err,
                    timeout=timeout,
                    check=False,
                    env=utf8_env(),
                )
            except (subprocess.TimeoutExpired, OSError, ValueError, TypeError):
                # Leftover ``\\ud800`` argv UnicodeEncodeError is ValueError, not OSError.
                return ""
            captured = getattr(proc, "stdout", None)
            if isinstance(captured, (bytes, bytearray)):
                text = bytes(captured).decode("utf-8", "replace")
            elif isinstance(captured, str):
                text = captured
            else:
                # Live path: stdout is the TemporaryFile.  str(file) used to
                # become the "public key".
                try:
                    out.seek(0)
                    text = out.read(4096).decode("utf-8", "replace")
                except OSError:
                    return ""
            return text.strip() if proc.returncode == 0 else ""
    except OSError:
        return ""


def generate_keypair() -> tuple[str, str]:
    """A fresh (private, public) Curve25519 pair from ``wg genkey`` / ``wg pubkey``."""
    rc, private, err = sh([WG, "genkey"], timeout=8)
    private = _as_text(private).strip()
    # _ping_rc (the health9 rc rule): this spawn does not own ``sh`` — tests
    # and tooling patch it — and an rc-subclass whose ``__eq__``/``__ne__``
    # raises used to detonate the bare ``rc != 0`` — a raw 500 on POST
    # /api/wireguard/peers, /peers/batch and /peers/psk before any coded
    # error could answer.  ``int.__index__`` salvages a bombed honest 0.
    if _ping_rc(rc) != 0 or not _KEY_RE.match(private):
        if _cli_missing(rc, err):
            raise WireGuardError("wg.not_installed")
        raise WireGuardError("wg.keygen_failed")
    public = _run_with_input([WG, "pubkey"], private + "\n")
    if not _KEY_RE.match(public):
        # Fresh on-disk probe, failure path only: an uninstall between the
        # genkey above and this spawn used to report a 500 "could not
        # generate a key" when the truthful answer is the same coded 503 the
        # route guard raises.  A timeout or a real conversion failure with
        # the binary still on disk keeps its original shape.
        if not _path_exists(WG):
            raise WireGuardError("wg.not_installed")
        raise WireGuardError("wg.keygen_failed")
    return private, public


def generate_psk() -> str:
    rc, psk, err = sh([WG, "genpsk"], timeout=8)
    psk = _as_text(psk).strip()
    # _ping_rc: same rc-``__eq__`` bomb launder as :func:`generate_keypair`.
    if _ping_rc(rc) != 0 or not _KEY_RE.match(psk):
        if _cli_missing(rc, err):
            raise WireGuardError("wg.not_installed")
        raise WireGuardError("wg.keygen_failed")
    return psk


def public_from_private(private: str) -> str:
    if not _KEY_RE.match(str(private or "")):
        raise WireGuardError("wg.bad_key")
    public = _run_with_input([WG, "pubkey"], str(private).strip() + "\n")
    if not _KEY_RE.match(public):
        # The stored key already matched _KEY_RE, so an empty answer here is
        # about the tool, not the key.  `wg` uninstalled between the route
        # guard and this spawn used to turn GET /api/wireguard/peers/config
        # and /download into a 400 "invalid WireGuard key" about a key that
        # is fine.  Coded 503 only after a fresh on-disk probe on this
        # failure path; a timeout with the binary still present keeps the
        # original wg.bad_key shape.
        if not _path_exists(WG):
            raise WireGuardError("wg.not_installed")
        raise WireGuardError("wg.bad_key")
    return public


# ── server config ────────────────────────────────────────────────────────────

def read_conf(interface: str | None = None) -> dict:
    """Parse the server config, or an empty skeleton when absent."""
    path = conf_path(interface)
    try:
        text = read_text_capped(path, _CONF_CAP)
    except (OSError, UnicodeDecodeError):
        return {"interface": {}, "peers": []}
    return wireguard_export.parse_conf(text)


def _conf_interface(parsed) -> dict:
    """The parsed ``[Interface]`` block as an *exact* dict, junk shapes empty.

    :func:`read_conf` does not own its provider (tests and tooling patch it,
    and ``wireguard_export.parse_conf`` is patchable the same way): a parsed
    conf whose ``interface`` block is a dict *subclass* with a bombing
    ``.get`` used to raise straight out of the bare method calls in
    :func:`status`, :func:`used_addresses`, :func:`server_identity` and
    :func:`_identify` — a raw 500 on GET /api/wireguard, GET
    /api/wireguard/readiness and GET /api/wireguard/next-ip.  ``dict(...)``
    copies through the C-level storage, bypassing the override; the values
    are still leftovers and stay individually laundered at each use.

    _isa gates: a parsed conf (or block) whose ``__class__`` is a raising
    property used to detonate the bare ``isinstance`` here — a raw 500 on
    GET /api/wireguard out of the very launder that exists to absorb junk.

    The unbound ``dict.get`` runs inside a ``try``: a *lying*-``__class__``
    impostor (the brew10/json9 shape — ``isinstance`` answers dict, the
    real object is a plain object) passed the ``_isa`` gate and made the
    descriptor itself raise TypeError — a raw 500 on GET /api/wireguard,
    /readiness and /next-ip out of a patched ``read_conf``.  A liar parsed
    conf reads as an empty skeleton, exactly like any other junk shape.
    """
    block = None
    if _isa(parsed, dict):
        try:
            block = dict.get(parsed, "interface")
        except Exception:
            block = None
    if not _isa(block, dict):
        return {}
    try:
        return dict(block)
    except Exception:
        return {}


def _plain_rows(value) -> list[dict]:
    """*value* as a list of exact dicts, one junk row costing only itself.

    The :func:`_ping_targets` convention on the listing seams: a peers value
    that is a list *subclass* whose ``__iter__`` raises, or a row that is a
    dict subclass with a bombing ``.get``, used to raise out of the walks in
    :func:`peer_records`, :func:`used_addresses` and :func:`status` — a raw
    500 where a blank row already drops silently.  Unbound ``list.__iter__``
    walks the real entries; ``dict(row)`` launders each row's own methods.

    _isa on every gate (the health9 rule): a listing or row whose
    ``__class__`` is a raising property used to detonate the bare
    ``isinstance`` checks themselves — the same raw 500 they exist to stop.

    Both unbound ``__iter__`` descriptors run inside a ``try`` and fall
    through to the generic ``iter()`` probe (the health10 ``_ping_targets``
    rule): a *lying*-``__class__`` impostor — ``isinstance`` answers tuple,
    the real object is a plain object — passed the ``_isa`` gate and made
    the bare ``tuple.__iter__`` raise TypeError, a raw 500 on GET
    /api/wireguard/next-ip and GET /api/wireguard/export for a peers value
    every other junk shape already degrades to an empty listing.
    """
    if value is None:
        return []
    rows = None
    if _isa(value, list):
        try:
            rows = list.__iter__(value)
        except Exception:
            rows = None
    elif _isa(value, tuple):
        try:
            rows = tuple.__iter__(value)
        except Exception:
            rows = None
    if rows is None:
        try:
            rows = iter(value)
        except Exception:
            return []
    out: list[dict] = []
    try:
        for row in rows:
            if not _isa(row, dict):
                continue
            try:
                out.append(dict(row))
            except Exception:
                continue
    except Exception:
        # An iterator whose __next__ bombs mid-walk keeps the rows walked so far.
        pass
    return out


def _conf_peers(parsed) -> list[dict]:
    """The parsed ``[Peer]`` blocks as exact dicts; see :func:`_conf_interface`."""
    peers = None
    if _isa(parsed, dict):
        try:
            # In a try for the same lying-``__class__`` impostor
            # :func:`_conf_interface` absorbs: the descriptor itself raises.
            peers = dict.get(parsed, "peers")
        except Exception:
            peers = None
    return _plain_rows(peers)


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
        f"# Last written: {strftime_now('%Y-%m-%d %H:%M:%S')}",
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
        keepalive = _conf_int(peer.get("keepalive"), cfg_["keepalive"] or 0)
        if keepalive:
            lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def server_identity() -> dict:
    """The server's own keys and address, creating them on first use."""
    iface = _conf_interface(read_conf())
    cfg_ = settings()
    network = _usable_network(cfg_["subnet"]) or ipaddress.ip_network(
        DEFAULTS["subnet"], strict=False
    )
    default_address = f"{network.network_address + 1}/{network.prefixlen}"

    private = _as_text(iface.get("PrivateKey")).strip()
    if not _KEY_RE.match(private):
        directory = conf_dir()
        key_file = directory / "privatekey"
        try:
            candidate = read_text_capped(key_file, _KEY_CAP).strip()
        except (OSError, UnicodeDecodeError):
            candidate = ""
        private = candidate if _KEY_RE.match(candidate) else ""
    if not private:
        private, _ = generate_keypair()

    return {
        "private_key": private,
        "public_key": public_from_private(private),
        # _as_text first: the old ``iface.get(...) or default`` blank probe
        # reflected into a leftover value's own ``__bool__``.
        "address": _as_text(iface.get("Address")).strip() or default_address,
        "listen_port": _conf_int(iface.get("ListenPort"), cfg_["listen_port"]),
    }


# ── peer registry ────────────────────────────────────────────────────────────

def _journal_int(text: str) -> int:
    """JSON integer literal, with CPython's 4300-digit cap absorbed to 0.

    ``json.loads`` converts integer literals via ``int(str)``, so one leftover
    over-cap number (a hand-edited ``created``, a restored backup) raised
    ValueError — *not* JSONDecodeError — and :func:`_load_registry` degraded
    the whole journal to ``{"peers": {}}``.  Every retained client private key
    then read as gone, and the next peer write persisted that empty view,
    destroying them for real.  One absurd number must not cost the journal.
    """
    try:
        return int(text)
    except ValueError:
        return 0


def _load_registry() -> dict:
    try:
        data = safe_json_loads(
            read_text_capped(REGISTRY_PATH, _REGISTRY_CAP), parse_int=_journal_int
        )
    except (OSError, ValueError, RecursionError):
        return {"peers": {}}
    if not isinstance(data, dict) or not isinstance(data.get("peers"), dict):
        return {"peers": {}}
    peers = {k: v for k, v in data["peers"].items() if isinstance(v, dict)}
    out = dict(data)
    out["peers"] = peers
    return out


def _save_registry(data: dict) -> None:
    def _clean(value, depth: int = 0):
        if depth > 16:
            return None
        if isinstance(value, float) and (
            value != value or value in (float("inf"), float("-inf"))
        ):
            return None
        if isinstance(value, str):
            return _as_text(value)
        if isinstance(value, dict):
            return {_as_text(k): _clean(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [_clean(v, depth + 1) for v in value]
        if isinstance(value, int) and not isinstance(value, bool):
            # str() probe, not an isinstance-str gate: json.dumps renders ints
            # through int->str, which CPython caps at 4300 digits.  One
            # leftover over-cap int used to fail the dump below and silently
            # skip the *whole* journal write for a peer create that reported
            # success.
            try:
                str(value)
            except ValueError:
                return 0
        return value

    drop_leftover_nonfile(REGISTRY_PATH)
    try:
        replace_secret_text(
            REGISTRY_PATH,
            json.dumps(_clean(data), indent=2, ensure_ascii=False, allow_nan=False, default=str),
        )
    except (OSError, TypeError, ValueError, RecursionError):
        # Leftover directory occupying wireguard-peers.json must not 500
        # peer create/import. RecursionError: leftover nested peers after
        # _clean is not OSError.
        pass


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
    # _conf_peers / _as_text throughout: a peers list-subclass __iter__ bomb,
    # a dict-subclass row, or a value whose __bool__/__str__ raises used to
    # 500 every caller of this listing (GET /api/wireguard, /readiness,
    # /next-ip, POST /ping) instead of costing only the junk row.
    for peer in _conf_peers(parsed):
        public = _as_text(peer.get("PublicKey")).strip()
        if not public:
            continue
        meta = registry.get(public) or {}
        if not isinstance(meta, dict):
            meta = {}
        records.append({
            "public_key": public,
            "ip": _as_text(peer.get("AllowedIPs")).strip(),
            "preshared_key": _as_text(peer.get("PresharedKey")).strip(),
            "keepalive": _as_text(peer.get("PersistentKeepalive")).strip(),
            "name": _as_text(meta.get("name")),
            "mode": _as_text(meta.get("mode")),
            "created": _conf_int(meta.get("created"), 0),
            # Whether this peer's config/QR can be produced again.
            "reissuable": _truthy(meta.get("private_key")),
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
    """Device names of the WireGuard UAPI sockets currently present.

    Only names ``wg`` could ever be asked about: a kernel utun or a manageable
    interface name.  Filenames come back surrogateescape'd, so a leftover
    socket with undecodable bytes in its name used to flow through
    :func:`real_interface` / :func:`runtime_state` into
    GET /api/wireguard/readiness (``runtime.sockets`` / ``real_interface``)
    and POST /api/wireguard/sync (``device``) and 500 the UTF-8 encode.
    """
    try:
        stems = sorted(p.stem for p in WG_RUN_DIR.glob("*.sock"))
    except OSError:
        return []
    return [s for s in stems if _UTUN_RE.match(s) or _IFACE_RE.match(s)]


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
        recorded = read_text_capped(name_file, _NAME_CAP, errors="replace").strip()
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
    if _path_exists(name_file):
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
    text = _as_text(field).strip()
    return "" if text in ("(none)", "off") else text


def _dump_rows(text: str, device: str = "") -> list[list[str]]:
    """Tab-separated dump rows, with ``wg show all``'s device column removed.

    The dump format is stable across versions, unlike the human-readable output:
    the first row is the interface (private key, public key, listen port, fwmark)
    and each later row is a peer (public key, preshared key, endpoint, allowed
    ips, latest handshake, rx bytes, tx bytes, persistent keepalive).
    """
    rows = []
    for line in _as_text(text).splitlines():
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
    # _ping_rc on every exit probe: an rc-subclass ``__eq__``/``__ne__`` bomb
    # from a patched/odd sh or sudo_capture used to detonate the bare
    # ``rc != 0`` — a raw 500 on GET /api/wireguard.  ``int.__index__``
    # salvages the honest exit; only a value that cannot answer one fails.
    rc, out, err = sh([WG, "show", "all", "dump"], timeout=10)
    if _ping_rc(rc) != 0:
        rc, out, err = sudo_capture([WG, "show", "all", "dump"], timeout=10)
    if _ping_rc(rc) != 0:
        del out  # carries key material; never reported
        return {}, _tool_error(err, "could not read interface state")
    grouped: dict[str, list[list[str]]] = {}
    for line in _as_text(out).splitlines():
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
    iface_block = _conf_interface(read_conf())
    try:
        expected_key = public_from_private(_as_text(iface_block.get("PrivateKey")))
    except WireGuardError:
        expected_key = ""
    expected_port = _as_text(iface_block.get("ListenPort")).strip()

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
        # _ping_rc on the exit probes (the health9 rc rule): a bombed rc
        # from a patched sh/sudo_capture used to 500 GET /api/wireguard.
        rc, out, err = sh([WG, "show", device, "dump"], timeout=10)
        if _ping_rc(rc) != 0:
            # The UAPI socket is root-owned: retry with root.  sudo_capture uses
            # the web-entered password when this request carries one (management
            # from another device), else the packaged passwordless sudoers rules.
            rc, out, err = sudo_capture([WG, "show", device, "dump"], timeout=10)
        if _ping_rc(rc) == 0:
            return device, _dump_rows(out, device), ""
        first_error = _tool_error(err, "")

    grouped, error = _dump_all()
    if not grouped:
        # `wg show interfaces` needs no elevation, so it separates "the tunnel is
        # down" from "the dump could not be read".  Those call for opposite
        # responses -- start the interface, or fix the sudoers rule -- and the old
        # code reported the kernel's "No such file or directory" for both.
        rc, out, _ = sh([WG, "show", "interfaces"], timeout=8)
        if _ping_rc(rc) == 0 and not _as_text(out).strip():
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
    # A leftover 400-digit ``rx``/``tx`` is a valid int; ``float()`` OverflowError'd
    # GET /api/wireguard.  YAML ``.inf`` is already dropped by ``_conf_int``.
    try:
        size = float(value)
    except (TypeError, ValueError, OverflowError):
        return "0.0B"
    if size != size or size in (float("inf"), float("-inf")) or size < 0:
        return "0.0B"
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
    # This walk does not own the provider (tests and tooling patch
    # ``peer_records``, the :func:`_ping_targets` rule): a listing that
    # raises, a list subclass whose ``__iter__`` bombs, or a junk row must
    # cost only itself, never the whole status poll.
    try:
        records = _plain_rows(peer_records())
    except Exception:
        records = []

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
            server_public = _as_text(head[1]).strip()
            try:
                listen_port = int(_as_text(head[2]).strip() or 0)
            except (TypeError, ValueError, OverflowError):
                listen_port = 0
        for row in rows[1:]:
            if len(row) < _DUMP_PEER_FIELDS:
                continue
            public = _as_text(row[0]).strip()
            try:
                handshake = int(_as_text(row[4]).strip() or 0)
            except (TypeError, ValueError, OverflowError):
                handshake = 0
            try:
                rx, tx = int(_as_text(row[5]).strip() or 0), int(_as_text(row[6]).strip() or 0)
            except (TypeError, ValueError, OverflowError):
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
                "keepalive": _as_text(row[7]).strip(),
                "preshared": _as_text(row[1]).strip() not in ("", "(none)"),
            }

    now = _now()
    peers = []
    active = stale = keepalive_missing = 0
    # ``.get`` with laundering, not bare indexing: a partial row from a
    # patched provider used to KeyError this walk (a raw 500 on every
    # GET /api/wireguard poll), and a value's __bool__/__str__ bomb fired
    # from the old ``stats.get(...) or record[...]`` chains.
    for record in records:
        public = _as_text(record.get("public_key"))
        stats = live.get(public) or {}
        handshake = _conf_int(stats.get("last_handshake"), 0)
        age = (now - handshake) if handshake else 0
        is_active = bool(handshake) and age <= ACTIVE_WINDOW
        is_stale = bool(handshake) and ACTIVE_WINDOW < age <= STALE_WINDOW
        active += 1 if is_active else 0
        stale += 1 if is_stale else 0
        # Scalar-gated: _as_text of an arbitrary junk object is its repr,
        # which would read as "keepalive set" in the count below.  _isa: a
        # stored value whose __class__ is a raising property detonated this
        # very gate — a raw 500 on every GET /api/wireguard poll.
        raw_keep = record.get("keepalive")
        if not _isa(raw_keep, (str, bytes, bytearray, int, float)):
            raw_keep = ""
        keepalive = (
            _as_text(stats.get("keepalive")) or _as_text(raw_keep).strip() or "off"
        )
        if keepalive in ("", "0", "off"):
            keepalive_missing += 1
        rx = _conf_int(stats.get("rx"), 0)
        tx = _conf_int(stats.get("tx"), 0)
        reissuable = _truthy(record.get("reissuable"))
        peers.append({
            "pubkey": public,
            "name": _as_text(record.get("name")),
            "mode": _as_text(record.get("mode")),
            "allowed_ips": _as_text(stats.get("allowed_ips")) or _as_text(record.get("ip")),
            "endpoint": _as_text(stats.get("endpoint")),
            "last_handshake": handshake,
            "handshake_age": age,
            "active": is_active,
            "stale": is_stale,
            "keepalive": keepalive,
            "psk": _truthy(stats.get("preshared")) or _truthy(record.get("preshared_key")),
            "rx": rx,
            "tx": tx,
            "rx_human": _human_bytes(rx),
            "tx_human": _human_bytes(tx),
            "reissuable": reissuable,
            "known": _truthy(record.get("known")),
        })

    iface = _conf_interface(read_conf())
    address = _as_text(iface.get("Address")).strip()
    # Only derive the key from the config when the running interface did not report
    # one.  `public_key` below is `server_public or conf_public`, so on a healthy
    # tunnel this value was computed and then discarded -- and computing it runs
    # `wg pubkey`, a subprocess, on every status poll.  The fallback still exists for
    # the case it was written for: the tunnel is down, so the dump has no interface
    # row, and the page should still show which key the config would serve.
    conf_public = ""
    if not server_public:
        try:
            conf_public = public_from_private(_as_text(iface.get("PrivateKey")))
        except WireGuardError:
            conf_public = ""

    return {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "installed": install["installed"],
        "install": install,
        "interface": _as_text(interface),
        "running": up,
        "state_error": _as_text(error),
        "listen_port": listen_port or _conf_int(
            iface.get("ListenPort"), cfg_["listen_port"],
        ),
        "public_key": _as_text(server_public or conf_public),
        "address": address,
        "subnet": _as_text(cfg_["subnet"]),
        "mtu": _conf_int(iface.get("MTU"), cfg_["mtu"]),
        "dns": _as_text(iface.get("DNS")) or _as_text(cfg_["dns"]),
        "endpoint": _as_text(cfg_["endpoint"]),
        "wstunnel": wstunnel_status(),
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
    # Laundered shape + _as_text: a subclass block/row or a bombing value
    # used to 500 GET /api/wireguard/next-ip and every peer mutation's
    # allocation step; junk now costs only the value it sits in.
    address = _as_text(_conf_interface(parsed).get("Address"))
    for part in address.split(","):
        host = part.strip().split("/")[0].strip()
        if host:
            used.add(host)
    for peer in _conf_peers(parsed):
        for part in _as_text(peer.get("AllowedIPs")).split(","):
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
    network = _usable_network(cfg_["subnet"])
    if network is None:
        raise WireGuardError("wg.bad_subnet", subnet=cfg_["subnet"])
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
    if _path_exists(path):
        try:
            backup = path.with_suffix(".conf.bak")
            # errors=replace: a torn/binary conf used to raise UnicodeDecodeError
            # (a ValueError, not OSError) and 500 the save.  Still take a
            # backup of whatever is on disk.
            replace_secret_text(
                backup, read_text_capped(path, _CONF_CAP, errors="replace")
            )
        except OSError:
            # A missing backup must not block a legitimate change.
            pass
    # Atomic publish: write_secret_text O_TRUNC'd the live file (private
    # key included) if the process died mid-write.
    drop_leftover_nonfile(path)
    try:
        replace_secret_text(path, body)
    except OSError:
        # A leftover *non-empty* directory occupying wg0.conf (an empty one
        # is cleared above) makes the final os.replace raise
        # IsADirectoryError, which used to escape as a raw 500 out of every
        # peer mutation after validation had already passed.  The coded 503
        # names the file so the operator removes the occupant; nothing was
        # persisted, so the registry and the config stay consistent.
        raise WireGuardError("wg.write_failed", path=str(path)[:120])
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


def wstunnel_status() -> dict:
    """Live + stored wstunnel layout, cheap enough for the Network overview."""
    return wireguard_wstunnel.status(settings())


def build_client_conf(
    *,
    private_key: str,
    ip: str,
    mode: str,
    preshared_key: str = "",
    obfuscated: bool = False,
) -> str:
    """Assemble the peer-side config for a client."""
    cfg_ = settings()
    server = server_identity()
    wst = wstunnel_status() if obfuscated else None
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
    if obfuscated and wst and wst.get("local_endpoint"):
        if wst.get("client_command"):
            lines.append(f"# {wst['client_command']}")
        lines.append(f"Endpoint = {wst['local_endpoint']}")
    else:
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
        "created": _now(),
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
    except (TypeError, ValueError, OverflowError):
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
    return {"ok": True, "created": len(created), "peers": _batch_payload(created)}


#: Secrets in a mint result that a retained peer can be asked for again later.
_REISSUABLE_SECRETS = ("client_conf", "psk")


def _batch_payload(created: list[dict]) -> list[dict]:
    """Batch results with key material stripped from the peers that still have it.

    A batch of fifty used to return fifty client configs -- each containing a
    private key -- plus fifty preshared keys, and the only caller reads `created`,
    the count.  Fifty private keys crossed the wire and sat in browser memory for
    nothing.

    Peers created with ``keep_key=False`` are the exception and must keep their
    config: that key is generated, handed over once and never stored, so
    withholding it here would not protect it, it would destroy it.  Those are
    exactly the entries whose ``reissuable`` is false.
    """
    payload = []
    for result in created:
        if not result.get("reissuable"):
            payload.append(result)
            continue
        payload.append(
            {k: v for k, v in result.items() if k not in _REISSUABLE_SECRETS}
        )
    return payload


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
            "created": _now(),
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
    private = _as_text(meta.get("private_key") or "")
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
        # _as_text, not str: a leftover ``\\ud800`` in the registry's ip
        # (hand-edited, or restored from a backup) leaked into ``content``
        # whenever the conf block had no AllowedIPs to prefer, and 500'd
        # peers/config (JSON body), peers/download (PlainTextResponse
        # encode) and export under Starlette's UTF-8 encode.
        ip=configured["ip"] or _as_text(meta.get("ip") or "").strip(),
        mode=str(meta.get("mode") or "split"),
        preshared_key=configured["preshared_key"],
        obfuscated=(fmt or "").lower() == "wst",
    )
    cfg_ = settings()
    name = _as_text(meta.get("name") or "peer") or "peer"
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
                "pubkey": _as_text(record["public_key"]),
                "name": _as_text(record["name"]),
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
        stripped = strip_conf(read_text_capped(conf_path(), _CONF_CAP))
    except (OSError, UnicodeDecodeError):
        return {"ok": False, "error": "conf_unreadable"}
    staged = DATA_DIR / f"{interface}.sync.conf"
    # Reused every sync; O_TRUNC mid-write left a torn private-key file
    # that ``wg syncconf`` then applied.
    drop_leftover_nonfile(staged)
    try:
        replace_secret_text(staged, stripped)
    except OSError:
        # A leftover non-empty directory at data/wg0.sync.conf used to raise
        # IsADirectoryError out of os.replace — a raw 500 on POST
        # /api/wireguard/sync, and on every peer mutation whose apply step
        # runs after the change was already persisted.  The dict shape keeps
        # peer routes answering 200 with applied=false, and /sync answers
        # its coded wg.sync_failed.
        return {"ok": False, "error": "stage_unwritable"}

    rc, _, err = sh(["/usr/bin/sudo", "-n", WG, "syncconf", device, str(staged)], timeout=30)
    # _ping_rc (the health9 rc rule): an rc-subclass ``__eq__`` bomb from a
    # patched/odd sh used to detonate the bare ``rc == 0`` — a raw 500 on
    # POST /api/wireguard/sync and on every peer mutation's apply step after
    # the change was already persisted.  A bombed honest 0 is salvaged.
    if _ping_rc(rc) == 0:
        return {"ok": True, "applied": True, "device": device}
    result = run_admin([WG, "syncconf", device, str(staged)], timeout=120)
    if result.get("ok"):
        return {"ok": True, "applied": True, "device": device}
    return {
        "ok": False,
        "error": result.get("error") or "sync_failed",
        "detail": _as_text(err)[:200],
    }


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
    recorded = _path_exists(name_file)
    device = real_interface(iface)
    live = bool(device) and _path_exists(WG_RUN_DIR / f"{device}.sock")
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
    if not _path_exists(path):
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
        rc, out, err = sh(["/usr/bin/sudo", "-n", *command], timeout=_WG_QUICK_TIMEOUT)
        # _ping_rc on both exit probes (the health9 rc rule): an rc-subclass
        # ``__eq__`` bomb used to detonate the bare ``rc == 0`` — a raw 500
        # on POST /api/wireguard/interface.  ``_as_text`` before
        # ``sudo_refused``: the marker scan runs string methods on the
        # stderr it is handed, and a leftover str-subclass bomb must cost
        # only this probe, never the route.
        if _ping_rc(rc) == 0:
            continue
        if sudo_refused(_as_text(err)):
            return run_admin_sequence(commands, timeout=_WG_QUICK_TIMEOUT + 60)
        combined = (_as_text(err) + "\n" + _as_text(out)).strip()
        # A zombie claim can appear between the check above and this call (or the
        # record can name a device that has since gone).  One repair attempt,
        # only when nothing is serving the interface.
        if verb in ("up", "restart") and "already exists" in combined:
            fresh = runtime_state(settings()["interface"])
            if fresh["live"]:
                return {"ok": True, "action": verb, "already_running": True}
            sh(["/usr/bin/sudo", "-n", RM, "-f", fresh["name_file"]], timeout=20)
            rc, out, err = sh(["/usr/bin/sudo", "-n", *command], timeout=_WG_QUICK_TIMEOUT)
            if _ping_rc(rc) == 0:
                continue
            combined = (_as_text(err) + "\n" + _as_text(out)).strip()
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
        text = read_text_capped(conf_path(), _CONF_CAP)
    except (OSError, UnicodeDecodeError):
        raise WireGuardError("wg.no_conf", path=str(conf_path()))
    if reveal:
        return {"ok": True, "conf": text, "redacted": False}
    redacted = re.sub(
        r"(?im)^(PrivateKey\s*=\s*).*$", r"\1[redacted]", text
    )
    return {"ok": True, "conf": redacted, "redacted": True}


#: Module-level so the vanished-CLI probe re-checks the exact path the spawn
#: used (the tools_svc / network_svc PING convention).
PING = "/sbin/ping"


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a peer listing (or row) whose ``__class__`` is a *raising
    property* detonated the gates in :func:`_ping_targets` themselves — a
    raw 500 on POST /api/wireguard/ping where every other junk row already
    drops silently.  A real subclass still matches through the C-level type
    check (the smart_test_svc._isa rule).
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _ping_rc(rc) -> int:
    """Exact exit status for the ``==`` probes; a bomb reads as failure.

    :func:`_ping_once` does not own ``sh`` (tests and tooling patch it), and
    an rc-*subclass* whose ``__eq__`` raises used to detonate
    ``rc == -1`` / ``rc == 0`` past the spawn try — ``fan_out`` re-raised it
    and 500'd POST /api/wireguard/ping.  ``-255`` is no honest ping exit and
    never the ``sh`` spawn sentinel, so a bomb reads as one unreachable peer,
    never the tool-absent 503.

    Also the launder for every other read-path exit probe
    (:func:`_binary_version`, :func:`_dump_all`, :func:`live_interface`):
    the same bomb out of those bare comparisons was a raw 500 on GET
    /api/wireguard and GET /api/wireguard/settings.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        if isinstance(rc, int):
            return int.__index__(rc)
        return int(rc)
    except Exception:
        return -255


def _ping_cli_gone() -> bool:
    """Fresh disk probe: True only for a confirmed-absent ``/sbin/ping``.

    Run on a failure path only (the network_svc ``_cli_gone`` rule — a
    successful spawn never pays the stat).  An unreadable parent directory
    (EIO/ESTALE on a dying mount) must not upgrade the failure to the coded
    503, so a stat that raises reads as "still present".
    """
    try:
        return not Path(PING).is_file()
    except (OSError, ValueError):
        return False


def _ping_spawn_sentinel(rc, out, err) -> bool:
    """True when ``(rc, out, err)`` is ``sh``'s FileNotFoundError sentinel.

    ``sh`` collapses every failed spawn of a missing binary into exactly
    ``(-1, "", "not found")`` — never a real ping exit.  Purely a
    message-pattern gate: :func:`ping_peers` still confirms with a fresh
    :func:`_ping_cli_gone` disk probe, so a genuine run whose output merely
    reads "not found" keeps its honest unreachable row.
    """
    return rc == -1 and (_as_text(err) or _as_text(out)).strip() == "not found"


def _ping_once(host: str, deadline_ms: int) -> tuple[bool, float | None, bool]:
    """``(reachable, latency_ms, spawn_vanished)`` for one peer.  Never raises.

    ``fan_out`` re-raises on iteration, so an exception here would lose every
    peer's result instead of marking one unreachable.
    """
    try:
        rc, out, err = sh(
            [PING, "-c", "1", "-W", str(deadline_ms), "-n", host], timeout=8
        )
    except Exception:
        return False, None, False
    # _ping_rc before any comparison: an rc-subclass ``__eq__`` bomb from a
    # patched/odd sh detonated the sentinel probe below, past this
    # function's spawn try — through fan_out, a raw 500 on the route.
    rc = _ping_rc(rc)
    vanished = _ping_spawn_sentinel(rc, out, err)
    match = re.search(r"time=([\d.]+)\s*ms", _as_text(out))
    if not match:
        return rc == 0, None, vanished
    try:
        latency = float(match.group(1))
    except ValueError:
        # ``[\d.]+`` also matches ``1.2.3``; the ValueError escaped through
        # fan_out and 500'd POST /api/wireguard/ping.
        return rc == 0, None, vanished
    # A >308-digit run parses to inf, which Starlette's allow_nan=False
    # encoder refuses -- same 500, one layer later.
    return rc == 0, (None if _nonfinite(latency) else latency), vanished


def _ping_deadline(timeout_ms) -> int:
    """Clamped probe deadline; a subclass bomb answers the default, never a 500.

    The route calls :func:`ping_peers` with no arguments, but the service is
    also called in-process, and an int/float-subclass ``__bool__``/``__int__``
    bomb used to blow ``timeout_ms or 800`` / ``int(timeout_ms)`` past the
    old arithmetic-trio except — the smart_test_svc._schedule_epoch rule, on
    the ping surface.  Base coercions first, then one Exception net: these
    bombs raise whatever they like.
    """
    try:
        if isinstance(timeout_ms, bool):
            return 800
        if isinstance(timeout_ms, int):
            timeout_ms = int.__index__(timeout_ms)
        elif isinstance(timeout_ms, float):
            timeout_ms = float.__float__(timeout_ms)
        return max(200, min(int(timeout_ms or 800), 5000))
    except Exception:
        return 800


def _ping_targets() -> list[tuple[dict, str]]:
    """``(record, host)`` pairs from the peer table, junk records dropped.

    This walk does not own the provider (tests and tooling patch
    ``peer_records``): a listing that is a list *subclass* whose ``__iter__``
    raises, a non-dict row, or a row whose ``ip`` is already-int (a poisoned
    registry merge) used to raise out of the loop below — a raw 500 on POST
    /api/wireguard/ping where every blank-ip peer already drops silently.
    Unbound ``list.__iter__`` walks the real entries; a junk row costs only
    itself, never its siblings or the route.
    """
    try:
        records = peer_records()
    except Exception:
        return []
    # _isa on both gates: a listing (or row) whose ``__class__`` is a
    # raising property used to detonate the bare isinstance itself — the
    # same raw 500 these gates exist to prevent.  The unbound
    # ``list.__iter__`` runs in a try: a lying-``__class__`` impostor (the
    # docker10/json9 shape — ``isinstance`` answers list, the real object is
    # not one) passed the gate but made the descriptor raise ``TypeError``,
    # a raw 500 on POST /api/wireguard/ping.  A liar falls through to the
    # generic guarded pull loop.
    rows = None
    if _isa(records, list):
        try:
            rows = list.__iter__(records)
        except Exception:
            rows = None
    if rows is None:
        # Guarded pull loop (the worker_health.problems rule): a generic
        # iterable that answers iter() but raises mid-iteration used to blow
        # the walk below past the per-row drops — rows already yielded
        # survive, the bomb costs only its own tail.
        try:
            it = iter(records or [])
        except Exception:
            return []
        pulled = []
        while True:
            try:
                pulled.append(next(it))
            except StopIteration:
                break
            except Exception:
                break
        rows = pulled
    targets: list[tuple[dict, str]] = []
    for record in rows:
        if not _isa(record, dict):
            continue
        # Exact-dict launder in a try: a *lying*-``__class__`` impostor row
        # (the brew10/json9 shape — ``isinstance`` answers dict, the real
        # object is a plain object) passed the ``_isa`` gate and made the
        # unbound ``dict.get`` descriptor below raise TypeError — a raw 500
        # on POST /api/wireguard/ping for a row every other junk shape
        # already drops alone.  ``dict(record)`` copies a real (sub)dict
        # through the C-level storage and refuses the liar; downstream
        # (:func:`ping_peers`'s result build) then reads exact dicts only.
        try:
            record = dict(record)
        except Exception:
            continue
        # Unbound ``dict.get`` (the smart_test_svc._schedule_cfg rule): a
        # dict-subclass row whose ``.get`` raises must drop alone.
        ip = _as_text(dict.get(record, "ip"))
        host = ip.split("/")[0].split(",")[0].strip()
        if not host:
            continue
        targets.append((record, host))
    return targets


def ping_peers(timeout_ms: int = 800) -> dict:
    """ICMP-probe each peer's tunnel address.

    Reachability here is a stronger signal than a recent handshake: a handshake
    only proves the peer's WireGuard is alive, not that traffic crosses the tunnel
    (a missing route or NAT rule breaks the second without touching the first).
    """
    deadline = _ping_deadline(timeout_ms)
    targets = _ping_targets()

    # One ICMP probe per peer, each waiting out its own deadline -- so in series
    # this endpoint cost the peer count times up to five seconds, and a WireGuard
    # server with a dozen phones on it simply timed out before answering. The
    # probes are independent by definition: different addresses, no shared state,
    # and nothing here is privileged, so they belong in a pool.
    #
    # `fan_out` keeps the results in peer order, which the table renders and
    # which must not reshuffle by who answered first.
    pinged = fan_out(lambda pair: _ping_once(pair[1], deadline), targets)

    if (
        targets
        and any(vanished for _r, _l, vanished in pinged)
        and _ping_cli_gone()
    ):
        # A vanished /sbin/ping answered 200 with every peer "unreachable" —
        # the same lie the Network failover tick and POST /api/tools/net/ping
        # already upgrade to a coded 503.  Disk-confirmed on the
        # spawn-sentinel failure path only; a present-but-failing ping keeps
        # its honest unreachable rows below.
        raise WireGuardError("wg.ping_missing")

    results = [
        {
            "pubkey": _as_text(dict.get(record, "public_key")),
            "name": _as_text(dict.get(record, "name")),
            "ip": host,
            "reachable": reachable,
            "latency_ms": latency,
        }
        for (record, host), (reachable, latency, _vanished) in zip(targets, pinged)
    ]
    reachable = sum(1 for r in results if r["reachable"])
    return {
        "ok": True,
        "results": results,
        "reachable": reachable,
        "total": len(results),
    }
