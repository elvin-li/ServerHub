"""What a macOS WireGuard server needs beyond ``wg0.conf`` to actually work.

On Linux a ``wg-quick`` config with ``PostUp`` iptables rules is self-contained.
On macOS three pieces live outside the config, and every one of them fails
*silently*: the tunnel comes up, peers handshake, and then traffic goes nowhere.
That combination — green status, no connectivity — is the single most common way a
hand-rolled Mac WireGuard server is broken, so the panel checks all three
explicitly rather than reporting "running" and leaving the operator to guess.

1. **IP forwarding.** ``net.inet.ip.forwarding`` is 0 by default, so the kernel
   drops packets that need to cross between the tunnel and the LAN.
2. **NAT.** macOS uses pf, and pf performs no NAT for the tunnel subnet unless a
   rule says so.  Without it a peer can reach the Mac itself but nothing beyond.
3. **Boot persistence.** ``wg-quick up`` does not survive a reboot; a LaunchDaemon
   has to be installed into ``/Library/LaunchDaemons``.

A fourth check has nothing to do with macOS and everything to do with how these
configs get built by hand: whether the local peer list was **copied from another
server**.  A peer entry is just a public key plus an address, so copying peers from
an existing server produces a config that looks complete and can never handshake,
because each client pins the *original* server's public key.  That is exactly the
state this machine was found in, so it is a first-class check.

Remediation is offered but never automatic: editing ``/etc/pf.conf`` and installing
a LaunchDaemon are system-level changes, each gets its own explicit action, and each
is reversible.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

from hub import wireguard_svc
from hub.host_address import default_interface
from hub.macos_admin import run_admin_sequence, sudo_capture
from hub.paths import DATA_DIR
from hub.secure_io import write_secret_text
from hub.util import fan_out, sh

SYSCTL = "/usr/sbin/sysctl"
PFCTL = "/sbin/pfctl"
LAUNCHCTL = "/bin/launchctl"
CP = "/bin/cp"
RM = "/bin/rm"
CHOWN = "/usr/sbin/chown"
CHMOD = "/bin/chmod"

PF_CONF = Path("/etc/pf.conf")
PF_ANCHOR_DIR = Path("/etc/pf.anchors")
ANCHOR_NAME = "serverhub-wireguard"
PF_ANCHOR_PATH = PF_ANCHOR_DIR / ANCHOR_NAME

LAUNCH_DAEMON_DIR = Path("/Library/LaunchDaemons")

#: Marker so the panel can find (and remove) exactly the lines it added to
#: /etc/pf.conf without disturbing anyone else's rules.
PF_MARKER = "# ServerHub WireGuard NAT"

_STAGE_DIR = DATA_DIR


def _default_wan_interface() -> str:
    """The interface holding the default route, e.g. ``en0``.

    One definition, in hub.host_address, shared with the power page and the network
    overview -- three modules used to ask the routing table this same question with
    three timeouts and two parses between them.
    """
    return default_interface()


def wan_interface() -> str:
    """Configured NAT egress interface, falling back to the default route."""
    configured = str(wireguard_svc.settings().get("wan_interface") or "").strip()
    if configured and re.fullmatch(r"[a-z][a-z0-9]{0,14}", configured):
        return configured
    return _default_wan_interface()


# ── individual checks ────────────────────────────────────────────────────────

def forwarding_enabled() -> bool | None:
    rc, out, _ = sh([SYSCTL, "-n", "net.inet.ip.forwarding"], timeout=5)
    if rc != 0:
        return None
    return out.strip() == "1"


def pf_enabled() -> bool | None:
    """Whether pf itself is running.  A loaded rule does nothing while pf is off."""
    rc, out, err = sh([PFCTL, "-s", "info"], timeout=6)
    if rc != 0:
        rc, out, err = sudo_capture([PFCTL, "-s", "info"], timeout=6)
    blob = f"{out}\n{err}"
    if rc != 0 and not blob.strip():
        return None
    return "Status: Enabled" in blob


def pf_conf_valid() -> dict:
    """Whether ``/etc/pf.conf`` still parses, and what pf says if it does not.

    This is the check whose absence let the whole feature fail silently.  pf
    enforces an order on rule classes -- options, normalization, queueing,
    translation, filtering -- and refuses to load a file that breaks it.  An
    earlier version of :func:`install_nat` appended its ``nat-anchor`` to the end
    of the file, after Apple's filter anchors, which made ``pfctl -f /etc/pf.conf``
    fail outright: not just the NAT rule but *every* pf rule stopped being
    reloadable, while the panel went on reporting NAT as installed because the
    anchor file and the reference were both present on disk.

    ``pfctl -n`` parses without loading and needs no privileges at all, so there is
    no excuse for not checking.
    """
    rc, out, err = sh([PFCTL, "-n", "-f", str(PF_CONF)], timeout=10)
    if rc == 0:
        return {"ok": True, "message": ""}
    # pfctl always prints a "Use of -f option" caution to stderr; the diagnosis is
    # whichever line names a file and a line number.
    lines = [line.strip() for line in f"{err}\n{out}".splitlines() if line.strip()]
    faults = [line for line in lines if re.search(r":\d+:", line)]
    return {"ok": False, "message": " ".join(faults or lines)[:300]}


def nat_active() -> bool | None:
    """Whether the NAT rule is actually loaded into pf, not merely on disk.

    ``None`` when it cannot be determined -- reading a pf anchor needs root, and an
    unanswerable probe must not be reported as a failure.
    """
    rc, out, err = sudo_capture([PFCTL, "-a", ANCHOR_NAME, "-s", "nat"], timeout=8)
    if rc != 0:
        return None
    del err
    return bool(re.search(r"^\s*nat\b", out or "", re.MULTILINE))


def nat_installed() -> dict:
    """Whether the NAT anchor file exists, pf.conf wires it in, and pf holds it."""
    anchor_exists = PF_ANCHOR_PATH.exists()
    try:
        conf_text = PF_CONF.read_text(errors="replace")
    except OSError:
        conf_text = ""
    # Detection keys off a reference to the anchor rather than off this panel's
    # marker comment: an operator (or an older build) may have wired the anchor in
    # by hand, and re-adding it on top would load the same rules twice.
    referenced = bool(_anchor_reference_lines(conf_text))
    anchor_body = ""
    if anchor_exists:
        try:
            anchor_body = PF_ANCHOR_PATH.read_text(errors="replace")[:600]
        except OSError:
            anchor_body = ""
    parses = pf_conf_valid()
    active = nat_active()
    return {
        "anchor_path": str(PF_ANCHOR_PATH),
        "anchor_exists": anchor_exists,
        "referenced": referenced,
        # "Installed on disk" and "in effect" are different questions, and the
        # gap between them is where this feature failed.  `complete` answers the
        # second: files present, pf.conf loadable, and -- when the rule can be
        # read back at all -- the rule actually there.
        "complete": bool(
            anchor_exists and referenced and parses["ok"] and active is not False
        ),
        # Whether this rule alone is in order, setting aside whether pf can load
        # the file it lives in.  `readiness` reports the parse failure once, under
        # its own heading, rather than as a second NAT problem.
        "wiring_ok": bool(anchor_exists and referenced and active is not False),
        "on_disk": anchor_exists and referenced,
        "conf_parses": parses["ok"],
        "conf_error": parses["message"],
        "loaded": active,
        "anchor_body": anchor_body,
    }


def render_daemon_plist(label: str, conf: str, bash: str, wg_quick: str) -> str:
    """The boot job that brings the tunnel up, written rather than borrowed.

    Homebrew's ``wireguard-tools`` ships a template next to the config, and copying
    it is a trap: it pairs ``ProgramArguments = wg-quick up`` with
    ``KeepAlive = true``.  ``wg-quick up`` is not a daemon -- it configures the
    interface and exits 0 -- so launchd sees the job "die" immediately and restarts
    it, the second run finds the interface it just created and dies with
    ``` `wg0' already exists as `utun8' ```, and that repeats forever.  On the host
    this was found on, ``/var/log/wireguard-wg0.log`` was a wall of that message.

    A one-shot ``RunAtLoad`` job with no ``KeepAlive`` is what this actually is:
    run once at boot, succeed, exit.  Nothing supervises wireguard-go afterwards,
    which is honest -- ``KeepAlive`` on ``wg-quick up`` never supervised it either,
    it only restarted the setup script.

    wg-quick is launched through a modern bash by absolute path for the same reason
    the panel does: its ``#!/usr/bin/env bash`` shebang finds Apple's bash 3.2
    under a scrubbed PATH and refuses to run.
    """
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bash}</string>
        <string>{wg_quick}</string>
        <string>up</string>
        <string>{conf}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>StandardErrorPath</key>
    <string>/var/log/wireguard-{label.rsplit('.', 1)[-1]}.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/wireguard-{label.rsplit('.', 1)[-1]}.log</string>
</dict>
</plist>
"""


def _daemon_plist_body() -> str:
    interface = wireguard_svc.settings()["interface"]
    return render_daemon_plist(
        f"com.wireguard.{interface}",
        str(wireguard_svc.conf_path(interface)),
        wireguard_svc.BASH,
        wireguard_svc.WG_QUICK,
    )


def daemon_state() -> dict:
    """Whether the boot-time LaunchDaemon for this interface is installed/loaded."""
    interface = wireguard_svc.settings()["interface"]
    label = f"com.wireguard.{interface}"
    target = LAUNCH_DAEMON_DIR / f"{label}.plist"
    installed = target.exists()
    rc, out, _ = sh([LAUNCHCTL, "print", f"system/{label}"], timeout=6)
    if rc != 0:
        # The system domain only answers to root; reuse the web password when
        # this request carries one.
        rc, out, _ = sudo_capture([LAUNCHCTL, "print", f"system/{label}"], timeout=6)
    loaded = rc == 0
    if not loaded:
        # `launchctl print` on a system domain needs root; fall back to the list.
        rc2, out2, _ = sh([LAUNCHCTL, "list"], timeout=6)
        loaded = rc2 == 0 and label in out2
    del out
    # An installed job that respawns `wg-quick up` in a loop is worse than no job
    # at all, so whether the file on disk is the one this panel would write is
    # part of the state, not an implementation detail.
    current = ""
    if installed:
        try:
            current = target.read_text(errors="replace")
        except OSError:
            current = ""
    return {
        "label": label,
        "plist_path": str(target),
        "installed": installed,
        "loaded": loaded,
        "managed": bool(current) and current == _daemon_plist_body(),
        # `KeepAlive` with `wg-quick up` is the specific defect worth naming: it
        # restarts the setup script forever instead of supervising the tunnel.
        "respawn_loop": "KeepAlive" in current and "sleep" not in current,
    }


#: IPv6 address flags ``ifconfig`` prints that disqualify an address from being
#: put in a DNS record: a temporary privacy address is rotated within a day or
#: two, and a deprecated one is on its way out already.
_UNSTABLE_V6_FLAGS = ("temporary", "deprecated")


def _local_address_lines() -> list[tuple[str, str]]:
    """``(address, flags)`` for every global address bound to an interface.

    ``ifconfig`` rather than ``getaddrinfo``: the machine's own hostname often
    resolves to nothing useful, and what matters here is what is actually bound to
    an interface.  The flags are kept because they decide whether an address is
    worth *recommending* -- see :func:`stable_local_addresses`.
    """
    rc, out, _ = sh(["/sbin/ifconfig"], timeout=6)
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        match = re.match(r"\s*(inet6?)\s+([0-9a-fA-F:.]+)(.*)$", line)
        if not match:
            continue
        raw = match.group(2).split("%")[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address.is_loopback or address.is_link_local or address.is_unspecified:
            continue
        found.append((str(address), match.group(3).lower()))
    return found


def _local_addresses() -> set[str]:
    """Every global address configured on this host, v4 and v6."""
    return {address for address, _ in _local_address_lines()}


def stable_local_addresses() -> list[str]:
    """Global IPv6 addresses of this host worth pointing a DNS record at.

    Ordered most durable first, and privacy addresses excluded.  The distinction
    matters because the output is a recommendation an operator will paste into DNS:
    macOS holds several addresses in the same /64 at once, most of them temporary
    ones it rotates within a day or two, so naming the wrong one produces a record
    that works this afternoon and fails tomorrow.  ``dynamic`` (DHCPv6 or manually
    configured) is the most durable, then a ``secured`` autoconf address, which is
    stable for the lifetime of the prefix.
    """
    def rank(flags: str) -> int:
        if "dynamic" in flags:
            return 0
        if "secured" in flags:
            return 1
        return 2

    candidates = []
    for address, flags in _local_address_lines():
        if ":" not in address:
            continue
        if any(flag in flags for flag in _UNSTABLE_V6_FLAGS):
            continue
        # A unique local address (fc00::/7) is the IPv6 equivalent of 10.0.0.0/8:
        # perfectly real, bound to an interface, and not routable from outside.
        # Recommending one for a public record would be worse than recommending
        # nothing, because it looks like an answer.
        if ipaddress.ip_address(address).is_private:
            continue
        candidates.append((rank(flags), address))
    return [address for _, address in sorted(candidates)]


def endpoint_resolution() -> dict:
    """Whether the endpoint clients are told to dial actually leads back here.

    This is the check whose absence cost the most time on the host it was written
    for.  Everything on the server was correct -- tunnel up, port bound, keys
    matching -- and no client could connect, because the endpoint's ``AAAA`` record
    pointed into a different /64 than the one this machine holds.  Clients follow
    RFC 6724 and prefer IPv6, so essentially every phone dialled an address that
    was not this server and simply got nothing back.  Nothing in the panel could
    have told the operator that; "endpoint is set" was the whole of the check.

    What can be established locally, and is:

    * a literal private or loopback address is wrong for a *public* endpoint;
    * a ``AAAA`` outside every prefix this host holds cannot reach it, and is
      reported as broken whenever the host has global IPv6 of its own to compare
      against;
    * an ``A`` record pointing at a private address is wrong the same way.

    What deliberately is *not* asserted: that a public ``A`` record belongs to this
    network.  Establishing that needs an outbound request to a third party to learn
    the egress address, and a NAT'd server legitimately has no way to see its own
    public IPv4 locally.  So a public ``A`` is reported, never failed.
    """
    # Shared splitting: an IPv6 literal endpoint is mostly colons, so stripping
    # "everything after the last colon" would resolve a truncated address.
    host, _ = wireguard_svc.split_endpoint(
        str(wireguard_svc.settings().get("endpoint") or "")
    )
    result = {
        "endpoint": host,
        "resolved": [],
        "unreachable": [],
        "ok": True,
        "reason": "",
        # What the record *should* say, when this can be worked out.  Reporting only
        # "not this host" left the operator to find the right address themselves,
        # and the obvious way to do that -- read `ifconfig` and pick a global
        # address -- picks a temporary privacy address about four times out of five.
        "suggest": [],
    }
    if not host:
        result.update(ok=False, reason="not_set")
        return result

    local = _local_addresses()
    has_global_v6 = any(":" in address for address in local)

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        result["resolved"] = [str(literal)]
        if literal.is_private or literal.is_loopback:
            result.update(ok=False, reason="private_address", unreachable=[str(literal)])
        return result

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except OSError:
        result.update(ok=False, reason="dns_failed")
        return result

    addresses = []
    for info in infos:
        address = info[4][0].split("%")[0]
        if address not in addresses:
            addresses.append(address)
    result["resolved"] = addresses

    bad = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_private or parsed.is_loopback:
            bad.append(address)
        elif parsed.version == 6 and has_global_v6 and address not in local:
            # A v6 endpoint has to *be* one of this host's addresses: there is no
            # NAT in between to explain a mismatch.
            bad.append(address)
    if bad:
        result.update(ok=False, reason="not_this_host", unreachable=bad)
        if any(":" in address for address in bad):
            result["suggest"] = stable_local_addresses()[:2]
    return result


def peer_origin_conflict() -> dict:
    """Detect a peer list copied from a different WireGuard server.

    The tell is structural rather than heuristic: peers that this panel did not
    create (no registry entry) and for which no private key was ever stored can
    only have come from somewhere else.  If *every* peer looks like that while the
    config also carries a server key of its own, the clients in the field are
    pinned to some other server's public key and none of them can ever complete a
    handshake here.
    """
    records = wireguard_svc.peer_records()
    if not records:
        return {"conflict": False, "reason": "no_peers", "foreign": 0, "total": 0}
    foreign = [r for r in records if not r["known"] and not r["reissuable"]]
    conflict = len(foreign) == len(records)
    return {
        "conflict": conflict,
        "reason": "all_peers_foreign" if conflict else "",
        "foreign": len(foreign),
        "total": len(records),
        "foreign_keys": [r["public_key"][:16] for r in foreign[:10]],
    }


def _daemon_detail(daemon: dict) -> str:
    """Say which boot job is installed, not merely that one is.

    "Installed" is not the same as "the job this panel manages", and the
    difference is observable: the variant found on the real host wrapped the
    command in ``bash -c '... && exec sleep infinity'``, which keeps a process
    alive purely so launchd counts the job as running.  Stopping the tunnel from
    the panel then leaves that process behind, launchd goes on reporting the job as
    running against a stopped tunnel, and ``launchctl kickstart`` becomes a no-op.
    It does bring the tunnel up at boot, so this is not a failure -- but reporting
    only the path gave the operator no way to tell the two apart.
    """
    if not daemon["installed"]:
        return daemon["plist_path"]
    if daemon["respawn_loop"]:
        return f"{daemon['plist_path']} restarts wg-quick in a loop"
    if not daemon["managed"]:
        return f"{daemon['plist_path']} (not the job this panel manages)"
    return daemon["plist_path"]


def _resolution_detail(resolution: dict) -> str:
    """Name the addresses that cannot work, not merely that something cannot."""
    reason = resolution["reason"]
    if reason == "not_set":
        return ""
    if reason == "dns_failed":
        return f"{resolution['endpoint']} does not resolve"
    if resolution["unreachable"]:
        detail = (
            f"{resolution['endpoint']} -> "
            + ", ".join(resolution["unreachable"])
            + " (not this host)"
        )
        # `.get`: the suggestion is genuinely optional -- there is often no
        # routable address of our own to name -- so a dict without one is
        # describing a real state rather than being malformed.
        suggest = resolution.get("suggest") or []
        if suggest:
            detail += "; this host is " + ", ".join(suggest)
        return detail
    return f"{resolution['endpoint']} -> " + ", ".join(resolution["resolved"])


def _nat_detail(nat: dict, egress: str) -> str:
    """Say which of the NAT preconditions is missing, not merely that one is.

    "NAT rule" with a path next to it was the same message whether the anchor was
    absent, present but not referenced, or referenced in a file pf could no longer
    load -- three different repairs behind one label.
    """
    if not nat["anchor_exists"]:
        return f"{nat['anchor_path']} missing"
    if not nat["referenced"]:
        return f"{PF_CONF} does not reference {ANCHOR_NAME}"
    if not nat["conf_parses"]:
        return nat["conf_error"] or f"{PF_CONF} does not parse"
    if nat["loaded"] is False:
        return f"rule not loaded into pf ({ANCHOR_NAME})"
    return f"{nat['anchor_path']} -> {egress or 'unknown egress'}"


def readiness() -> dict:
    """Every gate between "config exists" and "a client actually gets traffic".

    Eleven independent probes, none of which reads another's output.  Read in turn
    they cost the sum of eleven timeouts, and this is the page an operator opens
    precisely when the tunnel is not working -- when those probes are at their
    slowest.

    Four of them stay on the request thread, and that split is load-bearing rather
    than cautious.  ``wireguard_svc.status``, :func:`nat_installed`,
    :func:`daemon_state` and :func:`pf_enabled` all reach ``sudo_capture``, which
    reads the operator's password from a ContextVar.  A ContextVar is not inherited
    by a pool worker, so on a worker that read returns "" -- and the failure is
    silent: the call does not raise, it falls back to ``sudo -n``, and answers
    ``password_required`` about a password the operator just typed.  See
    tests/test_privileged_calls_stay_on_the_request_thread.py.

    The remaining seven touch nothing privileged and go in one wave.
    """
    # `fan_out` re-raises on iteration, exactly as the serial version propagated the
    # first failure, so a broken probe still surfaces rather than being swallowed.
    (
        install,
        cfg_,
        conflict,
        resolution,
        runtime,
        forwarding,
        egress,
    ) = fan_out(
        lambda probe: probe(),
        [
            wireguard_svc.installation,
            wireguard_svc.settings,
            peer_origin_conflict,
            endpoint_resolution,
            wireguard_svc.runtime_state,
            forwarding_enabled,
            wan_interface,
        ],
        max_workers=7,
    )

    # Password-dependent, so deliberately serial on the request thread.
    state = wireguard_svc.status()
    nat = nat_installed()
    daemon = daemon_state()
    pf_on = pf_enabled()

    endpoint = str(cfg_.get("endpoint") or "").strip()

    checks = [
        {
            "id": "installed",
            "ok": bool(install["installed"]),
            "level": "error",
            "detail": install["tools_version"] or "",
        },
        {
            "id": "conf",
            "ok": bool(install["conf_exists"]),
            "level": "error",
            "detail": install["conf_path"],
        },
        {
            "id": "running",
            "ok": bool(state["running"]),
            "level": "warn",
            # The device is worth stating when it differs from the configured
            # name: on macOS the tunnel runs as some utun, and an operator
            # comparing the panel against `ifconfig` has no other way to tell
            # which one is theirs.
            "detail": state.get("state_error")
            or runtime["real_interface"]
            or cfg_["interface"],
        },
        {
            "id": "endpoint",
            "ok": bool(endpoint),
            "level": "error",
            "detail": endpoint,
        },
        {
            # Separate from `endpoint` because "set" and "correct" fail for
            # different reasons and are fixed in different places -- one in this
            # panel, the other in DNS.  Suppressed while `endpoint` itself is
            # unset, where the two would say the same nothing twice.
            "id": "endpoint_resolves",
            "ok": bool(resolution["ok"]),
            "level": "error",
            "detail": _resolution_detail(resolution),
            "superseded_by": "endpoint",
        },
        {
            "id": "forwarding",
            "ok": forwarding is True,
            "level": "error",
            "detail": "net.inet.ip.forwarding",
        },
        {
            # Ahead of `nat` deliberately: when pf cannot load the file, that is
            # the cause and the NAT rule's absence is the symptom.  Listing the
            # symptom first sends the operator at the wrong thing, and listing
            # both with the same parser error next to them -- which is what
            # happened -- reads as the panel repeating itself.
            "id": "pf_conf",
            "ok": bool(nat["conf_parses"]),
            "level": "error",
            "detail": nat["conf_error"] or str(PF_CONF),
        },
        {
            "id": "nat",
            "ok": bool(nat["complete"]),
            "level": "error",
            "detail": _nat_detail(nat, egress),
            "superseded_by": "pf_conf",
        },
        {
            "id": "pf",
            "ok": pf_on is True,
            "level": "warn",
            "detail": "pfctl status",
            # pf cannot be enabled from a file it refuses to parse.
            "superseded_by": "pf_conf",
        },
        {
            # An installed job that respawns `wg-quick up` forever does not count
            # as boot persistence; it counts as a log-filling loop that has to be
            # replaced, so it must not show up here as satisfied.
            "id": "boot",
            "ok": bool(daemon["installed"]) and not daemon["respawn_loop"],
            "level": "warn",
            "detail": _daemon_detail(daemon),
        },
        {
            "id": "peer_origin",
            "ok": not conflict["conflict"],
            "level": "error",
            "detail": f"{conflict['foreign']}/{conflict['total']} peers from another server",
        },
        {
            # A claim left by a run that died mid-setup blocks every subsequent
            # start with a message about the interface "already existing", which
            # sends the operator looking in entirely the wrong place.
            "id": "stale_runtime",
            "ok": not runtime["stale"],
            "level": "error" if runtime["stale"] else "warn",
            "detail": runtime["name_file"] if runtime["stale"] else "",
        },
    ]
    # Drop any check whose stated cause is already failing.  Several of these
    # gates are downstream of one another -- NAT cannot load from a pf.conf that
    # does not parse, an endpoint cannot resolve correctly if none is set -- and
    # reporting both ends of such a pair puts two rows carrying the same message,
    # and sometimes the same button, in front of the operator.  Only the row that
    # can actually be acted on survives.
    failing = {c["id"] for c in checks if not c["ok"]}
    checks = [
        {k: v for k, v in c.items() if k != "superseded_by"}
        for c in checks
        if c["ok"] or c.get("superseded_by") not in failing
    ]

    blocking = [c for c in checks if not c["ok"] and c["level"] == "error"]
    return {
        "checks": checks,
        "ready": not blocking,
        "blocking": [c["id"] for c in blocking],
        "warnings": [c["id"] for c in checks if not c["ok"] and c["level"] == "warn"],
        "forwarding": forwarding,
        "pf_enabled": pf_on,
        "nat": nat,
        "daemon": daemon,
        "peer_origin": conflict,
        "wan_interface": egress,
        "endpoint": endpoint,
        "endpoint_resolution": resolution,
        "runtime": runtime,
    }


# ── remediation ──────────────────────────────────────────────────────────────

def render_anchor(subnet: str, egress: str) -> str:
    """The pf anchor body that NATs the tunnel subnet out of *egress*.

    Only a NAT rule, deliberately.  An earlier version also emitted
    ``pass in/out quick on utun0``, which was wrong twice over: wireguard-go picks
    its utun number at runtime (utun0 may belong to something else entirely), and
    macOS ships pf with a default-pass policy, so filter rules for the tunnel are
    redundant unless the operator has their own block rules — in which case they
    should decide what passes, not this generator.

    ``-> ({egress})`` in parentheses re-reads the interface address on each match,
    so the rule keeps working across a DHCP lease change without a pf reload.
    """
    return (
        f"{PF_MARKER}\n"
        f"# Generated by ServerHub. Tunnel subnet {subnet}, egress {egress}.\n"
        f"nat on {egress} inet from {subnet} to any -> ({egress})\n"
    )


def set_forwarding(enabled: bool) -> dict:
    """Toggle IPv4 forwarding for the running system.

    Deliberately runtime-only.  Persisting it means writing ``/etc/sysctl.conf``,
    which affects the whole machine's networking beyond WireGuard; the boot
    LaunchDaemon action is the supported way to make the tunnel survive a reboot,
    and it re-applies this.
    """
    value = "1" if enabled else "0"
    rc, _, _ = sh(["sudo", "-n", SYSCTL, "-w", f"net.inet.ip.forwarding={value}"], timeout=10)
    if rc == 0:
        return {"ok": True, "enabled": bool(enabled), "persisted": False}
    result = run_admin_sequence(
        [[SYSCTL, "-w", f"net.inet.ip.forwarding={value}"]], timeout=120
    )
    if result.get("ok"):
        result.update(enabled=bool(enabled), persisted=False)
    return result


# ── editing /etc/pf.conf ─────────────────────────────────────────────────────
#
# pf groups rules into classes and refuses to load a file that presents them out
# of order: options, normalization, queueing, translation, filtering.  A
# `nat-anchor` therefore cannot go at the end of a file that already has filter
# anchors, which is what appending produced -- and the failure is total.  pfctl
# rejects the whole file, so a bad append does not merely fail to add NAT, it
# stops every existing pf rule from being (re)loaded.  Placement per class, and a
# parse check before the file is put in place, are both mandatory.

#: Lines that put pfctl into its translation state.
_TRANSLATION_RE = re.compile(r"^\s*(?:nat|rdr|binat)(?:-anchor)?\b")
#: Lines that put pfctl into its normalization state (must precede translation).
_NORMALIZATION_RE = re.compile(r"^\s*scrub(?:-anchor)?\b")
#: Lines that put pfctl into its filtering state (must follow translation).
_FILTER_RE = re.compile(r"^\s*(?:anchor|pass|block|match|antispoof)\b")
#: `load anchor` is not part of the ordered classes; it is grouped for tidiness.
_LOAD_RE = re.compile(r"^\s*load\s+anchor\b")


def _anchor_reference_lines(text: str) -> list[str]:
    """Every line in *text* that wires our anchor into pf, however it got there."""
    quoted = f'"{ANCHOR_NAME}"'
    return [
        line
        for line in (text or "").splitlines()
        if quoted in line and not line.strip().startswith("#")
    ]


def _without_our_lines(text: str) -> list[str]:
    """*text* as lines, with this panel's contributions stripped out.

    Both the marker comment and any reference to the anchor go, whether this panel
    wrote them or an operator did.  Removing pre-existing references as well is
    what makes installing idempotent: the machine this was found on had the anchor
    wired in twice, once correctly and once appended out of order, and adding a
    third copy would not have helped.
    """
    quoted = f'"{ANCHOR_NAME}"'
    kept = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped == PF_MARKER or (stripped.startswith("#") and PF_MARKER in line):
            continue
        if quoted in line:
            continue
        kept.append(line)
    return kept


def _insert_after_last(lines: list[str], pattern: re.Pattern, entry: str) -> None:
    """Put *entry* directly after the last line matching *pattern*, else at the end."""
    for index in range(len(lines) - 1, -1, -1):
        if pattern.match(lines[index]):
            lines.insert(index + 1, entry)
            return
    lines.append(entry)


def render_pf_conf(text: str) -> str:
    """*text* with our three anchor directives wired into the right pf sections.

    ``nat-anchor`` joins the translation rules, ``anchor`` the filter rules and
    ``load anchor`` the other loads.  When a file has no translation rules at all
    the nat-anchor has to go *before* the first filter rule rather than after the
    last one, or it lands in the filtering section and pf rejects the file.

    Each line carries the marker as a trailing comment so it can be identified and
    removed later without depending on its position.
    """
    lines = _without_our_lines(text)
    tail_comment = f"  {PF_MARKER}"

    nat_entry = f'nat-anchor "{ANCHOR_NAME}"{tail_comment}'
    if any(_TRANSLATION_RE.match(line) for line in lines):
        _insert_after_last(lines, _TRANSLATION_RE, nat_entry)
    else:
        first_filter = next(
            (i for i, line in enumerate(lines) if _FILTER_RE.match(line)), None
        )
        if first_filter is not None:
            lines.insert(first_filter, nat_entry)
        else:
            _insert_after_last(lines, _NORMALIZATION_RE, nat_entry)

    _insert_after_last(lines, _FILTER_RE, f'anchor "{ANCHOR_NAME}"{tail_comment}')
    _insert_after_last(
        lines,
        _LOAD_RE,
        f'load anchor "{ANCHOR_NAME}" from "{PF_ANCHOR_PATH}"{tail_comment}',
    )
    return "\n".join(lines).strip("\n") + "\n"


def _validate_pf_conf(body: str, anchor_path: Path) -> dict:
    """Parse-check a candidate ``pf.conf`` before it is allowed near ``/etc``.

    ``load anchor`` is followed at parse time, so the check has to point at a copy
    of the anchor body that exists *now* -- on a first install the real anchor is
    not in place yet.  Only that one path differs from what gets written.
    """
    probe_body = body.replace(f'from "{PF_ANCHOR_PATH}"', f'from "{anchor_path}"')
    probe = _STAGE_DIR / "pf.conf.check"
    write_secret_text(probe, probe_body)
    rc, out, err = sh([PFCTL, "-n", "-f", str(probe)], timeout=15)
    if rc == 0:
        return {"ok": True, "message": ""}
    lines = [line.strip() for line in f"{err}\n{out}".splitlines() if line.strip()]
    faults = [line for line in lines if re.search(r":\d+:", line)]
    return {"ok": False, "message": " ".join(faults or lines)[:300]}


def install_nat() -> dict:
    """Install the pf NAT anchor and reference it from ``/etc/pf.conf``.

    ``/etc/pf.conf`` is Apple-owned, so it is edited rather than replaced, and a
    timestamped backup is taken first.  The generated file is parse-checked with
    ``pfctl -n`` before installation: that costs nothing, needs no privileges, and
    is the difference between "NAT could not be added" and "pf can no longer load
    any rules at all".
    """
    cfg_ = wireguard_svc.settings()
    egress = wan_interface()
    if not egress:
        return {"ok": False, "error": "no_egress"}
    subnet = cfg_["subnet"]

    anchor_body = render_anchor(subnet, egress)
    staged_anchor = _STAGE_DIR / "pf-anchor-wireguard"
    write_secret_text(staged_anchor, anchor_body)

    try:
        current = PF_CONF.read_text(errors="replace")
    except OSError:
        return {"ok": False, "error": "pf_conf_unreadable"}

    desired = render_pf_conf(current)
    check = _validate_pf_conf(desired, staged_anchor)
    if not check["ok"]:
        return {"ok": False, "error": "pf_conf_invalid", "message": check["message"]}

    staged_conf = _STAGE_DIR / "pf.conf.staged"
    write_secret_text(staged_conf, desired)

    commands = [
        ["/bin/mkdir", "-p", str(PF_ANCHOR_DIR)],
        [CP, str(staged_anchor), str(PF_ANCHOR_PATH)],
        [CHOWN, "root:wheel", str(PF_ANCHOR_PATH)],
        [CHMOD, "644", str(PF_ANCHOR_PATH)],
        [CP, str(PF_CONF), f"{PF_CONF}.serverhub.bak"],
        [CP, str(staged_conf), str(PF_CONF)],
        [CHOWN, "root:wheel", str(PF_CONF)],
        [CHMOD, "644", str(PF_CONF)],
        # -E enables pf and bumps its reference count, so this does not fight
        # another tool that also wants pf on.
        [PFCTL, "-f", str(PF_CONF)],
        [PFCTL, "-E"],
    ]
    result = run_admin_sequence(commands, timeout=180)
    if result.get("ok"):
        result.update(
            subnet=subnet,
            egress=egress,
            anchor=str(PF_ANCHOR_PATH),
            loaded=nat_active(),
        )
    return result


def remove_nat() -> dict:
    """Remove the anchor file and every line wiring the anchor into ``pf.conf``."""
    try:
        current = PF_CONF.read_text(errors="replace")
    except OSError:
        return {"ok": False, "error": "pf_conf_unreadable"}

    commands: list[list[str]] = []
    if _anchor_reference_lines(current) or PF_MARKER in current:
        desired = "\n".join(_without_our_lines(current)).strip("\n") + "\n"
        check = _validate_pf_conf(desired, PF_ANCHOR_PATH)
        if not check["ok"]:
            return {
                "ok": False,
                "error": "pf_conf_invalid",
                "message": check["message"],
            }
        staged = _STAGE_DIR / "pf.conf.staged"
        write_secret_text(staged, desired)
        commands += [
            [CP, str(PF_CONF), f"{PF_CONF}.serverhub.bak"],
            [CP, str(staged), str(PF_CONF)],
            [CHOWN, "root:wheel", str(PF_CONF)],
            [CHMOD, "644", str(PF_CONF)],
        ]
    if PF_ANCHOR_PATH.exists():
        commands.append([RM, "-f", str(PF_ANCHOR_PATH)])
    if not commands:
        return {"ok": True, "removed": False}
    commands.append([PFCTL, "-f", str(PF_CONF)])
    result = run_admin_sequence(commands, timeout=180)
    if result.get("ok"):
        result["removed"] = True
    return result


def install_daemon() -> dict:
    """Install the boot-time LaunchDaemon so the tunnel survives a reboot.

    The plist is generated here rather than copied from Homebrew's template; see
    :func:`render_daemon_plist` for why that template cannot be used as-is.  An
    existing job is booted out first so this is repeatable -- ``bootstrap`` over a
    loaded label fails, which previously made a second attempt look like a
    permissions problem.
    """
    daemon = daemon_state()
    target = Path(daemon["plist_path"])
    staged = _STAGE_DIR / f"{daemon['label']}.plist"
    write_secret_text(staged, _daemon_plist_body())

    commands: list[list[str]] = []
    if daemon["loaded"] or daemon["installed"]:
        commands.append([LAUNCHCTL, "bootout", f"system/{daemon['label']}"])
    commands += [
        [CP, str(staged), str(target)],
        [CHOWN, "root:wheel", str(target)],
        [CHMOD, "644", str(target)],
        [LAUNCHCTL, "bootstrap", "system", str(target)],
    ]
    result = run_admin_sequence(commands, timeout=180)
    if result.get("ok"):
        result["label"] = daemon["label"]
    return result


def uninstall_daemon() -> dict:
    """Unload and delete the boot-time LaunchDaemon.  The tunnel keeps running."""
    daemon = daemon_state()
    target = Path(daemon["plist_path"])
    if not target.exists():
        return {"ok": True, "removed": False}
    result = run_admin_sequence(
        [
            [LAUNCHCTL, "bootout", f"system/{daemon['label']}"],
            [RM, "-f", str(target)],
        ],
        timeout=180,
    )
    if result.get("ok"):
        result["removed"] = True
    return result
