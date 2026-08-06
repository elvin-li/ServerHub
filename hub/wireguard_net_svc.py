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

import re
from pathlib import Path

from hub import wireguard_svc
from hub.macos_admin import run_admin_sequence, sudo_capture
from hub.paths import DATA_DIR
from hub.secure_io import write_secret_text
from hub.util import sh

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
    """The interface holding the default route, e.g. ``en0``."""
    rc, out, _ = sh(["/sbin/route", "-n", "get", "default"], timeout=5)
    if rc == 0:
        match = re.search(r"interface:\s*(\S+)", out)
        if match:
            return match.group(1)
    return ""


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


def nat_installed() -> dict:
    """Whether the NAT anchor file exists and /etc/pf.conf references it."""
    anchor_exists = PF_ANCHOR_PATH.exists()
    referenced = False
    try:
        referenced = PF_MARKER in PF_CONF.read_text(errors="replace")
    except OSError:
        referenced = False
    anchor_body = ""
    if anchor_exists:
        try:
            anchor_body = PF_ANCHOR_PATH.read_text(errors="replace")[:600]
        except OSError:
            anchor_body = ""
    return {
        "anchor_path": str(PF_ANCHOR_PATH),
        "anchor_exists": anchor_exists,
        "referenced": referenced,
        "complete": anchor_exists and referenced,
        "anchor_body": anchor_body,
    }


def daemon_state() -> dict:
    """Whether the boot-time LaunchDaemon for this interface is installed/loaded."""
    interface = wireguard_svc.settings()["interface"]
    label = f"com.wireguard.{interface}"
    installed = (LAUNCH_DAEMON_DIR / f"{label}.plist").exists()
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
    # The Homebrew formula ships a template here; surface it so the UI can offer
    # to install the file the operator already has rather than inventing one.
    template = wireguard_svc.conf_dir() / f"{label}.plist"
    return {
        "label": label,
        "plist_path": str(LAUNCH_DAEMON_DIR / f"{label}.plist"),
        "installed": installed,
        "loaded": loaded,
        "template_path": str(template),
        "template_exists": template.exists(),
    }


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


def readiness() -> dict:
    """Every gate between "config exists" and "a client actually gets traffic"."""
    install = wireguard_svc.installation()
    state = wireguard_svc.status()
    cfg_ = wireguard_svc.settings()
    nat = nat_installed()
    daemon = daemon_state()
    conflict = peer_origin_conflict()
    runtime = wireguard_svc.runtime_state()
    forwarding = forwarding_enabled()
    pf_on = pf_enabled()
    egress = wan_interface()
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
            "detail": state.get("state_error") or cfg_["interface"],
        },
        {
            "id": "endpoint",
            "ok": bool(endpoint),
            "level": "error",
            "detail": endpoint,
        },
        {
            "id": "forwarding",
            "ok": forwarding is True,
            "level": "error",
            "detail": "net.inet.ip.forwarding",
        },
        {
            "id": "nat",
            "ok": bool(nat["complete"]),
            "level": "error",
            "detail": f"{nat['anchor_path']} -> {egress or 'unknown egress'}",
        },
        {
            "id": "pf",
            "ok": pf_on is True,
            "level": "warn",
            "detail": "pfctl status",
        },
        {
            "id": "boot",
            "ok": bool(daemon["installed"]),
            "level": "warn",
            "detail": daemon["plist_path"],
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


def install_nat() -> dict:
    """Install the pf NAT anchor and reference it from ``/etc/pf.conf``.

    ``/etc/pf.conf`` is Apple-owned, so it is edited rather than replaced: the
    existing text is read, the anchor lines are appended once behind a marker, and
    a timestamped backup is taken first.  ``nat-anchor`` must be placed with the
    other nat rules and ``anchor`` with the filter rules; pf rejects a file whose
    rule classes are out of order, which is why both go at the end together only
    when the file has no explicit rule sections of its own.
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

    commands: list[list[str]] = []
    if PF_MARKER not in current:
        addition = (
            f"\n{PF_MARKER}\n"
            f'nat-anchor "{ANCHOR_NAME}"\n'
            f'anchor "{ANCHOR_NAME}"\n'
            f'load anchor "{ANCHOR_NAME}" from "{PF_ANCHOR_PATH}"\n'
        )
        staged_conf = _STAGE_DIR / "pf.conf.staged"
        write_secret_text(staged_conf, current.rstrip("\n") + "\n" + addition)
        commands += [
            [CP, str(PF_CONF), f"{PF_CONF}.serverhub.bak"],
            [CP, str(staged_conf), str(PF_CONF)],
            [CHOWN, "root:wheel", str(PF_CONF)],
            [CHMOD, "644", str(PF_CONF)],
        ]

    commands = [
        ["/bin/mkdir", "-p", str(PF_ANCHOR_DIR)],
        [CP, str(staged_anchor), str(PF_ANCHOR_PATH)],
        [CHOWN, "root:wheel", str(PF_ANCHOR_PATH)],
        [CHMOD, "644", str(PF_ANCHOR_PATH)],
        *commands,
        # -E enables pf and bumps its reference count, so this does not fight
        # another tool that also wants pf on.
        [PFCTL, "-f", str(PF_CONF)],
        [PFCTL, "-E"],
    ]
    result = run_admin_sequence(commands, timeout=180)
    if result.get("ok"):
        result.update(subnet=subnet, egress=egress, anchor=str(PF_ANCHOR_PATH))
    return result


def remove_nat() -> dict:
    """Remove the anchor file and the lines this panel added to ``/etc/pf.conf``."""
    try:
        current = PF_CONF.read_text(errors="replace")
    except OSError:
        return {"ok": False, "error": "pf_conf_unreadable"}

    commands: list[list[str]] = []
    if PF_MARKER in current:
        kept: list[str] = []
        skip = 0
        for line in current.splitlines():
            if line.strip() == PF_MARKER:
                # The marker plus the three directives it introduces.
                skip = 4
            if skip:
                skip -= 1
                continue
            kept.append(line)
        staged = _STAGE_DIR / "pf.conf.staged"
        write_secret_text(staged, "\n".join(kept).rstrip("\n") + "\n")
        commands += [
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
    """Install the boot-time LaunchDaemon so the tunnel survives a reboot."""
    daemon = daemon_state()
    template = Path(daemon["template_path"])
    if not template.exists():
        return {"ok": False, "error": "no_template", "path": str(template)}
    target = Path(daemon["plist_path"])
    result = run_admin_sequence(
        [
            [CP, str(template), str(target)],
            [CHOWN, "root:wheel", str(target)],
            [CHMOD, "644", str(target)],
            [LAUNCHCTL, "bootstrap", "system", str(target)],
        ],
        timeout=180,
    )
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
