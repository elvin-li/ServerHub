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
import plistlib
import re
import socket
from pathlib import Path

from hub import wireguard_svc, wireguard_wstunnel
from hub.host_address import default_interface
from hub.launchd_cache import loaded_labels
from hub.macos_admin import run_admin_sequence, sudo_capture
from hub.paths import DATA_DIR
from hub.secure_io import drop_leftover_nonfile, replace_secret_text
from hub.util import fan_out, read_text_capped, sh

#: Leftover multi-MB ``/etc/pf.conf`` / LaunchDaemon plist used to OOM
#: GET /api/wireguard.
_PF_CONF_CAP = 256 * 1024
_ANCHOR_CAP = 8 * 1024
_PLIST_CAP = 256 * 1024


def _path_exists(path) -> bool:
    """``Path.exists()`` re-raises EIO/ESTALE; that used to 500 GET /api/wireguard."""
    try:
        return Path(path).exists()
    except (OSError, ValueError, TypeError):
        return False


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


def _stage_file(path: Path, content: str) -> bool:
    """Write a staging file under data/, clearing an empty leftover occupant.

    Every remediation stages its payload here before the privileged copy.  A
    leftover directory occupying one of these fixed names (``pf.conf.check``,
    ``pf.conf.staged``, ``pf-anchor-wireguard``, the two LaunchDaemon plists)
    made :func:`replace_secret_text`'s final ``os.replace`` raise
    IsADirectoryError — a raw 500 out of POST /api/wireguard/remediate before
    any privileged step ran.  An empty leftover is removed and the write
    self-heals; anything else reports False so the caller answers its coded
    failure instead.
    """
    drop_leftover_nonfile(path)
    try:
        replace_secret_text(path, content)
        return True
    except OSError:
        return False


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` so GET /api/wireguard/readiness cannot UTF-8 500.

    Unbound through the base types: a bytes-subclass whose bound ``.decode``
    raises, or a str-subclass whose ``__str__`` returns itself and whose
    bound ``.encode`` raises, used to detonate this launderer — the readiness
    probes run under ``fan_out``, which re-raises, so one poisoned ``sh``
    stream 500'd the whole page.
    """
    if isinstance(value, bytes):
        text = bytes.decode(value, "utf-8", "replace")
    elif isinstance(value, bytearray):
        text = bytearray.decode(value, "utf-8", "replace")
    elif isinstance(value, str):
        text = value
    elif value is None:
        return ""
    else:
        try:
            text = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return str.encode(text, "utf-8", "replace").decode("utf-8")


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
    return _as_text(out).strip() == "1"


def pf_enabled() -> bool | None:
    """Whether pf itself is running.  A loaded rule does nothing while pf is off."""
    rc, out, err = sh([PFCTL, "-s", "info"], timeout=6)
    if rc != 0:
        rc, out, err = sudo_capture([PFCTL, "-s", "info"], timeout=6)
    blob = f"{_as_text(out)}\n{_as_text(err)}"
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
    lines = [
        line.strip()
        for line in f"{_as_text(err)}\n{_as_text(out)}".splitlines()
        if line.strip()
    ]
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
    return bool(re.search(r"^\s*nat\b", _as_text(out), re.MULTILINE))


def nat_installed() -> dict:
    """Whether the NAT anchor file exists, pf.conf wires it in, and pf holds it."""
    anchor_exists = _path_exists(PF_ANCHOR_PATH)
    try:
        conf_text = read_text_capped(PF_CONF, _PF_CONF_CAP, errors="replace")
    except OSError:
        conf_text = ""
    # Detection keys off a reference to the anchor rather than off this panel's
    # marker comment: an operator (or an older build) may have wired the anchor in
    # by hand, and re-adding it on top would load the same rules twice.
    referenced = bool(_anchor_reference_lines(conf_text))
    anchor_body = ""
    if anchor_exists:
        try:
            anchor_body = read_text_capped(
                PF_ANCHOR_PATH, _ANCHOR_CAP, errors="replace"
            )[:600]
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

    The fix: wrap ``wg-quick up`` in ``bash -c '... && exec sleep 864000000'`` so
    the process stays alive after setup.  ``KeepAlive`` then supervises the long-
    running sleep: if the tunnel ever drops (crash, network change, manual down),
    launchd restarts the whole job.

    The ``wg-quick down`` in front of it is what makes that restart survivable, and
    it replaces a comment here that claimed ``wg-quick up`` "detects an existing
    interface and exits cleanly".  It does not: wg-quick answers an interface that
    already exists by calling ``die`` (wg-quick line 454), and ``die`` exits 1.
    So ``up`` on a tunnel that is already running fails, ``&&`` skips the
    sleep, bash exits non-zero, and ``KeepAlive`` restarts it -- the very respawn
    loop this wrapper exists to avoid.  That is not hypothetical: it is what
    installing this job from the panel would do on any host whose tunnel is
    currently up, which is exactly when an operator reaches for that button.

    The teardown is guarded on the claim file rather than run unconditionally, so a
    clean boot -- nothing to remove -- does not log a "not a WireGuard interface"
    error every time and leave the operator wondering what failed.  The guard also
    clears a *stale* claim left by a run that died mid-setup, which would otherwise
    block ``up`` on every boot with a message pointing at the wrong problem.

    ``sysctl -w net.inet.ip.forwarding=1`` leads the command because that setting is
    runtime-only and returns to 0 on every boot, and nothing else puts it back:
    ``wg0.conf`` carries no ``PostUp``, and :func:`set_forwarding` says so itself --
    it declines to write ``/etc/sysctl.conf`` and points here instead, claiming this
    job "re-applies this".  It did not.  The result was a tunnel that came up, let
    clients handshake, and then routed nothing at all, once per reboot, for the most
    misleading reason available: every status the panel showed was green, because the
    tunnel genuinely was up.  Running as root inside the daemon, no sudo is needed
    and no NOPASSWD rule has to cover it.

    macOS ``sleep`` does not accept ``infinity`` (GNU coreutils does); use a very
    large integer instead (864000000 s = ~27 years).

    wg-quick is launched through a modern bash by absolute path for the same reason
    the panel does: its ``#!/usr/bin/env bash`` shebang finds Apple's bash 3.2
    under a scrubbed PATH and refuses to run.
    """
    # Derived from the label rather than taken as an argument, matching what the log
    # path below has always done, so callers (and the tests) keep the 4-arg signature.
    interface = label.rsplit(".", 1)[-1]
    claim = f"{wireguard_svc.WG_RUN_DIR}/{interface}.name"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bash}</string>
        <string>-c</string>
        <string>{SYSCTL} -w net.inet.ip.forwarding=1; [ -e {claim} ] &amp;&amp; {wg_quick} down {conf}; {wg_quick} up {conf} &amp;&amp; exec sleep 864000000</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
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


#: The sleep wrapper's argument, so its *value* can be judged and not merely its
#: presence.  ``\S+`` rather than ``\d+`` on purpose: the whole point is to catch
#: an argument that is not a number.
_SLEEP_ARG_RE = re.compile(r"\bsleep\s+(\S+)")


def _daemon_defects(text: str) -> list[str]:
    """Why an installed boot job will not keep the tunnel up.  Worst first.

    "A job is installed" and "the tunnel comes back after a reboot" are different
    claims, and the gap between them is where this feature was actually broken on
    the host this was written for.  Its plist ran

        bash -c 'wg-quick up wg0.conf && exec sleep infinity'

    with no ``KeepAlive``.  Both halves are wrong, and neither was detected:

    * macOS ``sleep`` is BSD ``sleep``, which takes a number.  ``infinity`` is a
      GNU coreutils extension, so the wrapper printed ``usage: sleep number[unit]``
      and exited non-zero the instant ``wg-quick up`` finished.  launchd then tore
      down the job's process group, which took the backgrounded ``wireguard-go``
      with it -- so every boot configured the interface and then immediately killed
      it.  ``/var/log/wireguard-wg0.log`` recorded the pattern once per boot.
    * without ``KeepAlive`` nothing retried, and nothing restores the tunnel if it
      later drops.

    The previous detection was ``"KeepAlive" in text and "sleep" not in text``,
    which is a substring test against the raw XML looking for exactly one defect.
    This plist contained ``sleep`` and no ``KeepAlive``, so it scored clean, and
    :func:`readiness` reported boot persistence as satisfied while the tunnel was
    dead -- the panel actively told the operator to look elsewhere.  Parsing the
    plist and judging the sleep *argument* is what closes that gap.

    ``managed`` is deliberately not a defect: a job this panel did not write can
    still be perfectly good, and saying otherwise would nag on every host that
    installed the daemon by hand.  Only behaviour that demonstrably fails is listed.
    """
    text = _as_text(text)
    if not text:
        return []
    try:
        payload = plistlib.loads(text.encode("utf-8", "replace"))
    except Exception:
        # launchd will not load what plistlib cannot read, so this is a real fault
        # rather than a parsing inconvenience -- but fall back to the old substring
        # test first, so a plist that is merely unusual is not mislabelled.
        if "KeepAlive" in text and "sleep" not in text:
            return ["respawn_loop"]
        return ["unreadable"]
    if not isinstance(payload, dict):
        return ["unreadable"]

    argv = payload.get("ProgramArguments")
    command = " ".join(
        _as_text(a) for a in (argv if isinstance(argv, list) else [])
    )
    keep_alive = bool(payload.get("KeepAlive"))
    defects: list[str] = []

    if not payload.get("RunAtLoad"):
        # Loaded but inert: nothing runs it when the system comes up, which is the
        # entire job of this plist.
        defects.append("no_run_at_load")

    sleep_arg = _SLEEP_ARG_RE.search(command)
    if sleep_arg is None:
        # `wg-quick up` configures the interface and exits, so a job that runs it
        # bare does not stay alive to hold the tunnel's process group open.
        defects.append("respawn_loop" if keep_alive else "exits_after_setup")
    elif not sleep_arg.group(1).isdigit():
        defects.append("bad_sleep")

    if not keep_alive:
        defects.append("unsupervised")
    return defects


def _defects_of(daemon: dict) -> list[str]:
    """*daemon*'s defect list, tolerating a state dict from before they existed.

    Callers pass :func:`daemon_state` output, but tests and older callers build the
    dict by hand with only the legacy ``respawn_loop`` flag.  Deriving the list from
    that flag when the key is missing keeps both shapes meaningful, instead of
    silently reading a hand-built dict as defect-free.
    """
    if not isinstance(daemon, dict):
        return []
    defects = daemon.get("defects")
    if defects is None:
        return ["respawn_loop"] if daemon.get("respawn_loop") else []
    if isinstance(defects, str):
        return [defects] if defects else []
    if not isinstance(defects, (list, tuple)):
        return []
    return [str(d) for d in defects]


def daemon_state() -> dict:
    """Whether the boot-time LaunchDaemon for this interface is installed/loaded."""
    interface = wireguard_svc.settings()["interface"]
    label = f"com.wireguard.{interface}"
    target = LAUNCH_DAEMON_DIR / f"{label}.plist"
    installed = _path_exists(target)
    rc, out, _ = sh([LAUNCHCTL, "print", f"system/{label}"], timeout=6)
    if rc != 0:
        # The system domain only answers to root; reuse the web password when
        # this request carries one.
        rc, out, _ = sudo_capture([LAUNCHCTL, "print", f"system/{label}"], timeout=6)
    loaded = rc == 0
    if not loaded:
        # `launchctl print` on a system domain needs root; fall back to the listing.
        #
        # Exact label match through the shared snapshot, where this was
        # `label in out2` -- a substring test against the raw listing, which answers
        # yes for `com.wireguard.wg0` when only `com.wireguard.wg01` is loaded.  That
        # is the same defect hub/launchd_cache.py was written to remove from three
        # other modules, and this was the fourth.  `loaded_labels()` reaches only
        # `sh`, so it is safe on the request thread alongside the sudo probes above.
        loaded = label in loaded_labels()
    del out
    # An installed job that respawns `wg-quick up` in a loop is worse than no job
    # at all, so whether the file on disk is the one this panel would write is
    # part of the state, not an implementation detail.
    current = ""
    read_failed = False
    if installed:
        try:
            current = read_text_capped(target, _PLIST_CAP, errors="replace")
        except OSError:
            current = ""
            read_failed = True
    # Empty file vs unreadable leftover: ``_daemon_defects("")`` is clean,
    # which used to mark a 2MB junk plist as a healthy boot job.
    defects = ["unreadable"] if read_failed else _daemon_defects(current)
    return {
        "label": label,
        "plist_path": str(target),
        "installed": installed,
        "loaded": loaded,
        "managed": bool(current) and current == _daemon_plist_body(),
        # Every way this job can be installed and still not survive a reboot; see
        # :func:`_daemon_defects` for why presence alone was not enough to check.
        "defects": defects,
        # "The tunnel will actually be there after a reboot", which is the question
        # the readiness page is really asking.
        "healthy": installed and not defects,
        # `KeepAlive` with `wg-quick up` is the specific defect worth naming: it
        # restarts the setup script forever instead of supervising the tunnel.
        # Kept as its own key because it predates `defects` and callers read it.
        "respawn_loop": "respawn_loop" in defects,
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
    for line in _as_text(out).splitlines():
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
        _as_text(wireguard_svc.settings().get("endpoint") or "")
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
    except (OSError, UnicodeError, ValueError):
        # Leftover ``\\ud800`` in the endpoint is UnicodeError, not OSError;
        # GET /api/wireguard/readiness used to 500.
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
    # This probe does not own the provider (tests and tooling patch
    # ``peer_records``, the wireguard_svc._ping_targets rule): a listing that
    # raises, a list *subclass* whose ``__iter__`` bombs inside the old
    # comprehension, or a dict-subclass row whose bound ``.get`` raises used
    # to escape through :func:`readiness` — a raw 500 on GET
    # /api/wireguard/readiness where a junk row already dropped silently.
    try:
        raw = wireguard_svc.peer_records()
    except Exception:
        raw = []
    records = wireguard_svc._plain_rows(raw)
    if not records:
        return {"conflict": False, "reason": "no_peers", "foreign": 0, "total": 0}
    foreign = [
        r for r in records
        if not wireguard_svc._truthy(r.get("known"))
        and not wireguard_svc._truthy(r.get("reissuable"))
    ]
    conflict = len(foreign) == len(records)
    return {
        "conflict": conflict,
        "reason": "all_peers_foreign" if conflict else "",
        "foreign": len(foreign),
        "total": len(records),
        "foreign_keys": [_as_text(r.get("public_key"))[:16] for r in foreign[:10]],
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
    if not isinstance(daemon, dict):
        return ""
    path = daemon.get("plist_path") or ""
    if not daemon.get("installed"):
        return path
    # Ordered by what the operator should fix first, not by how the state dict is
    # laid out.  A defect is always more actionable than "someone else wrote this",
    # so every one of them outranks the managed notice.
    for defect, reason in (
        ("respawn_loop", "restarts wg-quick in a loop"),
        ("bad_sleep", "keeps itself alive with a sleep macOS rejects, so the "
                      "tunnel dies right after boot configures it"),
        ("exits_after_setup", "exits as soon as wg-quick finishes, which tears "
                              "down the tunnel it just created"),
        ("no_run_at_load", "has RunAtLoad off, so nothing starts it at boot"),
        ("unsupervised", "has no KeepAlive, so a dropped tunnel is never restored"),
        ("unreadable", "is not a plist launchd can load"),
    ):
        if defect in _defects_of(daemon):
            return f"{path} {reason}"
    if not daemon.get("managed"):
        return f"{path} (not the job this panel manages)"
    return path


def _addr_list(value) -> list[str]:
    """Addresses for a readiness sentence; leftover non-lists used to TypeError."""
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, (list, tuple)):
        return []
    return [_as_text(item) for item in value if item is not None and _as_text(item)]


def _resolution_detail(resolution: dict) -> str:
    """Name the addresses that cannot work, not merely that something cannot."""
    if not isinstance(resolution, dict):
        return ""
    reason = resolution.get("reason") or ""
    endpoint = _as_text(resolution.get("endpoint"))
    if reason == "not_set":
        return ""
    if reason == "dns_failed":
        return f"{endpoint} does not resolve"
    unreachable = _addr_list(resolution.get("unreachable"))
    if unreachable:
        detail = f"{endpoint} -> " + ", ".join(unreachable) + " (not this host)"
        # `.get`: the suggestion is genuinely optional -- there is often no
        # routable address of our own to name -- so a dict without one is
        # describing a real state rather than being malformed.
        suggest = _addr_list(resolution.get("suggest"))
        if suggest:
            detail += "; this host is " + ", ".join(suggest)
        return detail
    return f"{endpoint} -> " + ", ".join(_addr_list(resolution.get("resolved")))


def _nat_detail(nat: dict, egress: str) -> str:
    """Say which of the NAT preconditions is missing, not merely that one is.

    "NAT rule" with a path next to it was the same message whether the anchor was
    absent, present but not referenced, or referenced in a file pf could no longer
    load -- three different repairs behind one label.
    """
    if not isinstance(nat, dict):
        return ""
    path = nat.get("anchor_path") or str(PF_ANCHOR_PATH)
    if not nat.get("anchor_exists"):
        return f"{path} missing"
    if not nat.get("referenced"):
        return f"{PF_CONF} does not reference {ANCHOR_NAME}"
    if not nat.get("conf_parses"):
        return _as_text(nat.get("conf_error")) or f"{PF_CONF} does not parse"
    if nat.get("loaded") is False:
        return f"rule not loaded into pf ({ANCHOR_NAME})"
    return f"{path} -> {egress or 'unknown egress'}"


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
    if not isinstance(daemon, dict):
        daemon = {}
    if not isinstance(nat, dict):
        nat = {}
    if not isinstance(state, dict):
        state = {}
    if not isinstance(runtime, dict):
        runtime = {}
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
            "ok": bool(state.get("running")),
            "level": "warn",
            # The device is worth stating when it differs from the configured
            # name: on macOS the tunnel runs as some utun, and an operator
            # comparing the panel against `ifconfig` has no other way to tell
            # which one is theirs.
            "detail": state.get("state_error")
            or runtime.get("real_interface")
            or cfg_.get("interface"),
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
            "ok": bool(nat.get("conf_parses")),
            "level": "error",
            "detail": nat.get("conf_error") or str(PF_CONF),
        },
        {
            "id": "nat",
            "ok": bool(nat.get("complete")),
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
            # An installed job that cannot hold the tunnel up does not count as
            # boot persistence, so it must not show up here as satisfied. This used
            # to test only for the respawn loop, which let the defect actually
            # present on the host -- a sleep argument macOS rejects, and no
            # KeepAlive -- read as green while WireGuard was dead after every boot.
            "id": "boot",
            "ok": bool(daemon.get("installed")) and not _defects_of(daemon),
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
            "ok": not runtime.get("stale"),
            "level": "error" if runtime.get("stale") else "warn",
            "detail": runtime.get("name_file") if runtime.get("stale") else "",
        },
        *_wstunnel_readiness_checks(cfg_),
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
    and it re-applies this -- see :func:`render_daemon_plist`, which now actually
    does.  It did not when this sentence was first written, and the gap was costly:
    the setting resets to 0 on every boot, ``wg0.conf`` has no ``PostUp`` to restore
    it, so the tunnel came back up, clients handshook, and not one packet could
    leave the host.  Toggling it here therefore fixes the running system only; the
    boot job is what keeps it fixed.
    """
    value = "1" if enabled else "0"
    rc, _, _ = sh(["/usr/bin/sudo", "-n", SYSCTL, "-w", f"net.inet.ip.forwarding={value}"], timeout=10)
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
    if not _stage_file(probe, probe_body):
        # Nothing was parsed, so this is not a pf.conf verdict: flag it so
        # the caller reports the write failure rather than "pf.conf invalid".
        return {"ok": False, "message": "", "stage_failed": str(probe)}
    rc, out, err = sh([PFCTL, "-n", "-f", str(probe)], timeout=15)
    if rc == 0:
        return {"ok": True, "message": ""}
    lines = [
        line.strip()
        for line in f"{_as_text(err)}\n{_as_text(out)}".splitlines()
        if line.strip()
    ]
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
    if not _stage_file(staged_anchor, anchor_body):
        return {"ok": False, "error": "stage_write_failed", "path": str(staged_anchor)}

    try:
        current = read_text_capped(PF_CONF, _PF_CONF_CAP, errors="replace")
    except OSError:
        return {"ok": False, "error": "pf_conf_unreadable"}

    desired = render_pf_conf(current)
    check = _validate_pf_conf(desired, staged_anchor)
    if check.get("stage_failed"):
        return {"ok": False, "error": "stage_write_failed", "path": check["stage_failed"]}
    if not check["ok"]:
        return {"ok": False, "error": "pf_conf_invalid", "message": check["message"]}

    staged_conf = _STAGE_DIR / "pf.conf.staged"
    if not _stage_file(staged_conf, desired):
        return {"ok": False, "error": "stage_write_failed", "path": str(staged_conf)}

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
        current = read_text_capped(PF_CONF, _PF_CONF_CAP, errors="replace")
    except OSError:
        return {"ok": False, "error": "pf_conf_unreadable"}

    commands: list[list[str]] = []
    if _anchor_reference_lines(current) or PF_MARKER in current:
        desired = "\n".join(_without_our_lines(current)).strip("\n") + "\n"
        check = _validate_pf_conf(desired, PF_ANCHOR_PATH)
        if check.get("stage_failed"):
            return {
                "ok": False,
                "error": "stage_write_failed",
                "path": check["stage_failed"],
            }
        if not check["ok"]:
            return {
                "ok": False,
                "error": "pf_conf_invalid",
                "message": check["message"],
            }
        staged = _STAGE_DIR / "pf.conf.staged"
        if not _stage_file(staged, desired):
            return {"ok": False, "error": "stage_write_failed", "path": str(staged)}
        commands += [
            [CP, str(PF_CONF), f"{PF_CONF}.serverhub.bak"],
            [CP, str(staged), str(PF_CONF)],
            [CHOWN, "root:wheel", str(PF_CONF)],
            [CHMOD, "644", str(PF_CONF)],
        ]
    if _path_exists(PF_ANCHOR_PATH):
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
    if not _stage_file(staged, _daemon_plist_body()):
        return {"ok": False, "error": "stage_write_failed", "path": str(staged)}

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
    if not _path_exists(target):
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


def _wstunnel_readiness_checks(cfg: dict) -> list[dict]:
    """Warn-only gates, and only when the operator asked for obfuscation.

    A live process on this host must not light these up by itself: readiness
    tests (and the Health page) stay green on a Mac that happens to run the
    historical LaunchDaemon while ``wstunnel_enabled`` is off.
    """
    if not cfg.get("wstunnel_enabled"):
        return []
    snap = wireguard_wstunnel.status(cfg)
    running = bool(snap.get("running"))
    restrict = str(snap.get("restrict_to") or "")
    if snap.get("stale_restrict"):
        restrict_detail = f"{restrict} (not on this host)"
    elif not snap.get("stable_restrict"):
        suggest = snap.get("suggest_restrict_to") or "127.0.0.1"
        restrict_detail = f"{restrict} (use {suggest})"
    else:
        restrict_detail = restrict
    return [
        {
            "id": "wstunnel",
            "ok": running,
            "level": "warn",
            "detail": snap.get("listen") or snap.get("label") or "",
        },
        {
            "id": "wstunnel_align",
            "ok": bool(snap.get("aligned")),
            "level": "warn",
            "detail": (
                f"{snap.get('listen')} -> {snap.get('restrict_to')} "
                f"(want {snap.get('desired_listen')} -> {snap.get('desired_restrict_to')})"
            ),
            "superseded_by": "wstunnel",
        },
        {
            "id": "wstunnel_restrict",
            "ok": bool(snap.get("stable_restrict")) and not snap.get("stale_restrict"),
            "level": "warn",
            "detail": restrict_detail,
            # Keep this row while the process is up: "not running" is a
            # different repair.  Hide it only when the daemon is down, where
            # Apply/Stabilize on the other row already covers the gap.
            **({"superseded_by": "wstunnel"} if not running else {}),
        },
    ]


def install_wstunnel(*, restrict_to: str | None = None) -> dict:
    """Install or realign the root wstunnel LaunchDaemon from saved settings.

    The binary path is pinned to the Homebrew locations; a user-controlled
    path must never land in a root job.  ``bootout`` is joined with ``;`` so a
    missing label does not abort the rest of the sequence.
    """
    binary = wireguard_wstunnel.find_binary()
    if not binary:
        return {"ok": False, "error": "wstunnel_missing"}
    cfg = wireguard_svc.settings()
    snap = wireguard_wstunnel.status(cfg)
    listen = str(snap.get("desired_listen") or wireguard_wstunnel.DEFAULT_LISTEN)
    dest = str(restrict_to or snap.get("desired_restrict_to") or "")
    if not wireguard_wstunnel.valid_listen_url(listen):
        return {"ok": False, "error": "bad_wstunnel_url", "url": listen[:80]}
    if not wireguard_wstunnel.valid_restrict_to(dest):
        return {"ok": False, "error": "bad_wstunnel_target", "target": dest[:60]}
    try:
        body = wireguard_wstunnel.render_plist(
            binary=binary, listen=listen, restrict_to=dest,
        )
    except ValueError:
        return {"ok": False, "error": "bad_wstunnel_target", "target": dest[:60]}

    staged = _STAGE_DIR / f"{wireguard_wstunnel.LABEL}.plist"
    if not _stage_file(staged, body):
        return {"ok": False, "error": "stage_write_failed", "path": str(staged)}
    target = wireguard_wstunnel.PLIST_PATH
    result = run_admin_sequence(
        [
            [LAUNCHCTL, "bootout", f"system/{wireguard_wstunnel.LABEL}"],
            [CP, str(staged), str(target)],
            [CHOWN, "root:wheel", str(target)],
            [CHMOD, "644", str(target)],
            [LAUNCHCTL, "bootstrap", "system", str(target)],
        ],
        timeout=180,
    )
    # bootout already ran; drop the memo even when bootstrap is the step that
    # failed, or the page keeps showing a process we just tore down.
    wireguard_wstunnel.live.invalidate()
    if not result.get("ok"):
        return result
    # run_admin_sequence joins the steps with ";", so the exit status is the last
    # step's alone.  When an earlier cp/chown/chmod failed and a plist from a
    # previous install was already in place, bootstrap succeeds on the *stale*
    # file -- and echoing back `listen`/`dest` would report settings that are not
    # what root is running.  Read the installed plist back instead.
    installed = wireguard_wstunnel.read_plist(target)
    if installed.get("listen") != listen or installed.get("restrict_to") != dest:
        return {
            "ok": False,
            "error": "wstunnel_install_unverified",
            "listen": installed.get("listen") or "",
            "restrict_to": installed.get("restrict_to") or "",
        }
    result["label"] = wireguard_wstunnel.LABEL
    result["restrict_to"] = dest
    result["listen"] = listen
    return result


def uninstall_wstunnel() -> dict:
    """Unload the obfuscation daemon.  The WireGuard tunnel itself stays up."""
    target = wireguard_wstunnel.PLIST_PATH
    if not _path_exists(target):
        found = wireguard_wstunnel.live()
        if not found.get("running"):
            wireguard_svc.save_settings({"wstunnel_enabled": False})
            return {"ok": True, "removed": False, "label": wireguard_wstunnel.LABEL}
        # Process still up without a plist: unload the label, then clear the flag
        # even if launchctl says the job was already gone.
        result = run_admin_sequence(
            [[LAUNCHCTL, "bootout", f"system/{wireguard_wstunnel.LABEL}"]],
            timeout=180,
        )
        wireguard_wstunnel.live.invalidate()
        wireguard_svc.save_settings({"wstunnel_enabled": False})
        return {
            "ok": True,
            "removed": bool(result.get("ok")),
            "label": wireguard_wstunnel.LABEL,
        }
    result = run_admin_sequence(
        [
            [LAUNCHCTL, "bootout", f"system/{wireguard_wstunnel.LABEL}"],
            [RM, "-f", str(target)],
        ],
        timeout=180,
    )
    wireguard_wstunnel.live.invalidate()
    if result.get("ok"):
        wireguard_svc.save_settings({"wstunnel_enabled": False})
        result["removed"] = True
        result["label"] = wireguard_wstunnel.LABEL
    return result


def stabilize_wstunnel() -> dict:
    """Point ``--restrict-to`` at loopback, then apply the LaunchDaemon.

    Settings are written only after the privileged install succeeds, so a
    cancelled password sheet does not leave the panel believing the live
    process already dials 127.0.0.1.
    """
    cfg = wireguard_svc.settings()
    dest = wireguard_wstunnel.default_restrict_to(cfg.get("listen_port") or 0)
    if not dest:
        return {"ok": False, "error": "bad_wstunnel_target", "target": ""}
    result = install_wstunnel(restrict_to=dest)
    if result.get("ok"):
        wireguard_svc.save_settings({
            "wstunnel_enabled": True,
            "wstunnel_restrict_to": dest,
        })
        result["stabilized"] = dest
    return result
