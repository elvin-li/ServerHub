#!/bin/bash
# Repair the machine-side WireGuard state this host was found in.
#
# Five separate faults, each of which alone is enough to make the tunnel useless:
#
#  1. /etc/pf.conf had the NAT anchor wired in twice, the second copy appended
#     after Apple's filter anchors.  pf enforces an order on rule classes, so
#     `pfctl -f /etc/pf.conf` failed outright -- not just "NAT missing" but every
#     pf rule on the machine unloadable.  The panel meanwhile reported NAT as
#     installed, because the anchor file and the reference were both present.
#  2. The sudoers policy pinned `wg show wg0 dump`, an invocation that cannot
#     succeed on macOS: the tunnel runs as a kernel-assigned utun and `wg` has to
#     be given that name.  Hence "not running" beside a live tunnel, and a
#     `wg syncconf` that failed on every peer change.
#  3. /Library/LaunchDaemons/com.wireguard.wg0.plist ran `wg-quick up` under
#     KeepAlive.  `wg-quick up` exits as soon as the interface is configured, so
#     launchd restarted it forever; /var/log/wireguard-wg0.log is a wall of
#     "`wg0' already exists as `utun8'".
#  4. A leftover /var/run/wireguard/wg0.name from a teardown that was killed
#     part-way leaves the interface permanently unstartable.
#
#  5. The panel's own WireGuard settings (public endpoint, LAN CIDR, egress
#     interface) live in services.yaml and were lost when that file was reset to
#     defaults.  Without the endpoint, every client config the panel generates
#     carries a placeholder instead of an address to dial.
#
# Everything here is idempotent and every replaced file is backed up first.
# Rendering is delegated to hub/wireguard_net_svc.py so this script and the panel
# cannot disagree about what a correct pf.conf or plist looks like.
#
# Usage:
#     deploy/repair-wireguard.sh                      # repair, keep endpoint
#     deploy/repair-wireguard.sh --endpoint vpn.foo   # repair and set endpoint
#     deploy/repair-wireguard.sh --lan 192.168.1.0/24
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PY="$ROOT/.venv/bin/python"
STAMP="$(date +%Y%m%d-%H%M%S)"

ENDPOINT=""
LAN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) shift; ENDPOINT="${1:?--endpoint needs a value}" ;;
    --lan) shift; LAN="${1:?--lan needs a value}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -x "$PY" ] || { echo "no interpreter at $PY" >&2; exit 1; }

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# ── 0. panel settings ────────────────────────────────────────────────────────
# wg0.conf is the one source of truth that survived, so the port, MTU and DNS are
# read back from it rather than guessed.  Idempotent: re-run this after anything
# resets services.yaml.
say "0/5  panel settings"
cd "$ROOT"
SERVERHUB_WG_ENDPOINT="$ENDPOINT" SERVERHUB_WG_LAN="$LAN" "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, ".")
from hub import wireguard_svc as w

iface = w.read_conf()["interface"]
current = w.settings()
patch = {
    "listen_port": int(iface.get("ListenPort") or current["listen_port"]),
    "mtu": int(iface.get("MTU") or current["mtu"]),
    "dns": str(iface.get("DNS") or current["dns"]),
}
endpoint = (os.environ.get("SERVERHUB_WG_ENDPOINT") or "").strip() or current["endpoint"]
lan = (os.environ.get("SERVERHUB_WG_LAN") or "").strip() or current["lan_cidr"]
if endpoint:
    patch["endpoint"] = endpoint
if lan:
    patch["lan_cidr"] = lan
if not current["wan_interface"]:
    from hub import wireguard_net_svc as n
    egress = n._default_wan_interface()
    if egress:
        patch["wan_interface"] = egress
w.save_settings(patch)

s = w.settings()
for key in ("listen_port", "mtu", "dns", "endpoint", "lan_cidr", "wan_interface"):
    print(f"    {key:<15} {s[key] or '(unset)'}")
if not s["endpoint"]:
    print("    WARNING: no public endpoint set -- generated client configs will")
    print("             carry a placeholder and cannot connect.  Re-run with")
    print("             --endpoint <host you dial from outside>.")
PYEOF

# ── 1. sudoers ───────────────────────────────────────────────────────────────
say "1/5  sudoers policy"
"$HERE/install-sudoers.sh"

# ── 2. /etc/pf.conf ──────────────────────────────────────────────────────────
say "2/5  /etc/pf.conf"
STAGED_CONF="$(mktemp -t serverhub-pf-conf)"
STAGED_ANCHOR="$(mktemp -t serverhub-pf-anchor)"
trap 'rm -f "$STAGED_CONF" "$STAGED_ANCHOR"' EXIT

cd "$ROOT"
"$PY" - "$STAGED_CONF" "$STAGED_ANCHOR" <<'PYEOF'
import pathlib, sys
sys.path.insert(0, ".")
from hub import wireguard_net_svc as n

out_conf, out_anchor = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
egress = n.wan_interface()
if not egress:
    sys.exit("could not determine the NAT egress interface")
subnet = n.wireguard_svc.settings()["subnet"]
out_anchor.write_text(n.render_anchor(subnet, egress))

current = pathlib.Path("/etc/pf.conf").read_text(errors="replace")
desired = n.render_pf_conf(current)
check = n._validate_pf_conf(desired, out_anchor)
if not check["ok"]:
    sys.exit(f"generated pf.conf is invalid, refusing to install: {check['message']}")
out_conf.write_text(desired)
print(f"    egress {egress}, subnet {subnet}")
print("    generated pf.conf passes `pfctl -n -f`")
PYEOF

if diff -q "$STAGED_CONF" /etc/pf.conf >/dev/null 2>&1; then
  echo "    already correct, left alone"
else
  sudo cp -p /etc/pf.conf "/etc/pf.conf.serverhub-$STAMP.bak"
  sudo install -m 0644 -o root -g wheel "$STAGED_CONF" /etc/pf.conf
  echo "    rewritten (backup: /etc/pf.conf.serverhub-$STAMP.bak)"
fi
sudo mkdir -p /etc/pf.anchors
sudo install -m 0644 -o root -g wheel "$STAGED_ANCHOR" /etc/pf.anchors/serverhub-wireguard
sudo /sbin/pfctl -f /etc/pf.conf
# -E enables pf and bumps its reference count, so this does not fight another
# tool that also wants pf on.
sudo /sbin/pfctl -E 2>&1 | tail -2

# ── 3. LaunchDaemon ──────────────────────────────────────────────────────────
say "3/5  boot LaunchDaemon"
STAGED_PLIST="$(mktemp -t serverhub-wg-plist)"
trap 'rm -f "$STAGED_CONF" "$STAGED_ANCHOR" "$STAGED_PLIST"' EXIT
"$PY" - "$STAGED_PLIST" <<'PYEOF'
import pathlib, sys
sys.path.insert(0, ".")
from hub import wireguard_net_svc as n
pathlib.Path(sys.argv[1]).write_text(n._daemon_plist_body())
print("    generated a one-shot RunAtLoad job (no KeepAlive respawn loop)")
PYEOF
TARGET=/Library/LaunchDaemons/com.wireguard.wg0.plist
if [ -f "$TARGET" ]; then
  sudo cp -p "$TARGET" "$TARGET.serverhub-$STAMP.bak"
  sudo launchctl bootout system/com.wireguard.wg0 2>/dev/null || true
fi
sudo install -m 0644 -o root -g wheel "$STAGED_PLIST" "$TARGET"
echo "    installed $TARGET"

# ── 4. restart the tunnel ────────────────────────────────────────────────────
say "4/5  tunnel"
CONF=/opt/homebrew/etc/wireguard/wg0.conf
sudo /opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick down "$CONF" 2>&1 | tail -2 || true
# wg-quick does not clean up after a teardown that was interrupted, and the
# leftover record makes every subsequent `up` abort with "already exists".
sudo rm -f /var/run/wireguard/wg0.name
sudo /opt/homebrew/bin/bash /opt/homebrew/bin/wg-quick up "$CONF" 2>&1 | tail -3

# ── 5. verify ────────────────────────────────────────────────────────────────
say "5/5  verification"
DEV="$(/opt/homebrew/bin/wg show interfaces | tr ' ' '\n' | tail -1)"
echo "    device                : ${DEV:-none}"
echo "    ip forwarding         : $(sysctl -n net.inet.ip.forwarding)"
printf '    pf                    : '; sudo /sbin/pfctl -s info 2>/dev/null | head -1
printf '    NAT rule loaded       : '
sudo /sbin/pfctl -a serverhub-wireguard -s nat 2>/dev/null | head -1 || echo "(none)"
echo "    listening             : $(netstat -an -p udp | awk '/\.51821/{print $1" "$4}' | tr '\n' ' ')"
echo
echo "    peers (handshake = a client actually reached this server):"
sudo /opt/homebrew/bin/wg show "$DEV" 2>/dev/null | sed 's/^/      /'
echo
echo "done."
