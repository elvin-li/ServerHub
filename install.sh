#!/usr/bin/env bash
#
# ServerHub installer (macOS).
#
# Installs into whatever directory this script lives in — nothing is
# hardcoded, so the repo can be cloned anywhere.  Safe to re-run: it upgrades
# an existing install in place and never overwrites services.yaml.
#
#   ./install.sh                 install / upgrade
#   ./install.sh --no-menubar    panel only, skip the menu-bar agent
#   ./install.sh --port 9000     serve on a different port
#
set -euo pipefail

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=8086
WITH_MENUBAR=1
PYTHON_MIN="3.10"

LABEL_PANEL="local.serverhub.panel"
LABEL_MENUBAR="local.serverhub.menubar"
LABEL_WATCHDOG="local.serverhub.watchdog"
AGENTS="$HOME/Library/LaunchAgents"
LOGS="$HOME/Library/Logs"
VENV="$BASE/.venv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-menubar) WITH_MENUBAR=0; shift ;;
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror\033[0m %s\n' "$*" >&2; exit 1; }

STATIC_DIR="$BASE/static"
STATIC_NEXT="$BASE/static.next"
STATIC_PREV="$BASE/static.prev"
STATIC_PENDING="$BASE/.static-deploy-pending"
web_deployed=0
web_had_previous=0

validate_web_bundle() {  # validate_web_bundle <directory>
  local directory="$1" js_asset css_asset
  [[ -f "$directory/index.html" && -s "$directory/sw.js" && -d "$directory/assets" ]] || return 1
  js_asset="$(find "$directory/assets" -type f -name '*.js' -print -quit 2>/dev/null)"
  css_asset="$(find "$directory/assets" -type f -name '*.css' -print -quit 2>/dev/null)"
  [[ -n "$js_asset" && -n "$css_asset" ]] || return 1
  ! grep -Fq '__SERVERHUB_CACHE_FINGERPRINT__' "$directory/sw.js" || return 1
  grep -Eq "const CACHE_NAME = 'serverhub-[[:xdigit:]]{16}'" "$directory/sw.js"
}

finish_install() {
  local status=$?
  set +e
  if [[ "$status" -ne 0 && "$web_deployed" == "1" ]]; then
    if [[ "$web_had_previous" == "1" ]] && validate_web_bundle "$STATIC_PREV"; then
      warn "Install failed after publishing the web UI; restoring static.prev."
      rm -rf "$STATIC_DIR"
      if ! mv "$STATIC_PREV" "$STATIC_DIR"; then
        warn "Could not restore static.prev automatically."
      fi
    else
      warn "Install failed after the first web publish; no static.prev is available."
    fi
    rm -f "$STATIC_PENDING"
  fi
  rm -rf "$STATIC_NEXT"
  trap - EXIT
  exit "$status"
}
trap finish_install EXIT

# ── preflight ────────────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Darwin" ]] || die "ServerHub targets macOS (found $(uname -s))."

PY="$(command -v python3 || true)"
[[ -n "$PY" ]] || die "python3 not found. Install it from python.org or via 'brew install python'."

if ! "$PY" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= tuple(int(x) for x in '$PYTHON_MIN'.split('.')) else 1)"; then
  die "python3 >= $PYTHON_MIN required (found $("$PY" -V 2>&1))."
fi

# The panel has shipped under three launchd labels: this script manages
# $LABEL_PANEL, the native ServerHub.app writes local.serverhub, and early
# releases installed com.elvin.serverhub (the same lineage the watchdog
# probes).  If one of the *other* labels is loaded, this host is an existing
# install this script does not manage; writing $LABEL_PANEL beside it would
# leave two KeepAlive'd panels racing for one port and one services.yaml.
# The old advice here ("re-run with --port") was exactly that trap.  Refuse,
# and say what an in-place upgrade actually looks like.
for legacy_label in com.elvin.serverhub local.serverhub; do
  if launchctl print "gui/$(id -u)/$legacy_label" >/dev/null 2>&1; then
    warn "an existing ServerHub panel is loaded under launchd label '$legacy_label',"
    warn "which install.sh does not manage. Installing '$LABEL_PANEL' beside it"
    warn "would run two panels against the same port and services.yaml."
    warn "Upgrade that install in place instead (see docs/upgrade.md):"
    warn "    git pull"
    warn "    .venv/bin/python -m pip install -r requirements.txt"
    warn "    launchctl kickstart -k gui/$(id -u)/$legacy_label"
    warn "or remove it first with ./uninstall.sh and re-run this script."
    die "refusing to install a second panel beside '$legacy_label'."
  fi
done

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  # Our own running instance is fine — we restart it at the end.
  if ! launchctl print "gui/$(id -u)/$LABEL_PANEL" >/dev/null 2>&1; then
    die "port $PORT is already in use by another process. Re-run with --port <n>."
  fi
fi

say "Installing ServerHub from $BASE (port $PORT)"

# ── python env ───────────────────────────────────────────────────────────────
if [[ ! -x "$VENV/bin/python" ]]; then
  say "Creating virtualenv"
  "$PY" -m venv "$VENV"
fi
say "Installing Python dependencies"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
if [[ "$WITH_MENUBAR" == "1" ]]; then
  "$VENV/bin/python" -m pip install --quiet -r "$BASE/requirements.txt"
else
  # Skip the menu-bar extras (rumps/pyobjc) when the agent is not wanted.
  grep -v -e '^rumps' -e '^pyobjc' "$BASE/requirements.txt" \
    | "$VENV/bin/python" -m pip install --quiet -r /dev/stdin
fi

# ── frontend ─────────────────────────────────────────────────────────────────
# Recover a rotation interrupted between renames. Prefer the last known-good
# bundle; on a first install, retain a complete newly-published bundle.
if [[ -e "$STATIC_PENDING" ]]; then
  warn "Recovering an interrupted web UI deployment."
  if validate_web_bundle "$STATIC_PREV"; then
    rm -rf "$STATIC_DIR"
    mv "$STATIC_PREV" "$STATIC_DIR"
  elif ! validate_web_bundle "$STATIC_DIR" && validate_web_bundle "$STATIC_NEXT"; then
    rm -rf "$STATIC_DIR"
    mv "$STATIC_NEXT" "$STATIC_DIR"
  fi
  rm -f "$STATIC_PENDING"
fi
if ! validate_web_bundle "$STATIC_DIR" && validate_web_bundle "$STATIC_PREV"; then
  warn "Restoring the last known-good web UI from static.prev."
  rm -rf "$STATIC_DIR"
  mv "$STATIC_PREV" "$STATIC_DIR"
fi
rm -rf "$STATIC_NEXT"

# static/ is committed, so a plain clone can boot without Node. Rebuild only
# when the validated bundle is absent or frontend inputs are newer.
if [[ -d "$BASE/web" ]]; then
  rebuild_web=0
  if ! validate_web_bundle "$STATIC_DIR"; then
    rebuild_web=1
  elif find "$BASE/web/src" "$BASE/web/public" \
      "$BASE/web/package.json" "$BASE/web/package-lock.json" \
      "$BASE/web/vite.config.js" \
      -type f -newer "$STATIC_DIR/index.html" -print -quit 2>/dev/null \
      | grep -q .; then
    rebuild_web=1
  fi

  if [[ "$rebuild_web" == "1" ]]; then
    command -v npm >/dev/null 2>&1 \
      || die "web sources are newer than static/ and npm is not installed — cannot build the web UI."
    say "Building web UI in static.next"
    (
      cd "$BASE/web"
      npm ci --silent
      SERVERHUB_WEB_OUT_DIR="$STATIC_NEXT" npm run build --silent
    )
    validate_web_bundle "$STATIC_NEXT" \
      || die "web build is incomplete (need index.html, sw.js, and JS/CSS assets)."

    web_had_previous=0
    validate_web_bundle "$STATIC_DIR" && web_had_previous=1
    rm -rf "$STATIC_PREV"
    : > "$STATIC_PENDING"
    web_deployed=1
    if [[ -e "$STATIC_DIR" || -L "$STATIC_DIR" ]]; then
      mv "$STATIC_DIR" "$STATIC_PREV"
    fi
    mv "$STATIC_NEXT" "$STATIC_DIR"
  fi
fi

# ── config ───────────────────────────────────────────────────────────────────
mkdir -p "$BASE/data" "$LOGS"
# Clear macOS provenance xattr that can block chmod/writes in sandboxed contexts
xattr -d com.apple.provenance "$BASE/data" 2>/dev/null || true
chmod 700 "$BASE/data" 2>/dev/null || true
# Native clients and first-run setup use independent bearer secrets. They are
# generated locally and never placed in services.yaml or command arguments.
if [[ ! -s "$BASE/data/.local-client-token" ]]; then
  umask 077
  "$VENV/bin/python" -c 'import secrets,sys; open(sys.argv[1], "w").write(secrets.token_urlsafe(32)+"\n")' "$BASE/data/.local-client-token"
fi
chmod 600 "$BASE/data/.local-client-token"
if [[ ! -s "$BASE/data/.setup-token" ]] && ! grep -q 'password_hash:' "$BASE/services.yaml" 2>/dev/null; then
  umask 077
  "$VENV/bin/python" -c 'import secrets,sys; open(sys.argv[1], "w").write(secrets.token_urlsafe(32)+"\n")' "$BASE/data/.setup-token"
fi
[[ ! -e "$BASE/data/.setup-token" ]] || chmod 600 "$BASE/data/.setup-token"
if [[ -f "$BASE/services.yaml" ]]; then
  say "Keeping existing services.yaml"
else
  say "Creating services.yaml from the shipped example"
  install -m 600 "$BASE/services.yaml.example" "$BASE/services.yaml"
fi

# ── launch agents ────────────────────────────────────────────────────────────
mkdir -p "$AGENTS"

write_plist() {   # write_plist <label> <script> <logfile> [extra-env-key extra-env-val]
  local label="$1" script="$2" log="$3"
  cat > "$AGENTS/$label.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>$VENV/bin/python</string>
		<string>$BASE/$script</string>
	</array>
	<key>WorkingDirectory</key><string>$BASE</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
		<key>SERVERHUB_PORT</key><string>$PORT</string>
	</dict>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<!-- launchd throttles Background jobs on CPU and disk I/O.  The panel
	     serves a UI someone is waiting on, so it is classified with the apps. -->
	<key>ProcessType</key><string>Interactive</string>
	<key>StandardOutPath</key><string>$LOGS/$log.out.log</string>
	<key>StandardErrorPath</key><string>$LOGS/$log.err.log</string>
</dict>
</plist>
PLIST
}

reload_agent() {  # reload_agent <label>
  local label="$1" uid domain target out rc=0
  uid="$(id -u)"
  domain="gui/$uid"
  target="$domain/$label"
  launchctl bootout "$target" 2>/dev/null || true
  # `launchctl disable` writes to launchd's per-user database and survives
  # reboots, so a label the panel's autostart page once disabled makes
  # `bootstrap` fail with "Service is disabled".  Clear that record *before*
  # bootstrapping — the same order hub/launcher_svc.py:set_login_enabled() and
  # macos/ServerHubLauncher.swift:setLoginEnabled() use.
  launchctl enable "$target" 2>/dev/null || true
  out="$(launchctl bootstrap "$domain" "$AGENTS/$label.plist" 2>&1)" || rc=$?
  # bootstrap sometimes reports a failure for a job that did load; trust the
  # job state over the exit code (launcher_svc.py's "rc == 0 or _loaded(...)").
  if [[ "$rc" -ne 0 ]] && ! launchctl print "$target" >/dev/null 2>&1; then
    warn "launchctl bootstrap $label failed (exit $rc): ${out:-no output}"
    warn "  a persistent disable record blocks bootstrap; look for the label in:"
    warn "      launchctl print-disabled $domain"
    warn "  clear it with:"
    warn "      launchctl enable $target"
    warn "  panel log: tail -n 40 $LOGS/serverhub.err.log"
    die "could not load launch agent $label — it will not start at login."
  fi
}

say "Installing launch agent: $LABEL_PANEL"
write_plist "$LABEL_PANEL" "app.py" "serverhub"
reload_agent "$LABEL_PANEL"

if [[ "$WITH_MENUBAR" == "1" ]]; then
  say "Installing launch agent: $LABEL_MENUBAR"
  write_plist "$LABEL_MENUBAR" "menubar.py" "serverhub-menubar"
  reload_agent "$LABEL_MENUBAR"
fi

# KeepAlive restarts the panel when it exits, but not when it hangs without
# exiting -- a replacement can wedge in xpcproxy holding the job's pid, so
# launchd still reports the job as running while nothing answers on the port.
# This probe restarts the panel after ~3 minutes of an unreachable port; see
# deploy/panel-watchdog.sh for why it is deliberately slow to act.
say "Installing launch agent: $LABEL_WATCHDOG"
sed -e "s|__WATCHDOG__|$BASE/deploy/panel-watchdog.sh|" \
    -e "s|__LOG__|$LOGS/serverhub-watchdog.err.log|" \
    -e "s|__PORT__|$PORT|" \
    "$BASE/deploy/local.serverhub.watchdog.plist" > "$AGENTS/$LABEL_WATCHDOG.plist"
chmod +x "$BASE/deploy/panel-watchdog.sh" 2>/dev/null || true
reload_agent "$LABEL_WATCHDOG"

# ── WireGuard system integration ────────────────────────────────────────────
if command -v wg-quick >/dev/null 2>&1; then
  say "Setting up WireGuard system integration"

  # Install / update the WireGuard LaunchDaemon (runs wg-quick on boot).
  # Uses exec-sleep wrapper so wg-quick's exit after setup does not trigger
  # endless respawns that pile up duplicate processes.
  # The leading sysctl restores IP forwarding, which is runtime-only and resets to
  # 0 on every boot -- wg0.conf has no PostUp, so without this the tunnel comes up,
  # clients handshake, and nothing routes anywhere. Every panel status stays green,
  # which makes it the hardest version of this failure to diagnose.
  # The guarded `wg-quick down` in front matters when this runs against a tunnel
  # that is already up: wg-quick answers an existing interface with `die` (exit 1),
  # so a bare `up` would fail, skip the sleep, and let KeepAlive respawn forever.
  # Guarded on the claim file so a clean boot logs no spurious teardown error --
  # and so a stale claim from a dirty shutdown gets cleared instead of blocking up.
  # Keep this wrapper identical to hub/wireguard_net_svc.py:render_daemon_plist(),
  # which is what the panel writes; a difference between them shows up as the
  # daemon reading "not the job this panel manages".
  # macOS sleep does not accept "infinity"; use a very large value instead.
  # Whether this host wants a boot job is decided by wg0.conf, not by
  # Homebrew's own plist template — that template is never read, the daemon
  # below is written from scratch.  Homebrew's prefix differs between Apple
  # silicon and Intel, so probe both (hub/wireguard_svc.py:_CONF_DIRS).
  WG_LABEL="com.wireguard.wg0"
  WG_PLIST_DST="/Library/LaunchDaemons/$WG_LABEL.plist"
  WG_CONF=""
  for candidate in /opt/homebrew/etc/wireguard/wg0.conf /usr/local/etc/wireguard/wg0.conf; do
    [[ -f "$candidate" ]] || continue
    WG_CONF="$candidate"
    break
  done
  # wg-quick's `#!/usr/bin/env bash` shebang finds Apple's bash 3.2 under the
  # scrubbed daemon PATH and refuses to run, so both are pinned by absolute
  # path with the same Homebrew-prefix fallback.
  WG_BASH="/bin/bash"
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    [[ -x "$candidate" ]] || continue
    WG_BASH="$candidate"
    break
  done
  WG_QUICK_BIN=""
  for candidate in /opt/homebrew/bin/wg-quick /usr/local/bin/wg-quick; do
    [[ -x "$candidate" ]] || continue
    WG_QUICK_BIN="$candidate"
    break
  done
  [[ -n "$WG_QUICK_BIN" ]] || WG_QUICK_BIN="$(command -v wg-quick)"

  if [[ -n "$WG_CONF" ]]; then
    TMP_PLIST="$(mktemp -t wg-launchd)"
    # Unquoted heredoc delimiter so the probed paths expand.  The only other
    # shell metacharacter in this XML is none: `&amp;&amp;` is literal text and
    # must reach the plist verbatim (it is the escaped `&&` launchd needs).
    cat > "$TMP_PLIST" <<WGPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>$WG_LABEL</string>
    <key>ProgramArguments</key><array>
        <string>$WG_BASH</string>
        <string>-c</string>
        <string>/usr/sbin/sysctl -w net.inet.ip.forwarding=1; [ -e /var/run/wireguard/wg0.name ] &amp;&amp; $WG_QUICK_BIN down $WG_CONF; $WG_QUICK_BIN up $WG_CONF &amp;&amp; exec sleep 864000000</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>GroupName</key><string>wheel</string>
    <key>EnvironmentVariables</key><dict>
        <key>PATH</key><string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>StandardErrorPath</key><string>/var/log/wireguard-wg0.log</string>
    <key>StandardOutPath</key><string>/var/log/wireguard-wg0.log</string>
</dict></plist>
WGPLIST
    sudo cp "$TMP_PLIST" "$WG_PLIST_DST" && rm -f "$TMP_PLIST"
    sudo chown root:wheel "$WG_PLIST_DST" 2>/dev/null || true
    sudo chmod 644 "$WG_PLIST_DST" 2>/dev/null || true
    # launchctl load/unload are deprecated and report nothing useful.  bootout
    # may legitimately fail when the daemon was never loaded, but bootstrap's
    # result is the one that decides whether the tunnel comes up at boot.
    sudo launchctl bootout "system/$WG_LABEL" 2>/dev/null || true
    wg_boot_rc=0
    wg_boot_out="$(sudo launchctl bootstrap system "$WG_PLIST_DST" 2>&1)" || wg_boot_rc=$?
    if [[ "$wg_boot_rc" -eq 0 ]]; then
      say "WireGuard LaunchDaemon installed"
    else
      # WireGuard is optional, so a failure here must be loud but not fatal.
      warn "WireGuard LaunchDaemon failed to load (launchctl bootstrap exit $wg_boot_rc):"
      warn "  ${wg_boot_out:-launchctl printed nothing}"
      warn "  daemon log: sudo tail -n 40 /var/log/wireguard-wg0.log"
    fi
  else
    warn "wg0.conf not found in /opt/homebrew/etc/wireguard or /usr/local/etc/wireguard; skipping WireGuard LaunchDaemon"
  fi

  # Set up PF NAT so WireGuard peers can reach the internet
  if [[ -f "$BASE/data/pf-anchor-wireguard" ]]; then
    sudo mkdir -p /etc/pf.anchors 2>/dev/null || true
    sudo cp "$BASE/data/pf-anchor-wireguard" /etc/pf.anchors/serverhub-wireguard 2>/dev/null || true
    if ! grep -q 'serverhub-wireguard' /etc/pf.conf 2>/dev/null; then
      echo '' | sudo tee -a /etc/pf.conf >/dev/null
      echo 'nat-anchor "serverhub-wireguard"' | sudo tee -a /etc/pf.conf >/dev/null
      echo 'anchor "serverhub-wireguard"' | sudo tee -a /etc/pf.conf >/dev/null
      echo 'load anchor "serverhub-wireguard" from "/etc/pf.anchors/serverhub-wireguard"' | sudo tee -a /etc/pf.conf >/dev/null
    fi
    sudo pfctl -E 2>/dev/null || true
    sudo pfctl -f /etc/pf.conf 2>/dev/null || true
    say "PF NAT rules installed"
  fi
fi

# Install / refresh sudoers rules for passwordless privileged operations
if [[ -x "$BASE/deploy/install-sudoers.sh" ]]; then
  say "Installing sudoers rules"
  "$BASE/deploy/install-sudoers.sh"
fi

# ── verify ───────────────────────────────────────────────────────────────────
say "Waiting for the panel to answer on :$PORT"
ok=0
for _ in $(seq 1 30); do
  # Read curl headers from stdin so the mode-0600 token never appears in the
  # process list, command trace, or installer output.
  if {
    printf 'X-ServerHub-Local-Token: '
    tr -d '\r\n' < "$BASE/data/.local-client-token"
    printf '\n'
  } | curl -fsS -m 2 -H @- \
      "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
done

if [[ "$ok" != "1" ]]; then
  warn "The panel did not answer within 30s. Check the log:"
  warn "  tail -n 40 $LOGS/serverhub.err.log"
  exit 1
fi

# The new bundle is now known-good. Keep static.prev for manual recovery, but
# clear the transaction marker so later failures do not roll back this deploy.
rm -f "$STATIC_PENDING"
web_deployed=0

printf '\n'
say "ServerHub is running: http://localhost:$PORT"
cat <<NEXT

  Next step — set the administrator password locally:

      open http://localhost:$PORT

  On a fresh install, enter the one-time setup token from:

      $BASE/data/.setup-token

  The panel listens on loopback by default. Authentication is mandatory after
  setup; the menu-bar client uses its own mode-0600 local token.

  Manage the service:
      launchctl kickstart -k gui/$(id -u)/$LABEL_PANEL    # restart
      ./uninstall.sh                                     # remove

NEXT
