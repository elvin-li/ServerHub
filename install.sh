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

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((10#$PORT < 1 || 10#$PORT > 65535)); then
  die "--port must be an integer between 1 and 65535"
fi

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
		<key>SERVERHUB_HOST</key><string>127.0.0.1</string>
	</dict>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>10</integer>
	<key>ExitTimeOut</key><integer>30</integer>
	<key>StandardOutPath</key><string>$LOGS/$log.out.log</string>
	<key>StandardErrorPath</key><string>$LOGS/$log.err.log</string>
</dict>
</plist>
PLIST
}

reload_agent() {  # reload_agent <label>
  local label="$1" target="gui/$(id -u)/$1"
  launchctl bootout "$target" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$AGENTS/$label.plist"
  launchctl enable "$target" 2>/dev/null || true
}

say "Installing launch agent: $LABEL_PANEL"
write_plist "$LABEL_PANEL" "app.py" "serverhub"
reload_agent "$LABEL_PANEL"

if [[ "$WITH_MENUBAR" == "1" ]]; then
  say "Installing launch agent: $LABEL_MENUBAR"
  write_plist "$LABEL_MENUBAR" "menubar.py" "serverhub-menubar"
  reload_agent "$LABEL_MENUBAR"
fi

# Earlier installs used other launchd labels. Stop leftover panel (and, when
# this install owns the menu bar, leftover launcher) jobs so :$PORT is not
# held by com.elvin.serverhub / local.serverhub / the old watchdog.
_retire_leftover_agent() {
  local label="$1"
  [[ "$label" == "$LABEL_PANEL" || "$label" == "$LABEL_MENUBAR" ]] && return 0
  local target="gui/$(id -u)/$label"
  if launchctl print "$target" >/dev/null 2>&1; then
    say "Retiring leftover launch agent: $label"
    launchctl bootout "$target" 2>/dev/null || true
  fi
  rm -f "$AGENTS/$label.plist"
}
for leftover in local.serverhub.watchdog local.serverhub com.elvin.serverhub; do
  _retire_leftover_agent "$leftover"
done
if [[ "$WITH_MENUBAR" == "1" ]]; then
  for leftover in \
    local.serverhub-launcher local.serverhub-menubar \
    com.elvin.serverhub-launcher com.elvin.serverhub-menubar; do
    _retire_leftover_agent "$leftover"
  done
fi

# ── WireGuard system integration ────────────────────────────────────────────
if command -v wg-quick >/dev/null 2>&1; then
  say "Setting up WireGuard system integration"

  # Install / update the WireGuard LaunchDaemon (runs wg-quick on boot).
  # Uses exec-sleep wrapper so wg-quick's exit after setup does not trigger
  # endless respawns that pile up duplicate processes.
  WG_PLIST_SRC="/opt/homebrew/etc/wireguard/com.wireguard.wg0.plist"
  WG_PLIST_DST="/Library/LaunchDaemons/com.wireguard.wg0.plist"
  if [[ -f "$WG_PLIST_SRC" ]]; then
    TMP_PLIST="$(mktemp -t wg-launchd)"
    cat > "$TMP_PLIST" <<'WGPLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>com.wireguard.wg0</string>
    <key>ProgramArguments</key><array>
        <string>/opt/homebrew/bin/bash</string>
        <string>-c</string>
        <string>/opt/homebrew/bin/wg-quick up /opt/homebrew/etc/wireguard/wg0.conf && exec sleep infinity</string>
    </array>
    <key>RunAtLoad</key><true/>
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
    sudo launchctl unload "$WG_PLIST_DST" 2>/dev/null || true
    sudo launchctl load "$WG_PLIST_DST" 2>/dev/null || true
    say "WireGuard LaunchDaemon installed"
  else
    warn "WireGuard config not found at $WG_PLIST_SRC; skipping LaunchDaemon"
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

  The panel binds 127.0.0.1:$PORT (this Mac only). Open it at
  http://localhost:$PORT. Authentication is mandatory after setup; the
  menu-bar client uses its own mode-0600 local token. To listen on the LAN
  set SERVERHUB_HOST=0.0.0.0 in the LaunchAgent plist.

  Manage the service:
      launchctl kickstart -k gui/$(id -u)/$LABEL_PANEL    # restart
      ./uninstall.sh                                     # remove

NEXT
