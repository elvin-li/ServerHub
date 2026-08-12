#!/usr/bin/env bash
#
# ServerHub uninstaller — removes the LaunchAgents and (optionally) the venv.
#
#   ./uninstall.sh              stop + remove LaunchAgents, keep config & data
#   ./uninstall.sh --purge      also delete .venv, data/ and services.yaml
#
# Never touches the apps ServerHub manages (containers, brew services, VMs).
set -euo pipefail

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS="$HOME/Library/LaunchAgents"
UID_NUM="$(id -u)"
PURGE=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*"; }

# The panel and menu-bar jobs have shipped under three naming schemes, and a
# host can carry more than one at a time (a source install plus a native
# ServerHub.app, say).  Removing only the dotted install.sh labels left the
# native and distribution agents loaded and set to RunAtLoad, so the panel came
# straight back after an "uninstall".  Every spelling is booted out here; labels
# that are not present simply do not match and cost one launchctl probe.
for label in \
  local.serverhub.panel local.serverhub.menubar local.serverhub.launcher \
  local.serverhub.watchdog \
  local.serverhub local.serverhub-launcher local.serverhub-menubar \
  com.elvin.serverhub com.elvin.serverhub-launcher com.elvin.serverhub-menubar; do
  plist="$AGENTS/$label.plist"
  if launchctl print "gui/$UID_NUM/$label" >/dev/null 2>&1; then
    say "stopping $label"
    launchctl bootout "gui/$UID_NUM/$label" 2>/dev/null || true
  fi
  if [[ -f "$plist" ]]; then
    say "removing $plist"
    rm -f "$plist"
  fi
done

# The optional FileBrowser helper is installed by the Files page, not by
# install.sh, but a full uninstall should not leave it running either.
if launchctl print "gui/$UID_NUM/local.filebrowser" >/dev/null 2>&1; then
  say "stopping local.filebrowser"
  launchctl bootout "gui/$UID_NUM/local.filebrowser" 2>/dev/null || true
fi
rm -f "$AGENTS/local.filebrowser.plist"

if [[ "$PURGE" == "1" ]]; then
  warn "--purge: deleting venv, data/ and services.yaml"
  rm -rf "$BASE/.venv" "$BASE/data"
  rm -f "$BASE/services.yaml"
  say "purged"
else
  say "kept services.yaml and data/ (use --purge to delete them)"
fi

cat <<EOF

ServerHub has been removed from login items and is no longer running.
The source tree at $BASE was left in place — delete it manually if you
no longer need it.
EOF
