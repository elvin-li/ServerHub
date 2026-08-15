#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="ServerHub.app"
REQUESTED_DEST="${1:-/Applications/$APP_NAME}"
DEST_PARENT="$(dirname "$REQUESTED_DEST")"
DEST_BASENAME="$(basename "$REQUESTED_DEST")"

# Absolute production defaults keep packaging deterministic. Tests may point
# these at isolated fakes to exercise rollback paths without touching a live
# application bundle.
SWIFTC="${SERVERHUB_SWIFTC:-swiftc}"
SWIFT_ARCH="$(uname -m)"
case "$SWIFT_ARCH" in
  arm64|x86_64) ;;
  *)
    printf 'error: unsupported macOS build architecture: %s\n' "$SWIFT_ARCH" >&2
    exit 2
    ;;
esac
SWIFT_TARGET="$SWIFT_ARCH-apple-macosx13.0"
SIPS="${SERVERHUB_SIPS:-/usr/bin/sips}"
ICONUTIL="${SERVERHUB_ICONUTIL:-/usr/bin/iconutil}"
PLUTIL="${SERVERHUB_PLUTIL:-/usr/bin/plutil}"
CODESIGN="${SERVERHUB_CODESIGN:-/usr/bin/codesign}"
DITTO="${SERVERHUB_DITTO:-/usr/bin/ditto}"
TOUCH="${SERVERHUB_TOUCH:-/usr/bin/touch}"

# The installer replaces one fixed bundle. Refuse an arbitrary path before any
# recursive cleanup, and require its parent to exist so a typo cannot create a
# surprising directory tree.
if [[ "$DEST_BASENAME" != "$APP_NAME" ]]; then
  printf 'error: destination must end in /%s\n' "$APP_NAME" >&2
  exit 2
fi
if [[ ! -d "$DEST_PARENT" ]]; then
  printf 'error: destination parent does not exist: %s\n' "$DEST_PARENT" >&2
  exit 2
fi
DEST_PARENT="$(cd "$DEST_PARENT" && pwd -P)"
if [[ "$DEST_PARENT" == "/" ]]; then
  printf 'error: refusing to install at filesystem root\n' >&2
  exit 2
fi
DEST="$DEST_PARENT/$APP_NAME"

BUILD_DIR="${SERVERHUB_BUILD_DIR:-$ROOT/.build/macos}"
PREBUILT_APP="${SERVERHUB_PREBUILT_APP:-}"
APP="${PREBUILT_APP:-$BUILD_DIR/$APP_NAME}"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
ICONSET="$BUILD_DIR/AppIcon.iconset"
STAGED="$DEST_PARENT/.$APP_NAME.install.$$"
BACKUP="$DEST_PARENT/.$APP_NAME.backup.$$"
LOCK="$DEST_PARENT/.$APP_NAME.install.lock"
installed=0
destination_replaced=0
lock_acquired=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  rm -rf "$STAGED"
  if [[ "$status" -ne 0 ]]; then
    # Final verification can fail after STAGED has become DEST. Remove that
    # unverified bundle even on a first install, then restore a prior bundle if
    # one existed.
    if [[ "$destination_replaced" == "1" ]]; then
      rm -rf "$DEST"
    fi
    if [[ -e "$BACKUP" || -L "$BACKUP" ]]; then
      mv "$BACKUP" "$DEST" || true
    fi
  elif [[ "$installed" == "1" ]]; then
    rm -rf "$BACKUP"
  fi
  if [[ "$lock_acquired" == "1" && -f "$LOCK/pid" ]]; then
    lock_owner="$(<"$LOCK/pid")"
    if [[ "$lock_owner" == "$$" ]]; then
      rm -rf "$LOCK"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if ! mkdir "$LOCK" 2>/dev/null; then
  lock_owner=""
  lock_is_stale=0
  if [[ -f "$LOCK/pid" ]]; then
    lock_owner="$(<"$LOCK/pid")"
  fi
  if [[ "$lock_owner" =~ ^[0-9]+$ ]]; then
    if ! kill -0 "$lock_owner" 2>/dev/null; then
      lock_is_stale=1
    fi
  else
    # The process can die after mkdir or while writing its PID. Preserve a fresh
    # incomplete or malformed lock to avoid racing that window; reclaim only an old one.
    if [[ "$(uname -s)" == "Darwin" ]]; then
      lock_mtime="$(stat -f '%m' "$LOCK" 2>/dev/null || true)"
    else
      # GNU stat: -f is --file-system, so the BSD form never yields a mtime here.
      lock_mtime="$(stat -c '%Y' "$LOCK" 2>/dev/null || true)"
    fi
    now="$(date +%s)"
    if [[ "$lock_mtime" =~ ^[0-9]+$ ]] && (( now - lock_mtime >= 60 )); then
      lock_is_stale=1
    fi
  fi
  if [[ "$lock_is_stale" == "1" ]]; then
    # A process killed with SIGKILL cannot run the EXIT trap. Atomically move its
    # directory aside: only one recovering installer can win this rename, and no
    # process ever removes a newly-created lock owned by another installer.
    stale_lock="$LOCK.stale.$$"
    if ! mv "$LOCK" "$stale_lock" 2>/dev/null; then
      printf 'error: install already in progress for %s\n' "$DEST" >&2
      exit 3
    fi
    rm -rf "$stale_lock"
    if ! mkdir "$LOCK" 2>/dev/null; then
      printf 'error: install already in progress for %s\n' "$DEST" >&2
      exit 3
    fi
  else
    printf 'error: install already in progress for %s\n' "$DEST" >&2
    exit 3
  fi
fi
printf '%s\n' "$$" > "$LOCK/pid"
lock_acquired=1

if [[ -n "$PREBUILT_APP" ]]; then
  if [[ ! -d "$APP" ]]; then
    printf 'error: prebuilt app does not exist: %s\n' "$APP" >&2
    exit 2
  fi
  APP_PHYSICAL="$(cd "$APP" && pwd -P)"
  DEST_PHYSICAL="$DEST"
  if [[ -d "$DEST" ]]; then
    DEST_PHYSICAL="$(cd "$DEST" && pwd -P)"
  fi
  if [[ "$APP_PHYSICAL" == "$DEST_PHYSICAL" ]]; then
    printf 'error: prebuilt app cannot be the install destination\n' >&2
    exit 2
  fi
  if [[ "$APP_PHYSICAL" == "$DEST_PHYSICAL/"* ]]; then
    printf 'error: prebuilt app cannot be inside the install destination\n' >&2
    exit 2
  fi
  case "$APP_PHYSICAL" in
    "$DEST_PARENT/.$APP_NAME.install."*|"$DEST_PARENT/.$APP_NAME.backup."*)
      printf 'error: prebuilt app uses a reserved installer path\n' >&2
      exit 2
      ;;
  esac
else
  rm -rf "$APP" "$ICONSET"
  mkdir -p "$MACOS" "$RESOURCES" "$ICONSET"

  "$SWIFTC" -target "$SWIFT_TARGET" \
    -parse-as-library -warnings-as-errors -O \
    -framework AppKit -framework Foundation \
    "$ROOT/macos/ServerHubLauncher.swift" \
    -o "$MACOS/ServerHub"

  cat > "$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDisplayName</key><string>ServerHub</string>
  <key>CFBundleExecutable</key><string>ServerHub</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleIdentifier</key><string>local.serverhub.app</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>ServerHub</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>3.9.1</string>
  <key>CFBundleVersion</key><string>3.9.1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

  printf '%s\n' "$ROOT" > "$RESOURCES/install-root.txt"
  SOURCE_ICON="$ROOT/web/public/icon-512.png"
  [[ -s "$SOURCE_ICON" ]] || { printf 'error: missing app icon: %s\n' "$SOURCE_ICON" >&2; exit 1; }
  icon_pids=()
  for spec in \
    "16 icon_16x16.png" "32 icon_16x16@2x.png" \
    "32 icon_32x32.png" "64 icon_32x32@2x.png" \
    "128 icon_128x128.png" "256 icon_128x128@2x.png" \
    "256 icon_256x256.png" "512 icon_256x256@2x.png" \
    "512 icon_512x512.png"; do
    size="${spec%% *}"; name="${spec#* }"
    "$SIPS" -z "$size" "$size" "$SOURCE_ICON" --out "$ICONSET/$name" >/dev/null &
    icon_pids+=("$!")
  done
  icon_status=0
  for pid in "${icon_pids[@]}"; do
    if wait "$pid"; then
      :
    else
      status=$?
      [[ "$icon_status" -ne 0 ]] || icon_status="$status"
    fi
  done
  [[ "$icon_status" -eq 0 ]] || exit "$icon_status"
  cp "$SOURCE_ICON" "$ICONSET/icon_512x512@2x.png"
  "$ICONUTIL" -c icns "$ICONSET" -o "$RESOURCES/AppIcon.icns"
fi

"$PLUTIL" -lint "$CONTENTS/Info.plist" >/dev/null
[[ "$("$PLUTIL" -extract CFBundleIdentifier raw "$CONTENTS/Info.plist")" == "local.serverhub.app" ]]
[[ -x "$MACOS/ServerHub" && -s "$RESOURCES/AppIcon.icns" ]]
if [[ -z "$PREBUILT_APP" ]]; then
  "$CODESIGN" --force --deep --sign - "$APP"
fi
"$CODESIGN" --verify --deep --strict "$APP"

# Verify a same-volume staged copy before replacing the live bundle. If the move
# fails, the EXIT trap restores the previous bundle from BACKUP.
rm -rf "$STAGED" "$BACKUP"
"$DITTO" "$APP" "$STAGED"
"$CODESIGN" --verify --deep --strict "$STAGED"
"$PLUTIL" -lint "$STAGED/Contents/Info.plist" >/dev/null
if [[ -e "$DEST" || -L "$DEST" ]]; then
  mv "$DEST" "$BACKUP"
fi
mv "$STAGED" "$DEST"
destination_replaced=1
"$CODESIGN" --verify --deep --strict "$DEST"
installed=1
"$TOUCH" "$DEST"
printf 'Installed %s\n' "$DEST"
