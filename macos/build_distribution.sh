#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="3.9.4"
ARCH="arm64"
PYTHON_VERSION="3.12.13"
PYTHON_RELEASE="20260728"
PYTHON_ARCHIVE="cpython-${PYTHON_VERSION}+${PYTHON_RELEASE}-aarch64-apple-darwin-install_only_stripped.tar.gz"
PYTHON_SHA256="2f18cdef4125ca1440dd1ba00ebcb267526efb532138c0860438f755ea4eebac"
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_RELEASE}/cpython-${PYTHON_VERSION}%2B${PYTHON_RELEASE}-aarch64-apple-darwin-install_only_stripped.tar.gz"
LOCK_FILE="$ROOT/macos/requirements-distribution.txt"
OUTPUT_DIR="${1:-$ROOT/.build/distribution}"
CACHE_DIR="${SERVERHUB_DISTRIBUTION_CACHE:-$ROOT/.build/distribution-cache}"
LOCAL_PYTHON_ARCHIVE="${SERVERHUB_PYTHON_ARCHIVE:-}"
BUILD_APP="${SERVERHUB_BUILD_APP:-$ROOT/macos/build_app.sh}"
CURL="${SERVERHUB_CURL:-/usr/bin/curl}"
SHASUM="${SERVERHUB_SHASUM:-/usr/bin/shasum}"
TAR="${SERVERHUB_TAR:-/usr/bin/tar}"
DITTO="${SERVERHUB_DITTO:-/usr/bin/ditto}"
PLUTIL="${SERVERHUB_PLUTIL:-/usr/bin/plutil}"
CODESIGN="${SERVERHUB_CODESIGN:-/usr/bin/codesign}"
HDIUTIL="${SERVERHUB_HDIUTIL:-/usr/bin/hdiutil}"
XATTR="${SERVERHUB_XATTR:-/usr/bin/xattr}"
FILE="${SERVERHUB_FILE:-/usr/bin/file}"
LIPO="${SERVERHUB_LIPO:-/usr/bin/lipo}"
OTOOL="${SERVERHUB_OTOOL:-/usr/bin/otool}"

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "$ARCH" ]]; then
  printf 'error: distribution builds require Apple Silicon macOS\n' >&2
  exit 2
fi
[[ -f "$LOCK_FILE" ]] || { printf 'error: missing dependency lock: %s\n' "$LOCK_FILE" >&2; exit 2; }
[[ -x "$BUILD_APP" ]] || { printf 'error: build script is not executable: %s\n' "$BUILD_APP" >&2; exit 2; }
mkdir -p "$OUTPUT_DIR" "$CACHE_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
CACHE_DIR="$(cd "$CACHE_DIR" && pwd -P)"
WORK="$(mktemp -d "$OUTPUT_DIR/.serverhub-distribution.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

archive_sha256() {
  "$SHASUM" -a 256 "$1" | cut -d ' ' -f 1
}

if [[ -n "$LOCAL_PYTHON_ARCHIVE" ]]; then
  ARCHIVE_PATH="$LOCAL_PYTHON_ARCHIVE"
else
  ARCHIVE_PATH="$CACHE_DIR/$PYTHON_ARCHIVE"
  if [[ -f "$ARCHIVE_PATH" && "$(archive_sha256 "$ARCHIVE_PATH")" != "$PYTHON_SHA256" ]]; then
    rm -f "$ARCHIVE_PATH"
  fi
  if [[ ! -f "$ARCHIVE_PATH" ]]; then
    printf 'Downloading pinned CPython %s runtime...\n' "$PYTHON_VERSION"
    "$CURL" --fail --location --proto '=https' --tlsv1.2 \
      --retry 3 --output "$ARCHIVE_PATH.partial" "$PYTHON_URL"
    mv "$ARCHIVE_PATH.partial" "$ARCHIVE_PATH"
  fi
fi
[[ -f "$ARCHIVE_PATH" ]] || { printf 'error: Python archive not found: %s\n' "$ARCHIVE_PATH" >&2; exit 2; }
ACTUAL_SHA256="$(archive_sha256 "$ARCHIVE_PATH")"
if [[ "$ACTUAL_SHA256" != "$PYTHON_SHA256" ]]; then
  printf 'error: Python archive SHA-256 mismatch: expected %s, got %s\n' \
    "$PYTHON_SHA256" "$ACTUAL_SHA256" >&2
  exit 2
fi

INSTALL_ROOT="$WORK/install"
APP="$INSTALL_ROOT/ServerHub.app"
RUNTIME="$APP/Contents/Resources/ServerHubRuntime"
WHEELHOUSE="$CACHE_DIR/wheels-cpython312-macos-arm64"
mkdir -p "$INSTALL_ROOT" "$WHEELHOUSE"

# Build the native shell first. build_app.sh transactionally replaces its
# destination, so injecting the runtime before this step would silently discard
# the extracted Python tree.
printf 'Building native application bundle...\n'
SERVERHUB_BUILD_DIR="$WORK/native-build" "$BUILD_APP" "$APP"
rm -f "$APP/Contents/Resources/install-root.txt"
"$PLUTIL" -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
"$PLUTIL" -replace CFBundleVersion -string "$VERSION" "$APP/Contents/Info.plist"

mkdir -p "$RUNTIME"
printf 'Extracting standalone Python...\n'
"$TAR" -xzf "$ARCHIVE_PATH" -C "$RUNTIME"
PYTHON="$RUNTIME/python/bin/python3"
[[ -x "$PYTHON" ]] || { printf 'error: archive did not contain python/bin/python3\n' >&2; exit 2; }

printf 'Resolving exact backend wheel set...\n'
"$PYTHON" -m pip download \
  --disable-pip-version-check --only-binary=:all: --no-deps \
  --requirement "$LOCK_FILE" --dest "$WHEELHOUSE"
"$PYTHON" -m pip install \
  --disable-pip-version-check --no-index --find-links "$WHEELHOUSE" \
  --only-binary=:all: --no-deps --no-compile --requirement "$LOCK_FILE"
# These generated console entry points embed the temporary build directory in
# their shebangs. ServerHub imports the packages and launches app.py directly.
rm -f \
  "$RUNTIME/python/bin/fastapi" \
  "$RUNTIME/python/bin/idna" \
  "$RUNTIME/python/bin/uvicorn" \
  "$RUNTIME/python/bin/websockets"

# Copy only the immutable runtime allowlist. Mutable state is created under
# ~/Library/Application Support/ServerHub by the native launcher.
for path in app.py hub static templates services.yaml.example; do
  [[ -e "$ROOT/$path" ]] || { printf 'error: missing runtime input: %s\n' "$path" >&2; exit 2; }
  "$DITTO" --norsrc --noextattr "$ROOT/$path" "$RUNTIME/$path"
done
find "$RUNTIME" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$RUNTIME" -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' \) -delete

# Reject state, development trees, backups, credentials, and logs even if the
# allowlist is changed later.
if find "$RUNTIME" \( \
    -name services.yaml -o -name data -o -name tests -o -name node_modules -o \
    -name '.git' -o -name '.venv' -o -name '.setup-token' -o \
    -name '.local-client-token' -o -name '.session-secret' -o \
    -name '*.log' -o -name 'services.yaml.bak.*' \
  \) -print -quit | grep -q .; then
  printf 'error: forbidden mutable or development content entered runtime\n' >&2
  exit 2
fi
PATH_LEAKS="$WORK/build-path-leaks.txt"
{
  grep -R -a -F -l "$ROOT" "$APP" 2>/dev/null || true
  grep -R -a -F -l "$HOME" "$APP" 2>/dev/null || true
} | sort -u > "$PATH_LEAKS"
if [[ -s "$PATH_LEAKS" ]]; then
  printf 'error: application contains a build-machine absolute path in:\n' >&2
  while IFS= read -r leaked; do
    printf '  %s\n' "${leaked#"$APP"/}" >&2
  done < "$PATH_LEAKS"
  exit 2
fi

printf 'Validating isolated runtime...\n'
STATE="$WORK/state"
HOME_DIR="$WORK/home"
mkdir -p "$STATE" "$HOME_DIR"
env -i \
  HOME="$HOME_DIR" PATH="/usr/bin:/bin" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
  SERVERHUB_RUNTIME_DIR="$RUNTIME" SERVERHUB_STATE_DIR="$STATE" \
  "$PYTHON" -I -B - "$RUNTIME" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
from hub import auth
from hub.app_factory import create_app
from hub.config import cfg

cfg()
auth.local_client_token()
auth.setup_token()
app = create_app()
assert app is not None
PY
[[ -f "$STATE/services.yaml" && -f "$STATE/data/.local-client-token" && -f "$STATE/data/.setup-token" ]]
[[ ! -e "$RUNTIME/services.yaml" && ! -e "$RUNTIME/data" ]]

printf 'Writing release manifest...\n'
SERVERHUB_MANIFEST_VERSION="$VERSION" \
SERVERHUB_MANIFEST_PYTHON_ARCHIVE="$PYTHON_ARCHIVE" \
SERVERHUB_MANIFEST_PYTHON_SHA256="$PYTHON_SHA256" \
SERVERHUB_MANIFEST_LOCK="$LOCK_FILE" \
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -I -B - "$RUNTIME" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
lock = pathlib.Path(os.environ["SERVERHUB_MANIFEST_LOCK"])
dependencies = {}
for raw in lock.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if line and not line.startswith("#"):
        name, version = line.split("==", 1)
        dependencies[name] = version
files = []
for path in sorted(root.rglob("*")):
    if path.is_file() and not path.is_symlink() and path.name != "release-manifest.json":
        files.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        })
manifest = {
    "architecture": "arm64",
    "dependencies": dependencies,
    "files": files,
    "minimum_macos": "13.0",
    "python_archive": os.environ["SERVERHUB_MANIFEST_PYTHON_ARCHIVE"],
    "python_sha256": os.environ["SERVERHUB_MANIFEST_PYTHON_SHA256"],
    "version": os.environ["SERVERHUB_MANIFEST_VERSION"],
}
(root / "release-manifest.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

printf 'Checking Mach-O architecture and deployment targets...\n'
SERVERHUB_FILE="$FILE" SERVERHUB_LIPO="$LIPO" SERVERHUB_OTOOL="$OTOOL" \
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -I -B - "$APP" <<'PY'
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
file_tool = os.environ["SERVERHUB_FILE"]
lipo = os.environ["SERVERHUB_LIPO"]
otool = os.environ["SERVERHUB_OTOOL"]
checked = 0
for path in root.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    kind = subprocess.run([file_tool, "-b", str(path)], text=True, capture_output=True, check=True).stdout
    if "Mach-O" not in kind:
        continue
    checked += 1
    arches = subprocess.run([lipo, "-archs", str(path)], text=True, capture_output=True, check=True).stdout.split()
    if arches != ["arm64"]:
        raise SystemExit(f"non-arm64 Mach-O: {path}: {' '.join(arches)}")
    load = subprocess.run([otool, "-l", str(path)], text=True, capture_output=True, check=True).stdout
    versions = [tuple(map(int, value.split("."))) for value in re.findall(r"^\s*minos\s+(\d+(?:\.\d+){1,2})", load, re.M)]
    lines = load.splitlines()
    for index, line in enumerate(lines):
        if "cmd LC_VERSION_MIN_MACOSX" in line:
            for candidate in lines[index + 1:index + 5]:
                match = re.match(r"\s*version\s+(\d+(?:\.\d+){1,2})", candidate)
                if match:
                    versions.append(tuple(map(int, match.group(1).split("."))))
                    break
    if versions and max(versions) > (13, 0):
        raise SystemExit(f"Mach-O requires newer than macOS 13: {path}: {max(versions)}")
if checked == 0:
    raise SystemExit("no Mach-O files found in application")
print(f"Validated {checked} arm64 Mach-O files")
PY

if find "$RUNTIME" \( -type d -name __pycache__ -o -type f \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit | grep -q .; then
  printf 'error: Python bytecode cache entered signed runtime\n' >&2
  exit 2
fi

"$XATTR" -cr "$APP"
"$CODESIGN" --force --deep --sign - "$APP"
"$CODESIGN" --verify --deep --strict "$APP"

INSTALL_TEXT="$WORK/INSTALL.txt"
cat > "$INSTALL_TEXT" <<'TXT'
ServerHub 3.9.4 Apple Silicon 测试版 / Test Build

要求 / Requirements: Apple Silicon Mac, macOS 13 or newer.
安装 / Install: 将 ServerHub.app 拖入 Applications，然后启动。
首次打开 / First open: 此测试版未经过 Apple 公证。请右键点按应用并选择“打开”；
或在“系统设置 → 隐私与安全性”中允许打开。
首次设置 / First setup: 应用会启动本机后台、打开设置页，并在本机对话框中
显示且复制一次性设置令牌。令牌不会放入 URL 或日志。
数据 / Data: 配置与密钥保存在 ~/Library/Application Support/ServerHub。
TXT

DMG_ROOT="$WORK/dmg-root"
mkdir -p "$DMG_ROOT"
"$DITTO" --norsrc --noextattr "$APP" "$DMG_ROOT/ServerHub.app"
cp "$INSTALL_TEXT" "$DMG_ROOT/安装说明-INSTALL.txt"
ln -s /Applications "$DMG_ROOT/Applications"
DMG_NAME="ServerHub-${VERSION}-arm64-test.dmg"
DMG_STAGED="$WORK/$DMG_NAME"
"$HDIUTIL" create -quiet -volname "ServerHub $VERSION" -srcfolder "$DMG_ROOT" \
  -ov -format UDZO "$DMG_STAGED"

rm -rf "$OUTPUT_DIR/ServerHub.app"
rm -f "$OUTPUT_DIR/$DMG_NAME" "$OUTPUT_DIR/$DMG_NAME.sha256" "$OUTPUT_DIR/INSTALL.txt"
"$DITTO" --norsrc --noextattr "$APP" "$OUTPUT_DIR/ServerHub.app"
mv "$DMG_STAGED" "$OUTPUT_DIR/$DMG_NAME"
cp "$INSTALL_TEXT" "$OUTPUT_DIR/INSTALL.txt"
(
  cd "$OUTPUT_DIR"
  "$SHASUM" -a 256 "$DMG_NAME" > "$DMG_NAME.sha256"
)
printf 'Built %s\n' "$OUTPUT_DIR/$DMG_NAME"
printf 'SHA-256 %s\n' "$(archive_sha256 "$OUTPUT_DIR/$DMG_NAME")"
