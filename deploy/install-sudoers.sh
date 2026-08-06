#!/bin/bash
# Install ServerHub's sudoers rules for the account that actually runs the panel.
#
# Why a script instead of `install -m 0440 ...`:
#
#  1. The template cannot hardcode an account. The previously installed copy
#     granted its rules to a user named "serverhub" while the panel ran as
#     someone else, so every narrowed rule silently missed. Features that needed
#     them either prompted for a password (impossible from a web request) or
#     leaned on a separate, far broader grant.
#  2. A malformed sudoers file breaks sudo for everyone. `visudo -cf` validates
#     the generated file BEFORE it is put in place, and the previous file is
#     backed up so a bad outcome is recoverable.
#  3. Mode and owner must be exactly 0440 root:wheel. Two of the files found on
#     this machine were 0644, which sudo tolerates but which lets any local
#     account read the policy.
#
# Usage:
#     deploy/install-sudoers.sh            # install for the current user
#     deploy/install-sudoers.sh --check    # validate only, change nothing
#     deploy/install-sudoers.sh --user bob # install for a specific account
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/sudoers.d/serverhub"
TARGET="/etc/sudoers.d/serverhub"
STATE_ROOT="$(cd "$HERE/.." && pwd)"

CHECK_ONLY=0
RUN_USER="$(id -un)"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY=1 ;;
    --user) shift; RUN_USER="${1:?--user needs a value}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ ! -f "$TEMPLATE" ]; then
  echo "template missing: $TEMPLATE" >&2
  exit 1
fi
if ! id -u "$RUN_USER" >/dev/null 2>&1; then
  echo "no such account: $RUN_USER" >&2
  exit 1
fi

STAGED="$(mktemp -t serverhub-sudoers)"
# The template is the single source of truth; only the two placeholders move.
sed -e "s|__SERVERHUB_USER__|$RUN_USER|g" \
    -e "s|__SERVERHUB_STATE__|$STATE_ROOT|g" \
    "$TEMPLATE" > "$STAGED"

if grep -q "__SERVERHUB_" "$STAGED"; then
  echo "unsubstituted placeholder left in the generated file:" >&2
  grep -n "__SERVERHUB_" "$STAGED" >&2
  rm -f "$STAGED"
  exit 1
fi

# Validate before going anywhere near /etc. visudo needs the file to be named
# after the target for its own sanity checks, so check the staged copy directly.
if ! visudo -cf "$STAGED" >/dev/null; then
  echo "generated sudoers file is INVALID; refusing to install" >&2
  visudo -cf "$STAGED" || true
  rm -f "$STAGED"
  exit 1
fi

echo "validated: rules for '$RUN_USER', state root '$STATE_ROOT'"
echo "commands granted:"
grep -cE '^\s+/' "$STAGED" | sed 's/^/  pinned rules: /'

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "--check given: nothing installed"
  echo "generated file left at: $STAGED"
  exit 0
fi

if [ -f "$TARGET" ]; then
  BACKUP="$TARGET.bak-$(date +%Y%m%d-%H%M%S)"
  sudo cp -p "$TARGET" "$BACKUP"
  echo "backed up existing policy -> $BACKUP"
fi

sudo install -m 0440 -o root -g wheel "$STAGED" "$TARGET"
rm -f "$STAGED"
echo "installed $TARGET"

# A final whole-policy check: an individual file can be valid while the combined
# policy is not (duplicate aliases across files, for example).
if sudo visudo -c >/dev/null; then
  echo "combined sudoers policy is valid"
else
  echo "WARNING: combined policy failed validation; check /etc/sudoers.d" >&2
  exit 1
fi

echo
echo "verify with:  sudo -n -l | grep NOPASSWD"
