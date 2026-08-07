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
#  4. `visudo -cf` checks grammar, not whether a rule can ever match. 32 rules
#     once shipped as `smartctl -a ^/dev/[A-Za-z0-9]+$`, which is valid syntax
#     and is listed by `sudo -l`, but sudo only enters regex mode when the
#     argument list BEGINS with `^` -- so those rules were glob-matched against a
#     literal `^`, matched nothing, and SMART reads quietly asked for a password
#     for as long as they were installed. `--verify` catches that class of bug by
#     asking sudo what it will actually allow; see deploy/verify-sudoers.py.
#
# Usage:
#     deploy/install-sudoers.sh            # install for the current user
#     deploy/install-sudoers.sh --check    # validate only, change nothing
#     deploy/install-sudoers.sh --verify   # audit the policy sudo has loaded
#     deploy/install-sudoers.sh --user bob # install for a specific account
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/sudoers.d/serverhub"
TARGET="/etc/sudoers.d/serverhub"
STATE_ROOT="$(cd "$HERE/.." && pwd)"

CHECK_ONLY=0
VERIFY_ONLY=0
RUN_USER="$(id -un)"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK_ONLY=1 ;;
    --verify) VERIFY_ONLY=1 ;;
    --user) shift; RUN_USER="${1:?--user needs a value}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$VERIFY_ONLY" -eq 1 ]; then
  exec python3 "$HERE/verify-sudoers.py"
fi

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
  # The backup stays in /etc/sudoers.d, which sudo reads -- but sudo skips file
  # names containing a '.' or ending in '~' (sudoers(5)), so `serverhub.bak-...`
  # is inert. Do NOT rename a backup to something without a dot to "restore" it;
  # that loads it alongside the current policy instead of replacing it. Copy it
  # over $TARGET instead.
  BACKUP="$TARGET.bak-$(date +%Y%m%d-%H%M%S)"
  sudo cp -p "$TARGET" "$BACKUP"
  echo "backed up existing policy -> $BACKUP (inert: sudo skips names with a dot)"
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

# Grammar was valid and the file is in place; now check that the rules sudo
# loaded actually match the calls the panel makes. A rule that can never match is
# indistinguishable from a missing one at runtime, and `visudo` cannot see it.
echo
python3 "$HERE/verify-sudoers.py"
