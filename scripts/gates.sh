#!/usr/bin/env bash
#
# Run every quality gate and report each exit code accurately.
#
# Why this file exists: the ad-hoc form
#
#     npm test 2>&1 | tail -5; echo "rc=${PIPESTATUS[0]}"
#
# is wrong as soon as anything else runs between the pipeline and the echo --
# PIPESTATUS is clobbered by the next command, so the reported code was
# sometimes empty and sometimes belonged to `tail` rather than the tool. That
# produced "rc=0" for a gate whose result had never actually been read.
#
# Here every gate writes full output to a log file and its status is captured
# immediately into a variable, with no pipeline in between. Nothing is
# summarised until all gates have run, and the script's own exit code is
# non-zero if any gate failed.
#
# Usage:  scripts/gates.sh [--quiet]
#         --quiet   only print the summary table, not per-gate tails
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB="$REPO/web"
PY="$REPO/.venv/bin/python"
LOGS="$(mktemp -d)"
trap 'rm -rf "$LOGS"' EXIT

QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1

# name -> rc, kept in parallel arrays so this works on bash 3.2 (macOS default).
GATE_NAMES=()
GATE_CODES=()
GATE_NOTES=()

# run <name> <workdir> <command...>
# Captures the exit code with no pipeline involved, so $? is unambiguous.
run() {
  local name="$1" dir="$2"; shift 2
  local log="$LOGS/$name.log"
  ( cd "$dir" && "$@" ) >"$log" 2>&1
  local rc=$?
  GATE_NAMES+=("$name")
  GATE_CODES+=("$rc")
  GATE_NOTES+=("")
  if [ "$QUIET" -eq 0 ]; then
    printf '=== %s (rc=%d) ===\n' "$name" "$rc"
    tail -6 "$log"
    printf '\n'
  fi
  return $rc
}

note() {  # attach a measured value to the last gate
  GATE_NOTES[${#GATE_NOTES[@]}-1]="$1"
}

log_of() { printf '%s/%s.log' "$LOGS" "$1"; }

# ---------------------------------------------------------------- backend ----
run backend-unittest "$REPO" "$PY" -m unittest discover -s tests -t . -q
note "$(grep -Eo 'Ran [0-9]+ tests' "$(log_of backend-unittest)" | tail -1)"

run pyflakes "$REPO" "$PY" -m pyflakes hub tests app.py menubar.py
note "$(grep -c . "$(log_of pyflakes)" | tr -d ' ') finding(s)"

run vulture "$REPO" "$PY" -m vulture hub app.py menubar.py --min-confidence 80
note "$(grep -c . "$(log_of vulture)" | tr -d ' ') finding(s)"

# --------------------------------------------------------------- frontend ----
run frontend-test "$WEB" npm test --silent
note "$(grep -Eo 'Tests +[0-9]+ passed \([0-9]+\)' "$(log_of frontend-test)" | tail -1 | tr -s ' ')"

# stderr noise is its own gate: warnings do not fail a test run, so a passing
# suite can still be printing an experimental-API warning on every worker.
NOISE=$(grep -cE 'ExperimentalWarning|\[Vue warn\]|Not implemented' "$(log_of frontend-test)" | tr -d ' ')
GATE_NAMES+=("frontend-stderr-clean"); GATE_CODES+=("$([ "$NOISE" -eq 0 ] && echo 0 || echo 1)")
GATE_NOTES+=("$NOISE warning line(s)")

run frontend-build "$WEB" npm run build --silent
note "$(grep -Eo 'index-[A-Za-z0-9_-]+\.js +[0-9.]+ kB' "$(log_of frontend-build)" | tail -1 | tr -s ' ')"

run knip "$WEB" npm run check:dead-code --silent
note "$(grep -vcE '^$|^>' "$(log_of knip)" | tr -d ' ') report line(s)"

# ---------------------------------------------------------------- summary ----
printf '\n══ GATE SUMMARY ══\n'
FAILED=0
i=0
while [ $i -lt ${#GATE_NAMES[@]} ]; do
  rc="${GATE_CODES[$i]}"
  if [ "$rc" -eq 0 ]; then mark="PASS"; else mark="FAIL"; FAILED=1; fi
  printf '%-24s %s  rc=%-3s %s\n' "${GATE_NAMES[$i]}" "$mark" "$rc" "${GATE_NOTES[$i]}"
  i=$((i + 1))
done

if [ "$FAILED" -ne 0 ]; then
  printf '\nFailing gate logs:\n'
  i=0
  while [ $i -lt ${#GATE_NAMES[@]} ]; do
    if [ "${GATE_CODES[$i]}" -ne 0 ] && [ -f "$(log_of "${GATE_NAMES[$i]}")" ]; then
      printf -- '--- %s ---\n' "${GATE_NAMES[$i]}"
      tail -25 "$(log_of "${GATE_NAMES[$i]}")"
    fi
    i=$((i + 1))
  done
fi

exit "$FAILED"
