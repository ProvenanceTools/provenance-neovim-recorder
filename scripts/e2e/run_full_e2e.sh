#!/usr/bin/env bash
# Plan 9 Task 4 (SUCCESS CRITERION): produce a FULL-SIGNALS sealed bundle via
# the headless Neovim recorder (open/change/save/close + paste + external
# change + terminal + git + snapshot + a checkpoint), then hand it to the
# REAL Provenance monorepo's analysis-core for validation. This is stronger
# than scripts/e2e/run_e2e.sh (Plan 4 Task 10), which only exercises the lean
# doc.open/doc.change/doc.save core — this proves the real analyzer accepts a
# bundle carrying every signal kind, including paste and external-change
# reconstruction.
#
# Usage: scripts/e2e/run_full_e2e.sh
# Env:   PROVENANCE_MONOREPO (default: /Users/aaryanmehta/projects/provenance)
#        NVIM (default: nvim)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

NVIM="${NVIM:-nvim}"
PROVENANCE_MONOREPO="${PROVENANCE_MONOREPO:-/Users/aaryanmehta/projects/provenance}"

OUT_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$OUT_DIR"
}
trap cleanup EXIT

echo "== Producing full-signals bundle via headless Neovim recorder =="
PROVNVIM_E2E_OUT="$OUT_DIR" \
  "$NVIM" --headless -u tests/minimal_init.lua -l scripts/e2e/produce_full_signals_bundle.lua

BUNDLE_PATH="$OUT_DIR/full-signals-bundle.zip"
if [ ! -f "$BUNDLE_PATH" ]; then
  echo "FAIL: expected bundle not found at $BUNDLE_PATH"
  exit 1
fi
echo "Bundle produced: $BUNDLE_PATH"

echo
echo "== Validating full-signals bundle against the real Provenance analyzer =="
echo "PROVENANCE_MONOREPO=$PROVENANCE_MONOREPO"

if PROVENANCE_MONOREPO="$PROVENANCE_MONOREPO" node "$REPO_ROOT/scripts/verify-bundle-with-analyzer.mjs" "$BUNDLE_PATH"; then
  echo
  echo "PASS: real analyzer accepted the full-signals Neovim-produced bundle."
  exit 0
else
  status=$?
  echo
  echo "FAIL: real analyzer did not accept the full-signals Neovim-produced bundle (exit $status)."
  exit "$status"
fi
