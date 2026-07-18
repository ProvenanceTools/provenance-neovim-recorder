#!/usr/bin/env bash
# Plan 4 Task 10 (SUCCESS CRITERION): produce a real sealed bundle via the
# headless Neovim recorder, then hand it to the REAL Provenance monorepo's
# analysis-core for validation. This is the plan's gate — the first
# Neovim-produced bundle the real analyzer accepts.
#
# Usage: scripts/e2e/run_e2e.sh
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

echo "== Producing bundle via headless Neovim recorder =="
PROVNVIM_E2E_OUT="$OUT_DIR" \
  "$NVIM" --headless -u tests/minimal_init.lua -l scripts/e2e/produce_bundle.lua

BUNDLE_PATH="$OUT_DIR/e2e-bundle.zip"
if [ ! -f "$BUNDLE_PATH" ]; then
  echo "FAIL: expected bundle not found at $BUNDLE_PATH"
  exit 1
fi
echo "Bundle produced: $BUNDLE_PATH"

echo
echo "== Validating bundle against the real Provenance analyzer =="
echo "PROVENANCE_MONOREPO=$PROVENANCE_MONOREPO"

if PROVENANCE_MONOREPO="$PROVENANCE_MONOREPO" node "$REPO_ROOT/scripts/verify-bundle-with-analyzer.mjs" "$BUNDLE_PATH"; then
  echo
  echo "PASS: real analyzer accepted the Neovim-produced bundle."
  exit 0
else
  status=$?
  echo
  echo "FAIL: real analyzer did not accept the Neovim-produced bundle (exit $status)."
  exit "$status"
fi
