# Manual Verification Checklist

This file documents manual, real-TUI verification steps that the headless test suite cannot cover. Each item is checked off only after a human confirms it in a real `nvim` session. New plans append their own real-TUI items here over time.

## Plan 3 — Activation + status indicator

- [ ] **Non-assignment directory (no `.provenance-manifest`):** Open a directory that does not contain a `.provenance-manifest` file in `nvim`. Confirm that the status segment does NOT show "Provenance: recording" (it is absent from the statusline). Also verify that no `.provenance/` directory is created in that folder.

- [ ] **Valid signed manifest:** Create or navigate to a directory containing a valid, signed `.provenance-manifest` (one that verifies against the embedded course public key), then open that directory in `nvim`. Confirm that the status segment shows `● Provenance: recording`.

- [ ] **Tampered manifest signature:** In a directory with a valid `.provenance-manifest`, manually edit the manifest file and flip one hex character in the `sig` field (e.g., change the first hex digit of the signature), then save and relaunch `nvim` in that directory. Confirm that the status segment is absent (no "Provenance: recording" message), because signature verification fails on activation.

### How to view the status segment

To observe the status segment during testing, add the following to your Neovim statusline configuration (e.g., in `init.lua`):

```lua
vim.opt.statusline = '%{v:lua.require\'provenance.recorder.status\'.segment()}'
```

Or append it to an existing statusline if you prefer; the segment returns an empty string when recording is inactive, so it renders invisibly when not activated.

## Plan 4 — end-to-end analyzer acceptance

Task 10's success gate is that a bundle sealed by this recorder is accepted
by the REAL Provenance monorepo's `analysis-core` (`loadBundle` +
`runValidation`), not just by this repo's own tests.

### How to run

```sh
# Requires a sibling checkout of github.com/ProvenanceTools/provenance with
# analysis-core built (packages/analysis-core/dist/index.js must exist).
PROVENANCE_MONOREPO=/path/to/provenance scripts/e2e/run_e2e.sh
```

This:
1. Runs `scripts/e2e/produce_bundle.lua` headless (`nvim --headless -u
   tests/minimal_init.lua -l scripts/e2e/produce_bundle.lua`), which builds a
   temp workspace from the committed dev manifest fixture
   (`tests/conformance/fixtures/manifest.json`), starts a real
   `recording_session`, drives a real `:edit` / buffer-edit / `:write` cycle
   against a reviewed file, seals, and copies the resulting `.zip` to
   `$PROVNVIM_E2E_OUT/e2e-bundle.zip`.
2. Runs `node scripts/verify-bundle-with-analyzer.mjs
   $OUT/e2e-bundle.zip`, which imports `loadBundle`/`runValidation` from
   `$PROVENANCE_MONOREPO/packages/analysis-core/dist/index.js`, loads the
   bundle, and prints the full `ValidationReport`.

### Current status: PASSING — real analyzer accepts a Neovim-produced bundle

As of 2026-07-18, running the gate against a bundle produced by
`lua/provenance/recorder/wiring/doc_wiring.lua` (trailing-newline content
model — see `content_bytes()` in that file) produces `overall: "pass"`, with
every check — including `doc_save_hashes` and `submitted_code_match` —
`"pass"`. See `.superpowers/sdd/task-p4t10-report.md` for the full verbatim
`ValidationReport` and the fix that got it there.

Verbatim `ValidationReport` (`bash scripts/e2e/run_e2e.sh`,
`PROVENANCE_MONOREPO=/Users/aaryanmehta/projects/provenance`):

```json
{
  "checks": [
    {
      "id": "manifest_sig",
      "label": "Bundle manifest signature",
      "status": "pass",
      "detail": "Verified against session 73224ba1-a933-41c5-a617-5438794f41e6."
    },
    {
      "id": "session_binding",
      "label": "Session binding to assignment manifest",
      "status": "pass",
      "detail": "Single session; binding trivially consistent."
    },
    {
      "id": "chain_integrity",
      "label": "Hash chain integrity",
      "status": "pass"
    },
    {
      "id": "seq_gaps",
      "label": "No seq gaps",
      "status": "pass"
    },
    {
      "id": "monotonic_t",
      "label": "Monotonically non-decreasing t",
      "status": "pass"
    },
    {
      "id": "monotonic_wall",
      "label": "Monotonically non-decreasing wall clock",
      "status": "pass"
    },
    {
      "id": "doc_save_hashes",
      "label": "Doc save hash consistency",
      "status": "pass"
    },
    {
      "id": "submitted_code_match",
      "label": "Submitted code matches recorded final state",
      "status": "pass",
      "detail": "1 submitted file(s) match the recorded final state."
    }
  ],
  "overall": "pass"
}
```

Root cause of the earlier failure (fixed): `doc_wiring.lua` computed
doc.open/doc.save content and its `sha256` from
`table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n")`, which
never included a trailing newline for the buffer's last line. Neovim's
default `'fixeol'` (on) means every `:write` still terminates the file with
a trailing `\n` regardless of the buffer's own `'eol'` state, so the actual
on-disk bytes (and the raw-byte hash `seal.lua` computes for
`submission_files`) were systematically one `\n` ahead of every doc.save
hash this recorder emitted. VS Code's reference wiring
(`packages/recorder/src/wiring/doc-wiring.ts`) uses `document.getText()`,
which — unlike Neovim's line-array buffer model — includes that trailing
newline as part of the document text. The fix: `doc_wiring.lua` now models
file content uniformly (doc.open content/hash, doc.change delta text,
doc.save hash) as `table.concat(lines, "\n") .. "\n"` — buffer lines plus
one trailing newline — matching both Neovim's on-disk bytes and VS Code's
`getText()` semantics. Deferred as a known follow-up: fileformat=dos/mac,
`'nobinary'`/`'noeol'` buffers, and the empty-buffer/0-byte-file edge case.

## Plan 5 — external-change detection

`lua/provenance/recorder/watch/external_change_coordinator.lua` composes the
three emission paths (save-time check, `vim.uv` fs-poll watcher,
`FileChangedShellPost` reload-from-disk) behind one shared registry and
`recent_saves` tolerance map. The headless suite drives Path 1 and Path 3
deterministically and Path 2 via both its direct decision-handler seam and
one real `vim.uv.new_fs_poll()` integration test, and proves the no-
double-emit guarantee with a controllable clock. What it genuinely cannot
cover is the LAZY, focus-driven timing of `FileChangedShellPost` itself and
real OS-level watcher latency — those need a live TUI:

- [ ] **Focus-gain reload, exactly one event:** Open a watched file in a real
      `nvim` session (with `autoread` on, the plugin's default). Switch away
      from Neovim (e.g. `Ctrl-Z` to the shell, or switch terminal tabs/apps)
      and, with the editor UNFOCUSED, externally edit the file (e.g. run a
      formatter against it, or `echo "extra line" >> file`). Refocus Neovim
      (or run `:checktime` explicitly). Confirm exactly one
      `fs.external_change` event lands in the session's `.slog` — not a
      `doc.change`, and not doubled (i.e. Path 2's watcher, if it also fired
      while unfocused, did not produce a second event for the same write).

- [ ] **`vim.uv` native-watcher latency while focused:** With the same
      workspace open and Neovim FOCUSED, externally edit a watched file (a
      separate terminal, another editor, or a script). Confirm the resulting
      `fs.external_change` is recorded within roughly 1-2 seconds (bounded by
      Path 2's fs-poll `poll_interval_ms`, default 1000ms) — i.e. Path 2 (not
      the lazy Path 3) is the one that actually catches an external change
      while the editor has focus.

- [ ] **A normal save produces no external-change:** With a watched file
      open, edit it normally inside Neovim and `:w`. Confirm this produces a
      `doc.save` (and the preceding `doc.change`s) but does NOT produce an
      `fs.external_change` — i.e. `note_save` + the tolerance window
      correctly suppress the editor's own write from being misclassified as
      an external one.
