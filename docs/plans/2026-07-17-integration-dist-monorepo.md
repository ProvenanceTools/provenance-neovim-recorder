# Integration + `extension_hash` + Distribution + Monorepo Changes (Plan 9 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Land the real `extension_hash` (a deterministic runtime source-tree hash), the integration pass that wires **every** signal into one live session controller behind the `:ProvenanceSeal` command, a full-signals re-run against the real analyzer, the distribution story (tagged git release + README), and the two small **additive** monorepo changes (allowlist entry + producer-agnostic wording). The export/golden-vector script already exists and is consumed unchanged.

**Architecture:** `extension_hash.lua` replaces Plan 4's placeholder with a real DirectoryHash over the plugin's own installed Lua tree. The integration controller composes activation (Plan 3), doc events (Plan 4), external-change (Plan 5), paste (Plan 6), terminal/git/snapshot (Plan 7), and checkpoints/recovery/degraded (Plan 8) into one lifecycle with a single `dispose()`, and registers the user command. Distribution is a tagged release (no build step); the monorepo just needs this release's tree-hash in the allowlist.

**Tech Stack:** Lua, `vim.uv` (tree walk), `vim.fn.sha256`, `nvim_create_user_command`, plenary; monorepo `npm run update-hashes -- --hash <hex>`. Builds on Plans 1–8.

## Global Constraints

(Inherits Plans 1–8.) Additional:

- **`extension_hash` = deterministic runtime tree-hash of the installed Lua source** (design.md §6). Algorithm (must match `extension-hash.ts` / `update-extension-hash-allowlist.mjs` byte-for-byte): recursively collect **regular files** under the plugin root, map to relative paths, **sort by `localeCompare`** (⚠️ *not* Lua's bytewise `table.sort` — the single biggest silent-divergence risk; emulate `localeCompare` or restrict to ASCII paths and prove equivalence), rolling SHA-256 over `for each file: <relpath-utf8> .. "\0" .. <file-bytes>`. Empty tree → `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **The hashed tree defines identity.** The committed course public key (Plan 3) is part of the tree, so each course release's key binds a distinct `extension_hash` (design.md §6).
- **`manifest.json`/`manifest.sig` are never modified after seal** (design.md §7).
- **The only monorepo changes are additive** (design.md §8): (1) add this release's tree-hash to `known-good-extension-hashes.json` via the existing `--hash` mode; (2) a producer-agnostic wording fix to the update-hashes doc-comment. **No new event types, no heuristic logic changes.** The `extension_hash` allowlist is a *heuristic flag*, not a validation gate — a Neovim bundle already validates; the allowlist only clears the `extension_hash_mismatch` flag.
- Monorepo commits follow the *monorepo's* conventions; this-repo commits follow CLAUDE.md.

### File structure

```
lua/provenance/recorder/
  commands/extension_hash.lua     -- REPLACE placeholder with real DirectoryHash
  session/recording_controller.lua-- compose all signals + :ProvenanceSeal
plugin/provenance.lua             -- register :ProvenanceSeal on active session
scripts/exclude-manifest.lua      -- (if needed) tree-walk exclusions doc
docs/manual-verification.md       -- full-integration checklist
README.md                         -- install + distribution + course-key sections
--- monorepo (../provenance) ---
packages/analysis-core/src/heuristics/config/known-good-extension-hashes.json  -- add hash
scripts/update-extension-hash-allowlist.mjs  -- doc-comment wording only
```

---

### Task 1: DirectoryHash — real `extension_hash`

**Files:** Replace `recorder/commands/extension_hash.lua`; Test `tests/recorder/commands/extension_hash_spec.lua`.

**Interfaces:** `extension_hash.compute(root_dir) → 64-hex` — walk regular files (skip symlinks/dirs-as-entries; unreadable dir → empty), relative paths, **`localeCompare` sort**, rolling `sha256(<rel> .. "\0" .. <bytes>)` concatenated. `extension_hash.compute_installed() → 64-hex` resolves the plugin's own root (the directory containing `lua/provenance/`) and hashes it.

**Test intent:** empty tree → the pinned empty-sha; order-independence (same files, different insertion order → same hash); a known small tree hashed here matches the same tree hashed by the monorepo's `computeExtensionHash` (a cross-tool equality check — generate the expected value by running `extension-hash.ts` over a fixture dir and pin it); 64-lowercase-hex. **⚠️ If a non-ASCII relative path makes the Lua sort diverge from `localeCompare`, STOP and reconcile** (design decision, not a silent fix). **Gate:** spec green. **Commit:** `feat(recorder): real extension_hash directory tree hash`.

---

### Task 2: Integration controller — compose every signal

**Files:** Create `recorder/session/recording_controller.lua`; Modify `recorder/init.lua` to start the controller on activation; Test (headless).

**Interfaces:** `recording_controller.start({workspace, manifest, clock?}) → controller`:
- Runs recovery (Plan 8), generates keypair, builds context (real `extension_hash` available for seal), opens writer + meta, creates host, emits `session.start` (+ `recorder.recovered_from_corruption` if corrupt).
- Starts, each with its own dispose: doc-wiring (Plan 4) **routed through the paste correlator** (Plan 6), external-change coordinator (Plan 5, `note_save` wired from doc-wiring's `BufWritePost`), heartbeat (Plan 4), clock-skew watcher (a small `session.clock.skew` watcher mirroring `clock-watcher.ts` — add if not yet present), terminal/git/snapshot (Plan 7, git feeds the explanation tagger), paste reconciler (Plan 6), checkpoints (Plan 8), disk-full handler (Plan 8) as `writer.on_error`.
- `controller.seal()` flushes, drains checkpoints, calls `seal_bundle` with the real `extension_hash`.
- `controller.stop()` emits `session.end`, disposes **every** sub-handle idempotently.

**Test intent (headless):** a session with typing + paste + save + external write produces a chained `.slog` containing `session.start`, `doc.*`, `paste`, `fs.external_change`, `session.heartbeat`, `ext.snapshot`, and ends with `session.end`; `stop()` leaves no autocmds/timers/watchers (full teardown). **Gate:** spec green. **Commit:** `feat(recorder): integration controller composing all signals`.

---

### Task 3: `:ProvenanceSeal` command

**Files:** Modify `plugin/provenance.lua` / `recorder/init.lua`; Test.

**Interfaces:** when a session is active, register `nvim_create_user_command("ProvenanceSeal", ...)` → `controller.seal()`, then `vim.notify` the bundle path (or a warning on `warnings.chain_broken` / error on failure). When inactive, the stub from Plan 3 shows the guidance message.

**Test intent (headless):** `:ProvenanceSeal` on an active session writes a `.zip` and notifies its path; on an inactive workspace the stub message shows and nothing is written. **Gate:** spec green. **Commit:** `feat(recorder): :ProvenanceSeal user command`.

---

### Task 4: Full-signals re-run against the real analyzer

**Files:** Extend `tests/recorder/e2e_seal_spec.lua` (from Plan 4 Task 10) + a runbook note.

**Steps:**
- [ ] Drive a headless session exercising **every** signal (open/change/save/close, paste, external change, terminal, git, snapshot, a forced checkpoint, then seal).
- [ ] Load the `.zip` in the monorepo (`analysis-core` `loadBundle` + `runValidation`); assert `overall !== "fail"` and checks 1/2/3 pass, and that `doc_save_hashes` / `submitted_code_match` (checks 7/8) do not `fail` for a clean run.
- [ ] **Gate:** the real analyzer accepts a full-signals Neovim bundle. **Commit:** `test(recorder): full-signals bundle accepted by real analyzer`.

---

### Task 5: Distribution + README

**Files:** Modify `README.md`; append to `docs/manual-verification.md`.

**Interfaces:** README sections: install via lazy.nvim/packer (`{ "…/provenance-neovim-recorder" }`), the course-key model (a course commits its own `course_public_key.lua` in a tagged fork/release), `extension_hash` = tree-hash of the installed source (no build artifact), and how to compute this release's hash (`:lua print(require('provenance.recorder.commands.extension_hash').compute_installed())`). Manual full-integration checklist: install in a real nvim, open an assignment, work, `:ProvenanceSeal`, confirm the bundle.

**Gate:** docs committed. **Commit:** `docs: installation, distribution, and course-key model`.

---

### Task 6 (monorepo): allowlist entry + producer-agnostic wording

**Files (in `../provenance`):** `packages/analysis-core/src/heuristics/config/known-good-extension-hashes.json`; `scripts/update-extension-hash-allowlist.mjs` (doc-comment only).

**Steps:**
- [ ] Compute the tagged release's tree-hash in **this** repo (`extension_hash.compute_installed()` on the clean checkout).
- [ ] In the monorepo: `npm run update-hashes -- --hash <hex>` to add it to `known-good-extension-hashes.json` (flat `"hashes"` array; no per-entry metadata — the allowlist is producer-agnostic).
- [ ] Adjust the update-hashes script's header doc-comment to name the third (Neovim) producer and note that its hash is computed in the plugin repo (the plugin source tree *is* the distribution). **No build-mode change** — the script has no Lua toolchain; the Neovim hash is added via `--hash`.
- [ ] **Gate:** `npm run test --workspace=packages/analysis-core -- extension-hash-mismatch` still green; the `extension_hash_mismatch` heuristic no longer flags the Neovim bundle. **Commit (monorepo conventions):** `chore(analysis-core): allowlist provnvim release extension_hash`.

**Confirm (design.md §8):** the golden-vector export script (`tools/export-conformance-vectors.ts`) already exists and is editor-neutral — **consumed unchanged**, no export work.

---

### Task 7: Final gate — regenerate vectors + full suite

**Files:** none new.

**Steps:**
- [ ] `PROVENANCE_REPO=../provenance make vectors` — confirm committed fixtures are current (no drift).
- [ ] `make test` — entire suite (core conformance + all recorder wiring + e2e) green.
- [ ] Confirm `THIRD-PARTY-NOTICES.txt` covers every vendored file.
- [ ] Walk `docs/manual-verification.md` in a real TUI; check off what passes.
- [ ] **Commit:** `test: full suite green — provnvim v1 complete`.

---

## Self-Review

**Spec coverage (design.md §6/§7/§8/§9.8):** real `extension_hash` tree-hash with the `localeCompare` hazard called out (T1), integration controller composing every signal with full teardown (T2), `:ProvenanceSeal` (T3), full-signals analyzer acceptance (T4), distribution + course-key model (T5), the two additive monorepo changes (T6), final regenerate + full-suite gate (T7).

**Additive-only monorepo rule:** T6 changes exactly what design.md §8 permits — an allowlist entry via the existing `--hash` mode + a wording fix — and nothing else. No event types, no heuristic logic, no export rework.

**Risk called out:** the DirectoryHash `localeCompare`-vs-bytewise sort divergence is the one silent-hash risk; T1 pins it against the monorepo tool and STOPs on non-ASCII divergence.

**Type consistency:** `extension_hash.compute_installed` (T1) feeds seal (Plan 4) via the controller (T2); every sub-handle disposed in `controller.stop` comes from Plans 3–8; the analyzer acceptance criterion (`overall !== "fail"`, checks 1/2/3 pass) is the same gate introduced in Plan 4 Task 10, now with all signals live.

**Completion definition (CLAUDE.md):** "done" = conformance green, all wiring specs green, loads in headless Neovim, the real analyzer accepts a full-signals bundle, and the monorepo allowlist clears the flag — verified in T4 and T7, not merely written.
