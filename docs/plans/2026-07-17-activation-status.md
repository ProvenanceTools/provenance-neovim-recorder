# Activation + Manifest Verification + Status Indicator (Plan 3 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the plugin *activate scoped to an assignment workspace* — locate and verify a `.provenance-manifest` against the committed course public key, expose the verified workspace + `files_under_review` to later plans, and show a persistent "Provenance: recording" status indicator only when active. Record nothing yet (that is Plan 4); this plan is the activation gate + UI.

**Architecture:** `lua/provenance/recorder/` begins here — the Neovim wiring around `core/`. Activation is pure-logic-first (a `core`-only `evaluate_manifest` reusing Plan 2's `manifest`), then a thin Neovim seam (`recorder/activation.lua`) that reads the file via `vim.uv`, plus a project-scoped state table and a statusline segment. The course public key is a committed Lua constant (design.md §6). No events, no writer.

**Tech Stack:** Lua, `vim.uv` (file read), `vim.api`/autocmds (activation trigger), a statusline function, plenary + headless Neovim for wiring tests. Builds on Plan 2's `core/manifest`.

## Global Constraints

(Inherits Plans 1–2.) Additional:

- **Activation is scoped and privacy-preserving (PRD §4.1, CLAUDE.md).** Record only inside an activated assignment workspace whose `.provenance-manifest` verifies against the committed course public key. Invalid/missing/tampered manifest → the plugin does nothing (no recording, no status UI beyond an optional inert stub command). Never record the student's user config (`init.lua`, `~/.config/nvim`) or out-of-workspace buffers.
- **Producer identity:** the plugin id is `com.provenance.recorder.nvim` (design.md §6, open q4 — pinned here, stable forever). Used later as `session.start.recorder.extension_id`.
- **Manifest file names, precedence order:** `.provenance-manifest` (canonical dotfile), then `provenance-manifest` (fallback).
- **The course public key is a committed constant** (`course_public_key.lua`), never a secret. A course release commits its own key; because the key is part of the hashed source tree (Plan 9), each course release binds its key via a distinct `extension_hash`.
- **Every autocmd group / timer / watcher has an explicit `dispose()`** (CLAUDE.md). Activation returns a teardown handle.

### File structure

```
lua/provenance/
  course_public_key.lua           -- COURSE_PUBLIC_KEY_HEX committed constant
  recorder/
    activation.lua                -- evaluate + load/verify manifest (core + vim.uv seam)
    state.lua                     -- per-workspace RecorderState (active?, workspace, manifest)
    status.lua                    -- statusline segment + set/clear
    init.lua                      -- plugin bootstrap: autocmd → activate on workspace enter
plugin/provenance.lua             -- entry that requires recorder.init (loaded by Neovim)
tests/recorder/*_spec.lua
docs/manual-verification.md       -- created here; first checklist items (real-TUI floor)
```

---

### Task 1: Course public key committed constant

**Files:** Create `lua/provenance/course_public_key.lua`; Test `tests/recorder/course_public_key_spec.lua`.

**Interfaces:** returns `{ COURSE_PUBLIC_KEY_HEX = "<64-hex>" }`. For dev, use the `manifest.json` fixture's `course_pubkey_hex` (so the committed dev manifest fixture verifies in tests). Document that Plan 9's dist flow swaps this per course release.

**Test intent:** the constant is 64 lowercase hex. **Gate:** spec green. **Commit:** `feat(recorder): committed course public key constant (dev key)`.

---

### Task 2: Pure `evaluate_manifest` (core-only activation decision)

**Files:** Create `lua/provenance/recorder/activation.lua` (this task adds the pure part); Test `tests/recorder/activation_spec.lua`.

**Interfaces:**
- `activation.evaluate(text: string, pubkey_hex: string): {status="active", manifest} | {status="inactive", reason}` — parses via `core.manifest.parse`, verifies via `core.manifest.verify`. Reasons: `parse_error`, `signature_invalid`. **Never throws.** Zero Neovim API use.

**Test intent (using the `manifest.json` fixture):** valid signed manifest + correct pubkey → `active`; wrong pubkey or any tampered field → `signature_invalid`; malformed JSON → `parse_error` (no throw). **Gate:** spec green. **Commit:** `feat(recorder): pure evaluate_manifest activation decision`.

---

### Task 3: `vim.uv` manifest loader (the Neovim seam)

**Files:** Modify `lua/provenance/recorder/activation.lua` (add the file-reading part); Test `tests/recorder/activation_loader_spec.lua`.

**Interfaces:**
- `activation.load_and_verify(workspace_dir: string, pubkey_hex?: string): {status, manifest?/reason}` — tries each manifest file name in precedence order under `workspace_dir` via `vim.uv.fs_stat`/`fs_open`/`fs_read`; `ENOENT` on both → `{status="inactive", reason="no_manifest_file"}`; other read error → `reason="manifest_read_error"`; else delegates to `evaluate`. `pubkey_hex` defaults to `COURSE_PUBLIC_KEY_HEX`.

**Test intent (write manifest files into a temp dir):** no file → `no_manifest_file`; dotfile present + valid → `active`; dotfile preferred over plain form when both present; read of a directory-as-file → `manifest_read_error`. **Gate:** spec green (headless, real `vim.uv`). **Commit:** `feat(recorder): manifest loader over vim.uv`.

---

### Task 4: Per-workspace `RecorderState`

**Files:** Create `lua/provenance/recorder/state.lua`; Test `tests/recorder/state_spec.lua`.

**Interfaces:**
- `state.new(): RecorderState` with `is_active()`, `activate({workspace, manifest})`, `deactivate()`, `get()` (returns `{active, workspace, manifest}`). In-memory, single-workspace (Neovim is one process per session). No globals leaked.

**Test intent:** default inactive; activate then `is_active()` true and `get().manifest` present; deactivate clears. **Gate:** spec green. **Commit:** `feat(recorder): per-workspace recorder state`.

---

### Task 5: Status indicator (statusline segment)

**Files:** Create `lua/provenance/recorder/status.lua`; Test `tests/recorder/status_spec.lua`.

**Interfaces:**
- `status.segment(): string` — returns `"● Provenance: recording"` when state is active, `""` otherwise (empty = absent, mirroring the VS Code recorder's active/absent-only model; degraded surfaces via notification in Plan 8, not here).
- `status.attach(state)` / `status.detach()` — registers the segment so a user can add `%{v:lua.require'provenance.recorder.status'.segment()}` to their statusline; `detach` is the teardown.

**Test intent:** segment is empty when inactive, non-empty + contains "recording" when active. **Gate:** spec green. **Commit:** `feat(recorder): status indicator segment`.

---

### Task 6: Activation bootstrap (autocmd wiring) + teardown

**Files:** Create `lua/provenance/recorder/init.lua`, `plugin/provenance.lua`; Test `tests/recorder/init_spec.lua`.

**Interfaces:**
- `recorder.setup(opts?)` — creates an augroup; on `VimEnter`/`DirChanged` resolves the workspace root (cwd or first workspace dir), calls `activation.load_and_verify`, and on `active` populates `state` + `status.attach`; on inactive logs at debug and registers an inert `:ProvenanceSeal` stub that shows a guidance message (records nothing). Returns a handle with `dispose()` that clears the augroup and detaches status. The loader is injectable for tests (`opts.load_and_verify`).
- `plugin/provenance.lua` calls `require("provenance.recorder").setup()` guarded by a `vim.g.loaded_provenance` sentinel.

**Test intent (headless, injected fake loader):** active workspace → state active + status non-empty + augroup exists; inactive → state inactive + status empty + stub command registered; `dispose()` removes the augroup (no autocmds remain). **Gate:** spec green + full `make test`. **Commit:** `feat(recorder): activation bootstrap autocmd + teardown`.

---

### Task 7: Manual verification checklist (real-TUI floor)

**Files:** Create `docs/manual-verification.md`.

**Interfaces:** none (doc). Add the first checklist items that headless cannot cover: (1) open a non-assignment directory → no status segment, no `.provenance/` created; (2) open a directory with a valid signed `.provenance-manifest` → status shows "Provenance: recording"; (3) tamper the manifest `sig` → status absent on next launch. Mark all unchecked pending a real `nvim` session.

**Gate:** doc committed. **Commit:** `docs: manual verification checklist for activation`.

---

## Self-Review

**Spec coverage (design.md §9.2, PRD §4.1):** committed course key (T1), pure activation decision (T2), `vim.uv` loader with name precedence + workspace scoping (T3), state (T4), status indicator (T5), autocmd bootstrap + teardown + inert stub when inactive (T6), manual floor (T7). Recording is deliberately absent — Plan 4.

**Port fidelity:** activation gate mirrors `manifest-loader.ts` (candidate name precedence, `no_manifest_file`/`manifest_parse_error`/`manifest_signature_invalid` reasons, do-nothing-on-invalid). Status mirrors `status-bar.ts` (single active/absent state). The inert-stub-when-inactive mirrors `extension.ts` registering a guidance-only command.

**Type consistency:** `core.manifest.parse/verify` (Plan 2) consumed by `evaluate` (T2); `activation.load_and_verify` (T3) returns the shape `state.activate` (T4) expects; `state` read by `status` (T5) and `init` (T6).

**Teardown:** every autocmd group + status attachment has a `dispose()` (T6), per CLAUDE.md.
