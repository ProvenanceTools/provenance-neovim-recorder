# Terminal + Git + Plugin Snapshot (Plan 7 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Wire the remaining corroborating signals — terminal open/command capture, git events, and the plugin snapshot — each **degrading gracefully** when the underlying facility is absent (no shell integration, no git, no plugin manager API). Match the VS Code recorder's payloads; do not over-reach where Neovim can't observe.

**Architecture:** Pure payload builders first (`terminal.open`/`terminal.command`/`git.event`/`ext.snapshot`/`ext.activate`), then thin Neovim seams: `TermOpen`/`TermRequest`/`TermClose` autocmds for terminals, a git seam that shells out to `git` (or detects fugitive/gitsigns) and records `git.event`, and a snapshot that enumerates `runtimepath`/loaded packages. Everything is optional and guarded — a missing facility is a degraded signal, not a crash.

**Tech Stack:** Lua, `TermOpen`/`TermRequest`/`TermClose` autocmds, `jobstart`/`vim.fn.system` (git shell-out), `vim.api.nvim_list_runtime_paths`/`vim.fn.getscriptinfo`, `vim.uv` timer, plenary. Builds on Plan 4's emit.

## Global Constraints

(Inherits Plans 1–6.) Additional:

- **Degrade gracefully (CLAUDE.md, PRD §4.4).** Git may be absent or exposed only via a third-party plugin; terminals may lack shell integration. Missing integration is a degraded signal (record the fact + `shell_integration=false`), never a crash or `NoClassDefFound`-style failure.
- **Every `terminal.open` carries `shell_integration: true|false`** so the analyzer knows what was observable. Without shell integration, record `terminal.open`/`terminal.close` + the active-terminal fact, but not command text.
- **Snapshot field name stays `extensions`** (the `ext.snapshot` wire shape is fixed). Fill it with Neovim's plugin list. `ext.activate` fires for a newly-loaded plugin.
- **`git.event`** payload is `{operation, commit_sha?}` — `operation` a string (e.g. `"state_change"`, `"commit"`), `commit_sha` omitted when unknown. A `git.event` also feeds the Plan 5 explanation tagger (`mark_git`) so a git-driven file change is explained.
- Every timer/autocmd/job has a `dispose()`; optional facilities are detected once and their absence logged at debug.

### File structure

```
lua/provenance/recorder/
  events/terminal_payloads.lua   -- build_terminal_open/command (pure)
  events/git_payloads.lua        -- build_git_event (pure)
  events/snapshot_payloads.lua   -- build_ext_snapshot/build_ext_activate (pure)
  wiring/terminal_wiring.lua     -- TermOpen/TermRequest/TermClose seam (graceful)
  wiring/git_wiring.lua          -- git shell-out / plugin-detect seam (graceful)
  wiring/snapshot_wiring.lua     -- immediate + 5-min plugin snapshot
tests/recorder/**/*_spec.lua
docs/manual-verification.md      -- terminal/git live-TUI checklist items
```

---

### Task 1: Terminal payload builders (pure)

**Files:** Create `events/terminal_payloads.lua`; Test.

**Interfaces:** `build_terminal_open(terminal_id, shell, shell_integration) → {kind="terminal.open", data={terminal_id, shell, shell_integration}}`; `build_terminal_command(terminal_id, command, exit_code?) → {kind="terminal.command", data={terminal_id, command, exit_code?}}` (omit `exit_code` when nil).

**Test intent:** open carries all three fields incl. `shell_integration=false`; command omits `exit_code` when nil, includes it when set. **Gate:** spec green. **Commit:** `feat(recorder): terminal payload builders`.

---

### Task 2: Git payload builder (pure)

**Files:** Create `events/git_payloads.lua`; Test.

**Interfaces:** `build_git_event(operation, commit_sha?) → {kind="git.event", data={operation, commit_sha?}}` — omit `commit_sha` when nil.

**Test intent:** with and without `commit_sha`. **Gate:** spec green. **Commit:** `feat(recorder): git event payload builder`.

---

### Task 3: Snapshot payload builders (pure)

**Files:** Create `events/snapshot_payloads.lua`; Test.

**Interfaces:** `build_ext_snapshot(plugins) → {kind="ext.snapshot", data={extensions=json.array(list of {id, version, enabled})}}` (wire field stays `extensions`); `build_ext_activate(id, version) → {kind="ext.activate", data={id, version}}`.

**Test intent:** snapshot preserves the `extensions` field name + entry shape; activate shape. **Gate:** spec green. **Commit:** `feat(recorder): plugin snapshot payload builders`.

---

### Task 4: Plugin snapshot wiring (always-on)

**Files:** Create `wiring/snapshot_wiring.lua`; Test.

**Interfaces:** `snapshot_wiring.start({emit, list_plugins?, interval_ms?=300000, get_now}) → handle` — emits `ext.snapshot` immediately, then every 5 minutes via a `vim.uv` timer. `list_plugins` enumerates `nvim_list_runtime_paths`/`getscriptinfo` into `{id, version, enabled}` (version best-effort/`""`). `handle.dispose()` stops the timer.

**Test intent:** immediate emit on start; injected `list_plugins` reflected; `dispose` cancels the timer. **Gate:** spec green. **Commit:** `feat(recorder): plugin snapshot wiring`.

---

### Task 5: Terminal wiring (graceful)

**Files:** Create `wiring/terminal_wiring.lua`; Test (headless where possible; live parts to manual).

**Interfaces:** `terminal_wiring.start({emit}) → handle` — `TermOpen` → detect shell + whether `TermRequest`/OSC-133 shell integration is available → `build_terminal_open(id, shell, shell_integration)`; `TermRequest` (OSC 133 command markers) when present → `build_terminal_command`; `TermClose` → a close fact. When shell integration is absent, still emit `terminal.open` with `shell_integration=false` and no command text. `handle.dispose()` clears autocmds.

**Test intent (headless):** opening a terminal buffer emits `terminal.open` with `shell_integration=false` in a bare environment (no OSC-133) and does not crash. Live command-capture with a shell-integrated terminal → manual checklist. **Gate:** spec green (open path) + manual items added. **Commit:** `feat(recorder): terminal wiring (graceful, shell-integration aware)`.

---

### Task 6: Git wiring (graceful)

**Files:** Create `wiring/git_wiring.lua`; Test.

**Interfaces:** `git_wiring.start({workspace, emit, tagger, run_git?}) → handle` — on activation, detect a git repo (`run_git("rev-parse")` or `.git` presence); if absent, log debug and no-op. When present, watch for state changes (poll HEAD / `.git/HEAD` via `vim.uv.fs_event`, or hook fugitive/gitsigns events if loaded) → emit `git.event` and call `tagger.mark_git()` (feeds Plan 5). `run_git` injectable. `handle.dispose()` stops watchers.

**Test intent:** repo absent → no-op, no crash (the key graceful-degradation gate); repo present (injected `run_git`) → a HEAD change emits `git.event` and marks the tagger. **Gate:** spec green. **Commit:** `feat(recorder): git wiring (graceful degradation)`.

---

### Task 7: Assemble + degradation manual checklist

**Files:** No new code beyond wiring already added; append to `docs/manual-verification.md`.

**Steps:**
- [ ] Confirm terminal + git + snapshot wiring are startable from the recording session (Plan 9 composes them).
- [ ] Manual checklist: (a) shell-integrated terminal captures command text + exit codes; (b) non-integrated terminal records `terminal.open shell_integration=false` only; (c) a git commit emits `git.event`; (d) with no git installed, the session runs and seals normally.
- [ ] **Gate:** full `make test` (Tasks 1–4, 6 headless parts); manual items unchecked pending a live TUI. Verify a sealed bundle with terminal+git **absent** still passes the real analyzer (re-run Plan 4 Task 10).
- [ ] **Commit:** `docs: terminal/git/snapshot degradation manual checklist`.

---

## Self-Review

**Spec coverage (design.md §9.6, PRD §4.4):** terminal builders (T1), git builder (T2), snapshot builders (T3), always-on snapshot (T4), graceful terminal wiring with `shell_integration` flag (T5), graceful git wiring feeding the explanation tagger (T6), assembly + degradation checklist (T7).

**Graceful degradation:** the two facilities that can be absent — shell integration (T5) and git (T6) — are the explicit gates: absence is recorded as a fact, never a crash. The snapshot (T4) is always available (`runtimepath`).

**Depth deferral (design.md §12 open q5):** the terminal command-capture depth and git event richness that genuinely need a live TUI are pushed to the manual checklist (T5/T7), matching provjet's VERIFY-AT-EXECUTION gates. The headless-testable parts (open path, absent-facility no-op, snapshot) are covered.

**Type consistency:** `build_*` payloads (T1–T3) feed the same `emit`; `tagger.mark_git` (T6) is Plan 5's `ExplanationTagger`; `json.array` (Plan 1) used for the `extensions` list.
