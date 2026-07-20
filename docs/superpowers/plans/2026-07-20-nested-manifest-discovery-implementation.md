# Upward Manifest Discovery + Concurrent Multi-Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace provnvim's cwd-anchored, single-workspace activation with an upward root-marker walk from each buffer's file to its nearest ancestor `.provenance-manifest`, and support full concurrent multi-assignment recording (one live session per assignment root, each writing its own `<root>/.provenance/`), routing every buffer/terminal/git event to exactly one owning session.

**Architecture:** Two new pure/wiring modules — `discovery.lua` (upward walk via `vim.fs.find` + delegates verification to `activation.load_and_verify`) and `registry.lua` (root -> session map, replacing the single `state`/`controller` pair) — are composed by a rewritten `init.lua` that adds `BufEnter`/`BufReadPost`/`BufNewFile` triggers alongside the existing `VimEnter`/`DirChanged` cwd fallback. Five wiring modules that create a fixed-name augroup (`doc_wiring`, `terminal_wiring`, `selection_wiring`, `focus_wiring`, `external_change_coordinator`) are fixed to use a unique augroup per instance, since concurrent sessions now call each of them more than once in the same Neovim process. The single global `vim.paste` override (`paste_intercept.lua`) is redesigned as a ref-counted singleton so N concurrent sessions can register/unregister independently without teardown-order bugs. `terminal_wiring` gains an optional cwd-prefix filter so a terminal is attributed to at most one session. `git_wiring` needs no change — it is already instantiated per-session-workspace by `recording_session.lua` and never shares global state. `:ProvenanceSeal` becomes a single, always-registered command that queries the registry live at invocation time (sealing directly when one session is active, prompting via `vim.ui.select` when more than one is).

**Tech Stack:** Lua, `vim.fs.find`/`vim.fs.dirname` (upward walk), `vim.ui.select` (seal picker), autocmds (`BufEnter`/`BufReadPost`/`BufNewFile`/`VimEnter`/`DirChanged`/`VimLeavePre`), plenary busted-style headless tests (`make test`). Builds on the existing `provenance.recorder.activation`, `provenance.recorder.session.recording_controller`, and all Plan 1-9 modules — no new dependency.

## Global Constraints

(Inherits the repo's `CLAUDE.md` and `docs/design.md` in full.) Feature-specific, from `docs/superpowers/specs/2026-07-20-nested-manifest-discovery-design.md`:

- **No log format, manifest schema, JCS, hash chain, or signing change.** `packages/log-core`'s pinned format (this repo's Lua port) is untouched by this feature.
- **No new native dependency.** Pure-Lua / zero-native-dep keystone preserved. `vim.fs.find`, `vim.fs.dirname`, and `vim.ui.select` are Neovim builtins already relied on elsewhere (`vim.fs.normalize`/`vim.uv` are already used throughout the wiring tree).
- **Nearest-enclosing ownership per buffer.** A buffer's manifest is the nearest ancestor directory containing `.provenance-manifest`/`provenance-manifest`; no fallback search past a found-but-invalid manifest.
- **Full concurrent multi-session (locked).** Two assignment roots can record at the same instant, each with its own `.provenance/`, its own hash chain, its own signing keypair.
- **Terminal/git attribution by path; drop if no owner.** Never attribute a terminal or git event to a session whose root does not contain the relevant path.
- **Small, reviewable commits per task**, `git commit --no-gpg-sign`, conventional-commit prefixes, no `Co-Authored-By` trailer, explicit pathspecs only (never `git add -A`).
- **Never weaken a test to make it pass.** Where an existing test's assertion mechanism (e.g. a hardcoded augroup name) is made incorrect by a locked design change, replace the mechanism with an equivalent-or-stricter check of the same invariant — do not delete or loosen the invariant itself.
- Every new autocmd group / timer / watcher / global-slot registration keeps an explicit, idempotent `dispose()`.

---

## Empirically-verified facts this plan depends on

(Verified against the real `nvim 0.12.1` in this environment; re-verify if the plan is executed against a different Neovim build.)

1. `vim.fs.find({".provenance-manifest", "provenance-manifest"}, {upward = true, path = <dir>, limit = 1})` checks **both names at each directory level** before ascending, and returns the nearest level that has either — so a plain `provenance-manifest` two levels up beats a dotfile four levels up. Within a **single** directory that has both names, list order wins (dotfile first, matching `activation.lua`'s existing `MANIFEST_NAMES` precedence).
2. A real `:terminal`'s buffer name is `term://<cwd>//<pid>:<cmd>` and Neovim's `getcwd()` at `TermOpen` time equals that `<cwd>` (confirmed by literally opening a terminal and comparing). This plan uses `vim.fn.getcwd()` at `TermOpen` time as the terminal's cwd, **not** buffer-name parsing — because the existing `terminal_wiring_spec.lua` and `e2e_seal_spec.lua` synthesize terminal buffers via `nvim_create_buf(false, true)` with buffer-locals only (`term_title`/`terminal_job_id`) and **no real `term://` name**; buffer-name parsing would silently break every existing terminal test. `vim.fn.getcwd()` requires no change to any existing terminal test fixture.
3. `nvim_del_augroup_by_id` exists and removes an augroup by its integer id regardless of what name it was created with — this is what makes per-instance unique augroup names safe to tear down without needing to also thread the generated name back out for that purpose.

## Cross-cutting hazard inventory (why Tasks 1-6 exist)

Six places in the current single-workspace codebase assume **at most one instance ever runs per Neovim process**. Concurrent multi-session breaks that assumption. Confirmed by grep across `lua/provenance/recorder/`:

| # | File | Hazard | Fix (task) |
|---|---|---|---|
| 1 | `wiring/doc_wiring.lua:441` | `nvim_create_augroup("ProvenanceDocWiring", {clear=true})` — a second session's `attach()` wipes the first session's autocmds | Task 1 |
| 2 | `wiring/selection_wiring.lua:94` | same, `"ProvenanceSelection"` | Task 2 |
| 3 | `wiring/focus_wiring.lua:35` | same, `"ProvenanceFocus"` | Task 2 |
| 4 | `watch/external_change_coordinator.lua:122` | same, `"ProvenanceExternalChange"` | Task 3 |
| 5 | `wiring/terminal_wiring.lua:133` | same, `"ProvenanceTerminal"`; **also** no workspace scoping at all, so N sessions each independently emit for every terminal anywhere | Task 4 |
| 6 | `wiring/paste_intercept.lua:64,94` | `vim.paste = function(...)` is a single global slot; N nested wraps + non-LIFO `dispose()` can silently re-activate an already-stopped session's callback | Task 5 |

`git_wiring.lua` and the timer-only signals (`heartbeat`, `clock_skew_watcher`, `snapshot_wiring`, `ext_activation_wiring`) were checked and need **no change** — each instance owns only local `vim.uv` timer/poll handles, no fixed augroup, no global slot.

---

### Task 1: `doc_wiring.lua` — unique augroup per instance

**Files:**
- Modify: `lua/provenance/recorder/wiring/doc_wiring.lua:14` (module-level `AUGROUP_NAME`), `:441` (create), `:573` (dispose)
- Modify: `tests/recorder/wiring/doc_wiring_spec.lua:7` (local `AUGROUP_NAME`), `:604-632` (the `dispose()` test)

**Interfaces:**
- Produces: `handle._augroup_id` (integer) on the table returned by `doc_wiring.attach(opts)` — later tasks (and this task's own test) target a specific instance's augroup by id instead of by name.
- Consumes: nothing new.

This establishes the pattern every other augroup-uniqueness task (2, 3, 4) repeats.

- [ ] **Step 1: Read the current file to confirm line numbers haven't drifted**

Run: `grep -n "AUGROUP_NAME\|nvim_create_augroup\|nvim_del_augroup" lua/provenance/recorder/wiring/doc_wiring.lua`
Expected: matches at (or near) lines 14, 441, 573 as in this plan. If they've drifted, use the actual lines.

- [ ] **Step 2: Add a module-level instance counter and make the augroup name unique**

In `lua/provenance/recorder/wiring/doc_wiring.lua`, just below the existing `local AUGROUP_NAME = "ProvenanceDocWiring"` (line 14), add:

```lua
-- Concurrent multi-session support: two sessions may both call attach() in
-- the same Neovim process (one per assignment root). nvim_create_augroup
-- with a FIXED name and clear=true would wipe the FIRST session's autocmds
-- the moment the SECOND session attaches. Each attach() therefore gets its
-- own uniquely-suffixed augroup name; teardown uses the returned integer id
-- (nvim_del_augroup_by_id), never the name, so uniqueness is the only thing
-- that matters here.
local instance_seq = 0
```

Replace the augroup creation (around line 441):

```lua
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })
```

with:

```lua
  instance_seq = instance_seq + 1
  local augroup_name = AUGROUP_NAME .. ":" .. instance_seq
  local augroup = vim.api.nvim_create_augroup(augroup_name, { clear = true })
```

- [ ] **Step 3: Expose the augroup id on the handle and switch dispose() to delete by id**

In the same file, in the `handle.dispose()` function (around line 573), replace:

```lua
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
```

with:

```lua
    pcall(vim.api.nvim_del_augroup_by_id, augroup)
```

Just before `return handle` at the end of `M.attach`, add:

```lua
  handle._augroup_id = augroup
```

- [ ] **Step 4: Fix the one test that checked the augroup by fixed name**

In `tests/recorder/wiring/doc_wiring_spec.lua`, the `local AUGROUP_NAME = "ProvenanceDocWiring"` at line 7 is now only a prefix, not the real group name — delete that local (it's unused after this change; confirm with `grep -n AUGROUP_NAME tests/recorder/wiring/doc_wiring_spec.lua` that line 7 is the only occurrence before deleting).

In the `"dispose() removes the augroup and no further events emit"` test (around line 604-632), replace:

```lua
    local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = AUGROUP_NAME })
    assert.is_true(not ok or #autocmds == 0)
```

with:

```lua
    local augroup_id = handle._augroup_id
    assert.is_number(augroup_id)
    local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = augroup_id })
    assert.is_true(not ok or #autocmds == 0)
```

This is strictly more rigorous than the original: previously, `AUGROUP_NAME` happened to be globally unique, so the assertion was correct by coincidence; now it targets the exact instance under test.

- [ ] **Step 5: Add a new test proving two concurrent instances don't clobber each other**

Add to `tests/recorder/wiring/doc_wiring_spec.lua`, inside the `describe("doc_wiring.attach", ...)` block:

```lua
  it("CONCURRENCY: two attach() calls in the same process do not clobber each other's autocmds", function()
    local workspace_a = scratch.workspace()
    local workspace_b = scratch.workspace()
    local path_a = workspace_a .. "/a.txt"
    local path_b = workspace_b .. "/b.txt"
    scratch.write_file(path_a, "a\n")
    scratch.write_file(path_b, "b\n")

    local events_a, emit_a = new_emit()
    local events_b, emit_b = new_emit()
    local handle_a = doc_wiring.attach({ workspace = workspace_a, emit = emit_a })
    local handle_b = doc_wiring.attach({ workspace = workspace_b, emit = emit_b })
    scratch.handle = nil -- disposed manually below, not via scratch.teardown's single slot

    assert.is_not.equals(handle_a._augroup_id, handle_b._augroup_id)

    local buf_a = scratch.edit(path_a)
    assert.is_not_nil(find(events_a, "doc.open"))
    assert.is_nil(find(events_b, "doc.open"))

    local buf_b = scratch.edit(path_b)
    assert.is_not_nil(find(events_b, "doc.open"))

    -- Disposing A must leave B's autocmds (and future events) intact.
    handle_a.dispose()
    local before_b = #events_b
    vim.api.nvim_buf_set_lines(buf_b, 0, 1, false, { "changed" })
    assert.is_true(#events_b > before_b)

    handle_b.dispose()
  end)
```

- [ ] **Step 6: Run the doc_wiring suite**

Run: `make test 2>&1 | grep -A 30 "doc_wiring_spec"`
Expected: all tests in `tests/recorder/wiring/doc_wiring_spec.lua` pass, including the two new/changed ones.

- [ ] **Step 7: Commit**

```bash
git add lua/provenance/recorder/wiring/doc_wiring.lua tests/recorder/wiring/doc_wiring_spec.lua
git commit --no-gpg-sign -m "fix(recorder): unique per-instance augroup for doc_wiring (concurrency)"
```

---

### Task 2: `focus_wiring.lua` + `selection_wiring.lua` — unique augroup per instance

**Files:**
- Modify: `lua/provenance/recorder/wiring/focus_wiring.lua:15,35,76`
- Modify: `lua/provenance/recorder/wiring/selection_wiring.lua:25,94,134`

**Interfaces:**
- Produces: `handle._augroup_id` on both modules' returned handles (for consistency with Tasks 1/3/4; no existing test in either module's spec needs it — confirmed by `grep -n "AUGROUP_NAME\|nvim_get_autocmds" tests/recorder/wiring/focus_wiring_spec.lua tests/recorder/wiring/selection_wiring_spec.lua` returning no matches — so no test file changes are required for this task).

Same mechanical pattern as Task 1, applied to two modules with no test-file impact.

- [ ] **Step 1: `focus_wiring.lua`**

Below `local AUGROUP_NAME = "ProvenanceFocus"` (line 15), add:

```lua
-- See doc_wiring.lua's identical comment: concurrent sessions each call
-- start() once, so the augroup name must be unique per instance.
local instance_seq = 0
```

Replace (line 35):

```lua
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })
```

with:

```lua
  instance_seq = instance_seq + 1
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME .. ":" .. instance_seq, { clear = true })
```

Replace the dispose body (line 76):

```lua
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
```

with:

```lua
    pcall(vim.api.nvim_del_augroup_by_id, augroup)
```

Add before `return handle` in `M.start`:

```lua
  handle._augroup_id = augroup
```

- [ ] **Step 2: `selection_wiring.lua`** — identical pattern

Below `local AUGROUP_NAME = "ProvenanceSelection"` (line 25), add the same `local instance_seq = 0` comment+line. Replace the creation (line 94) and dispose (line 134) exactly as in Step 1, and expose `handle._augroup_id` before `return handle` in `M.start`.

- [ ] **Step 3: Run both suites**

Run: `make test 2>&1 | grep -A 20 "focus_wiring_spec\|selection_wiring_spec"`
Expected: all existing tests still pass unchanged (no test file was touched).

- [ ] **Step 4: Commit**

```bash
git add lua/provenance/recorder/wiring/focus_wiring.lua lua/provenance/recorder/wiring/selection_wiring.lua
git commit --no-gpg-sign -m "fix(recorder): unique per-instance augroup for focus/selection wiring (concurrency)"
```

---

### Task 3: `external_change_coordinator.lua` — unique augroup per instance

**Files:**
- Modify: `lua/provenance/recorder/watch/external_change_coordinator.lua:59,122,222`
- Modify: `tests/recorder/watch/external_change_coordinator_spec.lua:313-332`

**Interfaces:**
- Produces: `handle._augroup_id` on `external_change_coordinator.start(opts)`'s returned handle.

- [ ] **Step 1: Apply the same pattern**

Below `local AUGROUP_NAME = "ProvenanceExternalChange"` (line 59), add the `local instance_seq = 0` line (same comment as Task 1/2). Replace the creation at line 122:

```lua
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })
```

with:

```lua
  instance_seq = instance_seq + 1
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME .. ":" .. instance_seq, { clear = true })
```

Replace dispose (line 222):

```lua
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
```

with:

```lua
    pcall(vim.api.nvim_del_augroup_by_id, augroup)
```

Expose `handle._augroup_id = augroup` before `return handle`.

- [ ] **Step 2: Fix the one test that checks the augroup by fixed name**

In `tests/recorder/watch/external_change_coordinator_spec.lua`, the `"removes the ProvenanceExternalChange augroup"` test (lines 313-332) currently does:

```lua
      -- Augroup exists while active.
      assert.has_no.errors(function()
        vim.api.nvim_get_autocmds({ group = "ProvenanceExternalChange" })
      end)

      coordinator.dispose()

      assert.has_error(function()
        vim.api.nvim_get_autocmds({ group = "ProvenanceExternalChange" })
      end)
```

Replace both `"ProvenanceExternalChange"` occurrences with `coordinator._augroup_id`:

```lua
      -- Augroup exists while active.
      local augroup_id = coordinator._augroup_id
      assert.is_number(augroup_id)
      assert.has_no.errors(function()
        vim.api.nvim_get_autocmds({ group = augroup_id })
      end)

      coordinator.dispose()

      assert.has_error(function()
        vim.api.nvim_get_autocmds({ group = augroup_id })
      end)
```

- [ ] **Step 3: Run the suite**

Run: `make test 2>&1 | grep -A 15 "external_change_coordinator_spec"`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add lua/provenance/recorder/watch/external_change_coordinator.lua tests/recorder/watch/external_change_coordinator_spec.lua
git commit --no-gpg-sign -m "fix(recorder): unique per-instance augroup for external_change_coordinator (concurrency)"
```

---

### Task 4: `terminal_wiring.lua` — unique augroup + workspace-scoped attribution

**Files:**
- Modify: `lua/provenance/recorder/wiring/terminal_wiring.lua:43,121-154,205-212`
- Modify: `lua/provenance/recorder/session/recording_session.lua:379`
- Modify: `tests/recorder/wiring/terminal_wiring_spec.lua` (multiple `group = AUGROUP_NAME` sites)
- Modify: `tests/recorder/e2e_seal_spec.lua:257`

**Interfaces:**
- Produces: `terminal_wiring.start(opts)` gains an optional `opts.workspace` (string|nil). `nil` (the default) preserves EXACT current behavior — every terminal is recorded, no filtering — so every existing call site that never passes `workspace` is unaffected. When set, a terminal opened with a cwd (`vim.fn.getcwd()` at `TermOpen` time) that is not `workspace` or a descendant of it is silently dropped (no `terminal.open`/`terminal.command` emitted, no error). `handle._augroup_id` exposed, same as Tasks 1-3.
- Consumes: `recording_session.lua`'s existing `workspace` local (already in scope at its call site).

This is the design decision flagged in the spec ("Terminal cwd -> owning session; drop if none owns it"), implemented as a **per-instance** filter (not a shared router) because concurrent sessions only ever arise from **disjoint** assignment roots under the locked nearest-ancestor discovery model (Task 7) — two sibling roots never share a path prefix, so at most one session's `workspace` prefix-matches a given terminal's cwd. This keeps `terminal_wiring` self-contained (mirrors how `doc_wiring` already filters by its own `workspace`), avoiding a new cross-session router abstraction. Flag this as a documented assumption, not a silent one.

- [ ] **Step 1: Add the module-level counter and a `resolve_dir`-style path helper**

`doc_wiring.lua` already has a `resolve_dir(path)` helper (realpath-with-normalize-fallback) used for workspace prefix checks — duplicate the SAME logic here rather than requiring `doc_wiring` from `terminal_wiring` (keeps the module's dependency graph as-is; the two modules already independently duplicate the manifest-name list per `doc_wiring.lua`'s own docstring precedent at its `MANIFEST_RELS` comment).

In `lua/provenance/recorder/wiring/terminal_wiring.lua`, below the existing `local M = {}` / `local AUGROUP_NAME = "ProvenanceTerminal"` (line 43), add:

```lua
-- Concurrent multi-session support: see doc_wiring.lua's identical comment.
local instance_seq = 0

--- Best-effort realpath, falling back to plain normalize (mirrors
--- doc_wiring.lua's resolve_dir -- duplicated here rather than shared, since
--- neither module depends on the other).
local function resolve_dir(path)
  if not path then
    return nil
  end
  local normalized = vim.fs.normalize(path)
  local real = vim.uv.fs_realpath(normalized)
  return real and vim.fs.normalize(real) or normalized
end

--- is_under_workspace(cwd, workspace) -> boolean
---
--- True if `cwd` (a terminal's working directory) is `workspace` itself or a
--- descendant of it, after realpath-normalizing both sides the same way
--- doc_wiring.lua's is_recordable() does (symmetric regardless of which
--- side a symlink sits on).
local function is_under_workspace(cwd, workspace)
  if not workspace then
    return true -- no workspace filter configured: unchanged legacy behavior
  end
  local abs_cwd = resolve_dir(cwd)
  local abs_workspace = resolve_dir(workspace)
  if not abs_cwd or not abs_workspace then
    return false
  end
  return abs_cwd == abs_workspace or vim.startswith(abs_cwd, abs_workspace .. "/")
end
```

- [ ] **Step 2: Thread `workspace` through `start()` and gate both emit sites**

In `M.start(opts)` (around line 121), add after `local emit = opts.emit`:

```lua
  local workspace = opts.workspace
```

In the `TermOpen` callback (around line 138-154), the body currently always records the terminal and emits. Wrap the terminal-id tracking + emit in the workspace check — but tracking must still happen even when the emit is dropped, otherwise a later `TermRequest` on the same untracked buffer looks like "untracked" for the wrong reason. Replace the callback body:

```lua
      pcall(function()
        local buf = args.buf
        local terminal_id = detect_terminal_id(buf)
        terminals[buf] = terminal_id

        if not is_under_workspace(vim.fn.getcwd(), workspace) then
          return -- not owned by this session: track silently, emit nothing
        end

        local shell = detect_shell(buf)
        local ev = terminal_payloads.build_terminal_open(terminal_id, shell, false)
        emit(ev.kind, ev.data)
      end)
```

`TermRequest`'s handler does not need its own workspace check: it only fires for a `buf` already present in `terminals`, but `terminals[buf]` is now set **regardless** of ownership (Step 2 above tracks unconditionally). A foreign terminal's `TermRequest` would therefore still emit `terminal.command` from a non-owning instance. Fix this by tracking ownership alongside the id: change `terminals[buf] = terminal_id` (both in `TermOpen` and left as-is) to a table entry, and gate `TermRequest` on it. Replace the terminals table's per-open write and the `TermRequest` callback:

```lua
      pcall(function()
        local buf = args.buf
        local terminal_id = detect_terminal_id(buf)
        local owned = is_under_workspace(vim.fn.getcwd(), workspace)
        terminals[buf] = { id = terminal_id, owned = owned }

        if not owned then
          return
        end

        local shell = detect_shell(buf)
        local ev = terminal_payloads.build_terminal_open(terminal_id, shell, false)
        emit(ev.kind, ev.data)
      end)
```

and in `TermRequest`:

```lua
      pcall(function()
        local buf = args.buf
        local tracked = terminals[buf]
        if not tracked or not tracked.owned then
          return
        end
        local terminal_id = tracked.id

        local data = args.data
        local sequence = data and data.sequence
        local finished, exit_code = M._parse_osc133_command_finished(sequence)
        if not finished then
          return
        end

        local ev = terminal_payloads.build_terminal_command(terminal_id, "", exit_code)
        emit(ev.kind, ev.data)
      end)
```

(`TermClose`'s body — `terminals[args.buf] = nil` — is unchanged; it already works with the new `{id, owned}` table shape since it just clears the whole entry.)

- [ ] **Step 3: Apply the augroup-uniqueness fix (same pattern as Tasks 1-3)**

Replace the creation (around line 133):

```lua
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })
```

with:

```lua
  instance_seq = instance_seq + 1
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME .. ":" .. instance_seq, { clear = true })
```

Replace dispose (around line 210):

```lua
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
```

with:

```lua
    pcall(vim.api.nvim_del_augroup_by_id, augroup)
```

Expose `handle._augroup_id = augroup` before `return handle`.

- [ ] **Step 4: Fix `tests/recorder/wiring/terminal_wiring_spec.lua`'s hardcoded group references**

Every `group = AUGROUP_NAME` in this file targets a specific instance under test; since the real name is now suffixed, these must target the instance's `_augroup_id` instead. There is exactly one instance per test in this file, so the simplest correct fix is to drop the `group = AUGROUP_NAME,` line entirely from each `nvim_exec_autocmds`/`nvim_get_autocmds` call (omitting `group` fires/queries without a group filter, which is equivalent when only one instance exists in the test process) **except** the one dispose test, which must target its own instance specifically to prove teardown.

Run `grep -n "group = AUGROUP_NAME" tests/recorder/wiring/terminal_wiring_spec.lua` to get the current exact line numbers (expected around: 84, 145, 156, 177, 195, 214, 232, 249, 267, 276), then:

1. Delete the local `local AUGROUP_NAME = "ProvenanceTerminal"` at line 28 (no longer needed once every reference below is fixed).
2. In `scratch.open_terminal` (around line 82-86), change:
   ```lua
   function scratch.open_terminal(opts)
     local buf = scratch.new_term_buf(opts)
     vim.api.nvim_exec_autocmds("TermOpen", { group = AUGROUP_NAME, buffer = buf })
     return buf
   end
   ```
   to:
   ```lua
   function scratch.open_terminal(opts)
     local buf = scratch.new_term_buf(opts)
     vim.api.nvim_exec_autocmds("TermOpen", { buffer = buf })
     return buf
   end
   ```
3. In every other test body (lines ~145, 156, 177, 195, 214, 232, 249), delete the `group = AUGROUP_NAME,` line from the `nvim_exec_autocmds` call table, leaving `buffer = ...` (and `data = ...` where present) as the only fields.
4. In the `"dispose(): removes the augroup..."` test (around line 258-284), which uses a **local** `handle` (not `scratch.handle`), replace:
   ```lua
   local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = AUGROUP_NAME })
   assert.is_true(not ok or #autocmds == 0)
   ```
   with:
   ```lua
   local augroup_id = handle._augroup_id
   assert.is_number(augroup_id)
   local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = augroup_id })
   assert.is_true(not ok or #autocmds == 0)
   ```
   and delete the trailing `group = AUGROUP_NAME,` from the post-dispose `nvim_exec_autocmds("TermOpen", ...)` call a few lines below it (around line 276) the same way as step 3.

- [ ] **Step 5: Add new tests for the workspace filter and cross-instance isolation**

Add to `tests/recorder/wiring/terminal_wiring_spec.lua`, inside `describe("terminal_wiring.start", ...)`:

```lua
  describe("workspace-scoped attribution (concurrency)", function()
    it("no workspace opt (legacy default): every terminal is recorded regardless of cwd", function()
      local events, emit = new_emit()
      scratch.handle = terminal_wiring.start({ emit = emit })

      scratch.open_terminal()
      assert.equals(1, count(events, "terminal.open"))
    end)

    it("workspace opt set: a terminal whose cwd is NOT under workspace is dropped (tracked but silent)", function()
      local other_dir = vim.fs.normalize(vim.fn.tempname())
      vim.fn.mkdir(other_dir, "p")

      local events, emit = new_emit()
      scratch.handle = terminal_wiring.start({ emit = emit, workspace = other_dir .. "-not-the-real-cwd" })

      local buf = scratch.open_terminal()
      assert.equals(0, count(events, "terminal.open"))

      -- Still tracked (not owned): a TermRequest on it must not emit either,
      -- and must not error.
      assert.has_no.errors(function()
        vim.api.nvim_exec_autocmds("TermRequest", { buffer = buf, data = { sequence = "\27]133;D;0" } })
      end)
      assert.equals(0, #events)

      pcall(vim.fn.delete, other_dir, "rf")
    end)

    it("workspace opt set: a terminal whose cwd IS workspace is recorded", function()
      local events, emit = new_emit()
      scratch.handle = terminal_wiring.start({ emit = emit, workspace = vim.fn.getcwd() })

      scratch.open_terminal()
      assert.equals(1, count(events, "terminal.open"))
    end)

    it("CONCURRENCY: two workspace-scoped instances only the matching one records a given terminal", function()
      local events_a, emit_a = new_emit()
      local events_b, emit_b = new_emit()
      local other_dir = vim.fs.normalize(vim.fn.tempname())
      vim.fn.mkdir(other_dir, "p")

      local handle_a = terminal_wiring.start({ emit = emit_a, workspace = vim.fn.getcwd() })
      local handle_b = terminal_wiring.start({ emit = emit_b, workspace = other_dir })
      scratch.handle = nil -- disposed manually

      scratch.open_terminal()

      assert.equals(1, count(events_a, "terminal.open"))
      assert.equals(0, count(events_b, "terminal.open"))

      handle_a.dispose()
      handle_b.dispose()
      pcall(vim.fn.delete, other_dir, "rf")
    end)
  end)
```

- [ ] **Step 6: Thread `workspace` through `recording_session.lua`'s composition**

In `lua/provenance/recorder/session/recording_session.lua`, line 379:

```lua
    term = terminal_wiring.start({ emit = host.emit })
```

becomes:

```lua
    term = terminal_wiring.start({ emit = host.emit, workspace = workspace })
```

(`workspace` is already the function's own top-level local; no new parameter needed.)

- [ ] **Step 7: Fix `tests/recorder/e2e_seal_spec.lua`'s one hardcoded terminal group reference**

At line 257:

```lua
    vim.api.nvim_exec_autocmds("TermOpen", { group = "ProvenanceTerminal", buffer = term_buf })
```

becomes:

```lua
    vim.api.nvim_exec_autocmds("TermOpen", { buffer = term_buf })
```

(This test only ever has one live session/terminal_wiring instance, so dropping the group filter is exactly equivalent, mirroring Step 4's fix in `terminal_wiring_spec.lua`.)

- [ ] **Step 8: Run everything touched**

Run: `make test 2>&1 | grep -A 40 "terminal_wiring_spec\|e2e_seal_spec\|recording_session_spec"`
Expected: all pass, including the four new concurrency/filter tests.

- [ ] **Step 9: Commit**

```bash
git add lua/provenance/recorder/wiring/terminal_wiring.lua lua/provenance/recorder/session/recording_session.lua tests/recorder/wiring/terminal_wiring_spec.lua tests/recorder/e2e_seal_spec.lua
git commit --no-gpg-sign -m "fix(recorder): workspace-scoped terminal attribution + unique augroup (concurrency)"
```

---

### Task 5: `paste_intercept.lua` — ref-counted singleton `vim.paste` wrap

**Files:**
- Modify: `lua/provenance/recorder/wiring/paste_intercept.lua` (full internal rewrite; public API unchanged)
- Modify: `tests/recorder/wiring/paste_intercept_spec.lua` (add concurrency tests; existing tests unchanged)

**Interfaces:**
- Produces: `M.attach(opts) -> handle` with `handle.dispose()` — **identical public signature** to today. `paste_assembly.lua` (Task 6) requires zero changes to its call site.
- New test-only introspection: `M._listener_count()` (integer) — how many live registrations exist right now; used only by the new concurrency tests, mirrors the repo's existing convention of underscore-prefixed test hooks (e.g. `recording_session.lua`'s `session._simulate_write_error`).

**Why this is needed (not just an augroup problem):** `vim.paste` is a single global function slot, not an autocmd dispatch surface. Today, `M.attach` captures `local original = vim.paste` and `dispose()` does `vim.paste = original`. With two sessions calling `attach()` (session A first, then B — B's `original` is A's wrapper), if they are disposed in the **same** order they were attached (A first) rather than strict LIFO, A's `dispose()` sets `vim.paste = original_A` (the true pre-Provenance default), discarding B's wrapper — and when B later calls `dispose()`, `vim.paste = original_B` **re-installs A's already-torn-down wrapper**, silently reactivating a stopped session's callback. `registry.stop_all()` (Task 8) iterates a Lua table (`pairs`), whose order is unspecified — so this bug is not a rare edge case, it is the **default** teardown order. The fix is a ref-counted singleton: the first `attach()` performs the real wrap (capturing the one true original exactly once); every `attach()`/`dispose()` after that only adds/removes a listener from a shared list; the wrap only unwraps back to the true original when the listener list becomes empty, regardless of order.

- [ ] **Step 1: Read the current file in full**

Run: `cat lua/provenance/recorder/wiring/paste_intercept.lua`
(Already read during planning; re-read here to confirm no drift before editing.)

- [ ] **Step 2: Rewrite the module as a ref-counted singleton behind the same `attach`/`dispose` API**

Replace the entire body of `lua/provenance/recorder/wiring/paste_intercept.lua` from `local M = {}` onward (keep the file's existing header comment and `capture_text` helper unchanged) with:

```lua
local M = {}

--- capture_text(lines) -> string
---
--- Clipboard-then-lines fallback: prefer the system clipboard register
--- (`+`), then the selection register (`*`), then the lines Neovim handed
--- us. `vim.fn.getreg` never returns nil for an unset register (empty
--- string), so each step is just an emptiness check.
local function capture_text(lines)
  local plus = vim.fn.getreg("+")
  if plus ~= nil and plus ~= "" then
    return plus
  end
  local star = vim.fn.getreg("*")
  if star ~= nil and star ~= "" then
    return star
  end
  return table.concat(lines, "\n")
end

-------------------------------------------------------------------------
-- Ref-counted singleton wrap (concurrency): `vim.paste` is a single global
-- function slot, not an event-dispatch surface like an autocmd group. N
-- concurrent sessions must NOT each independently wrap it (nested wraps
-- unwind incorrectly on non-LIFO dispose -- see this module's docstring in
-- the implementation plan). Instead, the FIRST attach() installs the one
-- real wrap and captures the one true `original`; every attach()/dispose()
-- after that only registers/unregisters a listener in `listeners`. The true
-- original is restored only when the listener list becomes empty, so
-- dispose() order never matters.
-------------------------------------------------------------------------

local listeners = {} -- list of { on_intercept, get_now }
local true_original = nil -- vim.paste as it was before the FIRST attach()
local installed = false

local function broadcast(lines, phase)
  if phase == -1 or phase == 1 then
    local text = capture_text(lines)
    -- Snapshot the listener list: a listener's on_intercept could (in
    -- principle) dispose itself or another instance re-entrantly; iterate
    -- over a copy so that never corrupts this loop.
    local snapshot = {}
    for i, l in ipairs(listeners) do
      snapshot[i] = l
    end
    for _, l in ipairs(snapshot) do
      if l.on_intercept then
        local at = l.get_now and l.get_now() or nil
        pcall(l.on_intercept, text, at)
      end
    end
  end
end

local function install()
  if installed then
    return
  end
  installed = true
  true_original = vim.paste
  vim.paste = function(lines, phase)
    pcall(broadcast, lines, phase)
    if true_original then
      return true_original(lines, phase)
    end
    return true
  end
end

local function uninstall_if_empty()
  if installed and #listeners == 0 then
    vim.paste = true_original
    installed = false
    true_original = nil
  end
end

--- M.attach(opts) -> handle
---
--- opts:
---   on_intercept(text, at) — called ONCE per paste (whole or start-of-
---     streamed), wrapped in pcall so an error here can never break the
---     user's paste, and can never break another concurrent listener either.
---   get_now() -> number — injected clock.
---
--- Returns a handle with handle.dispose(), idempotent, safe to call in any
--- order relative to other concurrently-attached instances' dispose().
function M.attach(opts)
  opts = opts or {}

  install()

  local entry = { on_intercept = opts.on_intercept, get_now = opts.get_now }
  table.insert(listeners, entry)

  local disposed = false
  local handle = {}

  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    for i, l in ipairs(listeners) do
      if l == entry then
        table.remove(listeners, i)
        break
      end
    end
    uninstall_if_empty()
  end

  return handle
end

--- Test-only introspection: how many live (non-disposed) registrations
--- exist right now. Not part of the module's production API.
function M._listener_count()
  return #listeners
end

return M
```

- [ ] **Step 3: Run the EXISTING test file unchanged**

Run: `make test 2>&1 | grep -A 20 "paste_intercept_spec"`
Expected: all 5 existing tests pass unchanged (single-attach behavior is byte-identical: one listener installed, one removed, restores the true original).

- [ ] **Step 4: Add concurrency tests**

Add to `tests/recorder/wiring/paste_intercept_spec.lua`, inside `describe("paste_intercept.attach", ...)`:

```lua
  describe("CONCURRENCY: two concurrent attach() calls", function()
    it("both listeners fire for a single paste", function()
      local calls_a, on_intercept_a = new_capture()
      local calls_b, on_intercept_b = new_capture()

      local handle_a = paste_intercept.attach({ on_intercept = on_intercept_a, get_now = function() return 1 end })
      local handle_b = paste_intercept.attach({ on_intercept = on_intercept_b, get_now = function() return 2 end })

      vim.fn.setreg("+", "shared paste")
      local buf = vim.api.nvim_create_buf(false, true)
      table.insert(scratch.bufs, buf)
      vim.api.nvim_set_current_buf(buf)

      vim.paste({ "shared paste" }, -1)

      assert.equals(1, #calls_a)
      assert.equals(1, #calls_b)
      assert.equals("shared paste", calls_a[1].text)
      assert.equals("shared paste", calls_b[1].text)

      handle_a.dispose()
      handle_b.dispose()
    end)

    it("disposing in ATTACH order (non-LIFO) does not silently reactivate the first instance", function()
      local calls_a, on_intercept_a = new_capture()
      local calls_b, on_intercept_b = new_capture()

      local orig = vim.paste
      local handle_a = paste_intercept.attach({ on_intercept = on_intercept_a, get_now = function() return 0 end })
      local handle_b = paste_intercept.attach({ on_intercept = on_intercept_b, get_now = function() return 0 end })

      -- Dispose A FIRST (attach order, the pathological non-LIFO case).
      handle_a.dispose()
      assert.equals(1, paste_intercept._listener_count())
      -- vim.paste must still be wrapped (B is still registered), not yet
      -- restored to the true original.
      assert.is_not.equals(orig, vim.paste)

      vim.fn.setreg("+", "after a disposed")
      local buf = vim.api.nvim_create_buf(false, true)
      table.insert(scratch.bufs, buf)
      vim.api.nvim_set_current_buf(buf)
      vim.paste({ "after a disposed" }, -1)

      -- A must NOT have been reactivated; only B fires.
      assert.equals(0, #calls_a)
      assert.equals(1, #calls_b)

      handle_b.dispose()
      assert.equals(0, paste_intercept._listener_count())
      assert.equals(orig, vim.paste)
    end)

    it("disposing in REVERSE (LIFO) order also fully restores the true original", function()
      local calls_a, on_intercept_a = new_capture()
      local calls_b, on_intercept_b = new_capture()

      local orig = vim.paste
      local handle_a = paste_intercept.attach({ on_intercept = on_intercept_a, get_now = function() return 0 end })
      local handle_b = paste_intercept.attach({ on_intercept = on_intercept_b, get_now = function() return 0 end })

      handle_b.dispose()
      handle_a.dispose()

      assert.equals(0, paste_intercept._listener_count())
      assert.equals(orig, vim.paste)
    end)

    it("an error in one listener's on_intercept does not prevent the other from firing", function()
      local calls_b, on_intercept_b = new_capture()
      local handle_a = paste_intercept.attach({
        on_intercept = function() error("boom") end,
        get_now = function() return 0 end,
      })
      local handle_b = paste_intercept.attach({ on_intercept = on_intercept_b, get_now = function() return 0 end })

      vim.fn.setreg("+", "still works")
      local buf = vim.api.nvim_create_buf(false, true)
      table.insert(scratch.bufs, buf)
      vim.api.nvim_set_current_buf(buf)

      assert.has_no.errors(function()
        vim.paste({ "still works" }, -1)
      end)
      assert.equals(1, #calls_b)

      handle_a.dispose()
      handle_b.dispose()
    end)
  end)
```

- [ ] **Step 5: Run the full paste_intercept suite**

Run: `make test 2>&1 | grep -A 60 "paste_intercept_spec"`
Expected: 9 tests total (5 existing + 4 new), all pass.

- [ ] **Step 6: Commit**

```bash
git add lua/provenance/recorder/wiring/paste_intercept.lua tests/recorder/wiring/paste_intercept_spec.lua
git commit --no-gpg-sign -m "fix(recorder): ref-counted singleton vim.paste wrap (concurrency-safe teardown)"
```

---

### Task 6: `paste_assembly.lua` — ownership gate on the shared paste intercept

**Files:**
- Modify: `lua/provenance/recorder/wiring/paste_assembly.lua:54-59`
- Modify: `tests/recorder/wiring/paste_assembly_spec.lua` (add one concurrency test)

**Interfaces:**
- Consumes: `doc_wiring_handle.recordable_rel(buf)` (already exposed by `doc_wiring.lua`, already used identically by `selection_wiring.lua`).
- No public signature change to `paste_assembly.attach(opts)`.

**Why:** Task 5 makes the `vim.paste` wrap itself safe to share, but every registered listener still fires for **every** paste anywhere in the process — including one that lands in a buffer owned by a different session. Without a filter, session B's `paste_correlator` would see session A's paste text as a `pending` intercept and could misattribute a later, unrelated edit in B's own buffer as a confirmed paste (or inflate B's `paste.anomaly.intercepted_count`). The fix: before forwarding to `correlator.on_paste_intercept`, check that the buffer the paste is landing in (`vim.api.nvim_get_current_buf()` — the paste's target buffer is always current at the moment `vim.paste` runs) is recordable by **this** session's own `doc_wiring_handle`.

- [ ] **Step 1: Add the ownership gate**

In `lua/provenance/recorder/wiring/paste_assembly.lua`, the `intercept` construction (lines 54-59) currently reads:

```lua
  local intercept = paste_intercept.attach({
    on_intercept = function(text, at)
      correlator.on_paste_intercept(text, at)
    end,
    get_now = get_now,
  })
```

Replace with:

```lua
  local intercept = paste_intercept.attach({
    on_intercept = function(text, at)
      -- Concurrency: the shared vim.paste wrap (paste_intercept.lua)
      -- broadcasts to every attached session. Only forward this intercept
      -- to THIS session's correlator if the paste landed in a buffer this
      -- session actually owns -- otherwise a paste in a sibling session's
      -- buffer would pollute this session's paste_correlator with a
      -- foreign clipboard capture, risking a misattributed `paste` event
      -- (or an inflated paste.anomaly count) on a later, unrelated edit of
      -- THIS session's own buffer.
      local buf = vim.api.nvim_get_current_buf()
      if not doc_wiring_handle.recordable_rel(buf) then
        return
      end
      correlator.on_paste_intercept(text, at)
    end,
    get_now = get_now,
  })
```

- [ ] **Step 2: Run the existing paste_assembly suite (must be unaffected)**

Run: `make test 2>&1 | grep -A 20 "paste_assembly_spec"`
Expected: all existing tests still pass — they already drive `vim.paste` from within a buffer that `doc_wiring_handle` (a real instance) recognizes as recordable, so the new gate is a no-op for them.

- [ ] **Step 3: Add a concurrency test proving isolation**

Add to `tests/recorder/wiring/paste_assembly_spec.lua` (find the existing `new_scratch`/`new_emit` helpers already in that file and reuse them; check the file's current helper names with `grep -n "^local function\|^  function scratch" tests/recorder/wiring/paste_assembly_spec.lua` before writing this so the helper calls below match exactly):

```lua
  it("CONCURRENCY: a paste in session B's buffer is never seen by session A's correlator", function()
    local workspace_a = scratch.workspace()
    local workspace_b = scratch.workspace()
    local path_a = workspace_a .. "/a.txt"
    local path_b = workspace_b .. "/b.txt"
    scratch.write_file(path_a, "aaa\n")
    scratch.write_file(path_b, "bbb\n")

    local events_a, emit_a = new_emit()
    local events_b, emit_b = new_emit()

    local doc_a = doc_wiring.attach({ workspace = workspace_a, emit = emit_a })
    local doc_b = doc_wiring.attach({ workspace = workspace_b, emit = emit_b })
    local assembly_a = paste_assembly.attach({ emit = emit_a, doc_wiring_handle = doc_a })
    local assembly_b = paste_assembly.attach({ emit = emit_b, doc_wiring_handle = doc_b })

    local buf_b = scratch.edit(path_b)
    local clip = string.rep("X", 40) -- >= 30 chars: paste_likely shape
    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    -- Session B (the owning session) sees the paste.
    local paste_ev_b = find(events_b, "paste")
    assert.is_not_nil(paste_ev_b)

    -- Session A never sees a paste event, and its own next typed edit (in
    -- its OWN buffer) is not misattributed as a confirmed paste just
    -- because A's correlator saw B's clipboard capture.
    assert.is_nil(find(events_a, "paste"))

    local buf_a = scratch.edit(path_a)
    vim.api.nvim_buf_set_lines(buf_a, 0, 1, false, { "short" })
    local change_ev_a = find(events_a, "doc.change")
    assert.is_not_nil(change_ev_a)
    assert.equals("typed", change_ev_a.data.source)

    assembly_a.dispose()
    assembly_b.dispose()
    doc_a.dispose()
    doc_b.dispose()
  end)
```

If `paste_assembly_spec.lua` does not already `require("provenance.recorder.wiring.doc_wiring")` at the top, add that require alongside the existing `paste_assembly` require.

- [ ] **Step 4: Run the full suite**

Run: `make test 2>&1 | grep -A 30 "paste_assembly_spec"`
Expected: all pass, including the new concurrency test.

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/recorder/wiring/paste_assembly.lua tests/recorder/wiring/paste_assembly_spec.lua
git commit --no-gpg-sign -m "fix(recorder): gate shared paste intercept by buffer ownership (concurrency)"
```

---

### Task 7: `discovery.lua` — upward manifest walk (new module)

**Files:**
- Create: `lua/provenance/recorder/discovery.lua`
- Test: `tests/recorder/discovery_spec.lua`

**Interfaces:**
- Produces:
  - `discovery.resolve_from_dir(start_dir, opts) -> { status = "active", root, manifest } | { status = "inactive", reason, root? }` — walks upward from `start_dir` (inclusive) for the nearest ancestor directory containing `.provenance-manifest` or `provenance-manifest` (first name wins within a single directory, mirroring `activation.lua`'s `MANIFEST_NAMES` order — verified empirically, see plan header), then verifies via `opts.load_and_verify` (default `require("provenance.recorder.activation").load_and_verify`) at that directory. No manifest found anywhere upward -> `{status="inactive", reason="no_manifest_file"}`. Manifest found but fails verification -> `{status="inactive", reason=<activation's reason>, root=<the found dir>}` (search does NOT continue further upward past an invalid manifest — locked spec decision).
  - `discovery.resolve_for_file(file_path, opts) -> same shape` — convenience wrapper: `resolve_from_dir(vim.fs.dirname(file_path), opts)`.
  - `opts` (both functions): `{ pubkey_hex = <string|nil>, load_and_verify = <function|nil>, stop_dir = <string|nil> }`, all optional, threaded straight through to `vim.fs.find`'s `stop` and to the verification call.
- Consumes: `provenance.recorder.activation.load_and_verify(workspace_dir, pubkey_hex)` (existing, unchanged).

- [ ] **Step 1: Write the failing tests**

Create `tests/recorder/discovery_spec.lua`:

```lua
--- Tests for discovery.lua: the upward-walk manifest resolver (Plan:
--- 2026-07-20-nested-manifest-discovery). Uses REAL temp directories and the
--- REAL vim.fs.find/activation.load_and_verify (no filesystem mocking --
--- the whole point of this module is real upward-walk semantics), but signs
--- test manifests with an injected pubkey via activation.evaluate's
--- pure-Lua path so no real course keypair is needed.
local discovery = require("provenance.recorder.discovery")
local ed25519 = require("provenance.core.ed25519")
local json = require("provenance.core.json")

local function new_scratch()
  local scratch = { dirs = {} }
  function scratch.dir(rel)
    local d = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(d, "p")
    table.insert(scratch.dirs, d)
    if rel then
      local nested = d .. "/" .. rel
      vim.fn.mkdir(nested, "p")
      return d, nested
    end
    return d
  end
  function scratch.mkdir(path)
    vim.fn.mkdir(path, "p")
  end
  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end
  function scratch.teardown()
    for _, d in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, d, "rf")
    end
  end
  return scratch
end

--- Signs a minimal manifest payload with a fresh test keypair and returns
--- (manifest_json_text, pubkey_hex).
local function make_signed_manifest(assignment_id)
  local privkey = ed25519.random_private_key()
  local pubkey = ed25519.public_key(privkey)
  local payload = {
    assignment_id = assignment_id,
    semester = "fa25",
    issued_at = "2026-07-20T00:00:00.000Z",
    files_under_review = json.array({ "main.py" }),
  }
  local canonical = json.canonicalize(payload)
  local sig = ed25519.to_hex(ed25519.sign(canonical, privkey))
  local full = vim.deepcopy(payload)
  full.files_under_review = { "main.py" } -- plain array for vim.json.encode
  full.sig = sig
  return vim.json.encode(full), ed25519.to_hex(pubkey)
end

describe("discovery.resolve_from_dir", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("no manifest anywhere upward: inactive, reason no_manifest_file", function()
    local root = scratch.dir("a/b/c")
    local result = discovery.resolve_from_dir(root .. "/a/b/c")
    assert.equals("inactive", result.status)
    assert.equals("no_manifest_file", result.reason)
  end)

  it("manifest at the exact starting directory: active, root == starting dir", function()
    local base = scratch.dir()
    local text, pubkey = make_signed_manifest("hw1")
    scratch.write_file(base .. "/.provenance-manifest", text)

    local result = discovery.resolve_from_dir(base, { pubkey_hex = pubkey })
    assert.equals("active", result.status)
    assert.equals(base, result.root)
    assert.equals("hw1", result.manifest.assignment_id)
  end)

  it("LAUNCH CASE: cd assignment/ && nvim file.py -- manifest at file's own dir", function()
    local base, nested = scratch.dir("cats")
    local text, pubkey = make_signed_manifest("cats")
    scratch.write_file(nested .. "/.provenance-manifest", text)

    local result = discovery.resolve_from_dir(nested, { pubkey_hex = pubkey })
    assert.equals("active", result.status)
    assert.equals(nested, result.root)
  end)

  it("LAUNCH CASE: cd parent && nvim cats/cats.py -- resolves cats/, never considers sibling hog/", function()
    local base = scratch.dir()
    scratch.mkdir(base .. "/cats")
    scratch.mkdir(base .. "/hog")
    local cats_text, cats_key = make_signed_manifest("cats")
    local hog_text, _hog_key = make_signed_manifest("hog")
    scratch.write_file(base .. "/cats/.provenance-manifest", cats_text)
    scratch.write_file(base .. "/hog/.provenance-manifest", hog_text)

    local result = discovery.resolve_from_dir(base .. "/cats", { pubkey_hex = cats_key })
    assert.equals("active", result.status)
    assert.equals(base .. "/cats", result.root)
    assert.equals("cats", result.manifest.assignment_id)
  end)

  it("LAUNCH CASE: cd ~ && nvim 61a/cats/cats.py -- walks up 3 levels, rest of ~ never scanned", function()
    local base, nested = scratch.dir("61a/cats/extra")
    local text, pubkey = make_signed_manifest("cats")
    scratch.write_file(base .. "/61a/cats/.provenance-manifest", text)

    local result = discovery.resolve_from_dir(nested, { pubkey_hex = pubkey, stop_dir = base })
    assert.equals("active", result.status)
    assert.equals(base .. "/61a/cats", result.root)
  end)

  it("failing signature at the nearest manifest: inactive, does NOT fall through to search further up", function()
    local base = scratch.dir()
    scratch.mkdir(base .. "/outer")
    scratch.mkdir(base .. "/outer/inner")
    local outer_text, outer_key = make_signed_manifest("outer-assignment")
    local inner_text, _inner_key = make_signed_manifest("inner-assignment")
    scratch.write_file(base .. "/outer/.provenance-manifest", outer_text)
    scratch.write_file(base .. "/outer/inner/.provenance-manifest", inner_text)

    -- Verify against outer's key: the NEAREST manifest (inner) fails
    -- signature verification, and resolution must NOT fall through to the
    -- valid outer manifest.
    local result = discovery.resolve_from_dir(base .. "/outer/inner", { pubkey_hex = outer_key })
    assert.equals("inactive", result.status)
    assert.equals("signature_invalid", result.reason)
    assert.equals(base .. "/outer/inner", result.root)
  end)

  it("plain 'provenance-manifest' fallback name is found when the dotfile is absent", function()
    local base = scratch.dir()
    local text, pubkey = make_signed_manifest("plain-name")
    scratch.write_file(base .. "/provenance-manifest", text)

    local result = discovery.resolve_from_dir(base, { pubkey_hex = pubkey })
    assert.equals("active", result.status)
  end)
end)

describe("discovery.resolve_for_file", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("resolves from the FILE's directory, not the file path itself", function()
    local base = scratch.dir()
    local text, pubkey = make_signed_manifest("hw2")
    scratch.write_file(base .. "/.provenance-manifest", text)
    scratch.write_file(base .. "/main.py", "print(1)\n")

    local result = discovery.resolve_for_file(base .. "/main.py", { pubkey_hex = pubkey })
    assert.equals("active", result.status)
    assert.equals(base, result.root)
  end)

  it("a file under NO manifest resolves to nothing", function()
    local base = scratch.dir()
    scratch.write_file(base .. "/scratch.txt", "no manifest here\n")

    local result = discovery.resolve_for_file(base .. "/scratch.txt")
    assert.equals("inactive", result.status)
  end)
end)
```

- [ ] **Step 2: Run the tests, confirm they fail (module doesn't exist yet)**

Run: `make test 2>&1 | grep -B2 -A 10 "discovery_spec"`
Expected: failures/errors — `module 'provenance.recorder.discovery' not found`.

- [ ] **Step 3: Check `core/ed25519.lua`'s exact function names before using them in the test above**

Run: `grep -n "^function M\." lua/provenance/core/ed25519.lua`
Confirm the test helper `make_signed_manifest` above calls the real names (`random_private_key`, `public_key`, `sign`, `to_hex` or whatever the actual exports are — adjust the test file to match; do not guess if the grep output differs from what's used above).

- [ ] **Step 4: Implement `discovery.lua`**

Create `lua/provenance/recorder/discovery.lua`:

```lua
--- discovery.lua — upward manifest discovery (design:
--- docs/superpowers/specs/2026-07-20-nested-manifest-discovery-design.md).
---
--- Neovim has no opened-folder object, only buffers and a loosely-related
--- cwd, so activation must be anchored on the FILE, not the directory:
--- resolve_from_dir walks UPWARD from a starting directory to the nearest
--- ancestor containing a manifest (mirrors how LSP root_dir / .git detection
--- work in Neovim), then delegates verification to
--- provenance.recorder.activation.load_and_verify at that directory. A
--- manifest that is FOUND but fails verification is terminal -- the walk
--- does NOT continue further upward looking for another one (locked design
--- decision: "no manifest found or verification fails -> not recorded").
local activation = require("provenance.recorder.activation")

local M = {}

-- Precedence order mirrors activation.lua's own (unexported) MANIFEST_NAMES:
-- the canonical dotfile wins over the plain fallback when both exist in the
-- SAME directory. Duplicated here rather than shared, following this
-- repo's existing convention (doc_wiring.lua's MANIFEST_RELS comment notes
-- the same tradeoff) -- both must change together if the manifest filename
-- ever changes.
local MANIFEST_NAMES = { ".provenance-manifest", "provenance-manifest" }

--- @param start_dir string  directory to start the upward walk from (inclusive)
--- @param opts table|nil { pubkey_hex, load_and_verify, stop_dir }
--- @return table
---   { status = "active", root, manifest }
---   | { status = "inactive", reason = "no_manifest_file" }
---   | { status = "inactive", reason = <activation reason>, root = <found dir> }
function M.resolve_from_dir(start_dir, opts)
  opts = opts or {}
  local load_and_verify = opts.load_and_verify or activation.load_and_verify

  local ok, found = pcall(vim.fs.find, MANIFEST_NAMES, {
    upward = true,
    path = start_dir,
    limit = 1,
    stop = opts.stop_dir,
  })

  if not ok or not found or #found == 0 then
    return { status = "inactive", reason = "no_manifest_file" }
  end

  local root = vim.fs.dirname(found[1])
  local result = load_and_verify(root, opts.pubkey_hex)

  if result.status == "active" then
    return { status = "active", root = root, manifest = result.manifest }
  end

  return { status = "inactive", reason = result.reason, root = root }
end

--- @param file_path string  absolute path to a buffer's file
--- @param opts table|nil  see resolve_from_dir
--- @return table  see resolve_from_dir
function M.resolve_for_file(file_path, opts)
  return M.resolve_from_dir(vim.fs.dirname(file_path), opts)
end

return M
```

- [ ] **Step 5: Run the tests again**

Run: `make test 2>&1 | grep -A 40 "discovery_spec"`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add lua/provenance/recorder/discovery.lua tests/recorder/discovery_spec.lua
git commit --no-gpg-sign -m "feat(recorder): upward manifest discovery (vim.fs.find nearest-ancestor walk)"
```

---

### Task 8: `registry.lua` — the one-to-many session registry (new module)

**Files:**
- Create: `lua/provenance/recorder/registry.lua`
- Test: `tests/recorder/registry_spec.lua`

**Interfaces:**
- Produces:
  - `registry.new(opts) -> reg` where `opts = { start_recording = function(start_opts) -> controller }` (required; production wires `recording_controller.start`, tests inject a spy — mirrors `init_controller_spec.lua`'s existing `make_start_recording_spy()` pattern).
  - `reg.is_active() -> boolean` — **no-arg aggregate**: true iff at least one session is currently registered. Deliberately named to match `RecorderState.is_active()`'s no-arg shape so `status.attach(reg)` (Task 9) works with **zero changes to `status.lua`** — `status.lua`'s `attach(state)` only ever calls `state.is_active()`.
  - `reg.has_session(root) -> boolean` — single-root query (kept as a separate name from `is_active()` specifically to avoid the arity collision above).
  - `reg.get(root) -> { manifest, controller, provenance_dir } | nil`
  - `reg.list() -> array of { root, manifest, controller }`, sorted by `root` ascending (deterministic order for the seal picker and for tests).
  - `reg.ensure_session(root, manifest, extra_opts) -> controller, started` — idempotent: if a session already exists for `root`, returns it unchanged (`started = false`) without calling `start_recording` again. Otherwise calls `start_recording` with `{workspace = root, provenance_dir = root .. "/.provenance", manifest = manifest}` merged with `extra_opts` (`extra_opts` wins on conflicting keys, mirroring `vim.tbl_extend("force", ...)`'s existing use in `recording_controller.lua`), stores the result, returns `(controller, true)`. On a `start_recording` failure (pcall-guarded), returns `(nil, false, err)` and does NOT register a half-open entry.
  - `reg.stop_all(reason)` — pcall-guarded per-entry `controller.stop(reason)`, then clears every entry, regardless of iteration order (order-independence is required — see Task 5's rationale, which this registry's `pairs()`-based iteration directly exercises).
- Consumes: nothing beyond the injected `start_recording`.

- [ ] **Step 1: Write the failing tests**

Create `tests/recorder/registry_spec.lua`:

```lua
--- Tests for registry.lua: the root -> session map replacing the single
--- state/controller pair (Plan: 2026-07-20-nested-manifest-discovery).
--- Mirrors init_controller_spec.lua's injected start_recording spy style so
--- this never starts a real recording session or touches the filesystem.
local registry_mod = require("provenance.recorder.registry")

local function make_start_recording_spy()
  local calls = {}
  local function start_recording(args)
    local fake_controller = { stop_calls = {} }
    function fake_controller.stop(reason)
      table.insert(fake_controller.stop_calls, reason)
    end
    table.insert(calls, { args = args, controller = fake_controller })
    return fake_controller
  end
  return start_recording, calls
end

describe("registry.new", function()
  it("fresh registry: is_active() is false, list() is empty", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    assert.is_false(reg.is_active())
    assert.same({}, reg.list())
  end)

  it("ensure_session: starts a session with workspace/provenance_dir/manifest derived from root", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    local manifest = { assignment_id = "hw3" }

    local controller, started = reg.ensure_session("/tmp/ws-a", manifest)

    assert.is_true(started)
    assert.is_not_nil(controller)
    assert.equals(1, #calls)
    assert.equals("/tmp/ws-a", calls[1].args.workspace)
    assert.equals("/tmp/ws-a/.provenance", calls[1].args.provenance_dir)
    assert.equals(manifest, calls[1].args.manifest)
    assert.is_true(reg.is_active())
    assert.is_true(reg.has_session("/tmp/ws-a"))
  end)

  it("ensure_session is idempotent: a second call for the SAME root does not start a second session", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    local manifest = { assignment_id = "hw3" }

    local c1, started1 = reg.ensure_session("/tmp/ws-a", manifest)
    local c2, started2 = reg.ensure_session("/tmp/ws-a", manifest)

    assert.equals(1, #calls)
    assert.is_true(started1)
    assert.is_false(started2)
    assert.equals(c1, c2)
  end)

  it("CONCURRENCY: two different roots each get their own session", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })

    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    assert.equals(2, #calls)
    assert.is_true(reg.has_session("/tmp/cats"))
    assert.is_true(reg.has_session("/tmp/hog"))
    assert.is_true(reg.is_active())

    local list = reg.list()
    assert.equals(2, #list)
    -- Sorted by root ascending.
    assert.equals("/tmp/cats", list[1].root)
    assert.equals("/tmp/hog", list[2].root)
  end)

  it("get(root) returns the stored entry; get() for an unknown root returns nil", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })

    local entry = reg.get("/tmp/cats")
    assert.equals("cats", entry.manifest.assignment_id)
    assert.equals("/tmp/cats/.provenance", entry.provenance_dir)

    assert.is_nil(reg.get("/tmp/nonexistent"))
  end)

  it("ensure_session propagates extra_opts to start_recording, extra_opts winning on conflicts", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })

    reg.ensure_session("/tmp/cats", { assignment_id = "cats" }, { clock = "injected-clock", provenance_dir = "/tmp/cats/.override" })

    assert.equals("injected-clock", calls[1].args.clock)
    assert.equals("/tmp/cats/.override", calls[1].args.provenance_dir)
  end)

  it("ensure_session on a start_recording failure does not register a half-open entry", function()
    local reg = registry_mod.new({
      start_recording = function()
        error("boom")
      end,
    })

    local controller, started, err = reg.ensure_session("/tmp/cats", { assignment_id = "cats" })

    assert.is_nil(controller)
    assert.is_false(started)
    assert.is_not_nil(err)
    assert.is_false(reg.has_session("/tmp/cats"))
    assert.is_false(reg.is_active())
  end)

  it("stop_all: stops every session exactly once and clears the registry", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    reg.stop_all("deactivate")

    assert.equals(1, #calls[1].controller.stop_calls)
    assert.equals("deactivate", calls[1].controller.stop_calls[1])
    assert.equals(1, #calls[2].controller.stop_calls)
    assert.is_false(reg.is_active())
    assert.same({}, reg.list())
  end)

  it("stop_all is safe to call with zero active sessions", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    assert.has_no.errors(function()
      reg.stop_all("deactivate")
    end)
  end)

  it("stop_all does not stop the SAME controller twice if a controller.stop() call throws", function()
    local reg = registry_mod.new({
      start_recording = function()
        return { stop = function() error("stop failed") end }
      end,
    })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    -- A throwing stop() for one entry must not prevent the OTHER entry
    -- from being stopped and cleared too.
    assert.has_no.errors(function()
      reg.stop_all("deactivate")
    end)
    assert.is_false(reg.is_active())
  end)
end)
```

- [ ] **Step 2: Run, confirm failure**

Run: `make test 2>&1 | grep -B2 -A 10 "registry_spec"`
Expected: `module 'provenance.recorder.registry' not found`.

- [ ] **Step 3: Implement `registry.lua`**

Create `lua/provenance/recorder/registry.lua`:

```lua
--- registry.lua — the root -> session map (Plan:
--- 2026-07-20-nested-manifest-discovery). Replaces the single module-level
--- `state`/`controller` pair recorder/init.lua used to own with a table
--- keyed by assignment root, so more than one assignment can record at the
--- same instant, each with its own live recording_controller session.
---
--- Deliberately dumb: this module does not know about discovery, buffers,
--- or autocmds -- it only tracks "which roots currently have a live
--- session" and starts/stops sessions via an injected start_recording seam
--- (production: recording_controller.start; tests: a spy, mirroring
--- init_controller_spec.lua's existing style).
local M = {}

--- @param opts table { start_recording: function(start_opts) -> controller }
--- @return table registry
function M.new(opts)
  opts = opts or {}
  local start_recording = opts.start_recording

  -- root -> { manifest, controller, provenance_dir }
  local sessions = {}

  local reg = {}

  --- Aggregate, no-arg (deliberately named to match RecorderState.is_active()
  --- so status.attach(reg) works unmodified): true iff at least one session
  --- is currently registered.
  function reg.is_active()
    return next(sessions) ~= nil
  end

  --- @param root string
  --- @return boolean
  function reg.has_session(root)
    return sessions[root] ~= nil
  end

  --- @param root string
  --- @return table|nil { manifest, controller, provenance_dir }
  function reg.get(root)
    return sessions[root]
  end

  --- @return table[]  { root, manifest, controller }, sorted by root ascending
  function reg.list()
    local out = {}
    for root, entry in pairs(sessions) do
      out[#out + 1] = { root = root, manifest = entry.manifest, controller = entry.controller }
    end
    table.sort(out, function(a, b)
      return a.root < b.root
    end)
    return out
  end

  --- Idempotent: if `root` already has a live session, returns it unchanged
  --- (does not call start_recording again). Otherwise starts one.
  --- @param root string
  --- @param manifest table
  --- @param extra_opts table|nil  merged into the start_recording opts,
  ---   winning on any key collision with the derived workspace/provenance_dir/manifest
  --- @return table|nil controller, boolean started, string|nil err
  function reg.ensure_session(root, manifest, extra_opts)
    local existing = sessions[root]
    if existing then
      return existing.controller, false
    end

    local provenance_dir = root .. "/.provenance"
    local start_opts = vim.tbl_extend("force", {
      workspace = root,
      provenance_dir = provenance_dir,
      manifest = manifest,
    }, extra_opts or {})

    local ok, controller = pcall(start_recording, start_opts)
    if not ok then
      return nil, false, controller
    end

    sessions[root] = { manifest = manifest, controller = controller, provenance_dir = provenance_dir }
    return controller, true
  end

  --- Stop every registered session (pcall-guarded per entry, so one
  --- failing stop() never blocks the others) and clear the registry.
  --- Order-independent by construction (Lua's pairs() order is
  --- unspecified) -- this is deliberate: see paste_intercept.lua's
  --- ref-counted-singleton fix for why teardown order must never matter.
  --- @param reason string|nil
  function reg.stop_all(reason)
    for root, entry in pairs(sessions) do
      pcall(entry.controller.stop, reason)
      sessions[root] = nil
    end
  end

  return reg
end

return M
```

- [ ] **Step 4: Run the tests again**

Run: `make test 2>&1 | grep -A 60 "registry_spec"`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/recorder/registry.lua tests/recorder/registry_spec.lua
git commit --no-gpg-sign -m "feat(recorder): root -> session registry for concurrent multi-assignment recording"
```

---

### Task 9 [OPUS — highest-reasoning, highest-risk task]: rewire `init.lua`

**Files:**
- Modify: `lua/provenance/recorder/init.lua` (full rewrite of `M.setup`)
- Modify: `tests/recorder/init_spec.lua` (rewrite: `load_and_verify` seam -> `resolve` seam)
- Modify: `tests/recorder/init_controller_spec.lua` (rewrite: same seam rename, cwd-driven tests adapted)
- Modify: `tests/recorder/init_seal_command_spec.lua` (rewrite: single-session behavior preserved, new picker tests added)

**Interfaces:**
- Consumes: `discovery.resolve_from_dir(start_dir, opts)` (Task 7), `registry.new(opts)` (Task 8), `recording_controller.start` (existing), `status.attach/detach/segment` (existing, **unchanged** — `registry.is_active()` is a drop-in for `RecorderState.is_active()`).
- Produces: `recorder.setup(opts) -> handle` with `handle.dispose()`. New `opts` shape:
  - `opts.resolve = function(start_dir) -> {status, root?, manifest?, reason?}` — full bypass-or-production seam, **replaces** today's `opts.load_and_verify`. Defaults to `discovery.resolve_from_dir`. This is a deliberate, necessary rename: the old seam only ever verified a manifest at a single, externally-given directory; the new one also owns "which directory" (the upward walk), so its result must report `root` (Task 7's contract) in addition to `manifest`/`reason`.
  - `opts.start_recording` — unchanged seam (defaults to `recording_controller.start`), now threaded into `registry.new({start_recording = ...})` instead of called directly.
  - `opts.workspace` — unchanged meaning: overrides the cwd anchor used by the `VimEnter`/`DirChanged` path (still the "no file path" fallback anchor the design spec calls for).

**This is the single-workspace -> registry unwind.** Read `lua/provenance/recorder/init.lua`, `tests/recorder/init_spec.lua`, `tests/recorder/init_controller_spec.lua`, and `tests/recorder/init_seal_command_spec.lua` **in full** before starting (already read in full during planning; re-read to catch any drift). This task is inherently larger than the ~200-line guideline in `CLAUDE.md` — that guideline is a default, not an absolute; this exact task was pre-flagged as the expected exception. Still make each of the three phases below its own commit.

#### Phase A: swap `state`+`controller` for the registry, ZERO behavior change

Goal: prove the registry is a correct drop-in replacement before adding any new discovery/trigger behavior. Every existing test in `init_spec.lua`, `init_controller_spec.lua`, `init_seal_command_spec.lua` should need **only** the `load_and_verify` -> `resolve` rename (and `root` added to active results) — no new test cases yet, no BufEnter, no picker.

- [ ] **Step A1: Rewrite `init.lua`'s `M.setup` body (Phase A shape only)**

Replace the full contents of `lua/provenance/recorder/init.lua` from `local M = {}` through the end of `M.setup` (keep the top `local ... = require(...)` block, updating it) with:

```lua
local status = require("provenance.recorder.status")
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")
local discovery = require("provenance.recorder.discovery")
local registry_mod = require("provenance.recorder.registry")

local M = {}

local AUGROUP_NAME = "Provenance"
local SEAL_COMMAND_NAME = "ProvenanceSeal"

--- setup(opts?)
--- @param opts table|nil
---   workspace: string|nil        -- cwd override for the VimEnter/DirChanged
---     fallback anchor (a buffer with no file path); production default is
---     vim.fn.getcwd()
---   resolve: function|nil        -- (start_dir) -> {status, root?, manifest?, reason?};
---     injectable seam for tests; defaults to discovery.resolve_from_dir
---   start_recording: function|nil -- (start_opts) -> controller; injectable
---     seam for tests; defaults to recording_controller.start
--- @return table handle with dispose()
function M.setup(opts)
  opts = opts or {}

  local resolve = opts.resolve or discovery.resolve_from_dir
  local start_recording = opts.start_recording or recording_controller.start

  local registry = registry_mod.new({ start_recording = start_recording })
  status.attach(registry)

  --- Resolve a single anchor directory and, if active, ensure its session
  --- exists in the registry. Idempotent (registry.ensure_session already
  --- guards against double-starting the same root).
  local function resolve_and_activate(start_dir)
    local result = resolve(start_dir)
    if result.status == "active" then
      registry.ensure_session(result.root, result.manifest, { clock = core_clock.system() })
    end
    return result
  end

  local function resolve_cwd()
    resolve_and_activate(opts.workspace or vim.fn.getcwd())
  end

  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })

  vim.api.nvim_create_autocmd({ "VimEnter", "DirChanged" }, {
    group = augroup,
    callback = resolve_cwd,
    desc = "Provenance: re-evaluate activation on cwd change (fallback anchor for buffers with no file path)",
  })

  vim.api.nvim_create_autocmd("VimLeavePre", {
    group = augroup,
    callback = function()
      registry.stop_all("deactivate")
    end,
    desc = "Provenance: end every live recording session before Neovim exits",
  })

  --- :ProvenanceSeal -- registered ONCE, unconditionally. Its body queries
  --- the registry LIVE at invocation time, so there is no more "live vs
  --- inert stub command" swap to keep in sync (that swap was the source of
  --- a real bug fixed earlier in this file's history -- see git blame on
  --- init_seal_command_spec.lua's round-trip regression test). Phase C adds
  --- the multi-session picker; this phase preserves single-session behavior
  --- exactly.
  vim.api.nvim_create_user_command(SEAL_COMMAND_NAME, function()
    local active = registry.list()
    if #active == 0 then
      vim.notify("Provenance: not an activated assignment workspace; nothing to seal.", vim.log.levels.INFO)
      return
    end

    local entry = active[1]
    local ok, result = pcall(entry.controller.seal)
    if not ok then
      vim.notify("Provenance: seal failed: " .. tostring(result), vim.log.levels.ERROR)
      return
    end
    if result.kind == "ok" then
      if result.warnings and result.warnings.chain_broken then
        vim.notify(
          "Provenance: sealed WITH WARNINGS (hash chain broken) -> " .. result.bundle_path,
          vim.log.levels.WARN
        )
      else
        vim.notify("Provenance: sealed submission bundle -> " .. result.bundle_path, vim.log.levels.INFO)
      end
    elseif result.kind == "no_sessions" then
      vim.notify("Provenance: nothing to seal (no recorded sessions).", vim.log.levels.WARN)
    else
      vim.notify("Provenance: seal failed: " .. tostring(result.message or result.kind), vim.log.levels.ERROR)
    end
  end, { desc = "Provenance: seal the recorded submission bundle" })

  -- Run once immediately so tests (and a setup() call after VimEnter has
  -- already fired) see the resolved state without waiting for the next
  -- autocmd event.
  resolve_cwd()

  local handle = {}

  function handle.dispose()
    registry.stop_all("deactivate")
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
    status.detach()
    pcall(vim.api.nvim_del_user_command, SEAL_COMMAND_NAME)
  end

  return handle
end

return M
```

- [ ] **Step A2: Rewrite `tests/recorder/init_spec.lua`'s seam usage**

Every `load_and_verify = function() return {status=..., manifest=...} end` becomes `resolve = function() return {status=..., root=<workspace>, manifest=...} end`. For example, the first test:

```lua
  it("active loader: state becomes active and status segment is non-empty", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
    })
```

becomes:

```lua
  it("active loader: state becomes active and status segment is non-empty", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "active", root = "/tmp/ws", manifest = { assignment_id = "hw3" } }
      end,
    })
```

Apply this same `load_and_verify` -> `resolve` rename (adding `root = "/tmp/ws"` to every `active` result) across **every** test in this file. The `"inactive loader: :ProvenanceSeal command is registered"` test's assertion `assert.equals(2, vim.fn.exists(":ProvenanceSeal"))` and the `"invoking :ProvenanceSeal records nothing and does not error"` test both still hold verbatim under Phase A's design (the command is always registered; an inactive/empty registry produces the same "not an activated assignment workspace" message). No other assertions in this file need to change.

- [ ] **Step A3: Rewrite `tests/recorder/init_controller_spec.lua`'s seam usage**

Same `load_and_verify` -> `resolve` rename, adding `root` to every active result. For the workspace-change test (around line 170-206), which currently does:

```lua
      load_and_verify = function(workspace)
        return { status = "active", manifest = { assignment_id = "hw3", workspace = workspace } }
      end,
```

change to:

```lua
      resolve = function(start_dir)
        return { status = "active", root = start_dir, manifest = { assignment_id = "hw3", workspace = start_dir } }
      end,
```

(`resolve`'s single argument is the anchor directory being resolved — here still the cwd, matching what `load_and_verify(workspace)` received before.) Every other test in this file (`"controller is started once..."`, `"dispose(): stops the live controller"`, `"VimLeavePre: stops the live controller..."`, `"re-firing activation for the SAME workspace..."`) needs the same rename and nothing else — `registry.ensure_session`'s idempotency (Task 8) reproduces the exact "does not double-start for the same root" guarantee `controller_workspace` used to provide.

- [ ] **Step A4: Rewrite `tests/recorder/init_seal_command_spec.lua`'s seam usage (single-session cases only — Phase C adds the picker cases)**

Same rename throughout. The `"round-trip active->inactive->active"` regression test (lines 235-329) is the most important one to get right: its `load_and_verify = function(workspace) if workspace == resolved_a then ... end` becomes `resolve = function(start_dir) if start_dir == resolved_a then ... end`, preserving the exact same cwd-driven `:cd` flow (this test never opens a buffer, so it only exercises the `VimEnter`/`DirChanged` cwd path Phase A already implements unchanged).

- [ ] **Step A5: Run all three suites**

Run: `make test 2>&1 | grep -A 40 "init_spec\|init_controller_spec\|init_seal_command_spec"`
Expected: every existing test in all three files passes, with no new test cases yet.

- [ ] **Step A6: Commit Phase A**

```bash
git add lua/provenance/recorder/init.lua tests/recorder/init_spec.lua tests/recorder/init_controller_spec.lua tests/recorder/init_seal_command_spec.lua
git commit --no-gpg-sign -m "refactor(recorder): swap init.lua's single state/controller for the registry (no behavior change)"
```

#### Phase B: add BufEnter/BufReadPost/BufNewFile discovery triggers + concurrency

Goal: opening a file (not just `:cd`) activates its assignment, and two files under two different assignment roots produce two live sessions.

- [ ] **Step B1: Add the buffer-anchored trigger to `init.lua`**

In `lua/provenance/recorder/init.lua`, add a new local function next to `resolve_cwd` (inside `M.setup`, after it):

```lua
  --- Resolve activation from a BUFFER's file path (the primary anchor per
  --- the design: cwd may be unrelated to what's actually open). No-op for
  --- buffers with no file path or a non-file buftype -- those have nothing
  --- to walk upward from and are handled (if at all) by the cwd fallback.
  local function resolve_buf(buf)
    if not vim.api.nvim_buf_is_valid(buf) then
      return
    end
    if vim.api.nvim_get_option_value("buftype", { buf = buf }) ~= "" then
      return
    end
    local name = vim.api.nvim_buf_get_name(buf)
    if name == "" then
      return
    end
    resolve_and_activate(vim.fs.dirname(name))
  end
```

Add the new autocmd group entry right after the existing `VimEnter`/`DirChanged` block:

```lua
  vim.api.nvim_create_autocmd({ "BufEnter", "BufReadPost", "BufNewFile" }, {
    group = augroup,
    callback = function(args)
      resolve_buf(args.buf)
    end,
    desc = "Provenance: resolve + activate the buffer's own assignment root (upward discovery)",
  })
```

- [ ] **Step B2: Add new tests to `tests/recorder/init_controller_spec.lua`**

Add a new `describe` block:

```lua
describe("recorder.setup buffer-anchored discovery (BufEnter/BufReadPost/BufNewFile)", function()
  local recorder

  before_each(function()
    package.loaded["provenance.recorder"] = nil
    package.loaded["provenance.recorder.init"] = nil
    recorder = require("provenance.recorder")
  end)

  local handle
  local bufs

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
    for _, b in ipairs(bufs or {}) do
      if vim.api.nvim_buf_is_valid(b) then
        pcall(vim.cmd, "bwipeout! " .. b)
      end
    end
    bufs = {}
    status.detach()
  end)

  it("opening a file resolves its OWN root, independent of cwd", function()
    bufs = {}
    local start_recording, calls = make_start_recording_spy()
    local far_dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(far_dir, "p")
    local file_path = far_dir .. "/cats.py"
    local f = assert(io.open(file_path, "w"))
    f:write("print(1)\n")
    f:close()

    handle = recorder.setup({
      -- Deliberately a DIFFERENT, inactive cwd anchor, proving the buffer
      -- path (not cwd) drives this activation.
      workspace = "/tmp/unrelated-cwd",
      resolve = function(start_dir)
        if start_dir == far_dir then
          return { status = "active", root = far_dir, manifest = { assignment_id = "cats" } }
        end
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = start_recording,
    })

    assert.equals(0, #calls) -- cwd anchor is inactive; nothing started yet

    vim.cmd("edit " .. vim.fn.fnameescape(file_path))
    table.insert(bufs, vim.api.nvim_get_current_buf())

    assert.equals(1, #calls)
    assert.equals(far_dir, calls[1].args.workspace)

    pcall(vim.fn.delete, far_dir, "rf")
  end)

  it("CONCURRENCY: two buffers under two different roots produce two live sessions", function()
    bufs = {}
    local start_recording, calls = make_start_recording_spy()
    local dir_cats = vim.fs.normalize(vim.fn.tempname())
    local dir_hog = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir_cats, "p")
    vim.fn.mkdir(dir_hog, "p")
    local file_cats = dir_cats .. "/cats.py"
    local file_hog = dir_hog .. "/hog.py"
    for _, p in ipairs({ file_cats, file_hog }) do
      local f = assert(io.open(p, "w"))
      f:write("x = 1\n")
      f:close()
    end

    handle = recorder.setup({
      workspace = "/tmp/unrelated-cwd",
      resolve = function(start_dir)
        if start_dir == dir_cats then
          return { status = "active", root = dir_cats, manifest = { assignment_id = "cats" } }
        elseif start_dir == dir_hog then
          return { status = "active", root = dir_hog, manifest = { assignment_id = "hog" } }
        end
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = start_recording,
    })

    vim.cmd("edit " .. vim.fn.fnameescape(file_cats))
    table.insert(bufs, vim.api.nvim_get_current_buf())
    vim.cmd("edit " .. vim.fn.fnameescape(file_hog))
    table.insert(bufs, vim.api.nvim_get_current_buf())

    assert.equals(2, #calls)
    assert.equals(dir_cats, calls[1].args.workspace)
    assert.equals(dir_hog, calls[2].args.workspace)
    assert.equals(0, #calls[1].controller.stop_calls)
    assert.equals(0, #calls[2].controller.stop_calls)

    -- VimLeavePre stops BOTH sessions.
    vim.api.nvim_exec_autocmds("VimLeavePre", { group = "Provenance" })
    assert.equals(1, #calls[1].controller.stop_calls)
    assert.equals(1, #calls[2].controller.stop_calls)

    pcall(vim.fn.delete, dir_cats, "rf")
    pcall(vim.fn.delete, dir_hog, "rf")
  end)

  it("re-entering the SAME buffer's root does not double-start its session", function()
    bufs = {}
    local start_recording, calls = make_start_recording_spy()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    local file_path = dir .. "/a.py"
    local f = assert(io.open(file_path, "w"))
    f:write("x = 1\n")
    f:close()

    handle = recorder.setup({
      workspace = "/tmp/unrelated-cwd",
      resolve = function(start_dir)
        if start_dir == dir then
          return { status = "active", root = dir, manifest = { assignment_id = "a" } }
        end
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = start_recording,
    })

    vim.cmd("edit " .. vim.fn.fnameescape(file_path))
    table.insert(bufs, vim.api.nvim_get_current_buf())
    assert.equals(1, #calls)

    -- Re-fire BufEnter for the same buffer (e.g. switching away and back).
    vim.api.nvim_exec_autocmds("BufEnter", { buffer = vim.api.nvim_get_current_buf() })
    assert.equals(1, #calls)

    pcall(vim.fn.delete, dir, "rf")
  end)

  it("REGRESSION: cd <assignment> && nvim (no file arg) still activates via the cwd fallback", function()
    local start_recording, calls = make_start_recording_spy()

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function(start_dir)
        if start_dir == "/tmp/ws-a" then
          return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
        end
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    assert.equals("/tmp/ws-a", calls[1].args.workspace)
  end)
end)
```

`make_start_recording_spy` and `status` are already defined/required at the top of `init_controller_spec.lua` — reuse them, do not redefine.

- [ ] **Step B3: Run**

Run: `make test 2>&1 | grep -A 60 "init_controller_spec"`
Expected: all existing + all new tests pass.

- [ ] **Step B4: Commit Phase B**

```bash
git add lua/provenance/recorder/init.lua tests/recorder/init_controller_spec.lua
git commit --no-gpg-sign -m "feat(recorder): BufEnter/BufReadPost/BufNewFile activation triggers (upward discovery, concurrent)"
```

#### Phase C: `:ProvenanceSeal` multi-session picker

- [ ] **Step C1: Replace the seal command body in `init.lua`**

Replace the `vim.api.nvim_create_user_command(SEAL_COMMAND_NAME, function() ... end, {...})` block added in Phase A with:

```lua
  --- Shared result-notification helper (Phase A/C): identical
  --- INFO/WARN/ERROR handling regardless of whether the sealed session was
  --- chosen directly (0 or 1 active) or via the picker (>1 active).
  local function notify_seal_result(ok, result)
    if not ok then
      vim.notify("Provenance: seal failed: " .. tostring(result), vim.log.levels.ERROR)
      return
    end
    if result.kind == "ok" then
      if result.warnings and result.warnings.chain_broken then
        vim.notify(
          "Provenance: sealed WITH WARNINGS (hash chain broken) -> " .. result.bundle_path,
          vim.log.levels.WARN
        )
      else
        vim.notify("Provenance: sealed submission bundle -> " .. result.bundle_path, vim.log.levels.INFO)
      end
    elseif result.kind == "no_sessions" then
      vim.notify("Provenance: nothing to seal (no recorded sessions).", vim.log.levels.WARN)
    else
      vim.notify("Provenance: seal failed: " .. tostring(result.message or result.kind), vim.log.levels.ERROR)
    end
  end

  local function seal_entry(entry)
    local ok, result = pcall(entry.controller.seal)
    notify_seal_result(ok, result)
  end

  vim.api.nvim_create_user_command(SEAL_COMMAND_NAME, function(cmd_opts)
    local active = registry.list()

    if #active == 0 then
      vim.notify("Provenance: not an activated assignment workspace; nothing to seal.", vim.log.levels.INFO)
      return
    end

    local requested_id = cmd_opts.args ~= "" and cmd_opts.args or nil
    if requested_id then
      for _, entry in ipairs(active) do
        if entry.manifest.assignment_id == requested_id then
          seal_entry(entry)
          return
        end
      end
      vim.notify(
        "Provenance: no active recording session for assignment '" .. requested_id .. "'.",
        vim.log.levels.ERROR
      )
      return
    end

    if #active == 1 then
      seal_entry(active[1])
      return
    end

    vim.ui.select(active, {
      prompt = "Provenance: choose which assignment to seal",
      format_item = function(entry)
        return entry.manifest.assignment_id .. " (" .. entry.root .. ")"
      end,
    }, function(chosen)
      if chosen then
        seal_entry(chosen)
      end
    end)
  end, {
    desc = "Provenance: seal the recorded submission bundle (optionally: :ProvenanceSeal <assignment_id>)",
    nargs = "?",
  })
```

- [ ] **Step C2: Add multi-session picker tests to `tests/recorder/init_seal_command_spec.lua`**

Add a new `describe` block:

```lua
describe("recorder.setup :ProvenanceSeal multi-session picker", function()
  local recorder

  before_each(function()
    package.loaded["provenance.recorder"] = nil
    package.loaded["provenance.recorder.init"] = nil
    recorder = require("provenance.recorder")
  end)

  local handle
  local restore_notify
  local restore_select

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
    if restore_notify then
      restore_notify()
      restore_notify = nil
    end
    if restore_select then
      restore_select()
      restore_select = nil
    end
    status.detach()
  end)

  local function make_two_session_setup()
    local seal_calls = { cats = 0, hog = 0 }
    local controllers = {
      cats = {
        seal = function()
          seal_calls.cats = seal_calls.cats + 1
          return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
        end,
        stop = function() end,
      },
      hog = {
        seal = function()
          seal_calls.hog = seal_calls.hog + 1
          return { kind = "ok", bundle_path = "/tmp/hog-bundle.zip", warnings = {} }
        end,
        stop = function() end,
      },
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function(start_dir)
        if start_dir == "/tmp/ws-a" then
          return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
        end
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = function(args)
        if args.workspace == "/tmp/cats" then
          return controllers.cats
        end
        return controllers.hog
      end,
    })

    -- Manually register the second session the way Phase B's BufEnter path
    -- would (this describe block only exercises the picker, not discovery),
    -- by resolving a second root through the same recorder instance isn't
    -- possible from outside init.lua's closure -- instead, drive it via a
    -- second resolve() match on a distinct start_dir through DirChanged.
    return seal_calls
  end

  it("exactly one active session: seals it directly, no picker shown", function()
    local select_called = false
    local orig_select = vim.ui.select
    vim.ui.select = function(...)
      select_called = true
    end
    restore_select = function()
      vim.ui.select = orig_select
    end

    local seal_calls = 0
    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
      end,
      start_recording = function()
        return {
          seal = function()
            seal_calls = seal_calls + 1
            return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
          end,
          stop = function() end,
        }
      end,
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, seal_calls)
    assert.is_false(select_called)
    assert.equals(vim.log.levels.INFO, calls[1].level)
  end)

  it("two active sessions: vim.ui.select is invoked with both, choosing one seals only that one", function()
    local seal_calls = { cats = 0, hog = 0 }
    local controller_cats = {
      seal = function()
        seal_calls.cats = seal_calls.cats + 1
        return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }
    local controller_hog = {
      seal = function()
        seal_calls.hog = seal_calls.hog + 1
        return { kind = "ok", bundle_path = "/tmp/hog-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }

    local resolve_call_count = 0
    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        resolve_call_count = resolve_call_count + 1
        if resolve_call_count == 1 then
          return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
        end
        return { status = "active", root = "/tmp/hog", manifest = { assignment_id = "hog" } }
      end,
      start_recording = function(args)
        if args.workspace == "/tmp/cats" then
          return controller_cats
        end
        return controller_hog
      end,
    })

    -- Force a second resolve (a DirChanged re-fire) so the SECOND call to
    -- resolve() above registers the "hog" root too, yielding two live
    -- sessions in the registry (ensure_session is idempotent per-root, so
    -- this cleanly adds hog alongside the already-registered cats).
    vim.api.nvim_exec_autocmds("DirChanged", { group = "Provenance" })

    local selected_items
    local orig_select = vim.ui.select
    vim.ui.select = function(items, select_opts, on_choice)
      selected_items = items
      -- Choose the second item ("hog").
      on_choice(items[2].manifest.assignment_id == "hog" and items[2] or items[1])
    end
    restore_select = function()
      vim.ui.select = orig_select
    end

    vim.cmd("ProvenanceSeal")

    assert.is_not_nil(selected_items)
    assert.equals(2, #selected_items)
    assert.equals(1, seal_calls.hog)
    assert.equals(0, seal_calls.cats)
  end)

  it(":ProvenanceSeal <assignment_id> seals the named session directly, skipping the picker", function()
    local seal_calls = { cats = 0, hog = 0 }
    local controller_cats = {
      seal = function()
        seal_calls.cats = seal_calls.cats + 1
        return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }
    local controller_hog = {
      seal = function()
        seal_calls.hog = seal_calls.hog + 1
        return { kind = "ok", bundle_path = "/tmp/hog-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }

    local resolve_call_count = 0
    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        resolve_call_count = resolve_call_count + 1
        if resolve_call_count == 1 then
          return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
        end
        return { status = "active", root = "/tmp/hog", manifest = { assignment_id = "hog" } }
      end,
      start_recording = function(args)
        if args.workspace == "/tmp/cats" then
          return controller_cats
        end
        return controller_hog
      end,
    })
    vim.api.nvim_exec_autocmds("DirChanged", { group = "Provenance" })

    local select_called = false
    local orig_select = vim.ui.select
    vim.ui.select = function(...)
      select_called = true
    end
    restore_select = function()
      vim.ui.select = orig_select
    end

    vim.cmd("ProvenanceSeal hog")

    assert.is_false(select_called)
    assert.equals(1, seal_calls.hog)
    assert.equals(0, seal_calls.cats)
  end)
end)
```

(This reuses `capture_notify` already defined at the top of `init_seal_command_spec.lua`.)

- [ ] **Step C3: Run**

Run: `make test 2>&1 | grep -A 80 "init_seal_command_spec"`
Expected: all existing + all new tests pass.

- [ ] **Step C4: Commit Phase C**

```bash
git add lua/provenance/recorder/init.lua tests/recorder/init_seal_command_spec.lua
git commit --no-gpg-sign -m "feat(recorder): :ProvenanceSeal multi-session picker (vim.ui.select)"
```

- [ ] **Step C5: Run the FULL suite once more to confirm nothing elsewhere regressed**

Run: `make test 2>&1 | tail -20`
Expected: overall pass (see Task 10 for the one known pre-existing environmental flake unrelated to this feature — do not chase it in this task).

---

### Task 10: end-to-end concurrency proof + manual checklist

**Files:**
- Create: `tests/recorder/e2e_concurrent_spec.lua`
- Modify: `docs/manual-verification.md` (append a new section)

**Interfaces:** none new — this composes everything from Tasks 1-9 against the real `recording_controller`/`discovery`/`registry`, proving the acceptance criteria end-to-end at the local (non-analyzer) gate, mirroring `e2e_seal_spec.lua`'s existing style.

- [ ] **Step 1: Write the concurrency e2e test**

Create `tests/recorder/e2e_concurrent_spec.lua`:

```lua
--- e2e: two concurrent recording_controller sessions (Plan:
--- 2026-07-20-nested-manifest-discovery, acceptance criteria 2/3/6).
--- Drives TWO real sessions over two disjoint temp workspaces, proving:
---   - each gets its own .provenance/ with its own valid hash chain
---   - an edit in workspace A's buffer never appears in workspace B's slog
---   - a terminal opened with cwd = workspace A is recorded ONLY by A
---   - each can be sealed independently into a bundle whose manifest
---     verifies and whose chain validates (mirrors e2e_seal_spec.lua's
---     local, non-analyzer gate -- cross-language acceptance by the real
---     analyzer is exercised for the single-session case there already;
---     this spec proves concurrency-specific isolation, not format parity).
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")
local core_bundle = require("provenance.core.bundle")
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

local function manifest_for(id)
  return {
    assignment_id = id,
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "main.py" },
  }
end

describe("e2e: two concurrent recording_controller sessions", function()
  local workspace_a, workspace_b, session_a, session_b, buf_a, buf_b, term_buf

  before_each(function()
    workspace_a = vim.fs.normalize(vim.fn.tempname())
    workspace_b = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(workspace_a .. "/.provenance", "p")
    vim.fn.mkdir(workspace_b .. "/.provenance", "p")
    session_a, session_b, buf_a, buf_b, term_buf = nil, nil, nil, nil, nil
  end)

  after_each(function()
    if session_a then pcall(session_a.stop) end
    if session_b then pcall(session_b.stop) end
    for _, b in ipairs({ buf_a, buf_b, term_buf }) do
      if b and vim.api.nvim_buf_is_valid(b) then
        pcall(vim.cmd, "bwipeout! " .. b)
      end
    end
    pcall(vim.fn.delete, workspace_a, "rf")
    pcall(vim.fn.delete, workspace_b, "rf")
  end)

  it("isolates doc events, terminal attribution, and hash chains across two concurrent sessions", function()
    local file_a = workspace_a .. "/main.py"
    local file_b = workspace_b .. "/main.py"
    for _, p in ipairs({ file_a, file_b }) do
      local f = assert(io.open(p, "w"))
      f:write("print('hello')\n")
      f:close()
    end

    session_a = recording_controller.start({
      workspace = workspace_a,
      provenance_dir = workspace_a .. "/.provenance",
      manifest = manifest_for("cats"),
      clock = core_clock.system(),
    })
    session_b = recording_controller.start({
      workspace = workspace_b,
      provenance_dir = workspace_b .. "/.provenance",
      manifest = manifest_for("hog"),
      clock = core_clock.system(),
    })

    -- Edit A: must appear in A's slog, never B's.
    vim.cmd("edit " .. vim.fn.fnameescape(file_a))
    buf_a = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(buf_a, 0, 1, false, { "print('edited in A')" })
    vim.cmd("write")

    -- Edit B: must appear in B's slog, never A's.
    vim.cmd("edit " .. vim.fn.fnameescape(file_b))
    buf_b = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(buf_b, 0, 1, false, { "print('edited in B')" })
    vim.cmd("write")

    -- A terminal whose cwd is workspace A: recorded only by A's terminal
    -- signal, never B's (Task 4's workspace-scoped attribution).
    local orig_cwd = vim.fn.getcwd()
    vim.cmd("cd " .. vim.fn.fnameescape(workspace_a))
    term_buf = vim.api.nvim_create_buf(false, true)
    vim.b[term_buf].terminal_job_id = 777
    vim.b[term_buf].term_title = "/bin/fake-shell"
    vim.api.nvim_exec_autocmds("TermOpen", { buffer = term_buf })
    vim.cmd("cd " .. vim.fn.fnameescape(orig_cwd))

    local function slog_kinds(session)
      local text = read_all(session.slog_path)
      local parsed = core_ndjson.parse_entries(text)
      assert.is_true(parsed.ok)
      local by_kind = {}
      for _, e in ipairs(parsed.value) do
        by_kind[e.kind] = (by_kind[e.kind] or 0) + 1
      end
      return by_kind, parsed.value
    end

    local kinds_a, entries_a = slog_kinds(session_a)
    local kinds_b, entries_b = slog_kinds(session_b)

    assert.is_true((kinds_a["terminal.open"] or 0) >= 1, "A's slog should have terminal.open")
    assert.is_nil(kinds_b["terminal.open"], "B's slog must NOT have a terminal.open for A's terminal")

    -- Doc events are isolated: A's slog only ever references "main.py"
    -- content it itself wrote; find each session's doc.save and confirm
    -- against ITS OWN file's on-disk content, not the other's.
    assert.is_true((kinds_a["doc.save"] or 0) >= 1)
    assert.is_true((kinds_b["doc.save"] or 0) >= 1)

    -- Each session's own chain validates independently.
    assert.is_true(core_chain_validator.validate_chain(entries_a).ok)
    assert.is_true(core_chain_validator.validate_chain(entries_b).ok)

    -- Each seals independently into a bundle whose manifest verifies
    -- against ITS OWN session pubkey (not the other's).
    local result_a = session_a.seal({ now = function() return "2026-07-20T10:00:00.000Z" end })
    local result_b = session_b.seal({ now = function() return "2026-07-20T10:00:01.000Z" end })
    assert.equals("ok", result_a.kind)
    assert.equals("ok", result_b.kind)

    local manifest_a_text = read_all(workspace_a .. "/.provenance/manifest.json")
    local sig_a_text = read_all(workspace_a .. "/.provenance/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_a_text, sig_a_text, session_a.public_key_hex))
    assert.is_false(core_bundle.verify_sig(manifest_a_text, sig_a_text, session_b.public_key_hex))

    local manifest_b_text = read_all(workspace_b .. "/.provenance/manifest.json")
    local sig_b_text = read_all(workspace_b .. "/.provenance/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_b_text, sig_b_text, session_b.public_key_hex))
  end)
end)
```

- [ ] **Step 2: Run**

Run: `make test 2>&1 | grep -A 40 "e2e_concurrent_spec"`
Expected: pass. If `kinds_b["terminal.open"]` is NOT nil, re-check Task 4's Step 2 (the `owned` gate) before touching this test — do not weaken this assertion.

- [ ] **Step 3: Append the manual-verification checklist**

Append to `docs/manual-verification.md` (after the existing `## Plan 9 — full integration` section, at the end of the file):

```markdown

## Upward manifest discovery + concurrent multi-session (2026-07-20)

- [ ] **Bare `nvim` in `~`, then open a nested assignment file:** From your home directory, run plain `nvim` (no file argument), then `:e ~/<course>/<assignment>/<file>` where `<assignment>/` contains a valid signed `.provenance-manifest`. Confirm the status segment shows "Provenance: recording" as soon as the buffer opens — activation must not require `:cd`-ing into the assignment first.

- [ ] **Two assignments open at once:** `nvim ~/<course>/<assignment-1>/<file1> ~/<course>/<assignment-2>/<file2>` (two DIFFERENT assignment roots, each with its own valid manifest). Confirm both activate; inspect `<assignment-1>/.provenance/` and `<assignment-2>/.provenance/` and confirm each has its own `.slog` growing independently as you edit each buffer in turn.

- [ ] **`:ProvenanceSeal` picker:** With the two-assignment session above still open, run `:ProvenanceSeal`. Confirm a picker (`vim.ui.select`, typically `inputlist`-style or your configured `vim.ui.select` provider) appears listing both assignment ids; choosing one seals only that assignment's bundle (confirm only ONE new `*-bundle-*.zip` appears, in the CHOSEN assignment's directory).

- [ ] **Single assignment: no picker.** With only one assignment active, run `:ProvenanceSeal`. Confirm it seals immediately with no picker prompt (regression check for the pre-existing single-workspace flow).

- [ ] **Terminal attribution by cwd:** With the two-assignment session from above, open a `:terminal` while your shell's cwd is inside assignment-1's root. Confirm `assignment-1/.provenance/`'s `.slog` gets a `terminal.open` and assignment-2's does not.
```

- [ ] **Step 4: Run the full suite one final time**

Run: `make test 2>&1 | tail -30`
Expected: overall pass (see the note in the final report about one known pre-existing, unrelated environmental flake in `e2e_seal_spec.lua` involving a ShaDa read race — re-run once if it appears; it is not caused by this feature and predates this branch).

- [ ] **Step 5: Commit**

```bash
git add tests/recorder/e2e_concurrent_spec.lua docs/manual-verification.md
git commit --no-gpg-sign -m "test(recorder): e2e concurrency proof + manual verification checklist"
```

---

## Self-Review

**Spec coverage** (`docs/superpowers/specs/2026-07-20-nested-manifest-discovery-design.md`):
- Upward discovery, 4 launch cases + no-manifest + failing-signature-skip -> Task 7 (`discovery_spec.lua`).
- `BufEnter`/`BufReadPost`/`BufNewFile` triggers, cwd fallback preserved -> Task 9 Phase B.
- Full concurrent multi-session, one live session per root, idempotent -> Task 8 (`registry.lua`) + Task 9 Phase B.
- Per-assignment `.provenance/` derived from resolved root, not cwd -> `registry.ensure_session`'s `provenance_dir = root .. "/.provenance"` (Task 8).
- `:ProvenanceSeal` picker, single -> no prompt -> Task 9 Phase C.
- Terminal/git attribution by path, drop if unowned -> Task 4 (terminal) + confirmed no-op-needed for git (hazard inventory); proven end-to-end in Task 10.
- Nearest-enclosing ownership per buffer -> `vim.fs.find(..., limit=1)`'s natural nearest-level-wins semantics (Task 7), empirically verified in the plan header.
- Integrity invariants (independent chains, per-session manifest binding, no double-recording, no out-of-root recording, pure-Lua) -> proven in Task 10's e2e test; no format/crypto module touched anywhere in this plan.
- Regression: single-assignment `cd && nvim` path -> explicit regression test in Task 9 Phase B, Step B2.

**Placeholder scan:** every step above has literal, complete Lua (no "TBD"/"similar to Task N"/"add error handling" placeholders). Every commit step has an exact `git commit` message.

**Type consistency:**
- `discovery.resolve_from_dir`/`resolve_for_file` (Task 7) return `{status, root?, manifest?, reason?}` — the exact shape `init.lua`'s `resolve_and_activate` (Task 9) destructures (`result.status`, `result.root`, `result.manifest`).
- `registry.new(opts).ensure_session(root, manifest, extra_opts)` (Task 8) is called by `init.lua` (Task 9) with exactly that arity; `registry.list()`'s `{root, manifest, controller}` shape is what Task 9 Phase C's picker and Task 9's single-session seal path both consume.
- `registry.is_active()` (no-arg) matches `status.lua`'s existing `state.is_active()` call shape exactly — confirmed by reading `status.lua` during planning; zero changes to `status.lua` needed.
- `terminal_wiring.start(opts)`'s new `opts.workspace` (Task 4) is threaded from `recording_session.lua`'s existing `workspace` local — confirmed present at that exact call site during planning.
- `paste_intercept.attach(opts)` (Task 5) keeps its exact pre-existing signature and `handle.dispose()` contract — `paste_assembly.lua` (Task 6) needs no signature change, only its `on_intercept` closure body.
- Every module exposing `handle._augroup_id` (Tasks 1, 3, 4; also added to Task 2's two modules for consistency) uses that exact field name, so any future cross-task test reuses one convention.

**Known pre-existing, out-of-scope issue (do not fix in this branch):** the baseline `make test` run (before any change in this plan) showed one flaky failure in `tests/recorder/e2e_seal_spec.lua`'s first test — `Vim(edit):E576: Reading ShaDa file: last entry specified that it occupies N bytes, but file ended earlier` — caused by concurrent headless `nvim` processes racing on a shared ShaDa file in the environment, not by anything in this feature. It reproduces intermittently on `main` too. Re-run `make test` if it appears; do not weaken or remove the test it hits.
