# External-Change Detection (Plan 5 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Detect edits to watched files made **outside** the editor's tracked changes (formatters, git, `cp`, an AI CLI writing the file) and emit exactly one `fs.external_change` per external write, driven by the expected-content model. This is design.md §5's **highest-risk** item because Neovim learns about on-disk changes *lazily* (on focus-gain or `:checktime`).

**Architecture:** An in-memory `ExpectedContent` per watched file (the sum of tracked `doc.change` since last save) is the source of truth; a detector compares the **on-disk hash** against the **expected hash** — disk ≠ expected ⇒ external. Three emission paths, all producing one uniform `fs.external_change`: (1) save-time hash check (`BufWritePost`), (2) a `vim.uv.fs_event`/`fs_poll` watcher over `files_under_review` (catches writes while unfocused/closed), and (3) the reload-from-disk path (`FileChangedShellPost` after `autoread`/`:checktime`). Pure-logic-first; the lazy-notification timing is isolated and driven with `autoread` + `:checktime` in tests.

**Tech Stack:** Lua, `vim.uv.fs_event`/`fs_poll`, `FileChangedShell`/`FileChangedShellPost` autocmds, `autoread`, `vim.fn.sha256`, plenary. Builds on Plan 4's doc-wiring + emit.

## Global Constraints

(Inherits Plans 1–4.) Additional:

- **Direction is the trap (PRD §4.5, CLAUDE.md).** The expected-content model is what the editor *believes* it wrote; the on-disk hash is what's actually there. `external_change` = `sha256(on_disk) ≠ expected.hash`. `old_hash = expected.hash`, `new_hash = sha256(on_disk)`. Getting old/new backwards is the classic bug — pin it with an explicit direction regression test.
- **Neovim's awareness is lazy.** `FileChangedShell` fires on focus-gain or `:checktime`, not at write time. The `vim.uv` file watcher (path 2) is what catches out-of-focus writes promptly; tests drive the lazy path with `autoread=true` + `vim.cmd("checktime")`.
- **Exactly one event per external write.** The three paths must not double-emit. The `vim.uv` watcher suppresses the just-happened editor save (a short tolerance window, ~250ms, mirroring the VS Code watcher) so a normal `:w` does not masquerade as external.
- **The detector never mutates `ExpectedContent`.** The caller resets the model from disk *after* emitting, so subsequent tracked edits chain from reality.
- **Content fields:** `new_content_size` = UTF-8 bytes; inline `new_content` when `≤4096`, else `new_content_head`/`new_content_tail` = first/last 512 **chars**. `operation` = `create` (`old_hash=""`), `delete` (`new_hash=""`, no content), else `modify` (default). `explanation` = `formatter`/`git` when a benign op ran within the window (Plan 6/7 feed the tagger; here it is wired but usually empty).

### File structure

```
lua/provenance/recorder/
  state/expected_content.lua           -- offset model: content, line_count, hash, apply_delta, reset
  state/expected_content_registry.lua  -- path → ExpectedContent, scoped to files_under_review
  events/external_change_detector.lua  -- compare_saved_content (direction-critical, pure)
  events/external_change_content.lua   -- build_external_change_content (inline/truncate)
  events/explanation_tags.lua          -- ExplanationTagger (formatter/git window)
  watch/save_time_checker.lua          -- path 1: BufWritePost hash check
  watch/fs_watcher.lua                 -- path 2: vim.uv fs_event/fs_poll over watched files
  watch/reload_checker.lua             -- path 3: FileChangedShellPost
  watch/external_change_coordinator.lua-- owns registry + 3 paths, single dispose
tests/recorder/**/*_spec.lua
```

---

### Task 1: ExpectedContent + registry (offset model)

**Files:** Create `state/expected_content.lua`, `state/expected_content_registry.lua`; Tests for each.

**Interfaces:**
- `expected_content.new(initial) → ec` with `ec.content`, `ec.line_count` (`""`→0; no-newline→1; else newline count +1, trailing `\n` adds a line), `ec.hash` (memoized `sha256`, invalidated on mutate), `ec.apply_delta({range,text})` (offset splice; `\n`-only line counting; `character` clamped to line length), `ec.apply_deltas(list)`, `ec.reset(content)`.
- `registry.new(files_under_review)` with `is_watched(rel)`, `get_or_create(rel, initial)` (first construction wins), `get(rel)`, `delete(rel)`.

**Test intent:** `hash` pinned (`new("hello world").hash == b94d…cde9`); line_count edge cases (`"abc\n"`→2, `"\n\n"`→3); delta splice incl. char-beyond-line clamp and multi-line replacement; deletion (`text=""`); registry first-construction-wins + scope. **Gate:** spec green. **Commit:** `feat(recorder): expected-content model + registry`.

---

### Task 2: External-change content builder (inline/truncate)

**Files:** Create `events/external_change_content.lua`; Test + a cross-language fixture.

**Interfaces:** `build_external_change_content(text) → {new_content_size, new_content?/new_content_head?/new_content_tail?}` — size = UTF-8 bytes; ≤4096 → `new_content=text`; >4096 → head/tail 512 chars, omit `new_content`; empty → `{new_content="", new_content_size=0}`.

**Test intent:** short inline; >4096 truncated with head/tail; a multibyte-emoji case pinned byte-for-byte (generate a tiny Node vector against `external-change-content.ts` and commit it, mirroring provjet). **Gate:** spec green. **Commit:** `feat(recorder): external-change content builder`.

---

### Task 3: External-change detector (direction-critical, pure)

**Files:** Create `events/external_change_detector.lua`; Test `…_spec.lua`.

**Interfaces:** `compare_saved_content(expected_ec, on_disk_content) → {kind="clean_save", new_hash} | {kind="external_change", old_hash, new_hash, diff_size}`. `actual = sha256(on_disk)`; equal to `expected_ec.hash` → clean_save; else external_change with `old_hash=expected.hash`, `new_hash=actual`, `diff_size = abs(#on_disk_content - #expected.content)` (**char-length** difference, matching `external-change-detector.ts`). Does **not** mutate `expected`.

**Test intent:** typed-then-clean-save → `clean_save`; disk differs → `external_change` with **old=expected/new=disk** (explicit direction regression); non-mutation asserted; same-length-different-bytes → `diff_size=0` (documented limitation). **Gate:** spec green. **Commit:** `feat(recorder): external-change detector (direction-critical)`.

---

### Task 4: Explanation tagger (formatter/git window)

**Files:** Create `events/explanation_tags.lua`; Test.

**Interfaces:** `tagger.new({get_now, window_ms?=2000})` with `mark_formatter()`, `mark_git()`, `consume() → "formatter"|"git"|nil`. Single-slot (latest mark wins); consume-once; `now - at >= window_ms` → expired (returns nil). Feeds `fs.external_change.explanation`.

**Test intent:** within window returns kind; at 1999ms returns, at 2000ms nil; second consume nil; expired then new mark works. **Gate:** spec green. **Commit:** `feat(recorder): explanation tagger for external changes`.

---

### Task 5: Path 1 — save-time hash check

**Files:** Create `watch/save_time_checker.lua`; Test (headless, real buffers/files).

**Interfaces:** `save_time_checker.new({registry, emit, tagger}) → {check_after_save(rel, abs_path)}` — reads on-disk bytes (`vim.uv`), `compare_saved_content(registry.get(rel), disk)`; on `external_change` build the payload (add content fields via Task 2, `explanation` via `tagger.consume()`, `operation="modify"`), `emit("fs.external_change", data)`, then `registry.get(rel).reset(disk)`. Called from doc-wiring's `BufWritePost` **before** the `doc.save` emit. Never-opened file → no-op.

**Test intent:** typed-then-saved → no emit; overwrite the file on disk then save → emits with correct direction; never-opened file → no-op. **Gate:** spec green. **Commit:** `feat(recorder): save-time external-change path`.

---

### Task 6: Path 2 — `vim.uv` file watcher (the lazy-timing isolation)

**Files:** Create `watch/fs_watcher.lua`; Test (real temp dir, real writes).

**Interfaces:** `fs_watcher.start({registry, workspace, emit, tagger, recent_saves}) → handle` — for each watched file start a `vim.uv.fs_event` (fallback `fs_poll`) on its absolute path; on change, if the file was saved by the editor within the tolerance window (`recent_saves[rel]` set by path 1) skip; else read disk, `compare_saved_content`, emit + reset. Handles `create` (`old_hash=""`) / `delete` (`new_hash=""`, registry delete). `handle.dispose()` stops all watchers.

**Test intent:** external write (no editor save) emits once; an editor save within tolerance does **not** re-emit; create → `old_hash=""`; delete → `new_hash=""` + registry cleared; two rapid external writes → handled. **Gate:** spec green. **Commit:** `feat(recorder): vim.uv external-change watcher`.

---

### Task 7: Path 3 — reload-from-disk (`FileChangedShellPost`)

**Files:** Create `watch/reload_checker.lua`; Test (drive with `autoread` + `:checktime`).

**Interfaces:** `reload_checker.new({registry, emit, tagger}) → {on_file_changed_shell(buf)}` — wired to `FileChangedShellPost`; when Neovim reloads a watched buffer from disk, read the reloaded content, `compare_saved_content`, emit + reset. This is the path that fires on focus-gain/`:checktime`.

**Test intent (headless):** write the file externally, `set autoread`, `checktime` → the reload fires and emits one `external_change`, model reset; a no-op reload emits nothing; an unwatched file ignored. **Gate:** spec green. **Commit:** `feat(recorder): reload-from-disk external-change path`.

---

### Task 8: Coordinator + timing edge cases + manual floor

**Files:** Create `watch/external_change_coordinator.lua`; Test; append to `docs/manual-verification.md`.

**Interfaces:** `coordinator.start({workspace, files_under_review, emit, tagger}) → handle` — owns the registry (seeded from `doc.open`), all three path handlers, and the `recent_saves` tolerance map; exposes `note_save(rel)` for doc-wiring to call; `handle.dispose()` tears down everything (no post-dispose emits).

**Test intent:** each path emits exactly once for its scenario; no double-emit when path 1 and path 2 both observe the same save; `dispose` unsubscribes. Manual checklist items: real `FileChangedShell` on focus-gain, native-watcher latency (these need a live TUI). **Gate:** spec green + full `make test`. **Commit:** `feat(recorder): external-change coordinator + timing tests`.

---

## Self-Review

**Spec coverage (design.md §5 high-risk, §9.4, PRD §4.5):** expected-content model + registry (T1), content builder (T2), direction-critical detector (T3), explanation tagger (T4), three emission paths — save-time (T5), `vim.uv` watcher (T6), reload-from-disk (T7) — and the coordinator + manual floor (T8).

**Risk isolation:** the lazy-notification timing lives entirely in Tasks 6–7 and is driven headlessly with `autoread`+`checktime`; the direction bug is guarded by an explicit regression in T3; double-emit is guarded by the tolerance window in T6/T8. Items that genuinely need a TUI (focus-gain, watcher latency) are pushed to the manual checklist, not faked.

**Type consistency:** `expected_content`/`registry` (T1) consumed by all three paths; `compare_saved_content` (T3) is the single comparison used by T5/T6/T7; `build_external_change_content` (T2) + `tagger.consume` (T4) fill the same `fs.external_change` payload everywhere; `emit` is Plan 4's `SessionHost.emit`.

**Deferred/seams:** `explanation` marks come from Plan 6 (formatter) and Plan 7 (git) — wired here, usually empty until those land.
