# Upward manifest discovery + concurrent multi-assignment recording — Neovim recorder

**Repo:** `provenance-neovim-recorder` (provnvim, Lua)
**Date:** 2026-07-20
**Status:** Approved design, ready for implementation plan (superpowers SDD)
**Sibling specs:** VS Code (`provenance` monorepo `packages/recorder`), JetBrains (`provenance-jetbrains-recorder`) — same feature, editor-specific mechanics.

## Problem

provnvim keys activation off `vim.fn.getcwd()` and reads the manifest at exactly `<cwd>/.provenance-manifest`, non-recursively. It triggers only on `VimEnter` / `DirChanged` and is single-workspace by construction. If a student does `cd 61a && nvim cats/cats.py` (or `nvim ~/61a/cats/cats.py` from anywhere), the cwd holds no manifest and nothing records — the same "must be at the exact root" limitation as the other recorders, anchored on cwd.

## Why the fix is shaped differently here (upward, not downward)

Neovim has **no opened-folder object** — only the file(s) in buffers and a loosely-related cwd. Downward recursion from cwd is wrong: cwd may be the student's home dir (→ scanning all of `~`) or an unrelated parent (→ ambiguous which nested assignment is meant). The anchor must be the **file**. So discovery is an **upward** root-marker walk from each buffer's file to the nearest ancestor `.provenance-manifest` — exactly how LSP `root_dir` / `.git` detection work in Neovim (`vim.fs.find({...}, { upward = true })` / `vim.fs.root`). This resolves one unambiguous assignment per buffer regardless of cwd.

Concrete cases the upward walk must satisfy:
- `cd ~/61a/cats && nvim cats.py` → from `cats.py`, up → `cats/.provenance-manifest`.
- `cd ~/61a && nvim cats/cats.py` → from `cats/cats.py`, up → `cats/`; the sibling `hog/` manifest is never considered.
- `cd ~ && nvim 61a/cats/cats.py` → up 3 levels → `cats/`; the rest of `~` is never scanned.
- `nvim ~/61a/cats/cats.py ~/61a/hog/hog.py` → each buffer resolves its own manifest → **two concurrent sessions**.

## Goals

- Opening a file anywhere under an assignment folder activates recording for that assignment, regardless of cwd.
- Multiple buffers across different assignments record **concurrently, each as its own session** (full parity with the other recorders — locked decision), each writing to its **own** `<assignmentRoot>/.provenance/`.
- `:ProvenanceSeal` lets the student **choose which assignment** to bundle when more than one is active (`vim.ui.select`); exactly one → no prompt.
- Terminal/git events attributed **by path** to the owning session; dropped when no assignment owns them.
- Pure-Lua, zero-native-dep constraints preserved; log format untouched.

## Non-goals

- No change to log format, manifest schema, JCS (Lua port), hash chain, or signing/verification.
- No recording of buffers under no assignment root (unchanged privacy invariant).

## Locked decisions

1. **Full concurrent multi-session (parity).** Each buffer's nearest-ancestor manifest gets its own live session; two assignments can record at the same instant. This requires unwinding provnvim's single-workspace core.
2. **Per-assignment `.provenance/`** at `<assignmentRoot>/.provenance/`, derived from the resolved manifest dir (not cwd).
3. **Seal selector** via `vim.ui.select` when >1 active; single → no prompt.
4. **Terminal/git attribution = by path** (terminal cwd / git repo path → owning session; drop if none).
5. **Nearest-enclosing ownership** per buffer.

## Current architecture (seams to change)

| Concern | Location |
|---|---|
| Root = cwd; manifest at `<cwd>/name` non-recursive | `lua/provenance/recorder/init.lua:61`; `activation.lua:88-104` (names at `:14`) |
| Triggers = `VimEnter` + `DirChanged` only (no `BufEnter`) | `init.lua:171-175`, immediate call `:195` |
| Single controller keyed to one workspace | `init.lua:46-47, 64-92` (guard `:75`) |
| Module-level single `state` | `init.lua:30` |
| File scoping by prefix against the one workspace | `wiring/doc_wiring.lua:236-266` (esp. `:253`) |
| Seal command (single) | `init.lua:101` (live), `:158` (inert stub) |
| Lifecycle end on `VimLeavePre` | `init.lua:186` |
| Activation design | `docs/plans/2026-07-17-activation-status.md:5,75,98` |
| Doc-events/seal design | `docs/plans/2026-07-17-doc-events-seal.md:117,137` |

## Design

### 1. Discovery (upward, per buffer)

- Add a resolver: given a buffer's file path, walk **upward** (`vim.fs.find({ ".provenance-manifest", "provenance-manifest" }, { upward = true, path = <file dir>, stop = <home or fs root> })` or `vim.fs.root`) to the nearest ancestor containing a manifest. Verify it with the existing `activation.load_and_verify` / `evaluate` (ed25519 vs committed course key). No manifest found or verification fails → the buffer is not recorded.
- Keep cwd-based resolution as a fallback anchor for buffers with no file path (rare), but the file path is the primary anchor.

### 2. Triggers

- Add `BufEnter` / `BufReadPost` (and `BufNewFile` for new files under an assignment) autocmds so that **opening a file** — not just `:cd` — resolves and activates its assignment. Keep `VimEnter`/`DirChanged` for the cwd case. On each trigger, resolve the buffer's assignment and ensure its session exists (idempotent).

### 3. Session registry (one → many)

- Replace the module-level single `state` + single `controller` with a **registry** keyed by assignment root: `sessions[root] = { manifest, controller, provenance_dir, ... }`. Each session owns its own writer, `.provenance/` dir, `files_under_review` model, and lifecycle. Buffers are associated with the session of their nearest-ancestor root. `VimLeavePre` ends **all** sessions (emits `session.end` for each).

### 4. Scoping / event routing

- `doc_wiring.is_recordable` currently tests prefix against the one workspace. Change buffer/event routing to: resolve the buffer's owning session (nearest-ancestor root), record the event into **that** session only, using paths relative to **that** root; drop if no session owns the buffer. Exclude each session's own `.provenance/` and manifest file.
- `nvim_buf_attach` `on_lines` handlers must route by the buffer's owning session.

### 5. Seal selector

- `:ProvenanceSeal`: if one active session, seal it. If more than one, `vim.ui.select` over active assignments (label = `assignment_id` + relative dir), defaulting sensibly (e.g. the current buffer's assignment), and seal the chosen one to `<root>/<assignment_id>-bundle-<ts>.zip`. Optionally accept an argument (`:ProvenanceSeal cats`) to skip the prompt.

### 6. Terminal/git routing (by path)

- Route terminal/git events to the session whose assignment root contains the relevant path (terminal cwd, git repo root); drop if none owns it. (Terminal/git are best-effort/graceful-degrade signals already.)

## Integrity invariants (must hold)

- Log format, manifest schema, JCS (Lua), hash chain, signing untouched; conformance vectors still pass (sign → real analyzer verifies).
- Each session chains independently and is bound to its own manifest signature.
- No buffer outside all assignment roots recorded; no event double-recorded.
- A failing-signature manifest produces no session and does not affect others.
- Pure-Lua / zero-native-dep keystone preserved — no new native dependency.

## How we confirm it works (acceptance criteria)

Tests in the repo's existing harness (`tests/recorder/`, `tests/core/`, `tests/conformance/`):

1. **Upward discovery:** each of the four launch cases above resolves the correct assignment; a file under no manifest resolves to nothing; a failing-signature manifest is skipped.
2. **Concurrency:** editing `cats/cats.py` and `hog/hog.py` in one nvim yields two live sessions recording simultaneously into their own `.provenance/`.
3. **Routing:** an `on_lines` edit is recorded only by the owning session; buffers under no root are dropped; nearest-enclosing wins.
4. **Triggers:** opening a file under an assignment while cwd is `~` activates recording (BufEnter path).
5. **Seal selector:** one active → no prompt; two active → `vim.ui.select`, seals only the chosen assignment; bundle passes conformance.
6. **Terminal/git:** command cwd under cats → cats session; at the bare parent → dropped.
7. **Regression:** the `cd <assignment> && nvim` single-assignment path behaves as before.

"Works" = the repo's full test suite green (e.g. via its Makefile / plenary/busted runner — use whatever the repo already uses) plus conformance vectors passing. Report the exact commands and output.

## Rollout

- Feature branch off `main` (e.g. `feat/upward-manifest-discovery`). This spec is the branch's first commit.
- Small, reviewable commits per SDD task. Do not merge or open a PR — stop after verification and report. Flag the single-workspace → registry unwind (`init.lua`, `state`, `doc_wiring.lua`, seal) as the highest-risk area.
