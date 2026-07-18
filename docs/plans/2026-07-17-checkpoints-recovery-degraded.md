# Checkpoints + Chain Recovery + Disk-Full Degraded Mode (Plan 8 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add resilience: signed `seq→hash` checkpoints every 100 entries into the `.slog.meta`, startup chain recovery (link a crashed prior session via `prev_session_id`, quarantine a corrupt one), and disk-full degraded mode (critical-only ring buffer + `recorder.degraded`).

**Architecture:** A pure cadence counter + an ordered async checkpoint scheduler (sign + persist via `MetaWriter.append_checkpoint`); a pure recovery decision (`recover_previous_session` → clean_start / complete / dangling / corrupt) with a `vim.uv` deps layer; a pure disk-full handler (idempotent degrade flip + critical-kinds ring) wired to `SessionWriter.on_error`. Pure-logic-first; each wired into the session lifecycle.

**Tech Stack:** Lua, `core.checkpoint` (Plan 2), `MetaWriter` (Plan 4), `vim.uv` (fs ops), `vim.notify`, plenary. Builds on Plans 2 & 4.

## Global Constraints

(Inherits Plans 1–7.) Additional:

- **Checkpoint cadence = every 100 entries** (`CHECKPOINT_INTERVAL = 100`), a per-entry counter — **not** wall-clock. Checkpoints only accumulate when **not** degraded (degraded entries bypass the writer path).
- **Signing stays off the hot path.** Checkpoint signing is fire-and-forget but **serialized** (an ordered promise/queue chain); `stop()` drains the last in-flight checkpoint before the meta closes. Never sign inside `on_lines`.
- **Recovery does not resume a chain or truncate.** Each session is a **fresh `.slog`** (seq 0, GENESIS). Recovery only (a) links via `prev_session_id` for the *dangling* (crash) case, and (b) quarantines a *corrupt* prior log to `<file>.corrupt-<ISO>` and emits `recorder.recovered_from_corruption`. Completed prior sessions are **not** linked; `chain.broken` is **not** emitted by recovery (it's reserved for a live session detecting its own mid-stream break).
- **Choose the alphabetically-last `.slog`** as "previous" (deterministic, avoids stat/TOCTOU).
- **Disk-full handler is idempotent** and treats **all** write errors as disk-full in v1. `CRITICAL_KINDS = {session.start, session.end, fs.external_change, chain.broken, recorder.degraded, recorder.recovered_from_corruption}` are retained in the ring (FIFO, capacity 256); everything else is dropped. First error: flip degraded, `vim.notify` the user, emit `recorder.degraded {reason="disk_full"}` (through the host → routes back into the ring, no loop).

### File structure

```
lua/provenance/recorder/
  session/checkpoint_cadence.lua    -- pure every-N counter
  session/checkpoint_scheduler.lua  -- ordered async sign + persist
  startup/chain_recovery.lua        -- pure recovery decision
  startup/uv_recovery_deps.lua      -- vim.uv deps for recovery
  failure/disk_full_handler.lua     -- pure degraded handler + ring
  failure/degraded_notifier.lua     -- vim.notify wiring
tests/recorder/**/*_spec.lua
```

---

### Task 1: Checkpoint cadence (pure)

**Files:** Create `session/checkpoint_cadence.lua`; Test.

**Interfaces:** `cadence.new(interval?=100) → {on_entry_appended() → boolean}` — returns true (and resets) every `interval`th call. `interval <= 0` errors.

**Test intent:** 99 false then 100th true; custom interval; `interval=0` errors. **Gate:** spec green. **Commit:** `feat(recorder): checkpoint cadence counter`.

---

### Task 2: Checkpoint scheduler (ordered async)

**Files:** Create `session/checkpoint_scheduler.lua`; Test.

**Interfaces:** `scheduler.new({sign, persist, on_error?}) → {schedule(seq, hash), drain()}` — `schedule` enqueues a `sign(seq,hash)` → `persist(cp)` step onto an ordered queue (via `vim.uv` async / a coroutine chain), non-blocking; `drain()` awaits all pending. `sign` = `core.checkpoint.sign(seq, hash, privkey)`; `persist` = `MetaWriter.append_checkpoint`. Errors go to `on_error`, never thrown.

**Test intent:** one and two checkpoints persisted in order; an erroring `sign` does not wedge the queue; `drain` on empty is a no-op. **Gate:** spec green. **Commit:** `feat(recorder): ordered async checkpoint scheduler`.

---

### Task 3: Wire checkpoints into the entry path

**Files:** Modify the recording-session `on_entry` (Plan 4 `recording_session.lua`); Test.

**Interfaces:** in `on_entry(entry)`: after `writer.append(entry)`, if not degraded, `if cadence.on_entry_appended() then scheduler.schedule(entry.seq, entry.hash) end`. `session.stop()` calls `scheduler.drain()` before `meta_writer.dispose()`.

**Test intent (headless):** 100 entries → 1 checkpoint at seq 99 (0-indexed) in the meta; 250 → 2; ended at 150 → 1; none accumulate while degraded. **Gate:** spec green. **Commit:** `feat(recorder): wire checkpoints into entry path`.

---

### Task 4: Chain recovery decision (pure)

**Files:** Create `startup/chain_recovery.lua`; Test.

**Interfaces:** `recover_previous_session({list_slogs, read_slog, rename, now}) → {kind="clean_start"} | {kind="previous_session_complete", prev_session_id} | {kind="previous_session_dangling", prev_session_id, dangling_path} | {kind="previous_session_corrupt", quarantined_path}` — list `.slog` (sorted), none → clean_start; pick alphabetically-last; read + `parse_entries` + `validate_chain` + first-entry-is-`session.start`-with-string-id; any failure → quarantine (`rename` to `.corrupt-<ISO>`) → corrupt; valid + last entry `session.end` → complete; valid + no clean end → dangling.

**Test intent (in-memory fakes):** alphabetically-last chosen; parse/chain/first-entry failures → quarantine with exact `.corrupt-<ISO>` path; complete vs dangling by last entry; **never emits `chain.broken`**. **Gate:** spec green. **Commit:** `feat(recorder): chain recovery decision`.

---

### Task 5: Wire recovery into activation

**Files:** Create `startup/uv_recovery_deps.lua`; Modify `recording_session.start` to run recovery before opening the new session; Test (real temp dir).

**Interfaces:** `uv_recovery_deps.new(provenance_dir)` provides `list_slogs`/`read_slog`/`rename`/`now` over `vim.uv`. `recording_session.start` calls `recover_previous_session`; on **dangling** thread `prev_session_id` into `RecorderContext`; on **corrupt** emit `recorder.recovered_from_corruption {quarantined_path}` right after `session.start`; on complete/clean → `prev_session_id=null`.

**Test intent:** dangling prior → new `session.start.prev_session_id` set; corrupt prior → quarantine file exists + a `recorder.recovered_from_corruption` entry follows `session.start`; clean start → no link. **Gate:** spec green. **Commit:** `feat(recorder): wire chain recovery into activation`.

---

### Task 6: Disk-full degraded handler (pure)

**Files:** Create `failure/disk_full_handler.lua`; Test.

**Interfaces:** `disk_full_handler.new({ring_capacity?=256, on_degraded, notify}) → {handle_write_error(err), enqueue(entry) → boolean, is_degraded()}`. `CRITICAL_KINDS` set as above. `handle_write_error` idempotent: first call flips degraded, `notify("Disk full — Provenance recording is degraded…")`, `on_degraded({reason="disk_full"})`; later calls no-op. `enqueue`: not degraded → false; degraded + critical → push (FIFO evict at capacity), true; degraded + non-critical → false.

**Test intent:** degrade flips once (idempotent); after degrade only CRITICAL_KINDS buffered; FIFO eviction at capacity; ring snapshot is a copy. **Gate:** spec green. **Commit:** `feat(recorder): disk-full degraded handler + ring buffer`.

---

### Task 7: Wire degraded mode into writer + notifications

**Files:** Create `failure/degraded_notifier.lua`; Modify session composition to pass `disk_full_handler.handle_write_error` as `SessionWriter.on_error` and route `on_degraded` → `host.emit("recorder.degraded", ...)`; the `on_entry` path consults `disk_full_handler.enqueue` when degraded (writes bypass the writer). Test via Task 8.

**Interfaces:** `degraded_notifier` wraps `vim.notify` (error level). `on_degraded` emits `recorder.degraded` through the host, which re-enters `on_entry` → `enqueue` accepts it (critical) — no loop (handler idempotent, degraded flag suppresses the writer path).

**Gate:** covered by Task 8. **Commit:** `feat(recorder): wire degraded mode into writer + notifications`.

---

### Task 8: End-to-end integration + full-suite gate

**Files:** Create `tests/recorder/session_lifecycle_spec.lua`.

**Scenarios:** (1) checkpoints land at the right seqs; (2) dangling recovery links `prev_session_id`; (3) corrupt prior quarantined + `recorder.recovered_from_corruption` emitted; (4) disk-full → degraded, `recorder.degraded` emitted, non-critical entries dropped, critical retained; (5) no-retry invariant (buffered lines dropped, not re-written).

- [ ] **Gate:** all 5 pass + full `make test` (core + recorder) green — the gate before Plan 9. **Commit:** `test(recorder): checkpoint/recovery/degraded lifecycle integration`.

---

## Self-Review

**Spec coverage (design.md §9.7, PRD §4.6/4.8):** cadence (T1), ordered scheduler (T2), entry-path wiring (T3), recovery decision (T4), recovery activation wiring (T5), disk-full handler (T6), degraded wiring (T7), integration gate (T8).

**Port fidelity:** cadence 100 per-entry (not wall-clock); recovery does not truncate/resume — fresh chain, link-only-on-dangling, quarantine-on-corrupt, no `chain.broken` from recovery; alphabetically-last selection; disk-full idempotent + CRITICAL_KINDS + FIFO 256 + all-errors-are-disk-full. All match `chain-recovery.ts` / `disk-full-handler.ts` / the checkpoint-every-100 in `extension.ts`.

**Hot-path discipline:** checkpoint signing is ordered-async and drained at stop, never inside `on_lines` (CLAUDE.md).

**Type consistency:** `core.checkpoint.sign` (Plan 2) used by the scheduler (T2); `MetaWriter.append_checkpoint` (Plan 4) is `persist`; `SessionHost.emit` (Plan 4) carries `recorder.degraded`/`recorder.recovered_from_corruption`; `SessionWriter.on_error` (Plan 4) is `handle_write_error` (T6).
