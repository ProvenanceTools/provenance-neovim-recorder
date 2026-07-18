# Doc Events + Session Writer + Seal (Plan 4 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Record `doc.open/change/save/close` (+ `session.start`/`session.end`/`heartbeat`), write them through an atomic buffered session writer as a hash-chained `.slog` with a companion `.slog.meta`, and seal a submission bundle. **The success criterion is a real sealed `.zip` that the monorepo's `analysis-core` accepts** (`runValidation.overall !== "fail"`, checks `manifest_sig`/`session_binding`/`chain_integrity` all pass).

**Architecture:** Pure event transforms (`recorder/events/`) turn Neovim signals into `core` envelopes; a `SessionHost` (the single chaining chokepoint) owns `seq`/`prev_hash`; a `SessionWriter` buffers + atomically appends the NDJSON `.slog`; a `MetaWriter` persists the `.slog.meta`; `RecorderContext` builds `session.start`; doc-wiring bridges `nvim_buf_attach`/autocmds to the transforms with the recordability filter; `seal` reads the session(s) and produces the signed bundle. Pure-logic-first, Neovim seams second.

**Tech Stack:** Lua, `nvim_buf_attach` (`on_lines`), autocmds (`BufReadPost`/`BufNewFile`/`BufWritePre`/`BufWritePost`/`BufDelete`), `vim.uv` (atomic write, fsync, rename), `vim.fn.sha256`, plenary. Builds on Plans 1–3.

## Global Constraints

(Inherits Plans 1–3.) Additional:

- **Append-only, one chaining chokepoint.** All log-producing paths go through `SessionHost.emit`; there is no update/delete. `emit` advances `seq`/`prev_hash` **before** calling `onEntry` so state stays consistent if `onEntry` throws (mirrors `session-host.ts`).
- **The edit firehose is hot.** `on_lines` fires per keystroke — the handler must be minimal; **never canonicalize or sign on the hot path.** `SessionWriter.append` is synchronous (serialize + buffer only); flushing/hashing-for-chain is the only per-event work.
- **Atomic writes for `.meta`/`manifest.json`/`manifest.sig`:** temp → write → **fsync** → close → rename, via `vim.uv`; on error unlink the temp and re-raise the original error. The `.slog` is append-only (opened `"a"`), **not** atomic-rewritten.
- **Buffer policy:** flush when `buffered_bytes >= 256*1024` OR `now - last_flush >= 1000ms`; never flush an empty buffer. Plus a periodic 1s timer. On write failure, buffered lines are **dropped, not restored** (durability is Plan 8's disk-full handler's job), and `on_error` is called.
- **Two distinct UUIDs per session:** the `.slog` filename uses one fresh UUID; the logical `session_id` in `session.start`/meta is a *separate* UUID. Do not conflate.
- **Clock discipline:** `t = max(0, round(clock.now() - t_start))` (monotonic ms); `wall = clock.wall()` fixed-width ISO. Inject clocks in tests.
- **`session.start.vscode`** filled editor-generic: `version` = Neovim version (`vim.version()` → string), `commit = ""`, `platform` = OS (`vim.uv.os_uname().sysname`). **No format change.** `recorder.extension_id = "com.provenance.recorder.nvim"`.
- **Recordability filter:** record only buffers whose file is inside the activated workspace; exclude non-file buffers (`buftype ~= ""`), the manifest file, and anything under `<workspace>/.provenance/` (prevents a self-feeding record loop).
- **Session dir layout:** `<workspace>/.provenance/session-<uuid>.slog`, `…​.slog.meta`, and at seal time `manifest.json`/`manifest.sig`.

### File structure

```
lua/provenance/recorder/
  events/doc_events.lua      -- transform_doc_open/change/save/close (pure)
  events/heartbeat.lua       -- session.heartbeat timer (Task 9)
  io/atomic_write.lua        -- atomic_write_file over vim.uv
  io/session_writer.lua      -- buffered atomic .slog appender
  io/meta_writer.lua         -- .slog.meta writer
  session/session_host.lua   -- chain state machine (emit)
  session/recorder_context.lua -- build session.start payload
  wiring/doc_wiring.lua      -- nvim_buf_attach + autocmds → transforms + recordability
  commands/extension_hash.lua -- placeholder (real impl Plan 9) returning a fixed dev hash
  commands/seal.lua          -- sealBundle
tests/recorder/**/*_spec.lua
```

---

### Task 1: Pure doc-event transforms

**Files:** Create `recorder/events/doc_events.lua`; Test `tests/recorder/events/doc_events_spec.lua`.

**Interfaces (all pure; caller passes precomputed `content_hash` and relative `path`):**
- `transform_doc_open(path, content_hash, text, line_count, max_inline_bytes?=64*1024) → {kind="doc.open", data}` — `byte_len = #text` (UTF-8 bytes); ≤64KB → `{path, sha256, line_count, content=text}`; >64KB → `{path, sha256, line_count, truncated=true}` (no `content`).
- `transform_doc_change(path, deltas) → {kind="doc.change", data={path, deltas=json.array(...), source="typed"}}` — each delta `{range={start={line,character},end={line,character}}, text}`. Empty → `deltas=json.array({})`.
- `transform_doc_save(path, content_hash) → {kind="doc.save", data={path, sha256}}`.
- `transform_doc_close(path) → {kind="doc.close", data={path}}`.

**Test intent:** UTF-8 byte boundary at 64KB (a multibyte char straddling the limit); inline vs `truncated`; empty deltas → empty array (not object); `source` defaults `"typed"`. **Gate:** spec green. **Commit:** `feat(recorder): pure doc-event transforms`.

---

### Task 2: Atomic write

**Files:** Create `recorder/io/atomic_write.lua`; Test `tests/recorder/io/atomic_write_spec.lua`.

**Interfaces:** `atomic_write_file(target_path, contents)` — `tmp = target .. "." .. pid .. "." .. random_hex(8) .. ".tmp"`; `fs_open(tmp,"w")`, `fs_write`, `fs_fsync`, `fs_close`, `fs_rename(tmp, target)`; on any error `fs_unlink(tmp)` best-effort then re-raise original. (`random_hex` uses `vim.uv` entropy or a counter+time seed — not in assertions.)

**Test intent:** round-trip contents; no `.tmp` left after success; a forced mid-write failure leaves the original file intact and re-raises. **Gate:** spec green (real `vim.uv`, temp dir). **Commit:** `feat(recorder): atomic file write over vim.uv`.

---

### Task 3: SessionHost (chain state machine)

**Files:** Create `recorder/session/session_host.lua`; Test `tests/recorder/session/session_host_spec.lua`.

**Interfaces:** `session_host.new({session_id, clock, on_entry}) → host` with `host.emit(kind, data) → hashed_envelope`. State `seq=0`, `prev_hash=GENESIS`, `t_start=clock.now()`. `emit`: `t=max(0,round(clock.now()-t_start))`, `wall=clock.wall()`, `entry=core.hash_chain.chain_entry(prev_hash, envelope.new(seq,t,wall,kind,data))`, advance `seq`/`prev_hash` **then** `on_entry(entry)`. Exposes readonly `seq`, `session_id`, `t_start_ms`.

**Test intent (FixedClock):** first entry has seq 0 + GENESIS prev_hash; second chains (`h1.prev_hash == h0.hash`); `t` math from injected clock; an `on_entry` that errors still advanced state. **Gate:** spec green. **Commit:** `feat(recorder): session host chain state machine`.

---

### Task 4: SessionWriter (buffered atomic .slog appender)

**Files:** Create `recorder/io/session_writer.lua`; Test `tests/recorder/io/session_writer_spec.lua`.

**Interfaces:** `session_writer.open({slog_path, clock, buffer_policy?, on_error?}) → writer`. `writer.append(hashed)` synchronous: `core.ndjson.serialize_entry` → buffer + byte count; consult `core.buffer_policy.should_flush` → maybe background `flush()`. `writer.flush()` serialized (ordered) writes via `fs_open(slog_path,"a")` (created `recursive` dir). On write error: drop buffer, call `on_error`. `writer.dispose()` idempotent: stop timer, final flush, close. A periodic `vim.uv` timer flushes every `max_interval_ms`; `.dispose()` stops it.

**Test intent:** appended lines land in order; auto-flush when over `max_bytes`; `append` after `dispose` errors; `on_error` invoked + buffer dropped on a forced write failure; final flush on dispose. **Gate:** spec green. **Commit:** `feat(recorder): buffered atomic session writer`.

---

### Task 5: MetaWriter (.slog.meta)

**Files:** Create `recorder/io/meta_writer.lua`; Test `tests/recorder/io/meta_writer_spec.lua`.

**Interfaces:** `meta_writer.create({meta_path, session_id, session_pubkey_hex, encrypted_privkey}) → mw` — builds `SlogMeta` (`format_version="1.0"`, `checkpoints=json.array({})`) and **writes it immediately** via `atomic_write_file(meta_path, json.canonicalize(meta))`. `mw.append_checkpoint(cp)` pushes into `checkpoints` and atomically rewrites the whole meta. `mw.dispose()` no-op.

**Test intent:** meta round-trips + validates via `core.meta` shape (Plan 1 §meta — add a `core/meta.lua` shape validator if not already present, mirroring `validateMetaShape`); ordered checkpoint appends; on-disk bytes == `json.canonicalize(meta)`; no `.tmp` left. **Gate:** spec green. **Commit:** `feat(recorder): meta writer for .slog.meta`. *(If `core/meta.lua` validator is needed, add it in this task with its own spec.)*

---

### Task 6: RecorderContext (session.start payload)

**Files:** Create `recorder/session/recorder_context.lua`; Test `tests/recorder/session/recorder_context_spec.lua`.

**Interfaces:** `build_recorder_context({manifest, prev_session_id, session_pubkey_hex, env?}) → SessionStartPayload` — `session_id = uuid()`; `machine_id = sha256(hostname .. ":" .. username .. ":" .. session_id)` (username from `$USER`/`$USERNAME`/`"unknown"`); `format_version="1.0"`; `assignment={id=manifest.assignment_id, semester=manifest.semester}`; `manifest_sig=manifest.sig`; `vscode={version=<nvim version>, commit="", platform=<OS>}`; `recorder={version=<plugin version>, extension_id="com.provenance.recorder.nvim"}`; `session_pubkey=session_pubkey_hex`. `env` (hostname/username/nvim version/platform/uuid) injectable for determinism.

**Test intent:** exact `SessionStartPayload` shape; `vscode.commit == ""`; deterministic `machine_id` from injected env; username fallback when unset. **Gate:** spec green. **Commit:** `feat(recorder): recorder context / session.start payload`.

---

### Task 7: Doc wiring (the Neovim seam)

**Files:** Create `recorder/wiring/doc_wiring.lua`; Test `tests/recorder/wiring/doc_wiring_spec.lua` (headless, real buffers).

**Interfaces:** `doc_wiring.attach({workspace, provenance_dir, files_under_review, emit, get_hash}) → handle`:
- On `BufReadPost`/`BufNewFile` for a recordable buffer: emit `doc.open` (compute rel path, content hash, line count); also `nvim_buf_attach(buf, {on_lines=...})`.
- `on_lines(_, buf, _, first, last, new_last, ...)`: build a single delta from the changed line range (start/end positions), emit `doc.change`. Keep it minimal.
- `BufWritePost`: recompute hash, emit `doc.save`. (External-change detection hooks here in Plan 5.)
- `BufDelete`/`BufUnload`: emit `doc.close`, detach.
- Recordability filter `is_recordable(buf)`: `buftype == ""`, file inside `workspace`, not the manifest, not under `provenance_dir`.
- Catch-up: on attach, emit synthetic `doc.open` for already-open recordable buffers (PRD §4.2.1).
- `handle.dispose()`: clears autocmds + detaches all buffers.

**Test intent (headless):** opening a recordable buffer emits `doc.open`; typing emits chained `doc.change`; save emits `doc.save`; a buffer under `.provenance/` is **never** recorded; a file outside the workspace is ignored; already-open buffer gets a synthetic `doc.open`; `dispose` removes autocmds. **Gate:** spec green. **Commit:** `feat(recorder): doc wiring (on_lines + autocmds + recordability)`.

---

### Task 8: Extension-hash placeholder + Seal

**Files:** Create `recorder/commands/extension_hash.lua` (placeholder returning a fixed 64-hex dev value; real tree-hash is Plan 9), `recorder/commands/seal.lua`; Test `tests/recorder/commands/seal_spec.lua`.

**Interfaces:** `seal.seal_bundle({workspace, provenance_dir, assignment_id, semester, files_under_review, session_privkey, session_pubkey_hex, compute_extension_hash, now}) → {kind="ok", bundle_path, manifest_sha256, warnings} | {kind="no_sessions"|"write_error"}`:
1. List `.slog` files (exclude `.slog.meta`); none → `no_sessions`.
2. Per slog (sorted): read, `core.ndjson.parse_entries` (parse fail → `warnings.unreadable_session`, session ids null), `core.chain_validator.validate_chain` (broken → `warnings.chain_broken`, **do not abort**), extract `session_id`/`prev_session_id` from the first `session.start`; compute `slog_sha256`, `meta_sha256` (missing meta → sha of empty).
3. Read each reviewed file → `submission_files` (`present`+sha or `missing`+null).
4. `extension_hash = compute_extension_hash()`.
5. Build `BundleManifest` (format_version `"1.1"`) via `core.bundle`.
6. `signed = core.bundle.sign(manifest_value, session_privkey)`.
7. `atomic_write_file(provenance_dir.."/manifest.json", signed.canonical_json)`; `…/manifest.sig`, `signed.signature_hex`.
8. Build the `.zip` (see Task 8b) including `.slog`/`.slog.meta`/`manifest.*` (exclude `.corrupt-*`/`.tmp`) + present reviewed files at workspace-relative paths; write to `<workspace>/<assignment_id>-bundle-<ts>.zip` (`ts = now ISO with ':'→'-'`).

**Zip note (Task 8b, may be its own task):** Neovim has no zip builder. Options, decided at implementation time and flagged for review: (a) shell out to `zip`/`vim.fn.system` (degrade if absent); (b) vendor a small pure-Lua zip writer (store/deflate) — **licensing gate applies**. The analyzer loads a real zip, so this must produce a valid archive. **If neither is acceptable pure-Lua, STOP and ask.**

**Test intent:** `no_sessions` when empty; a produced manifest verifies (`core.bundle.verify_sig`); corrupted chain still seals with `warnings.chain_broken`; missing reviewed file → `status="missing"` + absent from zip. **Gate:** spec green. **Commit:** `feat(recorder): seal bundle (manifest + zip)`.

---

### Task 9: Heartbeat + session lifecycle composition (RecordingSession)

**Files:** Create `recorder/events/heartbeat.lua`, `recorder/session/recording_session.lua`; Tests for each.

**Interfaces:**
- `heartbeat.start({interval_ms?=30000, emit, get_now, get_focused, get_active_file}) → handle` — every interval emit `session.heartbeat {focused, active_file, idle_since_ms}`; activity (focus/buf change) resets idle; `.unref()`d timer; `dispose()` stops.
- `recording_session.start({workspace, provenance_dir, manifest, clock, prev_session_id}) → session` — generates keypair (`core.session_keys`), builds context, opens `SessionWriter`, encrypts privkey + `MetaWriter.create`, creates `SessionHost` with `on_entry = writer.append`, emits `session.start`, starts doc-wiring + heartbeat. `session.seal()` flushes + calls `seal_bundle`. `session.stop()` emits `session.end {reason="deactivate"}`, disposes writer/wiring/heartbeat (idempotent).

**Test intent (headless):** first `.slog` line is `session.start` seq 0; typing produces chained `doc.change`; `stop()` appends `session.end`; `.slog.meta` exists with pubkey + encrypted privkey. **Gate:** spec green. **Commit:** `feat(recorder): heartbeat + recording session composition`.

---

### Task 10: End-to-end — real analyzer accepts a sealed bundle (SUCCESS CRITERION)

**Files:** Optional throwaway monorepo script or a headless integration spec `tests/recorder/e2e_seal_spec.lua`; a short runbook in `docs/manual-verification.md`.

**Steps:**
- [ ] Drive a headless session: activate on a temp workspace with the dev manifest fixture, open + edit + save a reviewed file, `stop()`, `seal()`.
- [ ] In the monorepo, load the produced `.zip` via `analysis-core`'s `loadBundle` + `runValidation` (a small Node script committed under `scripts/` or run ad hoc).
- [ ] Assert `report.overall !== "fail"` and checks `manifest_sig`, `session_binding`, `chain_integrity` are all `"pass"`. **This is the plan's success gate** — the first Neovim-produced bundle the real analyzer accepts.
- [ ] Commit `test(recorder): e2e sealed bundle accepted by real analyzer`.

**Note:** the `extension_hash` allowlist is a *heuristic flag*, not a validation check — the bundle validates regardless (Plan 9 adds the hash to the allowlist to clear the flag).

---

## Self-Review

**Spec coverage (design.md §9.3, PRD §4.2/4.6/4.7):** doc transforms (T1), atomic write (T2), session host (T3), buffered writer (T4), meta writer (T5), recorder context with the `vscode`-field decision (T6), doc wiring incl. recordability + catch-up (T7), seal (T8), heartbeat + composition (T9), real-analyzer acceptance (T10).

**Port fidelity / hazards addressed:** hot-path minimalism (no sign/canonicalize in `on_lines`); atomic `.meta`/`manifest` vs append-only `.slog`; drop-not-restore on write failure; two-UUID rule; fixed-width `wall`; `t = max(0, round(...))`; `vscode.commit=""`; recordability excludes `.provenance/`. Zip construction is explicitly flagged as an open sub-decision (no native dep without asking).

**Type consistency:** `SessionHost.emit` (T3) is the sole producer feeding `SessionWriter.append` (T4); `core.bundle`/`core.session_keys`/`core.ndjson`/`core.chain_validator` (Plans 1–2) consumed by seal (T8) and composition (T9); transforms (T1) return `{kind,data}` consumed by wiring (T7) → `emit`.

**Deferred:** paste `source` stays `"typed"` here (paste is Plan 6); external-change save comparison is Plan 5; checkpoints/recovery/degraded are Plan 8. Each is a named seam, not a silent omission.
