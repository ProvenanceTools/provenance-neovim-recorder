--- RecordingSession: the Plan-4 CAPSTONE composition. Wires every module
--- built across Plan 4 into one live recording session for an activated
--- workspace: keypair -> session.start -> writer -> doc-wiring -> heartbeat
--- -> seal/stop (design.md; recorder PRD). This module composes; it does
--- not reimplement any of the logic owned by the modules it wires
--- together — read each one's own file before changing this one.
---
--- TWO-UUID RULE: the `.slog` FILENAME is a fresh UUID, generated
--- independently of the logical `session_id` embedded in the session.start
--- payload (`context.session_id`, built by recorder_context). The filename
--- uuid is never derived from, or equal to, the logical session id — the
--- caller of `start()` supplies (or the recorder_context env supplies) the
--- logical id, while the filename id always comes from a fresh random draw
--- local to this module.
---
--- `start()` ensures `provenance_dir` exists (mkdir -p) before anything
--- writes into it — meta_writer.create() atomic-writes immediately and does
--- not create parent directories itself, so as the composition entry point
--- and owner of the session directory lifecycle, start() creates it up
--- front rather than relying on a later step (e.g. session_writer's first
--- flush) to do so.
local bit = require("bit")
local band, bor = bit.band, bit.bor

local core_session_keys = require("provenance.core.session_keys")
local core_clock = require("provenance.core.clock")
local core_checkpoint = require("provenance.core.checkpoint")
local recorder_context = require("provenance.recorder.session.recorder_context")
local session_host = require("provenance.recorder.session.session_host")
local session_writer = require("provenance.recorder.io.session_writer")
local meta_writer = require("provenance.recorder.io.meta_writer")
local checkpoint_cadence = require("provenance.recorder.session.checkpoint_cadence")
local checkpoint_scheduler = require("provenance.recorder.session.checkpoint_scheduler")
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local heartbeat = require("provenance.recorder.events.heartbeat")
local seal_cmd = require("provenance.recorder.commands.seal")
local chain_recovery = require("provenance.recorder.startup.chain_recovery")
local uv_recovery_deps = require("provenance.recorder.startup.uv_recovery_deps")
local disk_full_handler = require("provenance.recorder.failure.disk_full_handler")
local degraded_notifier = require("provenance.recorder.failure.degraded_notifier")

local M = {}

--- Generate a UUID v4 (RFC 4122) from 16 random bytes, lowercase hex,
--- version nibble forced to 4, variant bits forced to 10xx. Deliberately
--- duplicated from recorder_context's private uuid generator (not exported
--- there): this is the SEPARATE fresh id used only for the `.slog`
--- filename (two-uuid rule; see module doc above), never the logical
--- session_id.
local function generate_file_uuid()
  local uv = vim.uv or vim.loop
  local bytes = uv.random(16)

  local b = {}
  for i = 1, 16 do
    b[i] = string.byte(bytes, i)
  end

  b[7] = bor(band(b[7], 0x0F), 0x40) -- version 4
  b[9] = bor(band(b[9], 0x3F), 0x80) -- variant 10xx

  local hex = {}
  for i = 1, 16 do
    hex[i] = string.format("%02x", b[i])
  end

  return table.concat(hex, "", 1, 4)
    .. "-"
    .. table.concat(hex, "", 5, 6)
    .. "-"
    .. table.concat(hex, "", 7, 8)
    .. "-"
    .. table.concat(hex, "", 9, 10)
    .. "-"
    .. table.concat(hex, "", 11, 16)
end

--- Default `now()` for seal(): a real fixed-width ISO wall-clock string
--- (mirrors core.clock.system().wall(), not the session's own injected
--- clock — sealing may happen long after the session's monotonic clock
--- state stopped mattering).
local function default_iso_now()
  return core_clock.system().wall()
end

--- start(opts) -> session
--- @param opts table {
---   workspace: string             -- activated assignment workspace root
---   provenance_dir: string        -- <workspace>/.provenance (must exist)
---   manifest: table                -- {assignment_id, semester, sig, files_under_review}
---   clock: table                   -- injectable {now(), wall()} (core.clock)
---   prev_session_id: string|nil    -- explicit override; wins over recovery's decision when set
---   env: table|nil                 -- recorder_context env overrides (uuid, hostname, ...)
---   checkpoint_interval: number|nil -- entries between signed checkpoints (default 100)
---   is_degraded: function|nil      -- () -> boolean; when explicitly supplied, overrides
---     the real degraded source (the disk-full handler's own is_degraded) — a seam so
---     tests can force degraded routing without a real write error. True suppresses
---     checkpoint scheduling AND routes entries through the disk-full handler's ring
---     instead of the writer (see on_entry below).
---   notify: function|nil           -- (message) -> nil; injected into the disk-full
---     handler as its user notification. Defaults to degraded_notifier.notify
---     (vim.notify at ERROR level). A seam so tests can capture the degraded message.
---   recover: function|nil          -- () -> RecoveryDecision; full injection seam for tests.
---     Defaults to running chain_recovery.recover_previous_session over the real
---     vim.uv deps (uv_recovery_deps.new(provenance_dir)). Runs BEFORE this
---     session's own artifacts (.slog/.slog.meta) exist, so it only ever sees
---     a PRIOR session. A "previous_session_dangling" decision links
---     prev_session_id (unless overridden above); "previous_session_corrupt"
---     additionally emits recorder.recovered_from_corruption as the entry
---     right after session.start. clean_start/complete do neither.
--- }
--- @return table session {
---   session_id, slog_path, meta_path, public_key_hex,
---   seal(seal_opts?), stop(reason?),
--- }
function M.start(opts)
  opts = opts or {}
  local workspace = opts.workspace
  local provenance_dir = opts.provenance_dir
  local manifest = opts.manifest
  local clock = opts.clock
  local checkpoint_interval = opts.checkpoint_interval or 100

  -- Forward-declared: the disk-full handler's on_degraded closure (built
  -- below, before the writer/host exist) must call host.emit(...), but
  -- `host` itself is only constructed at step 7. Capturing this local as an
  -- upvalue now and assigning it later (never re-`local`-ing it) means the
  -- closure sees the real host once writes are actually flowing — a write
  -- error can only happen after the host exists.
  local host

  -- 0. Ensure provenance_dir exists before anything below writes into it
  -- (meta_writer.create in step 6 atomic-writes immediately and does not
  -- mkdir). "p" is idempotent — a no-op if the dir already exists — so the
  -- common case never errors; pcall only guards against vim.fn.mkdir itself
  -- raising (e.g. E739 when a path component is a regular file), and a
  -- genuine failure like that still propagates as an error, same as before.
  local mkdir_ok, mkdir_err = pcall(vim.fn.mkdir, provenance_dir, "p")
  if not mkdir_ok then
    error(mkdir_err)
  end

  -- 0b. Startup chain recovery (Plan 8, Task 4/5): run BEFORE any of this
  -- session's own artifacts exist, so recovery only ever sees a PRIOR
  -- session's .slog(s) — never the one about to be created below. `recover`
  -- is a full-injection seam for tests; production wires the real vim.uv
  -- deps layer.
  local recover = opts.recover
  local recovery
  if recover then
    recovery = recover()
  else
    local deps = uv_recovery_deps.new(provenance_dir)
    recovery = chain_recovery.recover_previous_session(deps)
  end

  -- Derive prev_session_id from the recovery decision: an explicit
  -- opts.prev_session_id override always wins (backward compat for callers/
  -- tests that already pass it); otherwise a DANGLING prior session is
  -- linked, and clean_start/complete/corrupt leave it nil (no link — a
  -- complete prior session is reported by recovery but is deliberately not
  -- linked here, per chain_recovery.lua's own docstring).
  local prev_session_id = opts.prev_session_id
  if prev_session_id == nil and recovery.kind == "previous_session_dangling" then
    prev_session_id = recovery.prev_session_id
  end

  -- 1. Fresh per-session ed25519 keypair (recorder PRD §4.6).
  local keypair = core_session_keys.generate()

  -- 2. Logical session context — the session.start payload. session_id
  -- here is the LOGICAL session id (chain/manifest identity), distinct
  -- from the filename uuid generated below (two-uuid rule).
  local context = recorder_context.build_recorder_context({
    manifest = manifest,
    prev_session_id = prev_session_id,
    session_pubkey_hex = keypair.public_key_hex,
    env = opts.env,
  })

  -- 3. TWO-UUID RULE: the `.slog` FILENAME uses a SEPARATE fresh uuid, not
  -- context.session_id.
  local file_uuid = generate_file_uuid()
  local slog_path = provenance_dir .. "/session-" .. file_uuid .. ".slog"
  local meta_path = slog_path .. ".meta"

  -- 3b. Disk-full handler (Plan 8, Task 6/7). Wired as the writer's
  -- on_error below so a write failure flips it into degraded mode: notify
  -- once, emit recorder.degraded once (via host, once it exists), and from
  -- then on route entries through its in-memory critical-only ring instead
  -- of the writer (see on_entry in step 7).
  local disk_full = disk_full_handler.new({
    on_degraded = function(data)
      -- host is assigned by step 7 before writes can occur (session.start
      -- is the very first write below); a write error can only happen
      -- after that.
      if host then host.emit("recorder.degraded", data) end
    end,
    notify = opts.notify or degraded_notifier.notify,
  })

  -- 4. Buffered, append-only `.slog` writer. on_error routes write
  -- failures (e.g. ENOSPC) to the disk-full handler above.
  local writer = session_writer.open({ slog_path = slog_path, clock = clock, on_error = disk_full.handle_write_error })

  -- Real degraded source is the disk-full handler; opts.is_degraded (Task 3
  -- seam) still wins when explicitly supplied, so tests can force degraded
  -- routing without a real write error.
  local is_degraded = opts.is_degraded or disk_full.is_degraded

  -- 5. Wrap the session private key under the manifest signature so only a
  -- holder of the activation-gate secret can recover it.
  local encrypted_privkey = core_session_keys.encrypt_privkey(keypair.private_key, manifest.sig)

  -- 6. Persist `.slog.meta` immediately (pubkey + encrypted privkey). The
  -- handle is captured (not discarded) so checkpoint persistence below can
  -- append signed checkpoints to the same meta file.
  local mw = meta_writer.create({
    meta_path = meta_path,
    session_id = context.session_id,
    session_pubkey_hex = keypair.public_key_hex,
    encrypted_privkey = encrypted_privkey,
  })

  -- 6b. Checkpoint cadence + async scheduler (Plan 8). Every
  -- `checkpoint_interval`-th appended entry, a signed seq->hash checkpoint
  -- is scheduled: signing/persisting is deferred off the on_lines hot path
  -- (checkpoint_scheduler defers via vim.schedule) and drained synchronously
  -- at stop()/seal() so nothing pending is lost.
  local cadence = checkpoint_cadence.new(checkpoint_interval)
  local scheduler = checkpoint_scheduler.new({
    sign = function(seq, hash)
      return core_checkpoint.sign(seq, hash, keypair.private_key)
    end,
    persist = function(cp)
      mw.append_checkpoint(cp)
    end,
    on_error = function(err)
      -- Checkpoint failures must never crash recording; debug-log only.
      if vim.g.provenance_debug then
        vim.notify("Provenance: checkpoint error: " .. tostring(err), vim.log.levels.DEBUG)
      end
    end,
  })

  -- 7. The single chaining chokepoint; on_entry feeds the writer (or, while
  -- degraded, the disk-full handler's critical-only ring), then — only on
  -- the normal path — checks the checkpoint cadence and schedules a
  -- checkpoint. writer.append runs FIRST so the entry is persisted to the
  -- .slog before any checkpoint bookkeeping happens.
  --
  -- LOOP SAFETY: a write error -> disk_full.handle_write_error (idempotent)
  -- flips degraded + notifies once + calls on_degraded once ->
  -- host.emit("recorder.degraded", ...) -> chains a new entry -> this same
  -- on_entry -> is_degraded() now true -> disk_full.enqueue(the
  -- recorder.degraded entry) (a CRITICAL kind, retained in the ring) — NOT
  -- writer.append, so no new write is attempted and on_error cannot fire
  -- again. The idempotent handler plus the degraded flag routing away from
  -- the writer together rule out any recursion/infinite loop.
  host = session_host.new({
    session_id = context.session_id,
    clock = clock,
    on_entry = function(entry)
      if is_degraded() then
        -- Disk is failing: bypass the writer entirely; only CRITICAL kinds
        -- are retained (in-memory ring), everything else is dropped. No
        -- write is attempted, so on_error cannot re-trigger from here.
        disk_full.enqueue(entry)
      else
        writer.append(entry)
        if cadence.on_entry_appended() then
          scheduler.schedule(entry.seq, entry.hash)
        end
      end
    end,
  })

  -- 8. session.start MUST be the first line of the .slog (seq 0), so this
  -- emit happens before any other wiring is attached.
  host.emit("session.start", context)

  -- 8b. If recovery quarantined a corrupt prior .slog, record that fact as
  -- the SECOND entry (seq 1), chained right after session.start — before
  -- any other wiring is attached, mirroring session.start's own placement
  -- rule. clean_start/complete/dangling emit nothing here (dangling only
  -- affects prev_session_id above; a complete prior session is reported but
  -- not linked or announced).
  if recovery.kind == "previous_session_corrupt" then
    host.emit("recorder.recovered_from_corruption", { quarantined_path = recovery.quarantined_path })
  end

  -- 9. Doc-wiring: attaches buffer/autocmd listeners and (as part of
  -- attach()'s catch-up pass) emits doc.open for already-open recordable
  -- buffers, chained after session.start.
  local wiring = doc_wiring.attach({
    workspace = workspace,
    provenance_dir = provenance_dir,
    files_under_review = manifest.files_under_review,
    emit = host.emit,
  })

  -- 10. Heartbeat: production defaults (get_focused/get_active_file) come
  -- from heartbeat's own simple defaults; only the session's clock is
  -- threaded through so idle/heartbeat timing is consistent with the chain.
  local hb = heartbeat.start({
    emit = host.emit,
    get_now = clock.now,
  })

  local stopped = false

  local session = {
    session_id = context.session_id,
    slog_path = slog_path,
    meta_path = meta_path,
    public_key_hex = keypair.public_key_hex,
    -- Test/inspection seams onto the disk-full handler (Plan 8, Task 7).
    is_degraded = disk_full.is_degraded,
    _ring_snapshot = disk_full.ring_snapshot,
  }

  --- TEST-ONLY HOOK: deterministically drive the disk-full handler into
  --- degraded mode without needing a real ENOSPC on disk. Just calls
  --- disk_full.handle_write_error, the exact same entrypoint the writer's
  --- on_error uses. Not part of the session's real API surface.
  function session._simulate_write_error(err)
    disk_full.handle_write_error(err or "ENOSPC")
  end

  --- Flush the writer and seal a submission bundle from everything
  --- recorded so far (across all sessions in provenance_dir, per
  --- seal_bundle's own multi-session scan). Does not stop the session.
  --- @param seal_opts table|nil { now: function() -> string }
  --- @return table  seal_bundle's result ({kind="ok",...} | {kind="no_sessions"} | {kind="write_error",...})
  function session.seal(seal_opts)
    seal_opts = seal_opts or {}
    -- Drain any pending checkpoint first so the sealed meta includes it,
    -- even if seal() is called without a preceding stop().
    scheduler.drain()
    writer.flush()
    return seal_cmd.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = manifest.assignment_id,
      semester = manifest.semester,
      files_under_review = manifest.files_under_review,
      session_privkey = keypair.private_key,
      session_pubkey_hex = keypair.public_key_hex,
      now = seal_opts.now or default_iso_now,
    })
  end

  --- Idempotent: the second and later calls no-op. Emits session.end
  --- BEFORE tearing anything down (so the final writer flush includes it),
  --- then disposes every background resource this session started, in
  --- order: heartbeat timer, doc-wiring augroup/buf_attach, writer
  --- (final flush + its own timer teardown).
  --- @param reason string|nil  defaults to "deactivate"
  function session.stop(reason)
    if stopped then
      return
    end
    stopped = true

    host.emit("session.end", { reason = reason or "deactivate" })

    -- Drain any pending checkpoint (including one scheduled by session.end
    -- itself) so it is signed+persisted to the meta before teardown.
    scheduler.drain()

    hb.dispose()
    wiring.dispose()
    writer.dispose()
  end

  return session
end

return M
