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
-- Plan 9 additional signals (only wired when opts.enable_signals is true; see
-- M.start). recording_session with enable_signals=false stays byte-identical to
-- its pre-Plan-9 behavior — none of these are required-at-runtime unless enabled.
local external_change_coordinator = require("provenance.recorder.watch.external_change_coordinator")
local paste_assembly = require("provenance.recorder.wiring.paste_assembly")
local selection_wiring = require("provenance.recorder.wiring.selection_wiring")
local focus_wiring = require("provenance.recorder.wiring.focus_wiring")
local terminal_wiring = require("provenance.recorder.wiring.terminal_wiring")
local git_wiring = require("provenance.recorder.wiring.git_wiring")
local snapshot_wiring = require("provenance.recorder.wiring.snapshot_wiring")
local ext_activation_wiring = require("provenance.recorder.wiring.ext_activation_wiring")
local clock_skew_watcher = require("provenance.recorder.events.clock_skew_watcher")
local explanation_tags = require("provenance.recorder.events.explanation_tags")
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

  -- Plan 9 CAPSTONE seam: when false/absent (the default), recording_session
  -- behaves EXACTLY as it did pre-Plan-9 (the lean core used by focused specs
  -- + the e2e driver). When true, the additional signals (paste, external-
  -- change, terminal/git/snapshot, clock-skew) are wired below with the
  -- ordering they require. recording_controller.start sets this true.
  local enable_signals = opts.enable_signals

  -- Shared explanation tagger (only when signals are enabled): BOTH the
  -- external-change coordinator and git wiring mark it, so a git op explains a
  -- nearby external change (tagger.consume() in save_time_checker). Created
  -- before the coordinator so the same instance is threaded into both.
  local tagger = enable_signals and explanation_tags.new({ get_now = clock.now }) or nil

  -- Forward-declared signal sub-handles so session.stop()'s closure can
  -- dispose them (they are only assigned below when enable_signals is true;
  -- nil-guarded in stop() so the disabled path is a no-op).
  local coordinator, paste, term, git, snap, skew, sel, focus, extact

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

  -- 8c. External-change coordinator (Plan 9): MUST be created AFTER host
  -- exists (it needs host.emit) and AFTER session.start is emitted, but
  -- BEFORE doc-wiring, because doc-wiring below takes the coordinator's
  -- methods as its `external_change` dependency. Shares the tagger with git
  -- wiring so a git op can explain a nearby external change.
  if enable_signals then
    coordinator = external_change_coordinator.start({
      workspace = workspace,
      files_under_review = manifest.files_under_review,
      emit = host.emit,
      tagger = tagger,
      get_now = clock.now,
    })
  end

  -- 9. Doc-wiring: attaches buffer/autocmd listeners and (as part of
  -- attach()'s catch-up pass) emits doc.open for already-open recordable
  -- buffers, chained after session.start. When signals are enabled, the
  -- coordinator's methods are threaded in as `external_change` so doc.open
  -- seeds the expected-content baseline, on_lines keeps it current, and
  -- BufWritePost reconciles/checks it (Path 1). Omitted (nil) when disabled
  -- -> doc-wiring is byte-identical to pre-Plan-9.
  local wiring = doc_wiring.attach({
    workspace = workspace,
    provenance_dir = provenance_dir,
    files_under_review = manifest.files_under_review,
    emit = host.emit,
    external_change = coordinator and {
      seed_open = coordinator.seed_open,
      apply_change = coordinator.apply_change,
      reconcile_save = coordinator.reconcile_save,
      note_save = coordinator.note_save,
      check_after_save = coordinator.check_after_save,
    } or nil,
  })

  -- 9b. Paste assembly (Plan 9): MUST be started AFTER doc-wiring, because it
  -- installs doc-wiring's change_router (set_change_router) to fuse the three
  -- paste-detection signals. Disposed BEFORE wiring in stop() so it unhooks
  -- the router first.
  if enable_signals then
    paste = paste_assembly.attach({ emit = host.emit, doc_wiring_handle = wiring })
    -- Selection/cursor signal (selection.change). Reuses doc-wiring's
    -- recordable-buffer filter via its handle, mirroring VS Code's
    -- onDidChangeTextEditorSelection (colocated with doc-wiring there too).
    sel = selection_wiring.start({ emit = host.emit, doc_wiring_handle = wiring })
    -- Focus signal (focus.change) + the shared focus-state source the
    -- heartbeat reads below. Mirrors VS Code's onDidChangeWindowState.
    focus = focus_wiring.start({ emit = host.emit })
  end

  -- 9c. Terminal / git / snapshot / clock-skew signals (Plan 9). snapshot
  -- emits an ext.snapshot immediately on start; git degrades to an inert
  -- handle when the workspace is not a git repo; clock-skew + snapshot both
  -- run unref'd timers that never block headless exit.
  if enable_signals then
    term = terminal_wiring.start({ emit = host.emit })
    git = git_wiring.start({ workspace = workspace, emit = host.emit, tagger = tagger })
    snap = snapshot_wiring.start({ emit = host.emit })
    -- ext.activate: polls for plugins that load AFTER start (baseline covered
    -- by snap's immediate ext.snapshot). Mirrors VS Code's activation poller.
    extact = ext_activation_wiring.start({ emit = host.emit })
    skew = clock_skew_watcher.start({ emit = host.emit })
  end

  -- 10. Heartbeat: get_active_file uses heartbeat's own default; get_focused
  -- is threaded from the focus tracker when signals are enabled (so the
  -- heartbeat's `focused` field reflects real focus state instead of the
  -- hardcoded-true default), and the session's clock is threaded through so
  -- idle/heartbeat timing is consistent with the chain.
  local hb = heartbeat.start({
    emit = host.emit,
    get_now = clock.now,
    get_focused = focus and focus.get_focused or nil,
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
    -- Test/inspection seam: doc_wiring's real (uniquely-suffixed) augroup id,
    -- always present since doc_wiring runs unconditionally (unlike the
    -- enable_signals-gated _signals table below). Lets tests target the
    -- actual instance's augroup for leak checks instead of a fixed name that
    -- may never have existed (see doc_wiring.lua's per-instance suffixing).
    _doc_wiring_augroup_id = wiring._augroup_id,
    -- Same seam for the external-change coordinator's augroup. Only non-nil
    -- when enable_signals is true (coordinator is nil otherwise), same as
    -- the coordinator itself in _signals below.
    _external_change_augroup_id = coordinator and coordinator._augroup_id or nil,
  }

  -- TEST SEAM (Plan 9): expose the signal sub-handles so the integration test
  -- can force deterministic ticks (heartbeat._tick, clock_skew._tick,
  -- snapshot._tick) and drive coordinator paths directly. Only populated when
  -- signals are enabled; nil otherwise (so the disabled path exposes no new
  -- surface — existing specs see the exact same session table).
  if enable_signals then
    session._signals = {
      heartbeat = hb,
      paste = paste,
      selection = sel,
      focus = focus,
      coordinator = coordinator,
      terminal = term,
      git = git,
      snapshot = snap,
      ext_activation = extact,
      clock_skew = skew,
      tagger = tagger,
    }
  end

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

    -- Dispose the Plan 9 signal handles (each nil when signals were disabled,
    -- so guarded; each own dispose() is idempotent). Order matters:
    --   - paste BEFORE wiring: paste unhooks doc-wiring's change_router.
    --   - coordinator releases its fs_poll watchers + FileChangedShellPost
    --     augroup (no libuv/autocmd leak -> clean headless exit).
    -- Then the always-present hb/wiring/writer teardown, unchanged.
    if paste then paste.dispose() end
    if sel then sel.dispose() end
    if focus then focus.dispose() end
    if coordinator then coordinator.dispose() end
    if skew then skew.dispose() end
    if extact then extact.dispose() end
    if snap then snap.dispose() end
    if git then git.dispose() end
    if term then term.dispose() end

    hb.dispose()
    wiring.dispose()
    writer.dispose()
  end

  return session
end

return M
