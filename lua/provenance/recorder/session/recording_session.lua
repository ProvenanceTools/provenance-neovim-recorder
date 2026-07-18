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
local recorder_context = require("provenance.recorder.session.recorder_context")
local session_host = require("provenance.recorder.session.session_host")
local session_writer = require("provenance.recorder.io.session_writer")
local meta_writer = require("provenance.recorder.io.meta_writer")
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local heartbeat = require("provenance.recorder.events.heartbeat")
local seal_cmd = require("provenance.recorder.commands.seal")

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
---   prev_session_id: string|nil    -- previous session id for chained sessions
---   env: table|nil                 -- recorder_context env overrides (uuid, hostname, ...)
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

  -- 1. Fresh per-session ed25519 keypair (recorder PRD §4.6).
  local keypair = core_session_keys.generate()

  -- 2. Logical session context — the session.start payload. session_id
  -- here is the LOGICAL session id (chain/manifest identity), distinct
  -- from the filename uuid generated below (two-uuid rule).
  local context = recorder_context.build_recorder_context({
    manifest = manifest,
    prev_session_id = opts.prev_session_id,
    session_pubkey_hex = keypair.public_key_hex,
    env = opts.env,
  })

  -- 3. TWO-UUID RULE: the `.slog` FILENAME uses a SEPARATE fresh uuid, not
  -- context.session_id.
  local file_uuid = generate_file_uuid()
  local slog_path = provenance_dir .. "/session-" .. file_uuid .. ".slog"
  local meta_path = slog_path .. ".meta"

  -- 4. Buffered, append-only `.slog` writer.
  local writer = session_writer.open({ slog_path = slog_path, clock = clock })

  -- 5. Wrap the session private key under the manifest signature so only a
  -- holder of the activation-gate secret can recover it.
  local encrypted_privkey = core_session_keys.encrypt_privkey(keypair.private_key, manifest.sig)

  -- 6. Persist `.slog.meta` immediately (pubkey + encrypted privkey).
  meta_writer.create({
    meta_path = meta_path,
    session_id = context.session_id,
    session_pubkey_hex = keypair.public_key_hex,
    encrypted_privkey = encrypted_privkey,
  })

  -- 7. The single chaining chokepoint; on_entry feeds the writer.
  local host = session_host.new({
    session_id = context.session_id,
    clock = clock,
    on_entry = writer.append,
  })

  -- 8. session.start MUST be the first line of the .slog (seq 0), so this
  -- emit happens before any other wiring is attached.
  host.emit("session.start", context)

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
  }

  --- Flush the writer and seal a submission bundle from everything
  --- recorded so far (across all sessions in provenance_dir, per
  --- seal_bundle's own multi-session scan). Does not stop the session.
  --- @param seal_opts table|nil { now: function() -> string }
  --- @return table  seal_bundle's result ({kind="ok",...} | {kind="no_sessions"} | {kind="write_error",...})
  function session.seal(seal_opts)
    seal_opts = seal_opts or {}
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

    hb.dispose()
    wiring.dispose()
    writer.dispose()
  end

  return session
end

return M
