--- Plan 8 Task 8: the end-to-end integration gate. Five scenarios exercise
--- checkpoints (Task 3), chain recovery (Task 5) and disk-full/degraded mode
--- (Task 7) through the REAL `recording_session` composition — not through
--- any single module in isolation. Real headless Neovim, real vim.uv I/O,
--- real temp workspaces. Every session starts from the REAL activation gate
--- (`.provenance-manifest` written to the workspace root, loaded via
--- `activation.load_and_verify` against the conformance fixture's course
--- keypair) rather than a hand-built manifest table, so this file proves the
--- full chain from "workspace on disk" to "sealed/stopped session" the way
--- the other recording_session_*_spec.lua files (Tasks 3/5/7) proved their
--- individual seams.
local recording_session = require("provenance.recorder.session.recording_session")
local activation = require("provenance.recorder.activation")
local core_clock = require("provenance.core.clock")
local core_ndjson = require("provenance.core.ndjson")
local core_json = require("provenance.core.json")
local core_hash_chain = require("provenance.core.hash_chain")
local core_envelope = require("provenance.core.envelope")
local core_checkpoint = require("provenance.core.checkpoint")
local core_chain_validator = require("provenance.core.chain_validator")

local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

--- The same conformance-fixture manifest used by activation_loader_spec.lua:
--- a real course keypair + a real signed inner manifest, so
--- activation.load_and_verify actually verifies (not a stub).
local function load_fixture()
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. "manifest.json"), "\n"))
end

--- Track everything created by a test so it can be torn down afterward:
--- session ALWAYS stopped (idempotent), buffers wiped, any directory
--- permissions loosened before deletion (scenario 4/5 lock a directory
--- read-only to force a real write error), temp dirs deleted. Mirrors
--- recording_session_spec.lua's new_scratch(), plus permission tracking.
local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, readonly_dirs = {}, readonly_files = {}, session = nil }

  function scratch.workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end

  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  --- Strip write permission from `dir` (owner/group/other) so any create-new
  --- file attempt inside it fails with EACCES — used to force a REAL
  --- session_writer flush failure instead of the `_simulate_write_error`
  --- test hook (scenario 4/5).
  ---
  --- NOTE: locking the directory alone is NOT enough any more. session_writer
  --- creates the `.slog` at session start, and appending to an ALREADY-EXISTING
  --- file needs no write permission on its directory — directory permission
  --- gates creating and unlinking entries, not writing through an existing one.
  --- Callers forcing a write failure must also lock_file() the `.slog` itself.
  --- Before the eager create, this helper worked only because the file did not
  --- exist yet, so the failure it produced was really "cannot CREATE" rather
  --- than "cannot WRITE" — a weaker proxy for a full disk than it looked.
  function scratch.lock_dir(dir)
    vim.uv.fs_chmod(dir, tonumber("555", 8))
    table.insert(scratch.readonly_dirs, dir)
  end

  --- Strip write permission from a FILE so `fs_open(path, "a")` fails with
  --- EACCES — the accurate analogue of a disk that will not accept writes.
  function scratch.lock_file(path)
    vim.uv.fs_chmod(path, tonumber("444", 8))
    table.insert(scratch.readonly_files, path)
  end

  --- Restore write permission on every directory scratch.lock_dir() touched.
  --- Callable mid-test (to prove "even once disk space is back, dropped
  --- entries are not retried") and always called first in teardown() so
  --- cleanup can delete the tree.
  function scratch.unlock_dirs()
    for _, dir in ipairs(scratch.readonly_dirs) do
      pcall(vim.uv.fs_chmod, dir, tonumber("755", 8))
    end
    scratch.readonly_dirs = {}
    for _, path in ipairs(scratch.readonly_files) do
      pcall(vim.uv.fs_chmod, path, tonumber("644", 8))
    end
    scratch.readonly_files = {}
  end

  function scratch.teardown()
    scratch.unlock_dirs()
    if scratch.session then
      pcall(scratch.session.stop)
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
  end

  return scratch
end

local function read_all(path)
  if not vim.uv.fs_stat(path) then
    return ""
  end
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

local function read_meta(session)
  local text = read_all(session.meta_path)
  return vim.json.decode(text)
end

--- Real activation gate: writes the fixture's signed inner manifest to
--- `<workspace>/.provenance-manifest`, verifies it via
--- activation.load_and_verify (must come back "active" — a broken fixture
--- or a broken activation gate must fail loudly here, not silently fall
--- back to a hand-built manifest table), and returns the verified manifest
--- ready to hand to recording_session.start.
local function activated_manifest(fx, workspace)
  vim.fn.writefile({ vim.json.encode(fx.manifest) }, workspace .. "/.provenance-manifest")
  local res = activation.load_and_verify(workspace, fx.course_pubkey_hex)
  assert.equals("active", res.status)
  return res.manifest
end

--- Start a real recording_session against a fresh, activated workspace, with
--- one recordable buffer ("foo.txt") already open. Returns
--- workspace, provenance_dir, buf.
local function start_activated_session(fx, scratch, extra_opts)
  local workspace = scratch.workspace()
  local provenance_dir = workspace .. "/.provenance"
  vim.fn.mkdir(provenance_dir, "p")
  local manifest = activated_manifest(fx, workspace)

  local path = workspace .. "/foo.txt"
  scratch.write_file(path, "line0\n")

  local opts = vim.tbl_extend("force", {
    workspace = workspace,
    provenance_dir = provenance_dir,
    manifest = manifest,
    clock = core_clock.fixed(0, 0),
  }, extra_opts or {})

  scratch.session = recording_session.start(opts)
  local buf = scratch.edit(path)
  return workspace, provenance_dir, buf
end

--- Append one line to `buf` -> exactly one doc.change entry (same convention
--- as recording_session_checkpoints_spec.lua's make_entry).
local next_line = 0
local function make_entry(buf)
  next_line = next_line + 1
  local n = vim.api.nvim_buf_line_count(buf)
  vim.api.nvim_buf_set_lines(buf, n, n, false, { "line-" .. tostring(next_line) })
end

--- Build a real chained prior `.slog`'s raw NDJSON text (mirrors
--- recording_session_recovery_spec.lua / chain_recovery_spec.lua /
--- seal_spec.lua): session.start (data.session_id = session_id), optionally
--- followed by a clean session.end. Omitting the session.end makes it
--- DANGLING; garbage text (passed via `corrupt_text`) makes it CORRUPT.
local function build_prior_slog_text(session_id, with_end)
  local e0 = core_hash_chain.chain_entry(
    core_hash_chain.GENESIS_PREV_HASH,
    core_envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { session_id = session_id })
  )
  local entries = { e0 }
  if with_end then
    local e1 = core_hash_chain.chain_entry(
      e0.hash,
      core_envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "session.end", { reason = "seal" })
    )
    entries[#entries + 1] = e1
  end

  local lines = {}
  for _, e in ipairs(entries) do
    lines[#lines + 1] = core_ndjson.serialize_entry(e)
  end
  return table.concat(lines)
end

local function ring_kinds(session)
  local kinds = {}
  for _, entry in ipairs(session._ring_snapshot()) do
    kinds[#kinds + 1] = entry.kind
  end
  return kinds
end

local function contains(list, value)
  for _, v in ipairs(list) do
    if v == value then
      return true
    end
  end
  return false
end

describe("recording_session lifecycle integration (Plan 8 gate)", function()
  local fx = load_fixture()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("scenario 1: checkpoints land at the right seqs and each one verifies", function()
    local _, _, buf = start_activated_session(fx, scratch, { checkpoint_interval = 3 })

    -- session.start = seq 0. 5 edits -> doc.change seq 1..5. Cadence fires
    -- on every 3rd on_entry call -> checkpoints at seq 2 and seq 5.
    for _ = 1, 5 do
      make_entry(buf)
    end

    scratch.session.stop() -- drains any pending checkpoint

    local meta = read_meta(scratch.session)
    assert.equals(2, #meta.checkpoints)
    assert.equals(2, meta.checkpoints[1].seq)
    assert.equals(5, meta.checkpoints[2].seq)
    assert.is_true(core_checkpoint.verify(meta.checkpoints[1], scratch.session.public_key_hex))
    assert.is_true(core_checkpoint.verify(meta.checkpoints[2], scratch.session.public_key_hex))

    -- The .slog chain itself still validates end to end.
    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.is_true(parsed.ok)
    assert.is_true(core_chain_validator.validate_chain(parsed.value).ok)
  end)

  it("scenario 2: a dangling prior session links prev_session_id on the new session.start", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local manifest = activated_manifest(fx, workspace)

    -- A prior, real, chained .slog with NO session.end -- crashed mid-session.
    scratch.write_file(provenance_dir .. "/session-crashed.slog", build_prior_slog_text("crashed-id", false))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.is_true(parsed.ok)

    local first = parsed.value[1]
    assert.equals("session.start", first.kind)
    assert.equals(0, first.seq)
    assert.equals("crashed-id", first.data.prev_session_id)
  end)

  it("scenario 3: a corrupt prior .slog is quarantined and recorder.recovered_from_corruption follows session.start", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local manifest = activated_manifest(fx, workspace)

    local bad_path = provenance_dir .. "/session-bad.slog"
    scratch.write_file(bad_path, "{not ndjson garbage at all")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    -- (a) the corrupt file is gone; a quarantine file exists in its place.
    assert.is_nil(vim.uv.fs_stat(bad_path))

    local quarantined_name = nil
    for _, name in ipairs(vim.fn.readdir(provenance_dir)) do
      if name:match("^session%-bad%.slog%.corrupt%-") then
        quarantined_name = name
      end
    end
    assert.is_not_nil(quarantined_name)
    local quarantined_path = provenance_dir .. "/" .. quarantined_name
    assert.is_true(vim.uv.fs_stat(quarantined_path) ~= nil)

    -- (b) the new .slog's seq 1 entry reports the exact quarantine path.
    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.is_true(parsed.ok)
    assert.equals("session.start", parsed.value[1].kind)
    assert.equals(0, parsed.value[1].seq)
    assert.equals(core_json.NULL, parsed.value[1].data.prev_session_id)

    local second = parsed.value[2]
    assert.equals("recorder.recovered_from_corruption", second.kind)
    assert.equals(1, second.seq)
    assert.equals(quarantined_path, second.data.quarantined_path)

    assert.is_true(core_chain_validator.validate_chain(parsed.value).ok)
  end)

  it(
    "scenario 4: a REAL write error (read-only .provenance dir) flips degraded, "
      .. "notifies once, chains recorder.degraded, and drops non-critical entries while "
      .. "retaining critical ones -- with no hang",
    function()
      local notify_calls = {}
      local _, provenance_dir, buf = start_activated_session(fx, scratch, {
        notify = function(message)
          table.insert(notify_calls, message)
        end,
      })

      -- Nothing has flushed yet (fixed clock never satisfies the
      -- time-based autoflush, and the buffered bytes are tiny) -- the .slog
      -- file does not exist on disk at all yet.
      local st = vim.uv.fs_stat(scratch.session.slog_path)
      assert.is_not_nil(st, ".slog is created empty at session start")
      assert.equals(0, st.size, "nothing has been flushed yet")
      assert.is_false(scratch.session.is_degraded())

      -- Strip write permission from .provenance so the NEXT flush attempt's
      -- fs_open(slog_path, "a") genuinely fails with EACCES -- a real
      -- writer.on_error -> disk_full.handle_write_error, not the test hook.
      scratch.lock_dir(provenance_dir)
      scratch.lock_file(scratch.session.slog_path)

      -- Force a flush: seal() drains the checkpoint scheduler then calls
      -- writer.flush() directly. The flush fails (EACCES creating the new
      -- .slog file in a read-only directory); seal_bundle then finds zero
      -- .slog files on disk (the file was never created) and returns
      -- {kind="no_sessions"} -- an unrelated, harmless side effect. What we
      -- care about is the flush failure's cascade, asserted below.
      assert.has_no.errors(function()
        scratch.session.seal({ now = function() return "2026-07-17T00:00:00.000Z" end })
      end)

      assert.is_true(scratch.session.is_degraded())
      assert.equals(1, #notify_calls)

      local kinds = ring_kinds(scratch.session)
      assert.is_true(contains(kinds, "recorder.degraded"))

      -- NON-CRITICAL entries after degrade are dropped: not in the ring, and
      -- (since routing bypasses the writer entirely once degraded) never
      -- reach the .slog either.
      make_entry(buf)
      local kinds_after_edit = ring_kinds(scratch.session)
      assert.is_false(contains(kinds_after_edit, "doc.change"))

      -- CRITICAL entries ARE retained: stop()'s session.end must survive.
      assert.has_no.errors(function()
        scratch.session.stop("deactivate")
      end)
      local final_kinds = ring_kinds(scratch.session)
      assert.is_true(contains(final_kinds, "session.end"))

      -- No hang: reaching this line already proves seal()/make_entry/stop()
      -- all returned promptly (no infinite loop from the reentrant
      -- recorder.degraded emit).
    end
  )

  it("scenario 5: no-retry invariant -- dropped buffered lines are never later written to the .slog", function()
    local _, provenance_dir, _ = start_activated_session(fx, scratch)

    local st = vim.uv.fs_stat(scratch.session.slog_path)
      assert.is_not_nil(st, ".slog is created empty at session start")
      assert.equals(0, st.size, "nothing has been flushed yet")

    -- Force the same real write error as scenario 4: session.start (and any
    -- catch-up doc.open) are sitting in the writer's buffer, unflushed.
    scratch.lock_dir(provenance_dir)
    scratch.lock_file(scratch.session.slog_path)
    scratch.session.seal({ now = function() return "2026-07-17T00:00:00.000Z" end })

    assert.is_true(scratch.session.is_degraded())
    -- The failed flush's fail() path drops the buffer instead of preserving
    -- it for retry -- the .slog was never created.
    local st = vim.uv.fs_stat(scratch.session.slog_path)
      assert.is_not_nil(st, ".slog is created empty at session start")
      assert.equals(0, st.size, "nothing has been flushed yet")

    -- Restore write permission -- as if disk space were freed. If there
    -- were any retry/resume logic, this is where the previously-dropped
    -- session.start would reappear on disk.
    scratch.unlock_dirs()

    -- Drive more activity and stop the session (both flush the writer via
    -- writer.dispose(), and stop() also chains a fresh session.end).
    assert.has_no.errors(function()
      scratch.session.stop("deactivate")
    end)

    -- No retry happened: the .slog is still absent from disk. The dropped
    -- session.start (and any pre-degrade entries) are gone for good, and no
    -- later write ever recreates the file -- once degraded, all routing
    -- bypasses the writer permanently for this session.
    local st = vim.uv.fs_stat(scratch.session.slog_path)
      assert.is_not_nil(st, ".slog is created empty at session start")
      assert.equals(0, st.size, "nothing has been flushed yet")
  end)

  it("scenario 6: crossing the size threshold ARMS the rotation on the checkpoint-cadence branch but does not rotate, and it fires only after a quiet window, exactly once, naming the ended session's own id", function()
    local rotate_calls = {}
    local fake_clock = core_clock.fixed(0, 0)
    -- rotate_bytes = 1: any real entry (session.start alone is already far
    -- more than one byte) crosses the threshold immediately. This isolates
    -- exactly the property under test: the check is gated by cadence
    -- (checkpoint_interval = 3), not run per entry -- if it ran per entry,
    -- the rotation would be armed before start_activated_session even returns.
    -- The hard ceiling is pushed out of reach so this scenario exercises ONLY
    -- the idle gate (scenario 6b covers the ceiling).
    local _, _, buf = start_activated_session(fx, scratch, {
      clock = fake_clock,
      checkpoint_interval = 3,
      rotate_bytes = 1,
      rotate_hard_ceiling_bytes = math.huge,
      rotate_idle_quiet_ms = 2000,
      -- The real poll timer is pushed far out of the test's lifetime so the
      -- quiet-window check happens ONLY when this test drives it via
      -- _rotation_idle_tick against the injected clock. Determinism, not a
      -- behavioural claim: production polls every ROTATE_IDLE_POLL_MS.
      rotate_idle_poll_ms = 600000,
      on_rotate_needed = function(ended_id)
        table.insert(rotate_calls, ended_id)
      end,
    })

    -- session.start + the catch-up/open pass for `buf` are on the log by
    -- now, but that is fewer than 3 total on_entry calls, so the cadence
    -- branch has not run once yet -- no rotation check has happened despite
    -- bytes_appended() already exceeding rotate_bytes.
    assert.is_false(scratch.session._rotation_armed())
    assert.equals(0, #rotate_calls)

    -- The next appended entry is the 3rd on_entry call overall: cadence fires,
    -- the (already-crossed) byte check runs for the first time -- and ARMS.
    -- Nothing rotates: a rotation mid-burst drops whatever is typed during the
    -- predecessor's teardown, and a dropped edit across the seam makes
    -- inter_session_external_change accuse the student (design §3.3).
    make_entry(buf)
    assert.is_true(scratch.session._rotation_armed())
    vim.wait(50)
    assert.equals(0, #rotate_calls, "arming must not rotate")

    -- Still inside the quiet window -> still no rotation.
    fake_clock.advance(1999)
    scratch.session._rotation_idle_tick()
    vim.wait(50)
    assert.equals(0, #rotate_calls)

    -- STILL TYPING: a doc.change pushes the quiet window out again, so even a
    -- clock well past the interval does not rotate. This is the "never
    -- mid-burst" property.
    fake_clock.advance(5000)
    make_entry(buf)
    scratch.session._rotation_idle_tick()
    vim.wait(50)
    assert.equals(0, #rotate_calls, "a doc.change must reset the quiet window")

    -- Quiet at last.
    fake_clock.advance(2000)
    scratch.session._rotation_idle_tick()
    local fired = vim.wait(500, function()
      return #rotate_calls > 0
    end, 10)
    assert.is_true(fired, "the rotation should fire after the quiet window elapses")
    assert.equals(1, #rotate_calls)
    assert.equals(scratch.session.session_id, rotate_calls[1])

    -- `rotation_fired` latches: further entries, further cadence hits and
    -- further ticks must not fire it again.
    for _ = 1, 6 do
      make_entry(buf)
    end
    fake_clock.advance(10000)
    scratch.session._rotation_idle_tick()
    vim.wait(100)
    assert.equals(1, #rotate_calls)
  end)

  it("scenario 6b: past the hard ceiling the rotation fires without ever seeing a quiet window", function()
    local rotate_calls = {}
    local fake_clock = core_clock.fixed(0, 0)
    -- Both thresholds at 1 byte: the first cadence hit is already past the HARD
    -- CEILING, so the idle gate is bypassed entirely. The clock is never
    -- advanced and _rotation_idle_tick is never called, so if the rotation
    -- fires it can only be the ceiling path. A session that types continuously
    -- must not grow unbounded -- an unpushable repo is the worse outcome -- and
    -- this is the one path on which an edit can still be lost.
    local _, _, buf = start_activated_session(fx, scratch, {
      clock = fake_clock,
      checkpoint_interval = 3,
      rotate_bytes = 1,
      rotate_hard_ceiling_bytes = 1,
      rotate_idle_quiet_ms = 2000,
      on_rotate_needed = function(ended_id)
        table.insert(rotate_calls, ended_id)
      end,
    })

    assert.equals(0, #rotate_calls)
    make_entry(buf)
    local fired = vim.wait(500, function()
      return #rotate_calls > 0
    end, 10)
    assert.is_true(fired, "the hard ceiling must rotate regardless of the quiet window")
    assert.equals(1, #rotate_calls)
    assert.equals(scratch.session.session_id, rotate_calls[1])
    -- The ceiling fires directly; it never bothers arming the idle poller.
    assert.is_false(scratch.session._rotation_armed())
  end)

  it("scenario 6c: skip_chain_recovery means the successor never touches the predecessor's log", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local manifest = activated_manifest(fx, workspace)

    -- Proof BY CONSTRUCTION (design §5 item 6): a recovery seam that fails the
    -- test if it is invoked at all. In this port recovery reads, parses and
    -- chain-validates the whole predecessor log SYNCHRONOUSLY ON THE MAIN LOOP,
    -- which at 40 MiB of pure-Lua JCS + SHA-256 freezes the editor -- precisely
    -- while no wiring is attached and every keystroke is being dropped.
    local recovery_calls = 0
    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
      prev_session_id = "predecessor-session-id",
      skip_chain_recovery = true,
      recover = function()
        recovery_calls = recovery_calls + 1
        error("chain recovery must not run on the rotation path")
      end,
    })
    scratch.session.stop()

    assert.equals(0, recovery_calls, "the rotation path must not run chain recovery")

    -- The link is still recorded -- the successor was TOLD its predecessor's id,
    -- which is exactly why recovery is pointless here.
    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.is_true(parsed.ok)
    assert.equals("predecessor-session-id", parsed.value[1].data.prev_session_id)
  end)

  it("scenario 6d: without skip_chain_recovery an ordinary activation DOES run recovery (negative control for 6c)", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local manifest = activated_manifest(fx, workspace)

    local recovery_calls = 0
    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
      recover = function()
        recovery_calls = recovery_calls + 1
        return { kind = "clean_start" }
      end,
    })
    scratch.session.stop()

    assert.equals(1, recovery_calls)
  end)

  it("scenario 6e: EVERY content-mutating event defers an armed rotation -- fs.external_change and paste, not just doc.change -- while a non-content event does not", function()
    local rotate_calls = {}
    local fake_clock = core_clock.fixed(0, 0)
    local _, _, buf = start_activated_session(fx, scratch, {
      clock = fake_clock,
      checkpoint_interval = 3,
      rotate_bytes = 1,
      rotate_hard_ceiling_bytes = math.huge,
      rotate_idle_quiet_ms = 2000,
      -- As in scenario 6: the real poller is pushed past this test's lifetime so
      -- the quiet-window check happens only when the test drives it.
      rotate_idle_poll_ms = 600000,
      on_rotate_needed = function(ended_id)
        table.insert(rotate_calls, ended_id)
      end,
    })

    -- Arm on the 3rd on_entry call, exactly as scenario 6 does.
    make_entry(buf)
    assert.is_true(scratch.session._rotation_armed())

    fake_clock.advance(1999)
    scratch.session._rotation_idle_tick()
    -- fire_rotation hands off via vim.schedule, so the loop MUST be pumped
    -- before concluding that nothing fired -- otherwise the assertion passes
    -- vacuously and the test pins nothing.
    vim.wait(50)
    assert.equals(0, #rotate_calls)

    -- THE CASE THIS SCENARIO EXISTS FOR. An external write -- formatter-on-save,
    -- `git checkout`, a partner's write -- landing inside the teardown window is
    -- dropped exactly as a keystroke would be, and diverges the seam the same
    -- way. Worse, in fact: a whole-file rewrite clears
    -- highSeverityCharsChanged, so the false inter_session_external_change is
    -- reported at HIGH severity. Emitted through the session's own host, the
    -- same chokepoint the external-change coordinator uses in production.
    scratch.session._host.emit("fs.external_change", {
      path = "foo.txt",
      direction = "disk_ahead",
      expected_sha256 = string.rep("a", 64),
      actual_sha256 = string.rep("b", 64),
    })
    fake_clock.advance(1999)
    scratch.session._rotation_idle_tick()
    vim.wait(50)
    assert.equals(
      0,
      #rotate_calls,
      "fs.external_change must reset the quiet window (3998ms have now elapsed since arming, well past 2000)"
    )

    -- A paste does too.
    scratch.session._host.emit("paste", { path = "foo.txt", chars = 120 })
    fake_clock.advance(1999)
    scratch.session._rotation_idle_tick()
    vim.wait(50)
    assert.equals(0, #rotate_calls, "paste must reset the quiet window")

    -- A heartbeat does NOT: it mutates no file, so losing one across the seam
    -- cannot make the two sides differ -- and if it reset the window, a
    -- genuinely idle session could never rotate at all.
    scratch.session._host.emit("session.heartbeat", {
      focused = true,
      active_file = core_json.NULL,
      idle_since_ms = 0,
    })
    fake_clock.advance(1)
    scratch.session._rotation_idle_tick()
    local fired = vim.wait(500, function()
      return #rotate_calls > 0
    end, 10)
    assert.is_true(fired, "a non-content event must not defer the rotation")
    assert.equals(1, #rotate_calls)
    assert.equals(scratch.session.session_id, rotate_calls[1])
  end)

  it("scenario 6f: a session that degrades AFTER arming never rotates -- the idle poll is a second trigger and must be gated too", function()
    local rotate_calls = {}
    local fake_clock = core_clock.fixed(0, 0)
    local _, _, buf = start_activated_session(fx, scratch, {
      clock = fake_clock,
      checkpoint_interval = 3,
      rotate_bytes = 1,
      rotate_hard_ceiling_bytes = math.huge,
      rotate_idle_quiet_ms = 2000,
      rotate_idle_poll_ms = 600000,
      -- Silence the degraded notification; scenario 4 already pins it.
      notify = function() end,
      on_rotate_needed = function(ended_id)
        table.insert(rotate_calls, ended_id)
      end,
    })

    -- Arm on the cadence branch, while the session is still healthy. "A degraded
    -- session never rotates" was argued from on_entry's degraded branch
    -- returning before the cadence branch -- but that only ever covered the
    -- ENTRY path, and the poll timer is a SECOND, INDEPENDENT trigger.
    make_entry(buf)
    assert.is_true(scratch.session._rotation_armed())
    assert.is_false(scratch.session.is_degraded())

    -- The disk fills. Degraded is a ONE-WAY state.
    scratch.session._simulate_write_error("ENOSPC")
    assert.is_true(scratch.session.is_degraded())

    -- The student pauses to read the error notification -- which is exactly the
    -- quiet window the gate is waiting for, with the byte counter frozen at or
    -- above the threshold. Before the guard, the tick fired here: the
    -- predecessor would be stopped and its rolling seal would claim final = true
    -- over a `.slog` whose own session.end was never written (degraded diverts
    -- entries to the in-memory critical ring), and the successor would start
    -- recording onto a disk that is still full.
    fake_clock.advance(5000)
    scratch.session._rotation_idle_tick()
    -- Pumped before asserting the negative: fire_rotation hands off via
    -- vim.schedule, so an unpumped assertion passes vacuously (see 6e).
    vim.wait(100)
    assert.equals(0, #rotate_calls, "a degraded session must not rotate, via the poll path either")

    -- Still true however long it stays quiet: abandoned, not merely deferred.
    fake_clock.advance(60000)
    scratch.session._rotation_idle_tick()
    vim.wait(100)
    assert.equals(0, #rotate_calls)
  end)

  it("scenario 7: end-to-end rotation -- the old session ends with reason 'rotate', the replacement links prev_session_id to its LOGICAL id, and both chains validate", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local manifest = activated_manifest(fx, workspace)

    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line0\n")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
    })
    local buf = scratch.edit(path)
    make_entry(buf)

    local ended_id = scratch.session.session_id
    local first_slog_path = scratch.session.slog_path

    -- Stop-then-start (never the reverse): the replacement is only started
    -- below, after the first session's autocmds have fully detached.
    scratch.session.stop("rotate")

    local first_parsed = core_ndjson.parse_entries(read_all(first_slog_path))
    assert.is_true(first_parsed.ok)
    assert.is_true(core_chain_validator.validate_chain(first_parsed.value).ok)
    local last_entry = first_parsed.value[#first_parsed.value]
    assert.equals("session.end", last_entry.kind)
    assert.equals("rotate", last_entry.data.reason)

    -- The replacement, in the SAME provenance_dir, with prev_session_id set
    -- to the ended session's LOGICAL session_id (two-uuid rule) -- never the
    -- `.slog` filename uuid.
    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
      prev_session_id = ended_id,
    })
    -- Force the buffered session.start (+ catch-up doc.open) onto disk
    -- before reading it back; stop() is idempotent and teardown() will
    -- no-op on it.
    scratch.session.stop()

    local second_parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.is_true(second_parsed.ok)
    assert.is_true(core_chain_validator.validate_chain(second_parsed.value).ok)
    assert.equals("session.start", second_parsed.value[1].kind)
    assert.equals(ended_id, second_parsed.value[1].data.prev_session_id)

    -- The replacement's own catch-up pass re-baselines the still-open
    -- buffer with its own doc.open (§3.3 buffer-sourced baselines) --
    -- distinct from, and in addition to, the first session's doc.open.
    local has_doc_open = false
    for _, e in ipairs(second_parsed.value) do
      if e.kind == "doc.open" then
        has_doc_open = true
      end
    end
    assert.is_true(has_doc_open, "the replacement session must emit its own doc.open for the open buffer")
  end)
end)
