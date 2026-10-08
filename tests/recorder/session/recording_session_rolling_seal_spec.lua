--- recording_session ROLLING SEAL wiring (program spec §8, S3).
---
--- Proves the three write points and — the part that actually adjudicates
--- cases — that `final` appears on exactly one of them. Real headless Neovim,
--- real vim.uv I/O, same seam as recording_session_checkpoints_spec.lua, with a
--- small injected `checkpoint_interval` so cadence boundaries are cheap to drive.
---
--- The extension hash is injected: compute_installed() walks the whole `lua/`
--- tree, which is slow and irrelevant here, and pinning it keeps the canonical
--- bytes deterministic across runs.
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")
local rolling = require("provenance.core.rolling_manifest")
local bundle = require("provenance.core.bundle")
local sha256 = require("provenance.core.sha256")

local FAKE_EXT_HASH = string.rep("1", 64)

local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, session = nil }

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

  local next_line = 0
  function scratch.make_entry(buf)
    next_line = next_line + 1
    local n = vim.api.nvim_buf_line_count(buf)
    vim.api.nvim_buf_set_lines(buf, n, n, false, { "line-" .. tostring(next_line) })
  end

  function scratch.teardown()
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
  return table.concat(vim.fn.readfile(path, "b"), "\n")
end

local function exists(path)
  return (vim.uv or vim.loop).fs_stat(path) ~= nil
end

local function dev_manifest(extra)
  return vim.tbl_extend("force", {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }, extra or {})
end

describe("recording_session rolling seal wiring", function()
  local scratch, workspace, provenance_dir

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  local function start_session(extra_opts, manifest_extra)
    workspace = scratch.workspace()
    provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line0\n")

    local opts = vim.tbl_extend("force", {
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(manifest_extra),
      clock = core_clock.fixed(0, 0),
      checkpoint_interval = 3,
      compute_extension_hash = function()
        return FAKE_EXT_HASH
      end,
    }, extra_opts or {})

    scratch.session = recording_session.start(opts)
    return scratch.edit(path)
  end

  local function seal_paths()
    local names = rolling.filenames(scratch.session.session_id)
    return provenance_dir .. "/" .. names.json, provenance_dir .. "/" .. names.sig
  end

  local function read_seal()
    local json_path, sig_path = seal_paths()
    local canonical = read_all(json_path)
    return {
      canonical_json = canonical,
      manifest = vim.json.decode(canonical),
      signature_hex = read_all(sig_path),
    }
  end

  -- --- write point 1: session start ----------------------------------------

  it("WRITE POINT 1: a session is sealed from its first instant", function()
    -- A session that records only session.start never reaches a checkpoint, and
    -- in a git-submitted repo its `.slog` would otherwise be committed with no
    -- seal covering it at all.
    start_session()
    local json_path, sig_path = seal_paths()
    assert.is_true(exists(json_path), "no seal was written at session start")
    assert.is_true(exists(sig_path))

    local seal = read_seal()
    assert.equals("1.2", seal.manifest.format_version)
    assert.equals("hw3", seal.manifest.assignment_id)
    assert.equals("fa25", seal.manifest.semester)
    assert.equals(FAKE_EXT_HASH, seal.manifest.extension_hash)
  end)

  it("the seal covers exactly this session, named by the LOGICAL session id", function()
    start_session()
    local seal = read_seal()

    assert.equals(1, #seal.manifest.sessions)
    assert.equals(scratch.session.session_id, seal.manifest.sessions[1].session_id)

    -- The filename binding: the id in the name and the id in the payload agree.
    local parsed = rolling.parse_filename(vim.fn.fnamemodify((seal_paths()), ":t"))
    assert.is_table(parsed)
    assert.equals(scratch.session.session_id, parsed.session_id)
    local res = rolling.validate_session_manifest(seal.manifest, parsed.session_id)
    assert.is_true(res.ok, res.error and rolling.describe_error(res.error))

    -- And NOT the `.slog` filename uuid (two-uuid rule).
    local file_uuid = vim.fn.fnamemodify(scratch.session.slog_path, ":t"):match("^session%-(.*)%.slog$")
    assert.is_string(file_uuid)
    assert.are_not.equal(file_uuid, scratch.session.session_id)
  end)

  it("the seal is signed by this session's own ephemeral key", function()
    start_session()
    local seal = read_seal()
    assert.is_true(bundle.verify_sig(seal.canonical_json, seal.signature_hex, scratch.session.public_key_hex))
  end)

  -- --- write point 2: every checkpoint --------------------------------------

  it("WRITE POINT 2: the seal is rewritten after each checkpoint lands", function()
    local buf = start_session()
    local first = read_seal()

    -- interval=3: session.start (seq 0) + 2 edits fires the cadence at seq 2.
    scratch.make_entry(buf)
    scratch.make_entry(buf)
    vim.wait(200, function()
      return read_all((seal_paths())) ~= first.canonical_json
    end)

    local second = read_seal()
    assert.are_not.equal(first.canonical_json, second.canonical_json, "the seal did not roll on the checkpoint")
    assert.is_true(bundle.verify_sig(second.canonical_json, second.signature_hex, scratch.session.public_key_hex))

    -- The rewritten seal commits to the log AS IT NOW STANDS, and the
    -- checkpoint is inside the `.meta` it hashes.
    assert.equals(sha256.hex(read_all(scratch.session.slog_path)), second.manifest.sessions[1].slog_sha256)
    assert.equals(sha256.hex(read_all(scratch.session.meta_path)), second.manifest.sessions[1].meta_sha256)
    assert.is_true(#vim.json.decode(read_all(scratch.session.meta_path)).checkpoints > 0)
  end)

  it("mid-session rolls are NOT final — the log is still growing", function()
    local buf = start_session()
    assert.is_false(rolling.is_final(read_seal().manifest))

    scratch.make_entry(buf)
    scratch.make_entry(buf)
    vim.wait(200, function()
      return #vim.json.decode(read_all(scratch.session.meta_path)).checkpoints > 0
    end)

    local seal = read_seal()
    assert.is_false(rolling.is_final(seal.manifest), "a checkpoint roll must never claim finality")
    assert.is_nil(seal.manifest["final"], "`final` must be ABSENT, not false")
    assert.is_nil(string.find(seal.canonical_json, "final", 1, true))
  end)

  -- --- write point 3: teardown ----------------------------------------------

  it("WRITE POINT 3: stop() writes a FINAL seal over the fully flushed log", function()
    local buf = start_session()
    scratch.make_entry(buf)
    scratch.session.stop()

    local seal = read_seal()
    assert.is_true(rolling.is_final(seal.manifest), "the teardown roll must claim finality")
    assert.is_true(seal.manifest["final"])
    assert.is_true(bundle.verify_sig(seal.canonical_json, seal.signature_hex, scratch.session.public_key_hex))

    -- WHOLE-FILE, not a prefix: the final digests match the closed files
    -- exactly, session.end included.
    local slog = read_all(scratch.session.slog_path)
    assert.equals(sha256.hex(slog), seal.manifest.sessions[1].slog_sha256)
    assert.equals(sha256.hex(read_all(scratch.session.meta_path)), seal.manifest.sessions[1].meta_sha256)
    assert.is_not_nil(string.find(slog, "session.end", 1, true))
  end)

  it("`final` is inside the SIGNED payload, so it cannot be added or stripped", function()
    start_session()
    scratch.session.stop()
    local seal = read_seal()

    local stripped = seal.canonical_json:gsub('"final":true,', "", 1)
    assert.are_not.equal(seal.canonical_json, stripped)
    assert.is_false(bundle.verify_sig(stripped, seal.signature_hex, scratch.session.public_key_hex))
  end)

  it("a session that never reaches stop() has NO final seal, and that is blameless", function()
    -- A crash, a power cut, a full disk, a `git checkout` that removes
    -- `.provenance/`: the last non-final seal simply stands. It is a coverage
    -- gap the reader REPORTS, never a tamper finding.
    local buf = start_session()
    scratch.make_entry(buf)
    scratch.make_entry(buf)
    vim.wait(200, function()
      return #vim.json.decode(read_all(scratch.session.meta_path)).checkpoints > 0
    end)

    local seal = read_seal()
    assert.is_false(rolling.is_final(seal.manifest))
    assert.is_nil(seal.manifest["final"])

    -- The seal that IS there is still a valid, signed prefix commitment.
    assert.is_true(bundle.verify_sig(seal.canonical_json, seal.signature_hex, scratch.session.public_key_hex))
  end)

  it("finality is NOT inferred from session.end being in the log", function()
    -- `session.end` lives in the log, and the log's completeness is the very
    -- thing in question — so a log that ends with session.end but whose session
    -- never cleanly tore down must NOT read as final. Here the entry is emitted
    -- through the ordinary host, exactly as a forger could append it, without
    -- stop() ever running.
    local buf = start_session()
    scratch.session._host.emit("session.end", { reason = "deactivate" })

    -- Wait for the writer's periodic flush so session.end is genuinely on disk.
    vim.wait(3000, function()
      return string.find(read_all(scratch.session.slog_path), "session.end", 1, true) ~= nil
    end, 20)
    local slog_with_end = read_all(scratch.session.slog_path)
    assert.is_not_nil(string.find(slog_with_end, "session.end", 1, true), "session.end must be on disk for this test")

    -- Now force a roll that hashes a log which ALREADY CONTAINS session.end.
    local before = read_seal().canonical_json
    for _ = 1, 3 do
      scratch.make_entry(buf)
    end
    vim.wait(3000, function()
      return read_all((seal_paths())) ~= before
    end, 20)

    local seal = read_seal()
    assert.are_not.equal(before, seal.canonical_json, "a roll must have happened after session.end landed")
    -- The seal genuinely covers a log containing session.end...
    assert.equals(sha256.hex(read_all(scratch.session.slog_path)), seal.manifest.sessions[1].slog_sha256)
    assert.is_not_nil(string.find(read_all(scratch.session.slog_path), "session.end", 1, true))
    -- ...and is still NOT final. Only a clean teardown may claim that.
    assert.is_false(rolling.is_final(seal.manifest), "session.end in the log must not promote a seal to final")
    assert.is_nil(seal.manifest["final"])
  end)

  it("stop() is idempotent and does not re-roll a second final seal", function()
    start_session()
    scratch.session.stop()
    local first = read_seal()
    scratch.session.stop()
    local second = read_seal()
    assert.equals(first.canonical_json, second.canonical_json)
    assert.equals(first.signature_hex, second.signature_hex)
  end)

  -- --- the classic seal is untouched ---------------------------------------

  it("no roll ever writes manifest.json / manifest.sig", function()
    local buf = start_session()
    for _ = 1, 8 do
      scratch.make_entry(buf)
    end
    vim.wait(200, function()
      return #vim.json.decode(read_all(scratch.session.meta_path)).checkpoints >= 2
    end)
    scratch.session.stop()

    assert.is_false(exists(provenance_dir .. "/manifest.json"))
    assert.is_false(exists(provenance_dir .. "/manifest.sig"))
    assert.same({}, vim.fn.glob(provenance_dir .. "/*.tmp", true, true))
  end)

  it("a classic :ProvenanceSeal bundle is byte-identical with the rolling seal running", function()
    local buf = start_session()
    scratch.make_entry(buf)
    local sealed = scratch.session.seal({
      now = function()
        return "2026-08-19T00:00:00.000Z"
      end,
    })
    assert.equals("ok", sealed.kind, sealed.message)

    -- The classic manifest is a 1.1 covering every session in the directory,
    -- signed as it always was — the rolling files beside it changed nothing.
    local classic = vim.json.decode(read_all(provenance_dir .. "/manifest.json"))
    assert.equals("1.1", classic.format_version)
    assert.is_nil(classic["final"])
    assert.is_true(bundle.verify_sig(
      read_all(provenance_dir .. "/manifest.json"),
      read_all(provenance_dir .. "/manifest.sig"),
      scratch.session.public_key_hex
    ))

    local before = sha256.hex(read_all(provenance_dir .. "/manifest.json"))
    scratch.session.stop() -- drives the final rolling roll
    assert.equals(before, sha256.hex(read_all(provenance_dir .. "/manifest.json")))
  end)

  -- --- gating ---------------------------------------------------------------

  it("suppressed only when the course SIGNED that it submits bundles", function()
    start_session(nil, { submission = "bundle" })
    local json_path, sig_path = seal_paths()
    assert.is_false(exists(json_path))
    assert.is_false(exists(sig_path))

    scratch.session.stop()
    assert.is_false(exists(json_path), "a suppressed session must not get a final seal either")
  end)

  it("a 1.x manifest (no `submission` field at all) still rolls", function()
    -- Not rolling where it IS needed costs an `unsealed_session` defect on every
    -- session — a false accusation against a student whose course simply has not
    -- migrated to a 2.0 manifest.
    start_session(nil, { submission = nil })
    assert.is_true(exists((seal_paths())))
  end)

  it("a git-submission manifest rolls", function()
    start_session(nil, { submission = "git" })
    assert.is_true(exists((seal_paths())))
  end)

  -- --- degraded path --------------------------------------------------------

  it("a seal failure never stops recording or raises", function()
    local buf = start_session()
    -- The ground moves under the session, exactly as a `git checkout` can do.
    vim.fn.delete(provenance_dir, "rf")

    local ok = pcall(function()
      for _ = 1, 8 do
        scratch.make_entry(buf)
      end
      vim.wait(100)
      scratch.session.stop()
    end)
    assert.is_true(ok, "a seal failure must never abort recording")
    -- Recording itself survived and kept the student's evidence. (The `.provenance/`
    -- directory may reappear here: session_writer.flush() does its own `mkdir -p`
    -- so a recording can outlive the ground moving. That is pre-existing writer
    -- behaviour and deliberately NOT shared by the seal — see
    -- rolling_seal_writer_spec's "does NOT recreate a .provenance/" case.)
    assert.is_not_nil(string.find(read_all(scratch.session.slog_path), "session.end", 1, true))
  end)

  it("a failing extension hash degrades the seal, not the session", function()
    local buf = start_session({
      compute_extension_hash = function()
        error("dist/ is missing")
      end,
    })
    local json_path = (seal_paths())
    assert.is_false(exists(json_path))

    local ok = pcall(function()
      scratch.make_entry(buf)
      scratch.session.stop()
    end)
    assert.is_true(ok)
    -- Recording itself is intact.
    assert.is_not_nil(string.find(read_all(scratch.session.slog_path), "session.end", 1, true))
  end)

  -- --- write point 4: debounced reseal after a save ---------------------------

  describe("reseal on save", function()
    local rolling_seal_writer = require("provenance.recorder.io.rolling_seal_writer")
    local orig_write, calls, timers, cancelled

    -- Deterministic timer seam: nothing fires until the test says so.
    local function fake_set_timer(ms, cb)
      local t = { ms = ms, cb = cb, live = true }
      timers[#timers + 1] = t
      return function()
        if t.live then
          t.live = false
          cancelled = cancelled + 1
        end
      end
    end

    local function fire_last()
      local t = timers[#timers]
      assert.is_true(t.live, "timer was cancelled")
      t.live = false
      t.cb()
    end

    local function live_timers()
      local n = 0
      for _, t in ipairs(timers) do
        if t.live then
          n = n + 1
        end
      end
      return n
    end

    before_each(function()
      calls, timers, cancelled = {}, {}, 0
      orig_write = rolling_seal_writer.write_rolling_seal
      rolling_seal_writer.write_rolling_seal = function(o)
        calls[#calls + 1] = { final = o.final }
        return orig_write(o)
      end
    end)

    after_each(function()
      rolling_seal_writer.write_rolling_seal = orig_write
    end)

    local function save(buf)
      scratch.make_entry(buf)
      vim.api.nvim_buf_call(buf, function()
        vim.cmd("silent write")
      end)
    end

    it("a save arms ONE timer; when it fires the seal covers the save", function()
      local buf = start_session({ checkpoint_interval = 1000, set_timer = fake_set_timer })
      local rolls_before = #calls
      local before = read_seal().canonical_json

      save(buf)
      assert.equals(1, live_timers())
      assert.equals(1000, timers[#timers].ms)
      assert.equals(rolls_before, #calls, "must not roll inline on the save")
      assert.equals(before, read_seal().canonical_json)

      fire_last()
      assert.equals(rolls_before + 1, #calls)
      assert.is_nil(calls[#calls].final)
      local seal = read_seal()
      assert.are_not.equal(before, seal.canonical_json)
      -- The digest covers a log that already contains the doc.save.
      local slog = read_all(scratch.session.slog_path)
      assert.is_not_nil(string.find(slog, "doc.save", 1, true))
      assert.equals(sha256.hex(slog), seal.manifest.sessions[1].slog_sha256)
      assert.is_true(bundle.verify_sig(seal.canonical_json, seal.signature_hex, scratch.session.public_key_hex))
      assert.is_false(rolling.is_final(seal.manifest))
    end)

    it("a burst of saves coalesces into a single roll", function()
      local buf = start_session({ checkpoint_interval = 1000, set_timer = fake_set_timer })
      local rolls_before = #calls

      save(buf)
      save(buf)
      save(buf)
      assert.equals(1, live_timers(), "each save re-arms; at most one is pending")
      assert.is_true(cancelled >= 2)

      fire_last()
      assert.equals(rolls_before + 1, #calls)
      assert.equals(0, live_timers())
    end)

    it("stop() cancels the pending reseal and the final roll is the last write", function()
      local buf = start_session({ checkpoint_interval = 1000, set_timer = fake_set_timer })
      save(buf)
      local pending = timers[#timers]
      assert.is_true(pending.live)
      local rolls_before = #calls

      scratch.session.stop()
      assert.is_false(pending.live, "stop() must cancel the pending timer")
      assert.equals(rolls_before + 1, #calls)
      assert.is_true(calls[#calls].final)

      -- Even a stale callback that somehow still fires writes nothing.
      local final_json = read_seal().canonical_json
      pending.cb()
      assert.equals(rolls_before + 1, #calls)
      assert.equals(final_json, read_seal().canonical_json)
      assert.is_true(rolling.is_final(read_seal().manifest))
    end)

    it("a bundle-submission course never arms a reseal timer", function()
      local buf = start_session({ checkpoint_interval = 1000, set_timer = fake_set_timer }, { submission = "bundle" })
      save(buf)
      assert.equals(0, #timers)
      local json_path = seal_paths()
      assert.is_false(exists(json_path))
    end)

    it("the default timer really fires (unref'd libuv timer)", function()
      local buf = start_session({ checkpoint_interval = 1000, reseal_debounce_ms = 20 })
      local rolls_before = #calls
      save(buf)
      vim.wait(2000, function()
        return #calls > rolls_before
      end, 10)
      assert.equals(rolls_before + 1, #calls)
    end)
  end)
end)
