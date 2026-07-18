--- recording_session.start — chain recovery wiring (Plan 8, Task 5).
--- Exercises the real seam: chain_recovery.recover_previous_session run
--- over the real vim.uv deps layer (uv_recovery_deps), BEFORE this
--- session's own artifacts exist, so it only ever sees a PRIOR session's
--- `.slog`. Mirrors recording_session_spec.lua's real-temp-dir approach —
--- prior `.slog` files are built with core.hash_chain the same way
--- chain_recovery_spec.lua / seal_spec.lua build chained slogs.
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")
local core_ndjson = require("provenance.core.ndjson")
local core_json = require("provenance.core.json")
local core_hash_chain = require("provenance.core.hash_chain")
local core_envelope = require("provenance.core.envelope")

--- Track everything created by a test so it can be torn down afterward
--- (mirrors recording_session_spec.lua's new_scratch()).
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

  function scratch.teardown()
    if scratch.session then
      scratch.session.stop()
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
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

--- A minimal dev manifest with a real 128-hex signature (same convention as
--- recording_session_spec.lua / meta_writer_spec.lua / seal_spec.lua).
local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
end

--- Build a real chained prior `.slog`'s raw NDJSON text (mirrors
--- chain_recovery_spec.lua's build_chain/serialize): session.start
--- (data.session_id = session_id), optionally followed by a clean
--- session.end. Omitting the session.end makes it DANGLING.
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

describe("recording_session.start — chain recovery wiring", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("clean start: no prior .slog -> session.start.prev_session_id is JSON null, no recovery event", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    local first = parsed.value[1]
    assert.equals("session.start", first.kind)
    assert.equals(core_json.NULL, first.data.prev_session_id)

    for _, e in ipairs(parsed.value) do
      assert.are_not.equals("recorder.recovered_from_corruption", e.kind)
    end
  end)

  it("dangling prior session links prev_session_id via real recovery over vim.uv", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(provenance_dir .. "/session-aaa.slog", build_prior_slog_text("crashed-id", false))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    local first = parsed.value[1]
    assert.equals("session.start", first.kind)
    assert.equals("crashed-id", first.data.prev_session_id)
  end)

  it("a complete prior session is not linked (prev_session_id stays null)", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(provenance_dir .. "/session-aaa.slog", build_prior_slog_text("finished-id", true))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    local first = parsed.value[1]
    assert.equals(core_json.NULL, first.data.prev_session_id)
  end)

  it("an explicit opts.prev_session_id override wins over the recovery decision", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(provenance_dir .. "/session-aaa.slog", build_prior_slog_text("crashed-id", false))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
      prev_session_id = "explicit-override-id",
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    local first = parsed.value[1]
    assert.equals("explicit-override-id", first.data.prev_session_id)
  end)

  it(
    "corrupt prior session is quarantined on disk and recorder.recovered_from_corruption "
      .. "follows session.start as seq 1",
    function()
      local workspace = scratch.workspace()
      local provenance_dir = workspace .. "/.provenance"
      vim.fn.mkdir(provenance_dir, "p")

      local bad_path = provenance_dir .. "/session-bad.slog"
      scratch.write_file(bad_path, "{not ndjson garbage")

      scratch.session = recording_session.start({
        workspace = workspace,
        provenance_dir = provenance_dir,
        manifest = dev_manifest(),
        clock = core_clock.fixed(0, 0),
      })
      scratch.session.stop()

      -- The original corrupt file is gone; a quarantine file exists in its
      -- place, named `<original>.corrupt-<ts>`.
      assert.is_nil(vim.uv.fs_stat(bad_path))

      local names = vim.fn.readdir(provenance_dir)
      local quarantined_name = nil
      for _, name in ipairs(names) do
        if name:match("^session%-bad%.slog%.corrupt%-") then
          quarantined_name = name
        end
      end
      assert.is_not_nil(quarantined_name)
      local quarantined_path = provenance_dir .. "/" .. quarantined_name
      assert.is_true(vim.uv.fs_stat(quarantined_path) ~= nil)

      local text = read_all(scratch.session.slog_path)
      local parsed = core_ndjson.parse_entries(text)
      assert.is_true(parsed.ok)
      assert.is_true(#parsed.value >= 2)

      assert.equals("session.start", parsed.value[1].kind)
      assert.equals(0, parsed.value[1].seq)
      assert.equals(core_json.NULL, parsed.value[1].data.prev_session_id)

      local second = parsed.value[2]
      assert.equals("recorder.recovered_from_corruption", second.kind)
      assert.equals(1, second.seq)
      assert.equals(quarantined_path, second.data.quarantined_path)

      local chain = require("provenance.core.chain_validator").validate_chain(parsed.value)
      assert.is_true(chain.ok)
    end
  )
end)
