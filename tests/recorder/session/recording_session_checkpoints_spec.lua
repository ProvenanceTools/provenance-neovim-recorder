--- recording_session checkpoint wiring (Plan 8, Task 3). Proves the
--- checkpoint cadence (Task 1) + async scheduler (Task 2) are correctly
--- composed into the live session's on_entry path: writer.append runs
--- first (entry always persisted to the `.slog`), then — when not
--- degraded — the cadence decides whether to schedule a signed seq->hash
--- checkpoint, which lands in `.slog.meta`'s `checkpoints` array once
--- drained (synchronously, at stop()). Real headless Neovim, real vim.uv
--- I/O — same seam as recording_session_spec.lua, with an injected small
--- `checkpoint_interval` so cadence boundaries are cheap and deterministic
--- to drive via real buffer edits instead of waiting for 100 real entries.
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")
local core_checkpoint = require("provenance.core.checkpoint")

--- Track everything created by a test so it can be torn down afterward:
--- session ALWAYS stopped (idempotent, safe even if the test already
--- stopped it), buffers wiped, temp dirs deleted. Mirrors
--- recording_session_spec.lua's new_scratch().
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

  --- Opens `path` in the current window via :edit and returns the bufnr.
  --- Tracked for wipeout in teardown().
  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  --- Appends one line to `buf`, each call producing exactly one
  --- nvim_buf_attach on_lines callback -> exactly one doc.change entry
  --- (doc_wiring's default, un-routed on_lines path is 1:1 with the
  --- editor call — see doc_wiring.lua).
  local next_line = 0
  function scratch.make_entry(buf)
    next_line = next_line + 1
    local n = vim.api.nvim_buf_line_count(buf)
    vim.api.nvim_buf_set_lines(buf, n, n, false, { "line-" .. tostring(next_line) })
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

local function read_meta(session)
  local text = read_all(session.meta_path)
  return vim.json.decode(text)
end

--- A minimal dev manifest with a real 128-hex signature (encrypt_privkey
--- only uses it as HKDF input material, so any 128-hex string works — same
--- convention as meta_writer_spec.lua / seal_spec.lua / recording_session_spec.lua).
local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
end

local function is_64_hex(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

local function is_128_hex(v)
  return type(v) == "string" and #v == 128 and v:match("^[0-9a-f]+$") ~= nil
end

describe("recording_session checkpoint wiring", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  --- Starts a session against a fresh workspace with one recordable buffer
  --- open, ready for scratch.make_entry(buf) to drive further entries.
  local function start_session(extra_opts)
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line0\n")

    local opts = vim.tbl_extend("force", {
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    }, extra_opts or {})

    scratch.session = recording_session.start(opts)
    local buf = scratch.edit(path)
    return buf
  end

  it("fires a checkpoint at the right seq: interval=3, 2 edits -> 1 checkpoint at seq 2, signature verifies", function()
    local buf = start_session({ checkpoint_interval = 3 })

    -- session.start = seq 0 (entry 1). 2 edits -> doc.change seq 1, seq 2
    -- (entries 2, 3) -> the 3rd on_entry call fires the cadence.
    scratch.make_entry(buf)
    scratch.make_entry(buf)

    scratch.session.stop() -- drains any pending checkpoint

    local meta = read_meta(scratch.session)
    assert.equals(1, #meta.checkpoints)

    local cp = meta.checkpoints[1]
    assert.equals(2, cp.seq)
    assert.is_true(is_64_hex(cp.hash))
    assert.is_true(is_128_hex(cp.sig))
    assert.is_true(core_checkpoint.verify(cp, scratch.session.public_key_hex))
  end)

  it("multiple checkpoints: interval=3, 5 edits -> checkpoints at seq 2 and seq 5, in order", function()
    local buf = start_session({ checkpoint_interval = 3 })

    for _ = 1, 5 do
      scratch.make_entry(buf)
    end

    scratch.session.stop()

    local meta = read_meta(scratch.session)
    assert.equals(2, #meta.checkpoints)
    assert.equals(2, meta.checkpoints[1].seq)
    assert.equals(5, meta.checkpoints[2].seq)
    assert.is_true(core_checkpoint.verify(meta.checkpoints[1], scratch.session.public_key_hex))
    assert.is_true(core_checkpoint.verify(meta.checkpoints[2], scratch.session.public_key_hex))
  end)

  it("session ended right at a boundary: interval=3, 1 edit + stop's session.end -> 1 checkpoint at seq 2, captured by drain-at-stop", function()
    local buf = start_session({ checkpoint_interval = 3 })

    -- session.start(seq0) + 1 edit(seq1) = 2 entries; stop()'s session.end
    -- is the 3rd entry (seq2) -> cadence fires on that 3rd on_entry call.
    scratch.make_entry(buf)

    scratch.session.stop()

    local meta = read_meta(scratch.session)
    assert.equals(1, #meta.checkpoints)
    assert.equals(2, meta.checkpoints[1].seq)
    assert.is_true(core_checkpoint.verify(meta.checkpoints[1], scratch.session.public_key_hex))
  end)

  it("default interval is 100: a short session (a few entries) produces no checkpoints", function()
    local buf = start_session()

    scratch.make_entry(buf)
    scratch.make_entry(buf)
    scratch.make_entry(buf)

    scratch.session.stop()

    local meta = read_meta(scratch.session)
    assert.equals(0, #meta.checkpoints)
  end)

  it("is_degraded gate: while degraded, checkpoints never accumulate even at interval=1", function()
    local buf = start_session({
      checkpoint_interval = 1,
      is_degraded = function() return true end,
    })

    for _ = 1, 5 do
      scratch.make_entry(buf)
    end

    scratch.session.stop()

    local meta = read_meta(scratch.session)
    assert.equals(0, #meta.checkpoints)
  end)
end)
