--- recording_session degraded-mode wiring (Plan 8, Task 7). Proves the
--- Task-6 disk-full handler is correctly wired into the live session: the
--- writer's on_error is disk_full.handle_write_error, a write error flips
--- degraded mode (notify once, recorder.degraded emitted once and chained
--- through the host), and once degraded, on_entry routes entries through
--- the handler's critical-only ring instead of the writer (bypassing it
--- entirely) — with no infinite loop.
---
--- FORCING DEGRADED: reliably forcing a real ENOSPC write failure from
--- headless Neovim is flaky/platform-dependent (no portable way to make
--- vim.uv.fs_write fail deterministically without root-only tricks like
--- quota filesystems). recording_session.lua exposes a narrow, clearly
--- test-only hook for exactly this: session._simulate_write_error(err),
--- which just calls disk_full.handle_write_error(err) — the SAME function
--- session_writer's on_error calls on a real failure. This exercises the
--- full on_degraded -> host.emit -> on_entry -> enqueue chain identically
--- to a real write error; only the trigger (test hook vs. a real fs_write
--- failure) differs, so it proves the wiring under test without relying on
--- an unreliable filesystem fault.
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")

--- Track everything created by a test so it can be torn down afterward.
--- Mirrors recording_session_spec.lua / recording_session_checkpoints_spec.lua.
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

--- Tolerant of a not-yet-created .slog (a fully-degraded-from-the-start
--- session may never trigger a single flush): returns "" instead of
--- erroring, unlike the other specs' read_all (which always call it after
--- stop() has guaranteed the file exists).
local function read_all(path)
  if not vim.uv.fs_stat(path) then
    return ""
  end
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
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

describe("recording_session degraded-mode wiring", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  --- Starts a session against a fresh workspace with one recordable buffer
  --- open, plus an injected notify spy. Returns the buffer and the
  --- notify_calls list (mutated in place as calls happen).
  local function start_session(extra_opts)
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line0\n")

    local notify_calls = {}

    local opts = vim.tbl_extend("force", {
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
      notify = function(message)
        table.insert(notify_calls, message)
      end,
    }, extra_opts or {})

    scratch.session = recording_session.start(opts)
    local buf = scratch.edit(path)
    return buf, notify_calls
  end

  it("starts NOT degraded", function()
    start_session()
    assert.is_false(scratch.session.is_degraded())
  end)

  it("a simulated write error flips degraded, notifies exactly once, and chains recorder.degraded into the ring", function()
    local _, notify_calls = start_session()

    assert.is_false(scratch.session.is_degraded())

    scratch.session._simulate_write_error("ENOSPC")

    assert.is_true(scratch.session.is_degraded())
    assert.equals(1, #notify_calls)

    local kinds = ring_kinds(scratch.session)
    assert.is_true(contains(kinds, "recorder.degraded"))
  end)

  it("a second simulated write error is idempotent: no re-notify, no duplicate ring entry", function()
    local _, notify_calls = start_session()

    scratch.session._simulate_write_error("ENOSPC")
    scratch.session._simulate_write_error("ENOSPC")
    scratch.session._simulate_write_error("EACCES")

    assert.equals(1, #notify_calls)

    local degraded_count = 0
    for _, kind in ipairs(ring_kinds(scratch.session)) do
      if kind == "recorder.degraded" then
        degraded_count = degraded_count + 1
      end
    end
    assert.equals(1, degraded_count)
  end)

  it("after degrading, a CRITICAL entry (session.end via stop) is retained in the ring", function()
    start_session()
    scratch.session._simulate_write_error("ENOSPC")

    scratch.session.stop("deactivate")

    local kinds = ring_kinds(scratch.session)
    assert.is_true(contains(kinds, "session.end"))
  end)

  it("after degrading, a NON-CRITICAL entry (doc.change) is dropped: not in the ring, not written to the .slog", function()
    local buf = start_session()
    scratch.session._simulate_write_error("ENOSPC")

    -- .slog contents up to (and including) the write error are frozen —
    -- capture now, before the edit below, to compare against after.
    local before_text = read_all(scratch.session.slog_path)

    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "edited-while-degraded" })

    local kinds = ring_kinds(scratch.session)
    assert.is_false(contains(kinds, "doc.change"))

    local after_text = read_all(scratch.session.slog_path)
    assert.equals(before_text, after_text)
  end)

  it("no infinite loop / no hang: the simulated write error and subsequent stop() both return promptly", function()
    start_session()
    assert.has_no.errors(function()
      scratch.session._simulate_write_error("ENOSPC")
      scratch.session.stop()
    end)
  end)

  it("Task-3 gate still works: an explicit opts.is_degraded override routes entries to enqueue too", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line0\n")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
      is_degraded = function() return true end,
    })

    -- The override was never told about a real write error, so the
    -- disk-full handler's OWN internal degraded flag is still false; its
    -- enqueue() therefore declines to retain anything (not degraded from
    -- its own point of view) — but the entry is still routed through
    -- enqueue rather than the writer, so nothing lands on disk either.
    assert.is_false(scratch.session.is_degraded())

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "edited" })

    -- With is_degraded forced true from the very first entry (session.start
    -- itself), the writer never receives a single append, so it never
    -- flushes and the .slog is never created — the strongest possible
    -- confirmation that nothing is routed to the writer while forced
    -- degraded.
    assert.is_nil(vim.uv.fs_stat(scratch.session.slog_path))
  end)
end)
