--- terminal_wiring: the Neovim seam bridging TermOpen/TermRequest/TermClose
--- to terminal.open/terminal.command (Plan 7, Task 5). Headless, REAL
--- terminal buffers (`vim.cmd("terminal")`) for the open/close path; the
--- OSC-133 command-finished path is exercised via a SYNTHETIC TermRequest
--- (`nvim_exec_autocmds`) carrying `data.sequence`, since a bare headless
--- environment never emits real OSC-133 from a shell (see terminal_wiring.lua
--- for the confirmed real-Neovim shape of TermRequest's `args.data.sequence`,
--- captured against Neovim 0.12 with a literal printf'd OSC-133 sequence).
---
--- NOTE: the format has NO `terminal.close` event (log-core defines only
--- terminal.open/terminal.command) — TermClose is internal bookkeeping only
--- (untrack the buf) and must emit nothing.
local terminal_wiring = require("provenance.recorder.wiring.terminal_wiring")

local AUGROUP_NAME = "ProvenanceTerminal"

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

local function find(events, kind)
  for _, ev in ipairs(events) do
    if ev.kind == kind then
      return ev
    end
  end
  return nil
end

local function count(events, kind)
  local n = 0
  for _, ev in ipairs(events) do
    if ev.kind == kind then
      n = n + 1
    end
  end
  return n
end

--- Track terminal buffers created by a test so they're always wiped, even on
--- assertion failure, and the handle disposed. Mirrors doc_wiring_spec.lua's
--- new_scratch idiom.
local function new_scratch()
  local scratch = { bufs = {}, handle = nil }

  --- Opens a real terminal buffer via :terminal (reliably fires TermOpen
  --- headless) and returns its bufnr.
  function scratch.open_terminal()
    vim.cmd("terminal")
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.wipe(buf)
    if vim.api.nvim_buf_is_valid(buf) then
      pcall(vim.cmd, "bwipeout! " .. buf)
    end
  end

  function scratch.teardown()
    if scratch.handle then
      scratch.handle.dispose()
    end
    for _, buf in ipairs(scratch.bufs) do
      scratch.wipe(buf)
    end
  end

  return scratch
end

describe("terminal_wiring.start", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("TermOpen: emits exactly one terminal.open with shell_integration=false, a string terminal_id and shell", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf
    assert.has_no.errors(function()
      buf = scratch.open_terminal()
    end)

    assert.equals(1, count(events, "terminal.open"))
    local ev = find(events, "terminal.open")
    assert.is_not_nil(ev)
    assert.is_false(ev.data.shell_integration)
    assert.is_string(ev.data.terminal_id)
    assert.is_true(#ev.data.terminal_id > 0)
    assert.is_string(ev.data.shell)
  end)

  it("TermClose: untracks the terminal and emits NOTHING additional (no terminal.close in the format)", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf = scratch.open_terminal()
    assert.equals(1, #events)

    assert.has_no.errors(function()
      scratch.wipe(buf) -- fires TermClose
    end)

    assert.equals(1, #events) -- still just the one terminal.open
    assert.is_nil(find(events, "terminal.close"))
  end)

  it("OSC-133 command-finished (synthetic TermRequest): emits ONE terminal.command with terminal_id + exit_code (0 not dropped)", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf = scratch.open_terminal()
    local open_ev = find(events, "terminal.open")
    assert.is_not_nil(open_ev)
    local terminal_id = open_ev.data.terminal_id

    -- Synthetic OSC-133 "command finished, exit code 0" marker. Real shape
    -- confirmed against a literal printf'd sequence in a live Neovim 0.12
    -- terminal: args.data.sequence == "\27]133;D;0" (see module docstring).
    vim.api.nvim_exec_autocmds("TermRequest", {
      buffer = buf,
      data = { sequence = "\27]133;D;0" },
    })

    assert.equals(1, count(events, "terminal.command"))
    local ev = find(events, "terminal.command")
    assert.equals(terminal_id, ev.data.terminal_id)
    assert.equals(0, ev.data.exit_code)
  end)

  it("OSC-133 command-finished with a non-zero exit code is captured", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf = scratch.open_terminal()

    vim.api.nvim_exec_autocmds("TermRequest", {
      buffer = buf,
      data = { sequence = "\27]133;D;137" },
    })

    local ev = find(events, "terminal.command")
    assert.is_not_nil(ev)
    assert.equals(137, ev.data.exit_code)
  end)

  it("OSC-133 command-start marker (133;C) alone does not emit terminal.command", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf = scratch.open_terminal()
    local before = #events

    assert.has_no.errors(function()
      vim.api.nvim_exec_autocmds("TermRequest", {
        buffer = buf,
        data = { sequence = "\27]133;C" },
      })
    end)

    assert.equals(before, #events)
  end)

  it("garbled/unrecognized OSC sequence is ignored: no emit, no crash", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf = scratch.open_terminal()
    local before = #events

    assert.has_no.errors(function()
      vim.api.nvim_exec_autocmds("TermRequest", {
        buffer = buf,
        data = { sequence = "not an OSC sequence at all" },
      })
    end)

    assert.equals(before, #events)
  end)

  it("TermRequest for an untracked buffer (no prior TermOpen) is ignored gracefully", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local scratch_buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, scratch_buf)

    assert.has_no.errors(function()
      vim.api.nvim_exec_autocmds("TermRequest", {
        buffer = scratch_buf,
        data = { sequence = "\27]133;D;0" },
      })
    end)

    assert.equals(0, #events)
  end)

  it("dispose(): removes the augroup; a subsequent terminal open emits nothing", function()
    local events, emit = new_emit()
    local handle = terminal_wiring.start({ emit = emit })

    local buf1 = scratch.open_terminal()
    assert.equals(1, #events)

    handle.dispose()

    local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = AUGROUP_NAME })
    assert.is_true(not ok or #autocmds == 0)

    local before = #events
    assert.has_no.errors(function()
      scratch.open_terminal()
    end)
    assert.equals(before, #events)

    -- dispose() is idempotent.
    assert.has_no.errors(function()
      handle.dispose()
    end)
  end)
end)
