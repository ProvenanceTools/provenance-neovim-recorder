--- Tests for terminal_wiring: the Neovim seam bridging TermOpen/TermRequest/
--- TermClose to terminal.open/terminal.command (Plan 7, Task 5).
---
--- All three autocmds are fired SYNTHETICALLY via `nvim_exec_autocmds` on a
--- plain scratch buffer (never a real `:terminal`/`termopen`), so this suite
--- never spawns a shell/PTY and is safe in sandboxes/CI with no usable PTY
--- (real `:terminal` there fails with E903: "no such device or address").
--- `nvim_exec_autocmds` invokes the REAL autocmd registered by
--- `terminal_wiring.start` on the given buffer regardless of that buffer's
--- actual buftype -- the TermOpen handler only reads `vim.b[buf].term_title`
--- / `vim.b[buf].terminal_job_id` (see terminal_wiring.lua's detect_shell /
--- detect_terminal_id), so setting those buffer-locals on a scratch buffer
--- before firing TermOpen is enough to make the handler behave exactly as it
--- would for a real terminal buffer. Confirmed empirically against this
--- module before converting the whole suite.
---
--- The OSC-133 command-finished path is exercised via a SYNTHETIC TermRequest
--- carrying `data.sequence`, since a bare headless environment never emits
--- real OSC-133 from a shell (see terminal_wiring.lua for the confirmed real-
--- Neovim shape of TermRequest's `args.data.sequence`, captured against
--- Neovim 0.12 with a literal printf'd OSC-133 sequence in a live terminal).
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

--- Track scratch buffers created by a test so they're always wiped, even on
--- assertion failure, and the handle disposed. Mirrors doc_wiring_spec.lua's
--- new_scratch idiom, but buffers here are plain scratch buffers standing in
--- for terminal buffers -- never a real `:terminal`.
local function new_scratch()
  local scratch = { bufs = {}, handle = nil }

  --- Creates a plain scratch buffer with terminal-shaped buffer-locals set
  --- (job id + title), the way a real `:terminal`/`termopen` buffer would
  --- have them at TermOpen time. Does NOT fire TermOpen -- callers fire it
  --- (or another event) themselves via nvim_exec_autocmds.
  --- @param opts table|nil { job_id = ..., term_title = ... }
  function scratch.new_term_buf(opts)
    opts = opts or {}
    local buf = vim.api.nvim_create_buf(false, true)
    vim.b[buf].terminal_job_id = opts.job_id ~= nil and opts.job_id or 4242
    if opts.term_title ~= nil then
      vim.b[buf].term_title = opts.term_title
    end
    table.insert(scratch.bufs, buf)
    return buf
  end

  --- Creates a term-shaped scratch buffer AND fires a synthetic TermOpen for
  --- it, mirroring what a real `:terminal` open does but without a shell.
  function scratch.open_terminal(opts)
    local buf = scratch.new_term_buf(opts)
    vim.api.nvim_exec_autocmds("TermOpen", { group = AUGROUP_NAME, buffer = buf })
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

  it("TermOpen (synthetic): emits exactly one terminal.open with shell_integration=false, a string terminal_id and shell", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf
    assert.has_no.errors(function()
      buf = scratch.open_terminal({ job_id = 99, term_title = "/bin/fake-shell" })
    end)

    assert.equals(1, count(events, "terminal.open"))
    local ev = find(events, "terminal.open")
    assert.is_not_nil(ev)
    assert.is_false(ev.data.shell_integration)
    assert.is_string(ev.data.terminal_id)
    assert.is_true(#ev.data.terminal_id > 0)
    assert.equals("99", ev.data.terminal_id)
    assert.is_string(ev.data.shell)
    assert.equals("/bin/fake-shell", ev.data.shell)
  end)

  it("TermClose (synthetic): untracks the terminal and emits NOTHING additional (no terminal.close in the format)", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local buf = scratch.open_terminal()
    assert.equals(1, #events)

    assert.has_no.errors(function()
      vim.api.nvim_exec_autocmds("TermClose", { group = AUGROUP_NAME, buffer = buf })
    end)

    assert.equals(1, #events) -- still just the one terminal.open
    assert.is_nil(find(events, "terminal.close"))

    -- Confirms the untrack actually happened (not just "no event fired for
    -- TermClose itself"): a TermRequest arriving after close on the same buf
    -- has nothing to attribute to, so it too emits nothing.
    assert.has_no.errors(function()
      vim.api.nvim_exec_autocmds("TermRequest", {
        group = AUGROUP_NAME,
        buffer = buf,
        data = { sequence = "\27]133;D;0" },
      })
    end)
    assert.equals(1, #events)
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
      group = AUGROUP_NAME,
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
      group = AUGROUP_NAME,
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
        group = AUGROUP_NAME,
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
        group = AUGROUP_NAME,
        buffer = buf,
        data = { sequence = "not an OSC sequence at all" },
      })
    end)

    assert.equals(before, #events)
  end)

  it("TermRequest for an untracked buffer (no prior TermOpen) is ignored gracefully", function()
    local events, emit = new_emit()
    scratch.handle = terminal_wiring.start({ emit = emit })

    local scratch_buf = scratch.new_term_buf() -- deliberately never fires TermOpen

    assert.has_no.errors(function()
      vim.api.nvim_exec_autocmds("TermRequest", {
        group = AUGROUP_NAME,
        buffer = scratch_buf,
        data = { sequence = "\27]133;D;0" },
      })
    end)

    assert.equals(0, #events)
  end)

  it("dispose(): removes the augroup; a subsequent synthetic TermOpen emits nothing", function()
    local events, emit = new_emit()
    local handle = terminal_wiring.start({ emit = emit })

    local buf1 = scratch.open_terminal()
    assert.equals(1, #events)

    handle.dispose()

    local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = AUGROUP_NAME })
    assert.is_true(not ok or #autocmds == 0)

    local before = #events
    -- The augroup is gone, so nvim_exec_autocmds targeting it errors (there's
    -- nothing left to fire) -- that error itself is the proof dispose() tore
    -- down the wiring; no event is emitted either way.
    pcall(function()
      local buf2 = scratch.new_term_buf()
      vim.api.nvim_exec_autocmds("TermOpen", { group = AUGROUP_NAME, buffer = buf2 })
    end)
    assert.equals(before, #events)

    -- dispose() is idempotent.
    assert.has_no.errors(function()
      handle.dispose()
    end)
  end)
end)
