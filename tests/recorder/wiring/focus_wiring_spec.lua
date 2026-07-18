--- focus_wiring: FocusGained/FocusLost -> focus.change, plus the shared
--- focus-state source the heartbeat reads. Headless: focus events are driven
--- via nvim_exec_autocmds.
local focus_wiring = require("provenance.recorder.wiring.focus_wiring")

local function new_emit()
  local events = {}
  return events, function(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
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

describe("focus_wiring.start", function()
  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
  end)

  it("starts focused (get_focused() == true) and emits nothing on start", function()
    local events, emit = new_emit()
    handle = focus_wiring.start({ emit = emit })
    assert.is_true(handle.get_focused())
    assert.equals(0, count(events, "focus.change"))
  end)

  it("FocusLost -> focus.change gained=false and get_focused() == false", function()
    local events, emit = new_emit()
    handle = focus_wiring.start({ emit = emit })

    vim.api.nvim_exec_autocmds("FocusLost", {})

    assert.equals(1, count(events, "focus.change"))
    assert.equals(false, events[1].data.gained)
    assert.is_false(handle.get_focused())
  end)

  it("FocusGained after FocusLost -> gained=true and get_focused() == true", function()
    local events, emit = new_emit()
    handle = focus_wiring.start({ emit = emit })

    vim.api.nvim_exec_autocmds("FocusLost", {})
    vim.api.nvim_exec_autocmds("FocusGained", {})

    assert.equals(2, count(events, "focus.change"))
    assert.equals(true, events[2].data.gained)
    assert.is_true(handle.get_focused())
  end)

  it("does not emit on a repeated same-state event (transitions only)", function()
    local events, emit = new_emit()
    handle = focus_wiring.start({ emit = emit })

    -- Already focused: a FocusGained is a no-op.
    vim.api.nvim_exec_autocmds("FocusGained", {})
    assert.equals(0, count(events, "focus.change"))

    vim.api.nvim_exec_autocmds("FocusLost", {})
    -- A second FocusLost must not re-emit.
    vim.api.nvim_exec_autocmds("FocusLost", {})
    assert.equals(1, count(events, "focus.change"))
  end)

  it("dispose() stops further emits and is idempotent", function()
    local events, emit = new_emit()
    handle = focus_wiring.start({ emit = emit })

    handle.dispose()
    vim.api.nvim_exec_autocmds("FocusLost", {})
    assert.equals(0, count(events, "focus.change"))

    assert.has_no.errors(function()
      handle.dispose()
    end)
  end)
end)
