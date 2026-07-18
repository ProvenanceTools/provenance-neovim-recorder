--- focus_wiring.lua — the Neovim seam between FocusGained/FocusLost and the
--- `focus.change` event, mirroring VS Code's onDidChangeWindowState (which
--- emits only on an actual focused-state transition). Also owns the shared
--- focus-state source the heartbeat reads for its `focused` field — before
--- this, heartbeat hardcoded `focused = true` because nothing tracked focus.
---
--- Neovim only observes focus when the hosting terminal reports it (focus
--- reporting must be supported/enabled); FocusGained/FocusLost are the TUI
--- analogue of VS Code's window-state transitions. A live-TUI check for real
--- focus events is a manual-checklist item (docs/manual-verification.md).
local focus_payloads = require("provenance.recorder.events.focus_payloads")

local M = {}

local AUGROUP_NAME = "ProvenanceFocus"

--- start(opts) -> handle
---
--- opts:
---   emit: function(kind, data)   -- SessionHost.emit
---
--- Returns a handle with:
---   handle.get_focused() -> boolean   -- current focus state (for heartbeat)
---   handle.dispose()                  -- idempotent teardown
---
--- Starts in the focused state (Neovim launches focused); emits nothing until
--- the first real transition.
function M.start(opts)
  opts = opts or {}
  local emit = opts.emit

  local disposed = false
  local focused = true

  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })

  local function set_focused(next_state)
    if disposed then
      return
    end
    if next_state == focused then
      return -- transitions only (mirrors VS Code's prevFocused guard)
    end
    focused = next_state
    local ev = focus_payloads.build_focus_change(focused)
    emit(ev.kind, ev.data)
  end

  vim.api.nvim_create_autocmd("FocusGained", {
    group = augroup,
    desc = "Provenance: focus.change gained=true on editor focus gain",
    callback = function()
      pcall(set_focused, true)
    end,
  })

  vim.api.nvim_create_autocmd("FocusLost", {
    group = augroup,
    desc = "Provenance: focus.change gained=false on editor focus loss",
    callback = function()
      pcall(set_focused, false)
    end,
  })

  local handle = {}

  function handle.get_focused()
    return focused
  end

  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
  end

  return handle
end

return M
