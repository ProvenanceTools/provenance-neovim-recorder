--- focus_payloads.lua — pure builder for the `focus.change` event.
--- Mirrors log-core's FocusChangePayload: { gained, reason? }. Like VS Code's
--- transformFocusChange, `reason` is left unset (the format allows it to be
--- absent); only the gained/lost transition is recorded.
local M = {}

--- @param gained boolean  true = editor gained focus, false = lost it
--- @return table { kind = "focus.change", data = { gained } }
function M.build_focus_change(gained)
  return {
    kind = "focus.change",
    data = { gained = gained },
  }
end

return M
