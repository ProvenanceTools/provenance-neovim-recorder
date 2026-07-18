--- selection_payloads.lua — pure builder for the `selection.change` event.
--- Mirrors log-core's SelectionChangePayload: { path, range, was_selection }.
--- The range/was_selection are computed in selection_wiring (they need the
--- Neovim cursor/visual API + UTF-16 conversion); this only shapes the event.
local M = {}

--- @param path string  workspace-relative path
--- @param range table  { start = {line,character}, ["end"] = {line,character} }
--- @param was_selection boolean  true iff a (non-empty) selection was active
--- @return table { kind = "selection.change", data = {...} }
function M.build_selection_change(path, range, was_selection)
  return {
    kind = "selection.change",
    data = {
      path = path,
      range = range,
      was_selection = was_selection,
    },
  }
end

return M
