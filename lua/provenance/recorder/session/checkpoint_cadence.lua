--- Checkpoint cadence counter: pure counter that decides when to emit a signed
--- checkpoint during recording. Returns true every interval-th call, false otherwise.
--- No Neovim editor API; pure Lua; each instance is independent.

local M = {}

--- Create a new checkpoint cadence counter.
--- @param interval number? Emit checkpoint every N entries. Defaults to 100.
---                  Must be a positive integer. Errors if interval <= 0 or non-number.
--- @return table Instance with on_entry_appended() method
function M.new(interval)
  -- Default to 100 if nil
  if interval == nil then
    interval = 100
  end

  -- Validate interval
  if type(interval) ~= "number" then
    error("interval must be a number, got " .. type(interval))
  end

  if interval ~= math.floor(interval) then
    error("interval must be an integer, got " .. tostring(interval))
  end

  if interval <= 0 then
    error("interval must be positive, got " .. tostring(interval))
  end

  -- Private state, captured in closure
  local counter = 0

  -- Public methods
  local instance = {}

  --- Call on every appended entry. Returns true every interval-th call (and resets),
  --- false otherwise.
  --- @return boolean true if checkpoint should be emitted, false otherwise
  function instance.on_entry_appended()
    counter = counter + 1
    if counter >= interval then
      counter = 0
      return true
    end
    return false
  end

  return instance
end

return M
