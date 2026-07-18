--- Shared ok/err Result convention: { ok = true, value = ... } | { ok = false, error = ... }.
local M = {}

function M.ok(value)
  return { ok = true, value = value }
end

function M.err(error)
  return { ok = false, error = error }
end

return M
