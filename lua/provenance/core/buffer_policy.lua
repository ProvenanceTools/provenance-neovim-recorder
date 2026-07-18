--- Pure decision logic for SessionWriter's flush cadence (Plan 4 Global
--- Constraints). No Neovim API — a pure function over an explicit state
--- snapshot, so it is testable in isolation and callable from both the
--- hot `append` path and the periodic timer callback.

local M = {}

M.DEFAULT_MAX_BYTES = 256 * 1024
M.DEFAULT_MAX_INTERVAL_MS = 1000

--- @param opts table {buffered_bytes, last_flush_ms, now_ms, max_bytes, max_interval_ms}
--- @return boolean true if the buffer should be flushed now
function M.should_flush(opts)
  if opts.buffered_bytes <= 0 then
    return false
  end
  return opts.buffered_bytes >= opts.max_bytes
    or (opts.now_ms - opts.last_flush_ms) >= opts.max_interval_ms
end

return M
