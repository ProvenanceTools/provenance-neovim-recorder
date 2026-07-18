--- DegradedNotifier — the ONE place `vim.notify` is called for degraded
--- mode (recorder PRD disk-full row: "surface a notification"). A thin
--- wrapper so `disk_full_handler`'s `notify` callback stays injectable/
--- mockable in tests instead of hard-coding `vim.notify` there.
local M = {}

--- @param message string
function M.notify(message)
  vim.notify(message, vim.log.levels.ERROR)
end

return M
