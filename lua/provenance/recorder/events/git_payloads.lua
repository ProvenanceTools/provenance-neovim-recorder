--- Pure payload builder for git events.
--- No Neovim API — simple {kind, data} constructor.

local M = {}

--- Build a git.event payload.
--- @param operation string — e.g. "commit", "state_change", "checkout"
--- @param commit_sha string|nil — omit the key when nil
--- @return table {kind="git.event", data={operation, commit_sha?}}
function M.build_git_event(operation, commit_sha)
  local data = {
    operation = operation,
  }
  if commit_sha ~= nil then
    data.commit_sha = commit_sha
  end
  return {
    kind = "git.event",
    data = data,
  }
end

return M
