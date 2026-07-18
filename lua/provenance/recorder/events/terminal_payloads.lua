--- Pure payload builders for terminal events.
--- No Neovim API — these are simple {kind, data} constructors.

local M = {}

--- Build a terminal.open event payload.
--- @param terminal_id string
--- @param shell string
--- @param shell_integration boolean
--- @return table {kind="terminal.open", data={terminal_id, shell, shell_integration}}
function M.build_terminal_open(terminal_id, shell, shell_integration)
  return {
    kind = "terminal.open",
    data = {
      terminal_id = terminal_id,
      shell = shell,
      shell_integration = shell_integration,
    },
  }
end

--- Build a terminal.command event payload.
--- @param terminal_id string
--- @param command string
--- @param exit_code number|nil — omit the key when nil
--- @return table {kind="terminal.command", data={terminal_id, command, exit_code?}}
function M.build_terminal_command(terminal_id, command, exit_code)
  local data = {
    terminal_id = terminal_id,
    command = command,
  }
  if exit_code ~= nil then
    data.exit_code = exit_code
  end
  return {
    kind = "terminal.command",
    data = data,
  }
end

return M
