--- Per-workspace recorder state: activation status, workspace directory, and
--- manifest. Single-workspace, in-memory (Neovim is one process per session).
--- Each instance is independent; no module-level shared state between instances.

local M = {}

--- Create a new RecorderState instance.
--- @return table RecorderState with is_active(), activate(), deactivate(), get() methods
function M.new()
  -- Private state, captured in closure
  local state = {
    active = false,
    workspace = nil,
    manifest = nil,
  }

  -- Public methods
  local instance = {}

  --- Check if the recorder is currently active.
  --- @return boolean
  function instance.is_active()
    return state.active
  end

  --- Activate the recorder for a workspace and manifest.
  --- @param opts table with 'workspace' (string) and 'manifest' (table)
  function instance.activate(opts)
    if not opts or not opts.workspace or not opts.manifest then
      error("activate requires {workspace, manifest}")
    end
    state.active = true
    state.workspace = opts.workspace
    state.manifest = opts.manifest
  end

  --- Deactivate the recorder and clear state.
  function instance.deactivate()
    state.active = false
    state.workspace = nil
    state.manifest = nil
  end

  --- Get the current state as a table.
  --- @return table { active = bool, workspace = string|nil, manifest = table|nil }
  function instance.get()
    return {
      active = state.active,
      workspace = state.workspace,
      manifest = state.manifest,
    }
  end

  return instance
end

return M
