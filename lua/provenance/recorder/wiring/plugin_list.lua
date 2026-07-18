--- plugin_list.lua — best-effort enumeration of the loaded Neovim plugins,
--- shared by ext.snapshot (snapshot_wiring) and ext.activate
--- (ext_activation_wiring) so both observe the same set.
---
--- Every entry on the runtimepath, deduped by basename-as-id. Most Neovim
--- plugins expose no queryable version, so version is always "" here; being on
--- the runtimepath is taken to mean active, so enabled is always true. Exact
--- plugin-manager integration (querying a manager's own plugin list/version)
--- is out of scope — this is a coarse, degraded-by-design signal. `list()`
--- wraps the enumeration in pcall so any failure (missing API, unexpected
--- environment) degrades to an empty list rather than crashing the caller
--- (CLAUDE.md graceful-degradation rule).
local M = {}

local function enumerate()
  local plugins = {}
  local seen = {}
  for _, path in ipairs(vim.api.nvim_list_runtime_paths()) do
    local id = vim.fs.basename(path)
    if id and id ~= "" and not seen[id] then
      seen[id] = true
      table.insert(plugins, { id = id, version = "", enabled = true })
    end
  end
  return plugins
end

--- @return table  list of {id, version, enabled}; empty on any failure
function M.list()
  local ok, result = pcall(enumerate)
  if not ok then
    return {}
  end
  return result
end

return M
