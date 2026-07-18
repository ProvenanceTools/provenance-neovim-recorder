--- Pure payload builders for plugin snapshot events.
--- No Neovim API — simple {kind, data} constructors.
local json = require("provenance.core.json")

local M = {}

--- Build an ext.snapshot event payload.
--- @param plugins table — list of {id, version, enabled}
--- @return table {kind="ext.snapshot", data={extensions=json.array(...)}}
function M.build_ext_snapshot(plugins)
  return {
    kind = "ext.snapshot",
    data = {
      extensions = json.array(plugins or {}),
    },
  }
end

--- Build an ext.activate event payload.
--- @param id string — plugin id
--- @param version string — plugin version
--- @return table {kind="ext.activate", data={id, version}}
function M.build_ext_activate(id, version)
  return {
    kind = "ext.activate",
    data = {
      id = id,
      version = version,
    },
  }
end

return M
