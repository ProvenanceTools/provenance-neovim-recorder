--- ExpectedContentRegistry — maps relative file paths to their
--- ExpectedContent instances. Only maintains state for files in the
--- manifest's files_under_review list (docs/design.md §4.5).
---
--- Faithful port of the monorepo's expected-content-registry.ts.
---
--- PURE: no Neovim editor API; depends on expected_content.
local expected_content = require("provenance.recorder.state.expected_content")

local M = {}

--- @param files_under_review string[]|nil
--- @return table reg
function M.new(files_under_review)
  local self = {}

  local _watched = {}
  for _, rel in ipairs(files_under_review or {}) do
    _watched[rel] = true
  end

  local _map = {}

  --- Whether a path is in the files_under_review list.
  function self.is_watched(rel)
    return _watched[rel] == true
  end

  --- Get or create the ExpectedContent for a relative path. If the path
  --- already exists in the registry, returns the existing instance and
  --- ignores initial_content. If it's new, creates one with initial_content.
  --- Does NOT itself check is_watched — matches the TS; the caller gates on
  --- is_watched.
  function self.get_or_create(rel, initial_content)
    local existing = _map[rel]
    if existing ~= nil then
      return existing
    end
    local ec = expected_content.new(initial_content)
    _map[rel] = ec
    return ec
  end

  --- Get the ExpectedContent for a path, or nil if not tracked.
  function self.get(rel)
    return _map[rel]
  end

  --- Remove the ExpectedContent entry for a path.
  function self.delete(rel)
    _map[rel] = nil
  end

  return self
end

return M
