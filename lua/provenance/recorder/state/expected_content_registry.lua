--- ExpectedContentRegistry — maps relative file paths to their
--- ExpectedContent instances, for every path the manifest puts under review
--- (docs/design.md §4.5).
---
--- Faithful port of the monorepo's expected-content-registry.ts.
---
--- ## Live membership
---
--- Membership is a RULE evaluation, not a set lookup (path-scope design spec
--- §4.1). A manifest may name a folder, so the watched set is not knowable at
--- session start: a file the student creates ten minutes in is watched from
--- its first keystroke. Snapshotting instead would make "I wrote it in a new
--- file" — which is ordinary, innocent behaviour — produce a silent gap in
--- the record.
---
--- ## The cap
---
--- `ExpectedContent` holds full file content per path. Exact-path lists
--- bounded that naturally; a `src/` rule does not. `M.EXPECTED_CONTENT_MAX_FILES`
--- is the bound, and `self.cap_hit()` is how the seal learns it bit.
--- Disclosure is mandatory, not decorative: a session that silently stopped
--- watching files it was told to watch would let the analyzer conclude "in
--- scope, no activity" about a student who did nothing wrong.
---
--- PURE: no Neovim editor API; depends on expected_content and path_scope.
local expected_content = require("provenance.recorder.state.expected_content")
local path_scope = require("provenance.core.path_scope")

local M = {}

--- Maximum number of files whose expected content is held in memory.
---
--- Part of the WRITER CONTRACT: all three recorders must use the same
--- number, or two ports disagree about when a session is capped. Companion
--- to `recorder_context.FILE_SCOPE_MAX_ENTRIES`. DO NOT CHANGE.
M.EXPECTED_CONTENT_MAX_FILES = 512

--- @param scope table  a ResolvedScope-shaped table: {track, ignore, attachments}
---   (see core.manifest.scope_from_manifest — the ONLY way to build one)
--- @param opts table|nil {max_files: number|nil, defaults to M.EXPECTED_CONTENT_MAX_FILES}
--- @return table reg
function M.new(scope, opts)
  opts = opts or {}
  local self = {}

  local max_files = opts.max_files or M.EXPECTED_CONTENT_MAX_FILES

  local _map = {}
  local _size = 0
  local _cap_hit = false

  --- Whether this path is under review right now.
  ---
  --- Note the deliberate side effect: a path that WOULD have been admitted
  --- but for the cap flips `cap_hit`. That is the only moment the cap is
  --- observable, and the fact has to be recorded when it happens rather than
  --- inferred later. A path that was never in scope does not set it — the
  --- cap did not cost us that file.
  ---
  --- Order matters, and is load-bearing (path-scope-provnvim.md §4.2):
  ---   1. Already in the map -> true, WITHOUT consulting the cap. A path we
  ---      are already tracking is not newly admitted.
  ---   2. Not `resolve_path_role(rel, scope) == "reviewed"` -> false, BEFORE
  ---      the cap check, so hard-excluded/ignored/attachment/unscoped paths
  ---      can never trip the cap spuriously.
  ---   3. Map size >= max_files -> flip cap_hit, return false.
  ---   4. Otherwise -> true.
  function self.is_watched(rel)
    if _map[rel] ~= nil then
      return true
    end
    if path_scope.resolve_path_role(rel, scope) ~= "reviewed" then
      return false
    end
    if _size >= max_files then
      _cap_hit = true
      return false
    end
    return true
  end

  --- True once the cap has refused a path that was otherwise under review.
  function self.cap_hit()
    return _cap_hit
  end

  --- Get or create the ExpectedContent for a relative path. If the path
  --- already exists in the registry, returns the existing instance and
  --- ignores initial_content. If it's new, creates one with initial_content.
  --- Does NOT itself check is_watched — matches the TS; the caller gates on
  --- is_watched. This IS the admission step: whatever admits a path to a
  --- watcher handle must call this in the same step, or the cap becomes
  --- decorative (see this module's docstring).
  function self.get_or_create(rel, initial_content)
    local existing = _map[rel]
    if existing ~= nil then
      return existing
    end
    local ec = expected_content.new(initial_content)
    _map[rel] = ec
    _size = _size + 1
    return ec
  end

  --- Get the ExpectedContent for a path, or nil if not tracked.
  function self.get(rel)
    return _map[rel]
  end

  --- Remove the ExpectedContent entry for a path.
  function self.delete(rel)
    if _map[rel] ~= nil then
      _map[rel] = nil
      _size = _size - 1
    end
  end

  return self
end

return M
