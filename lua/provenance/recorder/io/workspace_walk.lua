--- The shared workspace walk, used by both seals.
---
--- `commands/seal.lua` (the classic seal) and `io/rolling_seal_writer.lua`
--- (the rolling seal) both need to enumerate every file under the workspace
--- and decide its scope role via `provenance.core.path_scope`. Two copies of
--- a directory walk that must agree about hard exclusions is exactly the
--- divergence path-scope exists to avoid — a course scoped to `src/` must
--- not get one seal that lists it and another that lists nothing — so this
--- module is the ONE walk both seals import.
---
--- Port of the monorepo's `packages/recorder/src/io/workspace-walk.ts`
--- (`walkWorkspace` / `hasHardExcludedSegment`); see that file's docstrings
--- for the reasoning behind every rule below, carried across unchanged.
---
--- `M.has_hard_excluded_segment` is exported alongside `M.walk_workspace`
--- because an EXACT `track` entry read directly by string (never discovered
--- by the walk, so never pruned by it) must be checked against the same rule
--- before it is read — see each seal's own exact-entry loop.
---
--- Pure I/O over vim.uv; no other Neovim editor API beyond `vim.split`.
local path_scope = require("provenance.core.path_scope")

local M = {}

-- ---------------------------------------------------------------------------
-- has_hard_excluded_segment
-- ---------------------------------------------------------------------------

--- True if any `/`-separated segment of `rel_path` is exactly `.git` or
--- `.provenance`.
---
--- Shared by `walk_workspace` (which prunes at the directory level, so it
--- only ever needs to check one segment — the immediate child's own name —
--- at a time) and each seal's own exact-entry loop, which reads a
--- manifest-supplied path directly and so never passes through the walk's
--- own pruning at all: an EXACT entry naming a path inside a nested
--- `.git/`/`.provenance/` must be caught here too, the same leak
--- `walk_workspace`'s docstring describes.
--- @param rel_path string
--- @return boolean
function M.has_hard_excluded_segment(rel_path)
  for _, seg in ipairs(vim.split(rel_path, "/", { plain = true })) do
    if seg == ".git" or seg == ".provenance" then
      return true
    end
  end
  return false
end

-- ---------------------------------------------------------------------------
-- walk_workspace
-- ---------------------------------------------------------------------------

--- Every file under `root`, as workspace-relative forward-slash paths.
---
--- Hard-excluded directories are skipped at the DIRECTORY level rather than
--- filtered afterwards: `.git/` in a real assignment holds thousands of
--- objects, and walking them to throw them away is the difference between a
--- seal that feels instant and one that does not.
---
--- The skip is by SEGMENT NAME (`name == ".git" or name == ".provenance"`),
--- not `path_scope.is_hard_excluded`'s root-anchored prefix check.
--- `is_hard_excluded` only matches a path that STARTS WITH `.git/` or
--- `.provenance/`, so it says nothing about `vendor/lib/.git/` (a submodule)
--- or, worse, a SIBLING assignment's `.provenance/` under this repo's
--- nested/concurrent multi-assignment recording — a rule entry like `*.json`
--- would otherwise walk into `hw3/.provenance/` and seal that assignment's
--- signed manifest into THIS bundle, leaking one student's provenance into
--- another's evidence. `path_scope.lua` is deliberately NOT changed to do
--- this itself: it is pinned by `tests/conformance/fixtures/path-scope-vectors.json`
--- and re-implemented by hand in the TypeScript and JetBrains ports, so its
--- root-anchored semantics stay put and this walk-local rule covers the
--- deeper case instead. `path_scope.is_hard_excluded` is still called
--- alongside, as a second, redundant check — cheap insurance if the
--- hard-excluded prefix list ever grows past this pair.
---
--- This pruning only protects paths the WALK produces. An EXACT `track`
--- entry naming a nested `.git/`/`.provenance/` path reads directly by
--- string and never passes through here, so each seal's own exact-entry
--- loop applies `M.has_hard_excluded_segment` again, itself, against the
--- manifest string.
---
--- `uv.fs_scandir_next`'s second return value classifies the directory ENTRY
--- itself (lstat-flavoured — verified empirically: a symlink to a file or
--- directory reports `"link"`, never `"file"`/`"directory"`), so a symlinked
--- directory is neither traversed nor walked into. This cannot cycle on a
--- self-referential link, and cannot walk outside the workspace through one.
--- A symlinked FILE is likewise never reported as `"file"` and so never
--- appears in `paths`; an EXACT `track` entry naming one is still resolved
--- correctly by each seal's own read step (`workspace_file_read.lua`),
--- because that step reads it directly, which does follow the link. Every
--- other in-scope symlink — an ATTACHMENT, or a file a RULE entry matched —
--- has no such rescue and is simply dropped, so each link the walk declines
--- is reported in the result's `symlink_paths` for the caller to disclose.
--- Hard-excluded segments are skipped for symlinks too, for the same reason
--- directories are: a link inside `.git/` is not in scope and never was, and
--- skipping it keeps an ordinary `node_modules` symlink farm from producing
--- noise.
---
--- A directory this function cannot `fs_scandir` (most often a permissions
--- problem) is not silently treated as empty: `had_unreadable_dir` bubbles
--- that up through every parent call, so the caller can warn rather than let
--- the subtree's files vanish from the bundle without a trace. The walk
--- NEVER aborts — it returns whatever it could see.
---
--- @param root string  absolute workspace root
--- @param rel string|nil  workspace-relative subdirectory to walk (default "")
--- @return table { paths: string[], had_unreadable_dir: boolean, symlink_paths: string[] }
function M.walk_workspace(root, rel)
  rel = rel or ""
  local uv = vim.uv or vim.loop
  local dir = rel == "" and root or (root .. "/" .. rel)

  local handle = uv.fs_scandir(dir)
  if not handle then
    return { paths = {}, had_unreadable_dir = true, symlink_paths = {} }
  end

  local paths = {}
  local symlink_paths = {}
  local had_unreadable_dir = false

  while true do
    local name, ftype = uv.fs_scandir_next(handle)
    if name == nil then
      break
    end
    local child_rel = rel == "" and name or (rel .. "/" .. name)

    if ftype == "directory" then
      if not (M.has_hard_excluded_segment(name) or path_scope.is_hard_excluded(child_rel .. "/")) then
        local child = M.walk_workspace(root, child_rel)
        for _, p in ipairs(child.paths) do
          paths[#paths + 1] = p
        end
        for _, p in ipairs(child.symlink_paths) do
          symlink_paths[#symlink_paths + 1] = p
        end
        if child.had_unreadable_dir then
          had_unreadable_dir = true
        end
      end
    elseif ftype == "file" then
      paths[#paths + 1] = child_rel
    elseif ftype == "link" then
      -- NOT followed, and that stays non-negotiable: following would let a
      -- link cycle spin this walk forever and let `ln -s / escape` seal the
      -- machine. But the entry is RECORDED so the caller can disclose the
      -- drop — a symlinked attachment or rule-matched source file vanishing
      -- from the bundle with no flag at all was the one drop that left no
      -- trace.
      if not (M.has_hard_excluded_segment(child_rel) or path_scope.is_hard_excluded(child_rel)) then
        symlink_paths[#symlink_paths + 1] = child_rel
      end
    end
    -- Any other entry type (fifo, socket, char/block device) is neither a
    -- file, a directory, nor a symlink the caller needs to know it declined
    -- to follow; it is simply not reported. `read_workspace_file` gates on
    -- regular-file-ness independently for anything reached by an exact
    -- entry, so nothing relies on the walk filtering these out for safety.
  end

  return { paths = paths, had_unreadable_dir = had_unreadable_dir, symlink_paths = symlink_paths }
end

return M
