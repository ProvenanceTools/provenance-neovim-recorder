--- discovery.lua — upward manifest discovery (design:
--- docs/superpowers/specs/2026-07-20-nested-manifest-discovery-design.md).
---
--- Neovim has no opened-folder object, only buffers and a loosely-related
--- cwd, so activation must be anchored on the FILE, not the directory:
--- resolve_from_dir walks UPWARD from a starting directory to the nearest
--- ancestor containing a manifest (mirrors how LSP root_dir / .git detection
--- work in Neovim), then delegates verification to
--- provenance.recorder.activation.load_and_verify at that directory. A
--- manifest that is FOUND but fails verification is terminal -- the walk
--- does NOT continue further upward looking for another one (locked design
--- decision: "no manifest found or verification fails -> not recorded").
local activation = require("provenance.recorder.activation")

local M = {}

-- Precedence order mirrors activation.lua's own (unexported) MANIFEST_NAMES:
-- the canonical dotfile wins over the plain fallback when both exist in the
-- SAME directory. Duplicated here rather than shared, following this
-- repo's existing convention (doc_wiring.lua's MANIFEST_RELS comment notes
-- the same tradeoff) -- both must change together if the manifest filename
-- ever changes.
local MANIFEST_NAMES = { ".provenance-manifest", "provenance-manifest" }

--- @param start_dir string  directory to start the upward walk from (inclusive)
--- @param opts table|nil { pubkey_hex, load_and_verify, stop_dir }
--- @return table
---   { status = "active", root, manifest }
---   | { status = "inactive", reason = "no_manifest_file" }
---   | { status = "inactive", reason = <activation reason>, root = <found dir> }
function M.resolve_from_dir(start_dir, opts)
  opts = opts or {}
  local load_and_verify = opts.load_and_verify or activation.load_and_verify

  local ok, found = pcall(vim.fs.find, MANIFEST_NAMES, {
    upward = true,
    path = start_dir,
    limit = 1,
    stop = opts.stop_dir,
  })

  if not ok or not found or #found == 0 then
    return { status = "inactive", reason = "no_manifest_file" }
  end

  local root = vim.fs.dirname(found[1])
  local result = load_and_verify(root, opts.pubkey_hex)

  if result.status == "active" then
    return { status = "active", root = root, manifest = result.manifest }
  end

  return { status = "inactive", reason = result.reason, root = root }
end

--- @param file_path string  absolute path to a buffer's file
--- @param opts table|nil  see resolve_from_dir
--- @return table  see resolve_from_dir
function M.resolve_for_file(file_path, opts)
  return M.resolve_from_dir(vim.fs.dirname(file_path), opts)
end

return M
