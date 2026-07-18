--- Pure activation decision (design.md §4.1): parse a `.provenance-manifest`
--- and verify it against the embedded course public key. This is the
--- Neovim-API-free core of the activation gate; `load_and_verify` below is
--- the `vim.uv` file-loading seam that wires it to an actual workspace
--- directory. It has zero Neovim editor API use (only depends on
--- core.manifest, itself pure Lua) and never throws.
local manifest = require("provenance.core.manifest")

local M = {}

-- Manifest filename precedence: canonical dotfile first, plain fallback
-- second. First one that exists on disk wins (see CLAUDE.md's format
-- contract notes — this is wiring, not format).
local MANIFEST_NAMES = { ".provenance-manifest", "provenance-manifest" }

--- @param text string  raw manifest JSON text (e.g. read from
---   `.provenance-manifest` in the workspace root)
--- @param pubkey_hex string  64-char hex ed25519 course public key
--- @return table
---   { status = "active", manifest = Manifest }
---   | { status = "inactive", reason = "parse_error" }
---   | { status = "inactive", reason = "signature_invalid" }
function M.evaluate(text, pubkey_hex)
  local parsed = manifest.parse(text)
  if not parsed.ok then
    return { status = "inactive", reason = "parse_error" }
  end

  if not manifest.verify(parsed.value, pubkey_hex) then
    return { status = "inactive", reason = "signature_invalid" }
  end

  return { status = "active", manifest = parsed.value }
end

-- Read a whole small file synchronously via vim.uv, fail-closed.
-- @return "ok", text | "not_found" | "error"
local function read_file(path)
  local uv = vim.uv or vim.loop

  local st = uv.fs_stat(path)
  if not st then
    return "not_found"
  end
  if st.type ~= "file" then
    -- Present at this path but not a regular file (e.g. a directory) — a
    -- present-but-unreadable manifest is an error, not "no manifest".
    return "error"
  end

  local fd = uv.fs_open(path, "r", 438) -- 438 = 0o666
  if not fd then
    return "error"
  end

  local ok, data = pcall(function()
    local fstat = uv.fs_fstat(fd)
    if not fstat then
      error("fstat failed")
    end
    local chunk = uv.fs_read(fd, fstat.size, 0)
    if chunk == nil then
      error("read failed")
    end
    return chunk
  end)
  uv.fs_close(fd) -- always close, on both the success and error paths

  if not ok then
    return "error"
  end
  return "ok", data
end

--- Find and read the manifest file from a workspace directory (trying each
--- candidate name in precedence order), then delegate to evaluate(). The
--- vim.uv-based file-loading seam of the activation gate (design.md §4.1) —
--- never throws.
--- @param workspace_dir string  assignment workspace root
--- @param pubkey_hex string|nil  64-char hex ed25519 course public key;
---   defaults to provenance.course_public_key.COURSE_PUBLIC_KEY_HEX
--- @return table
---   { status = "active", manifest = Manifest }
---   | { status = "inactive", reason = "no_manifest_file" }
---   | { status = "inactive", reason = "manifest_read_error" }
---   | { status = "inactive", reason = "parse_error" }
---   | { status = "inactive", reason = "signature_invalid" }
function M.load_and_verify(workspace_dir, pubkey_hex)
  local ok, out = pcall(function()
    local key = pubkey_hex or require("provenance.course_public_key").COURSE_PUBLIC_KEY_HEX

    for _, name in ipairs(MANIFEST_NAMES) do
      local status, text = read_file(workspace_dir .. "/" .. name)
      if status == "ok" then
        return M.evaluate(text, key)
      elseif status == "error" then
        -- Present but unreadable: stop here, do not fall through to the
        -- next candidate name.
        return { status = "inactive", reason = "manifest_read_error" }
      end
      -- status == "not_found": try the next candidate.
    end

    return { status = "inactive", reason = "no_manifest_file" }
  end)

  if not ok then
    return { status = "inactive", reason = "manifest_read_error" }
  end
  return out
end

return M
