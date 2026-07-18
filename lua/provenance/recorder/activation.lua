--- Pure activation decision (design.md §4.1): parse a `.provenance-manifest`
--- and verify it against the embedded course public key. This is the
--- Neovim-API-free core of the activation gate — a later task wires it to a
--- `vim.uv` file loader and session state. It has zero Neovim editor API use
--- (only depends on core.manifest, itself pure Lua) and never throws.
local manifest = require("provenance.core.manifest")

local M = {}

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

return M
