--- SHA-256 → 64-char lowercase hex, over the UTF-8 bytes of the input.
--- Mirrors log-core's sha256Hex. Uses Neovim's builtin (no native dep).
local M = {}

--- @param input string  raw byte string (Lua strings are byte arrays)
--- @return string       64-char lowercase hex digest
function M.hex(input)
  return vim.fn.sha256(input)
end

return M
