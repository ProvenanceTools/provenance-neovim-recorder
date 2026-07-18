-- HMAC-SHA256 (RFC 2104) + HKDF-SHA256 (RFC 5869) over Neovim's vim.fn.sha256.
local bit = require("bit")
local bxor = bit.bxor
local char, rep, sub, byte = string.char, string.rep, string.sub, string.byte

local BLOCK = 64

local function sha256_raw(s)
  local hex = vim.fn.sha256(s)
  return (hex:gsub("..", function(cc) return char(tonumber(cc, 16)) end))
end

local M = {}

function M.hmac_sha256(key, msg)
  if #key > BLOCK then key = sha256_raw(key) end
  if #key < BLOCK then key = key .. rep("\0", BLOCK - #key) end
  local ipad, opad = {}, {}
  for i = 1, BLOCK do
    local k = byte(key, i)
    ipad[i] = char(bxor(k, 0x36))
    opad[i] = char(bxor(k, 0x5c))
  end
  ipad = table.concat(ipad)
  opad = table.concat(opad)
  local inner = sha256_raw(ipad .. msg)
  return sha256_raw(opad .. inner)
end

function M.derive(ikm, salt, info, len)
  if salt == nil or #salt == 0 then salt = rep("\0", 32) end
  info = info or ""
  local prk = M.hmac_sha256(salt, ikm) -- HKDF-Extract
  local okm, t, i = {}, "", 0
  local total = 0
  while total < len do
    i = i + 1
    t = M.hmac_sha256(prk, t .. info .. char(i))
    okm[#okm + 1] = t
    total = total + #t
  end
  return sub(table.concat(okm), 1, len)
end

return M
