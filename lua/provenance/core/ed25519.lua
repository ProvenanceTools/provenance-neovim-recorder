--- ed25519 (RFC 8032, deterministic) — thin wrapper over the vendored pure-Lua
--- implementation (`provenance.vendor.ed25519`, ported from TweetNaCl.js).
---
--- This module speaks Lua byte-strings (like `core.sha256`): keys, messages and
--- signatures are raw strings; hex helpers convert to/from lowercase hex. The
--- vendored impl works on 0-indexed byte tables, so this wrapper marshals across
--- that seam. `verify` never throws — any malformed input yields `false`.
---
--- Producer parity: matches `@noble/ed25519` / log-core byte-for-byte. The
--- 32-byte private key is the RFC 8032 SEED (hashed with SHA-512 to derive the
--- scalar), not a raw scalar — this is the convention log-core signs with.
local vendor = require("provenance.vendor.ed25519")

local M = {}

--- @param bytes string  raw byte string
--- @return string       lowercase hex, 2 chars per byte
function M.to_hex(bytes)
  return (bytes:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

--- @param hex string  hex string (even length, [0-9a-fA-F])
--- @return string     raw bytes
function M.from_hex(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- string -> 0-indexed byte table (+ length)
local function to_bytes(s)
  local t = {}
  for i = 1, #s do t[i - 1] = string.byte(s, i) end
  return t, #s
end

-- 0-indexed byte table -> string
local function from_bytes(t, n)
  local chars = {}
  for i = 0, n - 1 do chars[i + 1] = string.char(t[i]) end
  return table.concat(chars)
end

--- Derive the 32-byte raw public key from a 32-byte private seed.
--- @param priv32 string  32-byte private key (seed)
--- @return string        32-byte raw public key
function M.public_key_of(priv32)
  assert(type(priv32) == "string" and #priv32 == 32, "priv32 must be 32 bytes")
  local seed = to_bytes(priv32)
  local pk = vendor.keypair_from_seed(seed)
  return from_bytes(pk, 32)
end

--- Generate a fresh keypair using the libuv CSPRNG.
--- @return string, string  priv32 (32-byte raw seed), pub_hex (64-char hex)
function M.generate_keypair()
  local uv = vim.uv or vim.loop
  local rand = uv.random(32)
  assert(type(rand) == "string" and #rand == 32, "uv.random did not return 32 bytes")
  local pub = M.public_key_of(rand)
  return rand, M.to_hex(pub)
end

--- Sign a message with a 32-byte private seed. Deterministic (RFC 8032).
--- @param message string  message bytes
--- @param priv32 string   32-byte private key (seed)
--- @return string         64-byte raw signature
function M.sign(message, priv32)
  assert(type(priv32) == "string" and #priv32 == 32, "priv32 must be 32 bytes")
  assert(type(message) == "string", "message must be a string")
  local seed = to_bytes(priv32)
  local msg, mlen = to_bytes(message)
  local sig = vendor.sign(seed, msg, mlen)
  return from_bytes(sig, 64)
end

--- Verify a signature. Never throws; returns false on any malformed input.
--- @param sig string      64-byte raw signature
--- @param message string  message bytes
--- @param pub string      public key, either 32 raw bytes or 64-char hex
--- @return boolean
function M.verify(sig, message, pub)
  local ok, result = pcall(function()
    if type(sig) ~= "string" or #sig ~= 64 then return false end
    if type(message) ~= "string" then return false end
    if type(pub) ~= "string" then return false end
    local pub_raw
    if #pub == 32 then
      pub_raw = pub
    elseif #pub == 64 and pub:match("^[0-9a-fA-F]+$") then
      pub_raw = M.from_hex(pub)
    else
      return false
    end
    local sig_t = to_bytes(sig)
    local msg_t, mlen = to_bytes(message)
    local pk_t = to_bytes(pub_raw)
    return vendor.verify(sig_t, msg_t, mlen, pk_t) == true
  end)
  if not ok then return false end
  return result
end

return M
