--- Per-session ed25519 keypair + encrypted private key (recorder PRD §4.6).
---
--- Each session gets a fresh ed25519 keypair. The public key travels in the
--- bundle; the private key is stored encrypted at rest so that only a holder of
--- the manifest signature (the activation gate secret) can recover it. The
--- symmetric key is HKDF-SHA256-derived from the hex-decoded manifest `sig`, and
--- the private key is sealed with XChaCha20-Poly1305 (16-byte tag appended).
---
--- Cross-language contract: the analyzer (`@noble/ciphers`) must decrypt what
--- this produces. Pinned byte-for-byte by tests/conformance/fixtures/
--- session-key.json (fixed salt 0x11×16, nonce 0x22×24).
local ed25519 = require("provenance.core.ed25519")
local hkdf = require("provenance.core.hkdf")
local aead = require("provenance.vendor.xchacha20poly1305")

local ALGORITHM = "xchacha20-poly1305-hkdf-sha256-v1"
local INFO = "provenance-session-key-v1"
local SALT_LEN = 16
local NONCE_LEN = 24
local KEY_LEN = 32

local M = {}

local function to_hex(bytes)
  return (bytes:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function from_hex(hex)
  return (hex:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

--- Generate a fresh per-session ed25519 keypair.
--- @return table { public_key_hex = string(64 hex), private_key = string(32 raw) }
function M.generate()
  local priv, pub_hex = ed25519.generate_keypair()
  return { public_key_hex = pub_hex, private_key = priv }
end

-- Derive the 32-byte symmetric key from the manifest signature.
local function derive_key(manifest_sig_hex, salt)
  return hkdf.derive(from_hex(manifest_sig_hex), salt, INFO, KEY_LEN)
end

--- Encrypt a 32-byte session private key under the manifest signature.
--- @param priv32 string            32-byte raw ed25519 private key (seed)
--- @param manifest_sig_hex string  manifest signature, hex (the IKM)
--- @param salt string|nil          16-byte salt; random if omitted
--- @param nonce string|nil         24-byte nonce; random if omitted
--- @return table EncryptedPrivkey  { algorithm, nonce(hex), ciphertext(hex), salt(hex), info }
function M.encrypt_privkey(priv32, manifest_sig_hex, salt, nonce)
  assert(type(priv32) == "string" and #priv32 == 32, "priv32 must be 32 bytes")
  local uv = vim.uv or vim.loop
  salt = salt or uv.random(SALT_LEN)
  nonce = nonce or uv.random(NONCE_LEN)
  assert(#salt == SALT_LEN, "salt must be 16 bytes")
  assert(#nonce == NONCE_LEN, "nonce must be 24 bytes")
  local key = derive_key(manifest_sig_hex, salt)
  local ciphertext = aead.encrypt(key, nonce, priv32) -- ct .. 16-byte tag
  return {
    algorithm = ALGORITHM,
    nonce = to_hex(nonce),
    ciphertext = to_hex(ciphertext),
    salt = to_hex(salt),
    info = INFO,
  }
end

--- Decrypt an EncryptedPrivkey with the manifest signature.
--- @param enc table               EncryptedPrivkey (as produced by encrypt_privkey)
--- @param manifest_sig_hex string  manifest signature, hex
--- @return string|nil  32-byte raw private key, or nil on auth-tag failure / malformed input
function M.decrypt_privkey(enc, manifest_sig_hex)
  local ok, result = pcall(function()
    if type(enc) ~= "table" then return nil end
    if enc.algorithm ~= ALGORITHM then return nil end
    local salt = from_hex(enc.salt)
    local nonce = from_hex(enc.nonce)
    local ciphertext = from_hex(enc.ciphertext)
    if #salt ~= SALT_LEN or #nonce ~= NONCE_LEN then return nil end
    local key = derive_key(manifest_sig_hex, salt)
    return aead.decrypt(key, nonce, ciphertext)
  end)
  if not ok then return nil end
  return result
end

return M
