--- Signed seq->hash checkpoints — periodic integrity anchors written into the
--- session log (design.md; every-100-entries checkpoint / seal). A checkpoint
--- binds a hash-chain sequence number to the entry hash at that point, signed
--- by the session's ed25519 keypair, so a verifier can confirm the chain
--- wasn't rewound or truncated without replaying the whole log.
---
--- sign() builds {hash, seq} (JCS sorts keys, so `hash` precedes `seq`),
--- canonicalizes it, and ed25519-signs the UTF-8 payload. verify() rebuilds
--- the same payload from the checkpoint and ed25519-verifies it; it never
--- throws, returning false on any malformed input (mirrors manifest.lua).
local json = require("provenance.core.json")
local ed25519 = require("provenance.core.ed25519")

local M = {}

local function is_128_hex(v)
  return type(v) == "string" and #v == 128 and v:match("^[0-9a-f]+$") ~= nil
end

--- Build the exact payload that gets signed: {hash, seq}, JCS-canonicalized.
--- Key order in the Lua table literal doesn't matter — canonicalize() sorts
--- keys by code unit, so "hash" always precedes "seq" in the output.
local function signed_payload(seq, entry_hash)
  return json.canonicalize({ hash = entry_hash, seq = seq })
end

--- @param seq number       hash-chain sequence number at the checkpoint
--- @param entry_hash string  64-char hex entry hash at that sequence number
--- @param priv32 string    32-byte raw ed25519 private key (seed)
--- @return table  { seq, hash, sig }  sig is 128-char lowercase hex
function M.sign(seq, entry_hash, priv32)
  local payload = signed_payload(seq, entry_hash)
  local sig = ed25519.to_hex(ed25519.sign(payload, priv32))
  return { seq = seq, hash = entry_hash, sig = sig }
end

--- @param cp table  { seq, hash, sig }
--- @param pubkey_hex string  64-char hex ed25519 public key
--- @return boolean  never throws; false on any malformed input
function M.verify(cp, pubkey_hex)
  local ok, verified = pcall(function()
    if type(cp) ~= "table" then return false end
    if type(cp.seq) ~= "number" then return false end
    if type(cp.hash) ~= "string" or cp.hash == "" then return false end
    if not is_128_hex(cp.sig) then return false end

    local payload = signed_payload(cp.seq, cp.hash)
    return ed25519.verify(ed25519.from_hex(cp.sig), payload, pubkey_hex)
  end)
  if not ok then return false end
  return verified == true
end

return M
