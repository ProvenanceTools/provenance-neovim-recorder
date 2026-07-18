--- The ONE hash-chaining function (PRD §5.2). Mirrors log-core hash-chain.ts.
local sha256 = require("provenance.core.sha256")
local envelope = require("provenance.core.envelope")

local M = {}

M.GENESIS_PREV_HASH = ("0"):rep(64)

--- @param prev_hash string  64-char hex (GENESIS for seq 0)
--- @param env table         {seq,t,wall,kind,data}
--- @return table            HashedEnvelope
function M.chain_entry(prev_hash, env)
  local canonical = envelope.canonical(env)
  local hash = sha256.hex(prev_hash .. canonical)
  return {
    seq = env.seq, t = env.t, wall = env.wall, kind = env.kind, data = env.data,
    prev_hash = prev_hash, hash = hash,
  }
end

return M
