--- Envelope = {seq, t, wall, kind, data}; the pre-hash log entry.
--- HashedEnvelope adds prev_hash + hash. Mirrors log-core envelope.ts.
local json = require("provenance.core.json")

local M = {}

function M.new(seq, t, wall, kind, data)
  return { seq = seq, t = t, wall = wall, kind = kind, data = data }
end

--- Canonical bytes of the 5-field envelope (no hash fields).
function M.canonical(env)
  return json.canonicalize({
    seq = env.seq, t = env.t, wall = env.wall, kind = env.kind, data = env.data,
  })
end

--- Identity seam: the on-wire HashedEnvelope object.
function M.hashed_to_wire(hashed)
  return hashed
end

return M
