--- SessionHost: the single chaining chokepoint (PRD §5.2). Every
--- log-producing path (session.start, doc.*, heartbeat, session.end) goes
--- through host.emit. Owns seq/prev_hash; the only place the hash chain
--- advances. Mirrors log-core's session-host.ts.
local hash_chain = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

local M = {}

--- @param opts table  {session_id, clock, on_entry}
---   clock: injectable {now(), wall()} (see core.clock).
---   on_entry: optional function(hashed_envelope) called AFTER chain state
---     has advanced. May be reassigned on the returned host at any time.
--- @return table host
function M.new(opts)
  local session_id = opts.session_id
  local clock = opts.clock
  local t_start_ms = clock.now()

  local seq = 0
  local prev_hash = hash_chain.GENESIS_PREV_HASH

  local host = {
    session_id = session_id,
    t_start_ms = t_start_ms,
    on_entry = opts.on_entry,
  }

  function host.get_seq()
    return seq
  end

  --- Emits one event through the chain. CRITICAL ORDERING: chain state
  --- (seq/prev_hash) advances BEFORE on_entry is invoked, so that if
  --- on_entry throws, the chain state is already consistent and the next
  --- emit still chains correctly. State is never rolled back on throw.
  function host.emit(kind, data)
    local t = math.max(0, math.floor((clock.now() - t_start_ms) + 0.5))
    local wall = clock.wall()
    local env = envelope.new(seq, t, wall, kind, data)
    local entry = hash_chain.chain_entry(prev_hash, env)

    prev_hash = entry.hash
    seq = seq + 1

    if host.on_entry then
      host.on_entry(entry)
    end

    return entry
  end

  return host
end

return M
