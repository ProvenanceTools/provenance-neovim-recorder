--- SessionHost: the single chaining chokepoint (PRD §5.2). Every
--- log-producing path (session.start, doc.*, heartbeat, session.end) goes
--- through host.emit. Owns seq/prev_hash; the only place the hash chain
--- advances. Mirrors log-core's session-host.ts.
---
--- It is also where the CAPTURE POLICY is enforced (program spec §4), for the
--- same reason it owns the chain: it is the one place every event must pass
--- through, so no wiring module — present or future — can emit a disabled kind
--- by forgetting a check. `doc_wiring` makes this concrete: it emits the
--- policy-gated `doc.open`/`doc.close` and is deliberately wired OUTSIDE
--- recording_session's `enable_signals` switch, so gating at that switch would
--- have silently left those two kinds ungated.
---
--- **A suppressed event must consume NO sequence number.** The policy check
--- therefore runs before the envelope is built and before the chain advances.
--- Dropping an event after chaining would leave a hole in the seq run, which
--- validation check 3 reads as a DELETED ENTRY — turning a course's privacy
--- setting into a tamper signal against the student. This ordering is the
--- whole safety property; do not move the check below `chain_entry`.
---
--- The gate itself is injected (see session/policy_gate.lua) so this module
--- keeps knowing only about seq/prev_hash and never about payload shapes.
local hash_chain = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

local M = {}

--- @param opts table  {session_id, clock, on_entry, policy_gate}
---   clock: injectable {now(), wall()} (see core.clock).
---   on_entry: optional function(hashed_envelope) called AFTER chain state
---     has advanced. May be reassigned on the returned host at any time.
---   policy_gate: optional {allows(kind), redact(kind, data)} (see
---     session/policy_gate.lua). Absent means capture everything, i.e. the
---     pre-policy behaviour, byte for byte.
--- @return table host
function M.new(opts)
  local session_id = opts.session_id
  local clock = opts.clock
  local t_start_ms = clock.now()
  local gate = opts.policy_gate

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

  --- Emits one event through the chain.
  ---
  --- CRITICAL ORDERING 1 — policy BEFORE the chain. A kind the capture policy
  --- disables is dropped here, before the envelope exists and before seq or
  --- prev_hash move, so a suppressed event consumes NO sequence number and
  --- leaves NO hole for validation check 3 to read as a deleted entry.
  --- Returns nil in that case; every caller is fire-and-forget.
  ---
  --- CRITICAL ORDERING 2 — chain state (seq/prev_hash) advances BEFORE
  --- on_entry is invoked, so that if on_entry throws, the chain state is
  --- already consistent and the next emit still chains correctly. State is
  --- never rolled back on throw.
  function host.emit(kind, data)
    if gate then
      if not gate.allows(kind) then
        return nil
      end
      data = gate.redact(kind, data)
    end

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
