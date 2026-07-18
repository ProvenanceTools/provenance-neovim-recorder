--- Validates a HashedEnvelope chain: seq contiguity, prev_hash linkage,
--- hash recomputation, monotonic t, and monotonic wall (with a clock.skew
--- escape hatch). Mirrors log-core's chain-validator.ts. First failure wins.
local hash_chain = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

local M = {}

local function break_(reason, at_seq, expected)
  return { ok = false, break_ = { reason = reason, at_seq = at_seq, expected = expected } }
end

--- @param entries table  list of HashedEnvelope {seq,t,wall,kind,data,prev_hash,hash}
--- @return table         {ok=true} | {ok=false, break_={reason, at_seq, expected?}}
function M.validate_chain(entries)
  for i, entry in ipairs(entries) do
    local index = i - 1 -- 0-based

    if entry.seq ~= index then
      return break_("seq_gap", entry.seq, index)
    end

    local prev = entries[i - 1]
    local expected_prev_hash = (index == 0) and hash_chain.GENESIS_PREV_HASH or prev.hash
    if entry.prev_hash ~= expected_prev_hash then
      return break_("hash_mismatch", entry.seq)
    end

    local recomputed = hash_chain.chain_entry(entry.prev_hash,
      envelope.new(entry.seq, entry.t, entry.wall, entry.kind, entry.data))
    if recomputed.hash ~= entry.hash then
      return break_("hash_mismatch", entry.seq)
    end

    if prev then
      if entry.t < prev.t then
        return break_("t_regression", entry.seq)
      end

      if entry.wall < prev.wall then
        -- Equivalent to log-core's inclusive [prev.seq, entry.seq] window check
        -- ONLY because rule 2 above (seq == index, checked first, first-failure-
        -- wins) guarantees entries are contiguous, so that window contains
        -- exactly {prev, entry} — checking just this adjacent pair covers it.
        local skew_in_window = prev.kind == "clock.skew" or entry.kind == "clock.skew"
        if not skew_in_window then
          return break_("wall_regression", entry.seq)
        end
      end
    end
  end

  return { ok = true }
end

return M
