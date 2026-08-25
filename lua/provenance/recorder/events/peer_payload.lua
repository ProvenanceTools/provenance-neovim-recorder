--- Pure payload builder for `peer.observed` — peer witnessing (program spec §7
--- mechanism 2, collaboration spec §5.5, Tier 4.1). No Neovim API, no I/O.
---
--- One contributor's signed record of ANOTHER contributor's `.provenance/` log:
--- the filename, the byte digest, and the foreign chain's `seq_high` + final
--- hash. Deleting a partner's log then leaves your own chain testifying that it
--- existed, so hiding a deletion means destroying both chains — which yields a
--- submission with no provenance at all, the loudest possible signal.
---
--- The reader half is `core/peer_observed.lua` (the narrowing, ported from
--- log-core) and the monorepo's `analysis-core/witness/reconcile-witnesses.ts`
--- (the five verdicts). The writer contract is pinned in the monorepo's
--- `docs/superpowers/specs/2026-08-19-program-decision-log.md`.
---
--- ## NO IDENTITY. EVER.
---
--- No student ref, no key, no git author, no path outside `.provenance/`. A
--- witness names a FILE and a CHAIN POSITION. This payload is about somebody
--- ELSE, so the CPHS constraint (2026-06-19796) that keeps author identity out
--- of `git.event` applies here with more force. Attribution runs through
--- `student_ref` inside `session.start.identity`, and nowhere else.
---
--- It is enforced structurally, as in `git_payloads.lua`: `M.build` takes
--- positional scalars plus a chain-tip table whose only three fields are read
--- by name — never merged — so a table handed in here carrying extra keys
--- contributes nothing beyond `session_id` / `seq_high` / `last_hash`.
---
--- ## THE THREE NULLS ARE VALUES, AND THEY ARE ALWAYS PRESENT
---
--- `session_id` / `seq_high` / `last_hash` are the three reads of the foreign
--- chain, and they are all-null together or all-non-null together. They are
--- ALWAYS present as keys, spelled `json.NULL`: an omitted key and a `null`
--- value canonicalize differently and therefore chain to different hashes, so a
--- port that omits them produces a log whose entries hash differently from
--- every other recorder's for the same observation. This is the single easiest
--- thing to get wrong in Lua, where a table simply cannot hold `nil` and the
--- key vanishes silently.
---
--- `seq_high = 0` is a REAL value — a foreign log holding only its
--- `session.start`. Nothing here uses truthiness on it; the "was the chain
--- read?" question is answered by the tip table's completeness, never by a
--- field being falsy.
---
--- ## `sha256` and `bytes` are corroborating detail, not the commitment
---
--- A foreign log is append-only and its owner keeps recording, so the bytes a
--- witness saw are normally a PREFIX of the bytes finally committed: digest
--- inequality is the NORMAL case, and comparing digests instead of chain
--- positions is the prefix-versus-whole-file error the reader half exists to
--- avoid. `seq_high` + `last_hash` are the commitment.
---
--- ## Fixed ASCII keys only
---
--- This port's JCS sorts object keys BYTEWISE, which matches JS/Kotlin's UTF-16
--- code-unit order only for ASCII (`core/json.lua`). The filename is a VALUE at
--- the fixed ASCII key `file`, so a partner's `.slog` name — a uuid today, but
--- not guaranteed to be by this module — can never reorder a signed payload or
--- make the three recorders disagree on bytes.
local json = require("provenance.core.json")

local M = {}

--- The "chain could not be read" tip: all three fields explicitly null.
---
--- Returned as a fresh table each call so a caller cannot mutate a shared one
--- into an already-built payload.
--- @return table
function M.unread_tip()
  return { session_id = json.NULL, seq_high = json.NULL, last_hash = json.NULL }
end

--- The ONLY view of a foreign chain this plugin is allowed to hold.
---
--- Takes exactly three positional scalars, so a partner's student ref, key or
--- git author are UNREACHABLE rather than merely unused — the same structural
--- enforcement `git_payloads.commit_view` uses.
---
--- All three or none: a log that parses but carries no `session.start`, or
--- whose `session_id` is not a string, cannot be named, so the honest answer is
--- that the chain was not read. `seq_high` is checked against `nil` and for
--- integer-ness, never for truthiness, because `0` is a real seq.
---
--- @param session_id string|nil
--- @param seq_high number|nil
--- @param last_hash string|nil
--- @return table tip  either a complete tip or `M.unread_tip()`
function M.chain_tip(session_id, seq_high, last_hash)
  local ok = type(session_id) == "string"
    and #session_id > 0
    and type(seq_high) == "number"
    and seq_high == math.floor(seq_high)
    and seq_high >= 0
    and type(last_hash) == "string"
  if not ok then
    return M.unread_tip()
  end
  return { session_id = session_id, seq_high = seq_high, last_hash = last_hash }
end

--- True when `tip` is a chain that was actually read (all three present).
--- @param tip table
--- @return boolean
function M.tip_was_read(tip)
  return type(tip) == "table" and tip.session_id ~= nil and tip.session_id ~= json.NULL
end

--- Build a `peer.observed` payload.
---
--- Every one of the seven keys is always present. `state` is DESCRIPTIVE, never
--- a verdict: `disappeared` is not misconduct — a checkout or a stash removes a
--- partner's `.slog` from the working tree — and its digest and chain fields
--- carry the LAST state seen, which is what makes the observation evidentiary.
---
--- @param file string       basename inside `.provenance/`, never a full path
--- @param sha256 string     lowercase hex over the file's exact bytes
--- @param bytes number      that file's length at observation time
--- @param tip table         from `M.chain_tip` / `M.unread_tip`; read by NAME
--- @param state string      one of core.peer_observed.STATES
--- @return table {kind="peer.observed", data={...}}
function M.build(file, sha256, bytes, tip, state)
  if type(tip) ~= "table" then
    tip = M.unread_tip()
  end

  -- Spelled with an explicit `== nil` test rather than `x and x or NULL`: the
  -- `and/or` idiom is safe for `0` in Lua but is the exact shape that turns
  -- `seq_high = 0` — the shortest possible honest witness — into a null in the
  -- languages this payload has to agree with byte for byte.
  local function or_null(v)
    if v == nil then
      return json.NULL
    end
    return v
  end

  return {
    kind = "peer.observed",
    data = {
      file = file,
      sha256 = sha256,
      bytes = bytes,
      -- Named field reads, NEVER a table merge: a tip table that also carried
      -- an identifier would contribute nothing beyond these three.
      session_id = or_null(tip.session_id),
      seq_high = or_null(tip.seq_high),
      last_hash = or_null(tip.last_hash),
      state = state,
    },
  }
end

return M
