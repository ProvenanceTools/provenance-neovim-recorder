--- Shape validation for the `peer.observed` payload — peer witnessing (program
--- spec §7 mechanism 2, collaboration spec §5.5, Tier 4.1). Lua port of
--- log-core's `peer-observed.ts`.
---
--- ## Why a WRITER ships the READER
---
--- `ndjson.parse_entries` deliberately does not reject unknown `kind` values
--- and does not look inside `data` at all (PRD §5.1, forward compatibility), so
--- every consumer of a `peer.observed` event has to narrow it itself — and
--- there are four: the monorepo's analyzer and server through `analysis-core`,
--- plus the two sibling recorder repos, which need the identical rules to EMIT
--- conformant payloads. One narrowing, with vectors, is how three ports are
--- kept from diverging. The hash chain has exactly one implementation for the
--- same reason.
---
--- The write side (`recorder/watch/peer_watcher.lua`) runs this function over
--- every payload before emitting it, so a payload this port's own reader would
--- reject is never chained. A recorder is the one place a malformed witness can
--- still be stopped: once it is inside a signed log it is permanent.
---
--- ## Why a malformed payload is REJECTED rather than partially read
---
--- A witness is an assertion about a **different student's** artifact. A
--- payload we cannot fully narrow is an assertion we cannot evaluate, and the
--- safe direction for an unevaluable claim against a third party is to decline
--- it — never to keep the fields that happened to parse and reason from those.
--- Half a witness could name a session and omit the chain commitment that
--- bounds what it proves, which is the shape most likely to be read as stronger
--- than it is.
---
--- Rejection is NOT a finding and NOT a load failure. It is one witness that
--- cannot be used, reported as such.
---
--- ## Cross-field rule: parsed-ness is all-or-nothing
---
--- `session_id`, `seq_high` and `last_hash` are the three values read out of
--- the foreign chain. Either the recorder parsed that chain or it did not, so
--- these are all non-null together or all null together. A payload with some of
--- them is self-contradictory and is rejected as `partially_parsed`.
---
--- The one exception is not an exception at all: `state = "unparseable"`
--- REQUIRES all three to be null, because that state is by definition the case
--- where the foreign chain could not be read.
---
--- ## `null` is a VALUE here, not an absence
---
--- In Lua a table cannot hold `nil`, so the three chain fields are spelled with
--- `json.NULL` when unread. That is not a workaround — it is the contract:
--- omitting the keys changes the canonical bytes and therefore the chain hash,
--- so a port that omits them produces a log whose entries hash differently from
--- every other recorder's for the same observation. `seq_high = 0` is likewise
--- a real value (a foreign log holding only its `session.start`); every
--- comparison below is against `json.NULL` explicitly, never truthiness.
---
--- Pure: no Neovim editor APIs, no I/O, total (never throws).
local json = require("provenance.core.json")
local result = require("provenance.core.result")

local M = {}

--- Every legal value of `state`, in a fixed order.
---
--- Exported so the conformance suite can assert it against the vector's own
--- `states` list. An unrecognised state is REJECTED: unlike an unknown event
--- KIND — which is forward compatibility and must pass — an unknown state
--- inside a payload we do understand would have to be given a meaning, and
--- inventing one is how a reader ends up treating an unfamiliar observation as
--- an accusation.
M.STATES = { "appeared", "grew", "shrank", "disappeared", "unparseable" }

local STATE_SET = {}
for _, s in ipairs(M.STATES) do
  STATE_SET[s] = true
end

--- The complete key set of a narrowed payload. Exported so a test can pin that
--- the payload cannot widen by accident — in particular that no identifier
--- (student ref, key, git author, path outside `.provenance/`) is ever added.
M.PAYLOAD_KEYS = { "bytes", "file", "last_hash", "seq_high", "session_id", "sha256", "state" }

local function is_hex64(s)
  return type(s) == "string" and #s == 64 and s:match("^[0-9a-f]+$") ~= nil
end

local function is_non_negative_integer(n)
  return type(n) == "number" and n == math.floor(n) and n >= 0 and n == n and n ~= math.huge
end

--- Normalize the two spellings of JSON null this codebase can hand us
--- (`core.json`'s sentinel and `vim.json.decode`'s) to `json.NULL`, and a
--- genuinely absent key to `nil`.
local function read_nullable(obj, key)
  local v = obj[key]
  if v == nil then
    return nil
  end
  if v == json.NULL or v == vim.NIL then
    return json.NULL
  end
  return v
end

--- Human-readable one-liner for a shape error. For diagnostics and tests.
--- @param error table
--- @return string
function M.describe_shape_error(error)
  local kind = error and error.kind
  if kind == "not_an_object" then
    return "the payload is not a JSON object"
  elseif kind == "bad_field" then
    return 'the field "' .. tostring(error.field) .. '" is missing or of the wrong type'
  elseif kind == "unknown_state" then
    return '"' .. tostring(error.state) .. '" is not a recognised observation state'
  elseif kind == "partially_parsed" then
    return "the foreign chain was read only in part — "
      .. table.concat(error.present, ", ")
      .. " present, "
      .. table.concat(error.absent, ", ")
      .. " absent; these are all read together or not at all"
  elseif kind == "unparseable_with_chain_values" then
    return "the observation says the file did not parse, yet it carries "
      .. table.concat(error.present, ", ")
      .. " read from that file"
  elseif kind == "bad_seq_high" then
    return "seq_high must be a non-negative integer, not " .. tostring(error.value)
  elseif kind == "bad_bytes" then
    return "bytes must be a non-negative integer, not " .. tostring(error.value)
  end
  return "unrecognised shape error"
end

--- Narrow an untyped `peer.observed` `data` value.
---
--- Pure and total: never throws, never mutates, and returns a Result because a
--- malformed payload is an EXPECTED input (the log is a student-editable file).
---
--- Unknown extra keys are IGNORED, not rejected — the same forward-compatibility
--- rule `capture_policy.resolve` applies to unknown capture keys. A future field
--- added by a newer recorder must not make this reader refuse the whole witness.
---
--- @param value any
--- @return table result  ok(payload) | err(shape_error)
function M.validate(value)
  if type(value) ~= "table" or json.is_array(value) or value == json.NULL then
    return result.err({ kind = "not_an_object" })
  end

  local file = value.file
  if type(file) ~= "string" or #file == 0 then
    return result.err({ kind = "bad_field", field = "file" })
  end

  local sha256 = value.sha256
  if not is_hex64(sha256) then
    return result.err({ kind = "bad_field", field = "sha256" })
  end

  local bytes = value.bytes
  if type(bytes) ~= "number" then
    return result.err({ kind = "bad_field", field = "bytes" })
  end
  if not is_non_negative_integer(bytes) then
    return result.err({ kind = "bad_bytes", value = bytes })
  end

  local state = value.state
  if type(state) ~= "string" then
    return result.err({ kind = "bad_field", field = "state" })
  end
  if not STATE_SET[state] then
    return result.err({ kind = "unknown_state", state = state })
  end

  local session_id = read_nullable(value, "session_id")
  if session_id ~= json.NULL and type(session_id) ~= "string" then
    return result.err({ kind = "bad_field", field = "session_id" })
  end

  local seq_high = read_nullable(value, "seq_high")
  if seq_high ~= json.NULL and type(seq_high) ~= "number" then
    return result.err({ kind = "bad_field", field = "seq_high" })
  end
  -- `0` is legal and is NOT absence. Compared against json.NULL explicitly:
  -- a truthiness check here rejects the shortest possible honest witness.
  if seq_high ~= json.NULL and not is_non_negative_integer(seq_high) then
    return result.err({ kind = "bad_seq_high", value = seq_high })
  end

  local last_hash = read_nullable(value, "last_hash")
  if last_hash ~= json.NULL and not is_hex64(last_hash) then
    return result.err({ kind = "bad_field", field = "last_hash" })
  end

  -- Cross-field: the three foreign-chain reads travel together.
  local present, absent = {}, {}
  for _, pair in ipairs({
    { "session_id", session_id },
    { "seq_high", seq_high },
    { "last_hash", last_hash },
  }) do
    if pair[2] == json.NULL then
      absent[#absent + 1] = pair[1]
    else
      present[#present + 1] = pair[1]
    end
  end

  if state == "unparseable" then
    if #present > 0 then
      return result.err({ kind = "unparseable_with_chain_values", present = present })
    end
  elseif #present > 0 and #absent > 0 then
    return result.err({ kind = "partially_parsed", present = present, absent = absent })
  end

  return result.ok({
    file = file,
    sha256 = sha256,
    bytes = bytes,
    session_id = session_id,
    seq_high = seq_high,
    last_hash = last_hash,
    state = state,
  })
end

return M
