--- Capture policy — the professor-facing control over what a recorder records.
--- Lua port of log-core's `policy.ts`; program spec §4
--- (2026-08-18-multicourse-program-architecture).
---
--- The block lives INSIDE the course-signed manifest payload, which is the
--- whole point: a professor can turn capture down, a student cannot turn it
--- off.
---
---   "policy": {
---     "capture": {
---       "selection_change":      true,
---       "focus_change":          true,
---       "terminal":              true,
---       "doc_open_close":        true,
---       "inline_content":        true,   -- paste + fs.external_change snippets
---       "heartbeat_interval_ms": 30000   -- clamped to [5000, 120000]
---     }
---   }
---
--- ## The hard floor
---
--- Most event kinds cannot be disabled at all, because validation checks 3-8
--- and the integrity story depend on them. The floor is enforced **by the
--- schema itself**: a floor event simply has no key in `policy.capture`, so
--- there is no way to express "off" for it. `FLOOR_EVENT_KINDS` is that set
--- written out so an implementation can assert it; `POLICY_GATED_EVENT_KINDS`
--- is its complement — the only kinds a policy can reach.
---
--- `session.heartbeat` is on the floor because bundle-level Active/Idle and the
--- `gap_in_heartbeats` heuristic depend on it; only its *interval* is tunable.
--- `paste.anomaly` is on the floor by the same schema rule (it has no
--- `policy.capture` key) even though program spec §4's prose list omits it.
---
--- ## The absence-vs-disabled rule
---
--- The effective policy MUST travel into the bundle (it does, inside the
--- manifest carried by `session.start`). Without it the analyzer cannot tell
--- "this student produced no `selection.change` events" from "this course
--- disabled `selection.change`", and heuristics mis-fire on the difference.
---
--- ## Permanent constraint: no user-derived object keys
---
--- Every key in `policy.capture` is a fixed ASCII identifier and every future
--- addition must be too. `core/json.lua` sorts object keys bytewise while the
--- JS and Kotlin canonicalizers sort by UTF-16 code unit; the two agree only
--- for ASCII. See `course_cert.lua` for the full statement of the rule.
---
--- Pure: no Neovim editor APIs, no I/O, and resolution is total — any absent,
--- malformed, or out-of-range input yields a well-defined value, so nothing
--- here returns a Result or throws.
local json = require("provenance.core.json")

local M = {}

--- Applied when the manifest carries no `policy` block at all, and per-key when
--- a key is absent or malformed. Everything on, 30s heartbeat — i.e. exactly
--- the v1.x recorder behaviour, so a 1.x manifest resolves to today's capture
--- set.
M.DEFAULTS = {
  selection_change = true,
  focus_change = true,
  terminal = true,
  doc_open_close = true,
  inline_content = true,
  heartbeat_interval_ms = 30000,
}

--- Inclusive lower clamp for `heartbeat_interval_ms` (program spec §4).
M.HEARTBEAT_INTERVAL_MIN_MS = 5000

--- Inclusive upper clamp for `heartbeat_interval_ms` (program spec §4).
M.HEARTBEAT_INTERVAL_MAX_MS = 120000

--- Event kinds that can NEVER be disabled. These have no key in
--- `policy.capture` **by design** — the schema is the enforcement mechanism and
--- this list is only the assertable statement of it. Do not add a
--- `policy.capture` key for anything on this list.
M.FLOOR_EVENT_KINDS = {
  "session.start",
  "session.end",
  "session.resumed",
  "session.heartbeat",
  "doc.change",
  "doc.save",
  "paste",
  "paste.anomaly",
  "fs.external_change",
  "git.event",
  "clock.skew",
  "chain.broken",
  "ext.snapshot",
  "ext.activate",
  "recorder.degraded",
  "recorder.recovered_from_corruption",
}

--- The complement of FLOOR_EVENT_KINDS: every event kind a policy can switch
--- off, mapped to the boolean key that switches it.
M.POLICY_GATED_EVENT_KINDS = {
  ["doc.open"] = "doc_open_close",
  ["doc.close"] = "doc_open_close",
  ["selection.change"] = "selection_change",
  ["focus.change"] = "focus_change",
  ["terminal.open"] = "terminal",
  ["terminal.command"] = "terminal",
}

-- JSON `null` reaches this module either as `vim.NIL` (raw `vim.json.decode`)
-- or as `json.NULL` (the manifest module's normalized value model). Neither is
-- a policy object.
local function is_plain_object(v)
  if type(v) ~= "table" then
    return false
  end
  if v == json.NULL or v == vim.NIL then
    return false
  end
  return not json.is_array(v)
end

local function resolve_bool(value, fallback)
  if type(value) == "boolean" then
    return value
  end
  return fallback
end

--- Clamp `heartbeat_interval_ms` into [MIN, MAX].
---
--- A non-number, NaN, or non-finite value falls back to the DEFAULT rather than
--- clamping: clamping NaN is meaningless, and a course that wrote garbage here
--- should get the safe cadence, not the floor.
local function resolve_heartbeat_interval(value)
  if type(value) ~= "number" or value ~= value or value == math.huge or value == -math.huge then
    return M.DEFAULTS.heartbeat_interval_ms
  end
  if value < M.HEARTBEAT_INTERVAL_MIN_MS then
    return M.HEARTBEAT_INTERVAL_MIN_MS
  end
  if value > M.HEARTBEAT_INTERVAL_MAX_MS then
    return M.HEARTBEAT_INTERVAL_MAX_MS
  end
  return value
end

--- Resolve a manifest `policy` block into the effective capture policy.
---
--- Total by construction. A missing block (a 1.x manifest, or a 2.0 manifest
--- whose course specified nothing) resolves to M.DEFAULTS. Unknown capture keys
--- are ignored, for forward compatibility.
--- @param block table|nil  the manifest's `policy` value, or nil
--- @return table  { selection_change, focus_change, terminal, doc_open_close,
---   inline_content, heartbeat_interval_ms }
function M.resolve(block)
  local defaults = M.DEFAULTS
  if not is_plain_object(block) then
    return vim.tbl_extend("force", {}, defaults)
  end

  local capture = block.capture
  if not is_plain_object(capture) then
    return vim.tbl_extend("force", {}, defaults)
  end

  return {
    selection_change = resolve_bool(capture.selection_change, defaults.selection_change),
    focus_change = resolve_bool(capture.focus_change, defaults.focus_change),
    terminal = resolve_bool(capture.terminal, defaults.terminal),
    doc_open_close = resolve_bool(capture.doc_open_close, defaults.doc_open_close),
    inline_content = resolve_bool(capture.inline_content, defaults.inline_content),
    heartbeat_interval_ms = resolve_heartbeat_interval(capture.heartbeat_interval_ms),
  }
end

--- Is `kind` captured under `policy`? Floor kinds always return true — there is
--- no key that could turn them off.
--- @param kind string  an event kind
--- @param policy table  a resolved policy (see M.resolve)
--- @return boolean
function M.is_event_kind_captured(kind, policy)
  local gate = M.POLICY_GATED_EVENT_KINDS[kind]
  if gate == nil then
    return true
  end
  local value = policy[gate]
  -- Every gated kind maps to a boolean key; the numeric key is never a gate.
  if type(value) ~= "boolean" then
    return true
  end
  return value
end

return M
