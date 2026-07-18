--- Startup chain recovery decision.
--- Port of the monorepo's `chain-recovery.ts` (recorder/src/startup). Pure
--- logic over injected deps — no vim.uv/fs here (that deps layer + the
--- activation wiring that actually calls this land in Task 5).
---
--- Decision — multiple .slog files / tie-breaking: alphabetically-last,
--- exactly as chain-recovery.ts documents (deterministic, no stat()/TOCTOU).
---
--- Decision — this function only REPORTS facts. It never resumes or
--- truncates a chain, and it never emits `chain.broken` — that event is
--- reserved for a *live* session detecting its own mid-stream break.
--- A complete previous session is reported (prev_session_id) but is NOT
--- linked; only the activation wiring (Task 5) threads prev_session_id
--- into a new session, and only for the dangling case.
local ndjson = require("provenance.core.ndjson")
local chain_validator = require("provenance.core.chain_validator")

local M = {}

--- Defensive filter: a real `.slog` file, not a `.slog.meta` sidecar (or
--- anything else). The deps layer is expected to have filtered already,
--- but this function does not trust that.
local function is_slog_name(name)
  return type(name) == "string" and name:match("%.slog$") ~= nil
end

--- Best-effort quarantine of a corrupt slog: rename it out of the way and
--- return the corrupt decision regardless of whether the rename succeeded
--- (the important thing callers need is the DECISION, not the rename).
local function quarantine(deps, prev)
  local quarantined_path = prev .. ".corrupt-" .. deps.now()
  pcall(deps.rename, prev, quarantined_path)
  return { kind = "previous_session_corrupt", quarantined_path = quarantined_path }
end

local function decide(deps)
  local slogs = {}
  for _, name in ipairs(deps.list_slogs() or {}) do
    if is_slog_name(name) then
      slogs[#slogs + 1] = name
    end
  end

  if #slogs == 0 then
    return { kind = "clean_start" }
  end

  table.sort(slogs)
  local prev = slogs[#slogs]

  local text = deps.read_slog(prev)
  if text == nil then
    return quarantine(deps, prev)
  end

  local parsed = ndjson.parse_entries(text)
  if not parsed.ok then
    return quarantine(deps, prev)
  end

  local entries = parsed.value
  local chain = chain_validator.validate_chain(entries)
  if not chain.ok then
    return quarantine(deps, prev)
  end

  local first = entries[1]
  if
    first == nil
    or first.kind ~= "session.start"
    or type(first.data) ~= "table"
    or type(first.data.session_id) ~= "string"
  then
    return quarantine(deps, prev)
  end

  local prev_session_id = first.data.session_id
  local last = entries[#entries]

  if last ~= nil and last.kind == "session.end" then
    return { kind = "previous_session_complete", prev_session_id = prev_session_id }
  end

  return { kind = "previous_session_dangling", prev_session_id = prev_session_id, dangling_path = prev }
end

--- @param deps table  { list_slogs, read_slog, rename, now }
--- @return table      RecoveryDecision (see module doc for the 4 kinds)
function M.recover_previous_session(deps)
  local ok, result_or_err = pcall(decide, deps)
  if not ok then
    -- Never throw: an unexpected deps failure degrades to the safest
    -- decision we can make without more information.
    return { kind = "clean_start" }
  end
  return result_or_err
end

return M
