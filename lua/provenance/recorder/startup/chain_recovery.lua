--- Startup chain recovery decision.
--- Port of the monorepo's `chain-recovery.ts` (recorder/src/startup). Pure
--- logic over injected deps — no vim.uv/fs here (that deps layer + the
--- activation wiring that actually calls this land in Task 5).
---
--- Decision — multiple .slog files / tie-breaking: alphabetically-last
--- ELIGIBLE file (deterministic, no stat()/TOCTOU). See OWNERSHIP below for
--- what "eligible" means; before that gate existed this was simply
--- "alphabetically last", which is the whole of decision-log bug 2.
---
--- Decision — this function only REPORTS facts. It never resumes or
--- truncates a chain, and it never emits `chain.broken` — that event is
--- reserved for a *live* session detecting its own mid-stream break.
--- A complete previous session is reported (prev_session_id) but is NOT
--- linked; only the activation wiring (Task 5) threads prev_session_id
--- into a new session, and only for the dangling case.
---
--- ===========================================================================
--- Decision — OWNERSHIP. `.provenance/` IS NOT NECESSARILY OURS.
--- ===========================================================================
---
--- Everything above was written assuming every `.slog` in the directory is
--- this student's. In a shared repo it is not: `.provenance/` is committed, so
--- a partner's `.slog` arrives by `git pull`. Two consequences were LIVE
--- DEFECTS here (decision-log bug 2, already fixed in the VS Code recorder):
---
---   1. The alphabetically last `.slog` — very possibly the PARTNER'S, since a
---      partner with their editor open right now has no `session.end` — was
---      RENAMED to `<slog>.corrupt-<ts>` whenever it failed to read, parse or
---      validate. `commands/seal.lua` skips `.corrupt-` files, so that rename
---      removes the partner's evidence from the submission, and because
---      `.provenance/` is committed, git blames the victim's partner for it.
---      It is also a free attack: corrupt one byte of a partner's log and
---      their own tooling erases it.
---   2. `prev_session_id` could be read off a partner's log and threaded as
---      THIS session's predecessor, asserting a relationship between two
---      different contributors that the evidence does not support.
---
--- The gate is `startup/slog_ownership.lua`, keyed on
--- `session.start.identity.enrollment.student_ref` — the only identity signal
--- that exists ACROSS sessions, and the only one available here, since
--- recovery runs before this session has minted a `session_id` of its own.
--- Read that module for the three classes, and for why an unattributed
--- candidate is eligible only to an unattributed recorder.
---
--- Consequences for this module, one line each:
---
---   - Selection considers ELIGIBLE files only. A foreign `.slog` is dropped
---     before anything else can happen to it: never selected, never linked,
---     never renamed, never read past its first line.
---   - `quarantine()` is therefore unreachable for a foreign file — it can
---     only ever be called with the path `select_eligible` returned, and the
---     scan that produces that path is handed a read function and nothing else.
---   - When nothing in the directory is eligible we return `clean_start` and
---     leave every one of those files exactly where it is. Losing a
---     back-pointer costs a link; renaming someone's only record costs the
---     evidence.
---
--- RESIDUAL GAP, stated rather than implied away: when NEITHER partner has
--- enrolled, every file is `unattributed`, no signal exists that could
--- separate them, and both defects above remain reachable in that one
--- configuration. Nothing in this module can close it — see
--- `slog_ownership.lua`.
---
--- NOT CHANGED HERE, deliberately: selection among eligible files is still
--- alphabetically-last rather than by `session.start.wall`. The VS Code
--- recorder moved to wall ordering for a DIFFERENT bug (one stale filename
--- winning repeatedly). Restricted to a single contributor's own files, that
--- mis-ordering costs at most a wrong-but-own back-pointer, and reordering is
--- a separate change from fixing ownership.
local ndjson = require("provenance.core.ndjson")
local chain_validator = require("provenance.core.chain_validator")
local slog_ownership = require("provenance.recorder.startup.slog_ownership")

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
---
--- PRECONDITION, and the whole of the bug-2 fix: `prev` came from
--- `slog_ownership.select_eligible`, so it is a file this recorder has
--- established it is entitled to touch. This is the only rename in the
--- startup path and it is the only call site.
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

  -- Sorted ascending so that "alphabetically last" is well defined;
  -- select_eligible walks it backwards and stops at the first file this
  -- recorder is entitled to touch. In the solo case that is the last file and
  -- exactly one read, so the ownership gate costs a solo student nothing.
  --
  -- `deps.read_slog` is passed on its own: the scan gets a read capability and
  -- no other, so a partner's `.slog` cannot be renamed from inside it.
  table.sort(slogs)
  local selected = slog_ownership.select_eligible(deps.read_slog, slogs, deps.own_student_ref)

  -- Every `.slog` here belongs to another contributor. Start clean and leave
  -- all of them exactly where they are.
  if selected == nil then
    return { kind = "clean_start" }
  end

  local prev = selected.path
  -- Reuse the bytes select_eligible already read; nil means the file could not
  -- be read at all, which for an ELIGIBLE file is the corrupt path.
  local text = selected.text
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

--- @param deps table  {
---   list_slogs, read_slog, rename, now,
---   own_student_ref: string|nil  -- `identity.enrollment.student_ref` of the
---     session that is STARTING, or nil when this recorder holds no verifying
---     enrollment. THE ENTIRE OWNERSHIP SIGNAL — see "Decision — OWNERSHIP".
---     Optional, and absent reads as nil, so a caller that predates the
---     enrollment work keeps exactly the behaviour it had (an unattributed
---     recorder in a directory of unattributed logs).
--- }
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
