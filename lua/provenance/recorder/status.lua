--- Statusline segment for the activation gate. Shows a persistent
--- "recording" indicator only when the attached RecorderState is active.
--- Active/absent-only model (mirrors the VS Code recorder): a degraded
--- state is surfaced via notification elsewhere, not here.
---
--- ENROLLMENT rides on top as a suffix. Recording that nobody can attribute is
--- its own quiet failure, and unlike a degraded write it is the DEFAULT state of
--- a fresh install -- so it belongs in the persistent indicator rather than in a
--- notification the student sees twice and never again. Read from the attached
--- registry's identity outcomes; absent (an older attach, or a plain
--- RecorderState with no such method) it is simply omitted.

local M = {}

-- Module-level attached-state reference. This singleton is intentional:
-- a user's statusline expression (`%{v:lua.require'provenance.recorder.status'.segment()}`)
-- calls segment() with no arguments, so it must read from somewhere the
-- plugin registered ahead of time. Kept as a `local` upvalue, never `_G`.
local attached = nil

local enroll_nudge = require("provenance.recorder.enroll_nudge")

local RECORDING_SEGMENT = "● Provenance: recording"

--- Register a RecorderState instance so segment() reflects it.
--- @param state table RecorderState instance (from provenance.recorder.state)
function M.attach(state)
  attached = state
end

--- Clear the attached state. Teardown counterpart to attach().
function M.detach()
  attached = nil
end

--- Whether the attached state reports every session un-enrolled.
--- Defensive: `identity_outcomes` is optional on the attached object, and a
--- statusline expression must never throw -- it is evaluated on every redraw.
--- @return boolean
local function unenrolled()
  if not attached or type(attached.identity_outcomes) ~= "function" then
    return false
  end
  local ok, outcomes = pcall(attached.identity_outcomes)
  if not ok then
    return false
  end
  return enroll_nudge.is_unenrolled(outcomes)
end

--- Statusline segment text.
--- @return string "● Provenance: recording" (plus " (not enrolled)") when active, "" otherwise
function M.segment()
  if attached and attached.is_active() then
    return RECORDING_SEGMENT .. enroll_nudge.segment_suffix(unenrolled())
  end
  return ""
end

return M
