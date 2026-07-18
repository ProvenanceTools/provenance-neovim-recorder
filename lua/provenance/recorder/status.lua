--- Statusline segment for the activation gate. Shows a persistent
--- "recording" indicator only when the attached RecorderState is active.
--- Active/absent-only model (mirrors the VS Code recorder): a degraded
--- state is surfaced via notification elsewhere, not here.

local M = {}

-- Module-level attached-state reference. This singleton is intentional:
-- a user's statusline expression (`%{v:lua.require'provenance.recorder.status'.segment()}`)
-- calls segment() with no arguments, so it must read from somewhere the
-- plugin registered ahead of time. Kept as a `local` upvalue, never `_G`.
local attached = nil

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

--- Statusline segment text.
--- @return string "● Provenance: recording" when active, "" otherwise
function M.segment()
  if attached and attached.is_active() then
    return RECORDING_SEGMENT
  end
  return ""
end

return M
