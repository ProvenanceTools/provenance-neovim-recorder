--- ExplanationTagger: a single-slot time-window store for marking benign
--- external changes (formatter/git operations) during the external-change
--- detection flow (Plan 5, recorder PRD §4.5).
---
--- When an fs.external_change event is detected, the wiring asks the tagger
--- whether a formatter or git operation ran within a recent window. If so,
--- the event carries an `explanation` field to help the analyzer distinguish
--- intentional tool-driven changes from unexpected file modifications.
---
--- Faithful port of `explanation-tags.ts`: single-slot state (_latest),
--- consume-once semantics, time-window expiry, and latest-mark-wins when
--- two operations occur in the same window.
local M = {}

local DEFAULT_WINDOW_MS = 2000

--- new(opts) -> tagger
--- @param opts table {
---   get_now: function() -> number (ms timestamp source; required),
---   window_ms?: number (time window for expiry; default 2000)
--- }
--- @return table tagger { mark_formatter(), mark_git(), consume() }
function M.new(opts)
  opts = opts or {}

  local get_now = opts.get_now
  local window_ms = opts.window_ms or DEFAULT_WINDOW_MS

  local latest = nil

  local tagger = {}

  --- Set the single slot to mark a formatter operation at the current time.
  function tagger.mark_formatter()
    latest = { kind = "formatter", at = get_now() }
  end

  --- Set the single slot to mark a git operation at the current time.
  function tagger.mark_git()
    latest = { kind = "git", at = get_now() }
  end

  --- Consume the mark if it exists and is still within the time window.
  --- Clears the slot after reading (consume-once semantics).
  --- Returns: "formatter" | "git" | nil
  function tagger.consume()
    if latest == nil then
      return nil
    end

    local elapsed = get_now() - latest.at
    if elapsed >= window_ms then
      latest = nil
      return nil
    end

    local kind = latest.kind
    latest = nil
    return kind
  end

  return tagger
end

return M
