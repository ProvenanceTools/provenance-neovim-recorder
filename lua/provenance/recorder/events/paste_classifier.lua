--- Paste classifier — signal 1 of three-signal paste detection (PRD §4.3).
---
--- Originally (per PRD's literal wording): exactly ONE delta whose
--- text length >= 30 AND whose range is empty. That catches classical Cmd+V
--- pastes but misses tool-applied edits (Claude Code, Copilot apply, etc.)
--- which routinely arrive as either multi-delta edits or as single deltas
--- that REPLACE existing text rather than insert at an empty range. Those
--- slipped through as plain doc.change events with source = "typed",
--- defeating downstream "low typing, high output" detection.
---
--- Broadened rule (intent-preserving, schema-compatible — the
--- "paste_likely" source value is already in the doc.change payload):
---
---   paste_likely if ANY of:
---     - a single delta with char-length >= PASTE_MIN_INSERT_CHARS
---       (covers classical paste AND large single-shot replacement edits)
---     - total inserted chars across deltas >= PASTE_MIN_INSERT_CHARS AND
---       at least one delta's text contains a newline
---       (covers multi-delta edits that span lines — typical of AI-applied
---       edits — without flagging multi-cursor typing, which produces many
---       small deltas without embedded newlines)
---   typed otherwise.
---
--- Pure function. No I/O, no global state, no Neovim editor API.
---
--- Faithful port of the monorepo's paste-classifier.ts.
local M = {}

--- Minimum characters for an insert to be classified as paste_likely.
M.PASTE_MIN_INSERT_CHARS = 30

--- Count UTF-16 code units a UTF-8 string would decode to (matches JS
--- string .length exactly): 1 per BMP codepoint (<= 0xFFFF), 2 per astral
--- codepoint (>= 0x10000, encoded as a surrogate pair in UTF-16).
--- @param s string  UTF-8 byte string
--- @return integer
local function char_len(s)
  local len = 0
  local i = 1
  local n = #s
  while i <= n do
    local b = s:byte(i)
    local cp, size
    if b < 0x80 then
      cp, size = b, 1
    elseif b >= 0xF0 then
      cp = b % 0x08
      size = 4
    elseif b >= 0xE0 then
      cp = b % 0x10
      size = 3
    elseif b >= 0xC0 then
      cp = b % 0x20
      size = 2
    else
      -- Stray continuation byte (malformed UTF-8): treat as one unit so we
      -- never throw on documented inputs.
      cp, size = b, 1
    end

    for k = 1, size - 1 do
      local cb = s:byte(i + k)
      if cb == nil or cb < 0x80 or cb >= 0xC0 then
        -- Truncated/malformed sequence: bail out to single-byte handling.
        cp, size = b, 1
        break
      end
      cp = cp * 0x40 + (cb % 0x40)
    end

    len = len + (cp >= 0x10000 and 2 or 1)
    i = i + size
  end
  return len
end

--- Given the delta set from a single doc.change event, classify whether
--- it looks like a paste / bulk insertion (vs. natural keystroke typing).
---
--- See module header for the full rule. The classifier is intentionally
--- coarse — false positives are addressed downstream by the paste
--- reconciler (signal 3) and analyzer-side heuristics, both of which have
--- more context than a single-event view.
---
--- @param deltas table  list of { range, text } (text is a UTF-8 string)
--- @return "typed"|"paste_likely"
function M.classify_change(deltas)
  if #deltas == 0 then
    return "typed"
  end

  local total_inserted_chars = 0
  local max_single_delta_chars = 0
  local any_delta_has_newline = false

  for _, d in ipairs(deltas) do
    local len = char_len(d.text)
    total_inserted_chars = total_inserted_chars + len
    if len > max_single_delta_chars then
      max_single_delta_chars = len
    end
    if not any_delta_has_newline and d.text:find("\n", 1, true) ~= nil then
      any_delta_has_newline = true
    end
  end

  -- Rule 1: a single delta carries >= threshold chars on its own. Covers
  -- classical paste (empty-range insert) AND large replacement edits where
  -- range is non-empty.
  if max_single_delta_chars >= M.PASTE_MIN_INSERT_CHARS then
    return "paste_likely"
  end

  -- Rule 2: aggregate of multi-delta event >= threshold AND at least one
  -- delta text contains a newline. The newline gate is what distinguishes
  -- a multi-line bulk edit (e.g. an AI tool applying an edit across
  -- several lines) from multi-cursor typing (many small single-line
  -- inserts at distinct cursors).
  if total_inserted_chars >= M.PASTE_MIN_INSERT_CHARS and any_delta_has_newline then
    return "paste_likely"
  end

  return "typed"
end

return M
