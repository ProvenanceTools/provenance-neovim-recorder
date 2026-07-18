--- paste_correlator.lua — fuses the three paste-detection signals into
--- exactly ONE decision per doc.change (Plan 6, Task 3):
---   signal 1: paste_classifier.classify_change (bulk-insertion shape)
---   signal 2: a vim.paste intercept (the editor tells us a paste happened)
---   signal 3: the intercepted/clipboard TEXT, content-matched against the
---     actual inserted text
---
--- Neovim-specific advantage over the VS Code v1 design: `vim.paste` hands
--- us the pasted text directly, so signals 2 and 3 collapse into a single
--- `on_paste_intercept(text, at)` call that carries both "a paste happened"
--- and "here is its content" — no separate clipboard-register poll needed.
---
--- DECISION TREE (see on_doc_change): a change is routed to a `paste` event
--- only when BOTH (a) it is either a CONFIRMED intercept (content-matched,
--- within the time window) or classifier-flagged "paste_likely", AND
--- (b) it is PasteDecision-shaped — a single delta at an EMPTY range (pure
--- insertion). That shape constraint exists because PastePayload can only
--- carry one range + one text; a multi-delta edit or a delta that REPLACES
--- an existing range (non-empty range) cannot be represented that way
--- without lossy reconstruction, so those route to `doc.change` with
--- `source = "paste_likely"` instead — preserving every delta faithfully.
--- Anything neither confirmed nor paste_likely is plain typing:
--- `doc.change` `source = "typed"`.
---
--- CONSUME-ONCE: the pending intercept is cleared (set to nil) exactly once
--- — the moment it CONFIRMS a doc.change (whichever branch that change
--- resolves to). A change that does not confirm (past window, or content
--- doesn't match) leaves `pending` untouched, so a later change still
--- inside the window can be confirmed by the same intercept.
---
--- PURE-ISH: no chain/canonicalization/signing/IO. Composes paste_classifier
--- and paste_payload (both pure). `at` is passed explicitly by the caller on
--- every call (mirrors doc_events.lua's pure-transform style); `get_now` is
--- accepted for interface parity with this codebase's other injected-clock
--- modules (explanation_tags.lua) and used only as a fallback default when a
--- caller omits `at` — every documented call site always supplies `at`
--- explicitly, so this fallback is not exercised by the fusion algorithm
--- itself.
local paste_classifier = require("provenance.recorder.events.paste_classifier")
local paste_payload = require("provenance.recorder.events.paste_payload")

local M = {}

local DEFAULT_WINDOW_MS = 1000
local DEFAULT_SIMILARITY = 0.9

--- EOL-normalize: CRLF and lone CR both collapse to LF before comparison,
--- so a clipboard capture and an inserted-text capture that differ only in
--- line-ending convention still match.
local function normalize_eol(s)
  s = s:gsub("\r\n", "\n")
  s = s:gsub("\r", "\n")
  return s
end

--- Signal 3 content match (v1 rule): after EOL normalization, a match is
--- equality OR containment in either direction, provided the clipboard side
--- is non-empty. `similarity` is accepted on the constructor for a possible
--- future fuzzy-ratio fallback but is NOT consulted here — containment /
--- equality is the entire implemented matching path.
local function matches(inserted, clipboard)
  local a = normalize_eol(inserted)
  local b = normalize_eol(clipboard)
  if b == "" then
    return false
  end
  if a == b then
    return true
  end
  if string.find(a, b, 1, true) ~= nil then
    return true
  end
  if string.find(b, a, 1, true) ~= nil then
    return true
  end
  return false
end

local function same_position(a, b)
  return a.line == b.line and a.character == b.character
end

--- @param opts table  { window_ms?, get_now, similarity? }
--- @return table c  { on_paste_intercept, on_doc_change, counts }
function M.new(opts)
  opts = opts or {}
  local window_ms = opts.window_ms or DEFAULT_WINDOW_MS
  local get_now = opts.get_now
  local _similarity = opts.similarity or DEFAULT_SIMILARITY -- accepted for interface parity; see matches()

  local pending = nil -- nil | { text = string, at = number }
  local intercepted_count = 0
  local large_insert_count = 0

  local function resolve_at(explicit_at)
    if explicit_at ~= nil then
      return explicit_at
    end
    if get_now then
      return get_now()
    end
    return 0
  end

  local c = {}

  --- SIGNAL 2+3: vim.paste hands us the intercepted text directly. Latest
  --- intercept wins — it overwrites any prior, still-unconsumed pending.
  function c.on_paste_intercept(text, at)
    at = resolve_at(at)
    intercepted_count = intercepted_count + 1
    pending = { text = text, at = at }
  end

  --- The fusion: exactly one decision per call. See module header for the
  --- decision tree and the consume-once rule.
  --- @param deltas table  list of { range, text }
  --- @param range table  overall paste-target range, passed through as-is
  ---   on a `paste` decision
  --- @param at number
  --- @return table decision
  function c.on_doc_change(deltas, range, at)
    at = resolve_at(at)

    local classification = paste_classifier.classify_change(deltas)
    if classification == "paste_likely" then
      large_insert_count = large_insert_count + 1
    end

    local inserted = table.concat(vim.tbl_map(function(d)
      return d.text
    end, deltas))

    local confirmed = false
    if pending ~= nil and (at - pending.at) <= window_ms and matches(inserted, pending.text) then
      confirmed = true
    end

    local is_paste_shaped = #deltas == 1 and same_position(deltas[1].range.start, deltas[1].range["end"])

    if (confirmed or classification == "paste_likely") and is_paste_shaped then
      if confirmed then
        pending = nil
      end
      return { kind = "paste", payload = paste_payload.build_paste_payload(inserted), range = range }
    elseif confirmed or classification == "paste_likely" then
      if confirmed then
        pending = nil
      end
      return { kind = "doc.change", source = "paste_likely", deltas = deltas }
    else
      return { kind = "doc.change", source = "typed", deltas = deltas }
    end
  end

  --- For the reconciler (Task 4).
  function c.counts()
    return { intercepted = intercepted_count, large_insert = large_insert_count }
  end

  return c
end

return M
