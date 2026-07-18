--- Tests for paste_correlator — the fusion of the three paste-detection
--- signals (Plan 6, Task 3):
---   signal 1: paste_classifier.classify_change (bulk-insertion shape)
---   signal 2: vim.paste intercept (the editor tells us a paste happened)
---   signal 3: the intercepted/clipboard TEXT, content-matched against the
---     actual inserted text
---
--- THE POINT OF THIS FILE: pin the decision tree (confirmed-vs-shape
--- routing), the EOL-normalized containment/equality content match, the
--- window gate, and consume-once semantics.
local correlator = require("provenance.recorder.events.paste_correlator")
local paste_payload = require("provenance.recorder.events.paste_payload")
local core_sha256 = require("provenance.core.sha256")

local function empty_range(line, character)
  line = line or 0
  character = character or 0
  return { start = { line = line, character = character }, ["end"] = { line = line, character = character } }
end

local function non_empty_range(line, start_char, end_char)
  line = line or 0
  return { start = { line = line, character = start_char }, ["end"] = { line = line, character = end_char } }
end

local function delta(text, range)
  return { range = range or empty_range(), text = text }
end

local function new_correlator(extra)
  local opts = { get_now = function() return 0 end }
  if extra then
    for k, v in pairs(extra) do
      opts[k] = v
    end
  end
  return correlator.new(opts)
end

-- ---------------------------------------------------------------------------
-- Confirmed paste (single-delta, empty range) + consume-once
-- ---------------------------------------------------------------------------

describe("paste_correlator: confirmed paste via intercept", function()
  it("intercept + matching single-delta empty-range change within window -> paste, payload correct, range passed through", function()
    local c = new_correlator()
    local clip = "HELLO WORLD, THIS IS A PASTED CLIPBOARD STRING"
    assert.is_true(#clip >= 30)

    c.on_paste_intercept(clip, 0)

    local range = empty_range(3, 4)
    local deltas = { delta(clip, range) }
    local decision = c.on_doc_change(deltas, range, 1)

    assert.equals("paste", decision.kind)
    assert.same(range, decision.range)
    assert.equals(clip, decision.payload.content)
    assert.equals(#clip, decision.payload.length)
    assert.equals(core_sha256.hex(clip), decision.payload.sha256)
    assert.same(paste_payload.build_paste_payload(clip), decision.payload)
  end)

  it("consumes the pending intercept: a later change (no new intercept) is NOT confirmed by it", function()
    local c = new_correlator()
    local clip = "HELLO WORLD, THIS IS A PASTED CLIPBOARD STRING"

    c.on_paste_intercept(clip, 0)

    local range = empty_range()
    c.on_doc_change({ delta(clip, range) }, range, 1)

    -- Second change: a SMALL (<30 char, so classifier says "typed") substring
    -- of the original clipboard text, no new intercept. If the pending
    -- intercept were still live it would content-match (containment) and
    -- confirm -> paste. Because it was consumed by the first change, this
    -- must resolve as plain typing.
    local small = clip:sub(1, 10)
    assert.is_true(#small < 30)
    local range2 = empty_range()
    local decision2 = c.on_doc_change({ delta(small, range2) }, range2, 2)

    assert.equals("doc.change", decision2.kind)
    assert.equals("typed", decision2.source)
  end)
end)

-- ---------------------------------------------------------------------------
-- EOL-normalized content match (signal 3)
-- ---------------------------------------------------------------------------

describe("paste_correlator: EOL-normalized content match", function()
  it("clipboard with CRLF matches inserted text with LF (same content, different EOL) -> confirmed paste", function()
    local c = new_correlator()
    -- Kept under 30 chars (both raw and normalized) so the classifier alone
    -- would say "typed" -- any "paste" result here must come from the
    -- confirmed-intercept path, proving EOL normalization drove the match.
    local clip = "x\r\n" .. string.rep("y", 20)
    local inserted = "x\n" .. string.rep("y", 20)
    assert.is_true(#clip < 30)
    assert.is_true(#inserted < 30)

    c.on_paste_intercept(clip, 0)

    local range = empty_range()
    local decision = c.on_doc_change({ delta(inserted, range) }, range, 1)

    assert.equals("paste", decision.kind)
    assert.equals(inserted, decision.payload.content)
  end)
end)

-- ---------------------------------------------------------------------------
-- Window gate
-- ---------------------------------------------------------------------------

describe("paste_correlator: window gate", function()
  it("change past window (classify=typed) -> NOT confirmed -> doc.change source=typed", function()
    local c = new_correlator({ window_ms = 1000 })
    local text = "short match"
    assert.is_true(#text < 30)

    c.on_paste_intercept(text, 0)

    local range = empty_range()
    local decision = c.on_doc_change({ delta(text, range) }, range, 1001) -- window_ms + 1

    assert.equals("doc.change", decision.kind)
    assert.equals("typed", decision.source)
  end)

  it("change exactly at the window boundary (<=window_ms) is still confirmed", function()
    local c = new_correlator({ window_ms = 1000 })
    local text = "short match"

    c.on_paste_intercept(text, 0)

    local range = empty_range()
    local decision = c.on_doc_change({ delta(text, range) }, range, 1000) -- == window_ms

    assert.equals("paste", decision.kind)
  end)
end)

-- ---------------------------------------------------------------------------
-- Non-matching clipboard content
-- ---------------------------------------------------------------------------

describe("paste_correlator: non-matching clipboard content", function()
  it("intercept content doesn't match inserted text; multi-delta (not paste-shaped) + paste_likely -> doc.change source=paste_likely", function()
    local c = new_correlator()
    c.on_paste_intercept("FOO", 0)

    local d1 = delta(string.rep("B", 30))
    local d2 = delta(string.rep("A", 30))
    local range = non_empty_range(0, 0, 5)
    local decision = c.on_doc_change({ d1, d2 }, range, 1)

    assert.equals("doc.change", decision.kind)
    assert.equals("paste_likely", decision.source)
    assert.same({ d1, d2 }, decision.deltas)

    local counts = c.counts()
    assert.equals(1, counts.large_insert)
  end)
end)

-- ---------------------------------------------------------------------------
-- paste_likely doc.change (no intercept at all)
-- ---------------------------------------------------------------------------

describe("paste_correlator: paste_likely without any intercept", function()
  it("multi-delta bulk edit, no intercept -> doc.change source=paste_likely, large_insert_count incremented", function()
    local c = new_correlator()

    local d1 = delta(string.rep("m", 15) .. "\n")
    local d2 = delta(string.rep("n", 16) .. "\n")
    local range = non_empty_range(2, 0, 0)
    local decision = c.on_doc_change({ d1, d2 }, range, 5)

    assert.equals("doc.change", decision.kind)
    assert.equals("paste_likely", decision.source)
    assert.same({ d1, d2 }, decision.deltas)
    assert.equals(1, c.counts().large_insert)
  end)

  it("single-delta, empty-range, >=30 chars, no intercept -> classifier alone routes to paste (shape fits)", function()
    local c = new_correlator()
    local text = string.rep("z", 40)
    local range = empty_range()
    local decision = c.on_doc_change({ delta(text, range) }, range, 5)

    assert.equals("paste", decision.kind)
    assert.equals(text, decision.payload.content)
    assert.equals(1, c.counts().large_insert)
  end)
end)

-- ---------------------------------------------------------------------------
-- Plain typing
-- ---------------------------------------------------------------------------

describe("paste_correlator: plain typing", function()
  it("small single-delta change, no intercept -> doc.change source=typed, large_insert_count NOT incremented", function()
    local c = new_correlator()

    local range = empty_range()
    local decision = c.on_doc_change({ delta("x") }, range, 5)

    assert.equals("doc.change", decision.kind)
    assert.equals("typed", decision.source)
    assert.equals(0, c.counts().large_insert)
  end)
end)

-- ---------------------------------------------------------------------------
-- Small confirmed paste (intercept confirms regardless of size)
-- ---------------------------------------------------------------------------

describe("paste_correlator: small confirmed paste", function()
  it("intercept + matching small (<30 char) single-delta empty-range change -> paste; large_insert_count NOT incremented (classify was typed)", function()
    local c = new_correlator()
    local text = "hi there"
    assert.is_true(#text < 30)

    c.on_paste_intercept(text, 0)

    local range = empty_range()
    local decision = c.on_doc_change({ delta(text, range) }, range, 10)

    assert.equals("paste", decision.kind)
    assert.equals(text, decision.payload.content)
    assert.equals(0, c.counts().large_insert)
  end)
end)

-- ---------------------------------------------------------------------------
-- counts()
-- ---------------------------------------------------------------------------

describe("paste_correlator.counts", function()
  it("tracks intercepted and large_insert counts independently across calls", function()
    local c = new_correlator()

    assert.same({ intercepted = 0, large_insert = 0 }, c.counts())

    c.on_paste_intercept("a", 0)
    c.on_paste_intercept("b", 1)
    assert.same({ intercepted = 2, large_insert = 0 }, c.counts())

    -- plain typing: no large_insert increment
    c.on_doc_change({ delta("x") }, empty_range(), 2)
    assert.same({ intercepted = 2, large_insert = 0 }, c.counts())

    -- paste_likely classification (single delta >= 30 chars, no matching intercept content)
    local big = string.rep("q", 30)
    c.on_doc_change({ delta(big) }, empty_range(), 3)
    assert.same({ intercepted = 2, large_insert = 1 }, c.counts())

    local big2 = string.rep("r", 40)
    c.on_doc_change({ delta(big2) }, empty_range(), 4)
    assert.same({ intercepted = 2, large_insert = 2 }, c.counts())
  end)
end)

-- ---------------------------------------------------------------------------
-- Independent instances
-- ---------------------------------------------------------------------------

describe("paste_correlator.new: independent instances", function()
  it("two correlator instances do not share state", function()
    local c1 = new_correlator()
    local c2 = new_correlator()

    c1.on_paste_intercept("shared text here padded to be long enough", 0)

    assert.equals(1, c1.counts().intercepted)
    assert.equals(0, c2.counts().intercepted)
  end)
end)
