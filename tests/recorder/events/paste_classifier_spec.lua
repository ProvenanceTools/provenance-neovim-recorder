--- Tests for paste_classifier.classify_change — signal 1 of three-signal
--- paste detection (PRD §4.3). Port of paste-classifier.test.ts.
---
--- THE POINT OF THIS FILE: pin the two-rule boundary exactly, and prove
--- char-length is UTF-16 code units (matches JS .length) — NOT Lua `#`
--- bytes and NOT Unicode codepoints.
local paste_classifier = require("provenance.recorder.events.paste_classifier")

local function delta(text, range)
  return {
    range = range or { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 0 } },
    text = text,
  }
end

-- ---------------------------------------------------------------------------
-- constant
-- ---------------------------------------------------------------------------

describe("paste_classifier.PASTE_MIN_INSERT_CHARS", function()
  it("is 30", function()
    assert.equals(30, paste_classifier.PASTE_MIN_INSERT_CHARS)
  end)
end)

-- ---------------------------------------------------------------------------
-- empty input
-- ---------------------------------------------------------------------------

describe("paste_classifier.classify_change: empty input", function()
  it("empty deltas list -> typed", function()
    assert.equals("typed", paste_classifier.classify_change({}))
  end)
end)

-- ---------------------------------------------------------------------------
-- Rule 1: single delta text length threshold
-- ---------------------------------------------------------------------------

describe("paste_classifier.classify_change: rule 1 (single delta length)", function()
  it("single delta text of exactly 30 chars -> paste_likely", function()
    local text = string.rep("a", 30)
    assert.equals("paste_likely", paste_classifier.classify_change({ delta(text) }))
  end)

  it("single delta text of 29 chars -> typed", function()
    local text = string.rep("a", 29)
    assert.equals("typed", paste_classifier.classify_change({ delta(text) }))
  end)

  it("single delta text of length 0 -> typed", function()
    assert.equals("typed", paste_classifier.classify_change({ delta("") }))
  end)

  it("single delta >=30 chars at a NON-EMPTY range -> paste_likely (rule 1 ignores range)", function()
    local text = string.rep("a", 30)
    local non_empty_range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 10 } }
    assert.equals("paste_likely", paste_classifier.classify_change({ delta(text, non_empty_range) }))
  end)

  it("multi-delta where ONE delta is >=30 chars -> paste_likely", function()
    local small = delta("ab")
    local big = delta(string.rep("x", 30))
    assert.equals("paste_likely", paste_classifier.classify_change({ small, big }))
  end)
end)

-- ---------------------------------------------------------------------------
-- Rule 2: aggregate length + newline gate
-- ---------------------------------------------------------------------------

describe("paste_classifier.classify_change: rule 2 (aggregate + newline)", function()
  it("aggregate >=30 chars across multiple deltas WITH a newline in some delta -> paste_likely", function()
    local d1 = delta(string.rep("a", 15))
    local d2 = delta(string.rep("b", 14) .. "\n")
    assert.equals("paste_likely", paste_classifier.classify_change({ d1, d2 }))
  end)

  it("aggregate >=30 chars across multiple deltas WITHOUT any newline (multi-cursor typing) -> typed", function()
    local d1 = delta(string.rep("a", 15))
    local d2 = delta(string.rep("b", 15))
    assert.equals("typed", paste_classifier.classify_change({ d1, d2 }))
  end)

  it("aggregate <30 chars WITH a newline -> typed", function()
    local d1 = delta(string.rep("a", 5))
    local d2 = delta(string.rep("b", 4) .. "\n")
    assert.equals("typed", paste_classifier.classify_change({ d1, d2 }))
  end)
end)

-- ---------------------------------------------------------------------------
-- UTF-16 fidelity: char-length is UTF-16 CODE UNITS, not bytes, not codepoints
-- ---------------------------------------------------------------------------

describe("paste_classifier.classify_change: UTF-16 code-unit fidelity", function()
  -- U+1F600 GRINNING FACE: 4 UTF-8 bytes, 1 codepoint, 2 UTF-16 units.
  local astral = "\240\159\152\128"

  it("16 astral emoji = 32 UTF-16 units (>=30) -> paste_likely, proving units not codepoints (16 codepoints < 30)", function()
    local text = string.rep(astral, 16)
    assert.equals("paste_likely", paste_classifier.classify_change({ delta(text) }))
  end)

  it("20 astral emoji = 40 UTF-16 units (>=30) but 80 bytes -> paste_likely (units), consistent with byte count too", function()
    local text = string.rep(astral, 20)
    assert.equals("paste_likely", paste_classifier.classify_change({ delta(text) }))
  end)

  it("14 astral emoji = 28 UTF-16 units (<30), 56 bytes -> typed, proving units not bytes (byte count would misclassify as paste)", function()
    local text = string.rep(astral, 14)
    assert.equals("typed", paste_classifier.classify_change({ delta(text) }))
  end)
end)
