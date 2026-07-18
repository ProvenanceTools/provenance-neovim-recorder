--- precise_delta: builds a VS-Code-shaped doc.change delta (precise
--- character-level range in pre-edit coords + exactly-inserted text) from an
--- on_bytes edit descriptor. `character` is UTF-16 code units, matching the
--- analyzer's offsetAt/clampPos contract (packages/analysis-core). Runs in the
--- headless nvim harness because it uses vim.str_utfindex.
local precise_delta = require("provenance.recorder.events.precise_delta")

describe("precise_delta.build", function()
  it("single-char insert at end of an ASCII line -> empty range at the insert point, text = the char", function()
    -- pre-edit line 0 = "return x + y" (12 bytes); typed "z" at byte col 12.
    local delta = precise_delta.build(
      { "return x + y" },
      { start_row = 0, start_col = 12, old_end_row = 0, old_end_col = 0, new_end_row = 0, new_end_col = 1 },
      "z"
    )
    assert.equals("z", delta.text)
    assert.same({ line = 0, character = 12 }, delta.range.start)
    assert.same({ line = 0, character = 12 }, delta.range["end"])
  end)

  it("insert after a multibyte char uses UTF-16 code units for the start column", function()
    -- pre-edit line 0 = "aa€bb" = a a € b b, € is 3 bytes (0xE2 0x82 0xAC).
    -- Insert "X" at byte col 5 (right after €). Bytes 0..5 = "aa€" = 3 UTF-16 units.
    local delta = precise_delta.build(
      { "aa\226\130\172bb" },
      { start_row = 0, start_col = 5, old_end_row = 0, old_end_col = 0, new_end_row = 0, new_end_col = 1 },
      "X"
    )
    assert.equals("X", delta.text)
    assert.same({ line = 0, character = 3 }, delta.range.start)
    assert.same({ line = 0, character = 3 }, delta.range["end"])
  end)

  it("deletion spans start..old_end in pre-edit coords, text empty", function()
    -- pre-edit "hello world"; delete " wo" (bytes 5..8). old_end_col delta = 3.
    local delta = precise_delta.build(
      { "hello world" },
      { start_row = 0, start_col = 5, old_end_row = 0, old_end_col = 3, new_end_row = 0, new_end_col = 0 },
      ""
    )
    assert.equals("", delta.text)
    assert.same({ line = 0, character = 5 }, delta.range.start)
    assert.same({ line = 0, character = 8 }, delta.range["end"])
  end)

  it("deletion end column uses the PRE-EDIT line's UTF-16 units", function()
    -- pre-edit "a€cd" (a, €=3B, c, d). Delete "€c": start byte col 1, old_end delta 4 bytes.
    -- start char = UTF-16(bytes 0..1) = 1; end char = UTF-16(bytes 0..5="a€c") = 3.
    local delta = precise_delta.build(
      { "a\226\130\172cd" },
      { start_row = 0, start_col = 1, old_end_row = 0, old_end_col = 4, new_end_row = 0, new_end_col = 0 },
      ""
    )
    assert.equals("", delta.text)
    assert.same({ line = 0, character = 1 }, delta.range.start)
    assert.same({ line = 0, character = 3 }, delta.range["end"])
  end)

  it("replacement: start..old_end replaced by inserted text", function()
    -- pre-edit "hello world"; replace "hello" (bytes 0..5) with "HI".
    local delta = precise_delta.build(
      { "hello world" },
      { start_row = 0, start_col = 0, old_end_row = 0, old_end_col = 5, new_end_row = 0, new_end_col = 2 },
      "HI"
    )
    assert.equals("HI", delta.text)
    assert.same({ line = 0, character = 0 }, delta.range.start)
    assert.same({ line = 0, character = 5 }, delta.range["end"])
  end)

  it("multiline insert: end line/char computed from old_end row delta", function()
    -- pre-edit ["line1"]; insert "AAA\nBBB" at (0,0). Pure insert: end == start.
    local delta = precise_delta.build(
      { "line1" },
      { start_row = 0, start_col = 0, old_end_row = 0, old_end_col = 0, new_end_row = 1, new_end_col = 3 },
      "AAA\nBBB"
    )
    assert.equals("AAA\nBBB", delta.text)
    assert.same({ line = 0, character = 0 }, delta.range.start)
    assert.same({ line = 0, character = 0 }, delta.range["end"])
  end)

  it("multiline deletion: end position is on a later pre-edit line", function()
    -- pre-edit ["a","b","c"]; delete from (0,1) to (1,1) [old_end row delta 1, col 1].
    local delta = precise_delta.build(
      { "a", "b", "c" },
      { start_row = 0, start_col = 1, old_end_row = 1, old_end_col = 1, new_end_row = 0, new_end_col = 0 },
      ""
    )
    assert.equals("", delta.text)
    assert.same({ line = 0, character = 1 }, delta.range.start)
    assert.same({ line = 1, character = 1 }, delta.range["end"])
  end)
end)
