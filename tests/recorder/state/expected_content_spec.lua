--- Tests for ExpectedContent — in-memory file content model + SHA-256.
--- Port of expected-content.test.ts. Foundation for external-change detection
--- (docs/design.md §4.5). See lua/provenance/recorder/state/expected_content.lua.
local expected_content = require("provenance.recorder.state.expected_content")

-- ---------------------------------------------------------------------------
-- Hash correctness (pinned test vector)
-- ---------------------------------------------------------------------------

describe("expected_content.hash", function()
  it("returns sha256 of initial content (pinned vector)", function()
    local ec = expected_content.new("hello world")
    assert.equals("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", ec.hash())
  end)

  it("hash updates after apply_delta", function()
    local ec = expected_content.new("hello world")
    local initial_hash = ec.hash()
    ec.apply_delta({
      range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 0 } },
      text = "X",
    })
    assert.is_not.equals(initial_hash, ec.hash())
  end)

  it("hash updates after reset", function()
    local ec = expected_content.new("hello world")
    local initial_hash = ec.hash()
    ec.reset("goodbye")
    assert.is_not.equals(initial_hash, ec.hash())
  end)

  it("memoizes hash between accesses", function()
    local ec = expected_content.new("hello world")
    local h1 = ec.hash()
    local h2 = ec.hash()
    assert.equals(h1, h2)
  end)
end)

-- ---------------------------------------------------------------------------
-- content access
-- ---------------------------------------------------------------------------

describe("expected_content.get_content", function()
  it("returns initial content", function()
    local ec = expected_content.new("abc")
    assert.equals("abc", ec.get_content())
  end)

  it("reflects insert at offset 0", function()
    local ec = expected_content.new("hello")
    ec.apply_delta({
      range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 0 } },
      text = "X",
    })
    assert.equals("Xhello", ec.get_content())
  end)

  it("reflects replacement of a range", function()
    local ec = expected_content.new("hello world")
    -- Replace 'world' (chars 6-11) with 'there'
    ec.apply_delta({
      range = { start = { line = 0, character = 6 }, ["end"] = { line = 0, character = 11 } },
      text = "there",
    })
    assert.equals("hello there", ec.get_content())
  end)

  it("reflects deletion (empty text)", function()
    local ec = expected_content.new("hello")
    ec.apply_delta({
      range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 3 } },
      text = "",
    })
    assert.equals("lo", ec.get_content())
  end)

  it("reset replaces content", function()
    local ec = expected_content.new("old content")
    ec.reset("new content")
    assert.equals("new content", ec.get_content())
  end)
end)

-- ---------------------------------------------------------------------------
-- line_count
-- ---------------------------------------------------------------------------

describe("expected_content.line_count", function()
  it('empty string -> 0', function()
    assert.equals(0, expected_content.new("").line_count())
  end)

  it('"abc" -> 1', function()
    assert.equals(1, expected_content.new("abc").line_count())
  end)

  it('"abc\\ndef" -> 2', function()
    assert.equals(2, expected_content.new("abc\ndef").line_count())
  end)

  it('"abc\\n" -> 2 (trailing newline counts empty line)', function()
    assert.equals(2, expected_content.new("abc\n").line_count())
  end)

  it('"\\n\\n" -> 3', function()
    assert.equals(3, expected_content.new("\n\n").line_count())
  end)
end)

-- ---------------------------------------------------------------------------
-- apply_deltas (ordered)
-- ---------------------------------------------------------------------------

describe("expected_content.apply_deltas", function()
  it("applies multiple deltas in order", function()
    local ec = expected_content.new("abc")
    ec.apply_deltas({
      { range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 0 } }, text = "X" },
      { range = { start = { line = 0, character = 4 }, ["end"] = { line = 0, character = 4 } }, text = "Y" },
    })
    -- After first: 'Xabc'; after second: 'XabcY'
    assert.equals("XabcY", ec.get_content())
  end)

  it("applying zero deltas is a no-op", function()
    local ec = expected_content.new("hello")
    local hash_before = ec.hash()
    ec.apply_deltas({})
    assert.equals("hello", ec.get_content())
    assert.equals(hash_before, ec.hash())
  end)
end)

-- ---------------------------------------------------------------------------
-- Range edge cases / 0-based offset -> Lua 1-based sub conversion
-- ---------------------------------------------------------------------------

describe("expected_content range edge cases", function()
  it("position at end-of-line inserts before newline", function()
    local ec = expected_content.new("ab\ncd")
    -- character 2 on line 0 = position just before \n
    ec.apply_delta({
      range = { start = { line = 0, character = 2 }, ["end"] = { line = 0, character = 2 } },
      text = "X",
    })
    assert.equals("abX\ncd", ec.get_content())
  end)

  it("position at end-of-document inserts at end", function()
    local ec = expected_content.new("abc")
    ec.apply_delta({
      range = { start = { line = 0, character = 3 }, ["end"] = { line = 0, character = 3 } },
      text = "!",
    })
    assert.equals("abc!", ec.get_content())
  end)

  it("character beyond remaining content clamps to end of content", function()
    local ec = expected_content.new("abc")
    -- character 999 on line 0 clamps to remaining content length (3)
    ec.apply_delta({
      range = { start = { line = 0, character = 999 }, ["end"] = { line = 0, character = 999 } },
      text = "!",
    })
    assert.equals("abc!", ec.get_content())
  end)

  it("multi-line delta replaces across lines", function()
    local ec = expected_content.new("line1\nline2\nline3")
    -- Replace from end of line 0 char 5 to end of line 1 char 5
    ec.apply_delta({
      range = { start = { line = 0, character = 5 }, ["end"] = { line = 1, character = 5 } },
      text = "-replaced-",
    })
    assert.equals("line1-replaced-\nline3", ec.get_content())
  end)

  it("offset 0 delta replaces from the very start", function()
    local ec = expected_content.new("hello")
    ec.apply_delta({
      range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 1 } },
      text = "H",
    })
    assert.equals("Hello", ec.get_content())
  end)

  it("offset at the very end appends", function()
    local ec = expected_content.new("hello")
    ec.apply_delta({
      range = { start = { line = 0, character = 5 }, ["end"] = { line = 0, character = 5 } },
      text = "!",
    })
    assert.equals("hello!", ec.get_content())
  end)
end)
