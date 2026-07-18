--- Tests for external_change_detector.compare_saved_content — direction-critical
--- pure comparison of expected (in-editor) vs on-disk content. Port of
--- external-change-detector.test.ts. See docs/design.md §4.5.
---
--- THE POINT OF THIS FILE: old_hash MUST be the expected/editor hash and
--- new_hash MUST be the actual on-disk hash. A swapped implementation must
--- fail the "explicit direction regression" test below.
local detector = require("provenance.recorder.events.external_change_detector")
local expected_content = require("provenance.recorder.state.expected_content")
local sha256 = require("provenance.core.sha256")

-- ---------------------------------------------------------------------------
-- clean_save
-- ---------------------------------------------------------------------------

describe("external_change_detector.compare_saved_content: clean save", function()
  it("typed-then-clean-save: on-disk content matches expected -> clean_save", function()
    local ec = expected_content.new("hello")
    ec.apply_delta({
      range = { start = { line = 0, character = 5 }, ["end"] = { line = 0, character = 5 } },
      text = " world",
    })
    -- Simulate the editor saving exactly its own in-memory content to disk.
    local on_disk = ec.get_content()

    local result = detector.compare_saved_content(ec, on_disk)

    assert.equals("clean_save", result.kind)
    assert.equals(ec.hash(), result.new_hash)
    assert.is_nil(result.old_hash)
    assert.is_nil(result.diff_size)
  end)
end)

-- ---------------------------------------------------------------------------
-- external_change: DIRECTION REGRESSION (the whole point of this task)
-- ---------------------------------------------------------------------------

describe("external_change_detector.compare_saved_content: direction regression", function()
  it("old_hash is the EXPECTED/editor hash; new_hash is the ACTUAL on-disk hash", function()
    local ec = expected_content.new("original content")
    local on_disk = "someone else changed this file"

    local expected_hash_value = ec.hash()
    local disk_hash_value = sha256.hex(on_disk)
    -- Sanity: the two hashes actually differ, else this test proves nothing.
    assert.is_not.equals(expected_hash_value, disk_hash_value)

    local result = detector.compare_saved_content(ec, on_disk)

    assert.equals("external_change", result.kind)
    -- DIRECTION GUARD: a swapped implementation (old<->new) must fail these two.
    assert.equals(expected_hash_value, result.old_hash)
    assert.equals(disk_hash_value, result.new_hash)
  end)
end)

-- ---------------------------------------------------------------------------
-- non-mutation
-- ---------------------------------------------------------------------------

describe("external_change_detector.compare_saved_content: non-mutation", function()
  it("does not mutate expected_ec's content or hash", function()
    local ec = expected_content.new("stable content")
    local content_before = ec.get_content()
    local hash_before = ec.hash()

    detector.compare_saved_content(ec, "totally different disk content")

    assert.equals(content_before, ec.get_content())
    assert.equals(hash_before, ec.hash())
  end)
end)

-- ---------------------------------------------------------------------------
-- diff_size: UTF-16 code-unit length difference (matches JS .length)
-- ---------------------------------------------------------------------------

describe("external_change_detector.compare_saved_content: diff_size", function()
  it("whole-file replacement, BMP multibyte: expected 'abc' (3 units) vs disk 'ab' (2 units) -> 1", function()
    local ec = expected_content.new("abc")
    local result = detector.compare_saved_content(ec, "ab")
    assert.equals("external_change", result.kind)
    assert.equals(1, result.diff_size)
  end)

  it("astral codepoint counts as 2 UTF-16 units: expected '' vs disk containing one astral char -> 2", function()
    local ec = expected_content.new("")
    -- U+1F600 GRINNING FACE, UTF-8 bytes: F0 9F 98 80
    local astral = "\240\159\152\128"
    local result = detector.compare_saved_content(ec, astral)
    assert.equals("external_change", result.kind)
    assert.equals(2, result.diff_size)
  end)

  it("documented limitation: same-length-different-bytes -> external_change with diff_size 0", function()
    local ec = expected_content.new("abcd")
    local result = detector.compare_saved_content(ec, "abXd")
    assert.equals("external_change", result.kind)
    assert.equals(0, result.diff_size)
  end)
end)
