--- paste_payload.build_paste_payload (Plan 6, Task 2).
--- Faithful port of the monorepo's events/paste-payload.ts. Pure function:
--- no editor API, no chain/signing. Close variant of Plan 5's
--- external_change_content.build_external_change_content — same 4096/512
--- constants and UTF-16 head/tail slicing, plus a sha256 field.
local pp = require("provenance.recorder.events.paste_payload")
local core_sha256 = require("provenance.core.sha256")
local ecc = require("provenance.recorder.events.external_change_content")

describe("paste_payload.build_paste_payload", function()
  it("constants match the monorepo source", function()
    assert.equals(4096, pp.MAX_INLINE_BYTES)
    assert.equals(512, pp.HEAD_TAIL_BYTES)
  end)

  it("short ASCII text: inline content, sha256 set, no head/tail", function()
    local text = "hello world"
    local fields = pp.build_paste_payload(text)
    assert.equals(11, fields.length)
    assert.equals(text, fields.content)
    assert.equals(core_sha256.hex(text), fields.sha256)
    assert.is_nil(fields.content_head)
    assert.is_nil(fields.content_tail)
  end)

  it("empty text: length = 0, content = '', sha256 of empty string (inline branch)", function()
    local fields = pp.build_paste_payload("")
    assert.equals(0, fields.length)
    assert.equals("", fields.content)
    assert.equals(core_sha256.hex(""), fields.sha256)
    assert.is_nil(fields.content_head)
    assert.is_nil(fields.content_tail)
  end)

  it("exactly MAX_INLINE_BYTES (4096) bytes: still inline (<=, not <)", function()
    local text = string.rep("a", 4096)
    local fields = pp.build_paste_payload(text)
    assert.equals(4096, fields.length)
    assert.equals(text, fields.content)
    assert.equals(core_sha256.hex(text), fields.sha256)
    assert.is_nil(fields.content_head)
    assert.is_nil(fields.content_tail)
  end)

  it("4097 bytes (one over the boundary): truncated, head/tail set, content absent", function()
    local text = string.rep("a", 4097)
    local fields = pp.build_paste_payload(text)
    assert.equals(4097, fields.length)
    assert.is_nil(fields.content)
    assert.equals(core_sha256.hex(text), fields.sha256)
    assert.equals(512, #fields.content_head)
    assert.equals(string.rep("a", 512), fields.content_head)
    assert.equals(512, #fields.content_tail)
    assert.equals(string.rep("a", 512), fields.content_tail)
  end)

  it("> MAX_INLINE_BYTES: head/tail set, content absent, length + sha256 correct", function()
    local text = string.rep("a", 5000)
    local fields = pp.build_paste_payload(text)
    assert.equals(5000, fields.length)
    assert.is_nil(fields.content)
    assert.equals(core_sha256.hex(text), fields.sha256)
    assert.equals(512, #fields.content_head)
    assert.equals(string.rep("a", 512), fields.content_head)
    assert.equals(512, #fields.content_tail)
    assert.equals(string.rep("a", 512), fields.content_tail)
  end)

  it("multibyte length in bytes: an emoji is 4 UTF-8 bytes, not 1 char", function()
    local fields = pp.build_paste_payload("\240\159\152\128") -- U+1F600 GRINNING FACE ("😀")
    assert.equals(4, fields.length)
    assert.equals("\240\159\152\128", fields.content)
  end)

  it("multibyte text under 4096 bytes: length is UTF-8 byte length, > char count", function()
    -- "日本語" = 3 codepoints, 3 bytes each in UTF-8 = 9 bytes.
    local text = "日本語"
    local fields = pp.build_paste_payload(text)
    assert.equals(9, fields.length)
    assert.equals(text, fields.content)
    assert.is_true(fields.length > 3) -- byte length, not codepoint count
  end)

  it(
    "large multibyte case (>4096 bytes of emoji): head/tail slice by UTF-16 units, "
      .. "identical to external_change_content's slicing for the same text",
    function()
      -- U+1F600 "😀" = 4 UTF-8 bytes, 2 UTF-16 units (surrogate pair).
      -- 1200 repeats = 4800 bytes > 4096, and an even count keeps the 512-unit
      -- boundary on a whole-codepoint edge (matches external_change_content's
      -- documented deviation: never split an astral codepoint).
      local emoji = "\240\159\152\128"
      local text = string.rep(emoji, 1200)
      local fields = pp.build_paste_payload(text)

      assert.equals(#text, fields.length)
      assert.equals(core_sha256.hex(text), fields.sha256)
      assert.is_nil(fields.content)
      assert.is_not_nil(fields.content_head)
      assert.is_not_nil(fields.content_tail)

      local ecc_fields = ecc.build_external_change_content(text)
      assert.equals(ecc_fields.new_content_head, fields.content_head)
      assert.equals(ecc_fields.new_content_tail, fields.content_tail)
    end
  )
end)
