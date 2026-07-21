--- paste_payload.build_paste_payload (Plan 6, Task 2).
--- Faithful port of the monorepo's events/paste-payload.ts. Pure function:
--- no editor API, no chain/signing. Close variant of Plan 5's
--- external_change_content.build_external_change_content — same 65536/512
--- constants and UTF-16 head/tail slicing, plus a sha256 field.
local pp = require("provenance.recorder.events.paste_payload")
local core_sha256 = require("provenance.core.sha256")
local ecc = require("provenance.recorder.events.external_change_content")

local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture(name)
  -- tests/recorder/events/ -> tests/conformance/fixtures/
  local dir = this_file_dir() .. "/../../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. name), "\n"))
end

describe("paste_payload.build_paste_payload", function()
  it("constants match the monorepo source", function()
    assert.equals(65536, pp.MAX_INLINE_BYTES)
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

  it("exactly MAX_INLINE_BYTES (65536) bytes: still inline (<=, not <)", function()
    local text = string.rep("a", 65536)
    local fields = pp.build_paste_payload(text)
    assert.equals(65536, fields.length)
    assert.equals(text, fields.content)
    assert.equals(core_sha256.hex(text), fields.sha256)
    assert.is_nil(fields.content_head)
    assert.is_nil(fields.content_tail)
  end)

  it("65537 bytes (one over the boundary): truncated, head/tail set, content absent", function()
    local text = string.rep("a", 65537)
    local fields = pp.build_paste_payload(text)
    assert.equals(65537, fields.length)
    assert.is_nil(fields.content)
    assert.equals(core_sha256.hex(text), fields.sha256)
    assert.equals(512, #fields.content_head)
    assert.equals(string.rep("a", 512), fields.content_head)
    assert.equals(512, #fields.content_tail)
    assert.equals(string.rep("a", 512), fields.content_tail)
  end)

  it("> MAX_INLINE_BYTES: head/tail set, content absent, length + sha256 correct", function()
    local text = string.rep("a", 70000)
    local fields = pp.build_paste_payload(text)
    assert.equals(70000, fields.length)
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

  it("multibyte text under the cap: length is UTF-8 byte length, > char count", function()
    -- "日本語" = 3 codepoints, 3 bytes each in UTF-8 = 9 bytes.
    local text = "日本語"
    local fields = pp.build_paste_payload(text)
    assert.equals(9, fields.length)
    assert.equals(text, fields.content)
    assert.is_true(fields.length > 3) -- byte length, not codepoint count
  end)

  it(
    "large multibyte case (> 64 KB of emoji): head/tail slice by UTF-16 units, "
      .. "identical to external_change_content's slicing for the same text",
    function()
      -- U+1F600 "😀" = 4 UTF-8 bytes, 2 UTF-16 units (surrogate pair).
      -- 16400 repeats = 65600 bytes > 65536, and an even count keeps the 512-unit
      -- boundary on a whole-codepoint edge (matches external_change_content's
      -- documented deviation: never split an astral codepoint).
      local emoji = "\240\159\152\128"
      local text = string.rep(emoji, 16400)
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

  -- Cross-language vector, generated from the monorepo TS by
  -- tools/export-conformance-vectors.ts --recorder-out. A `paste` event is NOT
  -- duplicated by a `doc.change`, so a divergence here silently loses evidence in
  -- exactly the case the product exists to catch. Never hand-edit; regenerate.
  describe("cross-language fixture (paste-payload.json, generated from the real TS source)", function()
    local fixture = load_fixture("paste-payload.json")

    it("has at least 6 cases and exercises both branches", function()
      assert.is_true(#fixture >= 6)
      local inlined, truncated = 0, 0
      for _, case in ipairs(fixture) do
        if case.expected.content ~= nil then
          inlined = inlined + 1
        else
          truncated = truncated + 1
        end
      end
      assert.is_true(inlined > 0)
      assert.is_true(truncated > 0)
    end)

    for idx, case in ipairs(fixture) do
      it(string.format("case %d: build_paste_payload matches Node's output exactly", idx), function()
        local fields = pp.build_paste_payload(case.input)
        assert.equals(case.expected.length, fields.length)
        assert.equals(case.expected.sha256, fields.sha256)
        assert.equals(case.expected.content, fields.content)
        assert.equals(case.expected.content_head, fields.content_head)
        assert.equals(case.expected.content_tail, fields.content_tail)
      end)
    end
  end)
end)
