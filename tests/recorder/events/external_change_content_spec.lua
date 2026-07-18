--- external_change_content.build_external_change_content (Plan 5, Task 2).
--- Faithful port of the monorepo's external-change-content.ts. Pure
--- function: no editor API, no chain/hash/signing.
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

describe("external_change_content.build_external_change_content", function()
  it("constants match the monorepo source", function()
    assert.equals(4096, ecc.MAX_INLINE_BYTES)
    assert.equals(512, ecc.HEAD_TAIL_BYTES)
  end)

  it("short ASCII text: inline new_content, no head/tail", function()
    local fields = ecc.build_external_change_content("hello world")
    assert.equals(11, fields.new_content_size)
    assert.equals("hello world", fields.new_content)
    assert.is_nil(fields.new_content_head)
    assert.is_nil(fields.new_content_tail)
  end)

  it("empty text: new_content = '', new_content_size = 0 (inline branch)", function()
    local fields = ecc.build_external_change_content("")
    assert.equals(0, fields.new_content_size)
    assert.equals("", fields.new_content)
    assert.is_nil(fields.new_content_head)
    assert.is_nil(fields.new_content_tail)
  end)

  it("exactly MAX_INLINE_BYTES (4096) bytes: still inline (<=, not <)", function()
    local text = string.rep("a", 4096)
    local fields = ecc.build_external_change_content(text)
    assert.equals(4096, fields.new_content_size)
    assert.equals(text, fields.new_content)
    assert.is_nil(fields.new_content_head)
    assert.is_nil(fields.new_content_tail)
  end)

  it("> MAX_INLINE_BYTES: head/tail set, new_content absent, sizes correct", function()
    local text = string.rep("a", 5000)
    local fields = ecc.build_external_change_content(text)
    assert.equals(5000, fields.new_content_size)
    assert.is_nil(fields.new_content)
    assert.equals(512, #fields.new_content_head)
    assert.equals(string.rep("a", 512), fields.new_content_head)
    assert.equals(512, #fields.new_content_tail)
    assert.equals(string.rep("a", 512), fields.new_content_tail)
  end)

  it("multibyte text under 4096 bytes: new_content_size is UTF-8 byte length, > char count", function()
    -- "日本語" = 3 codepoints, 3 bytes each in UTF-8 = 9 bytes.
    local text = "日本語"
    local fields = ecc.build_external_change_content(text)
    assert.equals(9, fields.new_content_size)
    assert.equals(text, fields.new_content)
    assert.is_true(fields.new_content_size > 3) -- byte length, not codepoint count
  end)

  describe("cross-language fixture (external-change-content.json, generated from the real TS source)", function()
    local fixture = load_fixture("external-change-content.json")

    it("has at least 4 cases", function()
      assert.is_true(#fixture >= 4)
    end)

    for idx, case in ipairs(fixture) do
      it(string.format("case %d: build_external_change_content matches Node's output exactly", idx), function()
        local fields = ecc.build_external_change_content(case.input)
        assert.equals(case.expected.new_content_size, fields.new_content_size)
        assert.equals(case.expected.new_content, fields.new_content)
        assert.equals(case.expected.new_content_head, fields.new_content_head)
        assert.equals(case.expected.new_content_tail, fields.new_content_tail)
      end)
    end
  end)
end)
