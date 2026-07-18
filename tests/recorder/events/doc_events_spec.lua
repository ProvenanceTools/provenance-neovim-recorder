--- Pure doc-event transforms: editor signal -> {kind, data} event shape.
--- No Neovim API, no hashing, no I/O — caller passes precomputed content_hash
--- and relative path. See lua/provenance/recorder/events/doc_events.lua.
local json = require("provenance.core.json")
local doc_events = require("provenance.recorder.events.doc_events")

describe("doc_events.transform_doc_open", function()
  it("inlines content when byte length is within the limit", function()
    local text = "hello world"
    local ev = doc_events.transform_doc_open("a.lua", "deadbeef", text, 1)
    assert.equals("doc.open", ev.kind)
    assert.equals("a.lua", ev.data.path)
    assert.equals("deadbeef", ev.data.sha256)
    assert.equals(1, ev.data.line_count)
    assert.equals(text, ev.data.content)
    assert.is_nil(ev.data.truncated)
  end)

  it("truncates when byte length exceeds the default 64KB limit", function()
    local text = string.rep("x", 64 * 1024 + 1)
    local ev = doc_events.transform_doc_open("big.lua", "cafef00d", text, 500)
    assert.equals("doc.open", ev.kind)
    assert.is_true(ev.data.truncated)
    assert.is_nil(ev.data.content)
    assert.equals("big.lua", ev.data.path)
    assert.equals("cafef00d", ev.data.sha256)
    assert.equals(500, ev.data.line_count)
  end)

  it("uses UTF-8 BYTE length, not character count, for the boundary", function()
    -- "€" is U+20AC, encoded as 3 bytes in UTF-8 (0xE2 0x82 0xAC).
    local euro = "\226\130\172"
    assert.equals(3, #euro)

    -- 3 bytes <= 4 -> inline.
    local ev1 = doc_events.transform_doc_open("f.txt", "h1", euro, 1, 4)
    assert.equals(euro, ev1.data.content)
    assert.is_nil(ev1.data.truncated)

    -- 4 bytes <= 4 -> inline (exactly at the boundary).
    local at_boundary = euro .. "x"
    assert.equals(4, #at_boundary)
    local ev2 = doc_events.transform_doc_open("f.txt", "h2", at_boundary, 1, 4)
    assert.equals(at_boundary, ev2.data.content)
    assert.is_nil(ev2.data.truncated)

    -- 5 bytes > 4 -> truncated.
    local over_boundary = euro .. "xy"
    assert.equals(5, #over_boundary)
    local ev3 = doc_events.transform_doc_open("f.txt", "h3", over_boundary, 1, 4)
    assert.is_true(ev3.data.truncated)
    assert.is_nil(ev3.data.content)
  end)

  it("defaults max_inline_bytes to 64KB when nil", function()
    local text = string.rep("x", 64 * 1024)
    local ev = doc_events.transform_doc_open("a.lua", "h", text, 1, nil)
    assert.equals(text, ev.data.content)
    assert.is_nil(ev.data.truncated)

    local text2 = string.rep("x", 64 * 1024 + 1)
    local ev2 = doc_events.transform_doc_open("a.lua", "h", text2, 1, nil)
    assert.is_true(ev2.data.truncated)
    assert.is_nil(ev2.data.content)
  end)
end)

describe("doc_events.transform_doc_change", function()
  it("passes deltas through as a tagged json array with source=typed", function()
    local deltas = {
      {
        range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 5 } },
        text = "hello",
      },
    }
    local ev = doc_events.transform_doc_change("a.lua", deltas)
    assert.equals("doc.change", ev.kind)
    assert.equals("a.lua", ev.data.path)
    assert.equals("typed", ev.data.source)
    assert.is_true(json.is_array(ev.data.deltas))
    assert.equals(1, #ev.data.deltas)
    assert.equals("hello", ev.data.deltas[1].text)
    assert.equals(0, ev.data.deltas[1].range.start.line)
    assert.equals(5, ev.data.deltas[1].range["end"].character)
  end)

  it("produces an empty json array (not object) when deltas is nil", function()
    local ev = doc_events.transform_doc_change("a.lua", nil)
    assert.is_true(json.is_array(ev.data.deltas))
    assert.equals(0, #ev.data.deltas)
    assert.equals("[]", json.canonicalize(ev.data.deltas))
  end)

  it("produces an empty json array (not object) when deltas is an empty table", function()
    local ev = doc_events.transform_doc_change("a.lua", {})
    assert.is_true(json.is_array(ev.data.deltas))
    assert.equals(0, #ev.data.deltas)
    assert.equals("[]", json.canonicalize(ev.data.deltas))
  end)
end)

describe("doc_events.transform_doc_save", function()
  it("returns kind doc.save with path and sha256", function()
    local ev = doc_events.transform_doc_save("a.lua", "deadbeef")
    assert.equals("doc.save", ev.kind)
    assert.same({ path = "a.lua", sha256 = "deadbeef" }, ev.data)
  end)
end)

describe("doc_events.transform_doc_close", function()
  it("returns kind doc.close with path only", function()
    local ev = doc_events.transform_doc_close("a.lua")
    assert.equals("doc.close", ev.kind)
    assert.same({ path = "a.lua" }, ev.data)
  end)
end)
