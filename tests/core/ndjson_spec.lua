local ndjson = require("provenance.core.ndjson")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local json = require("provenance.core.json")

local entry = hc.chain_entry(hc.GENESIS_PREV_HASH,
  envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.end", { reason = "test" }))

describe("ndjson", function()
  it("serialize_entry is canonical + trailing newline", function()
    local line = ndjson.serialize_entry(entry)
    assert.is_truthy(line:match("\n$"))
    assert.equals(json.canonicalize(entry) .. "\n", line)
  end)

  it("round-trips a single entry", function()
    local res = ndjson.parse_entries(ndjson.serialize_entry(entry))
    assert.is_true(res.ok)
    assert.equals(1, #res.value)
    assert.equals(entry.hash, res.value[1].hash)
  end)

  it("round-trips an entry with an empty array field", function()
    local dc = hc.chain_entry(entry.hash,
      envelope.new(1, 1, "2026-01-01T00:00:01.000Z", "doc.change",
        { path = "a.py", deltas = json.array({}), source = "typed" }))
    local line = ndjson.serialize_entry(dc)
    local res = ndjson.parse_entries(line)
    assert.is_true(res.ok)
    -- re-serializing the parsed entry reproduces the exact bytes (empty [] preserved)
    assert.equals(line, ndjson.serialize_entry(res.value[1]))
  end)

  it("round-trips an entry with a non-empty array field", function()
    local dc = hc.chain_entry(entry.hash,
      envelope.new(1, 1, "2026-01-01T00:00:01.000Z", "doc.change",
        { path = "a.py", source = "typed", deltas = json.array({
          { range = { ["start"] = { line = 0, character = 0 }, ["end"] = { line = 0, character = 1 } }, text = "x" },
        }) }))
    local line = ndjson.serialize_entry(dc)
    local res = ndjson.parse_entries(line)
    assert.is_true(res.ok)
    -- re-serializing the parsed entry reproduces the exact bytes (non-empty array, vim.islist branch)
    assert.equals(line, ndjson.serialize_entry(res.value[1]))
  end)

  it("rejects data:null (shape validation regression)", function()
    local line = '{"data":null,"hash":"' .. ("a"):rep(64) .. '","kind":"session.end",'
      .. '"prev_hash":"' .. ("0"):rep(64) .. '","seq":0,"t":0,"wall":"2026-01-01T00:00:00.000Z"}\n'
    local res = ndjson.parse_entries(line)
    assert.is_false(res.ok)
    assert.equals("data", res.error.missing_field)
  end)

  it("empty string parses to zero entries", function()
    local res = ndjson.parse_entries("")
    assert.is_true(res.ok)
    assert.equals(0, #res.value)
  end)

  it("reports the failing line (1-indexed) on invalid json", function()
    local res = ndjson.parse_entries(ndjson.serialize_entry(entry) .. "not json\n")
    assert.is_false(res.ok)
    assert.equals(2, res.error.line)
  end)
end)
