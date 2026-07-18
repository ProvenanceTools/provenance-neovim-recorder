--- Integration test closing the parse -> validate seam: entries built with
--- hash_chain.chain_entry, serialized through ndjson, re-parsed, and fed
--- straight into chain_validator.validate_chain. Proves normalize->recompute
--- round-trips byte-for-byte (a parsed entry validates identically to the
--- in-memory entry it came from).
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ndjson = require("provenance.core.ndjson")
local cv = require("provenance.core.chain_validator")
local json = require("provenance.core.json")

--- Build a valid 3-entry chain, serialize each entry to NDJSON text, and
--- concatenate into a single log body.
local function build_log_text()
  local e0 = hc.chain_entry(hc.GENESIS_PREV_HASH,
    envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { extension_id = "provnvim" }))
  local e1 = hc.chain_entry(e0.hash,
    envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "doc.change",
      { path = "a.py", deltas = json.array({}) }))
  local e2 = hc.chain_entry(e1.hash,
    envelope.new(2, 2000, "2026-01-01T00:00:02.000Z", "session.end", { reason = "seal" }))
  return ndjson.serialize_entry(e0) .. ndjson.serialize_entry(e1) .. ndjson.serialize_entry(e2)
end

describe("parse -> validate seam", function()
  it("round-trips a serialized chain through parse_entries and validates ok", function()
    local text = build_log_text()
    local parsed = ndjson.parse_entries(text)
    assert.is_true(parsed.ok)
    assert.equals(3, #parsed.value)

    local res = cv.validate_chain(parsed.value)
    assert.is_true(res.ok)
  end)

  it("detects a tampered parsed entry's data field as a hash_mismatch break", function()
    local text = build_log_text()
    local parsed = ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    parsed.value[2].data.path = "tampered.py"

    local res = cv.validate_chain(parsed.value)
    assert.is_false(res.ok)
    assert.equals("hash_mismatch", res.break_.reason)
    assert.equals(1, res.break_.at_seq)
  end)

  it("detects a tampered parsed entry's hash field as a hash_mismatch break", function()
    local text = build_log_text()
    local parsed = ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    parsed.value[2].hash = ("f"):rep(64)

    local res = cv.validate_chain(parsed.value)
    assert.is_false(res.ok)
    assert.equals("hash_mismatch", res.break_.reason)
  end)
end)
