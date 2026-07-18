local cv = require("provenance.core.chain_validator")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

--- Deep copy helper so mutations to build broken fixtures never leak
--- between test cases (entries are plain tables of scalars/tables).
local function deep_copy(t)
  if type(t) ~= "table" then
    return t
  end
  local out = {}
  for k, v in pairs(t) do
    out[k] = deep_copy(v)
  end
  return out
end

--- Build a valid 3-entry chain: session.start, doc.change, session.end.
local function valid_chain()
  local e0 = hc.chain_entry(hc.GENESIS_PREV_HASH,
    envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { extension_id = "provnvim" }))
  local e1 = hc.chain_entry(e0.hash,
    envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "doc.change", { path = "a.py" }))
  local e2 = hc.chain_entry(e1.hash,
    envelope.new(2, 2000, "2026-01-01T00:00:02.000Z", "session.end", { reason = "seal" }))
  return { e0, e1, e2 }
end

describe("chain_validator", function()
  it("accepts a valid multi-entry chain", function()
    local res = cv.validate_chain(valid_chain())
    assert.is_true(res.ok)
  end)

  it("accepts an empty chain", function()
    local res = cv.validate_chain({})
    assert.is_true(res.ok)
  end)

  it("rejects a tampered data field with hash_mismatch at that seq", function()
    local chain = valid_chain()
    local tampered = deep_copy(chain[2])
    tampered.data.path = "tampered.py"
    chain[2] = tampered

    local res = cv.validate_chain(chain)
    assert.is_false(res.ok)
    assert.equals("hash_mismatch", res.break_.reason)
    assert.equals(1, res.break_.at_seq)
  end)

  it("rejects a broken prev_hash link with hash_mismatch", function()
    local chain = valid_chain()
    local broken = deep_copy(chain[3])
    broken.prev_hash = ("f"):rep(64)
    chain[3] = broken

    local res = cv.validate_chain(chain)
    assert.is_false(res.ok)
    assert.equals("hash_mismatch", res.break_.reason)
    assert.equals(2, res.break_.at_seq)
  end)

  it("rejects a seq gap with seq_gap and expected index", function()
    local chain = valid_chain()
    local gapped = deep_copy(chain[3])
    gapped.seq = 5
    chain[3] = gapped

    local res = cv.validate_chain(chain)
    assert.is_false(res.ok)
    assert.equals("seq_gap", res.break_.reason)
    assert.equals(5, res.break_.at_seq)
    assert.equals(2, res.break_.expected)
  end)

  it("rejects t going backwards with t_regression", function()
    local e0 = hc.chain_entry(hc.GENESIS_PREV_HASH,
      envelope.new(0, 1000, "2026-01-01T00:00:00.000Z", "session.start", { extension_id = "provnvim" }))
    local e1 = hc.chain_entry(e0.hash,
      envelope.new(1, 500, "2026-01-01T00:00:01.000Z", "doc.change", { path = "a.py" }))
    local res = cv.validate_chain({ e0, e1 })
    assert.is_false(res.ok)
    assert.equals("t_regression", res.break_.reason)
    assert.equals(1, res.break_.at_seq)
  end)

  it("accepts wall going backwards when a preceding clock.skew entry is in the window", function()
    local e0 = hc.chain_entry(hc.GENESIS_PREV_HASH,
      envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { extension_id = "provnvim" }))
    local e1 = hc.chain_entry(e0.hash,
      envelope.new(1, 1000, "2026-01-01T00:00:05.000Z", "clock.skew", { delta_ms = 5000 }))
    local e2 = hc.chain_entry(e1.hash,
      envelope.new(2, 2000, "2026-01-01T00:00:01.000Z", "doc.change", { path = "a.py" }))
    local res = cv.validate_chain({ e0, e1, e2 })
    assert.is_true(res.ok)
  end)

  it("rejects wall going backwards without a clock.skew entry", function()
    local e0 = hc.chain_entry(hc.GENESIS_PREV_HASH,
      envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { extension_id = "provnvim" }))
    local e1 = hc.chain_entry(e0.hash,
      envelope.new(1, 1000, "2026-01-01T00:00:05.000Z", "doc.change", { path = "a.py" }))
    local e2 = hc.chain_entry(e1.hash,
      envelope.new(2, 2000, "2026-01-01T00:00:01.000Z", "doc.change", { path = "b.py" }))
    local res = cv.validate_chain({ e0, e1, e2 })
    assert.is_false(res.ok)
    assert.equals("wall_regression", res.break_.reason)
    assert.equals(2, res.break_.at_seq)
  end)
end)
