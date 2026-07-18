local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

local function session_end(seq, t, wall, reason)
  return envelope.new(seq, t, wall, "session.end", { reason = reason })
end

describe("hash_chain", function()
  it("genesis prev_hash is 64 zeros", function()
    assert.equals(("0"):rep(64), hc.GENESIS_PREV_HASH)
  end)

  it("chain_entry matches the log-core pinned vector", function()
    local h = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "2026-01-01T00:00:00.000Z", "test"))
    assert.equals("d33cad1d38b90b26a2f7b1181801805233bf4332eca5bc6d4ff4e1b677683625", h.hash)
    assert.equals(hc.GENESIS_PREV_HASH, h.prev_hash)
  end)

  it("second entry links to the first", function()
    local h0 = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "2026-01-01T00:00:00.000Z", "test"))
    local h1 = hc.chain_entry(h0.hash, session_end(1, 1000, "2026-01-01T00:00:01.000Z", "test"))
    assert.equals(h0.hash, h1.prev_hash)
    assert.are_not.equals(h0.hash, h1.hash)
  end)

  it("differing data changes the hash", function()
    local a = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "w", "a"))
    local b = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "w", "b"))
    assert.are_not.equals(a.hash, b.hash)
  end)
end)
