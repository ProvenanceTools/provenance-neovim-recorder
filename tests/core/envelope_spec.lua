local envelope = require("provenance.core.envelope")

describe("envelope", function()
  it("canonicalizes to sorted-key JSON without hash fields", function()
    local env = envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.end", { reason = "test" })
    assert.equals(
      '{"data":{"reason":"test"},"kind":"session.end","seq":0,"t":0,"wall":"2026-01-01T00:00:00.000Z"}',
      envelope.canonical(env)
    )
  end)

  it("does not include prev_hash or hash in the canonical form", function()
    local env = envelope.new(1, 5, "w", "doc.close", { path = "a.py" })
    local c = envelope.canonical(env)
    assert.is_nil(c:find("prev_hash", 1, true))
    assert.is_nil(c:find("\"hash\"", 1, true))
  end)
end)
