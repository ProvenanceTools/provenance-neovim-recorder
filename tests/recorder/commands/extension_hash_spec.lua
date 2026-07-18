--- Placeholder extension_hash (Plan 4 stand-in for Plan 9's real tree-hash).
--- Pure function: fixed, deterministic, well-formed hex.
local extension_hash = require("provenance.recorder.commands.extension_hash")

describe("extension_hash.compute", function()
  it("returns a 64-char lowercase hex string", function()
    local h = extension_hash.compute()
    assert.equals("string", type(h))
    assert.equals(64, #h)
    assert.is_not_nil(h:match("^[0-9a-f]+$"))
  end)

  it("is deterministic across repeated calls", function()
    assert.equals(extension_hash.compute(), extension_hash.compute())
  end)
end)
