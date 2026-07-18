local sha256 = require("provenance.core.sha256")

describe("sha256.hex", function()
  it("matches the NIST vector for 'hello world'", function()
    assert.equals(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      sha256.hex("hello world")
    )
  end)

  it("matches the NIST vector for the empty string", function()
    assert.equals(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      sha256.hex("")
    )
  end)

  it("returns 64 lowercase hex chars", function()
    local h = sha256.hex("anything")
    assert.equals(64, #h)
    assert.is_truthy(h:match("^[0-9a-f]+$"))
  end)
end)
