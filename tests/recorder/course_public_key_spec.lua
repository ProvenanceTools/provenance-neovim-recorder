--- Course public key constant verification.
local course_public_key = require("provenance.course_public_key")

describe("course_public_key", function()
  it("exports COURSE_PUBLIC_KEY_HEX as a string", function()
    assert.is_string(course_public_key.COURSE_PUBLIC_KEY_HEX)
  end)

  it("COURSE_PUBLIC_KEY_HEX is exactly 64 lowercase hex characters", function()
    local key = course_public_key.COURSE_PUBLIC_KEY_HEX
    assert.equals(64, #key)
    -- Verify all characters are lowercase hex
    for i = 1, #key do
      local c = key:sub(i, i)
      assert.is_true(c:match("[0-9a-f]") ~= nil, "Character at position " .. i .. " is not lowercase hex: " .. c)
    end
  end)

  it("matches the pinned master public key", function()
    -- Pins the committed production key so an accidental edit is caught. This is
    -- the public half only; the private key is held offline, never in the repo.
    assert.equals("b5bca59ffa918c879d01050dab428e60c630f9d2051508af3d29c60cce985e25", course_public_key.COURSE_PUBLIC_KEY_HEX)
  end)
end)
