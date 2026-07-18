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

  it("matches the pinned dev fixture value", function()
    assert.equals("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618", course_public_key.COURSE_PUBLIC_KEY_HEX)
  end)
end)
