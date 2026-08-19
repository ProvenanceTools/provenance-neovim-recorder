--- The recorder's two embedded verification anchors.
--- Both are pinned so an accidental edit is caught: these are public halves
--- only, and all three recorder implementations embed the same values.
local trust_keys = require("provenance.trust_keys")

local function assert_lowercase_hex_64(key, name)
  assert.is_string(key)
  assert.equals(64, #key, name .. " must be 64 chars")
  for i = 1, #key do
    local c = key:sub(i, i)
    assert.is_true(c:match("[0-9a-f]") ~= nil, name .. " char " .. i .. " is not lowercase hex: " .. c)
  end
end

describe("trust_keys", function()
  it("ROOT_PUBLIC_KEY_HEX is 64 lowercase hex characters", function()
    assert_lowercase_hex_64(trust_keys.ROOT_PUBLIC_KEY_HEX, "ROOT_PUBLIC_KEY_HEX")
  end)

  it("LEGACY_COURSE_PUBLIC_KEY_HEX is 64 lowercase hex characters", function()
    assert_lowercase_hex_64(trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX, "LEGACY_COURSE_PUBLIC_KEY_HEX")
  end)

  it("matches the pinned dev root public key shared by all three recorders", function()
    assert.equals(
      "80051f5bdb9064e0768bf2fca5cc9a4ee888502ab45472e0c6d0f4f704de4499",
      trust_keys.ROOT_PUBLIC_KEY_HEX
    )
  end)

  it("matches THIS recorder's own prior embedded master key", function()
    -- Each recorder grandfathers the key it was itself verifying against; the
    -- three implementations embed three DIFFERENT legacy keys and only the root
    -- key is shared. This value is provnvim's real maintainer-held master key,
    -- which shipped in every tagged release and signed every 1.x manifest in the
    -- field -- not a dev placeholder (provnvim has no build step). Replacing it
    -- with another recorder's key would silently stop recording for every
    -- existing user.
    --
    -- SCHEDULED FOR REMOVAL: delete this assertion together with the constant
    -- once no unreissued 1.x manifest remains in the field (program spec §9).
    assert.equals(
      "b5bca59ffa918c879d01050dab428e60c630f9d2051508af3d29c60cce985e25",
      trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX
    )
  end)

  it("is NOT another recorder's legacy key", function()
    -- Guards against a future "let's align the constants" change. The VS Code
    -- recorder grandfathers 46f91d59..., provjet grandfathers 958d262b...;
    -- neither may ever become this repo's anchor.
    assert.is_not.equals(
      "46f91d5902c53816110b05ddedd2b8caa95b452d51e696f5327b52bf90bf4838",
      trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX
    )
    assert.is_nil(trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX:find("^958d262b"))
  end)

  it("the two anchors are distinct", function()
    -- If these ever collide, the 1.x/2.0 routing stops being a real boundary
    -- and the step-0 downgrade gate loses its teeth.
    assert.is_not.equals(trust_keys.ROOT_PUBLIC_KEY_HEX, trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX)
  end)

  it("the retired single-key module is gone", function()
    -- provenance.course_public_key exported one COURSE_PUBLIC_KEY_HEX. One
    -- embedded key per build is exactly what the trust hierarchy removes.
    assert.is_false(pcall(require, "provenance.course_public_key"))
  end)
end)
