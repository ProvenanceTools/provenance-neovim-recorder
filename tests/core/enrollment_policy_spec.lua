--- enrollment_policy.resolve: the pure, block-level resolution of
--- `policy.enrollment.required`. Mirrors `capture_policy_spec`-style coverage
--- (there is no dedicated capture_policy spec file — its resolution is
--- exercised via conformance vectors and `policy_gate_spec.lua` instead — but
--- `policy.enrollment` has no cross-language conformance vectors of its own,
--- so this module gets a direct spec).
local json = require("provenance.core.json")
local enrollment_policy = require("provenance.core.enrollment_policy")

describe("enrollment_policy.resolve", function()
  it("defaults to required = true", function()
    assert.same({ required = true }, enrollment_policy.DEFAULTS)
  end)

  it("an absent policy block resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve(nil))
  end)

  it("a policy block with no enrollment key resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve({ capture = { terminal = true } }))
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve({}))
  end)

  it("required = false resolves to false", function()
    assert.same({ required = false }, enrollment_policy.resolve({ enrollment = { required = false } }))
  end)

  it("required = true resolves to true", function()
    assert.same({ required = true }, enrollment_policy.resolve({ enrollment = { required = true } }))
  end)

  it("an enrollment block with no required key resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve({ enrollment = {} }))
  end)

  local malformed_required_values = {
    "false", -- the STRING "false", not the boolean
    0,
    1,
    {},
    json.array({}),
  }
  for i, bad in ipairs(malformed_required_values) do
    it("a non-boolean required value #" .. i .. " (" .. type(bad) .. ") falls back to true, not false", function()
      assert.same({ required = true }, enrollment_policy.resolve({ enrollment = { required = bad } }))
    end)
  end

  it("required = json.NULL falls back to true, not false", function()
    -- THE Lua-specific hazard this module exists to get right: `required =
    -- false` and `required` absent/null are different at the JSON level even
    -- though both are falsy-ish in Lua. json.NULL is a truthy Lua table (not
    -- `nil` and not `false`), so a naive `not value` check would wrongly treat
    -- it as present-and-falsy; resolve_bool's `type(value) == "boolean"` check
    -- correctly falls through to the default instead.
    assert.same({ required = true }, enrollment_policy.resolve({ enrollment = { required = json.NULL } }))
  end)

  it("vim.NIL as the whole enrollment value resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve({ enrollment = vim.NIL }))
  end)

  it("json.NULL as the whole enrollment value resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve({ enrollment = json.NULL }))
  end)

  it("an enrollment value that is an array, not an object, resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve({ enrollment = json.array({}) }))
  end)

  it("a top-level policy block that is itself an array or NULL resolves to DEFAULTS", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve(json.array({})))
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve(json.NULL))
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve(vim.NIL))
  end)

  it("a top-level policy block that is a scalar resolves to DEFAULTS, never throws", function()
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve("nope"))
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve(42))
    assert.same(enrollment_policy.DEFAULTS, enrollment_policy.resolve(true))
  end)

  it("a full policy block carries capture and enrollment independently", function()
    local resolved = enrollment_policy.resolve({
      capture = { terminal = false },
      enrollment = { required = false },
    })
    assert.same({ required = false }, resolved)
  end)

  it("resolve never mutates the input block", function()
    local block = { enrollment = { required = false } }
    local before = vim.deepcopy(block)
    enrollment_policy.resolve(block)
    assert.same(before, block)
  end)
end)
