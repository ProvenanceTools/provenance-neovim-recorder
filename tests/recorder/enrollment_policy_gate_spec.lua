--- enrollment_policy_gate.effective_required: the manifest-format-version
--- trust gate for `policy.enrollment`, mirroring
--- `session/policy_gate_spec.lua`'s coverage of `effective_policy` for
--- `policy.capture`.
local enrollment_policy = require("provenance.core.enrollment_policy")
local gate = require("provenance.recorder.enrollment_policy_gate")

describe("enrollment_policy_gate.effective_required", function()
  it("a 2.0 manifest's policy.enrollment.required = false is honoured", function()
    local manifest = { format_version = "2.0", policy = { enrollment = { required = false } } }
    assert.is_false(gate.effective_required(manifest))
  end)

  it("a 2.0 manifest's policy.enrollment.required = true is honoured", function()
    local manifest = { format_version = "2.0", policy = { enrollment = { required = true } } }
    assert.is_true(gate.effective_required(manifest))
  end)

  it("a 2.0 manifest with no policy block at all defaults to required", function()
    assert.is_true(gate.effective_required({ format_version = "2.0" }))
  end)

  it("a 2.0 manifest with a policy block but no enrollment key defaults to required", function()
    local manifest = { format_version = "2.0", policy = { capture = { terminal = false } } }
    assert.is_true(gate.effective_required(manifest))
  end)

  it("THE 1.x GATE: a 1.x manifest carrying policy.enrollment.required = false STILL resolves required", function()
    -- Below 2.0 `policy` is not inside the signed payload, so a student could
    -- staple `policy: {enrollment: {required: false}}` onto their own
    -- genuinely-signed 1.x manifest to silence their own "not enrolled"
    -- notice. The gate must ignore it exactly like policy_gate.lua does for
    -- policy.capture.
    for _, manifest in ipairs({
      { policy = { enrollment = { required = false } } }, -- no format_version at all
      { format_version = "1.0", policy = { enrollment = { required = false } } },
      { format_version = "1.4", policy = { enrollment = { required = false } } },
    }) do
      assert.is_true(gate.effective_required(manifest), vim.inspect(manifest))
    end
  end)

  it("a missing or non-table manifest resolves to required", function()
    assert.is_true(gate.effective_required(nil))
    assert.is_true(gate.effective_required("nope"))
    assert.is_true(gate.effective_required(42))
  end)

  it("agrees with core enrollment_policy.DEFAULTS for every gated-away case", function()
    assert.equals(enrollment_policy.DEFAULTS.required, gate.effective_required(nil))
    assert.equals(enrollment_policy.DEFAULTS.required, gate.effective_required({ format_version = "1.0" }))
  end)
end)
