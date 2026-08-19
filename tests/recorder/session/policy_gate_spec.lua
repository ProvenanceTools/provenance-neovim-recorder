--- policy_gate: the capture policy compiled into the two lookups SessionHost
--- makes on the emit path (program spec §4).
local capture_policy = require("provenance.core.capture_policy")
local policy_gate = require("provenance.recorder.session.policy_gate")

local ALL_OFF = {
  capture = {
    selection_change = false,
    focus_change = false,
    terminal = false,
    doc_open_close = false,
    inline_content = false,
    heartbeat_interval_ms = 120000,
  },
}

describe("policy_gate.effective_policy", function()
  it("a 2.0 manifest's policy is honoured", function()
    local policy = policy_gate.effective_policy({ format_version = "2.0", policy = ALL_OFF })
    assert.is_false(policy.selection_change)
    assert.is_false(policy.inline_content)
    assert.equals(120000, policy.heartbeat_interval_ms)
  end)

  it("a 1.x manifest resolves to DEFAULTS even when it carries a policy block", function()
    -- THE STUDENT OFF-SWITCH. Below 2.0 the policy block is not inside the
    -- signed payload, so a student could staple a capture-disabling policy onto
    -- a genuinely signed 1.x manifest. Honouring it would hand them exactly the
    -- off switch the chain's step-0 gate exists to deny.
    for _, m in ipairs({
      { policy = ALL_OFF }, -- no format_version at all
      { format_version = "1.0", policy = ALL_OFF },
      { format_version = "1.4", policy = ALL_OFF },
    }) do
      assert.same(capture_policy.DEFAULTS, policy_gate.effective_policy(m))
    end
  end)

  it("a missing or non-table manifest resolves to DEFAULTS", function()
    assert.same(capture_policy.DEFAULTS, policy_gate.effective_policy(nil))
    assert.same(capture_policy.DEFAULTS, policy_gate.effective_policy("nope"))
    assert.same(capture_policy.DEFAULTS, policy_gate.effective_policy({ format_version = "2.0" }))
  end)
end)

describe("policy_gate.new", function()
  it("the default policy allows every gated kind", function()
    local gate = policy_gate.new(capture_policy.DEFAULTS)
    for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
      assert.is_true(gate.allows(kind), kind .. " must be allowed by default")
    end
  end)

  it("an all-off policy blocks exactly the gated kinds", function()
    local gate = policy_gate.new(capture_policy.resolve(ALL_OFF))
    for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
      assert.is_false(gate.allows(kind), kind .. " must be blocked")
    end
  end)

  it("EVERY floor kind survives an all-off policy", function()
    -- The floor is enforced by the SCHEMA (a floor kind has no policy.capture
    -- key), not by a list of exceptions here. This asserts that end of it.
    local gate = policy_gate.new(capture_policy.resolve(ALL_OFF))
    for _, kind in ipairs(capture_policy.FLOOR_EVENT_KINDS) do
      assert.is_true(gate.allows(kind), kind .. " is on the floor and can never be disabled")
    end
  end)

  it("an unknown future kind is treated as floor, never silently dropped", function()
    local gate = policy_gate.new(capture_policy.resolve(ALL_OFF))
    assert.is_true(gate.allows("some.future.kind"))
  end)

  it("a partial policy blocks only what it names", function()
    local gate = policy_gate.new(capture_policy.resolve({ capture = { terminal = false } }))
    assert.is_false(gate.allows("terminal.open"))
    assert.is_false(gate.allows("terminal.command"))
    assert.is_true(gate.allows("selection.change"))
    assert.is_true(gate.allows("doc.open"))
  end)

  it("nil policy means capture everything", function()
    local gate = policy_gate.new(nil)
    for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
      assert.is_true(gate.allows(kind))
    end
  end)
end)

describe("policy_gate redact (inline_content)", function()
  local function off_gate()
    return policy_gate.new(capture_policy.resolve(ALL_OFF))
  end

  it("withholds paste content but KEEPS length and sha256", function()
    local data = { length = 4096, sha256 = string.rep("a", 64), content = "secret solution" }
    local out = off_gate().redact("paste", data)
    assert.is_nil(out.content)
    assert.equals(4096, out.length)
    assert.equals(string.rep("a", 64), out.sha256)
  end)

  it("withholds the truncated head/tail preview too", function()
    local data = {
      length = 999999,
      sha256 = string.rep("b", 64),
      content_head = "head",
      content_tail = "tail",
    }
    local out = off_gate().redact("paste", data)
    assert.is_nil(out.content_head)
    assert.is_nil(out.content_tail)
    assert.equals(999999, out.length)
    assert.equals(string.rep("b", 64), out.sha256)
  end)

  it("withholds fs.external_change content but KEEPS new_content_size", function()
    local data = { new_content_size = 128, new_content = "rewritten by a script" }
    local out = off_gate().redact("fs.external_change", data)
    assert.is_nil(out.new_content)
    assert.equals(128, out.new_content_size)

    local big = { new_content_size = 99999, new_content_head = "h", new_content_tail = "t" }
    local out2 = off_gate().redact("fs.external_change", big)
    assert.is_nil(out2.new_content_head)
    assert.is_nil(out2.new_content_tail)
    assert.equals(99999, out2.new_content_size)
  end)

  it("never mutates the caller's table", function()
    -- Payload builders and their tests hand the same table to more than one
    -- consumer; redaction must be a copy, not an edit in place.
    local data = { length = 3, sha256 = "x", content = "abc" }
    off_gate().redact("paste", data)
    assert.equals("abc", data.content)
  end)

  it("leaves every other kind's payload alone, by identity", function()
    local gate = off_gate()
    local data = { path = "a.lua", text = "keep me" }
    assert.equals(data, gate.redact("doc.change", data))
    assert.equals(data, gate.redact("session.heartbeat", data))
  end)

  it("with inline_content ON, paste payloads pass through by identity", function()
    local gate = policy_gate.new(capture_policy.DEFAULTS)
    local data = { length = 3, sha256 = "x", content = "abc" }
    assert.equals(data, gate.redact("paste", data))
  end)

  it("tolerates a nil or non-table payload", function()
    local gate = off_gate()
    assert.is_nil(gate.redact("paste", nil))
    assert.equals("weird", gate.redact("paste", "weird"))
  end)
end)
