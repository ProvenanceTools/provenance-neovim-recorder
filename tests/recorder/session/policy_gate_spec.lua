--- policy_gate: the capture policy compiled into the two lookups SessionHost
--- makes on the emit path (program spec §4).
local capture_policy = require("provenance.core.capture_policy")
local policy_gate = require("provenance.recorder.session.policy_gate")

local ALL_OFF = {
  capture = {
    selection_change = false,
    focus_change = false,
    terminal = false,
    heartbeat_interval_ms = 120000,
  },
}

--- A policy still carrying the two RETIRED keys. `doc_open_close` and
--- `inline_content` were removed because doc.open carries the reconstruction
--- seed and paste content is what lets internal_move DOWNGRADE large_paste.
--- A manifest in the wild may still carry them; they must be inert.
local WITH_RETIRED_KEYS = {
  capture = {
    doc_open_close = false,
    inline_content = false,
  },
}

describe("policy_gate.effective_policy", function()
  it("a 2.0 manifest's policy is honoured", function()
    local policy = policy_gate.effective_policy({ format_version = "2.0", policy = ALL_OFF })
    assert.is_false(policy.selection_change)
    assert.is_false(policy.focus_change)
    assert.is_false(policy.terminal)
    assert.equals(120000, policy.heartbeat_interval_ms)
  end)

  it("the resolved policy has exactly the four surviving keys", function()
    local policy = policy_gate.effective_policy({ format_version = "2.0", policy = ALL_OFF })
    local keys = {}
    for k in pairs(policy) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    assert.same({ "focus_change", "heartbeat_interval_ms", "selection_change", "terminal" }, keys)
  end)

  it("a RETIRED key is inert — ignored, never an error, and it suppresses nothing", function()
    local policy = policy_gate.effective_policy({ format_version = "2.0", policy = WITH_RETIRED_KEYS })
    assert.same(capture_policy.DEFAULTS, policy)
    assert.is_nil(policy.doc_open_close)
    assert.is_nil(policy.inline_content)

    local gate = policy_gate.new(policy)
    assert.is_true(gate.allows("doc.open"), "doc.open is floor; a retired key must not reach it")
    assert.is_true(gate.allows("doc.close"))
    assert.is_true(gate.allows("paste"))
    assert.is_true(gate.allows("fs.external_change"))
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

--- An ARCHIVED, REAL signed manifest whose policy still carries both retired
--- keys — the exact bytes the shared dev manifest had before it was re-issued
--- without them. Kept as its own fixture precisely so re-issuing the live one
--- could not quietly delete this regression.
---
--- It is the strongest available inertness case, because the retired keys sit
--- INSIDE the course-signed payload: the signature covers them verbatim, so the
--- manifest must still verify byte-for-byte AND still resolve as if they were
--- not there. Manifests like this exist in the field and must keep working
--- forever; that is the whole forward-compatibility claim.
---
--- This matters more in this port than in the others: validate_signed_subtree
--- walks the policy sub-tree, so an over-strict "unknown capture key" rule here
--- would reject a manifest the other two recorders accept.
describe("policy_gate retired keys inside a real signed policy", function()
  local core_manifest = require("provenance.core.manifest")
  local trust_keys = require("provenance.trust_keys")

  local function this_file_dir()
    local source = debug.getinfo(1, "S").source
    local path = source:match("^@(.*)$") or source
    return vim.fn.fnamemodify(path, ":h")
  end

  local text = table.concat(
    vim.fn.readfile(this_file_dir() .. "/../fixtures/dev-manifest-v2-retired-keys.json"), "\n"
  )

  it("the archived fixture really does carry both retired keys in its signed policy", function()
    -- Guards the tests below from silently going vacuous. This fixture is
    -- FROZEN: it must never be re-signed, because its whole value is being a
    -- genuine signed artifact from before the keys were retired.
    local raw = vim.json.decode(text)
    assert.is_false(raw.policy.capture.doc_open_close == nil)
    assert.is_false(raw.policy.capture.inline_content == nil)
  end)

  it("the LIVE dev manifest has been re-issued without them", function()
    -- The current fixture tracks the monorepo's test-workspace manifest, which
    -- was re-signed once the keys were retired.
    local live = vim.json.decode(table.concat(
      vim.fn.readfile(this_file_dir() .. "/../fixtures/dev-manifest-v2.json"), "\n"
    ))
    assert.is_nil(live.policy.capture.doc_open_close)
    assert.is_nil(live.policy.capture.inline_content)
  end)

  it("still parses and still verifies its full trust chain", function()
    local parsed = core_manifest.parse(text)
    assert.is_true(parsed.ok, "a retired key must never make a manifest unparseable")
    local chain = core_manifest.verify_chain(parsed.value, trust_keys.ROOT_PUBLIC_KEY_HEX)
    assert.is_true(chain.ok, "retired keys are signed-over; the signature must still verify")
  end)

  it("resolves as if the retired keys were absent, and suppresses nothing", function()
    local parsed = core_manifest.parse(text)
    local policy = policy_gate.effective_policy(parsed.value)
    assert.same(capture_policy.DEFAULTS, policy)

    local gate = policy_gate.new(policy)
    for _, kind in ipairs({ "doc.open", "doc.close", "paste", "fs.external_change" }) do
      assert.is_true(gate.allows(kind), kind .. " is floor and must survive a retired key")
    end
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
    assert.is_true(gate.allows("doc.open"), "doc.open is now a FLOOR kind")
  end)

  it("nil policy means capture everything", function()
    local gate = policy_gate.new(nil)
    for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
      assert.is_true(gate.allows(kind))
    end
  end)
end)
