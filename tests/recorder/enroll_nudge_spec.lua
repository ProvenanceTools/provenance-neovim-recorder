--- Mirrors `packages/recorder/src/activation/enroll-nudge.test.ts` (VS Code) and
--- `EnrollNudgeTest.kt` (JetBrains).

local enroll_nudge = require("provenance.recorder.enroll_nudge")
local enroll_nudge_ui = require("provenance.recorder.enroll_nudge_ui")
local status = require("provenance.recorder.status")

local S = enroll_nudge.STATES
local A = enroll_nudge.ACTIONS

--- Every skip reason `session_identity.build` can return, so the partition is exhaustive.
local ALL_SKIP_REASONS = {
  { kind = "no_root_public_key" },
  { kind = "institution_cert_not_root_signed" },
  { kind = "credential_key_mismatch", credential_student_pubkey = "aa", derived_pubkey = "bb" },
  { kind = "manifest_not_2_0" },
  { kind = "not_enrolled", course_id = "cs61b" },
  { kind = "master_secret_unavailable", reason = "store_unreadable" },
  { kind = "invalid_session_pubkey" },
  { kind = "student_key_mismatch", token_student_pubkey = "aa", derived_pubkey = "bb" },
  { kind = "chain_did_not_verify", error = { kind = "bad_signature" } },
  { kind = "unexpected_error", reason = "boom" },
}

local function skipped(reason)
  return { kind = "skipped", reason = reason }
end

local function emitted()
  return { kind = "emitted", identity = {}, verified = {} }
end

describe("enroll_nudge.is_unenrolled_skip", function()
  it("is true for exactly the two reasons enrolling would fix", function()
    local actionable = {}
    for _, r in ipairs(ALL_SKIP_REASONS) do
      if enroll_nudge.is_unenrolled_skip(r) then
        actionable[#actionable + 1] = r.kind
      end
    end
    table.sort(actionable)
    assert.same({ "manifest_not_2_0", "not_enrolled" }, actionable)
  end)

  it("never blames the student for a broken build or an unreadable store", function()
    assert.is_false(enroll_nudge.is_unenrolled_skip({ kind = "no_root_public_key" }))
    assert.is_false(enroll_nudge.is_unenrolled_skip({ kind = "institution_cert_not_root_signed" }))
    assert.is_false(enroll_nudge.is_unenrolled_skip({ kind = "master_secret_unavailable" }))
    assert.is_false(enroll_nudge.is_unenrolled_skip({ kind = "unexpected_error" }))
  end)

  it("stays quiet on a key mismatch — they have a credential, it is the wrong machine", function()
    assert.is_false(enroll_nudge.is_unenrolled_skip({ kind = "credential_key_mismatch" }))
    assert.is_false(enroll_nudge.is_unenrolled_skip({ kind = "student_key_mismatch" }))
  end)

  it("tolerates a nil or non-table reason", function()
    assert.is_false(enroll_nudge.is_unenrolled_skip(nil))
    assert.is_false(enroll_nudge.is_unenrolled_skip("not_enrolled"))
  end)
end)

describe("enroll_nudge.is_unenrolled", function()
  it("is false for a legacy 2.0 holder: they emit, so they are attributed", function()
    -- The regression this module exists to avoid. A credential lookup would call
    -- this student un-enrolled and tell them their work is unattributed.
    assert.is_false(enroll_nudge.is_unenrolled({ emitted() }))
    assert.is_true(enroll_nudge.any_identity_emitted({ emitted(), skipped({ kind = "not_enrolled" }) }))
  end)

  it("is false when one root of several emitted", function()
    assert.is_false(enroll_nudge.is_unenrolled({ skipped({ kind = "not_enrolled" }), emitted() }))
  end)

  it("is true when every session skipped for want of a credential", function()
    assert.is_true(enroll_nudge.is_unenrolled({ skipped({ kind = "not_enrolled", course_id = "x" }) }))
    assert.is_true(enroll_nudge.is_unenrolled({ skipped({ kind = "manifest_not_2_0" }) }))
  end)

  it("is false when the only failure is one enrolling cannot fix", function()
    assert.is_false(enroll_nudge.is_unenrolled({ skipped({ kind = "no_root_public_key" }) }))
    assert.is_false(enroll_nudge.is_unenrolled({ skipped({ kind = "master_secret_unavailable" }) }))
  end)

  it("is true when a broken root sits alongside an un-enrolled one", function()
    assert.is_true(enroll_nudge.is_unenrolled({
      skipped({ kind = "no_root_public_key" }),
      skipped({ kind = "not_enrolled", course_id = "cs61c" }),
    }))
  end)

  it("is false for no sessions, and for nil", function()
    assert.is_false(enroll_nudge.is_unenrolled({}))
    assert.is_false(enroll_nudge.is_unenrolled(nil))
  end)
end)

describe("enroll_nudge state machine", function()
  local unenrolled = { skipped({ kind = "not_enrolled", course_id = "cs61b" }) }

  it("shows while unseen or intent, never once done", function()
    assert.is_true(enroll_nudge.should_show(unenrolled, S.UNSEEN))
    assert.is_true(enroll_nudge.should_show(unenrolled, S.INTENT))
    assert.is_false(enroll_nudge.should_show(unenrolled, S.DONE))
  end)

  it("never shows to an enrolled student whatever the state", function()
    for _, st in pairs(S) do
      assert.is_false(enroll_nudge.should_show({ emitted() }, st))
    end
  end)

  it("dismissing is permanent from either live state", function()
    assert.equals(S.DONE, enroll_nudge.next_state(S.UNSEEN, A.DISMISS))
    assert.equals(S.DONE, enroll_nudge.next_state(S.INTENT, A.DISMISS))
  end)

  it("every other action advances exactly one step", function()
    for _, action in ipairs({ A.ENROLL, A.SHOW_KEY, A.DISPLAYED }) do
      assert.equals(S.INTENT, enroll_nudge.next_state(S.UNSEEN, action))
      assert.equals(S.DONE, enroll_nudge.next_state(S.INTENT, action))
    end
  end)

  it("done is terminal under every action", function()
    for _, action in pairs(A) do
      assert.equals(S.DONE, enroll_nudge.next_state(S.DONE, action))
    end
  end)

  it("caps lifetime notifications at two", function()
    -- Ten un-enrolled sessions. The statusline keeps saying it; the notification
    -- must not.
    local state = S.UNSEEN
    local shown = 0
    for _ = 1, 10 do
      if enroll_nudge.should_show(unenrolled, state) then
        shown = shown + 1
        state = enroll_nudge.next_state(state, A.DISPLAYED)
      end
    end
    assert.equals(2, shown)
    assert.equals(S.DONE, state)
  end)

  it("parse_state treats anything unrecognised as fresh", function()
    assert.equals(S.INTENT, enroll_nudge.parse_state("intent"))
    assert.equals(S.DONE, enroll_nudge.parse_state("done"))
    assert.equals(S.UNSEEN, enroll_nudge.parse_state(nil))
    assert.equals(S.UNSEEN, enroll_nudge.parse_state("nonsense"))
    assert.equals(S.UNSEEN, enroll_nudge.parse_state(42))
  end)

  it("the message names the consequence and carries the URL", function()
    assert.is_truthy(enroll_nudge.MESSAGE:find("not be attributed", 1, true))
    assert.is_truthy(enroll_nudge.MESSAGE:find(enroll_nudge.ENROLL_URL, 1, true))
  end)
end)

describe("status.segment enrollment suffix", function()
  after_each(function()
    status.detach()
  end)

  local function fake_registry(active, outcomes)
    return {
      is_active = function()
        return active
      end,
      identity_outcomes = function()
        return outcomes
      end,
    }
  end

  it("appends (not enrolled) when every session skipped for want of a credential", function()
    status.attach(fake_registry(true, { skipped({ kind = "not_enrolled", course_id = "x" }) }))
    assert.equals("● Provenance: recording (not enrolled)", status.segment())
  end)

  it("leaves an enrolled student's segment byte-for-byte as it was", function()
    status.attach(fake_registry(true, { emitted() }))
    assert.equals("● Provenance: recording", status.segment())
  end)

  it("stays silent about enrollment when the recorder is inactive", function()
    status.attach(fake_registry(false, { skipped({ kind = "not_enrolled" }) }))
    assert.equals("", status.segment())
  end)

  it("omits the suffix for an attached state with no identity_outcomes at all", function()
    -- A plain RecorderState, not the registry. The statusline is evaluated on
    -- every redraw and must never throw.
    status.attach({
      is_active = function()
        return true
      end,
    })
    assert.equals("● Provenance: recording", status.segment())
  end)

  it("survives an identity_outcomes that throws", function()
    status.attach({
      is_active = function()
        return true
      end,
      identity_outcomes = function()
        error("boom")
      end,
    })
    assert.equals("● Provenance: recording", status.segment())
  end)
end)

describe("enroll_nudge_ui.maybe_nudge", function()
  local function harness(outcomes, initial)
    local shown = {}
    local persisted = { state = initial }
    local registry = {
      identity_outcomes = function()
        return outcomes
      end,
    }
    local deps = {
      notify = function(msg)
        shown[#shown + 1] = msg
      end,
      read_state = function()
        return persisted.state
      end,
      write_state = function(s)
        persisted.state = s
      end,
    }
    return registry, deps, shown, persisted
  end

  it("notifies an un-enrolled student and advances the stored state", function()
    local registry, deps, shown, persisted =
      harness({ skipped({ kind = "not_enrolled", course_id = "x" }) }, S.UNSEEN)
    enroll_nudge_ui.maybe_nudge(registry, deps)
    assert.equals(1, #shown)
    assert.equals(S.INTENT, persisted.state)
  end)

  it("says nothing to an enrolled student and leaves the state alone", function()
    local registry, deps, shown, persisted = harness({ emitted() }, S.UNSEEN)
    enroll_nudge_ui.maybe_nudge(registry, deps)
    assert.equals(0, #shown)
    assert.equals(S.UNSEEN, persisted.state)
  end)

  it("says nothing once done", function()
    local registry, deps, shown =
      harness({ skipped({ kind = "not_enrolled", course_id = "x" }) }, S.DONE)
    enroll_nudge_ui.maybe_nudge(registry, deps)
    assert.equals(0, #shown)
  end)

  it("stops after the second notification", function()
    local registry, deps, shown =
      harness({ skipped({ kind = "not_enrolled", course_id = "x" }) }, S.UNSEEN)
    for _ = 1, 5 do
      enroll_nudge_ui.maybe_nudge(registry, deps)
    end
    assert.equals(2, #shown)
  end)

  it("is a no-op for a registry that cannot report outcomes", function()
    local _, deps, shown = harness({}, S.UNSEEN)
    enroll_nudge_ui.maybe_nudge({}, deps)
    enroll_nudge_ui.maybe_nudge(nil, deps)
    assert.equals(0, #shown)
  end)

  it("never propagates a failure out of activation", function()
    local deps = {
      notify = function()
        error("notify blew up")
      end,
      read_state = function()
        return S.UNSEEN
      end,
      write_state = function() end,
    }
    local registry = {
      identity_outcomes = function()
        return { skipped({ kind = "not_enrolled" }) }
      end,
    }
    assert.has_no.errors(function()
      enroll_nudge_ui.maybe_nudge(registry, deps)
    end)
  end)
end)
