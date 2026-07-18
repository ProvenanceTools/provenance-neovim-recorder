local git_payloads = require("provenance.recorder.events.git_payloads")

describe("git_payloads.build_git_event", function()
  it("includes commit_sha when provided", function()
    local ev = git_payloads.build_git_event("commit", "abc123def456")
    assert.equals("git.event", ev.kind)
    assert.equals("commit", ev.data.operation)
    assert.equals("abc123def456", ev.data.commit_sha)
  end)

  it("omits commit_sha key when commit_sha is nil", function()
    local ev = git_payloads.build_git_event("state_change", nil)
    assert.equals("git.event", ev.kind)
    assert.equals("state_change", ev.data.operation)
    assert.is_nil(ev.data.commit_sha)
    -- Verify the key is actually absent (not just nil-valued)
    local has_commit_sha = false
    for k in pairs(ev.data) do
      if k == "commit_sha" then
        has_commit_sha = true
        break
      end
    end
    assert.is_false(has_commit_sha)
  end)

  it("omits commit_sha key when explicitly called without it", function()
    local ev = git_payloads.build_git_event("checkout")
    assert.equals("git.event", ev.kind)
    assert.equals("checkout", ev.data.operation)
    assert.is_nil(ev.data.commit_sha)
    -- Verify the key is actually absent
    local has_commit_sha = false
    for k in pairs(ev.data) do
      if k == "commit_sha" then
        has_commit_sha = true
        break
      end
    end
    assert.is_false(has_commit_sha)
  end)
end)
