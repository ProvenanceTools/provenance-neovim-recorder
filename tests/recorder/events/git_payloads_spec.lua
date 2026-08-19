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

-- ---------------------------------------------------------------------------
-- S5: the commit graph (sha / parents / branch).
--
-- Byte-level parity with provcode and provjet is pinned by the shared vector
-- in tests/conformance/fixtures/git-event.json (see conformance_spec.lua).
-- What follows is the behaviour that vector cannot express: what the builder
-- does with inputs a recorder can actually hand it, and — load-bearing — what
-- it refuses to carry.
-- ---------------------------------------------------------------------------

local core_json = require("provenance.core.json")

local function key_set(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  return keys
end

describe("git_payloads.commit_view", function()
  it("projects exactly sha and parents, and nothing else", function()
    local view = git_payloads.commit_view("a1b2c3d4e5f6", { "aaaa111", "bbbb222" })
    assert.same({ "parents", "sha" }, key_set(view))
    assert.equals("a1b2c3d4e5f6", view.sha)
    assert.same({ "aaaa111", "bbbb222" }, view.parents)
  end)

  it("keeps an EMPTY parents list (a root commit is a positive claim)", function()
    local view = git_payloads.commit_view("a1b2c3", {})
    assert.is_not_nil(view.parents)
    assert.equals(0, #view.parents)
  end)

  it("omits parents entirely when they are nil — 'could not read' is not 'has none'", function()
    local view = git_payloads.commit_view("a1b2c3", nil)
    assert.same({ "sha" }, key_set(view))
  end)

  it("treats a parents list containing a non-string as UNREADABLE, not as a shorter list", function()
    -- Length is the structure (0 root / 1 ordinary / 2+ merge), so a filtered
    -- list would be a WRONG claim about the graph rather than a partial one.
    local view = git_payloads.commit_view("a1b2c3", { "aaaa111", 42, "bbbb222" })
    assert.is_nil(view.parents)
  end)

  it("omits sha when it is not a string", function()
    assert.same({}, key_set(git_payloads.commit_view(nil, nil)))
    assert.is_nil(git_payloads.commit_view(1234, nil).sha)
  end)

  it("copies the parents list, so a later mutation cannot rewrite a built payload", function()
    local source = { "aaaa111" }
    local view = git_payloads.commit_view("a1b2c3", source)
    local ev = git_payloads.build_git_event("commit", "a1b2c3", view)
    source[1] = "tampered"
    source[2] = "alsotampered"
    assert.same({ "aaaa111" }, ev.data.parents)
  end)
end)

describe("git_payloads.build_git_event (commit graph)", function()
  it("emits commit_sha AND sha with the same value — 1.x readers only know the former", function()
    local sha = ("a"):rep(40)
    local ev = git_payloads.build_git_event("commit", sha, git_payloads.commit_view(sha, {}), "main")
    assert.equals(sha, ev.data.commit_sha)
    assert.equals(sha, ev.data.sha)
  end)

  it("tags parents as a JSON ARRAY, so an empty list canonicalizes as [] and never {}", function()
    local ev = git_payloads.build_git_event("commit", "aaa", git_payloads.commit_view("aaa", {}))
    assert.is_true(core_json.is_array(ev.data.parents))
    assert.equals('{"commit_sha":"aaa","operation":"commit","parents":[],"sha":"aaa"}',
      core_json.canonicalize(ev.data))
  end)

  it("never sorts parents — the first parent is the branch merged INTO", function()
    local ev = git_payloads.build_git_event(
      "commit", "ccc", git_payloads.commit_view("ccc", { "zzz", "aaa" })
    )
    assert.same({ "zzz", "aaa" }, { ev.data.parents[1], ev.data.parents[2] })
    assert.is_true(core_json.canonicalize(ev.data):find('"parents":["zzz","aaa"]', 1, true) ~= nil)
  end)

  it("omits branch when it is nil — a detached HEAD is never given an invented name", function()
    local ev = git_payloads.build_git_event("checkout", "aaa", git_payloads.commit_view("aaa", {}), nil)
    assert.same({ "commit_sha", "operation", "parents", "sha" }, key_set(ev.data))
  end)

  it("a nil view leaves the pre-S5 shape untouched (permanent 1.x compatibility)", function()
    local ev = git_payloads.build_git_event("state_change", "aaa", nil, nil)
    assert.same({ "commit_sha", "operation" }, key_set(ev.data))
  end)

  it("IRB (CPHS 2026-06-19796): NO git author name, email, date or message can reach the payload", function()
    -- This is a PROTOCOL commitment, not a style preference. The approved CPHS
    -- protocol treats a new category of identifier as requiring a filed
    -- modification BEFORE implementation, and git author identity — a real name
    -- and a real email, attached to every commit — is exactly that. sha,
    -- parents and branch describe the SHAPE of the history; attribution has a
    -- designed, opaque home already in session.start.identity.student_ref.
    --
    -- Enforced structurally: commit_view takes exactly two positional scalars,
    -- so there is no parameter an author field could arrive through, and
    -- build_git_event reads named fields off the view rather than merging it.
    local hostile = { sha = "aaa", parents = { "bbb" } }
    -- Every spelling a future edit might plausibly reach for. The assertion
    -- below is an EXACT key set, so a builder that copied any one of these
    -- through — under any of these names — turns this test red.
    for _, k in ipairs({
      "author", "authorName", "author_name", "authorEmail", "author_email",
      "authorDate", "author_date", "committer", "committerName", "committer_name",
      "committerEmail", "committer_email", "email", "name", "message",
      "commit_message", "summary", "subject", "body", "signature", "gpg_sig",
    }) do
      hostile[k] = "Ada Lovelace <ada@berkeley.edu> 2026-08-19 fix the thing"
    end

    local ev = git_payloads.build_git_event("commit", "aaa", hostile, "main")

    assert.same({ "branch", "commit_sha", "operation", "parents", "sha" }, key_set(ev.data))

    local serialized = core_json.canonicalize(ev.data)
    for _, forbidden in ipairs({ "Ada", "Lovelace", "@", "berkeley", "author", "Author", "message", "2026-08-19" }) do
      assert.is_nil(serialized:find(forbidden, 1, true),
        "git.event payload must never contain " .. forbidden .. "; got " .. serialized)
    end

    -- And the projection itself drops them before a payload is ever built.
    assert.same({ "parents", "sha" }, key_set(git_payloads.commit_view("aaa", { "bbb" })))
  end)

  it("IRB: commit_view's ARITY is the structural enforcement — exactly (sha, parents), nothing more", function()
    -- The whole no-author-identity argument rests on there being no parameter
    -- an author field could arrive through, which is a claim about the function
    -- SIGNATURE — so it is asserted as one. Widening commit_view is exactly what
    -- a port would have to do to start capturing author identity, and that must
    -- not be able to pass silently. (This test is the tripwire, not the
    -- permission: adding an author field is out of protocol until a CPHS
    -- modification is FILED, whatever the tests say.)
    local info = debug.getinfo(git_payloads.commit_view, "u")
    assert.equals(2, info.nparams)
    assert.is_false(info.isvararg)

    -- Behaviourally too: a third argument is ignored rather than absorbed.
    local view = git_payloads.commit_view("aaa", { "bbb" }, {
      name = "Ada Lovelace",
      email = "ada@berkeley.edu",
    })
    assert.same({ "parents", "sha" }, key_set(view))

    local ev = git_payloads.build_git_event("commit", "aaa", view, "main")
    assert.same({ "branch", "commit_sha", "operation", "parents", "sha" }, key_set(ev.data))
    assert.is_nil(core_json.canonicalize(ev.data):find("@", 1, true))
  end)
end)
