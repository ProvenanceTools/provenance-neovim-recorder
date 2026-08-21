--- The three `session.start` CAPABILITY REPORTS (collaboration spec §5.6).
--- Unit specs for core/session_capabilities.lua, focused on the READ/BUILD
--- rules a fixture-driven test cannot pin as clearly: omission vs `null`,
--- malformed-path rejection, and the empty-`watched`-array serialization.
--- Cross-language byte parity is covered separately by
--- tests/conformance/conformance_spec.lua's session-capabilities.json block.
local core_json = require("provenance.core.json")
local session_capabilities = require("provenance.core.session_capabilities")

describe("session_capabilities.read_git_capture / read_witness_capture", function()
  it("reads absent when the field is missing entirely", function()
    assert.equals("absent", session_capabilities.read_git_capture({}).kind)
    assert.equals("absent", session_capabilities.read_witness_capture({}).kind)
  end)

  it("reads absent when data itself is not a table", function()
    for _, bad in ipairs({ nil, "x", 5, true }) do
      assert.equals("absent", session_capabilities.read_git_capture(bad).kind)
      assert.equals("absent", session_capabilities.read_witness_capture(bad).kind)
    end
  end)

  it("reads absent when data is an array or json.NULL", function()
    assert.equals("absent", session_capabilities.read_git_capture(core_json.array({})).kind)
    assert.equals("absent", session_capabilities.read_git_capture(core_json.NULL).kind)
  end)

  it("reads absent for an explicit vim.NIL or core_json.NULL value — but a writer must OMIT", function()
    for _, null_value in ipairs({ vim.NIL, core_json.NULL }) do
      assert.equals("absent", session_capabilities.read_git_capture({ git_capture = null_value }).kind)
      assert.equals(
        "absent",
        session_capabilities.read_witness_capture({ witness_capture = null_value }).kind
      )
    end
  end)

  it("reads every legal git_capture value as recorded", function()
    for _, v in ipairs(session_capabilities.GIT_CAPTURE_VALUES) do
      local got = session_capabilities.read_git_capture({ git_capture = v })
      assert.equals("recorded", got.kind)
      assert.equals(v, got.capture)
    end
  end)

  it("reads every legal witness_capture value as recorded", function()
    for _, v in ipairs(session_capabilities.WITNESS_CAPTURE_VALUES) do
      local got = session_capabilities.read_witness_capture({ witness_capture = v })
      assert.equals("recorded", got.kind)
      assert.equals(v, got.capture)
    end
  end)

  it("witness_capture is a TWO-value enum: git_capture's 'not_owned' is malformed here", function()
    local got = session_capabilities.read_witness_capture({ witness_capture = "not_owned" })
    assert.equals("malformed", got.kind)
    assert.equals("unknown_value", got.problem)
  end)

  it("rejects an unknown string as malformed/unknown_value, never coerced or folded", function()
    local got = session_capabilities.read_git_capture({ git_capture = "partial" })
    assert.equals("malformed", got.kind)
    assert.equals("unknown_value", got.problem)
  end)

  it("case is not folded: an uppercased legal value is still malformed", function()
    local got = session_capabilities.read_git_capture({ git_capture = "Available" })
    assert.equals("malformed", got.kind)
    assert.equals("unknown_value", got.problem)
  end)

  it("rejects a non-string value as malformed/not_a_string, never coerced", function()
    for _, bad in ipairs({ true, 1, {} }) do
      local got = session_capabilities.read_git_capture({ git_capture = bad })
      assert.equals("malformed", got.kind)
      assert.equals("not_a_string", got.problem)
    end
  end)
end)

describe("session_capabilities.read_file_scope", function()
  it("reads absent when the field is missing, data is not an object, or the value is null", function()
    assert.equals("absent", session_capabilities.read_file_scope({}).kind)
    assert.equals("absent", session_capabilities.read_file_scope(nil).kind)
    assert.equals("absent", session_capabilities.read_file_scope(core_json.array({})).kind)
    assert.equals(
      "absent",
      session_capabilities.read_file_scope({ file_scope = vim.NIL }).kind
    )
    assert.equals(
      "absent",
      session_capabilities.read_file_scope({ file_scope = core_json.NULL }).kind
    )
  end)

  it("reads a complete watched list", function()
    local got = session_capabilities.read_file_scope({
      file_scope = { watched = core_json.array({ "Solver.java", "src/Board.java" }), complete = true },
    })
    assert.equals("recorded", got.kind)
    assert.same({ "Solver.java", "src/Board.java" }, got.watched)
    assert.is_true(got.complete)
  end)

  it("an EMPTY watched list with complete=true is a real, meaningful answer — not absence", function()
    local got = session_capabilities.read_file_scope({
      file_scope = { watched = core_json.array({}), complete = true },
    })
    assert.equals("recorded", got.kind)
    assert.same({}, got.watched)
    assert.is_true(got.complete)
  end)

  it("rejects file_scope that is not an object (an array is not a scope)", function()
    local got = session_capabilities.read_file_scope({ file_scope = core_json.array({ "x" }) })
    assert.equals("malformed", got.kind)
    assert.equals("not_an_object", got.problem)
  end)

  it("rejects a missing or non-array `watched`", function()
    local got1 = session_capabilities.read_file_scope({ file_scope = { complete = true } })
    assert.equals("malformed", got1.kind)
    assert.equals("watched_not_an_array", got1.problem)

    -- An UNTAGGED table (not core_json.array-wrapped) is indistinguishable
    -- from a JSON object post-normalize, so it must also be rejected as
    -- "not an array" — a writer that forgot to tag it must not slip through.
    local got2 = session_capabilities.read_file_scope({ file_scope = { watched = {}, complete = true } })
    assert.equals("malformed", got2.kind)
    assert.equals("watched_not_an_array", got2.problem)
  end)

  it("rejects a missing or non-boolean `complete` — it is required, never inferred", function()
    local got1 = session_capabilities.read_file_scope({
      file_scope = { watched = core_json.array({ "Solver.java" }) },
    })
    assert.equals("malformed", got1.kind)
    assert.equals("complete_not_a_boolean", got1.problem)

    local got2 = session_capabilities.read_file_scope({
      file_scope = { watched = core_json.array({}), complete = "true" },
    })
    assert.equals("malformed", got2.kind)
    assert.equals("complete_not_a_boolean", got2.problem)
  end)

  -- -------------------------------------------------------------------
  -- MALFORMED-PATH REJECTION — the DoD's explicit requirement. Every
  -- element rejects the WHOLE list, never just the offending entry.
  -- -------------------------------------------------------------------

  local function scope_with(paths)
    return { file_scope = { watched = core_json.array(paths), complete = true } }
  end

  it("rejects a POSIX absolute path", function()
    local got = session_capabilities.read_file_scope(scope_with({ "ok.txt", "/etc/passwd" }))
    assert.equals("malformed", got.kind)
    assert.equals("path_absolute", got.problem)
  end)

  it("rejects a leading-backslash path", function()
    local got = session_capabilities.read_file_scope(scope_with({ "\\Users\\student\\x" }))
    assert.equals("malformed", got.kind)
    assert.equals("path_absolute", got.problem)
  end)

  it("rejects a Windows drive path, with or without a trailing separator", function()
    for _, p in ipairs({ "C:\\Users\\student\\Solver.java", "c:/Users/x", "C:" }) do
      local got = session_capabilities.read_file_scope(scope_with({ p }))
      assert.equals("malformed", got.kind, p)
      assert.equals("path_absolute", got.problem, p)
    end
  end)

  it("rejects any remote URL spelling via the general colon rule", function()
    for _, p in ipairs({
      "https://github.com/some-student/proj2/Solver.java",
      "ssh://git@host/repo.git",
      "git@github.com:someone/proj2.git",
    }) do
      local got = session_capabilities.read_file_scope(scope_with({ p }))
      assert.equals("malformed", got.kind, p)
      assert.equals("path_has_colon", got.problem, p)
    end
  end)

  it("rejects a '..' path segment, forward or backward slash separated", function()
    for _, p in ipairs({ "../other-course/Solver.java", "a/../b", "a\\..\\b" }) do
      local got = session_capabilities.read_file_scope(scope_with({ p }))
      assert.equals("malformed", got.kind, p)
      assert.equals("path_escapes_scope", got.problem, p)
    end
  end)

  it("rejects an empty-string path and a non-string element", function()
    local got1 = session_capabilities.read_file_scope(scope_with({ "" }))
    assert.equals("malformed", got1.kind)
    assert.equals("path_empty", got1.problem)

    local got2 = session_capabilities.read_file_scope(scope_with({ 5 }))
    assert.equals("malformed", got2.kind)
    assert.equals("path_not_a_string", got2.problem)
  end)

  it("accepts paths that merely LOOK risky: a leading dot, a doubled dot inside a segment", function()
    local got = session_capabilities.read_file_scope(
      scope_with({ ".hidden/config.txt", "a..b/Solver.java", "src\\main\\Board.java" })
    )
    assert.equals("recorded", got.kind)
    assert.same({ ".hidden/config.txt", "a..b/Solver.java", "src\\main\\Board.java" }, got.watched)
  end)

  it("a single bad entry rejects the WHOLE list, not merely that entry", function()
    local got = session_capabilities.read_file_scope(scope_with({ "ok1.txt", "/etc/passwd", "ok2.txt" }))
    assert.equals("malformed", got.kind)
    assert.equals("path_absolute", got.problem)
  end)

  it("forward compatibility: an unknown extra key does not reject the scope", function()
    local got = session_capabilities.read_file_scope({
      file_scope = {
        watched = core_json.array({ "Solver.java" }),
        complete = true,
        resolution = "repo_tracked",
      },
    })
    assert.equals("recorded", got.kind)
    assert.same({ "Solver.java" }, got.watched)
  end)
end)

describe("session_capabilities.build_file_scope", function()
  it("copies watched verbatim and tags it as a JSON array, even when empty", function()
    local built = session_capabilities.build_file_scope({}, true)
    assert.is_not_nil(built)
    assert.same({}, built.watched)
    assert.is_true(built.complete)
    assert.is_true(core_json.is_array(built.watched))
  end)

  it("EMPTY-WATCHED-ARRAY SERIALIZATION: canonicalizes as [] and never as {}", function()
    local built = session_capabilities.build_file_scope({}, true)
    local canon = core_json.canonicalize(built)
    assert.equals('{"complete":true,"watched":[]}', canon)
    assert.is_nil(canon:find('"watched":{}', 1, true))
  end)

  it("a non-empty watched list also canonicalizes as a JSON array, in order", function()
    local built = session_capabilities.build_file_scope({ "b.txt", "a.txt" }, false)
    local canon = core_json.canonicalize(built)
    -- Array ELEMENT order is untouched by JCS (only object KEYS sort) — "b.txt"
    -- must still precede "a.txt".
    assert.equals('{"complete":false,"watched":["b.txt","a.txt"]}', canon)
  end)

  it("returns nil (never a partial list) when any entry fails the path check", function()
    assert.is_nil(session_capabilities.build_file_scope({ "ok.txt", "/etc/passwd" }, true))
    assert.is_nil(session_capabilities.build_file_scope({ "../escape.txt" }, true))
    assert.is_nil(session_capabilities.build_file_scope({ "git@host:path" }, true))
  end)

  it("mutating the input list after the call does not affect the returned copy", function()
    local input = { "a.txt" }
    local built = session_capabilities.build_file_scope(input, true)
    input[1] = "mutated.txt"
    input[2] = "extra.txt"
    assert.same({ "a.txt" }, built.watched)
  end)

  it("a caller must assign the nil result directly (never spread core_json.NULL) to omit the key", function()
    -- Documents the OMIT-never-null writer contract at the Lua-table level:
    -- assigning a `nil` build result to a table key already omits it.
    local payload = { format_version = "1.0" }
    payload.file_scope = session_capabilities.build_file_scope({ "/abs" }, true)
    assert.is_nil(payload.file_scope)
    assert.is_nil(core_json.canonicalize(payload):find("file_scope", 1, true))
  end)
end)
