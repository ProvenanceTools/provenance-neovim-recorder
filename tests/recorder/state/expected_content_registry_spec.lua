--- Tests for ExpectedContentRegistry.
--- Port of expected-content-registry.test.ts. See
--- lua/provenance/recorder/state/expected_content_registry.lua.
local registry = require("provenance.recorder.state.expected_content_registry")

--- Build a ResolvedScope-shaped table with defaults, mirroring the TS test's
--- `scope(over)` helper.
local function scope(over)
  over = over or {}
  return {
    track = over.track or {},
    ignore = over.ignore or {},
    attachments = over.attachments or {},
  }
end

describe("expected_content_registry", function()
  it("get_or_create returns same instance for same path", function()
    local reg = registry.new(scope({ track = { "src/foo.py" } }))
    local ec1 = reg.get_or_create("src/foo.py", "hello")
    local ec2 = reg.get_or_create("src/foo.py", "something else")
    assert.equals(ec1, ec2)
    -- Content should be from first construction, not overwritten
    assert.equals("hello", ec1.get_content())
  end)

  it("get returns nil for unknown path", function()
    local reg = registry.new(scope({ track = { "src/foo.py" } }))
    assert.is_nil(reg.get("not/there.py"))
  end)

  it("get returns the entry after get_or_create", function()
    local reg = registry.new(scope({ track = { "src/foo.py" } }))
    local ec = reg.get_or_create("src/foo.py", "content")
    assert.equals(ec, reg.get("src/foo.py"))
  end)

  it("delete removes entry; get returns nil after delete", function()
    local reg = registry.new(scope({ track = { "src/foo.py" } }))
    reg.get_or_create("src/foo.py", "content")
    reg.delete("src/foo.py")
    assert.is_nil(reg.get("src/foo.py"))
  end)

  it("can track multiple files independently", function()
    local reg = registry.new(scope({ track = { "a.py", "b.py" } }))
    local a = reg.get_or_create("a.py", "aaa")
    local b = reg.get_or_create("b.py", "bbb")
    assert.is_not.equals(a, b)
    assert.equals("aaa", a.get_content())
    assert.equals("bbb", b.get_content())
  end)

  it("get_or_create does not itself gate on is_watched", function()
    -- Matches the TS: registry construction does not check is_watched;
    -- the caller is responsible for gating on is_watched before calling.
    -- Confirmed BEFORE admission, since admitting the path via get_or_create
    -- puts it in the map, at which point is_watched's rule 1 ("already in
    -- the map") correctly reports it as watched regardless of scope.
    local reg = registry.new(scope({ track = { "src/foo.py" } }))
    assert.is_false(reg.is_watched("unwatched/path.py"))
    local ec = reg.get_or_create("unwatched/path.py", "content")
    assert.equals("content", ec.get_content())
  end)
end)

describe("expected_content_registry is_watched (live membership)", function()
  it("is true for an exact-path entry", function()
    local reg = registry.new(scope({ track = { "src/foo.py", "src/bar.py" } }))
    assert.is_true(reg.is_watched("src/foo.py"))
    assert.is_true(reg.is_watched("src/bar.py"))
  end)

  it("is false for paths outside the scope", function()
    local reg = registry.new(scope({ track = { "src/foo.py" } }))
    assert.is_false(reg.is_watched("src/other.py"))
    assert.is_false(reg.is_watched(""))
  end)

  it("admits a file created mid-session under a directory rule (live, not snapshotted)", function()
    local reg = registry.new(scope({ track = { "src/" } }))
    assert.is_true(reg.is_watched("src/written_later.py"))
  end)

  it("never watches an ignored path, even inside a tracked folder", function()
    local reg = registry.new(scope({ track = { "src/" }, ignore = { "*.class" } }))
    assert.is_false(reg.is_watched("src/A.class"))
  end)

  it("never watches an attachment", function()
    local reg = registry.new(scope({ track = { "src/" }, attachments = { "src/build.log" } }))
    assert.is_false(reg.is_watched("src/build.log"))
  end)

  it("never watches a hard-excluded path however greedy the manifest is", function()
    local reg = registry.new(scope({ track = { "*.json" } }))
    assert.is_false(reg.is_watched(".provenance/manifest.json"))
  end)

  it("a path already in the map returns true without consulting the cap", function()
    -- max_files=0 means the cap would refuse ANY new admission, but a path
    -- already admitted (before the cap was ever this tight) still reads true
    -- and does not flip cap_hit.
    local reg = registry.new(scope({ track = { "src/" } }), { max_files = 1 })
    assert.is_true(reg.is_watched("src/a.py"))
    reg.get_or_create("src/a.py", "")
    assert.is_false(reg.cap_hit())
    -- Now the cap is full; a second path is refused and flips cap_hit...
    assert.is_false(reg.is_watched("src/b.py"))
    assert.is_true(reg.cap_hit())
    -- ...but the already-admitted path is unaffected.
    assert.is_true(reg.is_watched("src/a.py"))
  end)

  it("a non-reviewed path never flips cap_hit, even with the cap already exhausted", function()
    local reg = registry.new(scope({ track = { "src/" } }), { max_files = 0 })
    assert.is_false(reg.is_watched("README.md"))
    assert.is_false(reg.cap_hit())
  end)
end)

describe("expected_content_registry the memory cap", function()
  it("defaults to the writer-contract cap", function()
    assert.equals(512, registry.EXPECTED_CONTENT_MAX_FILES)
  end)

  it("stops admitting new paths once full, and says so", function()
    local reg = registry.new(scope({ track = { "src/" } }), { max_files = 2 })
    assert.is_false(reg.cap_hit())

    assert.is_true(reg.is_watched("src/a.py"))
    reg.get_or_create("src/a.py", "")
    assert.is_true(reg.is_watched("src/b.py"))
    reg.get_or_create("src/b.py", "")

    assert.is_false(reg.is_watched("src/c.py"))
    assert.is_true(reg.cap_hit())
  end)

  it("keeps watching paths already admitted after the cap bites", function()
    local reg = registry.new(scope({ track = { "src/" } }), { max_files = 1 })
    assert.is_true(reg.is_watched("src/a.py"))
    reg.get_or_create("src/a.py", "")
    assert.is_false(reg.is_watched("src/b.py"))
    assert.is_true(reg.is_watched("src/a.py"))
  end)

  it("does not report a cap hit for a path that was never in scope", function()
    local reg = registry.new(scope({ track = { "src/" } }), { max_files = 0 })
    assert.is_false(reg.is_watched("README.md"))
    assert.is_false(reg.cap_hit())
  end)

  it("admission past the cap stops AND flips cap_hit (drives it with real admission, not a fake size)", function()
    -- Drives 512 + a few more admissions through the real default cap via a
    -- suffix rule, so this test would fail if is_watched's cap check and
    -- get_or_create's admission ever fell out of step with each other (the
    -- "decorative cap" hazard: something gating on is_watched but never
    -- populating the registry).
    local reg = registry.new(scope({ track = { "*.txt" } }))
    assert.is_false(reg.cap_hit())

    for i = 1, registry.EXPECTED_CONTENT_MAX_FILES do
      local rel = "f" .. i .. ".txt"
      assert.is_true(reg.is_watched(rel), "expected admission for " .. rel)
      reg.get_or_create(rel, "")
    end
    assert.is_false(reg.cap_hit())

    -- The 513th admission is refused and flips the cap.
    assert.is_false(reg.is_watched("overflow1.txt"))
    assert.is_true(reg.cap_hit())

    -- Further overflow paths are also refused (cap stays hit, not merely a
    -- one-shot flag), and none of them get admitted.
    for i = 1, 5 do
      local rel = "overflow_extra" .. i .. ".txt"
      assert.is_false(reg.is_watched(rel))
      assert.is_nil(reg.get(rel))
    end

    -- Every one of the first 512 is still tracked.
    for i = 1, registry.EXPECTED_CONTENT_MAX_FILES do
      assert.is_not_nil(reg.get("f" .. i .. ".txt"))
    end
  end)
end)
