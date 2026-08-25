-- Unit tests for provenance.core.path_scope, beyond the shared conformance
-- vectors (tests/conformance/path_scope_spec.lua). Aims at full branch
-- coverage of validate_scope_entry and resolve_path_role, matching this
-- repo's log-core equivalent's coverage bar.

local path_scope = require("provenance.core.path_scope")

describe("path_scope.is_hard_excluded", function()
  it("matches the .provenance/ prefix form", function()
    assert.is_true(path_scope.is_hard_excluded(".provenance/manifest.json"))
  end)

  it("matches the .git/ prefix form", function()
    assert.is_true(path_scope.is_hard_excluded(".git/config"))
  end)

  it("matches the exact-path form (.provenance-manifest)", function()
    assert.is_true(path_scope.is_hard_excluded(".provenance-manifest"))
  end)

  it("matches the exact-path form (provenance-manifest)", function()
    assert.is_true(path_scope.is_hard_excluded("provenance-manifest"))
  end)

  it("does NOT hard-exclude a near-miss prefix (.gitignore does not start with .git/)", function()
    assert.is_false(path_scope.is_hard_excluded(".gitignore"))
  end)

  it("does not hard-exclude an ordinary path", function()
    assert.is_false(path_scope.is_hard_excluded("src/Main.java"))
  end)
end)

describe("path_scope.is_exact_entry", function()
  it("is true for the exact-path form", function()
    assert.is_true(path_scope.is_exact_entry("Makefile"))
  end)

  it("is false for the directory-prefix form", function()
    assert.is_false(path_scope.is_exact_entry("src/"))
  end)

  it("is false for the leading-suffix form", function()
    assert.is_false(path_scope.is_exact_entry("*.java"))
  end)
end)

describe("path_scope.matches_scope_entry — suffix form matches at any depth", function()
  it("matches a top-level file", function()
    assert.is_true(path_scope.matches_scope_entry("Main.java", "*.java"))
  end)

  it("matches a deeply nested file", function()
    assert.is_true(path_scope.matches_scope_entry("a/b/c/d/Main.java", "*.java"))
  end)
end)

describe("path_scope.matches_any_scope_entry", function()
  it("is false for an empty entry list", function()
    assert.is_false(path_scope.matches_any_scope_entry("src/Main.java", {}))
  end)

  it("is false when scope list is nil", function()
    assert.is_false(path_scope.matches_any_scope_entry("src/Main.java", nil))
  end)

  it("is true when any entry matches", function()
    assert.is_true(path_scope.matches_any_scope_entry("src/Main.java", { "*.class", "src/" }))
  end)
end)

describe("path_scope.resolve_path_role", function()
  it("treats a nil ignore/attachments/track list as empty and resolves unscoped", function()
    assert.equals("unscoped", path_scope.resolve_path_role("README.md", {}))
  end)

  it("treats a nil ignore list as empty when track/attachments are present", function()
    local role = path_scope.resolve_path_role("src/Main.java", { track = { "src/" } })
    assert.equals("reviewed", role)
  end)

  it("treats a nil attachments list as empty when track is present", function()
    local role = path_scope.resolve_path_role("src/Main.java", { track = { "src/" }, ignore = {} })
    assert.equals("reviewed", role)
  end)

  it("resolves excluded ahead of everything else, even a matching track entry", function()
    local role = path_scope.resolve_path_role(".git/config", { track = { "*" } })
    assert.equals("excluded", role)
  end)

  it("resolves ignored ahead of attachment and track", function()
    local role = path_scope.resolve_path_role(
      "src/A.class",
      { track = { "src/" }, ignore = { "*.class" }, attachments = { "src/" } }
    )
    assert.equals("ignored", role)
  end)

  it("resolves attachment ahead of track", function()
    local role = path_scope.resolve_path_role(
      "src/build.log",
      { track = { "src/" }, attachments = { "src/build.log" } }
    )
    assert.equals("attachment", role)
  end)

  it("resolves reviewed when only track matches", function()
    local role = path_scope.resolve_path_role("src/Main.java", { track = { "src/" } })
    assert.equals("reviewed", role)
  end)

  it("resolves unscoped when nothing matches", function()
    local role = path_scope.resolve_path_role("README.md", { track = { "src/" } })
    assert.equals("unscoped", role)
  end)
end)

describe("path_scope.validate_scope_entry — every problem kind", function()
  it("empty", function()
    local problem = path_scope.validate_scope_entry("")
    assert.is_not_nil(problem)
    assert.equals("empty", problem.kind)
  end)

  it("whitespace (leading)", function()
    local problem = path_scope.validate_scope_entry(" src/")
    assert.is_not_nil(problem)
    assert.equals("whitespace", problem.kind)
  end)

  it("whitespace (trailing)", function()
    local problem = path_scope.validate_scope_entry("Makefile ")
    assert.is_not_nil(problem)
    assert.equals("whitespace", problem.kind)
  end)

  it("backslash", function()
    local problem = path_scope.validate_scope_entry("src\\Main.java")
    assert.is_not_nil(problem)
    assert.equals("backslash", problem.kind)
  end)

  it("absolute (leading slash)", function()
    local problem = path_scope.validate_scope_entry("/etc/passwd")
    assert.is_not_nil(problem)
    assert.equals("absolute", problem.kind)
  end)

  it("absolute (drive letter)", function()
    local problem = path_scope.validate_scope_entry("C:/Users/a")
    assert.is_not_nil(problem)
    assert.equals("absolute", problem.kind)
  end)

  it("dot_segment (single dot)", function()
    local problem = path_scope.validate_scope_entry("./src/")
    assert.is_not_nil(problem)
    assert.equals("dot_segment", problem.kind)
  end)

  it("dot_segment (double dot)", function()
    local problem = path_scope.validate_scope_entry("../secrets")
    assert.is_not_nil(problem)
    assert.equals("dot_segment", problem.kind)
  end)

  it("empty_segment", function()
    local problem = path_scope.validate_scope_entry("src//a.java")
    assert.is_not_nil(problem)
    assert.equals("empty_segment", problem.kind)
  end)

  it("bad_wildcard (more than one star)", function()
    local problem = path_scope.validate_scope_entry("**/a.java")
    assert.is_not_nil(problem)
    assert.equals("bad_wildcard", problem.kind)
  end)

  it("bad_wildcard (star not at index 0)", function()
    local problem = path_scope.validate_scope_entry("src/*.java")
    assert.is_not_nil(problem)
    assert.equals("bad_wildcard", problem.kind)
  end)

  it("bad_wildcard (bare star)", function()
    local problem = path_scope.validate_scope_entry("*")
    assert.is_not_nil(problem)
    assert.equals("bad_wildcard", problem.kind)
  end)

  it("bad_wildcard (leading star with trailing slash)", function()
    local problem = path_scope.validate_scope_entry("*.java/")
    assert.is_not_nil(problem)
    assert.equals("bad_wildcard", problem.kind)
  end)

  it("forbidden_char (?)", function()
    local problem = path_scope.validate_scope_entry("a?.java")
    assert.is_not_nil(problem)
    assert.equals("forbidden_char", problem.kind)
  end)

  it("forbidden_char ([)", function()
    local problem = path_scope.validate_scope_entry("a[0-9].java")
    assert.is_not_nil(problem)
    assert.equals("forbidden_char", problem.kind)
  end)

  it("forbidden_char (])", function()
    local problem = path_scope.validate_scope_entry("a0-9].java")
    assert.is_not_nil(problem)
    assert.equals("forbidden_char", problem.kind)
  end)

  it("forbidden_char ({)", function()
    local problem = path_scope.validate_scope_entry("{a,b}.java")
    assert.is_not_nil(problem)
    assert.equals("forbidden_char", problem.kind)
  end)

  it("forbidden_char (})", function()
    local problem = path_scope.validate_scope_entry("b}.java")
    assert.is_not_nil(problem)
    assert.equals("forbidden_char", problem.kind)
  end)

  it("accepts a legal exact-path entry", function()
    assert.is_nil(path_scope.validate_scope_entry("Makefile"))
  end)

  it("accepts a legal directory-prefix entry", function()
    assert.is_nil(path_scope.validate_scope_entry("src/"))
  end)

  it("accepts a legal leading-suffix entry", function()
    assert.is_nil(path_scope.validate_scope_entry("*.java"))
  end)

  it("every detail is a non-empty string (shown verbatim to staff)", function()
    local entries = {
      "",
      " src/",
      "src\\Main.java",
      "/etc/passwd",
      "../secrets",
      "src//a.java",
      "**/a.java",
      "*",
      "*.java/",
      "a?.java",
    }
    for _, entry in ipairs(entries) do
      local problem = path_scope.validate_scope_entry(entry)
      assert.is_not_nil(problem)
      assert.is_string(problem.detail)
      assert.is_true(#problem.detail > 0)
    end
  end)
end)
