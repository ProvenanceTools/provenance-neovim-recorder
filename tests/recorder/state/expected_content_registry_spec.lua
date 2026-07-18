--- Tests for ExpectedContentRegistry.
--- Port of expected-content-registry.test.ts. See
--- lua/provenance/recorder/state/expected_content_registry.lua.
local registry = require("provenance.recorder.state.expected_content_registry")

describe("expected_content_registry", function()
  it("get_or_create returns same instance for same path", function()
    local reg = registry.new({ "src/foo.py" })
    local ec1 = reg.get_or_create("src/foo.py", "hello")
    local ec2 = reg.get_or_create("src/foo.py", "something else")
    assert.equals(ec1, ec2)
    -- Content should be from first construction, not overwritten
    assert.equals("hello", ec1.get_content())
  end)

  it("get returns nil for unknown path", function()
    local reg = registry.new({ "src/foo.py" })
    assert.is_nil(reg.get("not/there.py"))
  end)

  it("get returns the entry after get_or_create", function()
    local reg = registry.new({ "src/foo.py" })
    local ec = reg.get_or_create("src/foo.py", "content")
    assert.equals(ec, reg.get("src/foo.py"))
  end)

  it("delete removes entry; get returns nil after delete", function()
    local reg = registry.new({ "src/foo.py" })
    reg.get_or_create("src/foo.py", "content")
    reg.delete("src/foo.py")
    assert.is_nil(reg.get("src/foo.py"))
  end)

  it("is_watched is true for paths in the list", function()
    local reg = registry.new({ "src/foo.py", "src/bar.py" })
    assert.is_true(reg.is_watched("src/foo.py"))
    assert.is_true(reg.is_watched("src/bar.py"))
  end)

  it("is_watched is false for paths not in the list", function()
    local reg = registry.new({ "src/foo.py" })
    assert.is_false(reg.is_watched("src/other.py"))
    assert.is_false(reg.is_watched(""))
  end)

  it("can track multiple files independently", function()
    local reg = registry.new({ "a.py", "b.py" })
    local a = reg.get_or_create("a.py", "aaa")
    local b = reg.get_or_create("b.py", "bbb")
    assert.is_not.equals(a, b)
    assert.equals("aaa", a.get_content())
    assert.equals("bbb", b.get_content())
  end)

  it("get_or_create does not itself gate on is_watched", function()
    -- Matches the TS: registry construction does not check is_watched;
    -- the caller is responsible for gating on is_watched before calling.
    local reg = registry.new({ "src/foo.py" })
    local ec = reg.get_or_create("unwatched/path.py", "content")
    assert.equals("content", ec.get_content())
    assert.is_false(reg.is_watched("unwatched/path.py"))
  end)
end)
