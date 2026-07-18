--- extension_hash.compute / compute_installed — the real DirectoryHash tree
--- hash (Plan 9 Task 1), replacing Plan 4's fixed placeholder.
---
--- Port of the monorepo's extension-hash.ts algorithm, with ONE deliberate
--- deviation: relative paths are sorted by plain `table.sort` (a codepoint
--- sort — see extension_hash.lua's module comment for why this replaces
--- extension-hash.ts's locale-dependent `localeCompare`). The cross-tool
--- check below pins a hash computed by a Node reference implementation that
--- ALSO uses a codepoint sort (not localeCompare), proving the Lua
--- implementation matches that documented deterministic algorithm.
local extension_hash = require("provenance.recorder.commands.extension_hash")

local EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

local function write_raw_file(path, contents)
  local uv = vim.uv or vim.loop
  local fd = assert(uv.fs_open(path, "w", 420)) -- 420 = 0o644
  uv.fs_write(fd, contents)
  uv.fs_close(fd)
end

describe("extension_hash.compute", function()
  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function new_tempdir()
    local dir = make_tempdir()
    table.insert(tempdirs, dir)
    return dir
  end

  it("returns the pinned empty-sha256 for an empty tree", function()
    local dir = new_tempdir()
    assert.equals(EMPTY_SHA256, extension_hash.compute(dir))
  end)

  it("returns the pinned empty-sha256 for a non-existent root_dir", function()
    local dir = new_tempdir() .. "/does-not-exist"
    assert.equals(EMPTY_SHA256, extension_hash.compute(dir))
  end)

  it("returns a 64-char lowercase hex string for a non-empty tree", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "hello")

    local h = extension_hash.compute(dir)
    assert.equals("string", type(h))
    assert.equals(64, #h)
    assert.is_not_nil(h:match("^[0-9a-f]+$"))
  end)

  it("is stable across repeated calls over the same tree", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "hello")
    vim.fn.mkdir(dir .. "/b", "p")
    write_raw_file(dir .. "/b/c.txt", "world")

    local h1 = extension_hash.compute(dir)
    local h2 = extension_hash.compute(dir)
    assert.equals(h1, h2)
  end)

  it("is independent of file creation order (same file set, different insertion order)", function()
    local dir_a = new_tempdir()
    write_raw_file(dir_a .. "/a.txt", "hello")
    vim.fn.mkdir(dir_a .. "/b", "p")
    write_raw_file(dir_a .. "/b/c.txt", "world")
    write_raw_file(dir_a .. "/z.txt", "zzz")

    local dir_b = new_tempdir()
    write_raw_file(dir_b .. "/z.txt", "zzz")
    vim.fn.mkdir(dir_b .. "/b", "p")
    write_raw_file(dir_b .. "/b/c.txt", "world")
    write_raw_file(dir_b .. "/a.txt", "hello")

    assert.equals(extension_hash.compute(dir_a), extension_hash.compute(dir_b))
  end)

  it("skips a symlink (included tree hash unchanged by adding one)", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "hello")
    local before = extension_hash.compute(dir)

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(dir .. "/a.txt", dir .. "/a-link.txt"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local after = extension_hash.compute(dir)
    assert.equals(before, after)
  end)

  it("matches a Node reference implementation using a codepoint sort (NOT localeCompare)", function()
    -- Fixture mirrors a scratchpad-only Node script (not committed) that
    -- built the identical tree and rolled sha256(relBytes + 0x00 +
    -- fileBytes) over paths sorted by a codePointAt-based comparator (a
    -- deterministic codepoint sort, deliberately NOT localeCompare — see
    -- extension_hash.lua's module comment for the rationale).
    -- Sorted rels: B_upper.txt, a.txt, b/c.txt, b/nested/d.lua, z_top.txt
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "hello")
    vim.fn.mkdir(dir .. "/b", "p")
    write_raw_file(dir .. "/b/c.txt", "world")
    vim.fn.mkdir(dir .. "/b/nested", "p")
    write_raw_file(dir .. "/b/nested/d.lua", "return 1\n")
    write_raw_file(dir .. "/z_top.txt", "zzz")
    write_raw_file(dir .. "/B_upper.txt", "upper")

    local expected = "fa4756ab1612de062edfd5bc123ea92d046e6df43ed4267ea13c2ab0d3753194"
    assert.equals(expected, extension_hash.compute(dir))
  end)
end)

describe("extension_hash.compute_installed", function()
  it("returns a 64-char lowercase hex string", function()
    local h = extension_hash.compute_installed()
    assert.equals("string", type(h))
    assert.equals(64, #h)
    assert.is_not_nil(h:match("^[0-9a-f]+$"))
  end)

  it("is deterministic across repeated calls", function()
    assert.equals(extension_hash.compute_installed(), extension_hash.compute_installed())
  end)
end)
