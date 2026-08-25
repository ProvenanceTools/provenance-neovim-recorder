--- workspace_walk.walk_workspace / has_hard_excluded_segment — the shared
--- directory walk both seals will use to discover in-scope files under a
--- `files_under_review`/`ignore`/`attachments` rule (path-scope, Manifest
--- 2.0). Port of the monorepo's `workspace-walk.test.ts` scenarios.
---
--- Real temp directories, real files, real symlinks — no mocking of vim.uv,
--- matching this repo's "real, focused" bar for editor-seam / fs-seam code.
local walk = require("provenance.recorder.io.workspace_walk")

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

local function write_raw_file(path, contents)
  local uv = vim.uv or vim.loop
  vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
  local fd = assert(uv.fs_open(path, "w", 420)) -- 420 = 0o644
  uv.fs_write(fd, contents)
  uv.fs_close(fd)
end

local function sorted(t)
  local copy = vim.deepcopy(t)
  table.sort(copy)
  return copy
end

local function contains(list, value)
  for _, v in ipairs(list) do
    if v == value then
      return true
    end
  end
  return false
end

describe("workspace_walk.has_hard_excluded_segment", function()
  it("is true for a top-level .git segment", function()
    assert.is_true(walk.has_hard_excluded_segment(".git"))
    assert.is_true(walk.has_hard_excluded_segment(".git/config"))
  end)

  it("is true for a .provenance segment at any depth", function()
    assert.is_true(walk.has_hard_excluded_segment("hw2/.provenance/manifest.json"))
    assert.is_true(walk.has_hard_excluded_segment("vendor/lib/.git/objects/pack/x"))
  end)

  it("is false when no segment is exactly .git or .provenance", function()
    assert.is_false(walk.has_hard_excluded_segment("src/main.java"))
    assert.is_false(walk.has_hard_excluded_segment("my.git.txt"))
    assert.is_false(walk.has_hard_excluded_segment(".gitignore"))
  end)
end)

describe("workspace_walk.walk_workspace", function()
  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      -- Best-effort: a test that locked a directory down restores it itself
      -- before this runs, but chmod it open anyway so cleanup never leaves
      -- a stray unremovable tree behind.
      pcall(vim.uv.fs_chmod, dir, tonumber("755", 8))
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function new_tempdir()
    local dir = make_tempdir()
    table.insert(tempdirs, dir)
    return dir
  end

  it("returns workspace-relative forward-slash paths at depth", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "a")
    write_raw_file(dir .. "/src/main/Main.java", "class Main {}")
    write_raw_file(dir .. "/src/main/util/Helper.java", "class Helper {}")

    local result = walk.walk_workspace(dir)
    assert.same(
      { "a.txt", "src/main/Main.java", "src/main/util/Helper.java" },
      sorted(result.paths)
    )
    assert.is_false(result.had_unreadable_dir)
    assert.same({}, result.symlink_paths)
  end)

  it("defaults rel to empty string", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/only.txt", "x")
    local result = walk.walk_workspace(dir, nil)
    assert.same({ "only.txt" }, sorted(result.paths))
  end)

  it("prunes a nested .git directory (submodule case) before recursing into it", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/src/Main.java", "class Main {}")
    write_raw_file(dir .. "/vendor/lib/.git/objects/pack/x", "git object bytes")
    write_raw_file(dir .. "/vendor/lib/.git/HEAD", "ref: refs/heads/main")

    local result = walk.walk_workspace(dir)
    assert.same({ "src/Main.java" }, sorted(result.paths))
    for _, p in ipairs(result.paths) do
      assert.is_nil(p:find(".git", 1, true))
    end
  end)

  it("prunes a nested .provenance directory (sibling assignment case) before recursing into it", function()
    -- The motivating leak: nested/concurrent multi-assignment recording puts
    -- a SIBLING assignment's signed manifest at hw2/.provenance/manifest.json.
    -- A rule entry like "*.json" must never see it.
    local dir = new_tempdir()
    write_raw_file(dir .. "/hw3/Main.java", "class Main {}")
    write_raw_file(dir .. "/hw2/.provenance/manifest.json", '{"signed":"payload"}')
    write_raw_file(dir .. "/hw2/.provenance/manifest.sig", "deadbeef")

    local result = walk.walk_workspace(dir)
    assert.same({ "hw3/Main.java" }, sorted(result.paths))
  end)

  it("prunes .git/.provenance at the root too, not only nested", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "a")
    write_raw_file(dir .. "/.git/HEAD", "ref: refs/heads/main")
    write_raw_file(dir .. "/.provenance/manifest.json", "{}")

    local result = walk.walk_workspace(dir)
    assert.same({ "a.txt" }, sorted(result.paths))
  end)

  it("does not cycle on a self-referential directory symlink, and walks nothing under it", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/a.txt", "a")

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(dir, dir .. "/loop"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local result = walk.walk_workspace(dir)
    -- Finishing at all (no timeout/hang) is part of the assertion.
    assert.same({ "a.txt" }, sorted(result.paths))
    for _, p in ipairs(result.paths) do
      assert.is_nil(p:find("loop/", 1, true))
    end
    assert.is_true(contains(result.symlink_paths, "loop"))
  end)

  it("reports a symlinked FILE in symlink_paths and never in paths", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/real.txt", "real content")

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(dir .. "/real.txt", dir .. "/link.txt"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local result = walk.walk_workspace(dir)
    assert.same({ "real.txt" }, sorted(result.paths))
    assert.is_false(contains(result.paths, "link.txt"))
    assert.is_true(contains(result.symlink_paths, "link.txt"))
  end)

  it("does not report a hard-excluded symlink (a symlink literally named .git)", function()
    local dir = new_tempdir()
    local elsewhere = new_tempdir()
    write_raw_file(dir .. "/a.txt", "a")

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(elsewhere, dir .. "/.git"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local result = walk.walk_workspace(dir)
    assert.same({ "a.txt" }, sorted(result.paths))
    assert.is_false(contains(result.symlink_paths, ".git"))
  end)

  it("sets had_unreadable_dir when a subdirectory cannot be listed, and still returns the rest", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/visible.txt", "v")
    vim.fn.mkdir(dir .. "/locked", "p")
    write_raw_file(dir .. "/locked/secret.txt", "s")

    vim.uv.fs_chmod(dir .. "/locked", tonumber("000", 8))
    -- Verify the denial actually took effect (root defeats permission bits).
    local handle = vim.uv.fs_scandir(dir .. "/locked")
    local defeated = handle ~= nil
    if defeated then
      vim.uv.fs_chmod(dir .. "/locked", tonumber("755", 8))
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    local result = walk.walk_workspace(dir)
    vim.uv.fs_chmod(dir .. "/locked", tonumber("755", 8))

    assert.is_true(result.had_unreadable_dir)
    assert.same({ "visible.txt" }, sorted(result.paths))
  end)

  it("propagates had_unreadable_dir up through a nested subtree", function()
    local dir = new_tempdir()
    write_raw_file(dir .. "/top.txt", "t")
    vim.fn.mkdir(dir .. "/a/locked", "p")
    write_raw_file(dir .. "/a/locked/secret.txt", "s")
    write_raw_file(dir .. "/a/sibling.txt", "sib")

    vim.uv.fs_chmod(dir .. "/a/locked", tonumber("000", 8))
    local handle = vim.uv.fs_scandir(dir .. "/a/locked")
    local defeated = handle ~= nil
    if defeated then
      vim.uv.fs_chmod(dir .. "/a/locked", tonumber("755", 8))
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    local result = walk.walk_workspace(dir)
    vim.uv.fs_chmod(dir .. "/a/locked", tonumber("755", 8))

    assert.is_true(result.had_unreadable_dir)
    assert.same({ "a/sibling.txt", "top.txt" }, sorted(result.paths))
  end)

  it("treats an unlistable ROOT as unreadable with no results, never an abort", function()
    local dir = new_tempdir()
    vim.uv.fs_chmod(dir, tonumber("000", 8))
    local handle = vim.uv.fs_scandir(dir)
    local defeated = handle ~= nil
    vim.uv.fs_chmod(dir, tonumber("755", 8))
    if defeated then
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    vim.uv.fs_chmod(dir, tonumber("000", 8))
    local result = walk.walk_workspace(dir)
    vim.uv.fs_chmod(dir, tonumber("755", 8))

    assert.same({ paths = {}, had_unreadable_dir = true, symlink_paths = {} }, result)
  end)
end)
