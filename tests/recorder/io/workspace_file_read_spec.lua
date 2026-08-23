--- workspace_file_read.resolve_containment / read_workspace_file — the
--- single point through which every `missing` decision in BOTH seals is
--- meant to flow. Port of the monorepo's `workspace-file-read.test.ts`.
---
--- `missing` is an AFFIRMATIVE claim about a student ("this file was named
--- and is not there") that is rendered into academic-integrity proceedings,
--- and this module's contract is that exactly ONE condition may mint it:
--- ENOENT. These tests exercise one outcome per condition directly, real
--- vim.uv against real temp-dir fixtures (no mocking), matching this repo's
--- fs-seam testing bar.
local wfr = require("provenance.recorder.io.workspace_file_read")
local core_json = require("provenance.core.json")

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

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

--- This spec file's own repo root, resolved from `debug.getinfo` (same
--- technique as `extension_hash.lua`'s `compute_installed`) rather than
--- `getcwd()`, so it does not depend on the Makefile's invocation directory.
--- Walks up from `tests/recorder/io/workspace_file_read_spec.lua` to the
--- repo root: strip the filename, then `io` -> `recorder` -> `tests` -> root.
local function resolve_repo_root()
  local info = debug.getinfo(1, "S")
  local source = info.source
  assert(type(source) == "string" and source:sub(1, 1) == "@", "could not resolve spec file source path")
  local dir = source:sub(2)
  for _ = 1, 4 do
    dir = dir:match("^(.*)/[^/]+$")
    assert(dir ~= nil, "could not walk up to repo root from spec file path")
  end
  return dir
end

local REPO_ROOT = resolve_repo_root()

local function keys_sorted(t)
  local out = {}
  for k in pairs(t) do
    out[#out + 1] = k
  end
  table.sort(out)
  return out
end

describe("workspace_file_read.read_workspace_file", function()
  local tempdirs = {}
  local restore_modes = {}

  before_each(function()
    tempdirs = {}
    restore_modes = {}
  end)

  after_each(function()
    for _, entry in ipairs(restore_modes) do
      pcall(vim.uv.fs_chmod, entry.path, entry.mode)
    end
    for _, dir in ipairs(tempdirs) do
      pcall(vim.uv.fs_chmod, dir, tonumber("755", 8))
      vim.fn.delete(dir, "rf")
    end
  end)

  local function new_tempdir()
    local dir = make_tempdir()
    table.insert(tempdirs, dir)
    return dir
  end

  --- The workspace root's real path, computed once (as production callers
  --- are meant to), and the tempdir itself.
  local function new_workspace()
    local dir = new_tempdir()
    local real_root = assert(vim.uv.fs_realpath(dir))
    return dir, real_root
  end

  -- ---------------------------------------------------------------------------
  -- present
  -- ---------------------------------------------------------------------------

  it("reports an ordinary readable file as present, with its sha256", function()
    local dir, real_root = new_workspace()
    write_raw_file(dir .. "/src/Main.java", "class Main {}")

    local result = wfr.read_workspace_file(dir, real_root, "src/Main.java")
    assert.equals("present", result.status)
    assert.equals("src/Main.java", result.path)
    assert.equals(vim.fn.sha256("class Main {}"), result.sha256)
  end)

  -- ---------------------------------------------------------------------------
  -- missing — the ONE condition
  -- ---------------------------------------------------------------------------

  it("reports genuine absence as missing", function()
    local dir, real_root = new_workspace()
    local result = wfr.read_workspace_file(dir, real_root, "NotThere.java")
    assert.equals("missing", result.status)
    assert.equals("NotThere.java", result.path)
    assert.equals(core_json.NULL, result.sha256)
  end)

  -- ---------------------------------------------------------------------------
  -- unreadable — everything else
  -- ---------------------------------------------------------------------------

  it("reports a chmod-000 file as unreadable, never missing", function()
    local dir, real_root = new_workspace()
    local abs = dir .. "/secret.txt"
    write_raw_file(abs, "x")
    vim.uv.fs_chmod(abs, tonumber("000", 8))
    table.insert(restore_modes, { path = abs, mode = tonumber("644", 8) })

    -- Verify the denial actually took effect before asserting; a uid that
    -- defeats permission bits (root) makes this pending rather than false.
    local fd = vim.uv.fs_open(abs, "r", 438)
    if fd ~= nil then
      vim.uv.fs_close(fd)
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    local result = wfr.read_workspace_file(dir, real_root, "secret.txt")
    assert.same({ path = "secret.txt", status = "unreadable" }, result)
  end)

  it("reports a file under an unreadable PARENT directory as unreadable, never missing", function()
    -- The one that matters most: a file the student definitely has, made
    -- unreachable by a directory mode. `missing` here would say "you did
    -- not submit it" about a file sitting on disk.
    local dir, real_root = new_workspace()
    local locked = dir .. "/locked"
    write_raw_file(locked .. "/Main.java", "class Main {}")
    vim.uv.fs_chmod(locked, tonumber("000", 8))
    table.insert(restore_modes, { path = locked, mode = tonumber("755", 8) })

    local fd = vim.uv.fs_open(locked .. "/Main.java", "r", 438)
    if fd ~= nil then
      vim.uv.fs_close(fd)
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    local result = wfr.read_workspace_file(dir, real_root, "locked/Main.java")
    assert.same({ path = "locked/Main.java", status = "unreadable" }, result)
  end)

  it("reports a DIRECTORY named as a file as unreadable (the staff manifest typo)", function()
    -- files_under_review: ["src"] instead of "src/". A real, ordinary
    -- mistake, and neither `present` nor `missing` is a true answer for it.
    local dir, real_root = new_workspace()
    write_raw_file(dir .. "/src/Main.java", "class Main {}")

    local result = wfr.read_workspace_file(dir, real_root, "src")
    assert.same({ path = "src", status = "unreadable" }, result)
  end)

  it("reports a FIFO as unreadable and does NOT hang", function()
    -- Reading a FIFO blocks vim.uv's synchronous fs_open forever waiting for
    -- a writer, with no timeout anywhere in this call stack — the fs_stat
    -- gate in read_workspace_file is what prevents that. Verified
    -- empirically that an unguarded fs_open on a writer-less FIFO blocks the
    -- ENTIRE Neovim process (not just a coroutine), so this must run the
    -- risky call in a CHILD `nvim -l` process and enforce a wall-clock
    -- timeout from here, or a regression would wedge the whole test run
    -- rather than fail one test.
    if vim.fn.executable("mkfifo") == 0 then
      pending("mkfifo not available on this machine")
      return
    end
    local dir, real_root = new_workspace()
    local fifo = dir .. "/pipe.txt"
    vim.fn.system({ "mkfifo", fifo })
    if vim.v.shell_error ~= 0 then
      pending("mkfifo failed on this machine")
      return
    end

    local out_file = dir .. "/result.txt"
    local child_script = dir .. "/child.lua"
    local script = string.format(
      [[
package.path = %q .. "/lua/?.lua;" .. %q .. "/lua/?/init.lua;" .. package.path
local m = require("provenance.recorder.io.workspace_file_read")
local result = m.read_workspace_file(%q, %q, "pipe.txt", {})
local f = assert(io.open(%q, "w"))
f:write(tostring(result.status))
f:close()
]],
      REPO_ROOT,
      REPO_ROOT,
      dir,
      real_root,
      out_file
    )
    write_raw_file(child_script, script)

    local job = vim.fn.jobstart({ "nvim", "-l", child_script })
    assert.is_true(job > 0, "failed to start child nvim -l process")

    local waited = vim.fn.jobwait({ job }, 5000)
    if waited[1] == -1 then
      pcall(vim.fn.jobstop, job)
      assert.is_true(false, "read_workspace_file HUNG on a FIFO: did not return within 5s")
      return
    end

    assert.is_true(vim.fn.filereadable(out_file) == 1, "child process produced no result file")
    local lines = vim.fn.readfile(out_file)
    assert.equals("unreadable", lines[1])
  end)

  -- ---------------------------------------------------------------------------
  -- out_of_workspace — its own third outcome, never folded into missing
  -- ---------------------------------------------------------------------------

  it("reports a symlink resolving OUTSIDE the workspace as out_of_workspace", function()
    -- The overwhelmingly common way to reach this is innocent:
    -- ln -s ~/shared/data.csv data.csv. Minting `missing` for it told staff
    -- the student did not submit a file that is on disk and fully readable.
    local dir, real_root = new_workspace()
    local outside = new_tempdir()
    write_raw_file(outside .. "/data.csv", "a,b\n")

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(outside .. "/data.csv", dir .. "/data.csv"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local result = wfr.read_workspace_file(dir, real_root, "data.csv")
    assert.same({ path = "data.csv", status = "out_of_workspace" }, result)
  end)

  it('reports a "../" entry as out_of_workspace, never missing', function()
    local dir, real_root = new_workspace()
    local escapee = vim.fn.fnamemodify(dir, ":h") .. "/escaped-" .. vim.fn.fnamemodify(dir, ":t") .. ".txt"
    write_raw_file(escapee, "x")

    local ok, result = pcall(wfr.read_workspace_file, dir, real_root, "../" .. vim.fn.fnamemodify(escapee, ":t"))
    vim.fn.delete(escapee)
    assert.is_true(ok)
    assert.equals("out_of_workspace", result.status)
  end)

  it("follows a symlink that stays INSIDE the workspace and reports it present", function()
    -- The containment check must not reject an ordinary in-workspace link —
    -- rejecting it would drop a file the student really did submit.
    local dir, real_root = new_workspace()
    write_raw_file(dir .. "/real/Main.java", "class Main {}")

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(dir .. "/real/Main.java", dir .. "/link.java"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local result = wfr.read_workspace_file(dir, real_root, "link.java")
    assert.equals("present", result.status)
  end)

  -- ---------------------------------------------------------------------------
  -- with_bytes — absent, not nil-valued-but-present
  -- ---------------------------------------------------------------------------

  it("attaches raw bytes when opts.with_bytes = true", function()
    local dir, real_root = new_workspace()
    write_raw_file(dir .. "/a.txt", "hello")

    local result = wfr.read_workspace_file(dir, real_root, "a.txt", { with_bytes = true })
    assert.equals("present", result.status)
    assert.equals("hello", result.bytes)
  end)

  it("OMITS the bytes key entirely when with_bytes is not asked for", function()
    -- ABSENT, not merely nil-valued. This result gets spread into a
    -- SubmissionFileEntry inside a manifest that is JCS-canonicalized and
    -- SIGNED; a stray key would shift the canonical bytes of the signed
    -- message.
    local dir, real_root = new_workspace()
    write_raw_file(dir .. "/a.txt", "hello")

    local result = wfr.read_workspace_file(dir, real_root, "a.txt")
    assert.same({ "path", "sha256", "status" }, keys_sorted(result))

    local result_default_opts = wfr.read_workspace_file(dir, real_root, "a.txt", {})
    assert.same({ "path", "sha256", "status" }, keys_sorted(result_default_opts))

    local result_explicit_false = wfr.read_workspace_file(dir, real_root, "a.txt", { with_bytes = false })
    assert.same({ "path", "sha256", "status" }, keys_sorted(result_explicit_false))
  end)
end)

describe("workspace_file_read.resolve_containment", function()
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

  it("reports inside for the root itself and for an ordinary child path", function()
    local dir = new_tempdir()
    local real_root = assert(vim.uv.fs_realpath(dir))
    write_raw_file(dir .. "/a.txt", "a")

    assert.same({ kind = "inside" }, wfr.resolve_containment(real_root, dir))
    assert.same({ kind = "inside" }, wfr.resolve_containment(real_root, dir .. "/a.txt"))
  end)

  it("does not treat a sibling directory with the root as a prefix as inside", function()
    -- `/ws` must not be seen as containing `/wsother` under a bare prefix
    -- test.
    local dir = new_tempdir()
    local real_root = assert(vim.uv.fs_realpath(dir))
    local sibling = dir .. "other"
    vim.fn.mkdir(sibling, "p")
    table.insert(tempdirs, sibling)
    write_raw_file(sibling .. "/x.txt", "x")

    local result = wfr.resolve_containment(real_root, sibling .. "/x.txt")
    assert.equals("outside", result.kind)
  end)

  it("returns unresolved with code ENOENT for a genuinely absent path", function()
    local dir = new_tempdir()
    local real_root = assert(vim.uv.fs_realpath(dir))

    local result = wfr.resolve_containment(real_root, dir .. "/nope.txt")
    assert.same({ kind = "unresolved", code = "ENOENT" }, result)
  end)
end)
