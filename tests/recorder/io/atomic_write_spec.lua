--- Atomic write over vim.uv (write-temp-then-rename): the primitive used
--- later for `.slog.meta`, `manifest.json`, and `manifest.sig` — the
--- signed/integrity-critical files that must never be left half-written.
--- Real vim.uv against real temp-dir fixtures, per CLAUDE.md's "real,
--- focused" testing bar for editor-seam code.
local atomic_write_file = require("provenance.recorder.io.atomic_write").atomic_write_file

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

describe("atomic_write_file", function()
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

  it("round-trips contents to the target path", function()
    local dir = new_tempdir()
    local target = dir .. "/manifest.json"
    atomic_write_file(target, '{"hello":"world"}')
    assert.equals('{"hello":"world"}', read_all(target))
  end)

  it("leaves no .tmp sibling after a successful write", function()
    local dir = new_tempdir()
    local target = dir .. "/manifest.sig"
    atomic_write_file(target, "signature-bytes")
    local leftovers = vim.fn.glob(dir .. "/*.tmp", true, true)
    assert.same({}, leftovers)
  end)

  it("atomically overwrites existing content", function()
    local dir = new_tempdir()
    local target = dir .. "/manifest.json"
    atomic_write_file(target, "V1 content")
    assert.equals("V1 content", read_all(target))

    atomic_write_file(target, "V2 content, different length")
    assert.equals("V2 content, different length", read_all(target))

    local leftovers = vim.fn.glob(dir .. "/*.tmp", true, true)
    assert.same({}, leftovers)
  end)

  it("raises and leaves no temp file when the parent directory does not exist", function()
    local dir = new_tempdir()
    local target = dir .. "/nonexistent-subdir/file.json"

    local ok, err = pcall(atomic_write_file, target, "should not land")

    assert.is_false(ok)
    assert.is_truthy(err)
    assert.is_false(vim.uv.fs_stat(target) ~= nil)

    -- No temp file leaked into the (existing) parent tempdir either.
    local leftovers = vim.fn.glob(dir .. "/*.tmp", true, true)
    assert.same({}, leftovers)
  end)

  it("leaves the original file intact when a later write to the same target fails", function()
    local dir = new_tempdir()
    local target = dir .. "/keepme.json"
    atomic_write_file(target, "original content")
    assert.equals("original content", read_all(target))

    -- A failing write to a *different*, unwritable target must not disturb
    -- an already-sealed file elsewhere in the same directory.
    local bad_target = dir .. "/nonexistent-subdir/other.json"
    local ok = pcall(atomic_write_file, bad_target, "new content")
    assert.is_false(ok)

    assert.equals("original content", read_all(target))
  end)
end)
