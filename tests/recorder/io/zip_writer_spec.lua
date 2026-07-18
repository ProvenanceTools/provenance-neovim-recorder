--- Pure-Lua STORE-method ZIP writer (design.md §3 keystone: no shelling out
--- to `zip`, no native dependency). `unzip` (present on this macOS dev box
--- at /usr/bin/unzip) is used here ONLY to validate the archives this
--- module produces are real, spec-compliant ZIP files that a standard
--- unarchiver (and, by extension, JSZip on the analyzer side) can read.
--- The plugin runtime never shells out to unzip/zip.
local zip_writer = require("provenance.recorder.io.zip_writer")

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

describe("zip_writer._crc32", function()
  it("matches the known CRC-32 vectors", function()
    assert.equals(0x00000000, zip_writer._crc32(""))
    assert.equals(0xCBF43926, zip_writer._crc32("123456789"))
  end)
end)

describe("zip_writer.build", function()
  it("is deterministic across repeated calls with identical input", function()
    local entries = {
      { name = "manifest.json", data = '{"a":1}' },
      { name = "dir/sub.txt", data = "hello\nworld" },
      { name = "empty", data = "" },
    }
    local a = zip_writer.build(entries)
    local b = zip_writer.build(entries)
    assert.equals(a, b)
  end)

  it("starts with the local file header signature", function()
    local archive = zip_writer.build({ { name = "a", data = "x" } })
    assert.equals(string.char(0x50, 0x4b, 0x03, 0x04), archive:sub(1, 4))
  end)
end)

describe("zip_writer round-trip via unzip", function()
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

  local function unzip_available()
    return vim.fn.executable("unzip") == 1
  end

  it("produces a zip unzip -t reports clean and unzip -p extracts byte-exact", function()
    if not unzip_available() then
      pending("unzip not available on this machine")
      return
    end

    local dir = new_tempdir()
    local zip_path = dir .. "/bundle.zip"

    -- Includes a NUL byte, deliberately: proves no text mangling / correct
    -- size accounting through the zip headers themselves.
    local binary_data = string.char(0, 255, 128) .. "mid" .. string.char(1, 2, 3)
    local entries = {
      { name = "manifest.json", data = '{"a":1}' },
      { name = "dir/sub.txt", data = "hello\nworld" },
      { name = "empty", data = "" },
      { name = "binary.bin", data = binary_data },
    }

    assert.is_true(zip_writer.write(zip_path, entries))
    assert.is_true(vim.uv.fs_stat(zip_path) ~= nil)

    -- Integrity check.
    local test_out = vim.fn.system({ "unzip", "-t", zip_path })
    assert.equals(0, vim.v.shell_error)
    assert.is_truthy(test_out:find("No errors detected"))

    -- Listing check: all names present.
    local list_out = vim.fn.system({ "unzip", "-l", zip_path })
    assert.equals(0, vim.v.shell_error)
    for _, e in ipairs(entries) do
      assert.is_truthy(list_out:find(e.name, 1, true), "missing " .. e.name .. " in listing")
    end

    -- Content extraction: byte-exact for the text-ish entries via
    -- `unzip -p` piped through vim.fn.system(). NOTE: vim.fn.system()'s
    -- return is a Vimscript *string*, which (like all Vim strings) cannot
    -- represent embedded NUL bytes — Neovim silently remaps any NUL byte
    -- in captured stdout to 0x01. That's a limitation of piping binary
    -- data through vim.fn.system(), not of the zip archive itself, so it
    -- is only exercised here for entries that don't contain NUL bytes.
    for _, e in ipairs(entries) do
      if e.name ~= "binary.bin" then
        local extracted = vim.fn.system({ "unzip", "-p", zip_path, e.name })
        assert.equals(0, vim.v.shell_error)
        assert.equals(e.data, extracted)
      end
    end

    -- The binary (NUL-containing) entry: extract to a real file with
    -- `unzip -o -d`, then read it back with vim.uv (raw fs I/O, no
    -- Vimscript string round-trip) for a true byte-exact comparison.
    local extract_dir = dir .. "/extracted"
    vim.fn.mkdir(extract_dir, "p")
    vim.fn.system({ "unzip", "-o", "-d", extract_dir, zip_path, "binary.bin" })
    assert.equals(0, vim.v.shell_error)

    local uv = vim.uv or vim.loop
    local fd = assert(uv.fs_open(extract_dir .. "/binary.bin", "r", 420))
    local stat = uv.fs_fstat(fd)
    local extracted_binary = uv.fs_read(fd, stat.size, 0)
    uv.fs_close(fd)
    assert.equals(binary_data, extracted_binary)
  end)
end)
