--- vim.uv-backed manifest loader (design.md §4.1): finds and reads the
--- manifest file from a workspace directory, then delegates to the pure
--- activation.evaluate(). Real vim.uv against real temp-dir fixtures — no
--- mocks, per CLAUDE.md's "real, focused" testing bar for editor-seam code.
local activation = require("provenance.recorder.activation")
local course_public_key = require("provenance.course_public_key")

local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture()
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. "manifest.json"), "\n"))
end

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

describe("activation.load_and_verify", function()
  local fx = load_fixture()
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

  it("is inactive with reason no_manifest_file when neither manifest name exists", function()
    local dir = new_tempdir()
    local res = activation.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("no_manifest_file", res.reason)
  end)

  it("is active when .provenance-manifest is present and valid", function()
    local dir = new_tempdir()
    vim.fn.writefile({ vim.json.encode(fx.manifest) }, dir .. "/.provenance-manifest")
    local res = activation.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals("active", res.status)
    assert.is_table(res.manifest)
    assert.equals("hw3", res.manifest.assignment_id)
  end)

  it("prefers .provenance-manifest over provenance-manifest when both exist", function()
    local dir = new_tempdir()
    vim.fn.writefile({ vim.json.encode(fx.manifest) }, dir .. "/.provenance-manifest")
    vim.fn.writefile({ "{not json" }, dir .. "/provenance-manifest")
    local res = activation.load_and_verify(dir, fx.course_pubkey_hex)
    -- If the plain-form garbage had been read instead, this would be
    -- inactive/parse_error, proving the dotfile actually won.
    assert.equals("active", res.status)
  end)

  it("is inactive with reason manifest_read_error when the manifest name is a directory", function()
    local dir = new_tempdir()
    vim.fn.mkdir(dir .. "/.provenance-manifest", "p")
    local res = activation.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("manifest_read_error", res.reason)
  end)

  it("defaults pubkey_hex to COURSE_PUBLIC_KEY_HEX when omitted", function()
    assert.equals(course_public_key.COURSE_PUBLIC_KEY_HEX, fx.course_pubkey_hex)
    local dir = new_tempdir()
    vim.fn.writefile({ vim.json.encode(fx.manifest) }, dir .. "/.provenance-manifest")
    local res = activation.load_and_verify(dir)
    assert.equals("active", res.status)
  end)

  it("never throws even for a nonexistent workspace_dir", function()
    local ok, res = pcall(activation.load_and_verify, "/no/such/workspace/dir/at/all", fx.course_pubkey_hex)
    assert.is_true(ok)
    assert.equals("inactive", res.status)
    assert.equals("no_manifest_file", res.reason)
  end)
end)
