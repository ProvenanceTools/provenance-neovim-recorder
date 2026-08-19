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
    -- Prove the default parameter *is* COURSE_PUBLIC_KEY_HEX: omitting the key
    -- must behave identically to passing that constant explicitly. (The fixture
    -- is signed with the master key, so both come back "active"; this assertion
    -- holds regardless of the resulting status.)
    local dir = new_tempdir()
    vim.fn.writefile({ vim.json.encode(fx.manifest) }, dir .. "/.provenance-manifest")
    local defaulted = activation.load_and_verify(dir)
    local explicit = activation.load_and_verify(dir, course_public_key.COURSE_PUBLIC_KEY_HEX)
    assert.equals(explicit.status, defaulted.status)
    assert.equals(explicit.reason, defaulted.reason)
  end)

  --- read_manifest is the cheap half of load_and_verify, split out so a caller
  --- can obtain the manifest bytes (to key a cache on) without paying for the
  --- ~12 ms ed25519 verification. It must agree with load_and_verify on every
  --- non-"found" outcome, or the cache would change activation semantics.
  describe("read_manifest", function()
    it("returns the manifest bytes and the path that won precedence", function()
      local dir = new_tempdir()
      local text = vim.json.encode(fx.manifest)
      vim.fn.writefile({ text }, dir .. "/.provenance-manifest")
      vim.fn.writefile({ "not json" }, dir .. "/provenance-manifest")

      local res = activation.read_manifest(dir)
      assert.equals("found", res.status)
      assert.equals(dir .. "/.provenance-manifest", res.path)
      assert.equals(text, vim.trim(res.text))
    end)

    it("falls back to the plain name when the dotfile is absent", function()
      local dir = new_tempdir()
      vim.fn.writefile({ vim.json.encode(fx.manifest) }, dir .. "/provenance-manifest")
      local res = activation.read_manifest(dir)
      assert.equals("found", res.status)
      assert.equals(dir .. "/provenance-manifest", res.path)
    end)

    it("reports no_manifest_file / manifest_read_error exactly as load_and_verify does", function()
      local empty = new_tempdir()
      assert.equals("no_manifest_file", activation.read_manifest(empty).reason)
      assert.equals("no_manifest_file", activation.load_and_verify(empty, fx.course_pubkey_hex).reason)

      local as_dir = new_tempdir()
      vim.fn.mkdir(as_dir .. "/.provenance-manifest", "p")
      assert.equals("manifest_read_error", activation.read_manifest(as_dir).reason)
      assert.equals("manifest_read_error", activation.load_and_verify(as_dir, fx.course_pubkey_hex).reason)
    end)

    it("never throws for a nonexistent workspace_dir", function()
      local ok, res = pcall(activation.read_manifest, "/no/such/workspace/dir/at/all")
      assert.is_true(ok)
      assert.equals("no_manifest_file", res.reason)
    end)
  end)

  it("course_pubkey defaults to COURSE_PUBLIC_KEY_HEX and passes through an explicit key", function()
    assert.equals(course_public_key.COURSE_PUBLIC_KEY_HEX, activation.course_pubkey())
    assert.equals(course_public_key.COURSE_PUBLIC_KEY_HEX, activation.course_pubkey(nil))
    assert.equals("ab", activation.course_pubkey("ab"))
  end)

  it("never throws even for a nonexistent workspace_dir", function()
    local ok, res = pcall(activation.load_and_verify, "/no/such/workspace/dir/at/all", fx.course_pubkey_hex)
    assert.is_true(ok)
    assert.equals("inactive", res.status)
    assert.equals("no_manifest_file", res.reason)
  end)
end)
