--- vim.uv-backed manifest loader (design.md §4.1): finds and reads the
--- manifest file from a workspace directory, then delegates to the pure
--- activation.evaluate(). Real vim.uv against real temp-dir fixtures — no
--- mocks, per CLAUDE.md's "real, focused" testing bar for editor-seam code.
local activation = require("provenance.recorder.activation")
local trust_keys = require("provenance.trust_keys")

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

  --- THE GRANDFATHER GATE. This is the one path the legacy anchor exists to
  --- protect, so it is the one path that must be proven end to end against the
  --- REAL embedded constant, with nothing injected.
  ---
  --- legacy-manifest-v1.json is a 1.x manifest signed with provnvim's master
  --- key. It is stored as a bare manifest object with no `course_pubkey_hex`
  --- alongside it, deliberately: there is no key in the file to pass as an
  --- override, so the only way this can come back "active" is the embedded
  --- LEGACY_COURSE_PUBLIC_KEY_HEX actually working.
  ---
  --- It is kept SEPARATE from tests/conformance/fixtures/manifest.json. That
  --- file was serving two masters -- a generator-signed conformance vector that
  --- must stay byte-identical to provjet's, and this activation gate -- and
  --- regenerating the vector silently broke the gate. Never merge them again.
  describe("the embedded 1.x anchor (grandfather gate)", function()
    local legacy_manifest_text = table.concat(
      vim.fn.readfile(this_file_dir() .. "/fixtures/legacy-manifest-v1.json"),
      "\n"
    )

    local function workspace_with_legacy_manifest()
      local dir = new_tempdir()
      vim.fn.writefile(vim.split(legacy_manifest_text, "\n"), dir .. "/.provenance-manifest")
      return dir
    end

    it("activates a master-key-signed 1.x manifest with NO pubkey override", function()
      local res = activation.load_and_verify(workspace_with_legacy_manifest())
      assert.equals("active", res.status)
      assert.equals("1.0", res.manifest.format_version)
      assert.equals("hw3", res.manifest.assignment_id)
    end)

    it("the fixture really is 1.x: no format_version and no course_cert", function()
      -- If this fixture ever became 2.0 the test above would start proving
      -- something else entirely, and the legacy anchor would go uncovered again.
      local decoded = vim.json.decode(legacy_manifest_text)
      assert.is_nil(decoded.format_version)
      assert.is_nil(decoded.course_cert)
    end)

    it("omitting the override is identical to passing LEGACY_COURSE_PUBLIC_KEY_HEX", function()
      local dir = workspace_with_legacy_manifest()
      local defaulted = activation.load_and_verify(dir)
      local explicit = activation.load_and_verify(dir, trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX)
      assert.equals("active", defaulted.status)
      assert.equals(explicit.status, defaulted.status)
      assert.equals(explicit.reason, defaulted.reason)
    end)

    it("and is NOT identical to passing the root key", function()
      -- The anchors are not interchangeable. If the 1.x path ever defaulted to
      -- the root key, this fixture would stop activating.
      local dir = workspace_with_legacy_manifest()
      local rooted = activation.load_and_verify(dir, trust_keys.ROOT_PUBLIC_KEY_HEX)
      assert.equals("inactive", rooted.status)
      assert.equals("signature_invalid", rooted.reason)
      assert.equals("active", activation.load_and_verify(dir).status)
    end)
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



  it("never throws even for a nonexistent workspace_dir", function()
    local ok, res = pcall(activation.load_and_verify, "/no/such/workspace/dir/at/all", fx.course_pubkey_hex)
    assert.is_true(ok)
    assert.equals("inactive", res.status)
    assert.equals("no_manifest_file", res.reason)
  end)
end)
