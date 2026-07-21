--- Tests for discovery.lua: the upward-walk manifest resolver (Plan:
--- 2026-07-20-nested-manifest-discovery). Uses REAL temp directories and the
--- REAL vim.fs.find/activation.load_and_verify (no filesystem mocking --
--- the whole point of this module is real upward-walk semantics), but signs
--- test manifests with an injected pubkey via activation.evaluate's
--- pure-Lua path so no real course keypair is needed.
local discovery = require("provenance.recorder.discovery")
local ed25519 = require("provenance.core.ed25519")
local json = require("provenance.core.json")

local function new_scratch()
  local scratch = { dirs = {} }
  function scratch.dir(rel)
    local d = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(d, "p")
    table.insert(scratch.dirs, d)
    if rel then
      local nested = d .. "/" .. rel
      vim.fn.mkdir(nested, "p")
      return d, nested
    end
    return d
  end
  function scratch.mkdir(path)
    vim.fn.mkdir(path, "p")
  end
  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end
  function scratch.teardown()
    for _, d in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, d, "rf")
    end
  end
  return scratch
end

--- Signs a minimal manifest payload with a fresh test keypair and returns
--- (manifest_json_text, pubkey_hex).
---
--- NOTE: the real `provenance.core.ed25519` API (verified via
--- `grep -n "^function M\." lua/provenance/core/ed25519.lua`) exports
--- `generate_keypair`, `public_key_of`, `sign`, `verify`, `to_hex`,
--- `from_hex` -- there is no `random_private_key`/`public_key`.
--- `generate_keypair()` already returns the pubkey pre-hex-encoded, so no
--- extra `to_hex` wrapping is needed for it here.
local function make_signed_manifest(assignment_id)
  local privkey, pubkey_hex = ed25519.generate_keypair()
  local payload = {
    assignment_id = assignment_id,
    semester = "fa25",
    issued_at = "2026-07-20T00:00:00.000Z",
    files_under_review = json.array({ "main.py" }),
  }
  local canonical = json.canonicalize(payload)
  local sig = ed25519.to_hex(ed25519.sign(canonical, privkey))
  local full = vim.deepcopy(payload)
  full.files_under_review = { "main.py" } -- plain array for vim.json.encode
  full.sig = sig
  return vim.json.encode(full), pubkey_hex
end

describe("discovery.resolve_from_dir", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("no manifest anywhere upward: inactive, reason no_manifest_file", function()
    local root = scratch.dir("a/b/c")
    local result = discovery.resolve_from_dir(root .. "/a/b/c")
    assert.equals("inactive", result.status)
    assert.equals("no_manifest_file", result.reason)
  end)

  it("manifest at the exact starting directory: active, root == starting dir", function()
    local base = scratch.dir()
    local text, pubkey = make_signed_manifest("hw1")
    scratch.write_file(base .. "/.provenance-manifest", text)

    local result = discovery.resolve_from_dir(base, { pubkey_hex = pubkey })
    assert.equals("active", result.status)
    assert.equals(base, result.root)
    assert.equals("hw1", result.manifest.assignment_id)
  end)

  it("LAUNCH CASE: cd assignment/ && nvim file.py -- manifest at file's own dir", function()
    local base, nested = scratch.dir("cats")
    local text, pubkey = make_signed_manifest("cats")
    scratch.write_file(nested .. "/.provenance-manifest", text)

    local result = discovery.resolve_from_dir(nested, { pubkey_hex = pubkey })
    assert.equals("active", result.status)
    assert.equals(nested, result.root)
  end)

  it("LAUNCH CASE: cd parent && nvim cats/cats.py -- resolves cats/, never considers sibling hog/", function()
    local base = scratch.dir()
    scratch.mkdir(base .. "/cats")
    scratch.mkdir(base .. "/hog")
    local cats_text, cats_key = make_signed_manifest("cats")
    local hog_text, _hog_key = make_signed_manifest("hog")
    scratch.write_file(base .. "/cats/.provenance-manifest", cats_text)
    scratch.write_file(base .. "/hog/.provenance-manifest", hog_text)

    local result = discovery.resolve_from_dir(base .. "/cats", { pubkey_hex = cats_key })
    assert.equals("active", result.status)
    assert.equals(base .. "/cats", result.root)
    assert.equals("cats", result.manifest.assignment_id)
  end)

  it("LAUNCH CASE: cd ~ && nvim 61a/cats/cats.py -- walks up 3 levels, rest of ~ never scanned", function()
    local base, nested = scratch.dir("61a/cats/extra")
    local text, pubkey = make_signed_manifest("cats")
    scratch.write_file(base .. "/61a/cats/.provenance-manifest", text)

    local result = discovery.resolve_from_dir(nested, { pubkey_hex = pubkey, stop_dir = base })
    assert.equals("active", result.status)
    assert.equals(base .. "/61a/cats", result.root)
  end)

  it("failing signature at the nearest manifest: inactive, does NOT fall through to search further up", function()
    local base = scratch.dir()
    scratch.mkdir(base .. "/outer")
    scratch.mkdir(base .. "/outer/inner")
    local outer_text, outer_key = make_signed_manifest("outer-assignment")
    local inner_text, _inner_key = make_signed_manifest("inner-assignment")
    scratch.write_file(base .. "/outer/.provenance-manifest", outer_text)
    scratch.write_file(base .. "/outer/inner/.provenance-manifest", inner_text)

    -- Verify against outer's key: the NEAREST manifest (inner) fails
    -- signature verification, and resolution must NOT fall through to the
    -- valid outer manifest.
    local result = discovery.resolve_from_dir(base .. "/outer/inner", { pubkey_hex = outer_key })
    assert.equals("inactive", result.status)
    assert.equals("signature_invalid", result.reason)
    assert.equals(base .. "/outer/inner", result.root)
  end)

  it("plain 'provenance-manifest' fallback name is found when the dotfile is absent", function()
    local base = scratch.dir()
    local text, pubkey = make_signed_manifest("plain-name")
    scratch.write_file(base .. "/provenance-manifest", text)

    local result = discovery.resolve_from_dir(base, { pubkey_hex = pubkey })
    assert.equals("active", result.status)
  end)
end)

describe("discovery.resolve_for_file", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("resolves from the FILE's directory, not the file path itself", function()
    local base = scratch.dir()
    local text, pubkey = make_signed_manifest("hw2")
    scratch.write_file(base .. "/.provenance-manifest", text)
    scratch.write_file(base .. "/main.py", "print(1)\n")

    local result = discovery.resolve_for_file(base .. "/main.py", { pubkey_hex = pubkey })
    assert.equals("active", result.status)
    assert.equals(base, result.root)
  end)

  it("a file under NO manifest resolves to nothing", function()
    local base = scratch.dir()
    scratch.write_file(base .. "/scratch.txt", "no manifest here\n")

    local result = discovery.resolve_for_file(base .. "/scratch.txt")
    assert.equals("inactive", result.status)
  end)
end)
