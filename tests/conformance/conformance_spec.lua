local sha256 = require("provenance.core.sha256")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ed25519 = require("provenance.core.ed25519")
local manifest = require("provenance.core.manifest")

-- NOTE: `<sfile>` (per the task brief) does not resolve to this file under
-- plenary's busted runner: specs are loaded via `loadfile()`, not `:source`,
-- so `vim.fn.expand("<sfile>:p")` yields "command line" rather than this
-- file's path. `debug.getinfo` reads the Lua chunk's own source instead,
-- which loadfile() sets correctly (as "@<path>").
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture(name)
  local dir = this_file_dir() .. "/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. name), "\n"))
end

describe("conformance: format vectors (vectors.json)", function()
  local v = load_fixture("vectors.json")

  it("sha256 vectors match", function()
    for _, case in ipairs(v.sha256) do
      assert.equals(case.hex, sha256.hex(case.input))
    end
  end)

  it("chain vectors match", function()
    for _, case in ipairs(v.chain) do
      local e = case.envelope
      local env = envelope.new(e.seq, e.t, e.wall, e.kind, e.data)
      assert.equals(case.hash, hc.chain_entry(case.prev_hash, env).hash)
    end
  end)
end)

describe("conformance: ed25519 vector (ed25519.json == @noble/ed25519)", function()
  local fx = load_fixture("ed25519.json")
  local priv = ed25519.from_hex(fx.priv_hex)

  it("public key matches", function()
    assert.equals(fx.pub_hex, ed25519.to_hex(ed25519.public_key_of(priv)))
  end)

  it("deterministic signature matches", function()
    assert.equals(fx.sig_hex, ed25519.to_hex(ed25519.sign(fx.msg_utf8, priv)))
  end)

  it("signature verifies", function()
    assert.is_true(ed25519.verify(ed25519.from_hex(fx.sig_hex), fx.msg_utf8, ed25519.from_hex(fx.pub_hex)))
  end)
end)

describe("conformance: manifest vector (manifest.json — activation gate)", function()
  local fx = load_fixture("manifest.json")

  it("parses and verifies the untouched fixture", function()
    local parsed = manifest.parse(vim.json.encode(fx.manifest))
    assert.is_true(parsed.ok)
    assert.is_true(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)

  it("verifies false if any field is mutated", function()
    for _, field in ipairs({ "assignment_id", "semester", "issued_at", "sig" }) do
      local decoded = vim.json.decode(vim.json.encode(fx.manifest))
      decoded[field] = decoded[field]:sub(1, -2) .. (decoded[field]:sub(-1) == "a" and "b" or "a")
      local parsed = manifest.parse(vim.json.encode(decoded))
      if parsed.ok then
        assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex), field .. " mutation should break verification")
      end
    end

    local decoded = vim.json.decode(vim.json.encode(fx.manifest))
    decoded.files_under_review = { "src/tampered.py" }
    local parsed = manifest.parse(vim.json.encode(decoded))
    assert.is_true(parsed.ok)
    assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)
end)
