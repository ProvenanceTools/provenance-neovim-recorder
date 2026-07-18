--- Bundle manifest — model, shape validation, signing.
--- Mirrors log-core's BundleManifest builder + validateBundleManifestShape +
--- the "sign the entire canonicalized manifest" convention (design.md /
--- 2026-07-17-core-crypto-bundle.md Task 3).
local bundle = require("provenance.core.bundle")
local ed25519 = require("provenance.core.ed25519")

-- Locate the shared conformance fixtures dir (see conformance_spec for why
-- debug.getinfo is used rather than <sfile> under plenary's loadfile runner).
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture(name)
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. name), "\n"))
end

local VALID_1_1 = {
  format_version = "1.1",
  assignment_id = "hw3",
  semester = "fa25",
  extension_hash = ("a"):rep(64),
  sessions = {
    {
      session_id = "11111111-1111-4111-8111-111111111111",
      prev_session_id = nil,
      slog_sha256 = ("b"):rep(64),
      meta_sha256 = ("c"):rep(64),
    },
  },
  submission_files = {
    { path = "src/main.py", status = "present", sha256 = ("f"):rep(64) },
    { path = "src/missing.py", status = "missing" },
  },
}

describe("bundle.sign / bundle.verify_sig round-trip", function()
  it("sign then verify_sig with the same generated keypair is true", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local built = bundle.build(VALID_1_1)
    local signed = bundle.sign(built, priv)
    assert.is_string(signed.canonical_json)
    assert.equals(128, #signed.signature_hex)
    assert.is_true(bundle.verify_sig(signed.canonical_json, signed.signature_hex, pub_hex))
  end)

  it("verify_sig is false against the wrong pubkey", function()
    local priv, _ = ed25519.generate_keypair()
    local _, other_pub_hex = ed25519.generate_keypair()
    local built = bundle.build(VALID_1_1)
    local signed = bundle.sign(built, priv)
    assert.is_false(bundle.verify_sig(signed.canonical_json, signed.signature_hex, other_pub_hex))
  end)

  it("verify_sig is false when the canonical_json is tampered", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local built = bundle.build(VALID_1_1)
    local signed = bundle.sign(built, priv)
    assert.is_false(bundle.verify_sig(signed.canonical_json .. "x", signed.signature_hex, pub_hex))
  end)
end)

describe("bundle.validate_shape", function()
  it("accepts a well-formed 1.1 manifest", function()
    local res = bundle.validate_shape(VALID_1_1)
    assert.is_true(res.ok)
  end)

  it("accepts a well-formed 1.0 manifest without submission_files", function()
    local v = vim.deepcopy(VALID_1_1)
    v.format_version = "1.0"
    v.submission_files = nil
    local res = bundle.validate_shape(v)
    assert.is_true(res.ok)
  end)

  it("rejects a wrong format_version", function()
    local v = vim.deepcopy(VALID_1_1)
    v.format_version = "2.0"
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("wrong_version", res.error.kind)
  end)

  it("rejects a missing extension_hash", function()
    local v = vim.deepcopy(VALID_1_1)
    v.extension_hash = nil
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
  end)

  it("rejects a non-64-hex extension_hash", function()
    local v = vim.deepcopy(VALID_1_1)
    v.extension_hash = "not-hex"
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
  end)

  it("rejects a non-64-hex session slog_sha256", function()
    local v = vim.deepcopy(VALID_1_1)
    v.sessions[1].slog_sha256 = "short"
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
  end)

  it("rejects 1.1 missing submission_files", function()
    local v = vim.deepcopy(VALID_1_1)
    v.submission_files = nil
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("submission_files", res.error.field)
  end)

  it("rejects a 'missing' status submission_file with a non-null sha256", function()
    local v = vim.deepcopy(VALID_1_1)
    v.submission_files[2].sha256 = ("f"):rep(64)
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
  end)

  it("rejects a 'present' status submission_file with a null sha256", function()
    local v = vim.deepcopy(VALID_1_1)
    v.submission_files[1].sha256 = nil
    local res = bundle.validate_shape(v)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
  end)

  it("rejects a non-table input", function()
    local res = bundle.validate_shape("not a table")
    assert.is_false(res.ok)
    assert.equals("not_object", res.error.kind)
  end)

  it("rejects a 1.1 manifest whose sessions is a JSON object, not an array", function()
    local decoded = vim.json.decode(
      '{"format_version":"1.1","assignment_id":"a","semester":"s",'
        .. '"extension_hash":"' .. ("a"):rep(64) .. '",'
        .. '"sessions":{"x":1},"submission_files":[]}'
    )
    local res = bundle.validate_shape(decoded)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("sessions", res.error.field)
  end)
end)

describe("conformance: bundle-manifest.json (byte-exact JCS pin + verify_sig)", function()
  local fx = load_fixture("bundle-manifest.json")

  it("bundle.build + to_canonical reproduces the fixture's canonical_json exactly", function()
    local built = bundle.build(fx.manifest)
    local canonical = bundle.to_canonical(built)
    assert.equals(fx.canonical_json, canonical)
  end)

  it("verify_sig is true for the fixture's canonical_json/signature/pubkey", function()
    assert.is_true(bundle.verify_sig(fx.canonical_json, fx.signature_hex, fx.session_pubkey_hex))
  end)

  it("sign -> verify_sig round-trips with a locally generated keypair", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local built = bundle.build(fx.manifest)
    local signed = bundle.sign(built, priv)
    assert.equals(fx.canonical_json, signed.canonical_json)
    assert.is_true(bundle.verify_sig(signed.canonical_json, signed.signature_hex, pub_hex))
  end)
end)

describe("conformance: golden-bundle.json (real sealed 1.0 manifest validates)", function()
  local fx = load_fixture("golden-bundle.json")

  it("validate_shape accepts it", function()
    local res = bundle.validate_shape(fx.manifest)
    assert.is_true(res.ok)
  end)
end)
