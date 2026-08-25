--- Pure activation decision: parse + verify a manifest against the course
--- pubkey. Mirrors the recorder's activation gate (design.md §4.1) but with
--- zero Neovim API use in the module under test — only this spec uses
--- vim.json.encode, to serialize the fixture's manifest object into text.
local activation = require("provenance.recorder.activation")

-- Locate the shared conformance fixtures dir (see conformance_spec for why
-- debug.getinfo is used rather than <sfile> under plenary's loadfile runner).
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture()
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. "manifest.json"), "\n"))
end

describe("activation.evaluate", function()
  local fx = load_fixture()

  it("is active for a valid signed manifest with the correct pubkey", function()
    local res = activation.evaluate(vim.json.encode(fx.manifest), fx.course_pubkey_hex)
    assert.equals("active", res.status)
    assert.is_table(res.manifest)
    assert.equals("hw3", res.manifest.assignment_id)
  end)

  it("is inactive with reason signature_invalid for the wrong pubkey", function()
    local wrong_pubkey = fx.course_pubkey_hex:sub(1, -2) .. (fx.course_pubkey_hex:sub(-1) == "0" and "1" or "0")
    local res = activation.evaluate(vim.json.encode(fx.manifest), wrong_pubkey)
    assert.equals("inactive", res.status)
    assert.equals("signature_invalid", res.reason)
  end)

  it("is inactive with reason signature_invalid for a tampered field", function()
    local decoded = vim.json.decode(vim.json.encode(fx.manifest))
    decoded.assignment_id = decoded.assignment_id .. "-tampered"
    local res = activation.evaluate(vim.json.encode(decoded), fx.course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("signature_invalid", res.reason)
  end)

  it("is inactive with reason parse_error for malformed JSON, and does not throw", function()
    local ok, res = pcall(activation.evaluate, "{not json", fx.course_pubkey_hex)
    assert.is_true(ok)
    assert.equals("inactive", res.status)
    assert.equals("parse_error", res.reason)
  end)
end)

--- Trust-anchor routing (program spec §2/§3/§9). Two embedded anchors, chosen
--- by the manifest's own `format_version`, and NOT interchangeable:
---   2.0        -> ROOT_PUBLIC_KEY_HEX, via manifest.verify_chain
---   1.x/absent -> LEGACY_COURSE_PUBLIC_KEY_HEX, via manifest.verify
describe("activation.evaluate trust-anchor routing", function()
  local trust_keys = require("provenance.trust_keys")
  local core_manifest = require("provenance.core.manifest")

  local function this_file_dir()
    local source = debug.getinfo(1, "S").source
    local path = source:match("^@(.*)$") or source
    return vim.fn.fnamemodify(path, ":h")
  end

  local function read_json(path)
    return vim.json.decode(table.concat(vim.fn.readfile(path), "\n"))
  end

  local fixtures = this_file_dir() .. "/../conformance/fixtures/"
  -- A 1.x manifest (no format_version at all).
  local legacy_fx = read_json(fixtures .. "manifest.json")
  -- A real 2.0 manifest whose course_cert chains to the DEV ROOT key. Copied
  -- verbatim from the monorepo's test-workspace/.provenance-manifest — the same
  -- dev manifest all three recorders activate against, which is the point of
  -- every recorder embedding the same dev root key.
  local dev_v2_text = table.concat(vim.fn.readfile(this_file_dir() .. "/fixtures/dev-manifest-v2.json"), "\n")
  -- A 1.x manifest signed with THIS recorder's embedded master key -- the
  -- grandfather gate. No key travels with it, so "active" can only mean the
  -- embedded LEGACY_COURSE_PUBLIC_KEY_HEX worked.
  local gate_v1_text = table.concat(vim.fn.readfile(this_file_dir() .. "/fixtures/legacy-manifest-v1.json"), "\n")
  local v2_fx = read_json(fixtures .. "manifest-v2.json")

  -- Routing is asserted directly, by capturing which key each verifier is
  -- handed, rather than inferred from a pass/fail outcome.
  local real_verify, real_verify_chain = core_manifest.verify, core_manifest.verify_chain
  local verify_keys, chain_keys

  before_each(function()
    verify_keys, chain_keys = {}, {}
    core_manifest.verify = function(m, key)
      table.insert(verify_keys, key)
      return real_verify(m, key)
    end
    core_manifest.verify_chain = function(m, key)
      table.insert(chain_keys, key)
      return real_verify_chain(m, key)
    end
  end)

  after_each(function()
    core_manifest.verify, core_manifest.verify_chain = real_verify, real_verify_chain
  end)

  it("1.x with no override verifies against LEGACY_COURSE_PUBLIC_KEY_HEX, and never walks a chain", function()
    activation.evaluate(vim.json.encode(legacy_fx.manifest))
    assert.same({ trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX }, verify_keys)
    assert.same({}, chain_keys)
  end)

  it("2.0 with no override chains to ROOT_PUBLIC_KEY_HEX, and never takes the plain 1.x path", function()
    -- verify_chain is STUBBED here rather than wrapped: step 2 of the chain
    -- legitimately calls manifest.verify with course_cert.course_pubkey, and
    -- for the dev keypair that value happens to equal the legacy constant. Cut
    -- the chain short and the only remaining question is the one under test —
    -- which verifier `evaluate` reaches for, and with which key.
    core_manifest.verify_chain = function(_, key)
      table.insert(chain_keys, key)
      return { ok = true, value = { window = { in_window = true } } }
    end
    activation.evaluate(dev_v2_text)
    assert.same({ trust_keys.ROOT_PUBLIC_KEY_HEX }, chain_keys)
    assert.same({}, verify_keys)
  end)

  it("the DEV 2.0 manifest activates against the embedded root key with no override", function()
    -- The end-to-end proof that ROOT_PUBLIC_KEY_HEX is wired as the 2.0 anchor:
    -- real crypto, the shared dev manifest, nothing injected.
    local res = activation.evaluate(dev_v2_text)
    assert.equals("active", res.status)
    assert.equals("2.0", res.manifest.format_version)
    assert.equals("dev-course", res.manifest.course_id)
    assert.is_table(res.manifest.course_cert)
  end)

  it("a 2.0 manifest NEVER falls back to the legacy course key", function()
    -- The legacy key is the dev COURSE key, i.e. exactly the key that signed
    -- this manifest's payload. If 2.0 could fall back to it, a stapled cert
    -- plus an invented capture-disabling policy would have a path that accepts
    -- it — which is what step 0 exists to deny.
    local res = activation.evaluate(dev_v2_text, trust_keys.LEGACY_COURSE_PUBLIC_KEY_HEX)
    assert.equals("inactive", res.status)
    assert.equals("chain_invalid", res.reason)
    assert.equals("invalid_root_signature", res.detail.kind)
  end)

  it("a master-key-signed 1.x manifest activates on the legacy anchor and NOT on the root key", function()
    -- Uses the gate fixture (signed with this recorder's own embedded master
    -- key), so both halves are load-bearing: it really does activate by
    -- default, and swapping in the root key really does refuse it. That pair is
    -- the whole grandfather clause in one assertion.
    assert.equals("active", activation.evaluate(gate_v1_text).status)

    local rooted = activation.evaluate(gate_v1_text, trust_keys.ROOT_PUBLIC_KEY_HEX)
    assert.equals("inactive", rooted.status)
    assert.equals("signature_invalid", rooted.reason)
  end)

  it("an explicit override applies on whichever path the version selects", function()
    activation.evaluate(vim.json.encode(legacy_fx.manifest), legacy_fx.course_pubkey_hex)
    assert.same({ legacy_fx.course_pubkey_hex }, verify_keys)

    verify_keys, chain_keys = {}, {}
    activation.evaluate(vim.json.encode(v2_fx.valid_2_0.manifest), v2_fx.root_pubkey_hex)
    assert.same({ v2_fx.root_pubkey_hex }, chain_keys)
  end)

  it("a 2.0 chain failure reports reason chain_invalid with the chain error attached", function()
    local res = activation.evaluate(vim.json.encode(v2_fx.valid_2_0.manifest), v2_fx.other_course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("chain_invalid", res.reason)
    assert.is_table(res.detail)
  end)

  it("an EXPIRED cert still activates — the window is non-fatal (program spec §4)", function()
    -- Refusing to activate would silently stop recording for a whole class,
    -- which is a worse failure for an integrity tool than recording under a
    -- stale key. The recorder records; the analyzer decides.
    local case
    for _, c in ipairs(v2_fx.chain_cases) do
      if c.name == "issued_at_after_valid_until" then case = c end
    end
    assert.is_not_nil(case)
    local res = activation.evaluate(vim.json.encode(case.input.manifest), case.input.root_pubkey_hex)
    assert.equals("active", res.status)
  end)

  it("is_manifest_2 answers on the resolved format version", function()
    assert.is_true(activation.is_manifest_2({ format_version = "2.0" }))
    assert.is_false(activation.is_manifest_2({ format_version = "1.0" }))
    assert.is_false(activation.is_manifest_2({}))
  end)
end)
