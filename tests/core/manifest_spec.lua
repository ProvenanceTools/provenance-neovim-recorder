--- Manifest parse + verify (the activation gate primitive).
--- Mirrors log-core's parseManifest: JSON + field-shape validation, then
--- ed25519 verify of the canonicalized payload (sig field excluded).
local manifest = require("provenance.core.manifest")
local json = require("provenance.core.json")
local ed25519 = require("provenance.core.ed25519")

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

local VALID_JSON = [[{
  "assignment_id": "hw3",
  "semester": "fa25",
  "issued_at": "2026-07-14T00:00:00Z",
  "files_under_review": ["src/main.py", "src/util.py"],
  "sig": "]] .. ("a"):rep(128) .. [["
}]]

describe("manifest.parse", function()
  it("parses a well-formed manifest", function()
    local res = manifest.parse(VALID_JSON)
    assert.is_true(res.ok)
    assert.equals("hw3", res.value.assignment_id)
    assert.equals("fa25", res.value.semester)
    assert.equals("2026-07-14T00:00:00Z", res.value.issued_at)
    assert.equals(2, #res.value.files_under_review)
    assert.equals("src/main.py", res.value.files_under_review[1])
    assert.equals("src/util.py", res.value.files_under_review[2])
    assert.equals(("a"):rep(128), res.value.sig)
  end)

  it("rejects invalid JSON, never throws", function()
    local res = manifest.parse("{not json")
    assert.is_false(res.ok)
    assert.equals("invalid_json", res.error.reason)
  end)

  it("rejects a non-object top-level value (array)", function()
    local res = manifest.parse("[1,2,3]")
    assert.is_false(res.ok)
    assert.equals("not_object", res.error.reason)
  end)

  it("rejects a non-object top-level value (string)", function()
    local res = manifest.parse('"hello"')
    assert.is_false(res.ok)
    assert.equals("not_object", res.error.reason)
  end)

  it("rejects a non-object top-level value (number)", function()
    local res = manifest.parse("5")
    assert.is_false(res.ok)
    assert.equals("not_object", res.error.reason)
  end)

  local required_fields = { "assignment_id", "semester", "issued_at", "files_under_review", "sig" }
  for _, field in ipairs(required_fields) do
    it("rejects a manifest missing '" .. field .. "'", function()
      local decoded = vim.json.decode(VALID_JSON)
      decoded[field] = nil
      local res = manifest.parse(vim.json.encode(decoded))
      assert.is_false(res.ok)
      assert.equals("missing", res.error.reason)
      assert.equals(field, res.error.field)
    end)
  end

  it("rejects a non-string assignment_id", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.assignment_id = 42
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("invalid", res.error.reason)
    assert.equals("assignment_id", res.error.field)
  end)

  it("rejects an empty-string semester", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.semester = ""
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("invalid", res.error.reason)
    assert.equals("semester", res.error.field)
  end)

  it("rejects files_under_review that is not an array", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.files_under_review = "not-an-array"
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("invalid", res.error.reason)
    assert.equals("files_under_review", res.error.field)
  end)

  it("rejects files_under_review with a non-string element", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.files_under_review = { "src/main.py", 7 }
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("invalid", res.error.reason)
    assert.equals("files_under_review", res.error.field)
  end)

  it("rejects a sig that is not 128-char hex (too short)", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.sig = "ab12"
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("sig must be 128-char hex", res.error.reason)
  end)

  it("rejects a sig with non-hex characters", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.sig = ("z"):rep(128)
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("sig must be 128-char hex", res.error.reason)
  end)

  it("rejects a sig with uppercase hex characters", function()
    local decoded = vim.json.decode(VALID_JSON)
    decoded.sig = ("A"):rep(128)
    local res = manifest.parse(vim.json.encode(decoded))
    assert.is_false(res.ok)
    assert.equals("sig must be 128-char hex", res.error.reason)
  end)

  it("never throws on non-string input", function()
    local res = manifest.parse(nil)
    assert.is_false(res.ok)
  end)
end)

describe("manifest.verify against the manifest.json fixture", function()
  local fx = load_fixture()

  it("verifies true for the untouched fixture", function()
    local parsed = manifest.parse(vim.json.encode(fx.manifest))
    assert.is_true(parsed.ok)
    assert.is_true(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)

  local mutable_fields = { "assignment_id", "semester", "issued_at" }
  for _, field in ipairs(mutable_fields) do
    it("verifies false when '" .. field .. "' is mutated", function()
      local decoded = vim.json.decode(vim.json.encode(fx.manifest))
      decoded[field] = decoded[field] .. "-tampered"
      local parsed = manifest.parse(vim.json.encode(decoded))
      assert.is_true(parsed.ok)
      assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex))
    end)
  end

  it("verifies false when files_under_review is mutated", function()
    local decoded = vim.json.decode(vim.json.encode(fx.manifest))
    decoded.files_under_review = { "src/other.py" }
    local parsed = manifest.parse(vim.json.encode(decoded))
    assert.is_true(parsed.ok)
    assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)

  it("verifies false when sig is mutated", function()
    local decoded = vim.json.decode(vim.json.encode(fx.manifest))
    decoded.sig = ("0"):rep(128)
    local parsed = manifest.parse(vim.json.encode(decoded))
    assert.is_true(parsed.ok)
    assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)

  it("verifies false against the wrong pubkey", function()
    local parsed = manifest.parse(vim.json.encode(fx.manifest))
    assert.is_true(parsed.ok)
    assert.is_false(manifest.verify(parsed.value, ("0"):rep(64)))
  end)

  it("never throws on malformed manifest input to verify", function()
    assert.is_false(manifest.verify(nil, fx.course_pubkey_hex))
    assert.is_false(manifest.verify({}, fx.course_pubkey_hex))
    assert.is_false(manifest.verify({ assignment_id = "x" }, fx.course_pubkey_hex))
  end)
end)

--- `policy.enrollment` (2026-08-25, professor-facing enrollment-nag off
--- switch) MUST NOT require any change to `signed_payload`, `verify`, or
--- `verify_chain` -- `policy` is signed and canonicalized VERBATIM
--- (`policy = m.policy` in `signed_payload`), so a new key nested inside it
--- rides along for free. This section proves that claim rather than assuming
--- it: a manifest carrying `policy.enrollment` signs and verifies exactly like
--- one that does not, and the ONLY difference in the signed bytes is the
--- `policy` sub-object itself -- nothing about the fixed field list changed.
describe("manifest signing with policy.enrollment present (a new signed-payload field is NOT needed)", function()
  --- A minimal, otherwise-valid 2.0 manifest body (no `sig` yet).
  --- @param policy table
  --- @return table
  local function v2_manifest(policy)
    return {
      format_version = "2.0",
      course_id = "cs61b",
      assignment_id = "hw3",
      semester = "fa26",
      issued_at = "2026-08-25T00:00:00Z",
      files_under_review = { "src/main.py" },
      ignore = {},
      attachments = {},
      collaboration = "solo",
      submission = "bundle",
      scope = "directory",
      policy = policy,
    }
  end

  it("the signed bytes differ from a policy with no enrollment key ONLY in the policy sub-object", function()
    local without_enrollment = v2_manifest({ capture = { terminal = true } })
    local with_enrollment = v2_manifest({ capture = { terminal = true }, enrollment = { required = false } })

    local payload_without = manifest.signed_payload(without_enrollment)
    local payload_with = manifest.signed_payload(with_enrollment)
    assert.are_not.equal(payload_without, payload_with)

    -- Rebuild the payload using json.canonicalize DIRECTLY (bypassing
    -- signed_payload entirely) over the exact same fixed field list
    -- signed_payload's 2.0 branch uses, but substituting the "without" policy
    -- back in. If this matches payload_without byte-for-byte, then
    -- `policy.enrollment` reached the wire purely through the pre-existing
    -- verbatim `policy = m.policy` passthrough -- no special-cased handling,
    -- no new top-level signed key, nothing signed_payload had to learn.
    local rebuilt = json.canonicalize({
      format_version = "2.0",
      course_id = with_enrollment.course_id,
      assignment_id = with_enrollment.assignment_id,
      semester = with_enrollment.semester,
      issued_at = with_enrollment.issued_at,
      files_under_review = json.array(with_enrollment.files_under_review),
      ignore = json.array(with_enrollment.ignore),
      attachments = json.array(with_enrollment.attachments),
      collaboration = with_enrollment.collaboration,
      submission = with_enrollment.submission,
      scope = with_enrollment.scope,
      policy = without_enrollment.policy,
    })
    assert.equals(payload_without, rebuilt)
  end)

  it("signs and verifies fine with policy.enrollment.required = false", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local m = v2_manifest({ capture = { terminal = true }, enrollment = { required = false } })
    m.sig = ed25519.to_hex(ed25519.sign(manifest.signed_payload(m), priv))

    assert.is_true(manifest.verify(m, pub_hex))
  end)

  it("signs and verifies fine with policy.enrollment.required = true, and against a fixture with no enrollment key at all", function()
    local priv, pub_hex = ed25519.generate_keypair()

    local required_true = v2_manifest({ enrollment = { required = true } })
    required_true.sig = ed25519.to_hex(ed25519.sign(manifest.signed_payload(required_true), priv))
    assert.is_true(manifest.verify(required_true, pub_hex))

    local no_enrollment_key = v2_manifest({ capture = { terminal = true } })
    no_enrollment_key.sig = ed25519.to_hex(ed25519.sign(manifest.signed_payload(no_enrollment_key), priv))
    assert.is_true(manifest.verify(no_enrollment_key, pub_hex))
  end)

  it("tampering policy.enrollment.required after signing invalidates the signature, same as any other policy field", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local m = v2_manifest({ enrollment = { required = false } })
    m.sig = ed25519.to_hex(ed25519.sign(manifest.signed_payload(m), priv))
    assert.is_true(manifest.verify(m, pub_hex))

    local tampered = vim.deepcopy(m)
    tampered.policy.enrollment.required = true
    assert.is_false(manifest.verify(tampered, pub_hex))
  end)
end)
