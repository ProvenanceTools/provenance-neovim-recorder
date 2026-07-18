--- Manifest parse + verify (the activation gate primitive).
--- Mirrors log-core's parseManifest: JSON + field-shape validation, then
--- ed25519 verify of the canonicalized payload (sig field excluded).
local manifest = require("provenance.core.manifest")

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
