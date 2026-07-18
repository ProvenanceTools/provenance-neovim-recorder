--- Manifest parse + verify — the activation gate primitive.
--- Mirrors log-core's `parseManifest`: a `.provenance-manifest` file the
--- course instructor signs and drops into the assignment workspace. The
--- recorder only activates (starts recording) inside a workspace whose
--- manifest verifies against the embedded course public key (design.md §4.1).
---
--- parse() validates JSON + field shapes and never throws. verify() builds
--- the signed payload — every field except `sig` — canonicalizes it (JCS),
--- and ed25519-verifies against the course pubkey; it never throws either,
--- returning false on any malformed input.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local ed25519 = require("provenance.core.ed25519")

local M = {}

-- Map a vim.json.decode result into the json value model (same convention as
-- ndjson.lua's normalize): null -> json.NULL, JSON arrays get tagged with
-- json.array so is_array()/canonicalize can tell them apart from objects.
local function normalize(v)
  if v == vim.NIL then return json.NULL end
  if type(v) ~= "table" then return v end
  if vim.tbl_isempty(v) then
    return getmetatable(v) and {} or json.array({})
  end
  if vim.islist(v) then
    local out = json.array({})
    for i = 1, #v do out[i] = normalize(v[i]) end
    return out
  end
  local out = {}
  for k, val in pairs(v) do out[k] = normalize(val) end
  return out
end

local function is_nonempty_string(v)
  return type(v) == "string" and v ~= ""
end

local function is_128_hex(v)
  return type(v) == "string" and #v == 128 and v:match("^[0-9a-f]+$") ~= nil
end

--- @param text string  raw manifest JSON text
--- @return table  { ok = true, value = Manifest } | { ok = false, error = { reason, field? } }
function M.parse(text)
  local decode_ok, decoded = pcall(vim.json.decode, text, { luanil = { object = false, array = false } })
  if not decode_ok then
    return result.err({ reason = "invalid_json", message = tostring(decoded) })
  end

  local obj = normalize(decoded)
  if type(obj) ~= "table" or json.is_array(obj) then
    return result.err({ reason = "not_object" })
  end

  -- Required non-empty string fields.
  for _, field in ipairs({ "assignment_id", "semester", "issued_at" }) do
    local v = obj[field]
    if v == nil then
      return result.err({ reason = "missing", field = field })
    end
    if not is_nonempty_string(v) then
      return result.err({ reason = "invalid", field = field })
    end
  end

  -- files_under_review: array of strings.
  local files = obj.files_under_review
  if files == nil then
    return result.err({ reason = "missing", field = "files_under_review" })
  end
  if type(files) ~= "table" or not json.is_array(files) then
    return result.err({ reason = "invalid", field = "files_under_review" })
  end
  for i = 1, #files do
    if type(files[i]) ~= "string" then
      return result.err({ reason = "invalid", field = "files_under_review" })
    end
  end

  -- sig: 128-char lowercase hex.
  local sig = obj.sig
  if sig == nil then
    return result.err({ reason = "missing", field = "sig" })
  end
  if not is_128_hex(sig) then
    return result.err({ reason = "sig must be 128-char hex", field = "sig" })
  end

  return result.ok({
    assignment_id = obj.assignment_id,
    semester = obj.semester,
    issued_at = obj.issued_at,
    files_under_review = files, -- already json.array-tagged by normalize()
    sig = sig,
  })
end

--- Build the exact payload the course tool signs: every manifest field
--- except `sig`, JCS-canonicalized. `files_under_review` must be tagged as a
--- json.array so it canonicalizes as `[...]`, not `{...}`.
local function signed_payload(m)
  return json.canonicalize({
    assignment_id = m.assignment_id,
    semester = m.semester,
    issued_at = m.issued_at,
    files_under_review = json.array(m.files_under_review),
  })
end

--- @param m table  a Manifest (typically the .value of a successful parse())
--- @param course_pubkey_hex string  64-char hex ed25519 public key
--- @return boolean  never throws; false on any malformed input
function M.verify(m, course_pubkey_hex)
  local ok, verified = pcall(function()
    if type(m) ~= "table" then return false end
    if not is_nonempty_string(m.assignment_id) then return false end
    if not is_nonempty_string(m.semester) then return false end
    if not is_nonempty_string(m.issued_at) then return false end
    if type(m.files_under_review) ~= "table" then return false end
    for i = 1, #m.files_under_review do
      if type(m.files_under_review[i]) ~= "string" then return false end
    end
    if not is_128_hex(m.sig) then return false end

    local payload = signed_payload(m)
    return ed25519.verify(ed25519.from_hex(m.sig), payload, course_pubkey_hex)
  end)
  if not ok then return false end
  return verified == true
end

return M
